// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! PageHandler manages the page states of multiple regions.

#![deny(missing_docs)]

use std::fs::File;
use std::mem;
use std::ops::Range;
use std::sync::Arc;

use anyhow::Context;
use base::error;
use base::unix::FileDataIterator;
use base::AsRawDescriptor;
use base::SharedMemory;
use data_model::VolatileSlice;
use sync::Mutex;
use thiserror::Error as ThisError;

use crate::file::Error as FileError;
use crate::file::SwapFile;
use crate::pagesize::addr_to_page_idx;
use crate::pagesize::bytes_to_pages;
use crate::pagesize::is_hugepage_aligned;
use crate::pagesize::is_page_aligned;
use crate::pagesize::page_base_addr;
use crate::pagesize::page_idx_to_addr;
use crate::pagesize::pages_to_bytes;
use crate::pagesize::round_up_hugepage_size;
use crate::pagesize::THP_SIZE;
use crate::staging::CopyOp;
use crate::staging::Error as StagingError;
use crate::staging::StagingMemory;
use crate::userfaultfd::Error as UffdError;
use crate::userfaultfd::Userfaultfd;
use crate::worker::Channel;
use crate::worker::Task;

pub(crate) const MLOCK_BUDGET: usize = 16 * 1024 * 1024; // = 16MB
const PREFETCH_THRESHOLD: usize = 4 * 1024 * 1024; // = 4MB

/// Result for PageHandler
pub type Result<T> = std::result::Result<T, Error>;

/// Errors for PageHandler
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("the address is invalid {0:#018X}")]
    /// the address is invalid
    InvalidAddress(usize),
    #[error("the regions {0:?} and {1:?} overlap")]
    /// regions are overlaps on registering
    RegionOverlap(Range<usize>, Range<usize>),
    #[error("failed to create page handler {0:?}")]
    /// failed to create page handler
    CreateFailed(anyhow::Error),
    #[error("file operation failed : {0:?}")]
    /// file operation failed
    File(#[from] FileError),
    #[error("staging operation failed : {0:?}")]
    /// staging operation failed
    Staging(#[from] StagingError),
    #[error("userfaultfd failed : {0:?}")]
    /// userfaultfd operation failed
    Userfaultfd(#[from] UffdError),
}

/// Remove the memory range on the guest memory.
///
/// This is an alternative to [vm_memory::GuestMemory::remove_range()] when working with host
/// addresses instead of guest addresses.
///
/// # Safety
///
/// The memory range must be on the guest memory.
#[deny(unsafe_op_in_unsafe_fn)]
unsafe fn remove_memory(addr: usize, len: usize) -> std::result::Result<(), base::Error> {
    // Safe because the caller guarantees addr is in guest memory, so this does not affect any rust
    // managed memory.
    let ret = unsafe { libc::madvise(addr as *mut libc::c_void, len, libc::MADV_REMOVE) };
    if ret < 0 {
        base::errno_result()
    } else {
        Ok(())
    }
}

fn uffd_copy_all(
    uffd: &Userfaultfd,
    mut page_addr: usize,
    mut data_slice: VolatileSlice,
    wake: bool,
) -> std::result::Result<(), UffdError> {
    loop {
        let result = uffd.copy(page_addr, data_slice.size(), data_slice.as_ptr(), wake);
        match result {
            Err(UffdError::PartiallyCopied(copied)) => {
                page_addr += copied;
                data_slice.advance(copied);
            }
            other => {
                // Even EEXIST for copy operation should be an error for page fault handling. If
                // the page was swapped in before, the page should be cleared from the swap file
                // and do `Userfaultfd::zero()` instead.
                return other.map(|_| ());
            }
        }
    }
}

/// [Region] represents a memory region and corresponding [SwapFile].
struct Region<'a> {
    /// the head page index of the region.
    head_page_idx: usize,
    file: SwapFile<'a>,
    staging_memory: StagingMemory,
    copied_from_file_pages: usize,
    copied_from_staging_pages: usize,
    zeroed_pages: usize,
    swap_in_pages: usize,
    /// the amount of pages which were already initialized on page faults.
    redundant_pages: usize,
    swap_active: bool,
}

/// MoveToStaging copies chunks of consecutive pages next to each other on the guest memory to the
/// staging memory and removes the chunks on the guest memory.
pub struct MoveToStaging {
    remove_area: Range<usize>,
    copies: Vec<CopyOp>,
}

impl Task for MoveToStaging {
    fn execute(self) {
        for copy_op in self.copies {
            copy_op.execute();
        }
        // Remove chunks of pages at once to reduce madvise(2) syscall.
        // Safe because the region is already backed by the file and the content will be
        // swapped in on a page fault.
        let result = unsafe {
            remove_memory(
                self.remove_area.start,
                self.remove_area.end - self.remove_area.start,
            )
        };
        if let Err(e) = result {
            panic!("failed to remove memory: {:?}", e);
        }
    }
}

struct PageHandleContext<'a> {
    regions: Vec<Region<'a>>,
    mlock_budget_pages: usize,
}

/// PageHandler manages the page states of multiple regions.
///
/// Handles multiple events derived from userfaultfd and swap out requests.
/// All the addresses and sizes in bytes are converted to page id internally.
pub struct PageHandler<'a> {
    ctx: Mutex<PageHandleContext<'a>>,
    channel: Arc<Channel<MoveToStaging>>,
}

impl<'a> PageHandler<'a> {
    /// Creates [PageHandler] for the given region.
    ///
    /// If any of regions overlaps, this returns [Error::RegionOverlap].
    ///
    /// # Arguments
    ///
    /// * `swap_file` - The swap file.
    /// * `staging_shmem` - The staging memory. It must have enough size to hold guest memory.
    ///   Otherwise monitor process crashes on creating a mmap.
    /// * `address_ranges` - The list of address range of the regions. the start address must align
    ///   with page. the size must be multiple of pagesize.
    pub fn create(
        swap_file: &'a File,
        staging_shmem: &'a SharedMemory,
        address_ranges: &[Range<usize>],
        stating_move_context: Arc<Channel<MoveToStaging>>,
    ) -> Result<Self> {
        // Truncate the file into the size to hold all regions, otherwise access beyond the end of
        // file may cause SIGBUS.
        swap_file
            .set_len(
                address_ranges
                    .iter()
                    .map(|r| (r.end.saturating_sub(r.start)) as u64)
                    .sum(),
            )
            .context("truncate swap file")
            .map_err(Error::CreateFailed)?;

        let mut regions: Vec<Region> = Vec::new();
        let mut offset_pages = 0;
        for address_range in address_ranges {
            let head_page_idx = addr_to_page_idx(address_range.start);
            if address_range.end < address_range.start {
                return Err(Error::CreateFailed(anyhow::anyhow!(
                    "invalid region end < start"
                )));
            }
            let region_size = address_range.end - address_range.start;
            let num_of_pages = bytes_to_pages(region_size);

            // Find an overlapping region
            match regions.iter().position(|region| {
                if region.head_page_idx < head_page_idx {
                    region.head_page_idx + region.file.num_pages() > head_page_idx
                } else {
                    region.head_page_idx < head_page_idx + num_of_pages
                }
            }) {
                Some(i) => {
                    let region = &regions[i];

                    return Err(Error::RegionOverlap(
                        address_range.clone(),
                        page_idx_to_addr(region.head_page_idx)
                            ..(page_idx_to_addr(region.head_page_idx + region.file.num_pages())),
                    ));
                }
                None => {
                    let base_addr = address_range.start;
                    assert!(is_page_aligned(base_addr));
                    assert!(is_page_aligned(region_size));

                    let file = SwapFile::new(swap_file, offset_pages, num_of_pages)?;
                    let staging_memory = StagingMemory::new(
                        staging_shmem,
                        pages_to_bytes(offset_pages) as u64,
                        num_of_pages,
                    )?;
                    regions.push(Region {
                        head_page_idx,
                        file,
                        staging_memory,
                        copied_from_file_pages: 0,
                        copied_from_staging_pages: 0,
                        zeroed_pages: 0,
                        swap_in_pages: 0,
                        redundant_pages: 0,
                        swap_active: false,
                    });
                    offset_pages += num_of_pages;
                }
            }
        }

        Ok(Self {
            ctx: Mutex::new(PageHandleContext {
                regions,
                mlock_budget_pages: bytes_to_pages(MLOCK_BUDGET),
            }),
            channel: stating_move_context,
        })
    }

    fn find_region<'b>(
        regions: &'b mut [Region<'a>],
        page_idx: usize,
    ) -> Option<&'b mut Region<'a>> {
        // sequential search the corresponding page map from the list. It should be fast enough
        // because there are a few regions (usually only 1).
        regions.iter_mut().find(|region| {
            region.head_page_idx <= page_idx
                && page_idx < region.head_page_idx + region.file.num_pages()
        })
    }

    /// Fills the faulted page with zero if the page is not initialized, with the content in the
    /// swap file if the page is swapped out.
    ///
    /// # Arguments
    ///
    /// * `uffd` - the reference to the [Userfaultfd] for the faulting process.
    /// * `address` - the address that triggered the page fault.
    pub fn handle_page_fault(&self, uffd: &Userfaultfd, address: usize) -> Result<()> {
        let page_idx = addr_to_page_idx(address);
        // the head address of the page.
        let page_addr = page_base_addr(address);
        let page_size = pages_to_bytes(1);
        let mut ctx = self.ctx.lock();
        let region =
            Self::find_region(&mut ctx.regions, page_idx).ok_or(Error::InvalidAddress(address))?;

        let idx_in_region = page_idx - region.head_page_idx;
        if let Some(page_slice) = region.staging_memory.page_content(idx_in_region)? {
            uffd_copy_all(uffd, page_addr, page_slice, true)?;
            // TODO(b/265758094): optimize clear operation.
            region
                .staging_memory
                .clear_range(idx_in_region..idx_in_region + 1)?;
            region.copied_from_staging_pages += 1;
            Ok(())
        } else if let Some(page_slice) = region.file.page_content(idx_in_region)? {
            // TODO(kawasin): Unlock regions to proceed swap-in operation background.
            uffd_copy_all(uffd, page_addr, page_slice, true)?;
            // TODO(b/265758094): optimize clear operation.
            // Do not erase the page from the disk for trimming optimization on next swap out.
            let munlocked_pages = region.file.clear_range(idx_in_region..idx_in_region + 1)?;
            region.copied_from_file_pages += 1;
            ctx.mlock_budget_pages += munlocked_pages;
            Ok(())
        } else {
            // Map a zero page since no swap file has been created yet but the fault
            // happened.
            // safe because the fault page is notified by uffd.
            let result = uffd.zero(page_addr, page_size, true);
            match result {
                Ok(_) => {
                    region.zeroed_pages += 1;
                    Ok(())
                }
                Err(UffdError::PageExist) => {
                    // This case can happen if page faults on the same page happen on different
                    // processes.
                    uffd.wake(page_addr, page_size)?;
                    region.redundant_pages += 1;
                    Ok(())
                }
                Err(e) => Err(e.into()),
            }
        }
    }

    /// Clear the internal state for the pages.
    ///
    /// When pages are removed by madvise with `MADV_DONTNEED` or `MADV_REMOVE`, userfaultfd
    /// notifies the event as `UFFD_EVENT_REMOVE`. This handles the remove event.
    ///
    /// In crosvm, balloon frees the guest memory and cause `UFFD_EVENT_REMOVE`.
    ///
    /// # Arguments
    ///
    /// * `start_addr` - the head address of the memory area to be freed.
    /// * `end_addr` - the end address of the memory area to be freed. `UFFD_EVENT_REMOVE` tells the
    ///   head address of the next memory area of the freed area. (i.e. the exact tail address of
    ///   the memory area is `end_addr - 1`.)
    pub fn handle_page_remove(&self, start_addr: usize, end_addr: usize) -> Result<()> {
        if !is_page_aligned(start_addr) {
            return Err(Error::InvalidAddress(start_addr));
        } else if !is_page_aligned(end_addr) {
            return Err(Error::InvalidAddress(end_addr));
        }
        let start_page_idx = addr_to_page_idx(start_addr);
        let last_page_idx = addr_to_page_idx(end_addr);
        let mut ctx = self.ctx.lock();
        // TODO(b/269983521): Clear multiple pages in the same region at once.
        for page_idx in start_page_idx..(last_page_idx) {
            let page_addr = page_idx_to_addr(page_idx);
            // TODO(kawasin): Cache the position if the range does not span multiple regions.
            let region = Self::find_region(&mut ctx.regions, page_idx)
                .ok_or(Error::InvalidAddress(page_addr))?;
            let idx_in_region = page_idx - region.head_page_idx;
            let idx_range = idx_in_region..idx_in_region + 1;
            if let Err(e) = region.staging_memory.clear_range(idx_range.clone()) {
                error!("failed to clear removed page from staging: {:?}", e);
            }
            // Erase the pages from the disk because the pages are removed from the guest memory.
            let munlocked_pages = region.file.erase_from_disk(idx_range)?;
            ctx.mlock_budget_pages += munlocked_pages;
        }
        Ok(())
    }

    /// Move active pages in the memory region to the staging memory.
    ///
    /// It only moves active contents in the guest memory to the swap file and skips empty pages
    /// (e.g. pages not touched, freed by balloon) using `lseek(2)` + `SEEK_HOLE/DATA`.
    ///
    /// Returns the count of moved out pages.
    ///
    /// # Arguments
    ///
    /// * `base_addr` - the head address of the memory region.
    /// * `memfd` - the file descriptor of the memfd backing the guest memory region.
    /// * `base_offset` - the offset of the memory region in the memfd.
    ///
    /// # Safety
    ///
    /// The region must have been registered to all userfaultfd of processes which may touch the
    /// region.
    ///
    /// The memory must be protected not to be updated while moving.
    ///
    /// The page fault events for the region from the userfaultfd must be handled by
    /// [Self::handle_page_fault()].
    ///
    /// Must call [Channel::wait_complete()] to wait all the copy operation complete within the
    /// memory protection period.
    #[deny(unsafe_op_in_unsafe_fn)]
    pub unsafe fn move_to_staging<T>(
        &self,
        base_addr: usize,
        memfd: &T,
        base_offset: u64,
    ) -> Result<usize>
    where
        T: AsRawDescriptor,
    {
        let hugepage_size = *THP_SIZE;
        let mut ctx = self.ctx.lock();
        let region = Self::find_region(&mut ctx.regions, addr_to_page_idx(base_addr))
            .ok_or(Error::InvalidAddress(base_addr))?;

        if page_idx_to_addr(region.head_page_idx) != base_addr {
            return Err(Error::InvalidAddress(base_addr));
        }
        let region_size = pages_to_bytes(region.file.num_pages());
        let mut file_data = FileDataIterator::new(memfd, base_offset, region_size as u64);
        let mut moved_size = 0;
        let mut copies = Vec::new();
        let mut remaining_batch_size = hugepage_size;
        let mut batch_head_offset = 0;
        let mut cur_data = None;
        while let Some(data_range) = cur_data.take().or_else(|| file_data.next()) {
            // Assert offset is page aligned
            let offset = (data_range.start - base_offset) as usize;
            assert!(is_page_aligned(offset));

            // The chunk size must be within usize since the chunk is within the guest memory.
            let chunk_size = (data_range.end - data_range.start) as usize;
            let data_range = if chunk_size > remaining_batch_size {
                // Split the chunk if it is bigger than remaining_batch_size.

                let split_size = if chunk_size >= hugepage_size {
                    // If the chunk size is bigger than or equals to huge page size, the chunk may
                    // contains a huge page. If we MADV_REMOVE a huge page partially, it can cause
                    // inconsistency between the actual page table and vmm-swap internal state.
                    let chunk_addr = base_addr + offset;
                    if !is_hugepage_aligned(chunk_addr) {
                        // Split the chunk before the where a huge page could start.
                        std::cmp::min(
                            round_up_hugepage_size(chunk_addr) - chunk_addr,
                            remaining_batch_size,
                        )
                    } else {
                        if remaining_batch_size < hugepage_size {
                            // Remove the batch since it does not have enough room for a huge page.
                            self.channel.push(MoveToStaging {
                                remove_area: base_addr + batch_head_offset..base_addr + offset,
                                copies: mem::take(&mut copies),
                            });
                            remaining_batch_size = hugepage_size;
                            batch_head_offset = offset;
                        }
                        hugepage_size
                    }
                } else {
                    remaining_batch_size
                };
                // Cache the rest of splitted chunk to avoid useless lseek(2) syscall.
                cur_data = Some(data_range.start + split_size as u64..data_range.end);
                data_range.start..data_range.start + split_size as u64
            } else {
                data_range
            };

            let size = (data_range.end - data_range.start) as usize;
            assert!(is_page_aligned(size));

            // Safe because:
            // * src_addr is aligned with page size
            // * the data_range starting from src_addr is on the guest memory.
            let copy_op = unsafe {
                region.staging_memory.copy(
                    (base_addr + offset) as *const u8,
                    bytes_to_pages(offset),
                    bytes_to_pages(size),
                )?
            };
            copies.push(copy_op);

            moved_size += size;
            // The size must be smaller than or equals to remaining_batch_size.
            remaining_batch_size -= size;

            if remaining_batch_size == 0 {
                // Remove the batch of pages at once to reduce madvise(2) syscall.
                self.channel.push(MoveToStaging {
                    remove_area: base_addr + batch_head_offset..base_addr + offset + size,
                    copies: mem::take(&mut copies),
                });
                remaining_batch_size = hugepage_size;
                batch_head_offset = offset + size;
            }
        }
        // Remove the final batch of pages.
        self.channel.push(MoveToStaging {
            remove_area: base_addr + batch_head_offset..base_addr + region_size,
            copies,
        });

        let moved_pages = bytes_to_pages(moved_size);
        // Suppress error log on the first swap_out, since page counts are not initialized but zero.
        if region.swap_active
            && moved_pages
                != (region.copied_from_file_pages
                    + region.copied_from_staging_pages
                    + region.zeroed_pages
                    + region.swap_in_pages)
        {
            error!(
                "moved pages ({}) does not match with resident pages (copied(file): {}, copied(staging): {}, zeroed: {}, swap_in: {}).",
                moved_pages, region.copied_from_file_pages, region.copied_from_staging_pages,
                region.zeroed_pages, region.swap_in_pages
            );
        }
        region.copied_from_file_pages = 0;
        region.copied_from_staging_pages = 0;
        region.zeroed_pages = 0;
        region.swap_in_pages = 0;
        region.redundant_pages = 0;
        region.swap_active = true;

        Ok(moved_pages)
    }

    /// Write a chunk of consecutive pages in the staging memory to the swap file.
    ///
    /// If there is no active pages in the staging memory, this returns `Ok(0)`.
    ///
    /// The pages in guest memory have been moved to staging memory by [Self::move_to_staging()].
    ///
    /// Returns the count of swapped out pages.
    ///
    /// Even if swap_out fails on any internal steps, it does not break the page state management
    /// and `PageHandler` can continue working with a little pages leaking in staging memory or swap
    /// file. The leaked pages are removed when vmm-swap is disabled and `PageHandler` is dropped.
    ///
    /// # Arguments
    ///
    /// * `max_size` - the upper limit of the chunk size to write into the swap file at once. The
    ///   chunk is splitted if it is bigger than `max_size`.
    pub fn swap_out(&self, max_size: usize) -> Result<usize> {
        let max_pages = bytes_to_pages(max_size);
        let mut ctx = self.ctx.lock();
        for region in ctx.regions.iter_mut() {
            if let Some(idx_range) = region.staging_memory.first_data_range(max_pages) {
                let pages = idx_range.end - idx_range.start;
                let slice = region.staging_memory.get_slice(idx_range.clone())?;
                // Convert VolatileSlice to &[u8]
                // Safe because the range of volatile slice is already validated.
                let slice = unsafe { std::slice::from_raw_parts(slice.as_ptr(), slice.size()) };
                region.file.write_to_file(idx_range.start, slice)?;
                // TODO(kawasin): clear state_list on each write and MADV_REMOVE several chunk at
                // once.
                region.staging_memory.clear_range(idx_range)?;
                // TODO(kawasin): free the page cache of the swap file.
                // TODO(kawasin): use writev() to swap_out several small chunks at once.
                return Ok(pages);
            }
        }
        Ok(0)
    }

    /// Create a new [SwapInContext].
    pub fn start_swap_in(&'a self) -> SwapInContext<'a> {
        SwapInContext {
            ctx: &self.ctx,
            cur_populate: 0,
            cur_staging: 0,
            cur_file: 0,
        }
    }

    /// Returns count of pages active on the memory.
    pub fn compute_resident_pages(&self) -> usize {
        self.ctx
            .lock()
            .regions
            .iter()
            .map(|r| r.copied_from_file_pages + r.copied_from_staging_pages + r.zeroed_pages)
            .sum()
    }

    /// Returns count of pages copied from vmm-swap file to the guest memory.
    pub fn compute_copied_from_file_pages(&self) -> usize {
        self.ctx
            .lock()
            .regions
            .iter()
            .map(|r| r.copied_from_file_pages)
            .sum()
    }

    /// Returns count of pages copied from staging memory to the guest memory.
    pub fn compute_copied_from_staging_pages(&self) -> usize {
        self.ctx
            .lock()
            .regions
            .iter()
            .map(|r| r.copied_from_staging_pages)
            .sum()
    }

    /// Returns count of pages initialized with zero.
    pub fn compute_zeroed_pages(&self) -> usize {
        self.ctx.lock().regions.iter().map(|r| r.zeroed_pages).sum()
    }

    /// Returns count of pages which were already initialized on page faults.
    pub fn compute_redundant_pages(&self) -> usize {
        self.ctx
            .lock()
            .regions
            .iter()
            .map(|r| r.redundant_pages)
            .sum()
    }

    /// Returns count of pages present in the staging memory.
    pub fn compute_staging_pages(&self) -> usize {
        self.ctx
            .lock()
            .regions
            .iter()
            .map(|r| r.staging_memory.present_pages())
            .sum()
    }

    /// Returns count of pages present in the swap files.
    pub fn compute_swap_pages(&self) -> usize {
        self.ctx
            .lock()
            .regions
            .iter()
            .map(|r| r.file.present_pages())
            .sum()
    }
}

/// Context for swap-in operation.
///
/// This holds cursor of indices in the regions for each step for optimization.
pub struct SwapInContext<'a> {
    ctx: &'a Mutex<PageHandleContext<'a>>,
    cur_populate: usize,
    cur_staging: usize,
    cur_file: usize,
}

impl SwapInContext<'_> {
    /// Swap in a chunk of consecutive pages from the staging memory and the swap file.
    ///
    /// If there is no more pages present outside of the guest memory, this returns `Ok(0)`.
    ///
    /// Returns the count of swapped in pages.
    ///
    /// # Arguments
    ///
    /// * `uffd` - the main [Userfaultfd].
    /// * `max_size` - the upper limit of the chunk size to swap into the guest memory at once. The
    ///   chunk is splitted if it is bigger than `max_size`.
    pub fn swap_in(&mut self, uffd: &Userfaultfd, max_size: usize) -> Result<usize> {
        let mut ctx = self.ctx.lock();
        // Request the kernel to pre-populate the present pages in the swap file to page cache
        // background. At most 16MB of pages will be populated.
        // The threshold is to apply MADV_WILLNEED to bigger chunk of pages. The kernel populates
        // consective pages at once on MADV_WILLNEED.
        if ctx.mlock_budget_pages > bytes_to_pages(PREFETCH_THRESHOLD) {
            let PageHandleContext {
                regions,
                mlock_budget_pages,
            } = &mut *ctx;
            'prefetch_loop: for region in regions[self.cur_populate..].iter_mut() {
                loop {
                    let locked_pages = region.file.lock_and_async_prefetch(*mlock_budget_pages)?;
                    if locked_pages > 0 {
                        *mlock_budget_pages -= locked_pages;
                        if *mlock_budget_pages == 0 {
                            break 'prefetch_loop;
                        }
                    } else {
                        // next region.
                        self.cur_populate += 1;
                        break;
                    }
                }
            }
        }

        let max_pages = bytes_to_pages(max_size);
        for region in ctx.regions[self.cur_staging..].iter_mut() {
            // TODO(kawasin): swap_in multiple chunks less than max_size at once.
            if let Some(idx_range) = region.staging_memory.first_data_range(max_pages) {
                let pages = idx_range.end - idx_range.start;
                let page_addr = page_idx_to_addr(region.head_page_idx + idx_range.start);
                let slice = region.staging_memory.get_slice(idx_range.clone())?;
                uffd_copy_all(uffd, page_addr, slice, false)?;
                // Clear the staging memory to avoid memory spike.
                // TODO(kawasin): reduce the call count of MADV_REMOVE by removing several data
                // at once.
                region.staging_memory.clear_range(idx_range)?;
                region.swap_in_pages += pages;
                return Ok(pages);
            }
            self.cur_staging += 1;
        }

        for region in ctx.regions[self.cur_file..].iter_mut() {
            if let Some(idx_range) = region.file.first_data_range(max_pages) {
                let pages = idx_range.end - idx_range.start;
                let page_addr = page_idx_to_addr(region.head_page_idx + idx_range.start);
                let slice = region.file.get_slice(idx_range.clone())?;
                // TODO(kawasin): Unlock regions to proceed page fault handling on the main thread.
                //                We also need to handle the EEXIST error from UFFD_COPY.
                uffd_copy_all(uffd, page_addr, slice, false)?;
                // Do not erase each chunk of pages from disk on swap_in. The whole file will be
                // truncated when swap_in is completed. Even if swap_in is aborted, the remaining
                // disk contents help the trimming optimization on swap_out.
                let munlocked_pages = region.file.clear_range(idx_range)?;
                region.swap_in_pages += pages;
                ctx.mlock_budget_pages += munlocked_pages;
                return Ok(pages);
            }
            self.cur_file += 1;
        }
        Ok(0)
    }
}

impl Drop for SwapInContext<'_> {
    fn drop(&mut self) {
        let mut ctx = self.ctx.lock();
        for region in ctx.regions.iter_mut() {
            if let Err(e) = region.file.clear_mlock() {
                panic!("failed to clear mlock: {:?}", e);
            }
        }
        ctx.mlock_budget_pages = bytes_to_pages(MLOCK_BUDGET);
    }
}
