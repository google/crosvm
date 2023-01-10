// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! PageHandler manages the page states of multiple regions.

#![deny(missing_docs)]

use std::ops::Range;
use std::path::Path;

use base::error;
use base::unix::FileDataIterator;
use base::AsRawDescriptor;
use data_model::VolatileSlice;
use thiserror::Error as ThisError;

use crate::file::Error as FileError;
use crate::file::SwapFile;
use crate::pagesize::addr_to_page_idx;
use crate::pagesize::bytes_to_pages;
use crate::pagesize::is_page_aligned;
use crate::pagesize::page_base_addr;
use crate::pagesize::page_idx_to_addr;
use crate::pagesize::pages_to_bytes;
use crate::staging::Error as StagingError;
use crate::staging::StagingMemory;
use crate::userfaultfd::UffdError;
use crate::userfaultfd::Userfaultfd;

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
    #[error("file operation failed : {0:?}")]
    /// file operation failed
    File(FileError),
    #[error("staging operation failed : {0:?}")]
    /// staging operation failed
    Staging(StagingError),
    #[error("userfaultfd failed : {0:?}")]
    /// userfaultfd operation failed
    Userfaultfd(UffdError),
}

impl From<UffdError> for Error {
    fn from(e: UffdError) -> Self {
        Self::Userfaultfd(e)
    }
}

impl From<FileError> for Error {
    fn from(e: FileError) -> Self {
        Self::File(e)
    }
}

impl From<StagingError> for Error {
    fn from(e: StagingError) -> Self {
        Self::Staging(e)
    }
}

/// [Region] represents a memory region and corresponding [SwapFile].
struct Region {
    /// the head page index of the region.
    head_page_idx: usize,
    file: SwapFile,
    staging_memory: Option<StagingMemory>,
    /// Cursor used when iterating over pages present in staging memory. All pages with indices less
    /// than the cursor are known to be empty.
    staging_cursor: usize,
    copied_from_file_pages: usize,
    copied_from_staging_pages: usize,
    zeroed_pages: usize,
    /// the amount of pages which were already initialized on page faults.
    redundant_pages: usize,
    swap_active: bool,
}

/// PageHandler manages the page states of multiple regions.
///
/// Handles multiple events derived from userfaultfd and swap out requests.
/// All the addresses and sizes in bytes are converted to page id internally.
pub struct PageHandler {
    regions: Vec<Region>,
}

impl PageHandler {
    /// Creates [PageHandler] for the given region.
    ///
    /// If any of regions overlaps, this returns [Error::RegionOverlap].
    ///
    /// # Arguments
    ///
    /// * `swap_dir` - path to the directory to create a swap file from.
    /// * `address_ranges` - the list of address range of the regions. the start address must align
    ///   with page. the size must be multiple of pagesize.
    pub fn create(swap_dir: &Path, address_ranges: &[Range<usize>]) -> Result<Self> {
        let mut regions: Vec<Region> = Vec::new();

        for address_range in address_ranges {
            let head_page_idx = addr_to_page_idx(address_range.start);
            let region_size = address_range.end - address_range.start;
            let num_of_pages = bytes_to_pages(region_size);

            // find an overlaping region
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

                    let file = SwapFile::new(swap_dir, num_of_pages)?;
                    regions.push(Region {
                        head_page_idx,
                        file,
                        staging_memory: None,
                        staging_cursor: 0,
                        copied_from_file_pages: 0,
                        copied_from_staging_pages: 0,
                        zeroed_pages: 0,
                        redundant_pages: 0,
                        swap_active: false,
                    });
                }
            }
        }

        Ok(Self { regions })
    }

    fn find_region_position(&self, page_idx: usize) -> Option<usize> {
        // sequential search the corresponding page map from the list. It should be fast enough
        // because there are a few regions (usually only 1).
        self.regions.iter().position(|region| {
            region.head_page_idx <= page_idx
                && page_idx < region.head_page_idx + region.file.num_pages()
        })
    }

    fn find_region(&mut self, page_idx: usize) -> Option<&mut Region> {
        self.find_region_position(page_idx)
            .map(|i| &mut self.regions[i])
    }

    fn copy_all(
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

    /// Fills the faulted page with zero if the page is not initialized, with the content in the
    /// swap file if the page is swapped out.
    ///
    /// # Arguments
    ///
    /// * `uffd` - the reference to the [Userfaultfd] for the faulting process.
    /// * `address` - the address that triggered the page fault.
    pub fn handle_page_fault(&mut self, uffd: &Userfaultfd, address: usize) -> Result<()> {
        let page_idx = addr_to_page_idx(address);
        // the head address of the page.
        let page_addr = page_base_addr(address);
        let page_size = pages_to_bytes(1);
        let region = self
            .find_region_position(page_idx)
            .map(|i| &mut self.regions[i])
            .ok_or(Error::InvalidAddress(address))?;

        let idx_in_region = page_idx - region.head_page_idx;
        if let Some(page_slice) = region
            .staging_memory
            .as_ref()
            .map(|sm| sm.page_content(idx_in_region))
            .transpose()?
            .flatten()
        {
            Self::copy_all(uffd, page_addr, page_slice, true)?;
            // staging_memory must present when page_slice is present.
            region
                .staging_memory
                .as_mut()
                .unwrap()
                .clear_range(idx_in_region..idx_in_region + 1)?;
            region.copied_from_staging_pages += 1;
            Ok(())
        } else if let Some(page_slice) = region.file.page_content(idx_in_region)? {
            Self::copy_all(uffd, page_addr, page_slice, true)?;
            region.file.clear(idx_in_region)?;
            region.copied_from_file_pages += 1;
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
                Err(UffdError::ZeropageFailed(errno)) if errno as i32 == libc::EEXIST => {
                    // zeroing fails with EEXIST if the page is already filled. This case
                    // can happen if page faults on the same page happen on different
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
    pub fn handle_page_remove(&mut self, start_addr: usize, end_addr: usize) -> Result<()> {
        if !is_page_aligned(start_addr) {
            return Err(Error::InvalidAddress(start_addr));
        } else if !is_page_aligned(end_addr) {
            return Err(Error::InvalidAddress(end_addr));
        }
        let start_page_idx = addr_to_page_idx(start_addr);
        let last_page_idx = addr_to_page_idx(end_addr);
        for page_idx in start_page_idx..(last_page_idx) {
            let page_addr = page_idx_to_addr(page_idx);
            let region = self
                .find_region(page_idx)
                .ok_or(Error::InvalidAddress(page_addr))?;
            if let Err(e) = region.file.clear(page_idx - region.head_page_idx) {
                error!("failed to clear removed page: {:?}", e);
            }
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
    /// * `max_batch_size` - The maximum number of bytes which are simultaneously present in both
    ///   guest memory and staging memory.
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
    #[deny(unsafe_op_in_unsafe_fn)]
    pub unsafe fn move_to_staging<T>(
        &mut self,
        base_addr: usize,
        memfd: &T,
        base_offset: u64,
        max_batch_size: usize,
    ) -> Result<usize>
    where
        T: AsRawDescriptor,
    {
        assert!(is_page_aligned(max_batch_size));
        let region = self
            .find_region(addr_to_page_idx(base_addr))
            .ok_or(Error::InvalidAddress(base_addr))?;

        if page_idx_to_addr(region.head_page_idx) != base_addr {
            return Err(Error::InvalidAddress(base_addr));
        }
        if region.staging_memory.is_none() {
            region.staging_memory = Some(StagingMemory::new(region.file.num_pages())?);
        }
        let staging_memory = region.staging_memory.as_mut().unwrap();
        let region_size = pages_to_bytes(region.file.num_pages());
        let mut file_data = FileDataIterator::new(memfd, base_offset, region_size as u64);
        let mut moved_size = 0;
        let mut remaining_batch_size = max_batch_size;
        let mut batch_head_offset = 0;
        let mut cur_data = None;
        while let Some(data_range) = cur_data.take().or_else(|| file_data.next()) {
            // Chops the chunk if it is bigger than remaining_batch_size.
            let data_range = if data_range.end - data_range.start > remaining_batch_size as u64 {
                // Cache the rest of splitted chunk to avoid useless lseek(2) syscall.
                cur_data = Some(data_range.start + remaining_batch_size as u64..data_range.end);
                data_range.start..data_range.start + remaining_batch_size as u64
            } else {
                data_range
            };

            // Assert offset is page aligned
            let offset = (data_range.start - base_offset) as usize;
            assert!(is_page_aligned(offset));
            let size = (data_range.end - data_range.start) as usize;
            assert!(is_page_aligned(size));

            // TODO(kawasin): multi thread for performance optimization.
            // Safe because:
            // * src_addr is aligned with page size
            // * the data_range starting from src_addr is on the guest memory.
            unsafe {
                staging_memory.copy(
                    (base_addr + offset) as *const u8,
                    bytes_to_pages(offset),
                    bytes_to_pages(size),
                )?;
            }

            moved_size += size;
            // The size must be smaller than or equals to remaining_batch_size.
            remaining_batch_size -= size;

            if remaining_batch_size == 0 {
                // Remove the batch of pages at once to reduce madvise(2) syscall.
                // Safe because the region is already backed by the file and the content will be
                // swapped in on a page fault.
                unsafe {
                    libc::madvise(
                        (base_addr + batch_head_offset) as *mut libc::c_void,
                        offset + size - batch_head_offset,
                        libc::MADV_REMOVE,
                    );
                }
                remaining_batch_size = max_batch_size;
                batch_head_offset = offset + size;
            }
        }
        // Remove the final batch of pages.
        // Safe because the region is already backed by the file and the content will be swapped in
        // on a page fault.
        unsafe {
            libc::madvise(
                (base_addr + batch_head_offset) as *mut libc::c_void,
                region_size - batch_head_offset,
                libc::MADV_REMOVE,
            );
        }

        let moved_pages = bytes_to_pages(moved_size);
        // Suppress error log on the first swap_out, since page counts are not initialized but zero.
        if region.swap_active
            && moved_pages
                != (region.copied_from_file_pages
                    + region.copied_from_staging_pages
                    + region.zeroed_pages)
        {
            error!(
                "moved pages ({}) does not match with resident pages (copied(file): {}, copied(staging): {}, zeroed: {}).",
                moved_pages, region.copied_from_file_pages, region.copied_from_staging_pages, region.zeroed_pages
            );
        }
        region.staging_cursor = 0;
        region.copied_from_file_pages = 0;
        region.copied_from_staging_pages = 0;
        region.zeroed_pages = 0;
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
    /// # Arguments
    ///
    /// * `max_size` - the upper limit of the chunk size to write into the swap file at once. The
    ///   chunk is splitted if it is bigger than `max_size`.
    pub fn swap_out(&mut self, max_size: usize) -> Result<usize> {
        let max_pages = bytes_to_pages(max_size);
        for region in self
            .regions
            .iter_mut()
            .filter(|r| r.staging_memory.is_some())
        {
            let staging_memory = region.staging_memory.as_mut().unwrap();

            if let Some(idx_range) = staging_memory.next_data_range(region.staging_cursor) {
                let pages = std::cmp::min(idx_range.end - idx_range.start, max_pages);
                let idx_range = idx_range.start..idx_range.start + pages;
                let slice = staging_memory.get_slice(idx_range.clone())?;
                // Convert VolatileSlice to &[u8]
                // Safe because the range of volatile slice is already validated.
                let slice = unsafe { std::slice::from_raw_parts(slice.as_ptr(), slice.size()) };
                region.file.write_to_file(idx_range.start, slice)?;
                region.staging_cursor = idx_range.end;
                // TODO(kawasin): clear state_list on each write and MADV_REMOVE several chunk at
                // once.
                staging_memory.clear_range(idx_range)?;
                // TODO(kawasin): free the page cache of the swap file.
                // TODO(kawasin): use writev() to swap_out several small chunks at once.
                return Ok(pages);
            } else {
                region.staging_memory = None;
            }
        }
        Ok(0)
    }

    /// Swap in all the content.
    ///
    /// Returns the count of swapped out pages.
    ///
    /// # Arguments
    ///
    /// * `uffd` - the main [Userfaultfd].
    pub fn swap_in(mut self, uffd: &Userfaultfd) -> Result<usize> {
        let mut swapped_size = 0;
        for region in self.regions.iter_mut() {
            let base_addr = page_idx_to_addr(region.head_page_idx);

            if let Some(mut staging_memory) = region.staging_memory.take() {
                while let Some(idx_range) = staging_memory.next_data_range(region.staging_cursor) {
                    let page_addr = base_addr + pages_to_bytes(idx_range.start);
                    let slice = staging_memory.get_slice(idx_range.clone())?;
                    let size = slice.size();
                    Self::copy_all(uffd, page_addr, slice, false)?;
                    region.staging_cursor = idx_range.end;
                    // Clear the staging memory to avoid memory spike.
                    // TODO(kawasin): reduce the call count of MADV_REMOVE by removing several data
                    // at once.
                    staging_memory.clear_range(idx_range)?;
                    swapped_size += size;
                }
            }

            for pages in region.file.all_present_pages() {
                let page_idx = region.head_page_idx + pages.base_idx;
                let page_addr = page_idx_to_addr(page_idx);
                let size = pages.content.size();
                Self::copy_all(uffd, page_addr, pages.content, false)?;
                swapped_size += size;
            }
        }
        Ok(bytes_to_pages(swapped_size))
    }

    /// Returns count of pages active on the memory.
    pub fn compute_resident_pages(&self) -> usize {
        self.regions
            .iter()
            .map(|r| r.copied_from_file_pages + r.copied_from_staging_pages + r.zeroed_pages)
            .sum()
    }

    /// Returns count of pages copied from vmm-swap file to the guest memory.
    pub fn compute_copied_from_file_pages(&self) -> usize {
        self.regions.iter().map(|r| r.copied_from_file_pages).sum()
    }

    /// Returns count of pages copied from staging memory to the guest memory.
    pub fn compute_copied_from_staging_pages(&self) -> usize {
        self.regions
            .iter()
            .map(|r| r.copied_from_staging_pages)
            .sum()
    }

    /// Returns count of pages initialized with zero.
    pub fn compute_zeroed_pages(&self) -> usize {
        self.regions.iter().map(|r| r.zeroed_pages).sum()
    }

    /// Returns count of pages which were already initialized on page faults.
    pub fn compute_redundant_pages(&self) -> usize {
        self.regions.iter().map(|r| r.redundant_pages).sum()
    }

    /// Returns count of pages present in the staging memory.
    pub fn compute_staging_pages(&self) -> usize {
        self.regions
            .iter()
            .map(|r| r.staging_memory.as_ref().map_or(0, |sm| sm.present_pages()))
            .sum()
    }

    /// Returns count of pages present in the swap files.
    pub fn compute_swap_pages(&self) -> usize {
        let mut swapped_size = 0;
        for r in self.regions.iter() {
            for pages in r.file.all_present_pages() {
                swapped_size += pages.content.size();
            }
        }
        bytes_to_pages(swapped_size)
    }
}
