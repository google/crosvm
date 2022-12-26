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

/// [Region] represents a memory region and corresponding [SwapFile].
struct Region {
    /// the head page index of the region.
    head_page_idx: usize,
    file: SwapFile,
    copied_pages: usize,
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
    /// # Arguments
    ///
    /// * `swap_dir` - path to the directory to create a swap file from.
    /// * `regions` - the list of the region. the start address must align with page. the size must
    ///   be multiple of pagesize.
    pub fn create(swap_dir: &Path, regions: &[Range<usize>]) -> Result<Self> {
        let mut handler = Self {
            regions: Vec::new(),
        };

        for address_range in regions {
            handler.add_region(swap_dir, address_range)?;
        }

        Ok(handler)
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

    /// Create a new internal context to handle userfaultfd events and swap in/out request.
    ///
    /// If the regions overlaps an existing region, it returns [Error::RegionOverlap].
    ///
    /// # Arguments
    ///
    /// * `swap_dir` - path to the directory to create a swap file from.
    /// * `address_range` - the range of the region. the start address must align with page. the
    ///   size must be multiple of pagesize.
    fn add_region(&mut self, swap_dir: &Path, address_range: &Range<usize>) -> Result<()> {
        let head_page_idx = addr_to_page_idx(address_range.start);
        let region_size = address_range.end - address_range.start;
        let num_of_pages = bytes_to_pages(region_size);

        // find an overlaping region
        match self.regions.iter().position(|region| {
            if region.head_page_idx < head_page_idx {
                region.head_page_idx + region.file.num_pages() > head_page_idx
            } else {
                region.head_page_idx < head_page_idx + num_of_pages
            }
        }) {
            Some(i) => {
                let region = &self.regions[i];

                Err(Error::RegionOverlap(
                    address_range.clone(),
                    page_idx_to_addr(region.head_page_idx)
                        ..(page_idx_to_addr(region.head_page_idx + region.file.num_pages())),
                ))
            }
            None => {
                let base_addr = address_range.start;
                assert!(is_page_aligned(base_addr));
                assert!(is_page_aligned(region_size));

                let file = SwapFile::new(swap_dir, num_of_pages)?;
                self.regions.push(Region {
                    head_page_idx,
                    file,
                    copied_pages: 0,
                    zeroed_pages: 0,
                    redundant_pages: 0,
                    swap_active: false,
                });
                Ok(())
            }
        }
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
        let Region {
            head_page_idx,
            file,
            copied_pages,
            zeroed_pages,
            redundant_pages,
            ..
        } = self
            .find_region(page_idx)
            .ok_or(Error::InvalidAddress(address))?;

        let idx_in_region = page_idx - *head_page_idx;
        match file.page_content(idx_in_region)? {
            Some(page_slice) => {
                Self::copy_all(uffd, page_addr, page_slice, true)?;
                file.clear(idx_in_region)?;
                *copied_pages += 1;
                Ok(())
            }
            None => {
                // Map a zero page since no swap file has been created yet but the fault happened.
                // safe because the fault page is notified by uffd.
                let result = uffd.zero(page_addr, page_size, true);
                match result {
                    Ok(_) => {
                        *zeroed_pages += 1;
                        Ok(())
                    }
                    Err(UffdError::ZeropageFailed(errno)) if errno as i32 == libc::EEXIST => {
                        // zeroing fails with EEXIST if the page is already filled. This case can
                        // happen if page faults on the same page happen on different processes.
                        uffd.wake(page_addr, page_size)?;
                        *redundant_pages += 1;
                        Ok(())
                    }
                    Err(e) => Err(e.into()),
                }
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

    /// Write active pages in the memory region to the swap file.
    ///
    /// It only writes active contents in the guest memory to the swap file and skips empty
    /// pages (e.g. pages not touched, freed by balloon) using `lseek(2)` + `SEEK_HOLE/DATA`.
    ///
    /// The memory must be protected not to be updated during swapped out.
    ///
    /// Returns the count of swapped out pages.
    ///
    /// # Arguments
    ///
    /// * `base_addr` - the head address of the memory region to swap out.
    /// * `memfd` - the file descriptor of the memfd backing the guest memory region.
    /// * `base_offset` - the offset of the memory region in the memfd.
    ///
    /// # Safety
    ///
    /// The region must have been registered to all userfaultfd of processes which may touch the
    /// region.
    ///
    /// The page fault events for the region from the userfaultfd must be handled by
    /// [PageHandler::handle_page_fault].
    #[deny(unsafe_op_in_unsafe_fn)]
    pub unsafe fn swap_out<T>(
        &mut self,
        base_addr: usize,
        memfd: &T,
        base_offset: u64,
    ) -> Result<usize>
    where
        T: AsRawDescriptor,
    {
        let head_page_idx = addr_to_page_idx(base_addr);
        // use find_region_position instead of find_region() due to borrow checker.
        let region_position = self
            .find_region_position(head_page_idx)
            .ok_or(Error::InvalidAddress(base_addr))?;
        if self.regions[region_position].head_page_idx != head_page_idx {
            return Err(Error::InvalidAddress(base_addr));
        }
        let region_size = pages_to_bytes(self.regions[region_position].file.num_pages());
        let file_data = FileDataIterator::new(memfd, base_offset, region_size as u64);

        let mut swapped_size = 0;
        for data_range in file_data {
            // assert offset is page aligned
            let offset = (data_range.start - base_offset) as usize;
            assert!(is_page_aligned(offset));
            let addr = base_addr + offset;
            let page_idx = addr_to_page_idx(addr);
            let size = (data_range.end - data_range.start) as usize;
            assert!(is_page_aligned(size));
            // safe because the page is within the range of the guest memory.
            let mem_slice = unsafe { std::slice::from_raw_parts(addr as *const u8, size) };
            self.regions[region_position]
                .file
                .write_to_file(page_idx - head_page_idx, mem_slice)?;
            swapped_size += size;
            // TODO(kawasin): periodically MADV_REMOVE the guest memory. if the pages are in zram,
            // it increases the RAM usage during swap_out.
            // TODO(kawasin): free the page cache of the swap file. or direct I/O.
        }

        // safe because the region is already backed by the file and the content will be swapped in
        // on a page fault.
        unsafe {
            libc::madvise(
                base_addr as *mut libc::c_void,
                region_size,
                libc::MADV_REMOVE,
            );
        }
        let swapped_pages = bytes_to_pages(swapped_size);
        let mut region = &mut self.regions[region_position];
        // Suppress error log on the first swap_out, since page counts are not initialized but
        // zero.
        if region.swap_active && swapped_pages != (region.copied_pages + region.zeroed_pages) {
            error!(
                "swapped pages ({}) does not match with resident pages (copied: {}, zeroed: {}).",
                swapped_pages, region.copied_pages, region.zeroed_pages
            );
        }
        region.copied_pages = 0;
        region.zeroed_pages = 0;
        region.redundant_pages = 0;
        region.swap_active = true;

        Ok(swapped_pages)
    }

    /// Swap in all the content.
    ///
    /// Returns the count of swapped out pages.
    ///
    /// # Arguments
    ///
    /// * `uffd` - the main [Userfaultfd].
    pub fn swap_in(self, uffd: &Userfaultfd) -> Result<usize> {
        let mut swapped_size = 0;
        for region in self.regions.iter() {
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
            .map(|r| r.copied_pages + r.zeroed_pages)
            .sum()
    }

    /// Returns count of pages copied from vmm-swap file on the memory.
    pub fn compute_copied_pages(&self) -> usize {
        self.regions.iter().map(|r| r.copied_pages).sum()
    }

    /// Returns count of pages initialized with zero.
    pub fn compute_zeroed_pages(&self) -> usize {
        self.regions.iter().map(|r| r.zeroed_pages).sum()
    }

    /// Returns count of pages which were already initialized on page faults.
    pub fn compute_redundant_pages(&self) -> usize {
        self.regions.iter().map(|r| r.redundant_pages).sum()
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
