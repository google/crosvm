// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use std::ops::Range;
use std::path::Path;

use base::error;
use base::pagesize;
use base::unix::FileDataIterator;
use base::AsRawDescriptor;
use thiserror::Error as ThisError;

use crate::file::Error as FileError;
use crate::file::SwapFile;
use crate::userfaultfd::UffdError;
use crate::userfaultfd::Userfaultfd;

/// Result for PageHandler
pub type Result<T> = std::result::Result<T, Error>;

/// Errors for PageHandler
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("the address is invalid {0:#018X}")]
    InvalidAddress(usize),
    #[error("the regions {0:?} and {1:?} overlap")]
    RegionOverlap(Range<usize>, Range<usize>),
    #[error("file operation failed : {0:?}")]
    File(FileError),
    #[error("userfaultfd failed : {0:?}")]
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
    head_page_idx: usize,
    file: SwapFile,
}

impl Region {
    /// the number of pages in the region.
    pub fn len(&self) -> usize {
        self.file.len()
    }
}

/// PageHandler manages the page states of multiple regions.
///
/// Handles multiple events derived from userfaultfd and swap out requests.
/// All the addresses and sizes in bytes are converted to page id internally.
pub struct PageHandler {
    regions: Vec<Region>,
    pagesize_shift: u32,
}

impl PageHandler {
    /// Creates [PageHandler] with no pages registered.
    ///
    /// # Arguments
    ///
    /// * `uffd` - the reference to the [Userfaultfd] for the main process.
    /// * `swap_dir` - path to the directory to create a swap file from.
    /// * `regions` - the list of the region. the start address must align with page. the size must
    ///   be multiple of pagesize.
    ///
    /// # Safety
    ///
    /// Each address range in `regions` must be from guest memory.
    #[deny(unsafe_op_in_unsafe_fn)]
    pub unsafe fn new(
        uffd: &Userfaultfd,
        swap_dir: &Path,
        regions: &Vec<Range<usize>>,
    ) -> Result<Self> {
        let pagesize_shift = pagesize().trailing_zeros();
        // pagesize() should be power of 2 in almost all cases. vmm-swap feature does not support
        // systems in which page size is not power of 2.
        if 1 << pagesize_shift != pagesize() {
            panic!("page size is not power of 2");
        }

        let mut handler = Self {
            regions: Vec::new(),
            pagesize_shift,
        };

        for address_range in regions.iter() {
            // safe because `address_range` in `regions` are from guest memory.
            unsafe {
                handler.register_region(uffd, swap_dir, address_range)?;
            }
        }

        Ok(handler)
    }

    /// The page index of the page which contains the "addr".
    fn addr_to_page_idx(&self, addr: usize) -> usize {
        addr >> self.pagesize_shift
    }

    /// The head address of the page.
    fn page_idx_to_addr(&self, page_idx: usize) -> usize {
        page_idx << self.pagesize_shift
    }

    /// The head address of the page which contains the "addr".
    fn page_base_addr(&self, addr: usize) -> usize {
        (addr >> self.pagesize_shift) << self.pagesize_shift
    }

    fn is_page_aligned(&self, addr: usize) -> bool {
        let mask = (1 << self.pagesize_shift) - 1;
        addr & mask == 0
    }

    fn find_region_position(&self, page_idx: usize) -> Option<usize> {
        // sequential search the corresponding page map from the list. It should be fast enough
        // because there are a few regions (usually only 1).
        self.regions.iter().position(|region| {
            region.head_page_idx <= page_idx && page_idx < region.head_page_idx + region.len()
        })
    }

    fn find_region(&mut self, page_idx: usize) -> Option<&mut Region> {
        self.find_region_position(page_idx)
            .map(|i| &mut self.regions[i])
    }

    /// Register the memory region to userfaultfd and create a new internal context to handle
    /// userfaultfd events and swap out request.
    ///
    /// If the regions overlaps an existing region, it returns [Error::RegionOverlap].
    ///
    /// # Arguments
    ///
    /// * `uffd` - the reference to the [Userfaultfd] for the main process.
    /// * `swap_dir` - path to the directory to create a swap file from.
    /// * `address_range` - the range of the region. the start address must align with page. the
    ///   size must be multiple of pagesize.
    ///
    /// # Safety
    ///
    /// The `address_range` must be from guest memory.
    #[deny(unsafe_op_in_unsafe_fn)]
    unsafe fn register_region(
        &mut self,
        uffd: &Userfaultfd,
        swap_dir: &Path,
        address_range: &Range<usize>,
    ) -> Result<()> {
        let head_page_idx = self.addr_to_page_idx(address_range.start);
        let region_size = address_range.end - address_range.start;
        let num_of_pages = region_size >> self.pagesize_shift;

        // find an overlaping region
        match self.regions.iter().position(|region| {
            if region.head_page_idx < head_page_idx {
                region.head_page_idx + region.len() > head_page_idx
            } else {
                region.head_page_idx < head_page_idx + num_of_pages
            }
        }) {
            Some(i) => {
                let region = &self.regions[i];

                Err(Error::RegionOverlap(
                    address_range.clone(),
                    self.page_idx_to_addr(region.head_page_idx)
                        ..(self.page_idx_to_addr(region.head_page_idx + region.len())),
                ))
            }
            None => {
                let base_addr = address_range.start;
                assert!(self.is_page_aligned(base_addr));
                assert!(self.is_page_aligned(region_size));

                let file = SwapFile::new(swap_dir, num_of_pages)?;
                // safe because the range is from the guest memory region. Even after the memory is
                // removed by `MADV_REMOVE` at [PageHandler::swap_out()], the content will be
                // swapped in from the swap file safely on a page fault.
                unsafe {
                    uffd.register(base_addr, region_size)?;
                }
                self.regions.push(Region {
                    head_page_idx,
                    file,
                });
                Ok(())
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
        let page_idx = self.addr_to_page_idx(address);
        // the head address of the page.
        let page_addr = self.page_base_addr(address);
        let Region {
            head_page_idx,
            file,
        } = self
            .find_region(page_idx)
            .ok_or(Error::InvalidAddress(address))?;

        let idx_in_region = page_idx - *head_page_idx;
        let page_content = file.page_content(idx_in_region)?;

        match page_content {
            Some(file_content) => {
                let mut data_slice = file_content.get_page()?;
                loop {
                    // safe because the fault page is notified by uffd.
                    let result = uffd.copy(page_addr, data_slice.size(), data_slice.as_ptr(), true);
                    match result {
                        Ok(_) => {
                            break;
                        }
                        Err(UffdError::PartiallyCopied(copied)) => {
                            data_slice.advance(copied);
                        }
                        Err(e) => {
                            // Even EEXIST for copy operation should be an error for page fault
                            // handling. If the page was swapped in before, the page should be
                            // cleared from the swap file and do `Userfaultfd::zero()` instead.
                            return Err(e.into());
                        }
                    }
                }
                file.clear(idx_in_region)?;
                Ok(())
            }
            None => {
                // Map a zero page since no swap file has been created yet but the fault happened.
                // safe because the fault page is notified by uffd.
                let result = uffd.zero(page_addr, 1 << self.pagesize_shift, true);
                match result {
                    Ok(_) => Ok(()),
                    Err(UffdError::ZeropageFailed(errno)) if errno as i32 == libc::EEXIST => {
                        // zeroing fails with EEXIST if the page is already filled. This case can
                        // happen if page faults on the same page happen on different processes.
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
        if !self.is_page_aligned(start_addr) {
            return Err(Error::InvalidAddress(start_addr));
        } else if !self.is_page_aligned(end_addr) {
            return Err(Error::InvalidAddress(end_addr));
        }
        let start_page_idx = self.addr_to_page_idx(start_addr);
        let last_page_idx = self.addr_to_page_idx(end_addr);
        for page_idx in start_page_idx..(last_page_idx) {
            let page_addr = self.page_idx_to_addr(page_idx);
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
    /// # Arguments
    ///
    /// * `region` - the memory region context to swap out.
    /// * `memfd` - the file descriptor of the memfd backing the guest memory region.
    /// * `base_offset` - the offset of the memory region in the memfd.
    pub fn swap_out<T>(&mut self, base_addr: usize, memfd: &T, base_offset: u64) -> Result<()>
    where
        T: AsRawDescriptor,
    {
        let head_page_idx = self.addr_to_page_idx(base_addr);
        // use find_region_position instead of find_region() due to borrow checker.
        let region_position = self
            .find_region_position(head_page_idx)
            .ok_or(Error::InvalidAddress(base_addr))?;
        if self.regions[region_position].head_page_idx != head_page_idx {
            return Err(Error::InvalidAddress(base_addr));
        }
        let region_size = self.regions[region_position].len() << self.pagesize_shift;
        let file_data = FileDataIterator::new(memfd, base_offset);

        for data_range in file_data {
            // assert offset is page aligned
            let offset = (data_range.start - base_offset) as usize;
            assert!(self.is_page_aligned(offset));
            let addr = base_addr + offset;
            let page_idx = self.addr_to_page_idx(addr);
            let size = (data_range.end - data_range.start) as usize;
            assert!(self.is_page_aligned(size));
            // safe because the page is within the range of the guest memory.
            let mem_slice = unsafe { std::slice::from_raw_parts(addr as *const u8, size) };
            self.regions[region_position]
                .file
                .write_to_file(page_idx - head_page_idx, mem_slice)?
            // TODO(kawasin): periodically MADV_REMOVE the guest memory. if the pages are in zram,
            // it increases the RAM usage during swap_out.
            // TODO(kawasin): free the page cache of the swap file. or direct I/O.
        }

        // safe because the memory area is already backed by the file and the content will be
        // swapped in on a page fault.
        unsafe {
            libc::madvise(
                base_addr as *mut libc::c_void,
                region_size,
                libc::MADV_REMOVE,
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use userfaultfd::UffdBuilder;

    use std::thread;
    use std::time;

    use base::MemoryMappingBuilder;
    use base::SharedMemory;
    use data_model::VolatileMemory;

    use crate::userfaultfd::Userfaultfd;

    fn create_uffd_for_test() -> Userfaultfd {
        UffdBuilder::new()
            .non_blocking(false)
            .create()
            .unwrap()
            .into()
    }

    #[test]
    fn register_region_success() {
        let dir_path = tempfile::tempdir().unwrap().into_path();
        let mmap = MemoryMappingBuilder::new(6 * pagesize()).build().unwrap();
        let uffd: Userfaultfd = create_uffd_for_test();
        let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;

        let result = unsafe {
            PageHandler::new(
                &uffd,
                &dir_path,
                &vec![
                    base_addr..(base_addr + 3 * pagesize()),
                    (base_addr + 3 * pagesize())..(base_addr + 6 * pagesize()),
                ],
            )
        };

        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn register_region_partially_overlap() {
        let dir_path = tempfile::tempdir().unwrap().into_path();
        let mmap = MemoryMappingBuilder::new(3 * pagesize()).build().unwrap();
        let uffd: Userfaultfd = create_uffd_for_test();
        let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;

        for range in [
            // the same address range
            base_addr..(base_addr + 3 * pagesize()),
            // left of the existing region overlaps
            (base_addr - pagesize())..(base_addr + pagesize()),
            // new region is inside
            (base_addr + pagesize())..(base_addr + 2 * pagesize()),
            // right of the existing region overlaps
            (base_addr + 2 * pagesize())..(base_addr + 4 * pagesize()),
            // new region covers whole the existing region
            (base_addr - pagesize())..(base_addr + 4 * pagesize()),
        ] {
            let result = unsafe {
                PageHandler::new(
                    &uffd,
                    &dir_path,
                    &vec![base_addr..(base_addr + 3 * pagesize()), range],
                )
            };
            assert_eq!(result.is_err(), true);
            match result {
                Err(Error::RegionOverlap(_, _)) => {}
                _ => {
                    unreachable!("not overlap")
                }
            }
        }
    }

    fn wait_thread_with_timeout<T>(join_handle: thread::JoinHandle<T>, timeout_millis: u64) -> T {
        for _ in 0..timeout_millis {
            if join_handle.is_finished() {
                return join_handle.join().unwrap();
            }
            thread::sleep(time::Duration::from_millis(1));
        }
        panic!("thread join timeout");
    }

    #[test]
    fn handle_page_fault_success() {
        let dir_path = tempfile::tempdir().unwrap().into_path();
        let mmap = MemoryMappingBuilder::new(3 * pagesize()).build().unwrap();
        let uffd: Userfaultfd = create_uffd_for_test();
        let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
        let mut page_handler = unsafe {
            PageHandler::new(
                &uffd,
                &dir_path,
                &vec![base_addr..(base_addr + 3 * pagesize())],
            )
        }
        .unwrap();

        page_handler
            .handle_page_fault(&uffd, base_addr as usize)
            .unwrap();
        page_handler
            .handle_page_fault(
                &uffd,
                mmap.get_ref::<u8>(pagesize() + 1).unwrap().as_mut_ptr() as usize,
            )
            .unwrap();
        page_handler
            .handle_page_fault(
                &uffd,
                mmap.get_ref::<u8>(3 * pagesize() - 1).unwrap().as_mut_ptr() as usize,
            )
            .unwrap();

        // read values on another thread to avoid blocking forever
        let join_handle = thread::spawn(move || {
            let mut result = Vec::new();
            for i in 0..(3 * pagesize()) {
                let ptr = mmap.get_ref::<u8>(i).unwrap().as_mut_ptr();
                unsafe {
                    result.push(*ptr);
                }
            }
            result
        });

        let result = wait_thread_with_timeout(join_handle, 100);

        assert_eq!(result, vec![0; 3 * pagesize()]);
    }

    #[test]
    fn handle_page_fault_invalid_address() {
        let dir_path = tempfile::tempdir().unwrap().into_path();
        let mmap = MemoryMappingBuilder::new(3 * pagesize()).build().unwrap();
        let uffd: Userfaultfd = create_uffd_for_test();
        let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
        let mut page_handler = unsafe {
            PageHandler::new(
                &uffd,
                &dir_path,
                &vec![base_addr..(base_addr + 3 * pagesize())],
            )
        }
        .unwrap();

        assert_eq!(
            page_handler
                .handle_page_fault(&uffd, (base_addr as usize) - 1)
                .is_err(),
            true
        );
        assert_eq!(
            page_handler
                .handle_page_fault(&uffd, (base_addr as usize) + 3 * pagesize())
                .is_err(),
            true
        );
    }

    #[test]
    fn handle_page_fault_duplicated_page_fault() {
        let dir_path = tempfile::tempdir().unwrap().into_path();
        let mmap = MemoryMappingBuilder::new(3 * pagesize()).build().unwrap();
        let uffd: Userfaultfd = create_uffd_for_test();
        let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
        let mut page_handler = unsafe {
            PageHandler::new(
                &uffd,
                &dir_path,
                &vec![base_addr..(base_addr + 3 * pagesize())],
            )
        }
        .unwrap();

        assert_eq!(
            page_handler
                .handle_page_fault(&uffd, base_addr as usize)
                .is_ok(),
            true
        );
        assert_eq!(
            page_handler
                .handle_page_fault(&uffd, (base_addr as usize) + 1)
                .is_ok(),
            true
        );
    }

    #[test]
    fn handle_page_remove_success() {
        let dir_path = tempfile::tempdir().unwrap().into_path();
        let mmap = MemoryMappingBuilder::new(3 * pagesize()).build().unwrap();
        let uffd: Userfaultfd = create_uffd_for_test();
        let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
        let mut page_handler = unsafe {
            PageHandler::new(
                &uffd,
                &dir_path,
                &vec![base_addr..(base_addr + 3 * pagesize())],
            )
        }
        .unwrap();

        // fill the first page with zero
        page_handler
            .handle_page_fault(&uffd, base_addr as usize)
            .unwrap();
        // write value on another thread to avoid blocking forever
        let base_addr_usize = base_addr as usize;
        let join_handle = thread::spawn(move || {
            let base_addr = base_addr_usize as *mut u8;
            unsafe {
                *base_addr = 1;
            }
        });
        wait_thread_with_timeout(join_handle, 100);
        let second_page_addr = mmap.get_ref::<u8>(pagesize()).unwrap().as_mut_ptr();
        page_handler
            .handle_page_remove(base_addr as usize, second_page_addr as usize)
            .unwrap();
        unsafe {
            libc::madvise(
                base_addr as *mut libc::c_void,
                pagesize(),
                libc::MADV_REMOVE,
            );
        }
        // fill the first page with zero again
        page_handler
            .handle_page_fault(&uffd, base_addr as usize)
            .unwrap();
        // read value on another thread to avoid blocking forever
        let join_handle = thread::spawn(move || {
            let base_addr = base_addr_usize as *mut u8;
            unsafe { *base_addr }
        });

        assert_eq!(wait_thread_with_timeout(join_handle, 100), 0);
    }

    #[test]
    fn handle_page_remove_invalid_address() {
        let dir_path = tempfile::tempdir().unwrap().into_path();
        let mmap = MemoryMappingBuilder::new(3 * pagesize()).build().unwrap();
        let uffd: Userfaultfd = create_uffd_for_test();
        let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
        let mut page_handler = unsafe {
            PageHandler::new(
                &uffd,
                &dir_path,
                &vec![base_addr..(base_addr + 3 * pagesize())],
            )
        }
        .unwrap();

        page_handler
            .handle_page_fault(&uffd, base_addr as usize)
            .unwrap();
        page_handler
            .handle_page_fault(&uffd, (base_addr as usize) + pagesize())
            .unwrap();
        page_handler
            .handle_page_fault(&uffd, (base_addr as usize) + 2 * pagesize())
            .unwrap();
        assert_eq!(
            page_handler
                .handle_page_remove(
                    (base_addr as usize) - 1,
                    (base_addr as usize) + 3 * pagesize()
                )
                .is_err(),
            true
        );
        assert_eq!(
            page_handler
                .handle_page_remove(
                    base_addr as usize,
                    (base_addr as usize) + 3 * pagesize() + 1
                )
                .is_err(),
            true
        );
        // remove for whole region should succeed.
        assert_eq!(
            page_handler
                .handle_page_remove(base_addr as usize, (base_addr as usize) + 3 * pagesize())
                .is_ok(),
            true
        );
    }

    #[test]
    fn swap_out_success() {
        let uffd: Userfaultfd = create_uffd_for_test();
        let dir_path = tempfile::tempdir().unwrap().into_path();
        let shm1 = SharedMemory::new("shm1", 3 * pagesize() as u64).unwrap();
        let mmap1 = MemoryMappingBuilder::new(3 * pagesize())
            .from_shared_memory(&shm1)
            .build()
            .unwrap();
        let base_addr1 = mmap1.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
        let shm2 = SharedMemory::new("shm2", 3 * pagesize() as u64).unwrap();
        let mmap2 = MemoryMappingBuilder::new(3 * pagesize())
            .from_shared_memory(&shm2)
            .build()
            .unwrap();
        let base_addr2 = mmap2.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
        let mut page_handler = unsafe {
            PageHandler::new(
                &uffd,
                &dir_path,
                &vec![
                    base_addr1..(base_addr1 + 3 * pagesize()),
                    base_addr2..(base_addr2 + 3 * pagesize()),
                ],
            )
        }
        .unwrap();

        page_handler.handle_page_fault(&uffd, base_addr1).unwrap();
        page_handler
            .handle_page_fault(&uffd, (base_addr1) + 2 * pagesize())
            .unwrap();
        page_handler.handle_page_fault(&uffd, base_addr2).unwrap();
        page_handler
            .handle_page_fault(&uffd, (base_addr2) + 2 * pagesize())
            .unwrap();
        // write values on another thread to avoid blocking forever
        let base_addr1_usize = base_addr1;
        let base_addr2_usize = base_addr2;
        let join_handle = thread::spawn(move || {
            for i in 0..pagesize() {
                let ptr = (base_addr1_usize + i) as *mut u8;
                unsafe {
                    *ptr = 1;
                }
            }
            for i in 0..pagesize() {
                let ptr = (base_addr1_usize + 2 * pagesize() + i) as *mut u8;
                unsafe {
                    *ptr = 2;
                }
            }
            for i in 0..pagesize() {
                let ptr = (base_addr2_usize + i) as *mut u8;
                unsafe {
                    *ptr = 3;
                }
            }
            for i in 0..pagesize() {
                let ptr = (base_addr2_usize + 2 * pagesize() + i) as *mut u8;
                unsafe {
                    *ptr = 4;
                }
            }
        });
        wait_thread_with_timeout(join_handle, 100);
        page_handler.swap_out(base_addr1, &shm1, 0).unwrap();
        page_handler.swap_out(base_addr2, &shm2, 0).unwrap();

        // page faults on all pages. page 0 and page 2 will be swapped in from the file. page 1 will
        // be filled with zero.
        for i in 0..3 {
            page_handler
                .handle_page_fault(&uffd, (base_addr1) + i * pagesize())
                .unwrap();
            page_handler
                .handle_page_fault(&uffd, (base_addr2) + i * pagesize())
                .unwrap();
        }
        // read values on another thread to avoid blocking forever
        let join_handle = thread::spawn(move || {
            let mut result = Vec::new();
            for i in 0..3 {
                for j in 0..pagesize() {
                    let ptr = (base_addr1_usize + i * pagesize() + j) as *mut u8;
                    unsafe {
                        result.push(*ptr);
                    }
                }
            }
            for i in 0..3 {
                for j in 0..pagesize() {
                    let ptr = (base_addr2_usize + i * pagesize() + j) as *mut u8;
                    unsafe {
                        result.push(*ptr);
                    }
                }
            }
            result
        });
        let result = wait_thread_with_timeout(join_handle, 100);
        let values: Vec<u8> = vec![1, 0, 2, 3, 0, 4];
        for (i, v) in values.iter().enumerate() {
            for j in 0..pagesize() {
                assert_eq!(&result[i * pagesize() + j], v);
            }
        }
    }

    #[test]
    fn swap_out_twice() {
        let uffd: Userfaultfd = create_uffd_for_test();
        let dir_path = tempfile::tempdir().unwrap().into_path();
        let shm1 = SharedMemory::new("shm1", 3 * pagesize() as u64).unwrap();
        let mmap1 = MemoryMappingBuilder::new(3 * pagesize())
            .from_shared_memory(&shm1)
            .build()
            .unwrap();
        let base_addr1 = mmap1.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
        let shm2 = SharedMemory::new("shm2", 3 * pagesize() as u64).unwrap();
        let mmap2 = MemoryMappingBuilder::new(3 * pagesize())
            .from_shared_memory(&shm2)
            .build()
            .unwrap();
        let base_addr2 = mmap2.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
        let mut page_handler = unsafe {
            PageHandler::new(
                &uffd,
                &dir_path,
                &vec![
                    base_addr1..(base_addr1 + 3 * pagesize()),
                    base_addr2..(base_addr2 + 3 * pagesize()),
                ],
            )
        }
        .unwrap();

        page_handler.handle_page_fault(&uffd, base_addr1).unwrap();
        page_handler
            .handle_page_fault(&uffd, (base_addr1) + 2 * pagesize())
            .unwrap();
        page_handler.handle_page_fault(&uffd, base_addr2).unwrap();
        page_handler
            .handle_page_fault(&uffd, (base_addr2) + 2 * pagesize())
            .unwrap();
        // write values on another thread to avoid blocking forever
        let base_addr1_usize = base_addr1;
        let base_addr2_usize = base_addr2;
        let join_handle = thread::spawn(move || {
            for i in 0..pagesize() {
                let ptr = (base_addr1_usize + i) as *mut u8;
                unsafe {
                    *ptr = 1;
                }
            }
            for i in 0..pagesize() {
                let ptr = (base_addr1_usize + 2 * pagesize() + i) as *mut u8;
                unsafe {
                    *ptr = 2;
                }
            }
            for i in 0..pagesize() {
                let ptr = (base_addr2_usize + i) as *mut u8;
                unsafe {
                    *ptr = 3;
                }
            }
            for i in 0..pagesize() {
                let ptr = (base_addr2_usize + 2 * pagesize() + i) as *mut u8;
                unsafe {
                    *ptr = 4;
                }
            }
        });
        wait_thread_with_timeout(join_handle, 100);
        page_handler.swap_out(base_addr1, &shm1, 0).unwrap();
        page_handler.swap_out(base_addr2, &shm2, 0).unwrap();
        // page faults on all pages in mmap1.
        for i in 0..3 {
            page_handler
                .handle_page_fault(&uffd, (base_addr1) + i * pagesize())
                .unwrap();
        }
        let join_handle = thread::spawn(move || {
            for i in 0..pagesize() {
                let ptr = (base_addr1_usize + pagesize() + i) as *mut u8;
                unsafe {
                    *ptr = 5;
                }
            }
            for i in 0..pagesize() {
                let ptr = (base_addr1_usize + 2 * pagesize() + i) as *mut u8;
                unsafe {
                    *ptr = 6;
                }
            }
        });
        wait_thread_with_timeout(join_handle, 100);
        page_handler.swap_out(base_addr1, &shm1, 0).unwrap();
        page_handler.swap_out(base_addr2, &shm2, 0).unwrap();

        // page faults on all pages.
        for i in 0..3 {
            page_handler
                .handle_page_fault(&uffd, (base_addr1) + i * pagesize())
                .unwrap();
            page_handler
                .handle_page_fault(&uffd, (base_addr2) + i * pagesize())
                .unwrap();
        }
        // read values on another thread to avoid blocking forever
        let join_handle = thread::spawn(move || {
            let mut result = Vec::new();
            for i in 0..3 {
                for j in 0..pagesize() {
                    let ptr = (base_addr1_usize + i * pagesize() + j) as *mut u8;
                    unsafe {
                        result.push(*ptr);
                    }
                }
            }
            for i in 0..3 {
                for j in 0..pagesize() {
                    let ptr = (base_addr2_usize + i * pagesize() + j) as *mut u8;
                    unsafe {
                        result.push(*ptr);
                    }
                }
            }
            result
        });
        let result = wait_thread_with_timeout(join_handle, 100);
        let values: Vec<u8> = vec![1, 5, 6, 3, 0, 4];
        for (i, v) in values.iter().enumerate() {
            for j in 0..pagesize() {
                assert_eq!(&result[i * pagesize() + j], v);
            }
        }
    }

    #[test]
    fn swap_out_invalid_base_addr() {
        let uffd: Userfaultfd = create_uffd_for_test();
        let dir_path = tempfile::tempdir().unwrap().into_path();
        let shm = SharedMemory::new("shm1", 3 * pagesize() as u64).unwrap();
        let mmap = MemoryMappingBuilder::new(3 * pagesize())
            .from_shared_memory(&shm)
            .build()
            .unwrap();
        let base_addr = mmap.get_ref::<u8>(0).unwrap().as_mut_ptr() as usize;
        let mut page_handler = unsafe {
            PageHandler::new(
                &uffd,
                &dir_path,
                &vec![base_addr..(base_addr + 3 * pagesize())],
            )
        }
        .unwrap();

        // the base_addr is within the region
        assert_eq!(
            page_handler
                .swap_out(base_addr + pagesize(), &shm, 0)
                .is_err(),
            true
        );
        // the base_addr is outside of the region
        assert_eq!(
            page_handler
                .swap_out(base_addr - pagesize(), &shm, 0)
                .is_err(),
            true
        );
    }
}
