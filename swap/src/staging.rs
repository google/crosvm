// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use std::ops::Range;
use std::ptr::copy_nonoverlapping;

use base::error;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::MemoryMappingUnix;
use base::MmapError;
use base::SharedMemory;
use data_model::VolatileMemory;
use data_model::VolatileMemoryError;
use data_model::VolatileSlice;
use thiserror::Error as ThisError;

use crate::pagesize::pages_to_bytes;
use crate::present_list::PresentList;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("failed to mmap operation: {0}")]
    Mmap(MmapError),
    #[error("failed to volatile memory operation: {0}")]
    VolatileMemory(VolatileMemoryError),
    #[error("index is out of range")]
    OutOfRange,
}

impl From<MmapError> for Error {
    fn from(e: MmapError) -> Self {
        Self::Mmap(e)
    }
}

impl From<VolatileMemoryError> for Error {
    fn from(e: VolatileMemoryError) -> Self {
        Self::VolatileMemory(e)
    }
}

/// Copy operation from the guest memory to the staging memory.
pub struct CopyOp {
    src_addr: *const u8,
    dst_addr: *mut u8,
    size: usize,
}

/// CopyOp is safe to be sent to other threads because:
///   * The source memory region (guest memory) is alive for the monitor process lifetime.
///   * The destination memory region (staging memory) is alive until all the [CopyOp] are executed.
///   * [CopyOp] accesses both src/dst memory region exclusively.
unsafe impl Send for CopyOp {}

impl CopyOp {
    /// Copies the specified the guest memory to the staging memory.
    pub fn execute(self) {
        // Safe because:
        // * the source memory is in guest memory and no processes access it.
        // * src_addr and dst_addr are aligned with the page size.
        // * src and dst does not overlap since src_addr is from the guest memory and dst_addr
        //   is from the staging memory.
        unsafe {
            copy_nonoverlapping(self.src_addr, self.dst_addr, self.size);
        }
    }
}

/// [StagingMemory] stores active pages from the guest memory in anonymous private memory.
///
/// [StagingMemory] is created per memory region.
///
/// On `crosvm swap enable` command, the monitor process moves all the active pages in the guest
/// memory to this staging memory. [StagingMemory] has several advantages over writing all
/// pages from the guest memory to the swap file directly.
///
/// * Less non-responsive time
///   * While moving the guest memory pages, the monitor process have to freeze whole crosvm
///   * processes to guarantee no updates on the guest memory. Moving memory is faster than writing
///   * them to disk.
/// * Hot pages bypass the disk
///   * The faulting pages between `crosvm swap enable` and `crosvm swap out` are swapped in from
///   * this [StagingMemory] directly without written into the swap file. This saves disk resouces
///   * and latency of page fault handling.
///
/// NB: Staging memory is a memfd instead of private anonymous memory to match GuestMemory. This is
/// done to make accounting easier when calculating total guest memory consumption.
pub struct StagingMemory {
    mmap: MemoryMapping,
    // Tracks which pages are present, indexed by page index within the memory region.
    present_list: PresentList,
}

impl StagingMemory {
    /// Creates [StagingMemory].
    ///
    /// # Arguments
    ///
    /// * `shmem` - [SharedMemory] to mmap from.
    /// * `offset_bytes` - The offset in bytes from the head of the `shmem`.
    /// * `num_of_pages` - The number of pages in the region.
    pub fn new(shmem: &SharedMemory, offset_bytes: u64, num_of_pages: usize) -> Result<Self> {
        let mmap = MemoryMappingBuilder::new(pages_to_bytes(num_of_pages))
            .from_shared_memory(shmem)
            .offset(offset_bytes)
            .build()?;
        Ok(Self {
            mmap,
            present_list: PresentList::new(num_of_pages),
        })
    }

    /// Copy the guest memory pages into the staging memory.
    ///
    /// # Arguments
    ///
    /// * `src_addr` - the head address of the pages on the guest memory.
    /// * `idx` - the index of the head of the pages.
    /// * `pages` - the number of pages to copy.
    ///
    /// # Safety
    ///
    /// * `src_addr` must be aligned with the page size.
    /// * The pages indicated by `src_addr` + `pages` must be within the guest memory.
    #[deny(unsafe_op_in_unsafe_fn)]
    pub unsafe fn copy(&mut self, src_addr: *const u8, idx: usize, pages: usize) -> Result<CopyOp> {
        let idx_range = idx..idx + pages;
        let dst_slice = self.get_slice(idx_range.clone())?;

        let copy_op = CopyOp {
            src_addr,
            dst_addr: dst_slice.as_mut_ptr(),
            size: dst_slice.size(),
        };
        if !self.present_list.mark_as_present(idx_range) {
            unreachable!("idx_range is already validated by get_slice().");
        }
        Ok(copy_op)
    }

    /// Returns a content of the page corresponding to the index.
    ///
    /// Returns [Option::None] if no content in the staging memory.
    ///
    /// Returns [Error::OutOfRange] if the `idx` is out of range.
    ///
    /// # Arguments
    ///
    /// * `idx` - the index of the page from the head of the pages.
    pub fn page_content(&self, idx: usize) -> Result<Option<VolatileSlice>> {
        match self.present_list.get(idx) {
            Some(is_present) => {
                if *is_present {
                    Ok(Some(self.get_slice(idx..idx + 1)?))
                } else {
                    Ok(None)
                }
            }
            None => Err(Error::OutOfRange),
        }
    }

    /// Clears the pages in the staging memory corresponding to the indices.
    ///
    /// # Arguments
    ///
    /// * `idx_range` - the indices of consecutive pages to be cleared.
    pub fn clear_range(&mut self, idx_range: Range<usize>) -> Result<()> {
        if !self.present_list.clear_range(idx_range.clone()) {
            return Err(Error::OutOfRange);
        }
        self.mmap.remove_range(
            pages_to_bytes(idx_range.start),
            pages_to_bytes(idx_range.end - idx_range.start),
        )?;
        Ok(())
    }

    /// Returns the first range of indices of consecutive pages present in the staging memory.
    ///
    /// # Arguments
    ///
    /// * `max_pages` - the max size of the returned chunk even if the chunk of consecutive present
    ///   pages is longer than this.
    pub fn first_data_range(&mut self, max_pages: usize) -> Option<Range<usize>> {
        self.present_list.first_data_range(max_pages)
    }

    /// Returns the [VolatileSlice] corresponding to the indices.
    ///
    /// If the range is out of the region, this returns [Error::OutOfRange].
    ///
    /// # Arguments
    ///
    /// * `idx_range` - the indices of the pages.
    pub fn get_slice(&self, idx_range: Range<usize>) -> Result<VolatileSlice> {
        match self.mmap.get_slice(
            pages_to_bytes(idx_range.start),
            pages_to_bytes(idx_range.end - idx_range.start),
        ) {
            Ok(slice) => Ok(slice),
            Err(VolatileMemoryError::OutOfBounds { .. }) => Err(Error::OutOfRange),
            Err(e) => Err(e.into()),
        }
    }

    /// Returns the count of present pages in the staging memory.
    pub fn present_pages(&self) -> usize {
        self.present_list.all_present_pages()
    }
}

#[cfg(test)]
mod tests {
    use base::pagesize;
    use base::MappedRegion;

    use super::*;

    #[test]
    fn new_success() {
        let shmem = SharedMemory::new("test staging memory", 200 * pagesize() as u64).unwrap();
        assert!(StagingMemory::new(&shmem, 0, 200).is_ok());
    }

    fn create_mmap(value: u8, pages: usize) -> MemoryMapping {
        let size = pages_to_bytes(pages);
        let mmap = MemoryMappingBuilder::new(size).build().unwrap();
        for i in 0..size {
            mmap.write_obj(value, i).unwrap();
        }
        mmap
    }

    #[test]
    fn copy_marks_as_present() {
        let shmem = SharedMemory::new("test staging memory", 200 * pagesize() as u64).unwrap();
        let mmap = create_mmap(1, 4);
        let mut staging_memory = StagingMemory::new(&shmem, 0, 200).unwrap();

        let src_addr = mmap.as_ptr();
        unsafe {
            staging_memory.copy(src_addr, 1, 4).unwrap();
            // empty
            staging_memory.copy(src_addr, 10, 0).unwrap();
            // single
            staging_memory.copy(src_addr, 12, 1).unwrap();
        }

        assert!(staging_memory.page_content(0).unwrap().is_none());
        for i in 1..5 {
            assert!(staging_memory.page_content(i).unwrap().is_some());
        }
        for i in 5..12 {
            assert!(staging_memory.page_content(i).unwrap().is_none());
        }
        assert!(staging_memory.page_content(12).unwrap().is_some());
        for i in 13..200 {
            assert!(staging_memory.page_content(i).unwrap().is_none());
        }
    }

    #[test]
    fn page_content_default_is_none() {
        let shmem = SharedMemory::new("test staging memory", 200 * pagesize() as u64).unwrap();
        let staging_memory = StagingMemory::new(&shmem, 0, 200).unwrap();

        assert!(staging_memory.page_content(0).unwrap().is_none());
    }

    #[test]
    fn page_content_returns_content() {
        let shmem = SharedMemory::new("test staging memory", 200 * pagesize() as u64).unwrap();
        let mmap = create_mmap(1, 1);
        let mut staging_memory = StagingMemory::new(&shmem, 0, 200).unwrap();

        unsafe {
            staging_memory.copy(mmap.as_ptr(), 0, 1).unwrap().execute();
        }

        let page = staging_memory.page_content(0).unwrap().unwrap();
        let result = unsafe { std::slice::from_raw_parts(page.as_ptr() as *const u8, page.size()) };
        assert_eq!(result, &vec![1; pagesize()]);
    }

    #[test]
    fn page_content_out_of_range() {
        let shmem = SharedMemory::new("test staging memory", 200 * pagesize() as u64).unwrap();
        let staging_memory = StagingMemory::new(&shmem, 0, 200).unwrap();

        assert!(staging_memory.page_content(199).is_ok());
        match staging_memory.page_content(200) {
            Err(Error::OutOfRange) => {}
            _ => unreachable!("not out of range"),
        }
    }

    #[test]
    fn clear_range() {
        let shmem = SharedMemory::new("test staging memory", 200 * pagesize() as u64).unwrap();
        let mmap = create_mmap(1, 5);
        let mut staging_memory = StagingMemory::new(&shmem, 0, 200).unwrap();

        unsafe {
            staging_memory.copy(mmap.as_ptr(), 0, 5).unwrap();
        }
        staging_memory.clear_range(1..3).unwrap();

        assert!(staging_memory.page_content(0).unwrap().is_some());
        assert!(staging_memory.page_content(1).unwrap().is_none());
        assert!(staging_memory.page_content(2).unwrap().is_none());
        assert!(staging_memory.page_content(3).unwrap().is_some());
        assert!(staging_memory.page_content(4).unwrap().is_some());
    }

    #[test]
    fn clear_range_out_of_range() {
        let shmem = SharedMemory::new("test staging memory", 200 * pagesize() as u64).unwrap();
        let mut staging_memory = StagingMemory::new(&shmem, 0, 200).unwrap();

        assert!(staging_memory.clear_range(199..200).is_ok());
        match staging_memory.clear_range(199..201) {
            Err(Error::OutOfRange) => {}
            _ => unreachable!("not out of range"),
        };
    }

    #[test]
    fn first_data_range() {
        let shmem = SharedMemory::new("test staging memory", 200 * pagesize() as u64).unwrap();
        let mmap = create_mmap(1, 2);
        let mut staging_memory = StagingMemory::new(&shmem, 0, 200).unwrap();

        let src_addr = mmap.as_ptr();
        unsafe {
            staging_memory.copy(src_addr, 1, 2).unwrap();
            staging_memory.copy(src_addr, 3, 1).unwrap();
        }

        assert_eq!(staging_memory.first_data_range(200).unwrap(), 1..4);
        assert_eq!(staging_memory.first_data_range(2).unwrap(), 1..3);
        staging_memory.clear_range(1..3).unwrap();
        assert_eq!(staging_memory.first_data_range(2).unwrap(), 3..4);
        staging_memory.clear_range(3..4).unwrap();
        assert!(staging_memory.first_data_range(2).is_none());
    }

    #[test]
    fn get_slice() {
        let shmem = SharedMemory::new("test staging memory", 200 * pagesize() as u64).unwrap();
        let mmap1 = create_mmap(1, 1);
        let mmap2 = create_mmap(2, 1);
        let mut staging_memory = StagingMemory::new(&shmem, 0, 200).unwrap();

        let src_addr1 = mmap1.as_ptr();
        let src_addr2 = mmap2.as_ptr();
        unsafe {
            staging_memory.copy(src_addr1, 1, 1).unwrap().execute();
            staging_memory.copy(src_addr2, 2, 1).unwrap().execute();
        }

        let slice = staging_memory.get_slice(1..3).unwrap();
        assert_eq!(slice.size(), 2 * pagesize());
        for i in 0..pagesize() {
            let mut byte = [0u8; 1];
            slice.get_slice(i, 1).unwrap().copy_to(&mut byte);
            assert_eq!(byte[0], 1);
        }
        for i in pagesize()..2 * pagesize() {
            let mut byte = [0u8; 1];
            slice.get_slice(i, 1).unwrap().copy_to(&mut byte);
            assert_eq!(byte[0], 2);
        }
    }

    #[test]
    fn get_slice_out_of_range() {
        let shmem = SharedMemory::new("test staging memory", 200 * pagesize() as u64).unwrap();
        let staging_memory = StagingMemory::new(&shmem, 0, 200).unwrap();

        match staging_memory.get_slice(200..201) {
            Err(Error::OutOfRange) => {}
            other => {
                unreachable!("unexpected result {:?}", other);
            }
        }
    }

    #[test]
    fn present_pages() {
        let shmem = SharedMemory::new("test staging memory", 200 * pagesize() as u64).unwrap();
        let mmap = create_mmap(1, 5);
        let mut staging_memory = StagingMemory::new(&shmem, 0, 200).unwrap();

        let src_addr = mmap.as_ptr();
        unsafe {
            staging_memory.copy(src_addr, 1, 4).unwrap();
            staging_memory.copy(src_addr, 12, 1).unwrap();
        }

        assert_eq!(staging_memory.present_pages(), 5);
    }
}
