// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use std::fs::File;
use std::fs::OpenOptions;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use base::error;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::MmapError;
use base::Protection;
use data_model::VolatileMemory;
use data_model::VolatileMemoryError;
use data_model::VolatileSlice;
use thiserror::Error as ThisError;

use crate::pagesize::bytes_to_pages;
use crate::pagesize::is_page_aligned;
use crate::pagesize::pages_to_bytes;
use crate::present_list::PresentList;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("failed to io: {0}")]
    Io(std::io::Error),
    #[error("failed to mmap operation: {0}")]
    Mmap(MmapError),
    #[error("failed to volatile memory operation: {0}")]
    VolatileMemory(VolatileMemoryError),
    #[error("index is out of range")]
    OutOfRange,
    #[error("data size is invalid")]
    InvalidSize,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
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

/// SwapFile stores active pages in a memory region.
///
/// TODO(kawasin): The file structure is straightforward and is not optimized yet.
/// Each page in the file corresponds to the page in the memory region.
///
/// The swap file is created as `O_TMPFILE` from the specified directory. As benefits:
///
/// * it has no chance to conflict and,
/// * it has a security benefit that no one (except root) can access the swap file.
/// * it will be automatically deleted by the kernel when crosvm exits/dies or on reboot if the
///   device panics/hard-resets while crosvm is running.
#[derive(Debug)]
pub struct SwapFile {
    file: File,
    file_mmap: MemoryMapping,
    // Tracks which pages are present, indexed by page index within the memory region.
    present_list: PresentList,
}

impl SwapFile {
    /// Creates an initialized [SwapFile] for a memory region.
    ///
    /// This creates the swapping file. If the file exists, it is truncated.
    ///
    /// The all pages are marked as empty at first time.
    ///
    /// # Arguments
    ///
    /// * `dir_path` - path to the directory to create a swap file from.
    /// * `num_of_pages` - the number of pages in the region.
    pub fn new(dir_path: &Path, num_of_pages: usize) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_TMPFILE | libc::O_EXCL)
            .mode(0o000) // other processes with the same uid can't open the file
            .open(dir_path)?;
        let file_mmap = MemoryMappingBuilder::new(pages_to_bytes(num_of_pages))
            .from_file(&file)
            .protection(Protection::read())
            .build()?;
        Ok(Self {
            file,
            file_mmap,
            present_list: PresentList::new(num_of_pages),
        })
    }

    /// Returns the total count of managed pages.
    pub fn num_pages(&self) -> usize {
        self.present_list.len()
    }

    /// Returns a content of the page corresponding to the index.
    ///
    /// Returns [Option::None] if no content in the file.
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

    /// Clears the pages in the file corresponding to the index.
    ///
    /// # Arguments
    ///
    /// * `idx_range` - the indices of consecutive pages to be cleared.
    pub fn clear_range(&mut self, idx_range: Range<usize>) -> Result<()> {
        if self.present_list.clear_range(idx_range) {
            // TODO(kawasin): punch a hole to the cleared page in the file.
            // TODO(kawasin): free the page cache for the page.
            Ok(())
        } else {
            Err(Error::OutOfRange)
        }
    }

    /// Writes the contents to the swap file.
    ///
    /// # Arguments
    ///
    /// * `idx` - the index of the head page of the content from the head of the pages.
    /// * `mem_slice` - the page content(s). this can be more than 1 page. the size must align with
    ///   the pagesize.
    pub fn write_to_file(&mut self, idx: usize, mem_slice: &[u8]) -> Result<()> {
        // validate
        if !is_page_aligned(mem_slice.len()) {
            // mem_slice size must align with page size.
            return Err(Error::InvalidSize);
        }
        let num_pages = bytes_to_pages(mem_slice.len());
        if idx + num_pages > self.present_list.len() {
            return Err(Error::OutOfRange);
        }

        let byte_offset = (pages_to_bytes(idx)) as u64;
        self.file.write_all_at(mem_slice, byte_offset)?;

        if !self.present_list.mark_as_present(idx..idx + num_pages) {
            // the range is already validated before writing.
            unreachable!("idx range is out of range");
        }

        Ok(())
    }

    /// Returns the first range of indices of consecutive pages present in the swap file.
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
        match self.file_mmap.get_slice(
            pages_to_bytes(idx_range.start),
            pages_to_bytes(idx_range.end - idx_range.start),
        ) {
            Ok(slice) => Ok(slice),
            Err(VolatileMemoryError::OutOfBounds { .. }) => Err(Error::OutOfRange),
            Err(e) => Err(e.into()),
        }
    }

    /// Returns the count of present pages in the swap file.
    pub fn present_pages(&self) -> usize {
        self.present_list.present_pages()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::slice;

    use base::pagesize;

    use super::*;

    #[test]
    fn new_success() {
        let dir_path = tempfile::tempdir().unwrap();

        assert_eq!(SwapFile::new(dir_path.path(), 200).is_ok(), true);
    }

    #[test]
    fn new_fails_to_open_file() {
        let dir_path = PathBuf::from("/invalid/invalid/invalid");
        assert_eq!(SwapFile::new(&dir_path, 200).is_err(), true);
    }

    #[test]
    fn len() {
        let dir_path = tempfile::tempdir().unwrap();
        let swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        assert_eq!(swap_file.num_pages(), 200);
    }

    #[test]
    fn page_content_default_is_none() {
        let dir_path = tempfile::tempdir().unwrap();
        let swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        assert_eq!(swap_file.page_content(0).unwrap().is_none(), true);
    }

    #[test]
    fn page_content_returns_content() {
        let dir_path = tempfile::tempdir().unwrap();
        let mut swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        let data = &vec![1; pagesize()];
        swap_file.write_to_file(0, data).unwrap();

        let page = swap_file.page_content(0).unwrap().unwrap();
        let result = unsafe { slice::from_raw_parts(page.as_ptr() as *const u8, pagesize()) };
        assert_eq!(result, data);
    }

    #[test]
    fn page_content_out_of_range() {
        let dir_path = tempfile::tempdir().unwrap();
        let swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        assert_eq!(swap_file.page_content(199).is_ok(), true);
        match swap_file.page_content(200) {
            Err(Error::OutOfRange) => {}
            _ => unreachable!("not out of range"),
        }
    }

    fn assert_page_content(swap_file: &SwapFile, idx: usize, data: &[u8]) {
        let page = swap_file.page_content(idx).unwrap().unwrap();
        let result = unsafe { slice::from_raw_parts(page.as_ptr() as *const u8, pagesize()) };
        assert_eq!(result, data);
    }

    #[test]
    fn write_to_file_swap_file() {
        let dir_path = tempfile::tempdir().unwrap();
        let mut swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        let buf1 = &vec![1; pagesize()];
        let buf2 = &vec![2; 2 * pagesize()];
        swap_file.write_to_file(0, buf1).unwrap();
        swap_file.write_to_file(2, buf2).unwrap();

        // page_content()
        assert_page_content(&swap_file, 0, buf1);
        assert_page_content(&swap_file, 2, &buf2[0..pagesize()]);
        assert_page_content(&swap_file, 3, &buf2[pagesize()..2 * pagesize()]);
    }

    #[test]
    fn write_to_file_invalid_size() {
        let dir_path = tempfile::tempdir().unwrap();
        let mut swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        let buf = &vec![1; pagesize() + 1];
        match swap_file.write_to_file(0, buf) {
            Err(Error::InvalidSize) => {}
            _ => unreachable!("not invalid size"),
        };
    }

    #[test]
    fn write_to_file_out_of_range() {
        let dir_path = tempfile::tempdir().unwrap();
        let mut swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        let buf1 = &vec![1; pagesize()];
        let buf2 = &vec![2; 2 * pagesize()];
        match swap_file.write_to_file(200, buf1) {
            Err(Error::OutOfRange) => {}
            _ => unreachable!("not out of range"),
        };
        match swap_file.write_to_file(199, buf2) {
            Err(Error::OutOfRange) => {}
            _ => unreachable!("not out of range"),
        };
    }

    #[test]
    fn clear() {
        let dir_path = tempfile::tempdir().unwrap();
        let mut swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        let data = &vec![1; pagesize()];
        swap_file.write_to_file(0, data).unwrap();
        swap_file.clear_range(0..1).unwrap();

        assert_eq!(swap_file.page_content(0).unwrap().is_none(), true);
    }

    #[test]
    fn clear_out_of_range() {
        let dir_path = tempfile::tempdir().unwrap();
        let mut swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        assert_eq!(swap_file.clear_range(199..200).is_ok(), true);
        match swap_file.clear_range(200..201) {
            Err(Error::OutOfRange) => {}
            _ => unreachable!("not out of range"),
        };
    }

    #[test]
    fn first_data_range() {
        let dir_path = tempfile::tempdir().unwrap();
        let mut swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        swap_file
            .write_to_file(1, &vec![1; 2 * pagesize()])
            .unwrap();
        swap_file.write_to_file(3, &vec![2; pagesize()]).unwrap();

        assert_eq!(swap_file.first_data_range(200).unwrap(), 1..4);
        assert_eq!(swap_file.first_data_range(2).unwrap(), 1..3);
        swap_file.clear_range(1..3).unwrap();
        assert_eq!(swap_file.first_data_range(2).unwrap(), 3..4);
        swap_file.clear_range(3..4).unwrap();
        assert!(swap_file.first_data_range(2).is_none());
    }

    #[test]
    fn get_slice() {
        let dir_path = tempfile::tempdir().unwrap();
        let mut swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        swap_file.write_to_file(1, &vec![1; pagesize()]).unwrap();
        swap_file.write_to_file(2, &vec![2; pagesize()]).unwrap();

        let slice = swap_file.get_slice(1..3).unwrap();
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
        let dir_path = tempfile::tempdir().unwrap();
        let swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        match swap_file.get_slice(200..201) {
            Err(Error::OutOfRange) => {}
            other => {
                unreachable!("unexpected result {:?}", other);
            }
        }
    }

    #[test]
    fn present_pages() {
        let dir_path = tempfile::tempdir().unwrap();
        let mut swap_file = SwapFile::new(dir_path.path(), 200).unwrap();

        swap_file.write_to_file(1, &vec![1; pagesize()]).unwrap();
        swap_file.write_to_file(2, &vec![2; pagesize()]).unwrap();

        assert_eq!(swap_file.present_pages(), 2);
    }
}
