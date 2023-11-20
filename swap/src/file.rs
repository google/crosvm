// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use std::fs::File;
use std::ops::Range;
use std::os::unix::fs::FileExt;

use base::error;
use base::linux::MemoryMappingUnix;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::MmapError;
use base::Protection;
use base::VolatileMemory;
use base::VolatileMemoryError;
use base::VolatileSlice;
use thiserror::Error as ThisError;

use crate::pagesize::bytes_to_pages;
use crate::pagesize::is_page_aligned;
use crate::pagesize::pages_to_bytes;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("failed to io: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to mmap operation ({0}): {1}")]
    Mmap(&'static str, MmapError),
    #[error("failed to volatile memory operation: {0}")]
    VolatileMemory(#[from] VolatileMemoryError),
    #[error("index is out of range")]
    OutOfRange,
    #[error("data size is invalid")]
    InvalidSize,
    #[error("index is invalid")]
    InvalidIndex,
}

/// TODO(kawasin): Serialize this into u32.
#[derive(Debug)]
enum FilePageState {
    Free(Option<usize>),
    Present(usize),
}

#[derive(Debug)]
struct FilePageStates {
    /// Freed pages on the swap file are managed in a free list. `first_freed_idx_file` points to
    /// the first page index in the list.
    first_idx_file_freed: Option<usize>,
    states: Vec<FilePageState>,
}

impl FilePageStates {
    fn new(capacity: usize) -> Self {
        FilePageStates {
            first_idx_file_freed: None,
            states: Vec::with_capacity(capacity),
        }
    }

    fn len(&self) -> usize {
        self.states.len()
    }

    /// Free a page on swap file.
    fn free(&mut self, idx_file: usize) {
        self.states[idx_file] = FilePageState::Free(self.first_idx_file_freed);
        self.first_idx_file_freed = Some(idx_file);
    }

    /// Allocates a file page on the swap file.
    ///
    /// This returns the index of the allocated file page.
    ///
    /// This reuses freed file pages first. If the free list is empty, this allocates new pages in
    /// the file.
    fn allocate(&mut self, idx_page: usize) -> usize {
        if let Some(idx_file_freed) = self.first_idx_file_freed {
            // TODO(kawasin): Collect consecutive freed pages in the free list to reduce number of
            // writes.
            let FilePageState::Free(next_idx_file_freed) = self.states[idx_file_freed] else {
                unreachable!("free list is broken");
            };
            self.states[idx_file_freed] = FilePageState::Present(idx_page);
            self.first_idx_file_freed = next_idx_file_freed;

            idx_file_freed
        } else {
            // The free list is empty. Allocate new pages.
            let head_idx_file = self.states.len();
            self.states.push(FilePageState::Present(idx_page));
            head_idx_file
        }
    }

    /// Find the index range of file pages that are all present.
    ///
    /// This returns the pair of range of file page indexes and the index of the corresponding first
    /// page.
    ///
    /// Returns `None` if no pages after `idx_file` are present.
    ///
    /// # Arguments
    ///
    /// * `idx_file` - The first index to start searching from.
    /// * `page_states` - The page states
    /// * `max_pages` - The maximum number of pages to search.
    /// * `consecutive` - If true, the pages must have consecutive idx_page values.
    fn find_present_pages_range(
        &self,
        idx_file: usize,
        page_states: &[Option<(usize, bool)>],
        max_pages: usize,
        consecutive: bool,
    ) -> Option<(Range<usize>, usize)> {
        let next_head_idx_offset = self.states[idx_file..]
            .iter()
            .position(|state| match state {
                FilePageState::Free(_) => false,
                FilePageState::Present(idx) => {
                    page_states[*idx].expect("page state must have idx_file").1
                }
            });
        let Some(next_head_idx_offset) = next_head_idx_offset else {
            return None;
        };
        let idx_file = idx_file + next_head_idx_offset;

        let FilePageState::Present(head_idx_page) = self.states[idx_file] else {
            unreachable!("state must be present");
        };

        let mut pages = 1;

        if max_pages > 1 {
            for state in self.states[idx_file + 1..].iter() {
                let FilePageState::Present(idx_page) = *state else {
                    break;
                };
                if !page_states[idx_page]
                    .expect("page state must have idx_file")
                    .1
                    || (consecutive && idx_page != head_idx_page + pages)
                {
                    break;
                }
                pages += 1;
                if pages >= max_pages {
                    break;
                }
            }
        }

        Some((idx_file..idx_file + pages, head_idx_page))
    }
}

/// [SwapFile] stores active pages in a memory region.
///
/// This shares the swap file with other regions and creates mmap corresponding range in the file.
///
/// TODO(kawasin): The file structure is straightforward and is not optimized yet.
/// Each page in the file corresponds to the page in the memory region.
#[derive(Debug)]
pub struct SwapFile<'a> {
    file: &'a File,
    file_mmap: MemoryMapping,
    /// TODO(kawasin): Serialize this into u32.
    page_states: Vec<Option<(usize, bool)>>,
    file_states: FilePageStates,
    // All the data pages before this index are mlock(2)ed.
    cursor_mlock: usize,
    min_possible_present_idx_file: usize,
}

impl<'a> SwapFile<'a> {
    /// Creates an initialized [SwapFile] for a memory region.
    ///
    /// The all pages are marked as empty at first time.
    ///
    /// # Arguments
    ///
    /// * `file` - The swap file.
    /// * `num_of_pages` - The number of pages in the region.
    pub fn new(file: &'a File, num_of_pages: usize) -> Result<Self> {
        let file_mmap = MemoryMappingBuilder::new(pages_to_bytes(num_of_pages))
            .from_file(file)
            .protection(Protection::read())
            .build()
            .map_err(|e| Error::Mmap("create", e))?;
        Ok(Self {
            file,
            file_mmap,
            page_states: vec![None; num_of_pages],
            file_states: FilePageStates::new(num_of_pages),
            cursor_mlock: 0,
            min_possible_present_idx_file: 0,
        })
    }

    /// Returns a content of the page corresponding to the index if it is present.
    ///
    /// Returns [Option::None] if no content in the file.
    ///
    /// Returns [Error::OutOfRange] if the `idx` is out of range.
    ///
    /// # Arguments
    ///
    /// * `idx_page` - the index of the page from the head of the pages.
    pub fn page_content(
        &self,
        idx_page: usize,
        allow_cleared: bool,
    ) -> Result<Option<VolatileSlice>> {
        if let Some((idx_file, is_present)) =
            self.page_states.get(idx_page).ok_or(Error::OutOfRange)?
        {
            if allow_cleared || *is_present {
                return match self
                    .file_mmap
                    .get_slice(pages_to_bytes(*idx_file), pages_to_bytes(1))
                {
                    Ok(slice) => Ok(Some(slice)),
                    Err(VolatileMemoryError::OutOfBounds { .. }) => Err(Error::OutOfRange),
                    Err(e) => Err(e.into()),
                };
            }
        }
        Ok(None)
    }

    /// Start readahead the swap file into the page cache from the head.
    ///
    /// This also `mlock2(2)` the pages not to be dropped again after populated. This does not block
    /// the caller thread by I/O wait because:
    ///
    /// * `mlock2(2)` is executed with `MLOCK_ONFAULT`.
    /// * `MADV_WILLNEED` is the same as `readahead(2)` which triggers the readahead background.
    ///   * However Linux has a bug that `readahead(2)` (and also `MADV_WILLNEED`) may block due to
    ///     reading the filesystem metadata.
    ///
    /// This returns the number of consecutive pages which are newly mlock(2)ed. Returning `0` means
    /// that there is no more data to be mlock(2)ed in this file.
    ///
    /// The caller must track the number of pages mlock(2)ed not to mlock(2) more pages than
    /// `RLIMIT_MEMLOCK` if it does not have `CAP_IPC_LOCK`.
    ///
    /// # Arguments
    ///
    /// * `max_pages` - The maximum number of pages to be mlock(2)ed at once.
    pub fn lock_and_async_prefetch(&mut self, max_pages: usize) -> Result<usize> {
        if let Some((idx_file_range, _)) = self.file_states.find_present_pages_range(
            self.cursor_mlock,
            &self.page_states,
            max_pages,
            false,
        ) {
            let pages = idx_file_range.end - idx_file_range.start;
            let mem_offset = pages_to_bytes(idx_file_range.start);
            let size_in_bytes = pages_to_bytes(pages);
            self.file_mmap
                .lock_on_fault(mem_offset, size_in_bytes)
                .map_err(|e| Error::Mmap("mlock", e))?;
            self.file_mmap
                .async_prefetch(mem_offset, size_in_bytes)
                .map_err(|e| Error::Mmap("madvise willneed", e))?;
            self.cursor_mlock = idx_file_range.end;
            Ok(pages)
        } else {
            self.cursor_mlock = self.file_states.len();
            Ok(0)
        }
    }

    /// Mark the pages in the file corresponding to the index as cleared.
    ///
    /// The contents on the swap file are preserved and will be reused by
    /// `SwapFile::mark_as_present()` and reduce disk I/O.
    ///
    /// If the pages are mlock(2)ed, unlock them before MADV_DONTNEED. This returns the number of
    /// pages munlock(2)ed.
    ///
    /// # Arguments
    ///
    /// * `idx_page_range` - The indices of consecutive pages to be cleared. All the pages must be
    ///   present and consecutive in the compacted file.
    pub fn clear_range(&mut self, idx_page_range: Range<usize>) -> Result<usize> {
        let idx_file_range = self.convert_idx_page_range_to_idx_file(idx_page_range.clone())?;

        for state in &mut self.page_states[idx_page_range] {
            state.as_mut().unwrap().1 = false;
        }

        let offset = pages_to_bytes(idx_file_range.start);
        let munlocked_size = if idx_file_range.start < self.cursor_mlock {
            // idx_page_range is validated at clear_range() and self.cursor_mlock is within the mmap.
            let pages = idx_file_range.end.min(self.cursor_mlock) - idx_file_range.start;
            // munlock(2) first because MADV_DONTNEED fails for mlock(2)ed pages.
            self.file_mmap
                .unlock(offset, pages_to_bytes(pages))
                .map_err(|e| Error::Mmap("munlock", e))?;
            pages
        } else {
            0
        };
        // offset and size are validated at clear_range().
        let size = pages_to_bytes(idx_file_range.end - idx_file_range.start);
        // The page cache is cleared without writing pages back to file even if they are dirty.
        // The disk contents which may not be the latest are kept for later trim optimization.
        self.file_mmap
            .drop_page_cache(offset, size)
            .map_err(|e| Error::Mmap("madvise dontneed", e))?;
        Ok(munlocked_size)
    }

    /// Free the pages corresponding to the given range in the file.
    ///
    /// If the pages are mlock(2)ed, unlock them. This returns the number of pages munlock(2)ed.
    ///
    /// # Arguments
    ///
    /// * `idx_page_range` - The indices of consecutive pages to be erased. This may contains
    ///   non-present pages.
    pub fn free_range(&mut self, idx_page_range: Range<usize>) -> Result<usize> {
        if idx_page_range.end > self.page_states.len() {
            return Err(Error::OutOfRange);
        }
        let mut mlocked_pages = 0;
        let mut mlock_range: Option<Range<usize>> = None;
        for state in &mut self.page_states[idx_page_range] {
            if let Some((idx_file, is_present)) = *state {
                self.file_states.free(idx_file);

                if is_present && idx_file < self.cursor_mlock {
                    mlocked_pages += 1;
                    if let Some(range) = mlock_range.as_mut() {
                        if idx_file + 1 == range.start {
                            range.start = idx_file;
                        } else if idx_file == range.end {
                            range.end += 1;
                        } else {
                            self.file_mmap
                                .unlock(
                                    pages_to_bytes(range.start),
                                    pages_to_bytes(range.end - range.start),
                                )
                                .map_err(|e| Error::Mmap("munlock", e))?;
                            mlock_range = Some(idx_file..idx_file + 1);
                        }
                    } else {
                        mlock_range = Some(idx_file..idx_file + 1);
                    }
                }
            }
            *state = None;
        }
        if let Some(mlock_range) = mlock_range {
            self.file_mmap
                .unlock(
                    pages_to_bytes(mlock_range.start),
                    pages_to_bytes(mlock_range.end - mlock_range.start),
                )
                .map_err(|e| Error::Mmap("munlock", e))?;
        }

        Ok(mlocked_pages)
    }

    /// munlock(2) pages if there are mlock(2)ed pages in the mmap and reset the internal cursor for
    /// mlock(2) tracking.
    pub fn clear_mlock(&mut self) -> Result<()> {
        if self.cursor_mlock > 0 {
            // cursor_mlock is not `0` only when disabling vmm-swap is aborted by overriding
            // vmm-swap enable. munlock(2)ing the whole possible pages is not a problem because this
            // is not a hot path.
            self.file_mmap
                .unlock(0, pages_to_bytes(self.cursor_mlock))
                .map_err(|e| Error::Mmap("munlock", e))?;
        }
        self.cursor_mlock = 0;
        Ok(())
    }

    /// Mark the page as present on the file.
    ///
    /// The content on the swap file on previous `SwapFile::write_to_file()` is reused.
    ///
    /// # Arguments
    ///
    /// * `idx_page` - the index of the page from the head of the pages.
    pub fn mark_as_present(&mut self, idx_page: usize) -> Result<()> {
        match self.page_states.get(idx_page).ok_or(Error::OutOfRange)? {
            Some((file_idx, false)) => {
                let file_idx = *file_idx;
                self.page_states[idx_page] = Some((file_idx, true));
                self.min_possible_present_idx_file =
                    std::cmp::min(file_idx, self.min_possible_present_idx_file);
                Ok(())
            }
            _ => Err(Error::InvalidIndex),
        }
    }

    /// Writes the contents to the swap file.
    ///
    /// # Arguments
    ///
    /// * `idx_page` - the index of the head page of the content from the head of the pages.
    /// * `mem_slice` - the page content(s). this can be more than 1 page. the size must align with
    ///   the pagesize.
    pub fn write_to_file(&mut self, idx_page: usize, mem_slice: &[u8]) -> Result<()> {
        // validate
        if !is_page_aligned(mem_slice.len()) {
            // mem_slice size must align with page size.
            return Err(Error::InvalidSize);
        }
        let num_pages = bytes_to_pages(mem_slice.len());
        if idx_page + num_pages > self.page_states.len() {
            return Err(Error::OutOfRange);
        }

        // Setting 0 is faster than setting exact index by complex conditions.
        self.min_possible_present_idx_file = 0;

        for cur in idx_page..idx_page + num_pages {
            if let Some((_, is_present)) = &mut self.page_states[cur] {
                *is_present = true;
            } else {
                let idx_file = self.file_states.allocate(cur);

                self.page_states[cur] = Some((idx_file, true));
            }
        }

        let mut pending_idx_file = None;
        let mut pending_pages = 0;
        let mut mem_slice = mem_slice;
        for state in self.page_states[idx_page..idx_page + num_pages].iter() {
            let Some((idx_file, _)) = state else {
                unreachable!("pages must be allocated");
            };
            if let Some(pending_idx_file) = pending_idx_file {
                if *idx_file == pending_idx_file + pending_pages {
                    pending_pages += 1;
                    continue;
                }
                let size = pages_to_bytes(pending_pages);
                // Write with pwrite(2) syscall instead of copying contents to mmap because write
                // syscall is more explicit for kernel how many pages are going to be written while
                // mmap only knows each page to be written on a page fault basis.
                self.file
                    .write_all_at(&mem_slice[..size], pages_to_bytes(pending_idx_file) as u64)?;
                mem_slice = &mem_slice[size..];
            }
            pending_idx_file = Some(*idx_file);
            pending_pages = 1;
        }
        if let Some(pending_idx_file) = pending_idx_file {
            let size = pages_to_bytes(pending_pages);
            self.file
                .write_all_at(&mem_slice[..size], pages_to_bytes(pending_idx_file) as u64)?;
            mem_slice = &mem_slice[size..];
        }
        if !mem_slice.is_empty() {
            unreachable!("mem_slice must be all consumed");
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
        if let Some((idx_file_range, head_idx_page)) = self.file_states.find_present_pages_range(
            self.min_possible_present_idx_file,
            &self.page_states,
            max_pages,
            true,
        ) {
            self.min_possible_present_idx_file = idx_file_range.start;
            let idx_page_range =
                head_idx_page..head_idx_page + idx_file_range.end - idx_file_range.start;
            Some(idx_page_range)
        } else {
            self.min_possible_present_idx_file = self.file_states.len();
            None
        }
    }

    /// Returns the [VolatileSlice] corresponding to the indices regardless of whether the pages are
    /// present or not.
    ///
    /// If the range is out of the region, this returns [Error::OutOfRange].
    ///
    /// # Arguments
    ///
    /// * `idx_page_range` - the indices of the pages. All the pages must be present and
    ///   consecutive in the compacted file.
    pub fn get_slice(&self, idx_page_range: Range<usize>) -> Result<VolatileSlice> {
        let idx_file_range = self.convert_idx_page_range_to_idx_file(idx_page_range)?;
        match self.file_mmap.get_slice(
            pages_to_bytes(idx_file_range.start),
            pages_to_bytes(idx_file_range.end - idx_file_range.start),
        ) {
            Ok(slice) => Ok(slice),
            Err(VolatileMemoryError::OutOfBounds { .. }) => Err(Error::OutOfRange),
            Err(e) => Err(e.into()),
        }
    }

    /// Returns the count of present pages in the swap file.
    pub fn present_pages(&self) -> usize {
        self.page_states
            .iter()
            .map(|state| matches!(state, Some((_, true))) as usize)
            .sum()
    }

    /// Convert the index range to corresponding index range of compacted file.
    ///
    /// This validates that the `idx_page_range` satisfy:
    ///
    /// * `idx_page_range` has corresponding page in the file.
    /// * corresponding index range in the file is consecutive.
    fn convert_idx_page_range_to_idx_file(
        &self,
        idx_page_range: Range<usize>,
    ) -> Result<Range<usize>> {
        // Validate that the idx_page_range is for cosecutive present file pages.
        let head_idx_file = match self
            .page_states
            .get(idx_page_range.start)
            .ok_or(Error::OutOfRange)?
        {
            Some((idx_file, true)) => Ok(*idx_file),
            _ => Err(Error::InvalidIndex),
        }?;
        let mut idx_file = head_idx_file;
        for idx in idx_page_range.start + 1..idx_page_range.end {
            idx_file = match self.page_states.get(idx).ok_or(Error::OutOfRange)? {
                Some((idx_file_of_page, true)) if *idx_file_of_page == idx_file + 1 => {
                    Ok(*idx_file_of_page)
                }
                _ => Err(Error::InvalidIndex),
            }?;
        }
        let idx_file_range =
            head_idx_file..head_idx_file + idx_page_range.end - idx_page_range.start;
        Ok(idx_file_range)
    }
}

#[cfg(test)]
mod tests {
    use std::slice;

    use base::pagesize;
    use base::sys::FileDataIterator;

    use super::*;

    #[test]
    fn new_success() {
        let file = tempfile::tempfile().unwrap();

        assert_eq!(SwapFile::new(&file, 200).is_ok(), true);
    }

    #[test]
    fn len() {
        let file = tempfile::tempfile().unwrap();
        let swap_file = SwapFile::new(&file, 200).unwrap();

        assert_eq!(swap_file.page_states.len(), 200);
    }

    #[test]
    fn page_content_default_is_none() {
        let file = tempfile::tempfile().unwrap();
        let swap_file = SwapFile::new(&file, 200).unwrap();

        assert_eq!(swap_file.page_content(0, false).unwrap().is_none(), true);
    }

    #[test]
    fn page_content_returns_content() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        let data = &vec![1; pagesize()];
        swap_file.write_to_file(0, data).unwrap();

        let page = swap_file.page_content(0, false).unwrap().unwrap();
        let result = unsafe { slice::from_raw_parts(page.as_ptr(), pagesize()) };
        assert_eq!(result, data);
    }

    #[test]
    fn page_content_out_of_range() {
        let file = tempfile::tempfile().unwrap();
        let swap_file = SwapFile::new(&file, 200).unwrap();

        assert_eq!(swap_file.page_content(199, false).is_ok(), true);
        match swap_file.page_content(200, false) {
            Err(Error::OutOfRange) => {}
            _ => unreachable!("not out of range"),
        }
    }

    fn assert_page_content(swap_file: &SwapFile, idx: usize, data: &[u8]) {
        let page = swap_file.page_content(idx, false).unwrap().unwrap();
        let result = unsafe { slice::from_raw_parts(page.as_ptr(), pagesize()) };
        assert_eq!(result, data);
    }

    #[test]
    fn write_to_file_swap_file() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

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
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        let buf = &vec![1; pagesize() + 1];
        match swap_file.write_to_file(0, buf) {
            Err(Error::InvalidSize) => {}
            _ => unreachable!("not invalid size"),
        };
    }

    #[test]
    fn write_to_file_out_of_range() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

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
    fn write_to_file_overwrite() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        swap_file.write_to_file(0, &vec![1; pagesize()]).unwrap();
        swap_file
            .write_to_file(2, &vec![2; 2 * pagesize()])
            .unwrap();

        let mut buf = vec![0; 3 * pagesize()];
        buf[..pagesize()].fill(3);
        buf[pagesize()..2 * pagesize()].fill(4);
        buf[2 * pagesize()..3 * pagesize()].fill(5);
        swap_file.write_to_file(0, &buf).unwrap();

        assert_page_content(&swap_file, 0, &vec![3; pagesize()]);
        assert_page_content(&swap_file, 1, &vec![4; pagesize()]);
        assert_page_content(&swap_file, 2, &vec![5; pagesize()]);
        assert_page_content(&swap_file, 3, &vec![2; pagesize()]);
        assert!(swap_file.page_content(4, false).unwrap().is_none());

        let data =
            FileDataIterator::new(&file, 0, file.metadata().unwrap().len()).collect::<Vec<_>>();
        assert_eq!(data, vec![0..4 * pagesize() as u64]);

        buf[..pagesize()].fill(6);
        buf[pagesize()..2 * pagesize()].fill(7);
        buf[2 * pagesize()..3 * pagesize()].fill(8);
        swap_file.write_to_file(2, &buf).unwrap();
        assert_page_content(&swap_file, 0, &vec![3; pagesize()]);
        assert_page_content(&swap_file, 1, &vec![4; pagesize()]);
        assert_page_content(&swap_file, 2, &vec![6; pagesize()]);
        assert_page_content(&swap_file, 3, &vec![7; pagesize()]);
        assert_page_content(&swap_file, 4, &vec![8; pagesize()]);
        assert!(swap_file.page_content(5, false).unwrap().is_none());

        let data =
            FileDataIterator::new(&file, 0, file.metadata().unwrap().len()).collect::<Vec<_>>();
        assert_eq!(data, vec![0..5 * pagesize() as u64]);
    }

    #[test]
    #[cfg(target_arch = "x86_64")] // TODO(b/272612118): unit test infra (qemu-user) support
    fn lock_and_start_populate() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        swap_file.write_to_file(1, &vec![1; pagesize()]).unwrap();
        swap_file
            .write_to_file(3, &vec![1; 5 * pagesize()])
            .unwrap();
        swap_file.write_to_file(10, &vec![1; pagesize()]).unwrap();

        let mut locked_pages = 0;
        loop {
            let pages = swap_file.lock_and_async_prefetch(2).unwrap();
            if pages == 0 {
                break;
            }
            assert!(pages <= 2);
            locked_pages += pages;
        }
        assert_eq!(locked_pages, 7);
    }

    #[test]
    fn clear_range() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        let data = &vec![1; pagesize()];
        swap_file.write_to_file(0, data).unwrap();
        swap_file.clear_range(0..1).unwrap();

        assert!(swap_file.page_content(0, false).unwrap().is_none());
    }

    #[test]
    #[cfg(target_arch = "x86_64")] // TODO(b/272612118): unit test infra (qemu-user) support
    fn clear_range_unlocked_pages() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        swap_file
            .write_to_file(1, &vec![1; 10 * pagesize()])
            .unwrap();
        // 1..6 is locked, 6..11 is not locked.
        assert_eq!(swap_file.lock_and_async_prefetch(5).unwrap(), 5);

        // locked pages only
        assert_eq!(swap_file.clear_range(1..4).unwrap(), 3);
        // locked pages + non-locked pages
        assert_eq!(swap_file.clear_range(4..7).unwrap(), 2);
        // non-locked pages
        assert_eq!(swap_file.clear_range(10..11).unwrap(), 0);
    }

    #[test]
    fn clear_range_keep_on_disk() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        let data = &vec![1; pagesize()];
        swap_file.write_to_file(0, data).unwrap();
        swap_file.clear_range(0..1).unwrap();

        let slice = swap_file.page_content(0, true).unwrap().unwrap();
        let slice = unsafe { slice::from_raw_parts(slice.as_ptr(), slice.size()) };
        assert_eq!(slice, data);
    }

    #[test]
    fn clear_range_out_of_range() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();
        swap_file.write_to_file(199, &vec![0; pagesize()]).unwrap();

        match swap_file.clear_range(199..201) {
            Err(Error::OutOfRange) => {}
            _ => unreachable!("not out of range"),
        };
        assert!(swap_file.clear_range(199..200).is_ok());
        match swap_file.clear_range(200..201) {
            Err(Error::OutOfRange) => {}
            _ => unreachable!("not out of range"),
        };
    }

    #[test]
    fn free_range() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        let data = &vec![1; pagesize()];
        swap_file.write_to_file(0, data).unwrap();
        swap_file.free_range(0..1).unwrap();

        assert!(swap_file.page_content(0, false).unwrap().is_none());
        assert!(swap_file.page_content(0, true).unwrap().is_none());
    }

    #[test]
    #[cfg(target_arch = "x86_64")] // TODO(b/272612118): unit test infra (qemu-user) support
    fn free_range_unlocked_pages() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        swap_file
            .write_to_file(1, &vec![1; 10 * pagesize()])
            .unwrap();
        // 1..6 is locked, 6..11 is not locked.
        assert_eq!(swap_file.lock_and_async_prefetch(5).unwrap(), 5);

        // empty pages
        assert_eq!(swap_file.free_range(0..1).unwrap(), 0);
        // empty pages + locked pages
        assert_eq!(swap_file.free_range(0..2).unwrap(), 1);
        // locked pages only
        assert_eq!(swap_file.free_range(2..4).unwrap(), 2);
        // empty pages + locked pages + non-locked pages
        assert_eq!(swap_file.free_range(3..7).unwrap(), 2);
        // non-locked pages
        assert_eq!(swap_file.free_range(10..11).unwrap(), 0);
    }

    #[test]
    fn free_range_out_of_range() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        assert_eq!(swap_file.free_range(199..200).is_ok(), true);
        match swap_file.free_range(200..201) {
            Err(Error::OutOfRange) => {}
            _ => unreachable!("not out of range"),
        };
        match swap_file.free_range(199..201) {
            Err(Error::OutOfRange) => {}
            _ => unreachable!("not out of range"),
        };
    }

    #[test]
    fn free_range_and_write() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        let data = &vec![1; 5 * pagesize()];
        swap_file.write_to_file(0, data).unwrap();
        swap_file.free_range(0..5).unwrap();

        swap_file
            .write_to_file(0, &vec![2; 2 * pagesize()])
            .unwrap();
        swap_file
            .write_to_file(5, &vec![3; 4 * pagesize()])
            .unwrap();

        assert_page_content(&swap_file, 0, &vec![2; pagesize()]);
        assert_page_content(&swap_file, 1, &vec![2; pagesize()]);
        assert!(swap_file.page_content(2, true).unwrap().is_none());
        assert!(swap_file.page_content(3, true).unwrap().is_none());
        assert!(swap_file.page_content(4, true).unwrap().is_none());
        assert_page_content(&swap_file, 5, &vec![3; pagesize()]);
        assert_page_content(&swap_file, 6, &vec![3; pagesize()]);
        assert_page_content(&swap_file, 7, &vec![3; pagesize()]);
        assert_page_content(&swap_file, 8, &vec![3; pagesize()]);
        assert!(swap_file.page_content(9, true).unwrap().is_none());

        let data =
            FileDataIterator::new(&file, 0, file.metadata().unwrap().len()).collect::<Vec<_>>();
        assert_eq!(data, vec![0..6 * pagesize() as u64]);
    }

    #[test]
    #[cfg(target_arch = "x86_64")] // TODO(b/272612118): unit test infra (qemu-user) support
    fn clear_mlock() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        swap_file
            .write_to_file(1, &vec![1; 10 * pagesize()])
            .unwrap();
        // success if there is no mlock.
        assert!(swap_file.clear_mlock().is_ok());

        assert_eq!(swap_file.lock_and_async_prefetch(11).unwrap(), 10);
        // success if there is mlocked area.
        assert!(swap_file.clear_mlock().is_ok());

        // mlock area is cleared.
        assert_eq!(swap_file.lock_and_async_prefetch(11).unwrap(), 10);
    }

    #[test]
    fn first_data_range() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        swap_file
            .write_to_file(1, &vec![1; 2 * pagesize()])
            .unwrap();
        swap_file.write_to_file(3, &vec![2; pagesize()]).unwrap();

        assert_eq!(swap_file.first_data_range(200).unwrap(), 1..4);
        assert_eq!(swap_file.first_data_range(2).unwrap(), 1..3);
        assert_eq!(swap_file.first_data_range(1).unwrap(), 1..2);
        swap_file.clear_range(1..3).unwrap();
        assert_eq!(swap_file.first_data_range(2).unwrap(), 3..4);
        swap_file.clear_range(3..4).unwrap();
        assert!(swap_file.first_data_range(2).is_none());
    }

    #[test]
    fn get_slice() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        swap_file.write_to_file(1, &vec![1; pagesize()]).unwrap();
        swap_file.write_to_file(2, &vec![2; pagesize()]).unwrap();

        let slice = swap_file.get_slice(1..3).unwrap();
        assert_eq!(slice.size(), 2 * pagesize());
        let mut buf = vec![0u8; pagesize()];
        slice.get_slice(0, pagesize()).unwrap().copy_to(&mut buf);
        assert_eq!(buf, vec![1; pagesize()]);

        let mut buf = vec![0u8; pagesize()];
        slice
            .get_slice(pagesize(), pagesize())
            .unwrap()
            .copy_to(&mut buf);
        assert_eq!(buf, vec![2; pagesize()]);
    }

    #[test]
    fn get_slice_out_of_range() {
        let file = tempfile::tempfile().unwrap();
        let swap_file = SwapFile::new(&file, 200).unwrap();

        match swap_file.get_slice(200..201) {
            Err(Error::OutOfRange) => {}
            other => {
                unreachable!("unexpected result {:?}", other);
            }
        }
    }

    #[test]
    fn present_pages() {
        let file = tempfile::tempfile().unwrap();
        let mut swap_file = SwapFile::new(&file, 200).unwrap();

        swap_file.write_to_file(1, &vec![1; pagesize()]).unwrap();
        swap_file.write_to_file(2, &vec![2; pagesize()]).unwrap();

        assert_eq!(swap_file.present_pages(), 2);
    }
}
