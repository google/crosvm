// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::c_void;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::mem::size_of;
use std::ops::Range;
use std::path::Path;

use win_util::LargeInteger;
use winapi::um::fileapi::GetFileSizeEx;
pub use winapi::um::winioctl::FSCTL_QUERY_ALLOCATED_RANGES;
pub use winapi::um::winioctl::FSCTL_SET_SPARSE;
use winapi::um::winnt::LARGE_INTEGER;

use crate::descriptor::AsRawDescriptor;
use crate::Error;
use crate::Result;

/// Open the file with the given path.
///
/// Note that on POSIX, this wrapper handles opening existing FDs via /proc/self/fd/N. On Windows,
/// this functionality doesn't exist, but we preserve this seemingly not very useful function to
/// simplify cross platform code.
pub fn open_file_or_duplicate<P: AsRef<Path>>(path: P, options: &OpenOptions) -> Result<File> {
    Ok(options.open(path)?)
}

/// Marks the given file as sparse. Required if we want hole punching to be performant.
/// (If a file is not marked as sparse, a hole punch will just write zeros.)
/// # Safety
///    handle *must* be File. We accept all AsRawDescriptors for convenience.
pub fn set_sparse_file<T: AsRawDescriptor>(handle: &T) -> io::Result<()> {
    // SAFETY:
    // Safe because we check the return value and handle is guaranteed to be a
    // valid file handle by the caller.
    let result = unsafe {
        super::ioctl::ioctl_with_ptr(handle, FSCTL_SET_SPARSE, std::ptr::null_mut::<c_void>())
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FileAllocatedRangeBuffer {
    file_offset: LARGE_INTEGER,
    length: LARGE_INTEGER,
}

/// Helper routine that converts LARGE_INTEGER to u64
/// # Safety
/// Within this scope it is not possible to use LARGE_INTEGER as something else.
fn large_integer_as_u64(lint: &LARGE_INTEGER) -> u64 {
    // SAFETY:
    // Safe because we use LARGE_INTEGER only as i64 or as u64 within this scope.
    unsafe { *lint.QuadPart() as u64 }
}

impl FileAllocatedRangeBuffer {
    pub fn start(&self) -> u64 {
        large_integer_as_u64(&self.file_offset)
    }

    pub fn end(&self) -> u64 {
        self.start() + self.length()
    }

    pub fn length(&self) -> u64 {
        large_integer_as_u64(&self.length)
    }
}

/// On success returns a vector of ranges with a file that have storage allocated
/// for them. The range is half-open [start, end) offsets.
/// Contiguous allocated ranges may not be coalesced meaning the output may contain
/// two or more ranges which could have been coalesced into one - ex: Output may
/// contain [0..100, 100.. 200] instead of just one range [0..200]
/// # Safety
///    descriptor *must* be File. We accept all AsRawDescriptors for convenience.
pub fn get_allocated_ranges<T: AsRawDescriptor>(descriptor: &T) -> Result<Vec<Range<u64>>> {
    let mut ranges = vec![];
    let mut file_size = *LargeInteger::new(0);

    // SAFETY:
    // Safe because we check return value.
    unsafe {
        let failed = GetFileSizeEx(descriptor.as_raw_descriptor(), &mut file_size);
        if failed == 0 {
            return crate::errno_result();
        }
    };

    // Query the range for the entire file. This gets updated if the file has
    // more ranges than what alloc_ranges can hold.
    let mut query_range = FileAllocatedRangeBuffer {
        file_offset: *LargeInteger::new(0),
        length: *LargeInteger::new(0),
    };
    query_range.file_offset = *LargeInteger::new(0);
    query_range.length = file_size;

    // Preallocated/initialized container for allocated ranges.
    let mut alloc_ranges: Vec<FileAllocatedRangeBuffer> =
        vec![Default::default(); if cfg!(test) { 1 } else { 1024 }];

    loop {
        let mut bytes_ret: u32 = 0;
        // SAFETY:
        // Safe because we return error on failure and all references have
        // bounded lifetime.
        // If the `alloc_ranges` buffer is smaller than the actual allocated ranges,
        // device_io_control returns error ERROR_MORE_DATA with `alloc_ranges` filled with
        // `bytes_ret` bytes worth of allocated ranges. On getting `ERROR_MORE_DATA` error,
        //  we update the query_range to reflect new offset range that we want to query.
        unsafe {
            crate::device_io_control(
                descriptor,
                FSCTL_QUERY_ALLOCATED_RANGES,
                &query_range,
                size_of::<FileAllocatedRangeBuffer>() as u32,
                alloc_ranges.as_mut_ptr(),
                (size_of::<FileAllocatedRangeBuffer>() * alloc_ranges.len()) as u32,
                &mut bytes_ret,
            )
            .or_else(|err| {
                if Error::new(winapi::shared::winerror::ERROR_MORE_DATA as i32) == err {
                    Ok(())
                } else {
                    Err(err)
                }
            })?
        };

        // Calculate number of entries populated by the syscall.
        let range_count = (bytes_ret / size_of::<FileAllocatedRangeBuffer>() as u32) as usize;

        // This guards against somethis that went really wrong with the syscall
        // to not return bytes that are multiple of struct size.
        if (range_count * size_of::<FileAllocatedRangeBuffer>()) != bytes_ret as usize {
            panic!("Something went wrong");
        }

        // device_io_control returned successfully with empty output buffer implies
        // that there are no more allocated ranges in the file.
        if range_count == 0 {
            break;
        }

        for r in &alloc_ranges[0..range_count] {
            let range = r.start()..r.end();
            ranges.push(range);
        }

        // Update offset so that we resume from where last call ended successfully.
        query_range.file_offset = *LargeInteger::new(alloc_ranges[range_count - 1].end() as i64);
        query_range.length =
            *LargeInteger::new((large_integer_as_u64(&file_size) - query_range.start()) as i64);
    }

    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::windows::prelude::FileExt;

    use tempfile::tempfile;

    use super::get_allocated_ranges;
    use super::set_sparse_file;

    #[test]
    fn get_allocated_ranges_for_empty_file() {
        let file = tempfile().unwrap();
        set_sparse_file(&file).unwrap();
        let ranges = get_allocated_ranges(&file).unwrap();
        assert!(ranges.is_empty());
    }

    #[test]
    fn get_allocated_ranges_for_fully_allocated_file() {
        let mut file = tempfile().unwrap();
        set_sparse_file(&file).unwrap();
        let zeroes = vec![0; 1024 * 1024];
        file.write_all(&zeroes).unwrap();
        let ranges = get_allocated_ranges(&file).unwrap();
        // Output will have at least one allocated range.
        assert!(!ranges.is_empty());
        let mut old_range: Option<std::ops::Range<u64>> = None;
        for r in ranges {
            if old_range.is_none() {
                assert_eq!(r.start, 0);
            } else {
                assert_eq!(r.start, old_range.as_ref().unwrap().end);
            }
            old_range = Some(r.clone());
        }
    }

    #[test]
    fn get_allocated_ranges_for_file_with_one_hole() {
        let mut file = tempfile().unwrap();
        set_sparse_file(&file).unwrap();
        let zeroes = vec![1; 1024 * 1024];
        file.write_all(&zeroes).unwrap();
        file.set_len(1024 * 1024 * 3).unwrap();
        file.seek_write(&zeroes, 1024 * 1024 * 2).unwrap();
        let ranges = get_allocated_ranges(&file).unwrap();
        assert!(ranges.len() > 1);

        let mut old_range: Option<std::ops::Range<u64>> = None;
        for r in ranges {
            // First allocated range starts at 0 offset
            if old_range.is_none() {
                assert_eq!(r.start, 0);
            } else if r.start != old_range.as_ref().unwrap().end {
                // The allocated range before the hole ends at 1M offset.
                assert_eq!(old_range.as_ref().unwrap().end, 1024 * 1024 * 1);
                // The allocated range after the hole starts at 2M offset.
                assert_eq!(r.start, 1024 * 1024 * 2);
            }
            old_range = Some(r.clone());
        }
        assert_eq!(old_range.as_ref().unwrap().end, 1024 * 1024 * 3);
    }

    #[test]
    fn get_allocated_ranges_for_file_with_many_hole() {
        let mut file = tempfile().unwrap();
        set_sparse_file(&file).unwrap();
        let data = vec![1; 1024];
        file.write_all(&data).unwrap();
        const RANGE_COUNT: u64 = 2048;
        file.set_len(1024 * 1024 * RANGE_COUNT).unwrap();
        for i in 1..RANGE_COUNT {
            file.seek_write(&data, 1024 * 1024 * i).unwrap();
        }
        let ranges = get_allocated_ranges(&file).unwrap();
        assert_eq!(ranges.len(), RANGE_COUNT as usize);
    }
}
