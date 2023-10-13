// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

use win_util::fail_if_zero;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::LPCVOID;
use winapi::shared::minwindef::LPVOID;
use winapi::shared::minwindef::TRUE;
use winapi::shared::winerror::ERROR_IO_PENDING;
use winapi::um::fileapi::ReadFile;
use winapi::um::fileapi::WriteFile;
use winapi::um::ioapiset::GetOverlappedResult;
use winapi::um::minwinbase::OVERLAPPED;

use crate::AsRawDescriptor;
use crate::Event;
use crate::RawDescriptor;

/// # Safety
/// 1. buf points to memory that will not be freed until the write operation completes.
/// 2. buf points to at least buf_len bytes.
pub unsafe fn write_file(
    handle: &dyn AsRawDescriptor,
    buf: *const u8,
    buf_len: usize,
    overlapped: Option<&mut OVERLAPPED>,
) -> io::Result<usize> {
    let is_overlapped = overlapped.is_some();

    // Safe because buf points to a valid region of memory whose size we have computed,
    // pipe has not been closed (as it's managed by this object), and we check the return
    // value for any errors
    let mut bytes_written: DWORD = 0;
    let success_flag = WriteFile(
        handle.as_raw_descriptor(),
        buf as LPCVOID,
        buf_len
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        match overlapped {
            Some(_) => std::ptr::null_mut(),
            None => &mut bytes_written,
        },
        match overlapped {
            Some(v) => v,
            None => std::ptr::null_mut(),
        },
    );

    if success_flag == 0 {
        let err = io::Error::last_os_error();
        if Some(ERROR_IO_PENDING as i32) == err.raw_os_error() && is_overlapped {
            Ok(0)
        } else {
            Err(err)
        }
    } else {
        Ok(bytes_written as usize)
    }
}

/// # Safety
/// 1. buf points to memory that will not be freed until the read operation completes.
/// 2. buf points to at least buf_len bytes.
pub unsafe fn read_file(
    handle: &dyn AsRawDescriptor,
    buf: *mut u8,
    buf_len: usize,
    overlapped: Option<&mut OVERLAPPED>,
) -> io::Result<usize> {
    // Used to verify if ERROR_IO_PENDING should be an error.
    let is_overlapped = overlapped.is_some();

    // Safe because we cap the size of the read to the size of the buffer
    // and check the return code
    let mut bytes_read: DWORD = 0;
    let success_flag = ReadFile(
        handle.as_raw_descriptor(),
        buf as LPVOID,
        buf_len as DWORD,
        match overlapped {
            Some(_) => std::ptr::null_mut(),
            None => &mut bytes_read,
        },
        match overlapped {
            Some(v) => v,
            None => std::ptr::null_mut(),
        },
    );

    if success_flag == 0 {
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            // ERROR_IO_PENDING, according the to docs, isn't really an error. This just means
            // that the ReadFile operation hasn't completed. In this case,
            // `get_overlapped_result` will wait until the operation is completed.
            Some(error_code) if error_code == ERROR_IO_PENDING as i32 && is_overlapped => Ok(0),
            _ => Err(e),
        }
    } else {
        Ok(bytes_read as usize)
    }
}

fn set_overlapped_offset(overlapped: &mut OVERLAPPED, offset: u64) {
    // # Safety: Safe because overlapped is allocated, and we are manipulating non-overlapping
    //           fields.
    unsafe {
        overlapped.u.s_mut().Offset = (offset & 0xffffffff) as DWORD;
        overlapped.u.s_mut().OffsetHigh = (offset >> 32) as DWORD;
    }
}

// Creates a new `OVERLAPPED` struct with given, if any, offset and event
pub fn create_overlapped(offset: Option<u64>, event: Option<RawDescriptor>) -> OVERLAPPED {
    let mut overlapped = OVERLAPPED::default();
    if let Some(offset) = offset {
        set_overlapped_offset(&mut overlapped, offset);
    }
    if let Some(event) = event {
        overlapped.hEvent = event;
    }
    overlapped
}

/// Reads buf from given handle from offset in a blocking mode.
/// handle is expected to be opened in overlapped mode.
pub fn read_overlapped_blocking(
    handle: &dyn AsRawDescriptor,
    offset: u64,
    buf: &mut [u8],
) -> io::Result<usize> {
    let mut size_transferred = 0;
    let event = Event::new()?;
    let mut overlapped = create_overlapped(Some(offset), Some(event.as_raw_descriptor()));

    // Safety: Safe because we check return values after the calls.
    unsafe {
        let _ = read_file(handle, buf.as_mut_ptr(), buf.len(), Some(&mut overlapped))?;
        fail_if_zero!(GetOverlappedResult(
            handle.as_raw_descriptor(),
            &mut overlapped,
            &mut size_transferred,
            TRUE,
        ));
    }
    Ok(size_transferred as usize)
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::PathBuf;

    use tempfile::TempDir;
    use winapi::um::winbase::FILE_FLAG_OVERLAPPED;

    use super::*;
    fn tempfile_path() -> (PathBuf, TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let mut file_path = PathBuf::from(dir.path());
        file_path.push("test");
        (file_path, dir)
    }

    fn open_overlapped(path: &PathBuf) -> File {
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .open(path)
            .unwrap()
    }

    fn open_blocking(path: &PathBuf) -> File {
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }

    #[test]
    fn test_read_overlapped() {
        let (file_path, _tmpdir) = tempfile_path();
        let mut f = open_blocking(&file_path);
        let data: [u8; 6] = [0, 1, 2, 3, 5, 6];
        f.write_all(&data).unwrap();
        f.flush().unwrap();
        drop(f);

        let of = open_overlapped(&file_path);
        let mut buf: [u8; 3] = [0; 3];
        read_overlapped_blocking(&of, 3, &mut buf).unwrap();
        assert_eq!(buf, data[3..6]);
    }
}
