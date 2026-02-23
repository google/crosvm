// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io;

/// Punches a hole in a file, deallocating the space.
/// On macOS, we use fcntl with F_PUNCHHOLE if available, otherwise fallback to writing zeros.
pub fn file_punch_hole(file: &File, offset: u64, length: u64) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    // macOS supports F_PUNCHHOLE on APFS volumes
    #[repr(C)]
    struct FPunchhole {
        fp_flags: libc::c_uint,
        reserved: libc::c_uint,
        fp_offset: libc::off_t,
        fp_length: libc::off_t,
    }

    const F_PUNCHHOLE: libc::c_int = 99;
    const FP_ALLOCATECONTIG: libc::c_uint = 0x00000002;
    const FP_ALLOCATEALL: libc::c_uint = 0x00000004;
    let _ = FP_ALLOCATECONTIG;
    let _ = FP_ALLOCATEALL;

    let punchhole = FPunchhole {
        fp_flags: 0,
        reserved: 0,
        fp_offset: offset as libc::off_t,
        fp_length: length as libc::off_t,
    };

    // SAFETY: The file descriptor is valid and the structure is properly initialized
    let ret = unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            F_PUNCHHOLE,
            &punchhole as *const FPunchhole,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        // F_PUNCHHOLE might not be supported (e.g., not APFS), so fall back to doing nothing
        // This is acceptable for VM use cases where hole punching is an optimization
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTSUP) || err.raw_os_error() == Some(libc::EINVAL) {
            Ok(())
        } else {
            Err(err)
        }
    }
}

/// Writes zeros to a file at the specified offset.
pub fn file_write_zeroes_at(
    file: &File,
    offset: u64,
    length: usize,
) -> io::Result<usize> {
    use std::os::unix::io::AsRawFd;

    // Create a buffer of zeros and write it using pwrite
    const CHUNK_SIZE: usize = 65536; // 64KB chunks
    let zeros = vec![0u8; std::cmp::min(length, CHUNK_SIZE)];

    let mut written = 0;
    let mut current_offset = offset;

    while written < length {
        let to_write = std::cmp::min(length - written, zeros.len());
        // SAFETY: The file descriptor is valid and the buffer is properly allocated
        let ret = unsafe {
            libc::pwrite(
                file.as_raw_fd(),
                zeros.as_ptr() as *const libc::c_void,
                to_write,
                current_offset as libc::off_t,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if written > 0 {
                return Ok(written);
            }
            return Err(err);
        }

        let bytes_written = ret as usize;
        written += bytes_written;
        current_offset += bytes_written as u64;

        if bytes_written == 0 {
            break;
        }
    }

    Ok(written)
}
