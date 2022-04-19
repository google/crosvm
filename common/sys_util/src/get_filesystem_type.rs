// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::{syscall, Result};
use libc::fstatfs;
use std::{fs::File, mem::MaybeUninit, os::unix::io::AsRawFd};

/// Obtain file system type of the file system that the file is served from.
pub fn get_filesystem_type(file: &File) -> Result<i64> {
    let mut statfs_buf = MaybeUninit::<libc::statfs>::uninit();
    // Safe because we just got the memory space with exact required amount and
    // passing that on.
    syscall!(unsafe { fstatfs(file.as_raw_fd(), statfs_buf.as_mut_ptr()) })?;
    // Safe because the kernel guarantees the struct is initialized.
    let statfs_buf = unsafe { statfs_buf.assume_init() };
    Ok(statfs_buf.f_type as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simple_test() {
        let file = File::open("/dev/null").unwrap();
        let _fstype = get_filesystem_type(&file).unwrap();
    }
}
