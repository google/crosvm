// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::io::RawFd;

use libc::c_int;
use libc::fcntl;
use libc::F_GETFL;
use libc::F_SETFL;

use crate::errno::Result;
use crate::syscall;

/// Returns the file flags set for the given `RawFD`
///
/// Returns an error if the OS indicates the flags can't be retrieved.
fn get_fd_flags(fd: RawFd) -> Result<c_int> {
    // Safe because no third parameter is expected and we check the return result.
    syscall!(unsafe { fcntl(fd, F_GETFL) })
}

/// Sets the file flags set for the given `RawFD`.
///
/// Returns an error if the OS indicates the flags can't be retrieved.
fn set_fd_flags(fd: RawFd, flags: c_int) -> Result<()> {
    // Safe because we supply the third parameter and we check the return result.
    // fcntlt is trusted not to modify the memory of the calling process.
    syscall!(unsafe { fcntl(fd, F_SETFL, flags) }).map(|_| ())
}

/// Performs a logical OR of the given flags with the FD's flags, setting the given bits for the
/// FD.
///
/// Returns an error if the OS indicates the flags can't be retrieved or set.
pub fn add_fd_flags(fd: RawFd, set_flags: c_int) -> Result<()> {
    let start_flags = get_fd_flags(fd)?;
    set_fd_flags(fd, start_flags | set_flags)
}

/// Clears the given flags in the FD's flags.
///
/// Returns an error if the OS indicates the flags can't be retrieved or set.
pub fn clear_fd_flags(fd: RawFd, clear_flags: c_int) -> Result<()> {
    let start_flags = get_fd_flags(fd)?;
    set_fd_flags(fd, start_flags & !clear_flags)
}
