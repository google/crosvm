// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Error;
use std::os::unix::io::RawFd;
use std::ptr::null_mut;

use libc::{c_int, c_long, c_void, syscall, SYS_io_uring_enter, SYS_io_uring_setup};

use crate::bindings::*;

/// Returns the system error as the result;
pub type Result<T> = std::result::Result<T, c_int>;

pub unsafe fn io_uring_setup(num_entries: usize, params: &io_uring_params) -> Result<RawFd> {
    let ret = syscall(
        SYS_io_uring_setup as c_long,
        num_entries as c_int,
        params as *const _,
    );
    if ret < 0 {
        return Err(Error::last_os_error().raw_os_error().unwrap());
    }
    Ok(ret as RawFd)
}

pub unsafe fn io_uring_enter(fd: RawFd, to_submit: u64, to_wait: u64, flags: u32) -> Result<()> {
    let ret = syscall(
        SYS_io_uring_enter as c_long,
        fd,
        to_submit as c_int,
        to_wait as c_int,
        flags as c_int,
        null_mut::<*mut c_void>(),
    );
    if ret < 0 {
        return Err(Error::last_os_error().raw_os_error().unwrap());
    }
    Ok(())
}
