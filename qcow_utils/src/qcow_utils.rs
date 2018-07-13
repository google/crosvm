// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Exported interface to basic qcow functionality to be used from C.

extern crate libc;
extern crate qcow;

use libc::EINVAL;
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::os::raw::{c_char, c_int};

use qcow::QcowFile;

#[no_mangle]
pub unsafe extern "C" fn create_qcow_with_size(path: *const c_char, virtual_size: u64) -> c_int {
    // NULL pointers are checked, but this will access any other invalid pointer passed from C
    // code. It's the caller's responsibility to pass a valid pointer.
    if path.is_null() {
        return -EINVAL;
    }
    let c_str = CStr::from_ptr(path);
    let file_path = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -EINVAL,
    };

    let file = match OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(file_path)
    {
        Ok(f) => f,
        Err(_) => return -1,
    };

    match QcowFile::new(file, virtual_size) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
