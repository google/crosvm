// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Exported interface to basic qcow functionality to be used from C.

use libc::{EINVAL, EIO, ENOSYS};
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::os::raw::{c_char, c_int};

use base::{flock, FlockOperation};
use disk::{self, DiskFile, ImageType, QcowFile};

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

#[no_mangle]
pub unsafe extern "C" fn expand_disk_image(path: *const c_char, virtual_size: u64) -> c_int {
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

    let raw_image = match OpenOptions::new().read(true).write(true).open(file_path) {
        Ok(f) => f,
        Err(_) => return -EIO,
    };

    // Lock the disk image to prevent other processes from using it.
    if flock(&raw_image, FlockOperation::LockExclusive, true).is_err() {
        return -EIO;
    }

    let image_type = match disk::detect_image_type(&raw_image) {
        Ok(t) => t,
        Err(_) => return -EINVAL,
    };

    let disk_image: Box<dyn DiskFile> = match image_type {
        ImageType::Raw => Box::new(raw_image),
        ImageType::Qcow2 => match QcowFile::from(raw_image, disk::MAX_NESTING_DEPTH) {
            Ok(f) => Box::new(f),
            Err(_) => return -EINVAL,
        },
        _ => return -EINVAL,
    };

    // For safety against accidentally shrinking the disk image due to a
    // programming error elsewhere, verify that the new size is larger than
    // the current size.  This is safe against races due to the exclusive
    // flock() taken above - this is only an advisory lock, but it is also
    // acquired by other instances of this function as well as crosvm
    // itself when running a VM, so this should be safe in all cases that
    // can access a disk image in normal operation.
    let current_size = match disk_image.get_len() {
        Ok(len) => len,
        Err(_) => return -EIO,
    };
    if current_size >= virtual_size {
        return 0;
    }

    match disk_image.set_len(virtual_size) {
        Ok(_) => 0,
        Err(_) => -ENOSYS,
    }
}
