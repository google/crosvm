// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Exported interface to basic qcow functionality to be used from C.

use libc::{EBADFD, EINVAL, EIO, ENOSYS};
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::mem::forget;
use std::os::raw::{c_char, c_int};
use std::os::unix::io::FromRawFd;
use std::panic::catch_unwind;

use qcow::{ImageType, QcowFile};
use sys_util::{flock, FileSetLen, FlockOperation};

trait DiskFile: FileSetLen + Seek {}
impl<D: FileSetLen + Seek> DiskFile for D {}

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
    if let Err(_) = flock(&raw_image, FlockOperation::LockExclusive, true) {
        return -EIO;
    }

    let image_type = match qcow::detect_image_type(&raw_image) {
        Ok(t) => t,
        Err(_) => return -EINVAL,
    };

    let mut disk_image: Box<DiskFile> = match image_type {
        ImageType::Raw => Box::new(raw_image),
        ImageType::Qcow2 => match QcowFile::from(raw_image) {
            Ok(f) => Box::new(f),
            Err(_) => return -EINVAL,
        },
    };

    // For safety against accidentally shrinking the disk image due to a
    // programming error elsewhere, verify that the new size is larger than
    // the current size.  This is safe against races due to the exclusive
    // flock() taken above - this is only an advisory lock, but it is also
    // acquired by other instances of this function as well as crosvm
    // itself when running a VM, so this should be safe in all cases that
    // can access a disk image in normal operation.
    let current_size = match disk_image.seek(SeekFrom::End(0)) {
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

#[no_mangle]
pub unsafe extern "C" fn convert_to_qcow2(src_fd: c_int, dst_fd: c_int) -> c_int {
    // The caller is responsible for passing valid file descriptors.
    // The caller retains ownership of the file descriptors.
    let src_file = File::from_raw_fd(src_fd);
    let src_file_owned = src_file.try_clone();
    forget(src_file);

    let dst_file = File::from_raw_fd(dst_fd);
    let dst_file_owned = dst_file.try_clone();
    forget(dst_file);

    match (src_file_owned, dst_file_owned) {
        (Ok(src_file), Ok(dst_file)) => {
            catch_unwind(
                || match qcow::convert(src_file, dst_file, ImageType::Qcow2) {
                    Ok(_) => 0,
                    Err(_) => -EIO,
                },
            )
            .unwrap_or(-EIO)
        }
        _ => -EBADFD,
    }
}

#[no_mangle]
pub unsafe extern "C" fn convert_to_raw(src_fd: c_int, dst_fd: c_int) -> c_int {
    // The caller is responsible for passing valid file descriptors.
    // The caller retains ownership of the file descriptors.
    let src_file = File::from_raw_fd(src_fd);
    let src_file_owned = src_file.try_clone();
    forget(src_file);

    let dst_file = File::from_raw_fd(dst_fd);
    let dst_file_owned = dst_file.try_clone();
    forget(dst_file);

    match (src_file_owned, dst_file_owned) {
        (Ok(src_file), Ok(dst_file)) => {
            catch_unwind(|| match qcow::convert(src_file, dst_file, ImageType::Raw) {
                Ok(_) => 0,
                Err(_) => -EIO,
            })
            .unwrap_or(-EIO)
        }
        _ => -EBADFD,
    }
}
