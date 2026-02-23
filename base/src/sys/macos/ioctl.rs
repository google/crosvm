// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::AsRawDescriptor;

pub type IoctlNr = std::ffi::c_ulong;

/// Executes an ioctl with no arguments.
///
/// # Safety
///
/// The caller must ensure that the ioctl number is valid for the
/// given file descriptor.
pub unsafe fn ioctl<F: AsRawDescriptor>(
    descriptor: &F,
    nr: IoctlNr,
) -> std::ffi::c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr)
}

/// Executes an ioctl with a value argument.
///
/// # Safety
///
/// The caller must ensure that the ioctl number is valid for the
/// given file descriptor and that the value is appropriate.
pub unsafe fn ioctl_with_val(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: std::ffi::c_ulong,
) -> std::ffi::c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg)
}

/// Executes an ioctl with a const reference argument.
///
/// # Safety
///
/// The caller must ensure that the ioctl number is valid for the
/// given file descriptor and that the reference points to valid data.
pub unsafe fn ioctl_with_ref<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: &T,
) -> std::ffi::c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg as *const T)
}

/// Executes an ioctl with a mutable reference argument.
///
/// # Safety
///
/// The caller must ensure that the ioctl number is valid for the
/// given file descriptor and that the reference points to valid data.
pub unsafe fn ioctl_with_mut_ref<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: &mut T,
) -> std::ffi::c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg as *mut T)
}

/// Executes an ioctl with a const pointer argument.
///
/// # Safety
///
/// The caller must ensure that the ioctl number is valid for the
/// given file descriptor and that the pointer is valid.
pub unsafe fn ioctl_with_ptr<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: *const T,
) -> std::ffi::c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg)
}

/// Executes an ioctl with a mutable pointer argument.
///
/// # Safety
///
/// The caller must ensure that the ioctl number is valid for the
/// given file descriptor and that the pointer is valid.
pub unsafe fn ioctl_with_mut_ptr<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: *mut T,
) -> std::ffi::c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg)
}
