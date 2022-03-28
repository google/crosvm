// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::descriptor::AsRawDescriptor;
use crate::IoctlNr;
use std::os::raw::{c_int, c_ulong, c_void};

/// Run an ioctl with no arguments.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl<F: AsRawDescriptor>(descriptor: &F, nr: IoctlNr) -> c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, 0)
}

/// Run an ioctl with a single value argument.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_val(descriptor: &dyn AsRawDescriptor, nr: IoctlNr, arg: c_ulong) -> c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg)
}

/// Run an ioctl with an immutable reference.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_ref<T>(descriptor: &dyn AsRawDescriptor, nr: IoctlNr, arg: &T) -> c_int {
    libc::ioctl(
        descriptor.as_raw_descriptor(),
        nr,
        arg as *const T as *const c_void,
    )
}

/// Run an ioctl with a mutable reference.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_mut_ref<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: &mut T,
) -> c_int {
    libc::ioctl(
        descriptor.as_raw_descriptor(),
        nr,
        arg as *mut T as *mut c_void,
    )
}

/// Run an ioctl with a raw pointer.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_ptr<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: *const T,
) -> c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg as *const c_void)
}

/// Run an ioctl with a mutable raw pointer.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_mut_ptr<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: *mut T,
) -> c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg as *mut c_void)
}
