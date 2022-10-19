// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::ffi::CString;
use std::fs::File;
use std::io::Stderr;
use std::io::Stdin;
use std::io::Stdout;
use std::marker::Send;
use std::marker::Sync;
use std::mem::MaybeUninit;
use std::ops::Drop;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::IntoRawHandle;
use std::os::windows::io::RawHandle;
use std::sync::Once;

use win_util::duplicate_handle;
use win_util::win32_wide_string;
use winapi::shared::minwindef::BOOL;
use winapi::shared::minwindef::HMODULE;
use winapi::shared::minwindef::TRUE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::libloaderapi;

use super::Result;
use crate::descriptor::AsRawDescriptor;
use crate::descriptor::Descriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::descriptor::SafeDescriptor;

pub type RawDescriptor = RawHandle;

pub const INVALID_DESCRIPTOR: RawDescriptor = INVALID_HANDLE_VALUE;

impl PartialEq for SafeDescriptor {
    fn eq(&self, other: &Self) -> bool {
        return compare_object_handles(self.descriptor, other.as_raw_descriptor());
    }
}

impl Drop for SafeDescriptor {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.descriptor) };
    }
}

impl AsRawHandle for SafeDescriptor {
    fn as_raw_handle(&self) -> RawHandle {
        self.as_raw_descriptor()
    }
}

static KERNELBASE_INIT: Once = Once::new();
static mut KERNELBASE_LIBRARY: MaybeUninit<HMODULE> = MaybeUninit::uninit();

fn compare_object_handles(first: RawHandle, second: RawHandle) -> bool {
    KERNELBASE_INIT.call_once(|| {
        unsafe {
            *KERNELBASE_LIBRARY.as_mut_ptr() =
                libloaderapi::LoadLibraryW(win32_wide_string("Kernelbase").as_ptr());
        };
    });
    let handle = unsafe { KERNELBASE_LIBRARY.assume_init() };
    if handle.is_null() {
        return first == second;
    }

    let addr = CString::new("CompareObjectHandles").unwrap();
    let addr_ptr = addr.as_ptr();
    let symbol = unsafe { libloaderapi::GetProcAddress(handle, addr_ptr) };
    if symbol.is_null() {
        return first == second;
    }

    let func = unsafe {
        std::mem::transmute::<
            *mut winapi::shared::minwindef::__some_function,
            extern "system" fn(RawHandle, RawHandle) -> BOOL,
        >(symbol)
    };
    let ret = func(first, second);
    ret == TRUE
}

impl TryFrom<&dyn AsRawHandle> for SafeDescriptor {
    type Error = std::io::Error;

    fn try_from(handle: &dyn AsRawHandle) -> std::result::Result<Self, Self::Error> {
        Ok(SafeDescriptor {
            descriptor: duplicate_handle(handle.as_raw_handle())?,
        })
    }
}

impl SafeDescriptor {
    /// Clones this descriptor, internally creating a new descriptor. The new SafeDescriptor will
    /// share the same underlying count within the kernel.
    pub fn try_clone(&self) -> Result<SafeDescriptor> {
        // Safe because `duplicate_handle` will return a valid handle, or at the very least error
        // out.
        Ok(unsafe {
            SafeDescriptor::from_raw_descriptor(win_util::duplicate_handle(self.descriptor)?)
        })
    }
}

// On Windows, RawHandles are represented by raw pointers but are not used as such in
// rust code, and are therefore safe to send between threads.
unsafe impl Send for SafeDescriptor {}
unsafe impl Sync for SafeDescriptor {}

// On Windows, RawHandles are represented by raw pointers but are opaque to the
// userspace and cannot be derefenced by rust code, and are therefore safe to
// send between threads.
unsafe impl Send for Descriptor {}
unsafe impl Sync for Descriptor {}

macro_rules! AsRawDescriptor {
    ($name:ident) => {
        impl AsRawDescriptor for $name {
            fn as_raw_descriptor(&self) -> RawDescriptor {
                return self.as_raw_handle();
            }
        }
    };
}

macro_rules! FromRawDescriptor {
    ($name:ident) => {
        impl FromRawDescriptor for $name {
            unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
                return $name::from_raw_handle(descriptor);
            }
        }
    };
}

macro_rules! IntoRawDescriptor {
    ($name:ident) => {
        impl IntoRawDescriptor for $name {
            fn into_raw_descriptor(self) -> RawDescriptor {
                return self.into_raw_handle();
            }
        }
    };
}

// Implementations for File. This enables the File-type to use the cross-platform
// RawDescriptor, but does not mean File should be used as a generic
// descriptor container. That should go to either SafeDescriptor or another more
// relevant container type.
// TODO(b/148971445): Ensure there are no usages of File that aren't actually files.
AsRawDescriptor!(File);
FromRawDescriptor!(File);
IntoRawDescriptor!(File);
AsRawDescriptor!(Stdin);
AsRawDescriptor!(Stdout);
AsRawDescriptor!(Stderr);

#[cfg_attr(all(target_os = "windows", target_env = "gnu"), ignore)]
#[test]
#[allow(clippy::eq_op)]
fn clone_equality() {
    use crate::descriptor::IntoRawDescriptor;
    use crate::Event;

    let evt = Event::new().unwrap();
    let descriptor = unsafe { SafeDescriptor::from_raw_descriptor(evt.into_raw_descriptor()) };

    assert_eq!(descriptor, descriptor);

    assert_eq!(
        descriptor,
        descriptor.try_clone().expect("failed to clone event")
    );

    let evt2 = Event::new().unwrap();
    let another = unsafe { SafeDescriptor::from_raw_descriptor(evt2.into_raw_descriptor()) };

    assert_ne!(descriptor, another);
}
