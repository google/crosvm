// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::{PollToken, Result};
use std::{
    convert::TryFrom,
    fs::File,
    io::{Stderr, Stdin, Stdout},
    mem,
    ops::Drop,
};

use serde::{Deserialize, Serialize};

// Windows imports
use std::{
    ffi::CString,
    marker::{Send, Sync},
    mem::{ManuallyDrop, MaybeUninit},
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle},
    sync::Once,
};
use win_util::{duplicate_handle, win32_wide_string};
use winapi::{
    shared::minwindef::{BOOL, HMODULE, TRUE},
    um::{
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        libloaderapi,
    },
};

pub type RawDescriptor = RawHandle;

pub const INVALID_DESCRIPTOR: RawDescriptor = INVALID_HANDLE_VALUE;

/// Trait for forfeiting ownership of the current raw descriptor, and returning the raw descriptor
pub trait IntoRawDescriptor {
    fn into_raw_descriptor(self) -> RawDescriptor;
}

/// Trait for returning the underlying raw descriptor, without giving up ownership of the
/// descriptor.
pub trait AsRawDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor;
}

pub trait FromRawDescriptor {
    /// # Safety
    /// Safe only if the caller ensures nothing has access to the descriptor after passing it to
    /// `from_raw_descriptor`
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self;
}

/// Wraps a RawDescriptor and safely closes it when self falls out of scope.
#[derive(Serialize, Deserialize, Debug, Eq)]
#[serde(transparent)]
pub struct SafeDescriptor {
    #[serde(with = "super::with_raw_descriptor")]
    descriptor: RawDescriptor,
}

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

impl AsRawDescriptor for SafeDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor
    }
}

impl IntoRawDescriptor for SafeDescriptor {
    fn into_raw_descriptor(self) -> RawDescriptor {
        let descriptor = self.descriptor;
        mem::forget(self);
        descriptor
    }
}

impl FromRawDescriptor for SafeDescriptor {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        SafeDescriptor { descriptor }
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

impl TryFrom<&dyn AsRawDescriptor> for SafeDescriptor {
    type Error = std::io::Error;

    /// Clones the underlying descriptor (handle), internally creating a new descriptor.
    ///
    /// WARNING: Windows does NOT support cloning/duplicating all types of handles. DO NOT use this
    /// function on IO completion ports, sockets, or pseudo-handles (except those from
    /// GetCurrentProcess or GetCurrentThread). See
    /// https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
    /// for further details.
    ///
    /// TODO(b/191800567): this API has sharp edges on Windows. We should evaluate making some
    /// adjustments to smooth those edges.
    fn try_from(rd: &dyn AsRawDescriptor) -> std::result::Result<Self, Self::Error> {
        // Safe because the underlying raw descriptor is guaranteed valid by rd's existence.
        //
        // Note that we are cloning the underlying raw descriptor since we have no guarantee of
        // its existence after this function returns.
        let rd_as_safe_desc = ManuallyDrop::new(unsafe {
            SafeDescriptor::from_raw_descriptor(rd.as_raw_descriptor())
        });

        // We have to clone rd because we have no guarantee ownership was transferred (rd is
        // borrowed).
        rd_as_safe_desc
            .try_clone()
            .map_err(|e| Self::Error::from_raw_os_error(e.errno()))
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

impl From<File> for SafeDescriptor {
    fn from(f: File) -> SafeDescriptor {
        // Safe because we own the File at this point.
        unsafe { SafeDescriptor::from_raw_descriptor(f.into_raw_descriptor()) }
    }
}

/// For use cases where a simple wrapper around a RawDescriptor is needed.
/// This is a simply a wrapper and does not manage the lifetime of the descriptor.
/// Most usages should prefer SafeDescriptor or using a RawDescriptor directly
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Descriptor(pub RawDescriptor);
impl AsRawDescriptor for Descriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0
    }
}

impl PollToken for Descriptor {
    fn as_raw_token(&self) -> u64 {
        self.0 as u64
    }

    fn from_raw_token(data: u64) -> Self {
        Descriptor(data as RawDescriptor)
    }
}

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

#[test]
#[allow(clippy::eq_op)]
fn clone_equality() {
    use super::{Event, IntoRawDescriptor};

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
