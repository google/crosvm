// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::IntoRawHandle;
use std::os::windows::io::OwnedHandle;
use std::os::windows::io::RawHandle;
use std::os::windows::raw::HANDLE;

use crate::rutabaga_os::descriptor::AsRawDescriptor;
use crate::rutabaga_os::descriptor::FromRawDescriptor;
use crate::rutabaga_os::descriptor::IntoRawDescriptor;

pub type RawDescriptor = RawHandle;
// Same as winapi::um::handleapi::INVALID_HANDLE_VALUE, but avoids compile issues.
pub const DEFAULT_RAW_DESCRIPTOR: RawDescriptor = -1isize as HANDLE;

type Error = std::io::Error;
type Result<T> = std::result::Result<T, Error>;

pub struct OwnedDescriptor {
    owned: OwnedHandle,
}

impl OwnedDescriptor {
    pub fn try_clone(&self) -> Result<OwnedDescriptor> {
        let clone = self.owned.try_clone()?;
        Ok(OwnedDescriptor { owned: clone })
    }
}

impl AsRawDescriptor for OwnedDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.owned.as_raw_handle()
    }
}

impl FromRawDescriptor for OwnedDescriptor {
    // SAFETY: It is caller's responsibility to ensure that the descriptor is valid.
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        OwnedDescriptor {
            owned: OwnedHandle::from_raw_handle(descriptor),
        }
    }
}

impl IntoRawDescriptor for OwnedDescriptor {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.owned.into_raw_handle()
    }
}

impl IntoRawDescriptor for File {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.into_raw_handle()
    }
}

impl From<File> for OwnedDescriptor {
    fn from(f: File) -> OwnedDescriptor {
        OwnedDescriptor { owned: f.into() }
    }
}
