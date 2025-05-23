// Copyright 2025 Google
// SPDX-License-Identifier: MIT

use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::RawFd;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::DescriptorType;

pub type RawDescriptor = RawFd;
pub const DEFAULT_RAW_DESCRIPTOR: RawDescriptor = -1;

pub struct OwnedDescriptor {
    owned: OwnedFd,
}

impl OwnedDescriptor {
    pub fn try_clone(&self) -> Result<OwnedDescriptor> {
        let clone = self.owned.try_clone()?;
        Ok(OwnedDescriptor { owned: clone })
    }

    pub fn determine_type(&self) -> Result<DescriptorType> {
        Err(Error::from(ErrorKind::Unsupported))
    }
}

impl AsRawDescriptor for OwnedDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.owned.as_raw_fd()
    }
}

impl FromRawDescriptor for OwnedDescriptor {
    // SAFETY:
    // It is caller's responsibility to ensure that the descriptor is valid and
    // stays valid for the lifetime of Self
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        OwnedDescriptor {
            owned: OwnedFd::from_raw_fd(descriptor),
        }
    }
}

impl IntoRawDescriptor for OwnedDescriptor {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.owned.into_raw_fd()
    }
}

impl AsFd for OwnedDescriptor {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.owned.as_fd()
    }
}

impl AsRawDescriptor for File {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.as_raw_fd()
    }
}

impl FromRawDescriptor for File {
    // SAFETY:
    // It is caller's responsibility to ensure that the descriptor is valid and
    // stays valid for the lifetime of Self
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        File::from_raw_fd(descriptor)
    }
}

impl IntoRawDescriptor for File {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.into_raw_fd()
    }
}

impl From<File> for OwnedDescriptor {
    fn from(f: File) -> OwnedDescriptor {
        OwnedDescriptor { owned: f.into() }
    }
}
