// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::ErrorKind as IoErrorKind;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::RawFd;

use libc::O_ACCMODE;
use libc::O_WRONLY;
use nix::fcntl::fcntl;
use nix::fcntl::FcntlArg;
use nix::unistd::lseek;
use nix::unistd::Whence;

use crate::rutabaga_os::descriptor::AsRawDescriptor;
use crate::rutabaga_os::descriptor::FromRawDescriptor;
use crate::rutabaga_os::descriptor::IntoRawDescriptor;
use crate::rutabaga_os::DescriptorType;

pub type RawDescriptor = RawFd;
pub const DEFAULT_RAW_DESCRIPTOR: RawDescriptor = -1;

type Error = std::io::Error;
type Result<T> = std::result::Result<T, Error>;

pub struct OwnedDescriptor {
    owned: OwnedFd,
}

impl OwnedDescriptor {
    pub fn try_clone(&self) -> Result<OwnedDescriptor> {
        let clone = self.owned.try_clone()?;
        Ok(OwnedDescriptor { owned: clone })
    }

    pub fn determine_type(&self) -> Result<DescriptorType> {
        match lseek(self.as_raw_descriptor(), 0, Whence::SeekEnd) {
            Ok(seek_size) => {
                let size: u32 = seek_size
                    .try_into()
                    .map_err(|_| Error::from(IoErrorKind::Unsupported))?;
                Ok(DescriptorType::Memory(size))
            }
            _ => {
                let flags = fcntl(self.as_raw_descriptor(), FcntlArg::F_GETFL)?;
                match flags & O_ACCMODE {
                    O_WRONLY => Ok(DescriptorType::WritePipe),
                    _ => Err(Error::from(IoErrorKind::Unsupported)),
                }
            }
        }
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

impl From<OwnedFd> for OwnedDescriptor {
    fn from(o: OwnedFd) -> OwnedDescriptor {
        OwnedDescriptor { owned: o }
    }
}
