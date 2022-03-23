// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    convert::TryFrom,
    fs::File,
    io::{Stderr, Stdin, Stdout},
    mem,
    mem::ManuallyDrop,
    net::UdpSocket,
    ops::Drop,
    os::unix::{
        io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
        net::{UnixDatagram, UnixListener, UnixStream},
    },
};

use serde::{Deserialize, Serialize};

use super::{
    errno_result,
    net::{UnixSeqpacket, UnlinkUnixSeqpacketListener},
    PollToken, Result,
};

pub type RawDescriptor = RawFd;

pub const INVALID_DESCRIPTOR: RawDescriptor = -1;

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

/// Clones `descriptor`, returning a new `RawDescriptor` that refers to the same open file
/// description as `descriptor`. The cloned descriptor will have the `FD_CLOEXEC` flag set but will
/// not share any other file descriptor flags with `descriptor`.
pub fn clone_descriptor(descriptor: &dyn AsRawDescriptor) -> Result<RawDescriptor> {
    clone_fd(&descriptor.as_raw_descriptor())
}

/// Clones `fd`, returning a new file descriptor that refers to the same open file description as
/// `fd`. The cloned fd will have the `FD_CLOEXEC` flag set but will not share any other file
/// descriptor flags with `fd`.
fn clone_fd(fd: &dyn AsRawFd) -> Result<RawFd> {
    // Safe because this doesn't modify any memory and we check the return value.
    let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if ret < 0 {
        errno_result()
    } else {
        Ok(ret)
    }
}

/// Wraps a RawDescriptor and safely closes it when self falls out of scope.
#[derive(Serialize, Deserialize, Debug, Eq)]
#[serde(transparent)]
pub struct SafeDescriptor {
    #[serde(with = "super::with_raw_descriptor")]
    descriptor: RawDescriptor,
}

const KCMP_FILE: u32 = 0;

impl PartialEq for SafeDescriptor {
    fn eq(&self, other: &Self) -> bool {
        // If RawFd numbers match then we can return early without calling kcmp
        if self.descriptor == other.descriptor {
            return true;
        }

        // safe because we only use the return value and libc says it's always successful
        let pid = unsafe { libc::getpid() };
        // safe because we are passing everything by value and checking the return value
        let ret = unsafe {
            libc::syscall(
                libc::SYS_kcmp,
                pid,
                pid,
                KCMP_FILE,
                self.descriptor,
                other.descriptor,
            )
        };

        ret == 0
    }
}

impl Drop for SafeDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.descriptor) };
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

impl AsRawFd for SafeDescriptor {
    fn as_raw_fd(&self) -> RawFd {
        self.as_raw_descriptor()
    }
}

impl TryFrom<&dyn AsRawFd> for SafeDescriptor {
    type Error = std::io::Error;

    fn try_from(fd: &dyn AsRawFd) -> std::result::Result<Self, Self::Error> {
        Ok(SafeDescriptor {
            descriptor: clone_fd(fd)?,
        })
    }
}

impl TryFrom<&dyn AsRawDescriptor> for SafeDescriptor {
    type Error = std::io::Error;

    /// Clones the underlying descriptor (handle), internally creating a new descriptor.
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
        // Safe because this doesn't modify any memory and we check the return value.
        let descriptor = unsafe { libc::fcntl(self.descriptor, libc::F_DUPFD_CLOEXEC, 0) };
        if descriptor < 0 {
            errno_result()
        } else {
            Ok(SafeDescriptor { descriptor })
        }
    }
}

impl From<SafeDescriptor> for File {
    fn from(s: SafeDescriptor) -> File {
        // Safe because we own the SafeDescriptor at this point.
        unsafe { File::from_raw_fd(s.into_raw_descriptor()) }
    }
}

impl From<File> for SafeDescriptor {
    fn from(f: File) -> SafeDescriptor {
        // Safe because we own the File at this point.
        unsafe { SafeDescriptor::from_raw_descriptor(f.into_raw_descriptor()) }
    }
}

impl From<SafeDescriptor> for UnixStream {
    fn from(s: SafeDescriptor) -> Self {
        // Safe because we own the SafeDescriptor at this point.
        unsafe { Self::from_raw_fd(s.into_raw_descriptor()) }
    }
}

impl From<UnixSeqpacket> for SafeDescriptor {
    fn from(s: UnixSeqpacket) -> Self {
        // Safe because we own the UnixSeqpacket at this point.
        unsafe { SafeDescriptor::from_raw_descriptor(s.into_raw_descriptor()) }
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

// AsRawFd for interoperability with interfaces that require it. Within crosvm,
// always use AsRawDescriptor when possible.
impl AsRawFd for Descriptor {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Implement token for implementations that wish to use this struct as such
impl PollToken for Descriptor {
    fn as_raw_token(&self) -> u64 {
        self.0 as u64
    }

    fn from_raw_token(data: u64) -> Self {
        Descriptor(data as RawDescriptor)
    }
}

macro_rules! AsRawDescriptor {
    ($name:ident) => {
        impl AsRawDescriptor for $name {
            fn as_raw_descriptor(&self) -> RawDescriptor {
                self.as_raw_fd()
            }
        }
    };
}

macro_rules! FromRawDescriptor {
    ($name:ident) => {
        impl FromRawDescriptor for $name {
            unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
                $name::from_raw_fd(descriptor)
            }
        }
    };
}

macro_rules! IntoRawDescriptor {
    ($name:ident) => {
        impl IntoRawDescriptor for $name {
            fn into_raw_descriptor(self) -> RawDescriptor {
                self.into_raw_fd()
            }
        }
    };
}

// Implementations for File. This enables the File-type to use
// RawDescriptor, but does not mean File should be used as a generic
// descriptor container. That should go to either SafeDescriptor or another more
// relevant container type.
AsRawDescriptor!(File);
AsRawDescriptor!(UnlinkUnixSeqpacketListener);
AsRawDescriptor!(UdpSocket);
AsRawDescriptor!(UnixDatagram);
AsRawDescriptor!(UnixListener);
AsRawDescriptor!(UnixStream);
FromRawDescriptor!(File);
FromRawDescriptor!(UnixStream);
FromRawDescriptor!(UnixDatagram);
IntoRawDescriptor!(File);
IntoRawDescriptor!(UnixDatagram);
AsRawDescriptor!(Stdin);
AsRawDescriptor!(Stdout);
AsRawDescriptor!(Stderr);

#[test]
#[allow(clippy::eq_op)]
fn clone_equality() {
    let ret = unsafe { libc::eventfd(0, 0) };
    if ret < 0 {
        panic!("failed to create eventfd");
    }
    let descriptor = unsafe { SafeDescriptor::from_raw_descriptor(ret) };

    assert_eq!(descriptor, descriptor);

    assert_eq!(
        descriptor,
        descriptor.try_clone().expect("failed to clone eventfd")
    );

    let ret = unsafe { libc::eventfd(0, 0) };
    if ret < 0 {
        panic!("failed to create eventfd");
    }
    let another = unsafe { SafeDescriptor::from_raw_descriptor(ret) };

    assert_ne!(descriptor, another);
}
