// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::fs::File;
use std::io::Stderr;
use std::io::Stdin;
use std::io::Stdout;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::ops::Drop;
use std::os::fd::OwnedFd;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixDatagram;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::Descriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::errno::errno_result;
use crate::errno::Result;

pub type RawDescriptor = RawFd;

pub const INVALID_DESCRIPTOR: RawDescriptor = -1;

/// Clones `descriptor`, returning a new `SafeDescriptor` that refers to the same file
/// `descriptor`. The cloned descriptor will have the `FD_CLOEXEC` flag set but will not share any
/// other file descriptor flags with `descriptor`.
pub fn clone_descriptor(descriptor: &(impl AsRawDescriptor + ?Sized)) -> Result<SafeDescriptor> {
    clone_fd(descriptor.as_raw_descriptor())
}

/// Clones `fd`, returning a new file descriptor that refers to the same open file as `fd`. The
/// cloned fd will have the `FD_CLOEXEC` flag set but will not share any other file descriptor
/// flags with `fd`.
fn clone_fd(fd: RawFd) -> Result<SafeDescriptor> {
    // SAFETY:
    // Safe because this doesn't modify any memory and we check the return value.
    let ret = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if ret < 0 {
        errno_result()
    } else {
        // SAFETY: We just dup'd the FD and so have exclusive access.
        Ok(unsafe { SafeDescriptor::from_raw_descriptor(ret) })
    }
}

/// Adds CLOEXEC flag on descriptor
pub fn set_descriptor_cloexec<A: AsRawDescriptor>(fd_owner: &A) -> Result<()> {
    modify_descriptor_flags(fd_owner.as_raw_descriptor(), |flags| {
        flags | libc::FD_CLOEXEC
    })
}

/// Clears CLOEXEC flag on descriptor
pub fn clear_descriptor_cloexec<A: AsRawDescriptor>(fd_owner: &A) -> Result<()> {
    modify_descriptor_flags(fd_owner.as_raw_descriptor(), |flags| {
        flags & !libc::FD_CLOEXEC
    })
}

/// Apply the specified modification to the file descriptor's flags.
fn modify_descriptor_flags(
    desc: RawDescriptor,
    modify_flags: impl FnOnce(libc::c_int) -> libc::c_int,
) -> Result<()> {
    // SAFETY:
    // Safe because fd is read only.
    let flags = unsafe { libc::fcntl(desc, libc::F_GETFD) };
    if flags == -1 {
        return errno_result();
    }

    let new_flags = modify_flags(flags);

    // SAFETY:
    // Safe because this has no side effect(s) on the current process.
    if new_flags != flags && unsafe { libc::fcntl(desc, libc::F_SETFD, new_flags) } == -1 {
        errno_result()
    } else {
        Ok(())
    }
}

impl Drop for SafeDescriptor {
    fn drop(&mut self) {
        // SAFETY:
        // Safe because descriptor is valid.
        let _ = unsafe { libc::close(self.descriptor) };
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
        Ok(clone_fd(fd.as_raw_fd())?)
    }
}

impl SafeDescriptor {
    /// Clones this descriptor, internally creating a new descriptor. The new SafeDescriptor will
    /// share the same underlying count within the kernel.
    pub fn try_clone(&self) -> Result<SafeDescriptor> {
        // SAFETY:
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
        // SAFETY:
        // Safe because we own the SafeDescriptor at this point.
        unsafe { File::from_raw_fd(s.into_raw_descriptor()) }
    }
}

impl From<SafeDescriptor> for TcpListener {
    fn from(s: SafeDescriptor) -> Self {
        // SAFETY:
        // Safe because we own the SafeDescriptor at this point.
        unsafe { Self::from_raw_fd(s.into_raw_descriptor()) }
    }
}

impl From<SafeDescriptor> for TcpStream {
    fn from(s: SafeDescriptor) -> Self {
        // SAFETY:
        // Safe because we own the SafeDescriptor at this point.
        unsafe { Self::from_raw_fd(s.into_raw_descriptor()) }
    }
}

impl From<SafeDescriptor> for UnixStream {
    fn from(s: SafeDescriptor) -> Self {
        // SAFETY:
        // Safe because we own the SafeDescriptor at this point.
        unsafe { Self::from_raw_fd(s.into_raw_descriptor()) }
    }
}

impl From<SafeDescriptor> for OwnedFd {
    fn from(s: SafeDescriptor) -> Self {
        // SAFETY:
        // Safe because we own the SafeDescriptor at this point.
        unsafe { OwnedFd::from_raw_descriptor(s.into_raw_descriptor()) }
    }
}

impl From<OwnedFd> for SafeDescriptor {
    fn from(fd: OwnedFd) -> Self {
        // SAFETY:
        // Safe because we own the OwnedFd at this point.
        unsafe { SafeDescriptor::from_raw_descriptor(fd.into_raw_descriptor()) }
    }
}

// AsRawFd for interoperability with interfaces that require it. Within crosvm,
// always use AsRawDescriptor when possible.
impl AsRawFd for Descriptor {
    fn as_raw_fd(&self) -> RawFd {
        self.0
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
AsRawDescriptor!(OwnedFd);
AsRawDescriptor!(TcpListener);
AsRawDescriptor!(TcpStream);
AsRawDescriptor!(UdpSocket);
AsRawDescriptor!(UnixDatagram);
AsRawDescriptor!(UnixListener);
AsRawDescriptor!(UnixStream);
FromRawDescriptor!(File);
FromRawDescriptor!(OwnedFd);
FromRawDescriptor!(UnixStream);
FromRawDescriptor!(UnixDatagram);
IntoRawDescriptor!(File);
IntoRawDescriptor!(OwnedFd);
IntoRawDescriptor!(UnixDatagram);
IntoRawDescriptor!(UnixStream);
AsRawDescriptor!(Stdin);
AsRawDescriptor!(Stdout);
AsRawDescriptor!(Stderr);
