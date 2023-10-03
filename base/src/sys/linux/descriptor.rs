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
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixDatagram;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;

use super::errno_result;
use super::Result;
use crate::descriptor::AsRawDescriptor;
use crate::descriptor::Descriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::descriptor::SafeDescriptor;

pub type RawDescriptor = RawFd;

pub const INVALID_DESCRIPTOR: RawDescriptor = -1;

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

/// Clears CLOEXEC flag on descriptor
pub fn clear_descriptor_cloexec<A: AsRawDescriptor>(fd_owner: &A) -> Result<()> {
    clear_fd_cloexec(&fd_owner.as_raw_descriptor())
}

/// Clears CLOEXEC flag on fd
fn clear_fd_cloexec<A: AsRawFd>(fd_owner: &A) -> Result<()> {
    let fd = fd_owner.as_raw_fd();
    // Safe because fd is read only.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return errno_result();
    }

    let masked_flags = flags & !libc::FD_CLOEXEC;
    // Safe because this has no side effect(s) on the current process.
    if masked_flags != flags && unsafe { libc::fcntl(fd, libc::F_SETFD, masked_flags) } == -1 {
        errno_result()
    } else {
        Ok(())
    }
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

impl From<SafeDescriptor> for TcpListener {
    fn from(s: SafeDescriptor) -> Self {
        // Safe because we own the SafeDescriptor at this point.
        unsafe { Self::from_raw_fd(s.into_raw_descriptor()) }
    }
}

impl From<SafeDescriptor> for TcpStream {
    fn from(s: SafeDescriptor) -> Self {
        // Safe because we own the SafeDescriptor at this point.
        unsafe { Self::from_raw_fd(s.into_raw_descriptor()) }
    }
}

impl From<SafeDescriptor> for UnixStream {
    fn from(s: SafeDescriptor) -> Self {
        // Safe because we own the SafeDescriptor at this point.
        unsafe { Self::from_raw_fd(s.into_raw_descriptor()) }
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
AsRawDescriptor!(TcpListener);
AsRawDescriptor!(TcpStream);
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
