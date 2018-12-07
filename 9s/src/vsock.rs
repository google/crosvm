// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Support for virtual sockets.
use std::io;
use std::mem::{self, size_of};
use std::os::raw::{c_int, c_uchar, c_uint, c_ushort};
use std::os::unix::io::RawFd;

use assertions::const_assert;
use libc::{self, c_void, sa_family_t, size_t, sockaddr, socklen_t};

// The domain for vsock sockets.
const AF_VSOCK: sa_family_t = 40;

// Vsock equivalent of INADDR_ANY.  Indicates the context id of the current endpoint.
const VMADDR_CID_ANY: c_uint = c_uint::max_value();

// The number of bytes of padding to be added to the sockaddr_vm struct.  Taken directly
// from linux/vm_sockets.h.
const PADDING: usize = size_of::<sockaddr>()
    - size_of::<sa_family_t>()
    - size_of::<c_ushort>()
    - (2 * size_of::<c_uint>());

#[repr(C)]
struct sockaddr_vm {
    svm_family: sa_family_t,
    svm_reserved1: c_ushort,
    svm_port: c_uint,
    svm_cid: c_uint,
    svm_zero: [c_uchar; PADDING],
}

/// An address associated with a virtual socket.
pub struct SocketAddr {
    pub cid: c_uint,
    pub port: c_uint,
}

/// A virtual stream socket.
pub struct VsockStream {
    fd: RawFd,
}

impl VsockStream {
    pub fn try_clone(&self) -> io::Result<VsockStream> {
        // Safe because this doesn't modify any memory and we check the return value.
        let dup_fd = unsafe { libc::fcntl(self.fd, libc::F_DUPFD_CLOEXEC, 0) };
        if dup_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(VsockStream { fd: dup_fd })
    }
}

impl io::Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Safe because this will only modify the contents of |buf| and we check the return value.
        let ret = unsafe {
            handle_eintr_errno!(libc::read(
                self.fd,
                buf as *mut [u8] as *mut c_void,
                buf.len() as size_t
            ))
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(ret as usize)
    }
}

impl io::Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe {
            handle_eintr_errno!(libc::write(
                self.fd,
                buf as *const [u8] as *const c_void,
                buf.len() as size_t,
            ))
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(ret as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        // No buffered data so nothing to do.
        Ok(())
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        // Safe because this doesn't modify any memory and we are the only
        // owner of the file descriptor.
        unsafe { libc::close(self.fd) };
    }
}

/// Represents a virtual socket server.
pub struct VsockListener {
    fd: RawFd,
}

impl VsockListener {
    /// Creates a new `VsockListener` bound to the specified port on the current virtual socket
    /// endpoint.
    pub fn bind(port: c_uint) -> io::Result<VsockListener> {
        const_assert!(size_of::<sockaddr_vm>() == size_of::<sockaddr>());

        // Safe because this doesn't modify any memory and we check the return value.
        let fd: RawFd =
            unsafe { libc::socket(AF_VSOCK as c_int, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we are zero-initializing a struct with only integer fields.
        let mut svm: sockaddr_vm = unsafe { mem::zeroed() };
        svm.svm_family = AF_VSOCK;
        svm.svm_cid = VMADDR_CID_ANY;
        svm.svm_port = port;

        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe {
            libc::bind(
                fd,
                &svm as *const sockaddr_vm as *const sockaddr,
                size_of::<sockaddr_vm>() as socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { libc::listen(fd, 1) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(VsockListener { fd })
    }

    /// Accepts a new incoming connection on this listener.  Blocks the calling thread until a
    /// new connection is established.  When established, returns the corresponding `VsockStream`
    /// and the remote peer's address.
    pub fn accept(&self) -> io::Result<(VsockStream, SocketAddr)> {
        // Safe because we are zero-initializing a struct with only integer fields.
        let mut svm: sockaddr_vm = unsafe { mem::zeroed() };

        // Safe because this will only modify |svm| and we check the return value.
        let mut socklen: socklen_t = size_of::<sockaddr_vm>() as socklen_t;
        let fd = unsafe {
            libc::accept4(
                self.fd,
                &mut svm as *mut sockaddr_vm as *mut sockaddr,
                &mut socklen as *mut socklen_t,
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        if svm.svm_family != AF_VSOCK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected address family: {}", svm.svm_family),
            ));
        }

        Ok((
            VsockStream { fd },
            SocketAddr {
                cid: svm.svm_cid,
                port: svm.svm_port,
            },
        ))
    }
}

impl Drop for VsockListener {
    fn drop(&mut self) {
        // Safe because this doesn't modify any memory and we are the only
        // owner of the file descriptor.
        unsafe { libc::close(self.fd) };
    }
}
