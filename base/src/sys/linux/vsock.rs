// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Support for virtual sockets.
use std::fmt;
use std::io;
use std::mem;
use std::mem::size_of;
use std::num::ParseIntError;
use std::os::raw::c_uchar;
use std::os::raw::c_uint;
use std::os::raw::c_ushort;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::RawFd;
use std::result;
use std::str::FromStr;

use libc::c_void;
use libc::sa_family_t;
use libc::size_t;
use libc::sockaddr;
use libc::socklen_t;
use libc::F_GETFL;
use libc::F_SETFL;
use libc::O_NONBLOCK;
use libc::VMADDR_CID_ANY;
use libc::VMADDR_CID_HOST;
use libc::VMADDR_CID_HYPERVISOR;
use thiserror::Error;

// The domain for vsock sockets.
const AF_VSOCK: sa_family_t = 40;

// Vsock loopback address.
const VMADDR_CID_LOCAL: c_uint = 1;

/// Vsock equivalent of binding on port 0. Binds to a random port.
pub const VMADDR_PORT_ANY: c_uint = c_uint::max_value();

// The number of bytes of padding to be added to the sockaddr_vm struct.  Taken directly
// from linux/vm_sockets.h.
const PADDING: usize = size_of::<sockaddr>()
    - size_of::<sa_family_t>()
    - size_of::<c_ushort>()
    - (2 * size_of::<c_uint>());

#[repr(C)]
#[derive(Default)]
struct sockaddr_vm {
    svm_family: sa_family_t,
    svm_reserved1: c_ushort,
    svm_port: c_uint,
    svm_cid: c_uint,
    svm_zero: [c_uchar; PADDING],
}

#[derive(Error, Debug)]
#[error("failed to parse vsock address")]
pub struct AddrParseError;

/// The vsock equivalent of an IP address.
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum VsockCid {
    /// Vsock equivalent of INADDR_ANY. Indicates the context id of the current endpoint.
    Any,
    /// An address that refers to the bare-metal machine that serves as the hypervisor.
    Hypervisor,
    /// The loopback address.
    Local,
    /// The parent machine. It may not be the hypervisor for nested VMs.
    Host,
    /// An assigned CID that serves as the address for VSOCK.
    Cid(c_uint),
}

impl fmt::Display for VsockCid {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            VsockCid::Any => write!(fmt, "Any"),
            VsockCid::Hypervisor => write!(fmt, "Hypervisor"),
            VsockCid::Local => write!(fmt, "Local"),
            VsockCid::Host => write!(fmt, "Host"),
            VsockCid::Cid(c) => write!(fmt, "'{}'", c),
        }
    }
}

impl From<c_uint> for VsockCid {
    fn from(c: c_uint) -> Self {
        match c {
            VMADDR_CID_ANY => VsockCid::Any,
            VMADDR_CID_HYPERVISOR => VsockCid::Hypervisor,
            VMADDR_CID_LOCAL => VsockCid::Local,
            VMADDR_CID_HOST => VsockCid::Host,
            _ => VsockCid::Cid(c),
        }
    }
}

impl FromStr for VsockCid {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let c: c_uint = s.parse()?;
        Ok(c.into())
    }
}

impl From<VsockCid> for c_uint {
    fn from(cid: VsockCid) -> c_uint {
        match cid {
            VsockCid::Any => VMADDR_CID_ANY,
            VsockCid::Hypervisor => VMADDR_CID_HYPERVISOR,
            VsockCid::Local => VMADDR_CID_LOCAL,
            VsockCid::Host => VMADDR_CID_HOST,
            VsockCid::Cid(c) => c,
        }
    }
}

/// An address associated with a virtual socket.
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SocketAddr {
    pub cid: VsockCid,
    pub port: c_uint,
}

pub trait ToSocketAddr {
    fn to_socket_addr(&self) -> result::Result<SocketAddr, AddrParseError>;
}

impl ToSocketAddr for SocketAddr {
    fn to_socket_addr(&self) -> result::Result<SocketAddr, AddrParseError> {
        Ok(*self)
    }
}

impl ToSocketAddr for str {
    fn to_socket_addr(&self) -> result::Result<SocketAddr, AddrParseError> {
        self.parse()
    }
}

impl ToSocketAddr for (VsockCid, c_uint) {
    fn to_socket_addr(&self) -> result::Result<SocketAddr, AddrParseError> {
        let (cid, port) = *self;
        Ok(SocketAddr { cid, port })
    }
}

impl<'a, T: ToSocketAddr + ?Sized> ToSocketAddr for &'a T {
    fn to_socket_addr(&self) -> result::Result<SocketAddr, AddrParseError> {
        (**self).to_socket_addr()
    }
}

impl FromStr for SocketAddr {
    type Err = AddrParseError;

    /// Parse a vsock SocketAddr from a string. vsock socket addresses are of the form
    /// "vsock:cid:port".
    fn from_str(s: &str) -> Result<SocketAddr, AddrParseError> {
        let components: Vec<&str> = s.split(':').collect();
        if components.len() != 3 || components[0] != "vsock" {
            return Err(AddrParseError);
        }

        Ok(SocketAddr {
            cid: components[1].parse().map_err(|_| AddrParseError)?,
            port: components[2].parse().map_err(|_| AddrParseError)?,
        })
    }
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}:{}", self.cid, self.port)
    }
}

/// Sets `fd` to be blocking or nonblocking. `fd` must be a valid fd of a type that accepts the
/// `O_NONBLOCK` flag. This includes regular files, pipes, and sockets.
unsafe fn set_nonblocking(fd: RawFd, nonblocking: bool) -> io::Result<()> {
    let flags = libc::fcntl(fd, F_GETFL, 0);
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }

    let flags = if nonblocking {
        flags | O_NONBLOCK
    } else {
        flags & !O_NONBLOCK
    };

    let ret = libc::fcntl(fd, F_SETFL, flags);
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// A virtual socket.
///
/// Do not use this class unless you need to change socket options or query the
/// state of the socket prior to calling listen or connect. Instead use either VsockStream or
/// VsockListener.
#[derive(Debug)]
pub struct VsockSocket {
    fd: RawFd,
}

impl VsockSocket {
    pub fn new() -> io::Result<Self> {
        // SAFETY: trivially safe
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(VsockSocket { fd })
        }
    }

    pub fn bind<A: ToSocketAddr>(&mut self, addr: A) -> io::Result<()> {
        let sockaddr = addr
            .to_socket_addr()
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

        // The compiler should optimize this out since these are both compile-time constants.
        assert_eq!(size_of::<sockaddr_vm>(), size_of::<sockaddr>());

        let svm = sockaddr_vm {
            svm_family: AF_VSOCK,
            svm_cid: sockaddr.cid.into(),
            svm_port: sockaddr.port,
            ..Default::default()
        };

        // SAFETY:
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe {
            libc::bind(
                self.fd,
                &svm as *const sockaddr_vm as *const sockaddr,
                size_of::<sockaddr_vm>() as socklen_t,
            )
        };
        if ret < 0 {
            let bind_err = io::Error::last_os_error();
            Err(bind_err)
        } else {
            Ok(())
        }
    }

    pub fn connect<A: ToSocketAddr>(self, addr: A) -> io::Result<VsockStream> {
        let sockaddr = addr
            .to_socket_addr()
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

        let svm = sockaddr_vm {
            svm_family: AF_VSOCK,
            svm_cid: sockaddr.cid.into(),
            svm_port: sockaddr.port,
            ..Default::default()
        };

        // SAFETY:
        // Safe because this just connects a vsock socket, and the return value is checked.
        let ret = unsafe {
            libc::connect(
                self.fd,
                &svm as *const sockaddr_vm as *const sockaddr,
                size_of::<sockaddr_vm>() as socklen_t,
            )
        };
        if ret < 0 {
            let connect_err = io::Error::last_os_error();
            Err(connect_err)
        } else {
            Ok(VsockStream { sock: self })
        }
    }

    pub fn listen(self) -> io::Result<VsockListener> {
        // SAFETY:
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { libc::listen(self.fd, 1) };
        if ret < 0 {
            let listen_err = io::Error::last_os_error();
            return Err(listen_err);
        }
        Ok(VsockListener { sock: self })
    }

    /// Returns the port that this socket is bound to. This can only succeed after bind is called.
    pub fn local_port(&self) -> io::Result<u32> {
        let mut svm: sockaddr_vm = Default::default();

        let mut addrlen = size_of::<sockaddr_vm>() as socklen_t;
        // SAFETY:
        // Safe because we give a valid pointer for addrlen and check the length.
        let ret = unsafe {
            // Get the socket address that was actually bound.
            libc::getsockname(
                self.fd,
                &mut svm as *mut sockaddr_vm as *mut sockaddr,
                &mut addrlen as *mut socklen_t,
            )
        };
        if ret < 0 {
            let getsockname_err = io::Error::last_os_error();
            Err(getsockname_err)
        } else {
            // If this doesn't match, it's not safe to get the port out of the sockaddr.
            assert_eq!(addrlen as usize, size_of::<sockaddr_vm>());

            Ok(svm.svm_port)
        }
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        // SAFETY:
        // Safe because this doesn't modify any memory and we check the return value.
        let dup_fd = unsafe { libc::fcntl(self.fd, libc::F_DUPFD_CLOEXEC, 0) };
        if dup_fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { fd: dup_fd })
        }
    }

    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        // SAFETY:
        // Safe because the fd is valid and owned by this stream.
        unsafe { set_nonblocking(self.fd, nonblocking) }
    }
}

impl IntoRawFd for VsockSocket {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        mem::forget(self);
        fd
    }
}

impl AsRawFd for VsockSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for VsockSocket {
    fn drop(&mut self) {
        // SAFETY:
        // Safe because this doesn't modify any memory and we are the only
        // owner of the file descriptor.
        unsafe { libc::close(self.fd) };
    }
}

/// A virtual stream socket.
#[derive(Debug)]
pub struct VsockStream {
    sock: VsockSocket,
}

impl VsockStream {
    pub fn connect<A: ToSocketAddr>(addr: A) -> io::Result<VsockStream> {
        let sock = VsockSocket::new()?;
        sock.connect(addr)
    }

    /// Returns the port that this stream is bound to.
    pub fn local_port(&self) -> io::Result<u32> {
        self.sock.local_port()
    }

    pub fn try_clone(&self) -> io::Result<VsockStream> {
        self.sock.try_clone().map(|f| VsockStream { sock: f })
    }

    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.sock.set_nonblocking(nonblocking)
    }
}

impl io::Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY:
        // Safe because this will only modify the contents of |buf| and we check the return value.
        let ret = unsafe {
            libc::read(
                self.sock.as_raw_fd(),
                buf as *mut [u8] as *mut c_void,
                buf.len() as size_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(ret as usize)
    }
}

impl io::Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY:
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe {
            libc::write(
                self.sock.as_raw_fd(),
                buf as *const [u8] as *const c_void,
                buf.len() as size_t,
            )
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

impl AsRawFd for VsockStream {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

impl IntoRawFd for VsockStream {
    fn into_raw_fd(self) -> RawFd {
        self.sock.into_raw_fd()
    }
}

/// Represents a virtual socket server.
#[derive(Debug)]
pub struct VsockListener {
    sock: VsockSocket,
}

impl VsockListener {
    /// Creates a new `VsockListener` bound to the specified port on the current virtual socket
    /// endpoint.
    pub fn bind<A: ToSocketAddr>(addr: A) -> io::Result<VsockListener> {
        let mut sock = VsockSocket::new()?;
        sock.bind(addr)?;
        sock.listen()
    }

    /// Returns the port that this listener is bound to.
    pub fn local_port(&self) -> io::Result<u32> {
        self.sock.local_port()
    }

    /// Accepts a new incoming connection on this listener.  Blocks the calling thread until a
    /// new connection is established.  When established, returns the corresponding `VsockStream`
    /// and the remote peer's address.
    pub fn accept(&self) -> io::Result<(VsockStream, SocketAddr)> {
        let mut svm: sockaddr_vm = Default::default();

        let mut socklen: socklen_t = size_of::<sockaddr_vm>() as socklen_t;
        // SAFETY:
        // Safe because this will only modify |svm| and we check the return value.
        let fd = unsafe {
            libc::accept4(
                self.sock.as_raw_fd(),
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
            VsockStream {
                sock: VsockSocket { fd },
            },
            SocketAddr {
                cid: svm.svm_cid.into(),
                port: svm.svm_port,
            },
        ))
    }

    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.sock.set_nonblocking(nonblocking)
    }
}

impl AsRawFd for VsockListener {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}
