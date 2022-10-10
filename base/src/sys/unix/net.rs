// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::Ordering;
use std::convert::TryFrom;
use std::ffi::OsString;
use std::fs::remove_file;
use std::io;
use std::mem;
use std::mem::size_of;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::Duration;
use std::time::Instant;

use libc::c_int;
use libc::in6_addr;
use libc::in_addr;
use libc::recvfrom;
use libc::sa_family_t;
use libc::sockaddr;
use libc::sockaddr_in;
use libc::sockaddr_in6;
use libc::socklen_t;
use libc::AF_INET;
use libc::AF_INET6;
use libc::MSG_PEEK;
use libc::MSG_TRUNC;
use libc::SOCK_CLOEXEC;
use libc::SOCK_STREAM;
use log::warn;
use serde::Deserialize;
use serde::Serialize;

use super::sock_ctrl_msg::ScmSocket;
use super::sock_ctrl_msg::SCM_SOCKET_MAX_FD_COUNT;
use super::Error;
use super::RawDescriptor;
use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::IntoRawDescriptor;

/// Assist in handling both IP version 4 and IP version 6.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InetVersion {
    V4,
    V6,
}

impl InetVersion {
    pub fn from_sockaddr(s: &SocketAddr) -> Self {
        match s {
            SocketAddr::V4(_) => InetVersion::V4,
            SocketAddr::V6(_) => InetVersion::V6,
        }
    }
}

impl From<InetVersion> for sa_family_t {
    fn from(v: InetVersion) -> sa_family_t {
        match v {
            InetVersion::V4 => AF_INET as sa_family_t,
            InetVersion::V6 => AF_INET6 as sa_family_t,
        }
    }
}

fn sockaddrv4_to_lib_c(s: &SocketAddrV4) -> sockaddr_in {
    sockaddr_in {
        sin_family: AF_INET as sa_family_t,
        sin_port: s.port().to_be(),
        sin_addr: in_addr {
            s_addr: u32::from_ne_bytes(s.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

fn sockaddrv6_to_lib_c(s: &SocketAddrV6) -> sockaddr_in6 {
    sockaddr_in6 {
        sin6_family: AF_INET6 as sa_family_t,
        sin6_port: s.port().to_be(),
        sin6_flowinfo: 0,
        sin6_addr: in6_addr {
            s6_addr: s.ip().octets(),
        },
        sin6_scope_id: 0,
    }
}

/// A TCP socket.
///
/// Do not use this class unless you need to change socket options or query the
/// state of the socket prior to calling listen or connect. Instead use either TcpStream or
/// TcpListener.
#[derive(Debug)]
pub struct TcpSocket {
    inet_version: InetVersion,
    fd: RawFd,
}

impl TcpSocket {
    pub fn new(inet_version: InetVersion) -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                Into::<sa_family_t>::into(inet_version) as c_int,
                SOCK_STREAM | SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(TcpSocket { inet_version, fd })
        }
    }

    pub fn bind<A: ToSocketAddrs>(&mut self, addr: A) -> io::Result<()> {
        let sockaddr = addr
            .to_socket_addrs()
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?
            .next()
            .unwrap();

        let ret = match sockaddr {
            SocketAddr::V4(a) => {
                let sin = sockaddrv4_to_lib_c(&a);
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    libc::bind(
                        self.fd,
                        &sin as *const sockaddr_in as *const sockaddr,
                        size_of::<sockaddr_in>() as socklen_t,
                    )
                }
            }
            SocketAddr::V6(a) => {
                let sin6 = sockaddrv6_to_lib_c(&a);
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    libc::bind(
                        self.fd,
                        &sin6 as *const sockaddr_in6 as *const sockaddr,
                        size_of::<sockaddr_in6>() as socklen_t,
                    )
                }
            }
        };
        if ret < 0 {
            let bind_err = io::Error::last_os_error();
            Err(bind_err)
        } else {
            Ok(())
        }
    }

    pub fn connect<A: ToSocketAddrs>(self, addr: A) -> io::Result<TcpStream> {
        let sockaddr = addr
            .to_socket_addrs()
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?
            .next()
            .unwrap();

        let ret = match sockaddr {
            SocketAddr::V4(a) => {
                let sin = sockaddrv4_to_lib_c(&a);
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    libc::connect(
                        self.fd,
                        &sin as *const sockaddr_in as *const sockaddr,
                        size_of::<sockaddr_in>() as socklen_t,
                    )
                }
            }
            SocketAddr::V6(a) => {
                let sin6 = sockaddrv6_to_lib_c(&a);
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    libc::connect(
                        self.fd,
                        &sin6 as *const sockaddr_in6 as *const sockaddr,
                        size_of::<sockaddr_in>() as socklen_t,
                    )
                }
            }
        };

        if ret < 0 {
            let connect_err = io::Error::last_os_error();
            Err(connect_err)
        } else {
            // Safe because the ownership of the raw fd is released from self and taken over by the
            // new TcpStream.
            Ok(unsafe { TcpStream::from_raw_fd(self.into_raw_fd()) })
        }
    }

    pub fn listen(self) -> io::Result<TcpListener> {
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { libc::listen(self.fd, 1) };
        if ret < 0 {
            let listen_err = io::Error::last_os_error();
            Err(listen_err)
        } else {
            // Safe because the ownership of the raw fd is released from self and taken over by the
            // new TcpListener.
            Ok(unsafe { TcpListener::from_raw_fd(self.into_raw_fd()) })
        }
    }

    /// Returns the port that this socket is bound to. This can only succeed after bind is called.
    pub fn local_port(&self) -> io::Result<u16> {
        match self.inet_version {
            InetVersion::V4 => {
                let mut sin = sockaddr_in {
                    sin_family: 0,
                    sin_port: 0,
                    sin_addr: in_addr { s_addr: 0 },
                    sin_zero: [0; 8],
                };

                // Safe because we give a valid pointer for addrlen and check the length.
                let mut addrlen = size_of::<sockaddr_in>() as socklen_t;
                let ret = unsafe {
                    // Get the socket address that was actually bound.
                    libc::getsockname(
                        self.fd,
                        &mut sin as *mut sockaddr_in as *mut sockaddr,
                        &mut addrlen as *mut socklen_t,
                    )
                };
                if ret < 0 {
                    let getsockname_err = io::Error::last_os_error();
                    Err(getsockname_err)
                } else {
                    // If this doesn't match, it's not safe to get the port out of the sockaddr.
                    assert_eq!(addrlen as usize, size_of::<sockaddr_in>());

                    Ok(u16::from_be(sin.sin_port))
                }
            }
            InetVersion::V6 => {
                let mut sin6 = sockaddr_in6 {
                    sin6_family: 0,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: in6_addr { s6_addr: [0; 16] },
                    sin6_scope_id: 0,
                };

                // Safe because we give a valid pointer for addrlen and check the length.
                let mut addrlen = size_of::<sockaddr_in6>() as socklen_t;
                let ret = unsafe {
                    // Get the socket address that was actually bound.
                    libc::getsockname(
                        self.fd,
                        &mut sin6 as *mut sockaddr_in6 as *mut sockaddr,
                        &mut addrlen as *mut socklen_t,
                    )
                };
                if ret < 0 {
                    let getsockname_err = io::Error::last_os_error();
                    Err(getsockname_err)
                } else {
                    // If this doesn't match, it's not safe to get the port out of the sockaddr.
                    assert_eq!(addrlen as usize, size_of::<sockaddr_in>());

                    Ok(u16::from_be(sin6.sin6_port))
                }
            }
        }
    }
}

impl IntoRawFd for TcpSocket {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        mem::forget(self);
        fd
    }
}

impl AsRawFd for TcpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for TcpSocket {
    fn drop(&mut self) {
        // Safe because this doesn't modify any memory and we are the only
        // owner of the file descriptor.
        unsafe { libc::close(self.fd) };
    }
}

// Offset of sun_path in structure sockaddr_un.
fn sun_path_offset() -> usize {
    // Prefer 0 to null() so that we do not need to subtract from the `sub_path` pointer.
    #[allow(clippy::zero_ptr)]
    let addr = 0 as *const libc::sockaddr_un;
    // Safe because we only use the dereference to create a pointer to the desired field in
    // calculating the offset.
    unsafe { &(*addr).sun_path as *const _ as usize }
}

// Return `sockaddr_un` for a given `path`
fn sockaddr_un<P: AsRef<Path>>(path: P) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let mut addr = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; 108],
    };

    // Check if the input path is valid. Since
    // * The pathname in sun_path should be null-terminated.
    // * The length of the pathname, including the terminating null byte,
    //   should not exceed the size of sun_path.
    //
    // and our input is a `Path`, we only need to check
    // * If the string size of `Path` should less than sizeof(sun_path)
    // and make sure `sun_path` ends with '\0' by initialized the sun_path with zeros.
    //
    // Empty path name is valid since abstract socket address has sun_paht[0] = '\0'
    let bytes = path.as_ref().as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Input path size should be less than the length of sun_path.",
        ));
    };

    // Copy data from `path` to `addr.sun_path`
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }

    // The addrlen argument that describes the enclosing sockaddr_un structure
    // should have a value of at least:
    //
    //     offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path) + 1
    //
    // or, more simply, addrlen can be specified as sizeof(struct sockaddr_un).
    let len = sun_path_offset() + bytes.len() + 1;
    Ok((addr, len as libc::socklen_t))
}

/// A Unix `SOCK_SEQPACKET` socket point to given `path`
#[derive(Debug, Serialize, Deserialize)]
pub struct UnixSeqpacket {
    #[serde(with = "super::with_raw_descriptor")]
    fd: RawFd,
}

impl UnixSeqpacket {
    /// Open a `SOCK_SEQPACKET` connection to socket named by `path`.
    ///
    /// # Arguments
    /// * `path` - Path to `SOCK_SEQPACKET` socket
    ///
    /// # Returns
    /// A `UnixSeqpacket` structure point to the socket
    ///
    /// # Errors
    /// Return `io::Error` when error occurs.
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        // Safe socket initialization since we handle the returned error.
        let fd = unsafe {
            match libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0) {
                -1 => return Err(io::Error::last_os_error()),
                fd => fd,
            }
        };

        let (addr, len) = sockaddr_un(path.as_ref())?;
        // Safe connect since we handle the error and use the right length generated from
        // `sockaddr_un`.
        unsafe {
            let ret = libc::connect(fd, &addr as *const _ as *const _, len);
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(UnixSeqpacket { fd })
    }

    /// Creates a pair of connected `SOCK_SEQPACKET` sockets.
    ///
    /// Both returned file descriptors have the `CLOEXEC` flag set.s
    pub fn pair() -> io::Result<(UnixSeqpacket, UnixSeqpacket)> {
        let mut fds = [0, 0];
        unsafe {
            // Safe because we give enough space to store all the fds and we check the return value.
            let ret = libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                &mut fds[0],
            );
            if ret == 0 {
                Ok((
                    UnixSeqpacket::from_raw_fd(fds[0]),
                    UnixSeqpacket::from_raw_fd(fds[1]),
                ))
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    /// Clone the underlying FD.
    pub fn try_clone(&self) -> io::Result<Self> {
        // Safe because this doesn't modify any memory and we check the return value.
        let fd = unsafe { libc::fcntl(self.fd, libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { fd })
        }
    }

    /// Gets the number of bytes that can be read from this socket without blocking.
    pub fn get_readable_bytes(&self) -> io::Result<usize> {
        let mut byte_count = 0i32;
        let ret = unsafe { libc::ioctl(self.fd, libc::FIONREAD, &mut byte_count) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(byte_count as usize)
        }
    }

    /// Gets the number of bytes in the next packet. This blocks as if `recv` were called,
    /// respecting the blocking and timeout settings of the underlying socket.
    pub fn next_packet_size(&self) -> io::Result<usize> {
        #[cfg(not(debug_assertions))]
        let buf = null_mut();
        // Work around for qemu's syscall translation which will reject null pointers in recvfrom.
        // This only matters for running the unit tests for a non-native architecture. See the
        // upstream thread for the qemu fix:
        // https://lists.nongnu.org/archive/html/qemu-devel/2021-03/msg09027.html
        #[cfg(debug_assertions)]
        let buf = &mut 0 as *mut _ as *mut _;

        // This form of recvfrom doesn't modify any data because all null pointers are used. We only
        // use the return value and check for errors on an FD owned by this structure.
        let ret = unsafe {
            recvfrom(
                self.fd,
                buf,
                0,
                MSG_TRUNC | MSG_PEEK,
                null_mut(),
                null_mut(),
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    /// Write data from a given buffer to the socket fd
    ///
    /// # Arguments
    /// * `buf` - A reference to the data buffer.
    ///
    /// # Returns
    /// * `usize` - The size of bytes written to the buffer.
    ///
    /// # Errors
    /// Returns error when `libc::write` failed.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        // Safe since we make sure the input `count` == `buf.len()` and handle the returned error.
        unsafe {
            let ret = libc::write(self.fd, buf.as_ptr() as *const _, buf.len());
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(ret as usize)
            }
        }
    }

    /// Read data from the socket fd to a given buffer
    ///
    /// # Arguments
    /// * `buf` - A mut reference to the data buffer.
    ///
    /// # Returns
    /// * `usize` - The size of bytes read to the buffer.
    ///
    /// # Errors
    /// Returns error when `libc::read` failed.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Safe since we make sure the input `count` == `buf.len()` and handle the returned error.
        unsafe {
            let ret = libc::read(self.fd, buf.as_mut_ptr() as *mut _, buf.len());
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(ret as usize)
            }
        }
    }

    /// Read data from the socket fd to a given `Vec`, resizing it to the received packet's size.
    ///
    /// # Arguments
    /// * `buf` - A mut reference to a `Vec` to resize and read into.
    ///
    /// # Errors
    /// Returns error when `libc::read` or `get_readable_bytes` failed.
    pub fn recv_to_vec(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        let packet_size = self.next_packet_size()?;
        buf.resize(packet_size, 0);
        let read_bytes = self.recv(buf)?;
        buf.resize(read_bytes, 0);
        Ok(())
    }

    /// Read data from the socket fd to a new `Vec`.
    ///
    /// # Returns
    /// * `vec` - A new `Vec` with the entire received packet.
    ///
    /// # Errors
    /// Returns error when `libc::read` or `get_readable_bytes` failed.
    pub fn recv_as_vec(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.recv_to_vec(&mut buf)?;
        Ok(buf)
    }

    /// Read data and fds from the socket fd to a new pair of `Vec`.
    ///
    /// # Returns
    /// * `Vec<u8>` - A new `Vec` with the entire received packet's bytes.
    /// * `Vec<RawFd>` - A new `Vec` with the entire received packet's fds.
    ///
    /// # Errors
    /// Returns error when `recv_with_fds` or `get_readable_bytes` failed.
    pub fn recv_as_vec_with_fds(&self) -> io::Result<(Vec<u8>, Vec<RawFd>)> {
        let packet_size = self.next_packet_size()?;
        let mut buf = vec![0; packet_size];
        let mut fd_buf = vec![-1; SCM_SOCKET_MAX_FD_COUNT];
        let (read_bytes, read_fds) =
            self.recv_with_fds(io::IoSliceMut::new(&mut buf), &mut fd_buf)?;
        buf.resize(read_bytes, 0);
        fd_buf.resize(read_fds, -1);
        Ok((buf, fd_buf))
    }

    fn set_timeout(&self, timeout: Option<Duration>, kind: libc::c_int) -> io::Result<()> {
        let timeval = match timeout {
            Some(t) => {
                if t.as_secs() == 0 && t.subsec_micros() == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "zero timeout duration is invalid",
                    ));
                }
                // subsec_micros fits in i32 because it is defined to be less than one million.
                let nsec = t.subsec_micros() as i32;
                libc::timeval {
                    tv_sec: t.as_secs() as libc::time_t,
                    tv_usec: libc::suseconds_t::from(nsec),
                }
            }
            None => libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        };
        // Safe because we own the fd, and the length of the pointer's data is the same as the
        // passed in length parameter. The level argument is valid, the kind is assumed to be valid,
        // and the return value is checked.
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                kind,
                &timeval as *const libc::timeval as *const libc::c_void,
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Sets or removes the timeout for read/recv operations on this socket.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_timeout(timeout, libc::SO_RCVTIMEO)
    }

    /// Sets or removes the timeout for write/send operations on this socket.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_timeout(timeout, libc::SO_SNDTIMEO)
    }

    /// Sets the blocking mode for this socket.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let mut nonblocking = nonblocking as libc::c_int;
        // Safe because the return value is checked, and this ioctl call sets the nonblocking mode
        // and does not continue holding the file descriptor after the call.
        let ret = unsafe { libc::ioctl(self.fd, libc::FIONBIO, &mut nonblocking) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for UnixSeqpacket {
    fn drop(&mut self) {
        // Safe if the UnixSeqpacket is created from Self::connect.
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl FromRawFd for UnixSeqpacket {
    // Unsafe in drop function
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl FromRawDescriptor for UnixSeqpacket {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        Self { fd: descriptor }
    }
}

impl IntoRawDescriptor for UnixSeqpacket {
    fn into_raw_descriptor(self) -> RawDescriptor {
        let fd = self.fd;
        mem::forget(self);
        fd
    }
}

impl AsRawFd for UnixSeqpacket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl AsRawFd for &UnixSeqpacket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl AsRawDescriptor for UnixSeqpacket {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.fd
    }
}

impl AsRawDescriptor for &UnixSeqpacket {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.fd
    }
}

impl io::Read for UnixSeqpacket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf)
    }
}

impl io::Write for UnixSeqpacket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl IntoRawFd for UnixSeqpacket {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        mem::forget(self);
        fd
    }
}

/// Like a `UnixListener` but for accepting `UnixSeqpacket` type sockets.
pub struct UnixSeqpacketListener {
    fd: RawFd,
    no_path: bool,
}

impl UnixSeqpacketListener {
    /// Creates a new `UnixSeqpacketListener` bound to the given path.
    pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        if path.as_ref().starts_with("/proc/self/fd/") {
            let fd = path
                .as_ref()
                .file_name()
                .expect("Failed to get fd filename")
                .to_str()
                .expect("fd filename should be unicode")
                .parse::<i32>()
                .expect("fd should be an integer");
            let mut result: c_int = 0;
            let mut result_len = size_of::<c_int>() as libc::socklen_t;
            let ret = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ACCEPTCONN,
                    &mut result as *mut _ as *mut libc::c_void,
                    &mut result_len,
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            if result != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "specified descriptor is not a listening socket",
                ));
            }
            return Ok(UnixSeqpacketListener { fd, no_path: true });
        }
        // Safe socket initialization since we handle the returned error.
        let fd = unsafe {
            match libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0) {
                -1 => return Err(io::Error::last_os_error()),
                fd => fd,
            }
        };

        let (addr, len) = sockaddr_un(path.as_ref())?;
        // Safe connect since we handle the error and use the right length generated from
        // `sockaddr_un`.
        unsafe {
            let ret = handle_eintr_errno!(libc::bind(fd, &addr as *const _ as *const _, len));
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            let ret = handle_eintr_errno!(libc::listen(fd, 128));
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(UnixSeqpacketListener { fd, no_path: false })
    }

    /// Blocks for and accepts a new incoming connection and returns the socket associated with that
    /// connection.
    ///
    /// The returned socket has the close-on-exec flag set.
    pub fn accept(&self) -> io::Result<UnixSeqpacket> {
        // Safe because we own this fd and the kernel will not write to null pointers.
        let ret = unsafe { libc::accept4(self.fd, null_mut(), null_mut(), libc::SOCK_CLOEXEC) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        // Safe because we checked the return value of accept. Therefore, the return value must be a
        // valid socket.
        Ok(unsafe { UnixSeqpacket::from_raw_fd(ret) })
    }

    pub fn accept_with_timeout(&self, timeout: Duration) -> io::Result<UnixSeqpacket> {
        let start = Instant::now();

        loop {
            let mut fds = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let elapsed = Instant::now().saturating_duration_since(start);
            let remaining = timeout.checked_sub(elapsed).unwrap_or(Duration::ZERO);
            let cur_timeout_ms = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
            // Safe because we give a valid pointer to a list (of 1) FD and we check
            // the return value.
            match unsafe { libc::poll(&mut fds, 1, cur_timeout_ms) }.cmp(&0) {
                Ordering::Greater => return self.accept(),
                Ordering::Equal => return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT)),
                Ordering::Less => {
                    if Error::last() != Error::new(libc::EINTR) {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
        }
    }

    /// Gets the path that this listener is bound to.
    pub fn path(&self) -> io::Result<PathBuf> {
        let mut addr = libc::sockaddr_un {
            sun_family: libc::AF_UNIX as libc::sa_family_t,
            sun_path: [0; 108],
        };
        if self.no_path {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket has no path",
            ));
        }
        let sun_path_offset = (&addr.sun_path as *const _ as usize
            - &addr.sun_family as *const _ as usize)
            as libc::socklen_t;
        let mut len = mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        // Safe because the length given matches the length of the data of the given pointer, and we
        // check the return value.
        let ret = unsafe {
            handle_eintr_errno!(libc::getsockname(
                self.fd,
                &mut addr as *mut libc::sockaddr_un as *mut libc::sockaddr,
                &mut len
            ))
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        if addr.sun_family != libc::AF_UNIX as libc::sa_family_t
            || addr.sun_path[0] == 0
            || len < 1 + sun_path_offset
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "getsockname on socket returned invalid value",
            ));
        }

        let path_os_str = OsString::from_vec(
            addr.sun_path[..(len - sun_path_offset - 1) as usize]
                .iter()
                .map(|&c| c as _)
                .collect(),
        );
        Ok(path_os_str.into())
    }

    /// Sets the blocking mode for this socket.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let mut nonblocking = nonblocking as libc::c_int;
        // Safe because the return value is checked, and this ioctl call sets the nonblocking mode
        // and does not continue holding the file descriptor after the call.
        let ret = unsafe { libc::ioctl(self.fd, libc::FIONBIO, &mut nonblocking) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for UnixSeqpacketListener {
    fn drop(&mut self) {
        // Safe if the UnixSeqpacketListener is created from Self::listen.
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl FromRawFd for UnixSeqpacketListener {
    // Unsafe in drop function
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self { fd, no_path: false }
    }
}

impl AsRawFd for UnixSeqpacketListener {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Used to attempt to clean up a `UnixSeqpacketListener` after it is dropped.
pub struct UnlinkUnixSeqpacketListener(pub UnixSeqpacketListener);
impl AsRef<UnixSeqpacketListener> for UnlinkUnixSeqpacketListener {
    fn as_ref(&self) -> &UnixSeqpacketListener {
        &self.0
    }
}

impl AsRawFd for UnlinkUnixSeqpacketListener {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl Deref for UnlinkUnixSeqpacketListener {
    type Target = UnixSeqpacketListener;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for UnlinkUnixSeqpacketListener {
    fn drop(&mut self) {
        if let Ok(path) = self.0.path() {
            if let Err(e) = remove_file(path) {
                warn!("failed to remove control socket file: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::io::ErrorKind;
    use std::path::PathBuf;

    use super::*;

    fn tmpdir() -> PathBuf {
        env::temp_dir()
    }

    #[test]
    fn sockaddr_un_zero_length_input() {
        let _res = sockaddr_un(Path::new("")).expect("sockaddr_un failed");
    }

    #[test]
    fn sockaddr_un_long_input_err() {
        let res = sockaddr_un(Path::new(&"a".repeat(108)));
        assert!(res.is_err());
    }

    #[test]
    fn sockaddr_un_long_input_pass() {
        let _res = sockaddr_un(Path::new(&"a".repeat(107))).expect("sockaddr_un failed");
    }

    #[test]
    fn sockaddr_un_len_check() {
        let (_addr, len) = sockaddr_un(Path::new(&"a".repeat(50))).expect("sockaddr_un failed");
        assert_eq!(len, (sun_path_offset() + 50 + 1) as u32);
    }

    #[test]
    #[allow(clippy::unnecessary_cast)]
    // c_char is u8 on aarch64 and i8 on x86, so clippy's suggested fix of changing
    // `'a' as libc::c_char` below to `b'a'` won't work everywhere.
    #[allow(clippy::char_lit_as_u8)]
    fn sockaddr_un_pass() {
        let path_size = 50;
        let (addr, len) =
            sockaddr_un(Path::new(&"a".repeat(path_size))).expect("sockaddr_un failed");
        assert_eq!(len, (sun_path_offset() + path_size + 1) as u32);
        assert_eq!(addr.sun_family, libc::AF_UNIX as libc::sa_family_t);

        // Check `sun_path` in returned `sockaddr_un`
        let mut ref_sun_path = [0 as libc::c_char; 108];
        for path in ref_sun_path.iter_mut().take(path_size) {
            *path = 'a' as libc::c_char;
        }

        for (addr_char, ref_char) in addr.sun_path.iter().zip(ref_sun_path.iter()) {
            assert_eq!(addr_char, ref_char);
        }
    }

    #[test]
    fn unix_seqpacket_path_not_exists() {
        let res = UnixSeqpacket::connect("/path/not/exists");
        assert!(res.is_err());
    }

    #[test]
    fn unix_seqpacket_listener_path() {
        let mut socket_path = tmpdir();
        socket_path.push("unix_seqpacket_listener_path");
        let listener = UnlinkUnixSeqpacketListener(
            UnixSeqpacketListener::bind(&socket_path)
                .expect("failed to create UnixSeqpacketListener"),
        );
        let listener_path = listener.path().expect("failed to get socket listener path");
        assert_eq!(socket_path, listener_path);
    }

    #[test]
    fn unix_seqpacket_listener_from_fd() {
        let mut socket_path = tmpdir();
        socket_path.push("unix_seqpacket_listener_from_fd");
        let listener = UnlinkUnixSeqpacketListener(
            UnixSeqpacketListener::bind(&socket_path)
                .expect("failed to create UnixSeqpacketListener"),
        );
        // UnixSeqpacketListener should succeed on a valid listening descriptor.
        let good_dup = UnixSeqpacketListener::bind(&format!("/proc/self/fd/{}", unsafe {
            libc::dup(listener.as_raw_fd())
        }));
        let good_dup_path = good_dup
            .expect("failed to create dup UnixSeqpacketListener")
            .path();
        // Path of socket created by descriptor should be hidden.
        assert!(good_dup_path.is_err());
        // UnixSeqpacketListener must fail on an existing non-listener socket.
        let s1 =
            UnixSeqpacket::connect(socket_path.as_path()).expect("UnixSeqpacket::connect failed");
        let bad_dup = UnixSeqpacketListener::bind(&format!("/proc/self/fd/{}", unsafe {
            libc::dup(s1.as_raw_fd())
        }));
        assert!(bad_dup.is_err());
    }

    #[test]
    fn unix_seqpacket_path_exists_pass() {
        let mut socket_path = tmpdir();
        socket_path.push("path_to_socket");
        let _listener = UnlinkUnixSeqpacketListener(
            UnixSeqpacketListener::bind(&socket_path)
                .expect("failed to create UnixSeqpacketListener"),
        );
        let _res =
            UnixSeqpacket::connect(socket_path.as_path()).expect("UnixSeqpacket::connect failed");
    }

    #[test]
    fn unix_seqpacket_path_listener_accept_with_timeout() {
        let mut socket_path = tmpdir();
        socket_path.push("path_listerner_accept_with_timeout");
        let listener = UnlinkUnixSeqpacketListener(
            UnixSeqpacketListener::bind(&socket_path)
                .expect("failed to create UnixSeqpacketListener"),
        );

        for d in [Duration::from_millis(10), Duration::ZERO] {
            let _ = listener.accept_with_timeout(d).expect_err(&format!(
                "UnixSeqpacket::accept_with_timeout {:?} connected",
                d
            ));

            let s1 = UnixSeqpacket::connect(socket_path.as_path())
                .unwrap_or_else(|_| panic!("UnixSeqpacket::connect {:?} failed", d));

            let s2 = listener
                .accept_with_timeout(d)
                .unwrap_or_else(|_| panic!("UnixSeqpacket::accept {:?} failed", d));

            let data1 = &[0, 1, 2, 3, 4];
            let data2 = &[10, 11, 12, 13, 14];
            s2.send(data2).expect("failed to send data2");
            s1.send(data1).expect("failed to send data1");
            let recv_data = &mut [0; 5];
            s2.recv(recv_data).expect("failed to recv data");
            assert_eq!(data1, recv_data);
            s1.recv(recv_data).expect("failed to recv data");
            assert_eq!(data2, recv_data);
        }
    }

    #[test]
    fn unix_seqpacket_path_listener_accept() {
        let mut socket_path = tmpdir();
        socket_path.push("path_listerner_accept");
        let listener = UnlinkUnixSeqpacketListener(
            UnixSeqpacketListener::bind(&socket_path)
                .expect("failed to create UnixSeqpacketListener"),
        );
        let s1 =
            UnixSeqpacket::connect(socket_path.as_path()).expect("UnixSeqpacket::connect failed");

        let s2 = listener.accept().expect("UnixSeqpacket::accept failed");

        let data1 = &[0, 1, 2, 3, 4];
        let data2 = &[10, 11, 12, 13, 14];
        s2.send(data2).expect("failed to send data2");
        s1.send(data1).expect("failed to send data1");
        let recv_data = &mut [0; 5];
        s2.recv(recv_data).expect("failed to recv data");
        assert_eq!(data1, recv_data);
        s1.recv(recv_data).expect("failed to recv data");
        assert_eq!(data2, recv_data);
    }

    #[test]
    fn unix_seqpacket_zero_timeout() {
        let (s1, _s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
        // Timeouts less than a microsecond are too small and round to zero.
        s1.set_read_timeout(Some(Duration::from_nanos(10)))
            .expect_err("successfully set zero timeout");
    }

    #[test]
    fn unix_seqpacket_read_timeout() {
        let (s1, _s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
        s1.set_read_timeout(Some(Duration::from_millis(1)))
            .expect("failed to set read timeout for socket");
        let _ = s1.recv(&mut [0]);
    }

    #[test]
    fn unix_seqpacket_write_timeout() {
        let (s1, _s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
        s1.set_write_timeout(Some(Duration::from_millis(1)))
            .expect("failed to set write timeout for socket");
    }

    #[test]
    fn unix_seqpacket_send_recv() {
        let (s1, s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
        let data1 = &[0, 1, 2, 3, 4];
        let data2 = &[10, 11, 12, 13, 14];
        s2.send(data2).expect("failed to send data2");
        s1.send(data1).expect("failed to send data1");
        let recv_data = &mut [0; 5];
        s2.recv(recv_data).expect("failed to recv data");
        assert_eq!(data1, recv_data);
        s1.recv(recv_data).expect("failed to recv data");
        assert_eq!(data2, recv_data);
    }

    #[test]
    fn unix_seqpacket_send_fragments() {
        let (s1, s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
        let data1 = &[0, 1, 2, 3, 4];
        let data2 = &[10, 11, 12, 13, 14, 15, 16];
        s1.send(data1).expect("failed to send data1");
        s1.send(data2).expect("failed to send data2");

        let recv_data = &mut [0; 32];
        let size = s2.recv(recv_data).expect("failed to recv data");
        assert_eq!(size, data1.len());
        assert_eq!(data1, &recv_data[0..size]);

        let size = s2.recv(recv_data).expect("failed to recv data");
        assert_eq!(size, data2.len());
        assert_eq!(data2, &recv_data[0..size]);
    }

    #[test]
    fn unix_seqpacket_get_readable_bytes() {
        let (s1, s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
        assert_eq!(s1.get_readable_bytes().unwrap(), 0);
        assert_eq!(s2.get_readable_bytes().unwrap(), 0);
        let data1 = &[0, 1, 2, 3, 4];
        s1.send(data1).expect("failed to send data");

        assert_eq!(s1.get_readable_bytes().unwrap(), 0);
        assert_eq!(s2.get_readable_bytes().unwrap(), data1.len());

        let recv_data = &mut [0; 5];
        s2.recv(recv_data).expect("failed to recv data");
        assert_eq!(s1.get_readable_bytes().unwrap(), 0);
        assert_eq!(s2.get_readable_bytes().unwrap(), 0);
    }

    #[test]
    fn unix_seqpacket_next_packet_size() {
        let (s1, s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
        let data1 = &[0, 1, 2, 3, 4];
        s1.send(data1).expect("failed to send data");

        assert_eq!(s2.next_packet_size().unwrap(), 5);
        s1.set_read_timeout(Some(Duration::from_micros(1)))
            .expect("failed to set read timeout");
        assert_eq!(
            s1.next_packet_size().unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        drop(s2);
        assert_eq!(
            s1.next_packet_size().unwrap_err().kind(),
            ErrorKind::ConnectionReset
        );
    }

    #[test]
    fn unix_seqpacket_recv_to_vec() {
        let (s1, s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
        let data1 = &[0, 1, 2, 3, 4];
        s1.send(data1).expect("failed to send data");

        let recv_data = &mut vec![];
        s2.recv_to_vec(recv_data).expect("failed to recv data");
        assert_eq!(recv_data, &mut vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn unix_seqpacket_recv_as_vec() {
        let (s1, s2) = UnixSeqpacket::pair().expect("failed to create socket pair");
        let data1 = &[0, 1, 2, 3, 4];
        s1.send(data1).expect("failed to send data");

        let recv_data = s2.recv_as_vec().expect("failed to recv data");
        assert_eq!(recv_data, vec![0, 1, 2, 3, 4]);
    }
}
