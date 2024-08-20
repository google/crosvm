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
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::ops::Deref;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::Duration;
use std::time::Instant;

use libc::c_int;
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
use log::warn;
use serde::Deserialize;
use serde::Serialize;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::handle_eintr_errno;
use crate::sys::sockaddr_un;
use crate::sys::sockaddrv4_to_lib_c;
use crate::sys::sockaddrv6_to_lib_c;
use crate::Error;
use crate::RawDescriptor;
use crate::SafeDescriptor;

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

pub(in crate::sys) fn socket(
    domain: c_int,
    sock_type: c_int,
    protocol: c_int,
) -> io::Result<SafeDescriptor> {
    // SAFETY:
    // Safe socket initialization since we handle the returned error.
    match unsafe { libc::socket(domain, sock_type, protocol) } {
        -1 => Err(io::Error::last_os_error()),
        // SAFETY:
        // Safe because we own the file descriptor.
        fd => Ok(unsafe { SafeDescriptor::from_raw_descriptor(fd) }),
    }
}

pub(in crate::sys) fn socketpair(
    domain: c_int,
    sock_type: c_int,
    protocol: c_int,
) -> io::Result<(SafeDescriptor, SafeDescriptor)> {
    let mut fds = [0, 0];
    // SAFETY:
    // Safe because we give enough space to store all the fds and we check the return value.
    match unsafe { libc::socketpair(domain, sock_type, protocol, fds.as_mut_ptr()) } {
        -1 => Err(io::Error::last_os_error()),
        _ => Ok(
            // SAFETY:
            // Safe because we own the file descriptors.
            unsafe {
                (
                    SafeDescriptor::from_raw_descriptor(fds[0]),
                    SafeDescriptor::from_raw_descriptor(fds[1]),
                )
            },
        ),
    }
}

/// A TCP socket.
///
/// Do not use this class unless you need to change socket options or query the
/// state of the socket prior to calling listen or connect. Instead use either TcpStream or
/// TcpListener.
#[derive(Debug)]
pub struct TcpSocket {
    pub(in crate::sys) inet_version: InetVersion,
    pub(in crate::sys) descriptor: SafeDescriptor,
}

impl TcpSocket {
    pub fn bind<A: ToSocketAddrs>(&mut self, addr: A) -> io::Result<()> {
        let sockaddr = addr
            .to_socket_addrs()
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?
            .next()
            .unwrap();

        let ret = match sockaddr {
            SocketAddr::V4(a) => {
                let sin = sockaddrv4_to_lib_c(&a);
                // SAFETY:
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    libc::bind(
                        self.as_raw_descriptor(),
                        &sin as *const sockaddr_in as *const sockaddr,
                        size_of::<sockaddr_in>() as socklen_t,
                    )
                }
            }
            SocketAddr::V6(a) => {
                let sin6 = sockaddrv6_to_lib_c(&a);
                // SAFETY:
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    libc::bind(
                        self.as_raw_descriptor(),
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
                // SAFETY:
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    libc::connect(
                        self.as_raw_descriptor(),
                        &sin as *const sockaddr_in as *const sockaddr,
                        size_of::<sockaddr_in>() as socklen_t,
                    )
                }
            }
            SocketAddr::V6(a) => {
                let sin6 = sockaddrv6_to_lib_c(&a);
                // SAFETY:
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    libc::connect(
                        self.as_raw_descriptor(),
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
            Ok(TcpStream::from(self.descriptor))
        }
    }

    pub fn listen(self) -> io::Result<TcpListener> {
        // SAFETY:
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { libc::listen(self.as_raw_descriptor(), 1) };
        if ret < 0 {
            let listen_err = io::Error::last_os_error();
            Err(listen_err)
        } else {
            Ok(TcpListener::from(self.descriptor))
        }
    }

    /// Returns the port that this socket is bound to. This can only succeed after bind is called.
    pub fn local_port(&self) -> io::Result<u16> {
        match self.inet_version {
            InetVersion::V4 => {
                let mut sin = sockaddrv4_to_lib_c(&SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));

                let mut addrlen = size_of::<sockaddr_in>() as socklen_t;
                // SAFETY:
                // Safe because we give a valid pointer for addrlen and check the length.
                let ret = unsafe {
                    // Get the socket address that was actually bound.
                    libc::getsockname(
                        self.as_raw_descriptor(),
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
                let mut sin6 = sockaddrv6_to_lib_c(&SocketAddrV6::new(
                    Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
                    0,
                    0,
                    0,
                ));

                let mut addrlen = size_of::<sockaddr_in6>() as socklen_t;
                // SAFETY:
                // Safe because we give a valid pointer for addrlen and check the length.
                let ret = unsafe {
                    // Get the socket address that was actually bound.
                    libc::getsockname(
                        self.as_raw_descriptor(),
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

impl AsRawDescriptor for TcpSocket {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor.as_raw_descriptor()
    }
}

// Offset of sun_path in structure sockaddr_un.
pub(in crate::sys) fn sun_path_offset() -> usize {
    // Prefer 0 to null() so that we do not need to subtract from the `sub_path` pointer.
    #[allow(clippy::zero_ptr)]
    let addr = 0 as *const libc::sockaddr_un;
    // SAFETY:
    // Safe because we only use the dereference to create a pointer to the desired field in
    // calculating the offset.
    unsafe { &(*addr).sun_path as *const _ as usize }
}

/// A Unix `SOCK_SEQPACKET` socket point to given `path`
#[derive(Debug, Serialize, Deserialize)]
pub struct UnixSeqpacket(SafeDescriptor);

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
        let descriptor = socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0)?;
        let (addr, len) = sockaddr_un(path.as_ref())?;
        // SAFETY:
        // Safe connect since we handle the error and use the right length generated from
        // `sockaddr_un`.
        unsafe {
            let ret = libc::connect(
                descriptor.as_raw_descriptor(),
                &addr as *const _ as *const _,
                len,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(UnixSeqpacket(descriptor))
    }

    /// Clone the underlying FD.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }

    /// Gets the number of bytes that can be read from this socket without blocking.
    pub fn get_readable_bytes(&self) -> io::Result<usize> {
        let mut byte_count = 0i32;
        // SAFETY:
        // Safe because self has valid raw descriptor and return value are checked.
        let ret = unsafe { libc::ioctl(self.as_raw_descriptor(), libc::FIONREAD, &mut byte_count) };
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

        // SAFETY:
        // This form of recvfrom doesn't modify any data because all null pointers are used. We only
        // use the return value and check for errors on an FD owned by this structure.
        let ret = unsafe {
            recvfrom(
                self.as_raw_descriptor(),
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
        // SAFETY:
        // Safe since we make sure the input `count` == `buf.len()` and handle the returned error.
        unsafe {
            let ret = libc::write(
                self.as_raw_descriptor(),
                buf.as_ptr() as *const _,
                buf.len(),
            );
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
        // SAFETY:
        // Safe since we make sure the input `count` == `buf.len()` and handle the returned error.
        unsafe {
            let ret = libc::read(
                self.as_raw_descriptor(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
            );
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

    #[allow(clippy::useless_conversion)]
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
        // SAFETY:
        // Safe because we own the fd, and the length of the pointer's data is the same as the
        // passed in length parameter. The level argument is valid, the kind is assumed to be valid,
        // and the return value is checked.
        let ret = unsafe {
            libc::setsockopt(
                self.as_raw_descriptor(),
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
        // SAFETY:
        // Safe because the return value is checked, and this ioctl call sets the nonblocking mode
        // and does not continue holding the file descriptor after the call.
        let ret = unsafe { libc::ioctl(self.as_raw_descriptor(), libc::FIONBIO, &mut nonblocking) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl From<UnixSeqpacket> for SafeDescriptor {
    fn from(s: UnixSeqpacket) -> Self {
        s.0
    }
}

impl From<SafeDescriptor> for UnixSeqpacket {
    fn from(s: SafeDescriptor) -> Self {
        Self(s)
    }
}

impl FromRawDescriptor for UnixSeqpacket {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        Self(SafeDescriptor::from_raw_descriptor(descriptor))
    }
}

impl AsRawDescriptor for UnixSeqpacket {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}

impl IntoRawDescriptor for UnixSeqpacket {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.0.into_raw_descriptor()
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

/// Like a `UnixListener` but for accepting `UnixSeqpacket` type sockets.
pub struct UnixSeqpacketListener {
    descriptor: SafeDescriptor,
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
            // SAFETY: Safe because fd and other args are valid and the return value is checked.
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
            // SAFETY:
            // Safe because we validated the socket file descriptor.
            let descriptor = unsafe { SafeDescriptor::from_raw_descriptor(fd) };
            return Ok(UnixSeqpacketListener {
                descriptor,
                no_path: true,
            });
        }

        let descriptor = socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0)?;
        let (addr, len) = sockaddr_un(path.as_ref())?;

        // SAFETY:
        // Safe connect since we handle the error and use the right length generated from
        // `sockaddr_un`.
        unsafe {
            let ret = handle_eintr_errno!(libc::bind(
                descriptor.as_raw_descriptor(),
                &addr as *const _ as *const _,
                len
            ));
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            let ret = handle_eintr_errno!(libc::listen(descriptor.as_raw_descriptor(), 128));
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(UnixSeqpacketListener {
            descriptor,
            no_path: false,
        })
    }

    pub fn accept_with_timeout(&self, timeout: Duration) -> io::Result<UnixSeqpacket> {
        let start = Instant::now();

        loop {
            let mut fds = libc::pollfd {
                fd: self.as_raw_descriptor(),
                events: libc::POLLIN,
                revents: 0,
            };
            let elapsed = Instant::now().saturating_duration_since(start);
            let remaining = timeout.checked_sub(elapsed).unwrap_or(Duration::ZERO);
            let cur_timeout_ms = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
            // SAFETY:
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
        let mut addr = sockaddr_un(Path::new(""))?.0;
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
        // SAFETY:
        // Safe because the length given matches the length of the data of the given pointer, and we
        // check the return value.
        let ret = unsafe {
            handle_eintr_errno!(libc::getsockname(
                self.as_raw_descriptor(),
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
        // SAFETY:
        // Safe because the return value is checked, and this ioctl call sets the nonblocking mode
        // and does not continue holding the file descriptor after the call.
        let ret = unsafe { libc::ioctl(self.as_raw_descriptor(), libc::FIONBIO, &mut nonblocking) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl AsRawDescriptor for UnixSeqpacketListener {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor.as_raw_descriptor()
    }
}

impl From<UnixSeqpacketListener> for OwnedFd {
    fn from(val: UnixSeqpacketListener) -> Self {
        val.descriptor.into()
    }
}

/// Used to attempt to clean up a `UnixSeqpacketListener` after it is dropped.
pub struct UnlinkUnixSeqpacketListener(pub UnixSeqpacketListener);

impl AsRawDescriptor for UnlinkUnixSeqpacketListener {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}

impl AsRef<UnixSeqpacketListener> for UnlinkUnixSeqpacketListener {
    fn as_ref(&self) -> &UnixSeqpacketListener {
        &self.0
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
    use super::*;

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
}
