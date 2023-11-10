// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::mem::size_of;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::ptr::null_mut;

use libc::c_int;
use libc::c_void;
use libc::close;
use libc::fcntl;
use libc::in6_addr;
use libc::in_addr;
use libc::sa_family_t;
use libc::setsockopt;
use libc::sockaddr_in;
use libc::sockaddr_in6;
use libc::socklen_t;
use libc::AF_INET;
use libc::AF_INET6;
use libc::FD_CLOEXEC;
use libc::F_SETFD;
use libc::SOCK_STREAM;
use libc::SOL_SOCKET;
use libc::SO_NOSIGPIPE;

use crate::unix::net::socket;
use crate::unix::net::socketpair;
use crate::unix::net::sun_path_offset;
use crate::unix::net::InetVersion;
use crate::unix::net::TcpSocket;
use crate::AsRawDescriptor;
use crate::FromRawDescriptor;
use crate::SafeDescriptor;
use crate::ScmSocket;
use crate::StreamChannel;
use crate::UnixSeqpacket;
use crate::UnixSeqpacketListener;

macro_rules! ScmSocketTryFrom {
    ($name:ident) => {
        impl TryFrom<$name> for ScmSocket<$name> {
            type Error = io::Error;

            fn try_from(socket: $name) -> io::Result<Self> {
                let set = 1;
                let set_ptr = &set as *const c_int as *const c_void;
                let size = size_of::<c_int>() as socklen_t;
                let res = unsafe {
                    setsockopt(
                        socket.as_raw_descriptor(),
                        SOL_SOCKET,
                        SO_NOSIGPIPE,
                        set_ptr,
                        size,
                    )
                };
                if res < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(ScmSocket { socket })
                }
            }
        }
    };
}

ScmSocketTryFrom!(StreamChannel);
ScmSocketTryFrom!(UnixDatagram);
ScmSocketTryFrom!(UnixListener);
ScmSocketTryFrom!(UnixSeqpacket);
ScmSocketTryFrom!(UnixStream);

pub(crate) fn sockaddrv4_to_lib_c(s: &SocketAddrV4) -> sockaddr_in {
    sockaddr_in {
        sin_family: AF_INET as sa_family_t,
        sin_port: s.port().to_be(),
        sin_addr: in_addr {
            s_addr: u32::from_ne_bytes(s.ip().octets()),
        },
        sin_zero: [0; 8],
        sin_len: size_of::<sockaddr_in>() as u8,
    }
}

pub(crate) fn sockaddrv6_to_lib_c(s: &SocketAddrV6) -> sockaddr_in6 {
    sockaddr_in6 {
        sin6_family: AF_INET6 as sa_family_t,
        sin6_port: s.port().to_be(),
        sin6_flowinfo: 0,
        sin6_addr: in6_addr {
            s6_addr: s.ip().octets(),
        },
        sin6_scope_id: 0,
        sin6_len: size_of::<sockaddr_in6>() as u8,
    }
}

fn cloexec_or_close<Raw: AsRawDescriptor>(raw: Raw) -> io::Result<Raw> {
    let res = unsafe { fcntl(raw.as_raw_descriptor(), F_SETFD, FD_CLOEXEC) };
    if res >= 0 {
        Ok(raw)
    } else {
        let err = io::Error::last_os_error();
        unsafe {
            close(raw.as_raw_descriptor());
        }
        Err(err)
    }
}

// Return `sockaddr_un` for a given `path`
pub(in crate::sys) fn sockaddr_un<P: AsRef<Path>>(
    path: P,
) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let mut addr = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: std::array::from_fn(|_| 0),
        sun_len: 0,
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
    addr.sun_len = sun_path_offset() as u8 + bytes.len() as u8 + 1;
    Ok((addr, addr.sun_len as libc::socklen_t))
}

impl TcpSocket {
    pub fn new(inet_version: InetVersion) -> io::Result<Self> {
        Ok(TcpSocket {
            inet_version,
            descriptor: cloexec_or_close(socket(
                Into::<sa_family_t>::into(inet_version) as libc::c_int,
                SOCK_STREAM,
                0,
            )?)?,
        })
    }
}

impl UnixSeqpacket {
    /// Creates a pair of connected `SOCK_SEQPACKET` sockets.
    ///
    /// Both returned file descriptors have the `CLOEXEC` flag set.
    pub fn pair() -> io::Result<(UnixSeqpacket, UnixSeqpacket)> {
        let (fd0, fd1) = socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0)?;
        let (s0, s1) = (UnixSeqpacket::from(fd0), UnixSeqpacket::from(fd1));
        Ok((cloexec_or_close(s0)?, cloexec_or_close(s1)?))
    }
}

impl UnixSeqpacketListener {
    /// Blocks for and accepts a new incoming connection and returns the socket associated with that
    /// connection.
    ///
    /// The returned socket has the close-on-exec flag set.
    pub fn accept(&self) -> io::Result<UnixSeqpacket> {
        // Safe because we own this fd and the kernel will not write to null pointers.
        match unsafe { libc::accept(self.as_raw_descriptor(), null_mut(), null_mut()) } {
            -1 => Err(io::Error::last_os_error()),
            fd => {
                // Safe because we checked the return value of accept. Therefore, the return value
                // must be a valid socket.
                Ok(UnixSeqpacket::from(cloexec_or_close(unsafe {
                    SafeDescriptor::from_raw_descriptor(fd)
                })?))
            }
        }
    }
}
