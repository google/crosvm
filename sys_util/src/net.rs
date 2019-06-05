// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::OsString;
use std::fs::remove_file;
use std::io;
use std::mem;
use std::ops::Deref;
use std::os::unix::{
    ffi::{OsStrExt, OsStringExt},
    io::{AsRawFd, FromRawFd, RawFd},
};
use std::path::Path;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::Duration;

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
pub struct UnixSeqpacket {
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
        // Calling `dup` is safe as the kernel doesn't touch any user memory it the process.
        let new_fd = unsafe { libc::dup(self.fd) };
        if new_fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(UnixSeqpacket { fd: new_fd })
        }
    }

    /// Gets the number of bytes that can be read from this socket without blocking.
    pub fn get_readable_bytes(&self) -> io::Result<usize> {
        let mut byte_count = 0 as libc::c_int;
        let ret = unsafe { libc::ioctl(self.fd, libc::FIONREAD, &mut byte_count) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(byte_count as usize)
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

impl AsRawFd for UnixSeqpacket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Like a `UnixListener` but for accepting `UnixSeqpacket` type sockets.
pub struct UnixSeqpacketListener {
    fd: RawFd,
}

impl UnixSeqpacketListener {
    /// Creates a new `UnixSeqpacketListener` bound to the given path.
    pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<Self> {
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
        Ok(UnixSeqpacketListener { fd })
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

    /// Gets the path that this listener is bound to.
    pub fn path(&self) -> io::Result<PathBuf> {
        let mut addr = libc::sockaddr_un {
            sun_family: libc::AF_UNIX as libc::sa_family_t,
            sun_path: [0; 108],
        };
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
        Self { fd }
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
    use super::*;
    use std::env;
    use std::path::PathBuf;

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
    fn sockaddr_un_pass() {
        let path_size = 50;
        let (addr, len) =
            sockaddr_un(Path::new(&"a".repeat(path_size))).expect("sockaddr_un failed");
        assert_eq!(len, (sun_path_offset() + path_size + 1) as u32);
        assert_eq!(addr.sun_family, libc::AF_UNIX as libc::sa_family_t);

        // Check `sun_path` in returned `sockaddr_un`
        let mut ref_sun_path = [0 as libc::c_char; 108];
        for i in 0..path_size {
            ref_sun_path[i] = 'a' as libc::c_char;
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
}
