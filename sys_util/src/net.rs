// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use std::io;
use std::mem;
use std::os::unix::{
    ffi::OsStrExt,
    io::{AsRawFd, FromRawFd, RawFd},
};
use std::path::Path;

// Offset of sun_path in structure sockaddr_un.
fn sun_path_offset() -> usize {
    // Safe block since we only use the created structure to calculate the offset
    unsafe {
        let addr: libc::sockaddr_un = mem::uninitialized();
        let base = &addr as *const _ as usize;
        let path = &addr.sun_path as *const _ as usize;
        path - base
    }
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
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes.iter()) {
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
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
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
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
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

    // Get `RawFd` from this server_socket
    fn socket_fd(&self) -> RawFd {
        self.fd
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
        self.socket_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;

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
        let mut ref_sun_path = [0i8; 108];
        for i in 0..path_size {
            ref_sun_path[i] = 'a' as i8;
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

    fn tmpdir() -> PathBuf {
        env::temp_dir()
    }

    fn mock_server_socket(socket_path: &Path) {
        unsafe {
            let socket_fd = libc::socket(libc::PF_UNIX, libc::SOCK_SEQPACKET, 0);
            assert!(socket_fd > 0);
            // Bind socket to path
            let (addr, len) = sockaddr_un(socket_path).unwrap();
            libc::unlink(&addr.sun_path as *const _ as *const _);
            let rc = libc::bind(socket_fd, &addr as *const _ as *const _, len);
            assert_eq!(rc, 0);
            // Mark the `socket_fd` as passive socket
            let rc = libc::listen(socket_fd, 5);
            assert_eq!(rc, 0);
        };
    }

    #[test]
    fn unix_seqpacket_path_exists_pass() {
        let mut socket_path = tmpdir();
        socket_path.push("path_to_socket");
        mock_server_socket(socket_path.as_path());
        let _res =
            UnixSeqpacket::connect(socket_path.as_path()).expect("UnixSeqpacket::connect failed");
    }
}
