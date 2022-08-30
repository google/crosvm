// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::ffi::OsString;
use std::fs::remove_file;
use std::io;
use std::mem::size_of;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use base::warn;
use base::AsRawDescriptor;
use base::FromRawDescriptor;
use base::IntoRawDescriptor;
use base::SafeDescriptor;
use memoffset::offset_of;
use thiserror::Error as ThisError;

use super::io_driver;
use crate::AsIoBufs;
use crate::OwnedIoBuf;

#[derive(Debug, ThisError)]
#[error("Failed to prepare socket fd")]
struct PrepareSocket;

fn sockaddr_un<P: AsRef<Path>>(path: P) -> anyhow::Result<(libc::sockaddr_un, libc::socklen_t)> {
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
        bail!(io::Error::new(
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
    let len = offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    Ok((addr, len as libc::socklen_t))
}

/// A Unix `SOCK_SEQPACKET`.
#[derive(Debug)]
pub struct SeqPacket {
    fd: Arc<SafeDescriptor>,
}

impl SeqPacket {
    /// Open a `SOCK_SEQPACKET` connection to socket named by `path`.
    pub async fn connect<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        // Safe because this doesn't modify any memory and we check the return value.
        let fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("failed to create SOCK_SEQPACKET socket");
        }

        // Safe because we just opened this socket and we know it is valid.
        let fd = Arc::new(unsafe { SafeDescriptor::from_raw_descriptor(fd) });
        io_driver::prepare(&*fd).context(PrepareSocket)?;

        let (addr, len) = sockaddr_un(path).context("failed to create `sockaddr_un`")?;
        io_driver::connect(&fd, addr, len)
            .await
            .context("failed to connect socket")?;

        Ok(SeqPacket { fd })
    }

    /// Creates a pair of connected `SOCK_SEQPACKET` sockets.
    ///
    /// Both returned file descriptors have the `CLOEXEC` flag set.s
    pub fn pair() -> anyhow::Result<(Self, Self)> {
        let mut fds = [0, 0];
        // Safe because we give enough space to store all the fds and we check the return value.
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                &mut fds[0],
            )
        };

        if ret == 0 {
            // Safe because we just created these sockets and we know they are valid.
            let (s1, s2) = unsafe {
                (
                    Arc::new(SafeDescriptor::from_raw_descriptor(fds[0])),
                    Arc::new(SafeDescriptor::from_raw_descriptor(fds[1])),
                )
            };

            io_driver::prepare(&*s1).context(PrepareSocket)?;
            io_driver::prepare(&*s2).context(PrepareSocket)?;

            Ok((Self { fd: s1 }, Self { fd: s2 }))
        } else {
            Err(anyhow!(io::Error::last_os_error()))
        }
    }

    /// Gets the number of bytes in the next packet. This blocks as if `recv` were called,
    /// respecting the blocking and timeout settings of the underlying socket.
    pub async fn next_packet_size(&self) -> anyhow::Result<usize> {
        io_driver::next_packet_size(&self.fd).await
    }

    /// Clone the underlying FD.
    pub fn try_clone(&self) -> anyhow::Result<Self> {
        self.fd
            .try_clone()
            .map(|fd| Self { fd: Arc::new(fd) })
            .map_err(From::from)
    }

    /// Writes data from `buf` to the socket.
    ///
    /// Returns the number of bytes written to the socket. Note that when using I/O drivers like
    /// io_uring the data will be copied into an intermediate buffer before it is written to the
    /// socket and so this function is best suited for sending small amounts of data. Callers that
    /// want to avoid the intermediate buffer should use `send_iobuf` instead.
    pub async fn send(&self, buf: &[u8]) -> anyhow::Result<usize> {
        io_driver::write(&self.fd, buf, None).await
    }

    /// Writes `buf` with the provided file descriptors to the socket.
    ///
    /// Returns the number of bytes written to the socket. Like with `send`, this method may copy
    /// both the data and the fds into an intermediate buffer before writing them to the socket.
    /// Callers that want to avoid copying should use `send_iobuf_with_fds` instead.
    pub async fn send_with_fds(&self, buf: &[u8], fds: &[RawFd]) -> anyhow::Result<usize> {
        io_driver::sendmsg(&self.fd, buf, fds).await
    }

    /// Writes data from `buf` to the socket.
    ///
    /// This function is like `send` but takes an owned buffer instead, avoiding the need to first
    /// copy the data into an intermediate buffer.
    pub async fn send_iobuf<B: AsIoBufs + Unpin + 'static>(
        &self,
        buf: B,
    ) -> (anyhow::Result<usize>, B) {
        io_driver::write_iobuf(&self.fd, buf, None).await
    }

    /// Writes data from `buf` with the provided file descriptors to the socket.
    ///
    /// Like `send_with_fds` but doesn't require copying the data into an intermediate buffer first.
    /// Returns the number of bytes written to the socket.
    pub async fn send_iobuf_with_fds<B: AsIoBufs + Unpin + 'static>(
        &self,
        buf: B,
        fds: &[RawFd],
    ) -> (anyhow::Result<usize>, B) {
        io_driver::send_iobuf_with_fds(&self.fd, buf, fds).await
    }

    /// Reads data from the socket into `buf`.
    ///
    /// Returns the number of bytes read from the socket. Note that when using I/O drivers like
    /// io_uring the data will first be read into an intermediate buffer before it is copied into
    /// `buf` and so this function is best suited for reading small amounts of data. Callers that
    /// want to avoid the intermediate buffer should use `recv_iobuf` instead.
    pub async fn recv(&self, buf: &mut [u8]) -> anyhow::Result<usize> {
        io_driver::read(&self.fd, buf, None).await
    }

    /// Reads data from the socket into `buf` and any file descriptors into `fds`.
    ///
    /// Returns the number of bytes read from the socket and the number of file descriptors
    /// received. Note that when using I/O drivers like io_uring the data will first be read into an
    /// intermediate buffer before it is copied into `buf` and so this function is best suited for
    /// reading small amounts of data. Callers that want to avoid the intermediate buffer should use
    /// `recv_iobuf_with_fds` instead.
    pub async fn recv_with_fds(
        &self,
        buf: &mut [u8],
        fds: &mut [RawFd],
    ) -> anyhow::Result<(usize, usize)> {
        io_driver::recvmsg(&self.fd, buf, fds).await
    }

    /// Reads data from the socket into `buf`.
    ///
    /// This function is like `recv` but takes an owned buffer instead, avoiding the need to first
    /// copy the data into an intermediate buffer.
    pub async fn recv_iobuf<B: AsIoBufs + Unpin + 'static>(
        &self,
        buf: B,
    ) -> (anyhow::Result<usize>, B) {
        io_driver::read_iobuf(&self.fd, buf, None).await
    }

    /// Reads data from the socket into `buf` and any file descriptors into `fds`.
    ///
    /// Like `recv_with_fds` but doesn't require copying the data into an intermediate buffer first.
    /// Returns the number of bytes read from the socket as well as the number of file descriptors
    /// received.
    pub async fn recv_iobuf_with_fds<B: AsIoBufs + Unpin + 'static>(
        &self,
        buf: B,
        fds: &mut [RawFd],
    ) -> (anyhow::Result<(usize, usize)>, B) {
        io_driver::recv_iobuf_with_fds(&self.fd, buf, fds).await
    }

    /// Reads data from the socket into a `Vec<u8>`.
    pub async fn recv_as_vec(&self) -> anyhow::Result<Vec<u8>> {
        let len = self.next_packet_size().await?;
        let (res, mut buf) = self.recv_iobuf(OwnedIoBuf::new(vec![0u8; len])).await;
        let count = res?;
        buf.truncate(count);
        Ok(buf.into_inner())
    }

    /// Reads data and file descriptors from the socket.
    pub async fn recv_as_vec_with_fds(&self) -> anyhow::Result<(Vec<u8>, Vec<RawFd>)> {
        let len = self.next_packet_size().await?;
        let mut fds = vec![0; base::SCM_SOCKET_MAX_FD_COUNT];
        let (res, mut buf) = self
            .recv_iobuf_with_fds(OwnedIoBuf::new(vec![0u8; len]), &mut fds)
            .await;
        let (data_len, fd_len) = res?;
        buf.truncate(data_len);
        fds.truncate(fd_len);

        Ok((buf.into_inner(), fds))
    }
}

impl TryFrom<base::net::UnixSeqpacket> for SeqPacket {
    type Error = anyhow::Error;

    fn try_from(value: base::net::UnixSeqpacket) -> anyhow::Result<Self> {
        // Safe because `value` owns the fd.
        let fd =
            Arc::new(unsafe { SafeDescriptor::from_raw_descriptor(value.into_raw_descriptor()) });
        io_driver::prepare(&*fd)?;
        Ok(Self { fd })
    }
}

impl TryFrom<SeqPacket> for base::net::UnixSeqpacket {
    type Error = SeqPacket;

    fn try_from(value: SeqPacket) -> Result<Self, Self::Error> {
        Arc::try_unwrap(value.fd)
            .map(|fd| unsafe {
                base::net::UnixSeqpacket::from_raw_descriptor(fd.into_raw_descriptor())
            })
            .map_err(|fd| SeqPacket { fd })
    }
}

impl AsRawDescriptor for SeqPacket {
    fn as_raw_descriptor(&self) -> base::RawDescriptor {
        self.fd.as_raw_descriptor()
    }
}

impl AsRawFd for SeqPacket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Like a `UnixListener` but for accepting `SOCK_SEQPACKET` sockets.
pub struct SeqPacketListener {
    fd: Arc<SafeDescriptor>,
}

impl SeqPacketListener {
    pub fn bind<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        // Safe because this doesn't modify any memory and we check the return value.
        let fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("failed to create SOCK_SEQPACKET socket");
        }

        // Safe because we just opened this socket and we know it is valid.
        let fd = Arc::new(unsafe { SafeDescriptor::from_raw_descriptor(fd) });
        io_driver::prepare(&*fd).context(PrepareSocket)?;

        let (addr, len) = sockaddr_un(path).context("failed to create `sockaddr_un`")?;
        // Safe connect since we handle the error and use the right length generated from
        // `sockaddr_un`.
        unsafe {
            let ret = libc::bind(fd.as_raw_descriptor(), &addr as *const _ as *const _, len);
            if ret < 0 {
                return Err(anyhow!(io::Error::last_os_error()));
            }
            let ret = libc::listen(fd.as_raw_descriptor(), 128);
            if ret < 0 {
                return Err(anyhow!(io::Error::last_os_error()));
            }
        }

        Ok(Self { fd })
    }

    /// Accepts a new incoming connection and returns the socket associated with that connection.
    pub async fn accept(&self) -> anyhow::Result<SeqPacket> {
        let fd = io_driver::accept(&self.fd)
            .await
            .map(Arc::new)
            .context("failed to accept connection")?;
        io_driver::prepare(&*fd).context(PrepareSocket)?;
        Ok(SeqPacket { fd })
    }

    /// Gets the path that this listener is bound to.
    pub fn path(&self) -> anyhow::Result<PathBuf> {
        let mut addr = libc::sockaddr_un {
            sun_family: libc::AF_UNIX as libc::sa_family_t,
            sun_path: [0; 108],
        };
        let sun_path_offset = offset_of!(libc::sockaddr_un, sun_path) as libc::socklen_t;
        let mut len = size_of::<libc::sockaddr_un>() as libc::socklen_t;
        // Safe because the length given matches the length of the data of the given pointer, and we
        // check the return value.
        let ret = unsafe {
            libc::getsockname(
                self.fd.as_raw_descriptor(),
                &mut addr as *mut libc::sockaddr_un as *mut libc::sockaddr,
                &mut len,
            )
        };
        if ret < 0 {
            return Err(anyhow!(io::Error::last_os_error()));
        }
        if addr.sun_family != libc::AF_UNIX as libc::sa_family_t
            || addr.sun_path[0] == 0
            || len < 1 + sun_path_offset
        {
            return Err(anyhow!(io::Error::new(
                io::ErrorKind::InvalidData,
                "getsockname on socket returned invalid value",
            )));
        }

        let path = OsString::from_vec(
            addr.sun_path[..(len - sun_path_offset - 1) as usize]
                .iter()
                .map(|&c| c as _)
                .collect(),
        );
        Ok(path.into())
    }
}

impl AsRawDescriptor for SeqPacketListener {
    fn as_raw_descriptor(&self) -> base::RawDescriptor {
        self.fd.as_raw_descriptor()
    }
}

impl AsRawFd for SeqPacketListener {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Used to attempt to clean up a `SeqPacketListener` after it is dropped.
pub struct UnlinkSeqPacketListener(pub SeqPacketListener);
impl AsRef<SeqPacketListener> for UnlinkSeqPacketListener {
    fn as_ref(&self) -> &SeqPacketListener {
        &self.0
    }
}

impl AsRawFd for UnlinkSeqPacketListener {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl Deref for UnlinkSeqPacketListener {
    type Target = SeqPacketListener;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for UnlinkSeqPacketListener {
    fn drop(&mut self) {
        if let Ok(path) = self.0.path() {
            if let Err(e) = remove_file(path) {
                warn!("failed to remove socket file: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::time::Duration;
    use std::time::Instant;

    use base::AsRawDescriptor;
    use base::EventExt;

    use super::*;
    use crate::with_deadline;
    use crate::Executor;

    #[test]
    fn send_recv_no_fd() {
        Executor::new()
            .run_until(async {
                let (s1, s2) = SeqPacket::pair().expect("failed to create socket pair");

                let send_buf = [1u8, 1, 2, 21, 34, 55];
                let write_count = s1
                    .send_with_fds(&send_buf, &[])
                    .await
                    .expect("failed to send data");

                assert_eq!(write_count, 6);

                let mut buf = [0; 6];
                let mut files = [0; 1];
                let (read_count, file_count) = s2
                    .recv_with_fds(&mut buf[..], &mut files)
                    .await
                    .expect("failed to recv data");

                assert_eq!(read_count, 6);
                assert_eq!(file_count, 0);
                assert_eq!(buf, [1, 1, 2, 21, 34, 55]);
            })
            .unwrap();
    }

    #[test]
    fn send_recv_iobuf_no_fd() {
        Executor::new()
            .run_until(async {
                let (s1, s2) = SeqPacket::pair().expect("failed to create socket pair");

                let send_buf = [1u8, 1, 2, 21, 34, 55];
                let (res, _) = s1
                    .send_iobuf_with_fds(OwnedIoBuf::new(Vec::from(send_buf)), &[])
                    .await;
                let write_count = res.expect("failed to send data");
                assert_eq!(write_count, 6);

                let iobuf = OwnedIoBuf::new(vec![0; 6]);
                let mut files = [0; 1];
                let (res, iobuf) = s2.recv_iobuf_with_fds(iobuf, &mut files).await;
                let (read_count, file_count) = res.expect("failed to recv data");

                assert_eq!(read_count, 6);
                assert_eq!(file_count, 0);
                assert_eq!(&*iobuf, &[1, 1, 2, 21, 34, 55]);
            })
            .unwrap();
    }

    #[test]
    fn send_recv_only_fd() {
        Executor::new()
            .run_until(async {
                let (s1, s2) = SeqPacket::pair().expect("failed to create socket pair");

                let evt = base::Event::new().expect("failed to create eventfd");
                let write_count = s1
                    .send_with_fds(&[], &[evt.as_raw_descriptor()])
                    .await
                    .expect("failed to send fd");

                assert_eq!(write_count, 0);

                let mut files = [-1; 2];
                let (read_count, file_count) = s2
                    .recv_with_fds(&mut [], &mut files)
                    .await
                    .expect("failed to recv fd");

                assert_eq!(read_count, 0);
                assert_eq!(file_count, 1);
                assert!(files[0] >= 0);
                assert_ne!(files[0], s1.as_raw_descriptor());
                assert_ne!(files[0], s2.as_raw_descriptor());
                assert_ne!(files[0], evt.as_raw_descriptor());

                let mut file = unsafe { File::from_raw_descriptor(files[0]) };
                file.write_all(&1203u64.to_ne_bytes())
                    .expect("failed to write to sent fd");

                assert_eq!(evt.read_count().expect("failed to read from eventfd"), 1203);
            })
            .unwrap();
    }

    #[test]
    fn send_recv_iobuf_only_fd() {
        Executor::new()
            .run_until(async {
                let (s1, s2) = SeqPacket::pair().expect("failed to create socket pair");

                let evt = base::Event::new().expect("failed to create eventfd");
                let (res, _) = s1
                    .send_iobuf_with_fds(OwnedIoBuf::new(vec![]), &[evt.as_raw_descriptor()])
                    .await;
                let write_count = res.expect("failed to send fd");
                assert_eq!(write_count, 0);

                let mut files = [-1; 2];
                let (res, _) = s2
                    .recv_iobuf_with_fds(OwnedIoBuf::new(vec![]), &mut files)
                    .await;
                let (read_count, file_count) = res.expect("failed to recv fd");

                assert_eq!(read_count, 0);
                assert_eq!(file_count, 1);
                assert!(files[0] >= 0);
                assert_ne!(files[0], s1.as_raw_descriptor());
                assert_ne!(files[0], s2.as_raw_descriptor());
                assert_ne!(files[0], evt.as_raw_descriptor());

                let mut file = unsafe { File::from_raw_descriptor(files[0]) };
                file.write_all(&1203u64.to_ne_bytes())
                    .expect("failed to write to sent fd");

                assert_eq!(evt.read_count().expect("failed to read from eventfd"), 1203);
            })
            .unwrap();
    }

    #[test]
    fn send_recv_with_fd() {
        Executor::new()
            .run_until(async {
                let (s1, s2) = SeqPacket::pair().expect("failed to create socket pair");

                let evt = base::Event::new().expect("failed to create eventfd");
                let write_count = s1
                    .send_with_fds(&[237], &[evt.as_raw_descriptor()])
                    .await
                    .expect("failed to send fd");

                assert_eq!(write_count, 1);

                let mut files = [-1; 2];
                let mut buf = [0u8];
                let (read_count, file_count) = s2
                    .recv_with_fds(&mut buf, &mut files)
                    .await
                    .expect("failed to recv fd");

                assert_eq!(read_count, 1);
                assert_eq!(buf[0], 237);
                assert_eq!(file_count, 1);
                assert!(files[0] >= 0);
                assert_ne!(files[0], s1.as_raw_descriptor());
                assert_ne!(files[0], s2.as_raw_descriptor());
                assert_ne!(files[0], evt.as_raw_descriptor());

                let mut file = unsafe { File::from_raw_descriptor(files[0]) };

                file.write_all(&1203u64.to_ne_bytes())
                    .expect("failed to write to sent fd");

                assert_eq!(evt.read_count().expect("failed to read from eventfd"), 1203);
            })
            .unwrap();
    }

    #[test]
    fn send_recv_iobuf_with_fd() {
        Executor::new()
            .run_until(async {
                let (s1, s2) = SeqPacket::pair().expect("failed to create socket pair");

                let evt = base::Event::new().expect("failed to create eventfd");
                let (res, _) = s1
                    .send_iobuf_with_fds(OwnedIoBuf::new(vec![237]), &[evt.as_raw_descriptor()])
                    .await;
                let write_count = res.expect("failed to send fd");

                assert_eq!(write_count, 1);

                let mut files = [-1; 2];
                let iobuf = OwnedIoBuf::new(vec![0]);
                let (res, iobuf) = s2.recv_iobuf_with_fds(iobuf, &mut files).await;
                let (read_count, file_count) = res.expect("failed to recv fd");

                assert_eq!(read_count, 1);
                assert_eq!(iobuf[0], 237);
                assert_eq!(file_count, 1);
                assert!(files[0] >= 0);
                assert_ne!(files[0], s1.as_raw_descriptor());
                assert_ne!(files[0], s2.as_raw_descriptor());
                assert_ne!(files[0], evt.as_raw_descriptor());

                let mut file = unsafe { File::from_raw_descriptor(files[0]) };

                file.write_all(&1203u64.to_ne_bytes())
                    .expect("failed to write to sent fd");

                assert_eq!(evt.read_count().expect("failed to read from eventfd"), 1203);
            })
            .unwrap();
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
        assert_eq!(
            len,
            (offset_of!(libc::sockaddr_un, sun_path) + 50 + 1) as u32
        );
    }

    #[test]
    // c_char is u8 on aarch64 and i8 on x86, so clippy's suggested fix of changing
    // `'a' as libc::c_char` below to `b'a'` won't work everywhere.
    #[allow(clippy::char_lit_as_u8)]
    fn sockaddr_un_pass() {
        let path_size = 50;
        let (addr, len) =
            sockaddr_un(Path::new(&"a".repeat(path_size))).expect("sockaddr_un failed");
        assert_eq!(
            len,
            (offset_of!(libc::sockaddr_un, sun_path) + path_size + 1) as u32
        );
        assert_eq!(addr.sun_family, libc::AF_UNIX as libc::sa_family_t);

        // Check `sun_path` in returned `sockaddr_un`
        let mut ref_sun_path = [0; 108];
        for path in ref_sun_path.iter_mut().take(path_size) {
            *path = 'a' as libc::c_char;
        }

        for (addr_char, ref_char) in addr.sun_path.iter().zip(ref_sun_path.iter()) {
            assert_eq!(addr_char, ref_char);
        }
    }

    #[test]
    fn unix_seqpacket_path_not_exists() {
        Executor::new()
            .run_until(async {
                let res = SeqPacket::connect("/path/not/exists").await;
                assert!(res.is_err());
            })
            .unwrap();
    }

    #[test]
    fn unix_seqpacket_listener_path() {
        let mut socket_path = env::temp_dir();
        socket_path.push("unix_seqpacket_listener_path");
        let listener = UnlinkSeqPacketListener(
            SeqPacketListener::bind(&socket_path).expect("failed to create SeqPacketListener"),
        );
        let listener_path = listener.path().expect("failed to get socket listener path");
        assert_eq!(socket_path, listener_path);
    }

    #[test]
    fn unix_seqpacket_path_exists_pass() {
        Executor::new()
            .run_until(async {
                let mut socket_path = env::temp_dir();
                socket_path.push("path_to_socket");
                let _listener = UnlinkSeqPacketListener(
                    SeqPacketListener::bind(&socket_path)
                        .expect("failed to create SeqPacketListener"),
                );
                let _res = SeqPacket::connect(socket_path.as_path())
                    .await
                    .expect("SeqPacket::connect failed");
            })
            .unwrap();
    }

    #[test]
    fn unix_seqpacket_path_listener_accept() {
        Executor::new()
            .run_until(async {
                let mut socket_path = env::temp_dir();
                socket_path.push("path_listerner_accept");
                let listener = UnlinkSeqPacketListener(
                    SeqPacketListener::bind(&socket_path)
                        .expect("failed to create SeqPacketListener"),
                );
                let s1 = SeqPacket::connect(&socket_path)
                    .await
                    .expect("SeqPacket::connect failed");

                let s2 = listener.accept().await.expect("SeqPacket::accept failed");

                let data1 = &[0, 1, 2, 3, 4];
                let data2 = &[10, 11, 12, 13, 14];
                s2.send(data2).await.expect("failed to send data2");
                s1.send(data1).await.expect("failed to send data1");
                let recv_data = &mut [0; 5];
                s2.recv(recv_data).await.expect("failed to recv data");
                assert_eq!(data1, recv_data);
                s1.recv(recv_data).await.expect("failed to recv data");
                assert_eq!(data2, recv_data);
            })
            .unwrap();
    }

    #[test]
    fn unix_seqpacket_send_recv() {
        Executor::new()
            .run_until(async {
                let (s1, s2) = SeqPacket::pair().expect("failed to create socket pair");
                let data1 = &[0, 1, 2, 3, 4];
                let data2 = &[10, 11, 12, 13, 14];
                s2.send(data2).await.expect("failed to send data2");
                s1.send(data1).await.expect("failed to send data1");
                let recv_data = &mut [0; 5];
                s2.recv(recv_data).await.expect("failed to recv data");
                assert_eq!(data1, recv_data);
                s1.recv(recv_data).await.expect("failed to recv data");
                assert_eq!(data2, recv_data);
            })
            .unwrap();
    }

    #[test]
    fn unix_seqpacket_send_fragments() {
        Executor::new()
            .run_until(async {
                let (s1, s2) = SeqPacket::pair().expect("failed to create socket pair");
                let data1 = &[0, 1, 2, 3, 4];
                let data2 = &[10, 11, 12, 13, 14, 15, 16];
                s1.send(data1).await.expect("failed to send data1");
                s1.send(data2).await.expect("failed to send data2");

                let recv_data = &mut [0; 32];
                let size = s2.recv(recv_data).await.expect("failed to recv data");
                assert_eq!(size, data1.len());
                assert_eq!(data1, &recv_data[0..size]);

                let size = s2.recv(recv_data).await.expect("failed to recv data");
                assert_eq!(size, data2.len());
                assert_eq!(data2, &recv_data[0..size]);
            })
            .unwrap();
    }

    #[test]
    fn unix_seqpacket_next_packet_size() {
        Executor::new()
            .run_until(async {
                let (s1, s2) = SeqPacket::pair().expect("failed to create socket pair");
                let data1 = &[0, 1, 2, 3, 4];
                s1.send(data1).await.expect("failed to send data");

                assert_eq!(s2.next_packet_size().await.unwrap(), 5);
                assert!(with_deadline(
                    Instant::now() + Duration::from_micros(1),
                    s1.next_packet_size()
                )
                .await
                .is_err());

                drop(s2);
                assert_eq!(
                    s1.next_packet_size()
                        .await
                        .unwrap_err()
                        .downcast::<io::Error>()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::ConnectionReset
                );
            })
            .unwrap();
    }

    #[test]
    fn unix_seqpacket_recv_as_vec() {
        Executor::new()
            .run_until(async {
                let (s1, s2) = SeqPacket::pair().expect("failed to create socket pair");
                let data1 = &[0, 1, 2, 3, 4];
                s1.send(data1).await.expect("failed to send data");

                let recv_data = s2.recv_as_vec().await.expect("failed to recv data");
                assert_eq!(&recv_data, &*data1);
            })
            .unwrap();
    }
}
