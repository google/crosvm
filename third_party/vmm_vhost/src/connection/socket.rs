// Copyright 2021 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structs for Unix Domain Socket listener and connection.

use std::any::Any;
use std::fs::File;
use std::io::ErrorKind;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::path::Path;
use std::path::PathBuf;

use base::AsRawDescriptor;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::SafeDescriptor;
use base::ScmSocket;

use crate::connection::Listener;
use crate::message::*;
use crate::unix::SystemListener;
use crate::Connection;
use crate::Error;
use crate::Result;
use crate::SystemStream;

/// Unix domain socket listener for accepting incoming connections.
pub struct SocketListener {
    fd: SystemListener,
    drop_path: Option<Box<dyn Any>>,
}

impl SocketListener {
    /// Create a unix domain socket listener.
    ///
    /// # Return:
    /// * - the new SocketListener object on success.
    /// * - SocketError: failed to create listener socket.
    pub fn new<P: AsRef<Path>>(path: P, unlink: bool) -> Result<Self> {
        if unlink {
            let _ = std::fs::remove_file(&path);
        }
        let fd = SystemListener::bind(&path).map_err(Error::SocketError)?;

        struct DropPath {
            path: PathBuf,
        }

        impl Drop for DropPath {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.path);
            }
        }

        Ok(SocketListener {
            fd,
            drop_path: Some(Box::new(DropPath {
                path: path.as_ref().to_owned(),
            })),
        })
    }

    /// Take and return the resources that the parent process needs to keep alive as long as the
    /// child process lives, in case of incoming fork.
    pub fn take_resources_for_parent(&mut self) -> Option<Box<dyn Any>> {
        self.drop_path.take()
    }
}

impl Listener for SocketListener {
    /// Accept an incoming connection.
    ///
    /// # Return:
    /// * - Some(SystemListener): new SystemListener object if new incoming connection is available.
    /// * - None: no incoming connection available.
    /// * - SocketError: errors from accept().
    fn accept(&mut self) -> Result<Option<Connection<MasterReq>>> {
        loop {
            match self.fd.accept() {
                Ok((stream, _addr)) => {
                    return Ok(Some(Connection::from(stream)));
                }
                Err(e) => {
                    match e.kind() {
                        // No incoming connection available.
                        ErrorKind::WouldBlock => return Ok(None),
                        // New connection closed by peer.
                        ErrorKind::ConnectionAborted => return Ok(None),
                        // Interrupted by signals, retry
                        ErrorKind::Interrupted => continue,
                        _ => return Err(Error::SocketError(e)),
                    }
                }
            }
        }
    }

    /// Change blocking status on the listener.
    ///
    /// # Return:
    /// * - () on success.
    /// * - SocketError: failure from set_nonblocking().
    fn set_nonblocking(&self, block: bool) -> Result<()> {
        self.fd.set_nonblocking(block).map_err(Error::SocketError)
    }
}

impl AsRawDescriptor for SocketListener {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.fd.as_raw_descriptor()
    }
}

/// Unix domain socket based vhost-user connection.
pub struct SocketPlatformConnection {
    sock: ScmSocket<SystemStream>,
}

// TODO: Switch to TryFrom to avoid the unwrap.
impl From<SystemStream> for SocketPlatformConnection {
    fn from(sock: SystemStream) -> Self {
        Self {
            sock: sock.try_into().unwrap(),
        }
    }
}

impl SocketPlatformConnection {
    /// Create a new stream by connecting to server at `str`.
    ///
    /// # Return:
    /// * - the new SocketPlatformConnection object on success.
    /// * - SocketConnect: failed to connect to peer.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self> {
        let sock = SystemStream::connect(path).map_err(Error::SocketConnect)?;
        Ok(Self::from(sock))
    }

    /// Sends bytes from scatter-gather vectors over the socket with optional attached file
    /// descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn send_iovec(&self, iovs: &[IoSlice], fds: Option<&[RawDescriptor]>) -> Result<usize> {
        let rfds = match fds {
            Some(rfds) => rfds,
            _ => &[],
        };
        self.sock.send_bufs_with_fds(iovs, rfds).map_err(Into::into)
    }

    /// Reads bytes from the socket into the given scatter/gather vectors with optional attached
    /// file.
    ///
    /// The underlying communication channel is a Unix domain socket in STREAM mode. It's a little
    /// tricky to pass file descriptors through such a communication channel. Let's assume that a
    /// sender sending a message with some file descriptors attached. To successfully receive those
    /// attached file descriptors, the receiver must obey following rules:
    ///   1) file descriptors are attached to a message.
    ///   2) message(packet) boundaries must be respected on the receive side.
    /// In other words, recvmsg() operations must not cross the packet boundary, otherwise the
    /// attached file descriptors will get lost.
    /// Note that this function wraps received file descriptors as `File`.
    ///
    /// # Return:
    /// * - (number of bytes received, [received files]) on success
    /// * - Disconnect: the connection is closed.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn recv_into_bufs(
        &self,
        bufs: &mut [IoSliceMut],
        allow_fd: bool,
    ) -> Result<(usize, Option<Vec<File>>)> {
        let mut fd_array = if allow_fd {
            vec![0; MAX_ATTACHED_FD_ENTRIES]
        } else {
            vec![]
        };
        let (bytes, fds) = self.sock.recv_iovecs_with_fds(bufs, &mut fd_array)?;

        // 0-bytes indicates that the connection is closed.
        if bytes == 0 {
            return Err(Error::Disconnect);
        }

        let files = match fds {
            0 => None,
            n => {
                let files = fd_array
                    .iter()
                    .take(n)
                    .map(|fd| {
                        // Safe because we have the ownership of `fd`.
                        unsafe { File::from_raw_descriptor(*fd as RawDescriptor) }
                    })
                    .collect();
                Some(files)
            }
        };

        Ok((bytes, files))
    }
}

impl AsRawDescriptor for SocketPlatformConnection {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.sock.as_raw_descriptor()
    }
}

impl AsMut<SystemStream> for SocketPlatformConnection {
    fn as_mut(&mut self) -> &mut SystemStream {
        self.sock.inner_mut()
    }
}

/// Convert a `SafeDescriptor` to a `UnixStream`.
///
/// # Safety
///
/// `file` must represent a unix domain socket.
pub unsafe fn to_system_stream(fd: SafeDescriptor) -> Result<SystemStream> {
    Ok(fd.into())
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;
    use std::mem;

    use tempfile::tempfile;
    use tempfile::Builder;
    use tempfile::TempDir;
    use zerocopy::AsBytes;

    use super::*;

    fn temp_dir() -> TempDir {
        Builder::new().prefix("/tmp/vhost_test").tempdir().unwrap()
    }

    #[test]
    fn create_listener() {
        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let listener = SocketListener::new(&path, true).unwrap();

        assert!(listener.as_raw_descriptor() > 0);
    }

    #[test]
    fn accept_connection() {
        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let mut listener = SocketListener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();

        // accept on a fd without incoming connection
        let conn = listener.accept().unwrap();
        assert!(conn.is_none());
    }

    #[test]
    fn send_data() {
        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let mut listener = SocketListener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let master = Connection::<MasterReq>::connect(&path).unwrap();
        let slave = listener.accept().unwrap().unwrap();

        let buf1 = [0x1, 0x2, 0x3, 0x4];
        let mut len = master.send_slice(IoSlice::new(&buf1[..]), None).unwrap();
        assert_eq!(len, 4);
        let (bytes, buf2, _) = slave.recv_into_buf(0x1000).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..bytes]);

        len = master.send_slice(IoSlice::new(&buf1[..]), None).unwrap();
        assert_eq!(len, 4);
        let (bytes, buf2, _) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        let (bytes, buf2, _) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
    }

    #[test]
    fn send_fd() {
        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let mut listener = SocketListener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let master = Connection::<MasterReq>::connect(&path).unwrap();
        let slave = listener.accept().unwrap().unwrap();

        let mut fd = tempfile().unwrap();
        write!(fd, "test").unwrap();

        // Normal case for sending/receiving file descriptors
        let buf1 = [0x1, 0x2, 0x3, 0x4];
        let len = master
            .send_slice(IoSlice::new(&buf1[..]), Some(&[fd.as_raw_descriptor()]))
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, files) = slave.recv_into_buf(4).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..]);
        assert!(files.is_some());
        let files = files.unwrap();
        {
            assert_eq!(files.len(), 1);
            let mut file = &files[0];
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }

        // Following communication pattern should work:
        // Sending side: data(header, body) with fds
        // Receiving side: data(header) with fds, data(body)
        let len = master
            .send_slice(
                IoSlice::new(&buf1[..]),
                Some(&[
                    fd.as_raw_descriptor(),
                    fd.as_raw_descriptor(),
                    fd.as_raw_descriptor(),
                ]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, files) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        assert!(files.is_some());
        let files = files.unwrap();
        {
            assert_eq!(files.len(), 3);
            let mut file = &files[1];
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }
        let (bytes, buf2, files) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(files.is_none());

        // Following communication pattern should not work:
        // Sending side: data(header, body) with fds
        // Receiving side: data(header), data(body) with fds
        let len = master
            .send_slice(
                IoSlice::new(&buf1[..]),
                Some(&[
                    fd.as_raw_descriptor(),
                    fd.as_raw_descriptor(),
                    fd.as_raw_descriptor(),
                ]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let mut buf4 = vec![0u8; 2];
        slave.recv_into_bufs_all(&mut [&mut buf4[..]]).unwrap();
        assert_eq!(&buf1[..2], &buf4[..]);
        let (bytes, buf2, files) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(files.is_none());

        // Following communication pattern should work:
        // Sending side: data, data with fds
        // Receiving side: data, data with fds
        let len = master.send_slice(IoSlice::new(&buf1[..]), None).unwrap();
        assert_eq!(len, 4);
        let len = master
            .send_slice(
                IoSlice::new(&buf1[..]),
                Some(&[
                    fd.as_raw_descriptor(),
                    fd.as_raw_descriptor(),
                    fd.as_raw_descriptor(),
                ]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, files) = slave.recv_into_buf(0x4).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..]);
        assert!(files.is_none());

        let (bytes, buf2, files) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        assert!(files.is_some());
        let files = files.unwrap();
        {
            assert_eq!(files.len(), 3);
            let mut file = &files[1];
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }
        let (bytes, buf2, files) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(files.is_none());

        // Following communication pattern should not work:
        // Sending side: data1, data2 with fds
        // Receiving side: data + partial of data2, left of data2 with fds
        let len = master.send_slice(IoSlice::new(&buf1[..]), None).unwrap();
        assert_eq!(len, 4);
        let len = master
            .send_slice(
                IoSlice::new(&buf1[..]),
                Some(&[
                    fd.as_raw_descriptor(),
                    fd.as_raw_descriptor(),
                    fd.as_raw_descriptor(),
                ]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let mut v = vec![0u8; 5];
        slave.recv_into_bufs_all(&mut [&mut v[..]]).unwrap();
        assert_eq!(&v[..], &[1, 2, 3, 4, 1]);

        let (bytes, _, files) = slave.recv_into_buf(0x4).unwrap();
        assert_eq!(bytes, 3);
        assert!(files.is_none());

        // If the target fd array is too small, extra file descriptors will get lost.
        let len = master
            .send_slice(
                IoSlice::new(&buf1[..]),
                Some(&[
                    fd.as_raw_descriptor(),
                    fd.as_raw_descriptor(),
                    fd.as_raw_descriptor(),
                ]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, _, files) = slave.recv_into_buf(0x4).unwrap();
        assert_eq!(bytes, 4);
        assert!(files.is_some());
    }

    #[test]
    fn send_recv() {
        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let mut listener = SocketListener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let master = Connection::<MasterReq>::connect(&path).unwrap();
        let slave = listener.accept().unwrap().unwrap();

        let mut hdr1 =
            VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0, mem::size_of::<u64>() as u32);
        hdr1.set_need_reply(true);
        let features1 = 0x1u64;
        master.send_message(&hdr1, &features1, None).unwrap();

        let mut hdr2 = VhostUserMsgHeader::default();
        let mut features2 = 0u64;
        let files = slave
            .recv_into_bufs_all(&mut [hdr2.as_bytes_mut(), features2.as_bytes_mut()])
            .unwrap();
        assert!(hdr2.is_valid());
        assert_eq!(hdr1, hdr2);
        assert_eq!(features1, features2);
        assert!(files.is_none());

        master.send_header(&hdr1, None).unwrap();
        let (hdr2, files) = slave.recv_header().unwrap();
        assert_eq!(hdr1, hdr2);
        assert!(files.is_none());
    }
}
