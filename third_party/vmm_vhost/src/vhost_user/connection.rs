// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structs for Unix Domain Socket listener and endpoint.

#![allow(dead_code)]

use std::fs::File;
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::{mem, slice};

use libc::{c_void, iovec};
use sys_util::ScmSocket;

use super::message::*;
use super::{Error, Result};

/// Unix domain socket listener for accepting incoming connections.
pub struct Listener {
    fd: UnixListener,
    path: PathBuf,
}

impl Listener {
    /// Create a unix domain socket listener.
    ///
    /// # Return:
    /// * - the new Listener object on success.
    /// * - SocketError: failed to create listener socket.
    pub fn new<P: AsRef<Path>>(path: P, unlink: bool) -> Result<Self> {
        if unlink {
            let _ = std::fs::remove_file(&path);
        }
        let fd = UnixListener::bind(&path).map_err(Error::SocketError)?;
        Ok(Listener {
            fd,
            path: path.as_ref().to_owned(),
        })
    }

    /// Accept an incoming connection.
    ///
    /// # Return:
    /// * - Some(UnixStream): new UnixStream object if new incoming connection is available.
    /// * - None: no incoming connection available.
    /// * - SocketError: errors from accept().
    pub fn accept(&self) -> Result<Option<UnixStream>> {
        loop {
            match self.fd.accept() {
                Ok((socket, _addr)) => return Ok(Some(socket)),
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
    pub fn set_nonblocking(&self, block: bool) -> Result<()> {
        self.fd.set_nonblocking(block).map_err(Error::SocketError)
    }
}

impl AsRawFd for Listener {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Unix domain socket endpoint for vhost-user connection.
pub(super) struct Endpoint<R: Req> {
    sock: UnixStream,
    _r: PhantomData<R>,
}

impl<R: Req> Endpoint<R> {
    /// Create a new stream by connecting to server at `str`.
    ///
    /// # Return:
    /// * - the new Endpoint object on success.
    /// * - SocketConnect: failed to connect to peer.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self> {
        let sock = UnixStream::connect(path).map_err(Error::SocketConnect)?;
        Ok(Self::from_stream(sock))
    }

    /// Create an endpoint from a stream object.
    pub fn from_stream(sock: UnixStream) -> Self {
        Endpoint {
            sock,
            _r: PhantomData,
        }
    }

    /// Sends bytes from scatter-gather vectors over the socket with optional attached file
    /// descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn send_iovec(&mut self, iovs: &[&[u8]], fds: Option<&[RawFd]>) -> Result<usize> {
        let rfds = match fds {
            Some(rfds) => rfds,
            _ => &[],
        };
        self.sock.send_bufs_with_fds(iovs, rfds).map_err(Into::into)
    }

    /// Sends all bytes from scatter-gather vectors over the socket with optional attached file
    /// descriptors. Will loop until all data has been transfered.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn send_iovec_all(&mut self, iovs: &[&[u8]], fds: Option<&[RawFd]>) -> Result<usize> {
        let mut data_sent = 0;
        let mut data_total = 0;
        let iov_lens: Vec<usize> = iovs.iter().map(|iov| iov.len()).collect();
        for len in &iov_lens {
            data_total += len;
        }

        while (data_total - data_sent) > 0 {
            let (nr_skip, offset) = get_sub_iovs_offset(&iov_lens, data_sent);
            let iov = &iovs[nr_skip][offset..];

            let data = &[&[iov], &iovs[(nr_skip + 1)..]].concat();
            let sfds = if data_sent == 0 { fds } else { None };

            let sent = self.send_iovec(data, sfds);
            match sent {
                Ok(0) => return Ok(data_sent),
                Ok(n) => data_sent += n,
                Err(e) => match e {
                    Error::SocketRetry(_) => {}
                    _ => return Err(e),
                },
            }
        }
        Ok(data_sent)
    }

    /// Sends bytes from a slice over the socket with optional attached file descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn send_slice(&mut self, data: &[u8], fds: Option<&[RawFd]>) -> Result<usize> {
        self.send_iovec(&[data], fds)
    }

    /// Sends a header-only message with optional attached file descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    pub fn send_header(
        &mut self,
        hdr: &VhostUserMsgHeader<R>,
        fds: Option<&[RawFd]>,
    ) -> Result<()> {
        // Safe because there can't be other mutable referance to hdr.
        let iovs = unsafe {
            [slice::from_raw_parts(
                hdr as *const VhostUserMsgHeader<R> as *const u8,
                mem::size_of::<VhostUserMsgHeader<R>>(),
            )]
        };
        let bytes = self.send_iovec_all(&iovs[..], fds)?;
        if bytes != mem::size_of::<VhostUserMsgHeader<R>>() {
            return Err(Error::PartialMessage);
        }
        Ok(())
    }

    /// Send a message with header and body. Optional file descriptors may be attached to
    /// the message.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    pub fn send_message<T: Sized>(
        &mut self,
        hdr: &VhostUserMsgHeader<R>,
        body: &T,
        fds: Option<&[RawFd]>,
    ) -> Result<()> {
        if mem::size_of::<T>() > MAX_MSG_SIZE {
            return Err(Error::OversizedMsg);
        }
        // Safe because there can't be other mutable referance to hdr and body.
        let iovs = unsafe {
            [
                slice::from_raw_parts(
                    hdr as *const VhostUserMsgHeader<R> as *const u8,
                    mem::size_of::<VhostUserMsgHeader<R>>(),
                ),
                slice::from_raw_parts(body as *const T as *const u8, mem::size_of::<T>()),
            ]
        };
        let bytes = self.send_iovec_all(&iovs[..], fds)?;
        if bytes != mem::size_of::<VhostUserMsgHeader<R>>() + mem::size_of::<T>() {
            return Err(Error::PartialMessage);
        }
        Ok(())
    }

    /// Send a message with header, body and payload. Optional file descriptors
    /// may also be attached to the message.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - OversizedMsg: message size is too big.
    /// * - PartialMessage: received a partial message.
    /// * - IncorrectFds: wrong number of attached fds.
    pub fn send_message_with_payload<T: Sized>(
        &mut self,
        hdr: &VhostUserMsgHeader<R>,
        body: &T,
        payload: &[u8],
        fds: Option<&[RawFd]>,
    ) -> Result<()> {
        let len = payload.len();
        if mem::size_of::<T>() > MAX_MSG_SIZE {
            return Err(Error::OversizedMsg);
        }
        if len > MAX_MSG_SIZE - mem::size_of::<T>() {
            return Err(Error::OversizedMsg);
        }
        if let Some(fd_arr) = fds {
            if fd_arr.len() > MAX_ATTACHED_FD_ENTRIES {
                return Err(Error::IncorrectFds);
            }
        }

        // Safe because there can't be other mutable reference to hdr, body and payload.
        let iovs = unsafe {
            [
                slice::from_raw_parts(
                    hdr as *const VhostUserMsgHeader<R> as *const u8,
                    mem::size_of::<VhostUserMsgHeader<R>>(),
                ),
                slice::from_raw_parts(body as *const T as *const u8, mem::size_of::<T>()),
                slice::from_raw_parts(payload.as_ptr() as *const u8, len),
            ]
        };
        let total = mem::size_of::<VhostUserMsgHeader<R>>() + mem::size_of::<T>() + len;
        let len = self.send_iovec_all(&iovs, fds)?;
        if len != total {
            return Err(Error::PartialMessage);
        }
        Ok(())
    }

    /// Reads bytes from the socket into the given scatter/gather vectors.
    ///
    /// # Return:
    /// * - (number of bytes received, buf) on success
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn recv_data(&mut self, len: usize) -> Result<(usize, Vec<u8>)> {
        let mut rbuf = vec![0u8; len];
        let (bytes, _) = self.sock.recv_with_fds(&mut rbuf[..], &mut [])?;
        Ok((bytes, rbuf))
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
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn recv_into_iovec(&mut self, iovs: &mut [iovec]) -> Result<(usize, Option<Vec<File>>)> {
        let mut fd_array = vec![0; MAX_ATTACHED_FD_ENTRIES];
        let (bytes, fds) = self.sock.recv_iovecs_with_fds(iovs, &mut fd_array)?;

        let files = match fds {
            0 => None,
            n => {
                let files = fd_array
                    .iter()
                    .take(n)
                    .map(|fd| {
                        // Safe because we have the ownership of `fd`.
                        unsafe { File::from_raw_fd(*fd) }
                    })
                    .collect();
                Some(files)
            }
        };

        Ok((bytes, files))
    }

    /// Reads all bytes from the socket into the given scatter/gather vectors with optional
    /// attached files. Will loop until all data has been transferred.
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
    /// * - (number of bytes received, [received fds]) on success
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn recv_into_iovec_all(
        &mut self,
        iovs: &mut [iovec],
    ) -> Result<(usize, Option<Vec<File>>)> {
        let mut data_read = 0;
        let mut data_total = 0;
        let mut rfds = None;
        let iov_lens: Vec<usize> = iovs.iter().map(|iov| iov.iov_len).collect();
        for len in &iov_lens {
            data_total += len;
        }

        while (data_total - data_read) > 0 {
            let (nr_skip, offset) = get_sub_iovs_offset(&iov_lens, data_read);
            let iov = &mut iovs[nr_skip];

            let mut data = [
                &[iovec {
                    iov_base: (iov.iov_base as usize + offset) as *mut c_void,
                    iov_len: iov.iov_len - offset,
                }],
                &iovs[(nr_skip + 1)..],
            ]
            .concat();

            let res = self.recv_into_iovec(&mut data);
            match res {
                Ok((0, _)) => return Ok((data_read, rfds)),
                Ok((n, fds)) => {
                    if data_read == 0 {
                        rfds = fds;
                    }
                    data_read += n;
                }
                Err(e) => match e {
                    Error::SocketRetry(_) => {}
                    _ => return Err(e),
                },
            }
        }
        Ok((data_read, rfds))
    }

    /// Reads bytes from the socket into a new buffer with optional attached
    /// files. Received file descriptors are set close-on-exec and converted to `File`.
    ///
    /// # Return:
    /// * - (number of bytes received, buf, [received files]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    pub fn recv_into_buf(
        &mut self,
        buf_size: usize,
    ) -> Result<(usize, Vec<u8>, Option<Vec<File>>)> {
        let mut buf = vec![0u8; buf_size];
        let (bytes, files) = {
            let mut iovs = [iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf_size,
            }];
            self.recv_into_iovec(&mut iovs)?
        };
        Ok((bytes, buf, files))
    }

    /// Receive a header-only message with optional attached files.
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be
    /// accepted and all other file descriptor will be discard silently.
    ///
    /// # Return:
    /// * - (message header, [received files]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    pub fn recv_header(&mut self) -> Result<(VhostUserMsgHeader<R>, Option<Vec<File>>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let mut iovs = [iovec {
            iov_base: (&mut hdr as *mut VhostUserMsgHeader<R>) as *mut c_void,
            iov_len: mem::size_of::<VhostUserMsgHeader<R>>(),
        }];
        let (bytes, files) = self.recv_into_iovec_all(&mut iovs[..])?;

        if bytes != mem::size_of::<VhostUserMsgHeader<R>>() {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, files))
    }

    /// Receive a message with optional attached file descriptors.
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be
    /// accepted and all other file descriptor will be discard silently.
    ///
    /// # Return:
    /// * - (message header, message body, [received files]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    pub fn recv_body<T: Sized + Default + VhostUserMsgValidator>(
        &mut self,
    ) -> Result<(VhostUserMsgHeader<R>, T, Option<Vec<File>>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let mut body: T = Default::default();
        let mut iovs = [
            iovec {
                iov_base: (&mut hdr as *mut VhostUserMsgHeader<R>) as *mut c_void,
                iov_len: mem::size_of::<VhostUserMsgHeader<R>>(),
            },
            iovec {
                iov_base: (&mut body as *mut T) as *mut c_void,
                iov_len: mem::size_of::<T>(),
            },
        ];
        let (bytes, files) = self.recv_into_iovec_all(&mut iovs[..])?;

        let total = mem::size_of::<VhostUserMsgHeader<R>>() + mem::size_of::<T>();
        if bytes != total {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, body, files))
    }

    /// Receive a message with header and optional content. Callers need to
    /// pre-allocate a big enough buffer to receive the message body and
    /// optional payload. If there are attached file descriptor associated
    /// with the message, the first MAX_ATTACHED_FD_ENTRIES file descriptors
    /// will be accepted and all other file descriptor will be discard
    /// silently.
    ///
    /// # Return:
    /// * - (message header, message size, [received files]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    pub fn recv_body_into_buf(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(VhostUserMsgHeader<R>, usize, Option<Vec<File>>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let mut iovs = [
            iovec {
                iov_base: (&mut hdr as *mut VhostUserMsgHeader<R>) as *mut c_void,
                iov_len: mem::size_of::<VhostUserMsgHeader<R>>(),
            },
            iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf.len(),
            },
        ];
        let (bytes, files) = self.recv_into_iovec_all(&mut iovs[..])?;

        if bytes < mem::size_of::<VhostUserMsgHeader<R>>() {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, bytes - mem::size_of::<VhostUserMsgHeader<R>>(), files))
    }

    /// Receive a message with optional payload and attached file descriptors.
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be
    /// accepted and all other file descriptor will be discard silently.
    ///
    /// # Return:
    /// * - (message header, message body, size of payload, [received files]) on success.
    /// * - SocketRetry: temporary error caused by signals or short of resources.
    /// * - SocketBroken: the underline socket is broken.
    /// * - SocketError: other socket related errors.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::type_complexity))]
    pub fn recv_payload_into_buf<T: Sized + Default + VhostUserMsgValidator>(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(VhostUserMsgHeader<R>, T, usize, Option<Vec<File>>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let mut body: T = Default::default();
        let mut iovs = [
            iovec {
                iov_base: (&mut hdr as *mut VhostUserMsgHeader<R>) as *mut c_void,
                iov_len: mem::size_of::<VhostUserMsgHeader<R>>(),
            },
            iovec {
                iov_base: (&mut body as *mut T) as *mut c_void,
                iov_len: mem::size_of::<T>(),
            },
            iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf.len(),
            },
        ];
        let (bytes, files) = self.recv_into_iovec_all(&mut iovs[..])?;

        let total = mem::size_of::<VhostUserMsgHeader<R>>() + mem::size_of::<T>();
        if bytes < total {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, body, bytes - total, files))
    }
}

impl<T: Req> AsRawFd for Endpoint<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

// Given a slice of sizes and the `skip_size`, return the offset of `skip_size` in the slice.
// For example:
//     let iov_lens = vec![4, 4, 5];
//     let size = 6;
//     assert_eq!(get_sub_iovs_offset(&iov_len, size), (1, 2));
fn get_sub_iovs_offset(iov_lens: &[usize], skip_size: usize) -> (usize, usize) {
    let mut size = skip_size;
    let mut nr_skip = 0;

    for len in iov_lens {
        if size >= *len {
            size -= *len;
            nr_skip += 1;
        } else {
            break;
        }
    }
    (nr_skip, size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::{tempfile, Builder, TempDir};

    fn temp_dir() -> TempDir {
        Builder::new().prefix("/tmp/vhost_test").tempdir().unwrap()
    }

    #[test]
    fn create_listener() {
        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let listener = Listener::new(&path, true).unwrap();

        assert!(listener.as_raw_fd() > 0);
    }

    #[test]
    fn accept_connection() {
        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let listener = Listener::new(&path, true).unwrap();
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
        let listener = Listener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut master = Endpoint::<MasterReq>::connect(&path).unwrap();
        let sock = listener.accept().unwrap().unwrap();
        let mut slave = Endpoint::<MasterReq>::from_stream(sock);

        let buf1 = vec![0x1, 0x2, 0x3, 0x4];
        let mut len = master.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let (bytes, buf2, _) = slave.recv_into_buf(0x1000).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..bytes]);

        len = master.send_slice(&buf1[..], None).unwrap();
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
        let listener = Listener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut master = Endpoint::<MasterReq>::connect(&path).unwrap();
        let sock = listener.accept().unwrap().unwrap();
        let mut slave = Endpoint::<MasterReq>::from_stream(sock);

        let mut fd = tempfile().unwrap();
        write!(fd, "test").unwrap();

        // Normal case for sending/receiving file descriptors
        let buf1 = vec![0x1, 0x2, 0x3, 0x4];
        let len = master
            .send_slice(&buf1[..], Some(&[fd.as_raw_fd()]))
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
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
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
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf4) = slave.recv_data(2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf4[..]);
        let (bytes, buf2, files) = slave.recv_into_buf(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(files.is_none());

        // Following communication pattern should work:
        // Sending side: data, data with fds
        // Receiving side: data, data with fds
        let len = master.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
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
        let len = master.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, _) = slave.recv_data(5).unwrap();
        assert_eq!(bytes, 5);

        let (bytes, _, files) = slave.recv_into_buf(0x4).unwrap();
        assert_eq!(bytes, 3);
        assert!(files.is_none());

        // If the target fd array is too small, extra file descriptors will get lost.
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
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
        let listener = Listener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut master = Endpoint::<MasterReq>::connect(&path).unwrap();
        let sock = listener.accept().unwrap().unwrap();
        let mut slave = Endpoint::<MasterReq>::from_stream(sock);

        let mut hdr1 =
            VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0, mem::size_of::<u64>() as u32);
        hdr1.set_need_reply(true);
        let features1 = 0x1u64;
        master.send_message(&hdr1, &features1, None).unwrap();

        let mut features2 = 0u64;
        let slice = unsafe {
            slice::from_raw_parts_mut(
                (&mut features2 as *mut u64) as *mut u8,
                mem::size_of::<u64>(),
            )
        };
        let (hdr2, bytes, files) = slave.recv_body_into_buf(slice).unwrap();
        assert_eq!(hdr1, hdr2);
        assert_eq!(bytes, 8);
        assert_eq!(features1, features2);
        assert!(files.is_none());

        master.send_header(&hdr1, None).unwrap();
        let (hdr2, files) = slave.recv_header().unwrap();
        assert_eq!(hdr1, hdr2);
        assert!(files.is_none());
    }
}
