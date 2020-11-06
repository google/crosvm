// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod msg_on_socket;
mod serializable_descriptors;

use base::{
    handle_eintr, net::UnixSeqpacket, AsRawDescriptor, Error as SysError, RawDescriptor, ScmSocket,
    UnsyncMarker,
};
use std::io::{IoSlice, Result};
use std::marker::PhantomData;
use std::os::unix::io::{AsRawFd, RawFd};

pub use crate::msg_on_socket::*;
pub use msg_on_socket_derive::*;

/// Create a pair of socket. Request is send in one direction while response is in the other
/// direction.
pub fn pair<Request: MsgOnSocket, Response: MsgOnSocket>(
) -> Result<(MsgSocket<Request, Response>, MsgSocket<Response, Request>)> {
    let (sock1, sock2) = UnixSeqpacket::pair()?;
    let requester = MsgSocket::new(sock1);
    let responder = MsgSocket::new(sock2);
    Ok((requester, responder))
}

/// Bidirection sock that support both send and recv.
pub struct MsgSocket<I: MsgOnSocket, O: MsgOnSocket> {
    sock: UnixSeqpacket,
    _i: PhantomData<I>,
    _o: PhantomData<O>,
    _unsync_marker: UnsyncMarker,
}

impl<I: MsgOnSocket, O: MsgOnSocket> MsgSocket<I, O> {
    // Create a new MsgSocket.
    pub fn new(s: UnixSeqpacket) -> MsgSocket<I, O> {
        MsgSocket {
            sock: s,
            _i: PhantomData,
            _o: PhantomData,
            _unsync_marker: PhantomData,
        }
    }

    // Creates an async receiver that implements `futures::Stream`.
    pub fn async_receiver(&self) -> MsgResult<AsyncReceiver<I, O>> {
        AsyncReceiver::new(self)
    }
}

/// One direction socket that only supports sending.
pub struct Sender<M: MsgOnSocket> {
    sock: UnixSeqpacket,
    _m: PhantomData<M>,
}

impl<M: MsgOnSocket> Sender<M> {
    /// Create a new sender sock.
    pub fn new(s: UnixSeqpacket) -> Sender<M> {
        Sender {
            sock: s,
            _m: PhantomData,
        }
    }
}

/// One direction socket that only supports receiving.
pub struct Receiver<M: MsgOnSocket> {
    sock: UnixSeqpacket,
    _m: PhantomData<M>,
}

impl<M: MsgOnSocket> Receiver<M> {
    /// Create a new receiver sock.
    pub fn new(s: UnixSeqpacket) -> Receiver<M> {
        Receiver {
            sock: s,
            _m: PhantomData,
        }
    }
}

impl<I: MsgOnSocket, O: MsgOnSocket> AsRef<UnixSeqpacket> for MsgSocket<I, O> {
    fn as_ref(&self) -> &UnixSeqpacket {
        &self.sock
    }
}

impl<I: MsgOnSocket, O: MsgOnSocket> AsRawDescriptor for MsgSocket<I, O> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.sock.as_raw_fd()
    }
}

impl<I: MsgOnSocket, O: MsgOnSocket> AsRawDescriptor for &MsgSocket<I, O> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.sock.as_raw_fd()
    }
}

impl<M: MsgOnSocket> AsRef<UnixSeqpacket> for Sender<M> {
    fn as_ref(&self) -> &UnixSeqpacket {
        &self.sock
    }
}

impl<M: MsgOnSocket> AsRawFd for Sender<M> {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

impl<M: MsgOnSocket> AsRef<UnixSeqpacket> for Receiver<M> {
    fn as_ref(&self) -> &UnixSeqpacket {
        &self.sock
    }
}

impl<M: MsgOnSocket> AsRawFd for Receiver<M> {
    fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

/// Types that could send a message.
pub trait MsgSender: AsRef<UnixSeqpacket> {
    type M: MsgOnSocket;
    fn send(&self, msg: &Self::M) -> MsgResult<()> {
        let msg_size = msg.msg_size();
        let fd_size = msg.descriptor_count();
        let mut msg_buffer: Vec<u8> = vec![0; msg_size];
        let mut fd_buffer: Vec<RawFd> = vec![0; fd_size];

        let fd_size = msg.write_to_buffer(&mut msg_buffer, &mut fd_buffer)?;
        let sock: &UnixSeqpacket = self.as_ref();
        if fd_size == 0 {
            handle_eintr!(sock.send(&msg_buffer))
                .map_err(|e| MsgError::Send(SysError::new(e.raw_os_error().unwrap_or(0))))?;
        } else {
            let ioslice = IoSlice::new(&msg_buffer[..]);
            sock.send_with_fds(&[ioslice], &fd_buffer[0..fd_size])
                .map_err(MsgError::Send)?;
        }
        Ok(())
    }
}

/// Types that could receive a message.
pub trait MsgReceiver: AsRef<UnixSeqpacket> {
    type M: MsgOnSocket;
    fn recv(&self) -> MsgResult<Self::M> {
        let sock: &UnixSeqpacket = self.as_ref();

        let (msg_buffer, fd_buffer) = {
            if Self::M::uses_descriptor() {
                sock.recv_as_vec_with_fds()
                    .map_err(|e| MsgError::Recv(SysError::new(e.raw_os_error().unwrap_or(0))))?
            } else {
                (
                    sock.recv_as_vec().map_err(|e| {
                        MsgError::Recv(SysError::new(e.raw_os_error().unwrap_or(0)))
                    })?,
                    vec![],
                )
            }
        };

        if msg_buffer.len() == 0 && Self::M::fixed_size() != Some(0) {
            return Err(MsgError::RecvZero);
        }

        if let Some(fixed_size) = Self::M::fixed_size() {
            if fixed_size != msg_buffer.len() {
                return Err(MsgError::BadRecvSize {
                    expected: fixed_size,
                    actual: msg_buffer.len(),
                });
            }
        }

        // Safe because fd buffer is read from socket.
        let (v, read_fd_size) = unsafe { Self::M::read_from_buffer(&msg_buffer, &fd_buffer)? };
        if fd_buffer.len() != read_fd_size {
            return Err(MsgError::NotExpectDescriptor);
        }
        Ok(v)
    }
}

impl<I: MsgOnSocket, O: MsgOnSocket> MsgSender for MsgSocket<I, O> {
    type M = I;
}
impl<I: MsgOnSocket, O: MsgOnSocket> MsgReceiver for MsgSocket<I, O> {
    type M = O;
}

impl<I: MsgOnSocket> MsgSender for Sender<I> {
    type M = I;
}
impl<O: MsgOnSocket> MsgReceiver for Receiver<O> {
    type M = O;
}

/// Asynchronous adaptor for `MsgSocket`.
pub struct AsyncReceiver<'a, I: MsgOnSocket, O: MsgOnSocket> {
    inner: &'a MsgSocket<I, O>,
}

impl<'a, I: MsgOnSocket, O: MsgOnSocket> AsyncReceiver<'a, I, O> {
    fn new(msg_socket: &MsgSocket<I, O>) -> MsgResult<AsyncReceiver<I, O>> {
        Ok(AsyncReceiver { inner: msg_socket })
    }

    pub async fn next(&mut self) -> MsgResult<O> {
        let p = cros_async::async_from(&self.inner.sock).unwrap();
        p.wait_readable().await.unwrap();
        self.inner.recv()
    }
}
