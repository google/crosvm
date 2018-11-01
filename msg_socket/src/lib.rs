// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)]
#[macro_use]
extern crate msg_on_socket_derive;
extern crate data_model;
#[macro_use]
extern crate sys_util;

mod msg_on_socket;

use std::io::Result;
use std::marker::PhantomData;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixDatagram;
use sys_util::{Error as SysError, ScmSocket, UnlinkUnixDatagram};

pub use msg_on_socket::*;
pub use msg_on_socket_derive::*;

/// Create a pair of socket. Request is send in one direction while response is in the other
/// direction.
pub fn pair<Request: MsgOnSocket, Response: MsgOnSocket>(
) -> Option<(MsgSocket<Request, Response>, MsgSocket<Response, Request>)> {
    let (sock1, sock2) = match UnixDatagram::pair() {
        Ok((sock1, sock2)) => (sock1, sock2),
        _ => {
            return None;
        }
    };
    let requester = MsgSocket {
        sock: sock1,
        _i: PhantomData,
        _o: PhantomData,
    };
    let responder = MsgSocket {
        sock: sock2,
        _i: PhantomData,
        _o: PhantomData,
    };
    Some((requester, responder))
}

/// Bidirection sock that support both send and recv.
pub struct MsgSocket<I: MsgOnSocket, O: MsgOnSocket> {
    sock: UnixDatagram,
    _i: PhantomData<I>,
    _o: PhantomData<O>,
}

impl<I: MsgOnSocket, O: MsgOnSocket> MsgSocket<I, O> {
    // Create a new MsgSocket.
    pub fn new(s: UnixDatagram) -> MsgSocket<I, O> {
        MsgSocket {
            sock: s,
            _i: PhantomData,
            _o: PhantomData,
        }
    }
}

/// Bidirection sock that support both send and recv.
pub struct UnlinkMsgSocket<I: MsgOnSocket, O: MsgOnSocket> {
    sock: UnlinkUnixDatagram,
    _i: PhantomData<I>,
    _o: PhantomData<O>,
}

impl<I: MsgOnSocket, O: MsgOnSocket> UnlinkMsgSocket<I, O> {
    // Create a new MsgSocket.
    pub fn new(s: UnlinkUnixDatagram) -> UnlinkMsgSocket<I, O> {
        UnlinkMsgSocket {
            sock: s,
            _i: PhantomData,
            _o: PhantomData,
        }
    }
}

/// One direction socket that only supports sending.
pub struct Sender<M: MsgOnSocket> {
    sock: UnixDatagram,
    _m: PhantomData<M>,
}

impl<M: MsgOnSocket> Sender<M> {
    /// Create a new sender sock.
    pub fn new(s: UnixDatagram) -> Sender<M> {
        Sender {
            sock: s,
            _m: PhantomData,
        }
    }
}

/// One direction socket that only supports receiving.
pub struct Receiver<M: MsgOnSocket> {
    sock: UnixDatagram,
    _m: PhantomData<M>,
}

impl<M: MsgOnSocket> Receiver<M> {
    /// Create a new receiver sock.
    pub fn new(s: UnixDatagram) -> Receiver<M> {
        Receiver {
            sock: s,
            _m: PhantomData,
        }
    }
}

impl<I: MsgOnSocket, O: MsgOnSocket> AsRef<UnixDatagram> for MsgSocket<I, O> {
    fn as_ref(&self) -> &UnixDatagram {
        &self.sock
    }
}

impl<I: MsgOnSocket, O: MsgOnSocket> AsRef<UnixDatagram> for UnlinkMsgSocket<I, O> {
    fn as_ref(&self) -> &UnixDatagram {
        self.sock.as_ref()
    }
}

impl<M: MsgOnSocket> AsRef<UnixDatagram> for Sender<M> {
    fn as_ref(&self) -> &UnixDatagram {
        &self.sock
    }
}

impl<M: MsgOnSocket> AsRef<UnixDatagram> for Receiver<M> {
    fn as_ref(&self) -> &UnixDatagram {
        &self.sock
    }
}

/// Types that could send a message.
pub trait MsgSender<M: MsgOnSocket>: AsRef<UnixDatagram> {
    fn send(&self, msg: &M) -> MsgResult<()> {
        let msg_size = M::msg_size();
        let fd_size = M::max_fd_count();
        let mut msg_buffer: Vec<u8> = vec![0; msg_size];
        let mut fd_buffer: Vec<RawFd> = vec![0; fd_size];

        let fd_size = msg.write_to_buffer(&mut msg_buffer, &mut fd_buffer)?;
        let sock: &UnixDatagram = self.as_ref();
        if fd_size == 0 {
            handle_eintr!(sock.send(&msg_buffer))
                .map_err(|e| MsgError::Send(SysError::new(e.raw_os_error().unwrap_or(0))))?;
        } else {
            sock.send_with_fds(&msg_buffer[..], &fd_buffer[0..fd_size])
                .map_err(|e| MsgError::Send(e))?;
        }
        Ok(())
    }
}

/// Types that could receive a message.
pub trait MsgReceiver<M: MsgOnSocket>: AsRef<UnixDatagram> {
    fn recv(&self) -> MsgResult<M> {
        let msg_size = M::msg_size();
        let fd_size = M::max_fd_count();
        let mut msg_buffer: Vec<u8> = vec![0; msg_size];
        let mut fd_buffer: Vec<RawFd> = vec![0; fd_size];

        let sock: &UnixDatagram = self.as_ref();

        let (recv_msg_size, recv_fd_size) = {
            if fd_size == 0 {
                let size = sock
                    .recv(&mut msg_buffer)
                    .map_err(|e| MsgError::Recv(SysError::new(e.raw_os_error().unwrap_or(0))))?;
                (size, 0)
            } else {
                sock.recv_with_fds(&mut msg_buffer, &mut fd_buffer)
                    .map_err(|e| MsgError::Recv(e))?
            }
        };
        if msg_size != recv_msg_size {
            return Err(MsgError::BadRecvSize(msg_size));
        }
        // Safe because fd buffer is read from socket.
        let (v, read_fd_size) = unsafe {
            M::read_from_buffer(&msg_buffer[0..recv_msg_size], &fd_buffer[0..recv_fd_size])?
        };
        if recv_fd_size != read_fd_size {
            return Err(MsgError::NotExpectFd);
        }
        Ok(v)
    }
}

impl<I: MsgOnSocket, O: MsgOnSocket> MsgSender<I> for MsgSocket<I, O> {}
impl<I: MsgOnSocket, O: MsgOnSocket> MsgReceiver<O> for MsgSocket<I, O> {}

impl<I: MsgOnSocket, O: MsgOnSocket> MsgSender<I> for UnlinkMsgSocket<I, O> {}
impl<I: MsgOnSocket, O: MsgOnSocket> MsgReceiver<O> for UnlinkMsgSocket<I, O> {}

impl<M: MsgOnSocket> MsgSender<M> for Sender<M> {}
impl<M: MsgOnSocket> MsgReceiver<M> for Receiver<M> {}

#[cfg(test)]
mod tests {
    use super::*;
    use sys_util::EventFd;

    #[derive(MsgOnSocket)]
    struct Request {
        field0: u8,
        field1: EventFd,
        field2: u32,
    }

    #[derive(MsgOnSocket)]
    enum Response {
        A(u8),
        B,
        C(u32, EventFd),
        D([u8; 4]),
        E { f0: u8, f1: u32 },
    }

    #[derive(MsgOnSocket)]
    struct Message(u8, u16, EventFd);

    #[test]
    fn sock_send_recv_struct() {
        let (req, res) = pair::<Request, Response>().unwrap();
        let e0 = EventFd::new().unwrap();
        let e1 = e0.try_clone().unwrap();
        req.send(&Request {
            field0: 2,
            field1: e0,
            field2: 0xf0f0,
        }).unwrap();
        let r = res.recv().unwrap();
        assert_eq!(r.field0, 2);
        assert_eq!(r.field2, 0xf0f0);
        r.field1.write(0x0f0f).unwrap();
        assert_eq!(e1.read().unwrap(), 0x0f0f);
    }

    #[test]
    fn sock_send_recv_enum() {
        let (req, res) = pair::<Request, Response>().unwrap();
        let e0 = EventFd::new().unwrap();
        let e1 = e0.try_clone().unwrap();
        res.send(&Response::C(0xf0f0, e0)).unwrap();
        let r = req.recv().unwrap();
        match r {
            Response::C(v, efd) => {
                assert_eq!(v, 0xf0f0);
                efd.write(0x0f0f).unwrap();
            }
            _ => panic!("wrong type"),
        };
        assert_eq!(e1.read().unwrap(), 0x0f0f);

        res.send(&Response::B).unwrap();
        match req.recv().unwrap() {
            Response::B => {}
            _ => panic!("Wrong enum type"),
        };

        res.send(&Response::A(0x3)).unwrap();
        match req.recv().unwrap() {
            Response::A(v) => assert_eq!(v, 0x3),
            _ => panic!("Wrong enum type"),
        };

        res.send(&Response::D([0, 1, 2, 3])).unwrap();
        match req.recv().unwrap() {
            Response::D(v) => assert_eq!(v, [0, 1, 2, 3]),
            _ => panic!("Wrong enum type"),
        };

        res.send(&Response::E {
            f0: 0x12,
            f1: 0x0f0f,
        }).unwrap();
        match req.recv().unwrap() {
            Response::E { f0, f1 } => {
                assert_eq!(f0, 0x12);
                assert_eq!(f1, 0x0f0f);
            }
            _ => panic!("Wrong enum type"),
        };
    }

    #[test]
    fn sock_send_recv_tuple() {
        let (req, res) = pair::<Message, Message>().unwrap();
        let e0 = EventFd::new().unwrap();
        let e1 = e0.try_clone().unwrap();
        req.send(&Message(1, 0x12, e0)).unwrap();
        let r = res.recv().unwrap();
        assert_eq!(r.0, 1);
        assert_eq!(r.1, 0x12);
        r.2.write(0x0f0f).unwrap();
        assert_eq!(e1.read().unwrap(), 0x0f0f);
    }

}
