// Copyright 2025 Google
// SPDX-License-Identifier: MIT

use std::io::IoSlice;
use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::path::Path;

use rustix::cmsg_space;
use rustix::fs::fcntl_setfl;
use rustix::fs::OFlags;
use rustix::net::accept;
use rustix::net::bind;
use rustix::net::connect;
use rustix::net::listen;
use rustix::net::recvmsg;
use rustix::net::sendmsg;
use rustix::net::socket_with;
use rustix::net::AddressFamily;
use rustix::net::RecvAncillaryBuffer;
use rustix::net::RecvAncillaryMessage;
use rustix::net::RecvFlags;
use rustix::net::SendAncillaryBuffer;
use rustix::net::SendAncillaryMessage;
use rustix::net::SendFlags;
use rustix::net::SocketAddrUnix;
use rustix::net::SocketFlags;
use rustix::net::SocketType;
use rustix::path::Arg;

use crate::AsBorrowedDescriptor;
use crate::MesaError;
use crate::MesaResult;
use crate::OwnedDescriptor;
use crate::TubeType;

const MAX_IDENTIFIERS: usize = 28;

pub struct Tube {
    socket: OwnedDescriptor,
}

impl Tube {
    pub fn new<P: AsRef<Path> + Arg>(path: P, kind: TubeType) -> MesaResult<Tube> {
        let socket = match kind {
            TubeType::Packet => socket_with(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::empty(),
                None,
            )?,
            TubeType::Stream => socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC,
                None,
            )?,
        };

        let unix_addr = SocketAddrUnix::new(path)?;
        connect(&socket, &unix_addr)?;

        Ok(Tube {
            socket: socket.into(),
        })
    }

    pub fn send(&self, opaque_data: &[u8], descriptors: &[OwnedDescriptor]) -> MesaResult<usize> {
        let mut space = [MaybeUninit::<u8>::uninit(); cmsg_space!(ScmRights(MAX_IDENTIFIERS))];
        let mut cmsg_buffer = SendAncillaryBuffer::new(&mut space);

        let borrowed_fds: Vec<_> = descriptors.iter().map(AsFd::as_fd).collect();

        let cmsg = SendAncillaryMessage::ScmRights(&borrowed_fds);
        cmsg_buffer.push(cmsg);

        let bytes_sent = sendmsg(
            &self.socket,
            &[IoSlice::new(opaque_data)],
            &mut cmsg_buffer,
            SendFlags::empty(),
        )?;

        Ok(bytes_sent)
    }

    pub fn receive(&self, opaque_data: &mut [u8]) -> MesaResult<(usize, Vec<OwnedDescriptor>)> {
        let mut iovecs = [IoSliceMut::new(opaque_data)];

        let mut space = [MaybeUninit::<u8>::uninit(); cmsg_space!(ScmRights(MAX_IDENTIFIERS))];
        let mut cmsg_buffer = RecvAncillaryBuffer::new(&mut space);
        let r = recvmsg(
            &self.socket,
            &mut iovecs,
            &mut cmsg_buffer,
            RecvFlags::empty(),
        )?;

        let len = r.bytes;
        let mut received_descriptors: Vec<OwnedDescriptor> = Vec::new();

        // Iterate over received control messages
        for cmsg in cmsg_buffer.drain() {
            match cmsg {
                RecvAncillaryMessage::ScmRights(fds) => {
                    received_descriptors.extend(fds.into_iter().map(Into::into));
                }
                _ => return Err(MesaError::Unsupported), // Handle unexpected control messages
            }
        }

        Ok((len, received_descriptors))
    }
}

impl AsBorrowedDescriptor for Tube {
    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
        &self.socket
    }
}

pub struct Listener {
    socket: OwnedDescriptor,
}

impl Listener {
    /// Creates a new `Listener` bound to the given path.
    pub fn bind<P: AsRef<Path> + Arg>(path: P) -> MesaResult<Listener> {
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::empty(),
            None,
        )?;

        let unix_addr = SocketAddrUnix::new(path)?;
        bind(&socket, &unix_addr)?;
        listen(&socket, 128)?;

        fcntl_setfl(&socket, OFlags::NONBLOCK)?;

        Ok(Listener {
            socket: socket.into(),
        })
    }

    pub fn accept(&self) -> MesaResult<Tube> {
        let accepted_fd = accept(&self.socket)?;
        let descriptor: OwnedDescriptor = accepted_fd.into();
        Ok(Tube { socket: descriptor })
    }
}

impl AsBorrowedDescriptor for Listener {
    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor {
        &self.socket
    }
}
