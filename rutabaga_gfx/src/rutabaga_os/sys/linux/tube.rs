// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Error as IoError;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::path::Path;

use nix::cmsg_space;
use nix::fcntl::fcntl;
use nix::fcntl::FcntlArg;
use nix::fcntl::OFlag;
use nix::sys::socket::accept;
use nix::sys::socket::bind;
use nix::sys::socket::connect;
use nix::sys::socket::listen;
use nix::sys::socket::recvmsg;
use nix::sys::socket::sendmsg;
use nix::sys::socket::socket;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::Backlog;
use nix::sys::socket::ControlMessage;
use nix::sys::socket::ControlMessageOwned;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockType;
use nix::sys::socket::UnixAddr;
use nix::NixPath;

use crate::rutabaga_os::AsRawDescriptor;
use crate::rutabaga_os::FromRawDescriptor;
use crate::rutabaga_os::RawDescriptor;
use crate::rutabaga_utils::RutabagaError;
use crate::rutabaga_utils::RutabagaResult;

const MAX_IDENTIFIERS: usize = 28;

pub struct Tube {
    socket: File,
}

impl Tube {
    pub fn new<P: AsRef<Path> + NixPath>(path: P) -> RutabagaResult<Tube> {
        let socket_fd = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::empty(),
            None,
        )?;

        let unix_addr = UnixAddr::new(&path)?;
        connect(socket_fd.as_raw_fd(), &unix_addr)?;
        let socket: File = socket_fd.into();

        Ok(Tube { socket })
    }

    pub fn send(&self, opaque_data: &[u8], descriptors: &[RawDescriptor]) -> RutabagaResult<usize> {
        let cmsg = ControlMessage::ScmRights(descriptors);
        let bytes_sent = sendmsg::<()>(
            self.socket.as_raw_descriptor(),
            &[IoSlice::new(opaque_data)],
            &[cmsg],
            MsgFlags::empty(),
            None,
        )?;

        Ok(bytes_sent)
    }

    pub fn receive(&self, opaque_data: &mut [u8]) -> RutabagaResult<(usize, Vec<File>)> {
        let mut iovecs = [IoSliceMut::new(opaque_data)];
        let mut cmsgspace = cmsg_space!([RawDescriptor; MAX_IDENTIFIERS]);
        let flags = MsgFlags::empty();

        let r = recvmsg::<()>(
            self.socket.as_raw_descriptor(),
            &mut iovecs,
            Some(&mut cmsgspace),
            flags,
        )?;

        let len = r.bytes;
        let files = match r.cmsgs().next() {
            Some(ControlMessageOwned::ScmRights(fds)) => {
                fds.into_iter()
                    .map(|fd| {
                        // SAFETY:
                        // Safe since the descriptors from recvmsg(..) are owned by us and
                        // valid.
                        unsafe { File::from_raw_descriptor(fd) }
                    })
                    .collect()
            }
            Some(_) => return Err(RutabagaError::Unsupported),
            None => Vec::new(),
        };

        Ok((len, files))
    }
}

impl AsFd for Tube {
    fn as_fd(&self) -> BorrowedFd {
        self.socket.as_fd()
    }
}

impl From<File> for Tube {
    fn from(file: File) -> Tube {
        Tube { socket: file }
    }
}

pub struct Listener {
    socket: OwnedFd,
}

impl Listener {
    /// Creates a new `Listener` bound to the given path.
    pub fn bind<P: AsRef<Path> + NixPath>(path: P) -> RutabagaResult<Listener> {
        let socket = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::empty(),
            None,
        )?;

        let unix_addr = UnixAddr::new(&path)?;
        bind(socket.as_raw_fd(), &unix_addr)?;
        listen(&socket, Backlog::new(128)?)?;

        fcntl(socket.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;

        Ok(Listener { socket })
    }

    pub fn accept(&self) -> RutabagaResult<Tube> {
        let sock = match accept(self.socket.as_raw_fd()) {
            Ok(socket) => socket,
            Err(_) => return Err(IoError::last_os_error().into()),
        };

        // SAFETY: Safe because we know the underlying OS descriptor is valid and
        // owned by us.
        let descriptor: File = unsafe { File::from_raw_descriptor(sock) };
        Ok(descriptor.into())
    }
}
