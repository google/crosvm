// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Common data structures for listener and connection.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod socket;
        pub use socket::to_system_stream;
        mod unix;
    } else if #[cfg(windows)] {
        mod tube;
        pub use tube::TubePlatformConnection;
        pub use tube::to_system_stream;
        mod windows;
    }
}

use std::fs::File;
use std::io::IoSliceMut;
use std::mem;
use std::path::Path;

use base::AsRawDescriptor;
use base::RawDescriptor;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::connection::Req;
use crate::message::MasterReq;
use crate::message::*;
use crate::sys::PlatformConnection;
use crate::Error;
use crate::Result;
use crate::SystemStream;

/// Listener for accepting connections.
pub trait Listener: Sized {
    /// Accept an incoming connection.
    fn accept(&mut self) -> Result<Option<Connection<MasterReq>>>;

    /// Change blocking status on the listener.
    fn set_nonblocking(&self, block: bool) -> Result<()>;
}

// Advance the internal cursor of the slices.
// This is same with a nightly API `IoSliceMut::advance_slices` but for `&mut [u8]`.
fn advance_slices_mut(bufs: &mut &mut [&mut [u8]], mut count: usize) {
    use std::mem::take;

    let mut idx = 0;
    for b in bufs.iter() {
        if count < b.len() {
            break;
        }
        count -= b.len();
        idx += 1;
    }
    *bufs = &mut take(bufs)[idx..];
    if !bufs.is_empty() {
        let slice = take(&mut bufs[0]);
        let (_, remaining) = slice.split_at_mut(count);
        bufs[0] = remaining;
    }
}

/// A vhost-user connection at a low abstraction level. Provides methods for sending and receiving
/// vhost-user message headers and bodies.
///
/// Builds on top of `PlatformConnection`, which provides methods for sending and receiving raw
/// bytes and file descriptors (a thin cross-platform abstraction for unix domain sockets).
pub struct Connection<R: Req>(
    pub(crate) PlatformConnection,
    std::marker::PhantomData<R>,
    // Mark `Connection` as `!Sync` because message sends and recvs cannot safely be done
    // concurrently.
    std::marker::PhantomData<std::cell::Cell<()>>,
);

impl<R: Req> From<SystemStream> for Connection<R> {
    fn from(sock: SystemStream) -> Self {
        Self(
            PlatformConnection::from(sock),
            std::marker::PhantomData,
            std::marker::PhantomData,
        )
    }
}

impl<R: Req> Connection<R> {
    /// Create a new stream by connecting to server at `path`.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self(
            PlatformConnection::connect(path)?,
            std::marker::PhantomData,
            std::marker::PhantomData,
        ))
    }

    /// Sends a header-only message with optional attached file descriptors.
    pub fn send_header_only_message(
        &self,
        hdr: &VhostUserMsgHeader<R>,
        fds: Option<&[RawDescriptor]>,
    ) -> Result<()> {
        self.0.send_message(hdr.as_bytes(), &[], &[], fds)
    }

    /// Send a message with header and body. Optional file descriptors may be attached to
    /// the message.
    pub fn send_message<T: AsBytes>(
        &self,
        hdr: &VhostUserMsgHeader<R>,
        body: &T,
        fds: Option<&[RawDescriptor]>,
    ) -> Result<()> {
        self.0
            .send_message(hdr.as_bytes(), body.as_bytes(), &[], fds)
    }

    /// Send a message with header and body. `payload` is appended to the end of the body. Optional
    /// file descriptors may also be attached to the message.
    pub fn send_message_with_payload<T: Sized + AsBytes>(
        &self,
        hdr: &VhostUserMsgHeader<R>,
        body: &T,
        payload: &[u8],
        fds: Option<&[RawDescriptor]>,
    ) -> Result<()> {
        self.0
            .send_message(hdr.as_bytes(), body.as_bytes(), payload, fds)
    }

    /// Reads all bytes into the given scatter/gather vectors with optional attached files. Will
    /// loop until all data has been transfered and errors if EOF is reached before then.
    ///
    /// # Return:
    /// * - received fds on success
    /// * - `Disconnect` - client is closed
    ///
    /// # TODO
    /// This function takes a slice of `&mut [u8]` instead of `IoSliceMut` because the internal
    /// cursor needs to be moved by `advance_slices_mut()`.
    /// Once `IoSliceMut::advance_slices()` becomes stable, this should be updated.
    /// <https://github.com/rust-lang/rust/issues/62726>.
    fn recv_into_bufs_all(&self, mut bufs: &mut [&mut [u8]]) -> Result<Vec<File>> {
        let mut first_read = true;
        let mut rfds = Vec::new();

        // Guarantee that `bufs` becomes empty if it doesn't contain any data.
        advance_slices_mut(&mut bufs, 0);

        while !bufs.is_empty() {
            let mut slices: Vec<IoSliceMut> = bufs.iter_mut().map(|b| IoSliceMut::new(b)).collect();
            let res = self.0.recv_into_bufs(&mut slices, true);
            match res {
                Ok((0, _)) => return Err(Error::PartialMessage),
                Ok((n, fds)) => {
                    if first_read {
                        first_read = false;
                        if let Some(fds) = fds {
                            rfds = fds;
                        }
                    }
                    advance_slices_mut(&mut bufs, n);
                }
                Err(e) => match e {
                    Error::SocketRetry(_) => {}
                    _ => return Err(e),
                },
            }
        }
        Ok(rfds)
    }

    /// Receive message header
    ///
    /// Errors if the header is invalid.
    ///
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be accepted and all
    /// other file descriptor will be discard silently.
    pub fn recv_header(&self) -> Result<(VhostUserMsgHeader<R>, Vec<File>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let files = self.recv_into_bufs_all(&mut [hdr.as_bytes_mut()])?;
        if !hdr.is_valid() {
            return Err(Error::InvalidMessage);
        }
        Ok((hdr, files))
    }

    /// Receive the body following the header `hdr`.
    pub fn recv_body_bytes(&self, hdr: &VhostUserMsgHeader<R>) -> Result<Vec<u8>> {
        // NOTE: `recv_into_bufs_all` is a noop when the buffer is empty, so `hdr.get_size() == 0`
        // works as expected.
        let mut body = vec![0; hdr.get_size().try_into().unwrap()];
        let files = self.recv_into_bufs_all(&mut [&mut body[..]])?;
        if !files.is_empty() {
            return Err(Error::InvalidMessage);
        }
        Ok(body)
    }

    /// Receive a message header and body.
    ///
    /// Errors if the header or body is invalid.
    ///
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be
    /// accepted and all other file descriptor will be discard silently.
    pub fn recv_message<T: AsBytes + FromBytes + VhostUserMsgValidator>(
        &self,
    ) -> Result<(VhostUserMsgHeader<R>, T, Vec<File>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let mut body = T::new_zeroed();
        let mut slices = [hdr.as_bytes_mut(), body.as_bytes_mut()];
        let files = self.recv_into_bufs_all(&mut slices)?;

        if !hdr.is_valid() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, body, files))
    }

    /// Receive a message header and body, where the body includes a variable length payload at the
    /// end.
    ///
    /// Errors if the header or body is invalid.
    ///
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be accepted and all
    /// other file descriptor will be discard silently.
    pub fn recv_message_with_payload<T: AsBytes + FromBytes + VhostUserMsgValidator>(
        &self,
    ) -> Result<(VhostUserMsgHeader<R>, T, Vec<u8>, Vec<File>)> {
        let (hdr, files) = self.recv_header()?;

        let mut body = T::new_zeroed();
        let payload_size = hdr.get_size() as usize - mem::size_of::<T>();
        let mut buf: Vec<u8> = vec![0; payload_size];
        let mut slices = [body.as_bytes_mut(), buf.as_bytes_mut()];
        let more_files = self.recv_into_bufs_all(&mut slices)?;
        if !body.is_valid() || !more_files.is_empty() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, body, buf, files))
    }
}

impl<R: Req> AsRawDescriptor for Connection<R> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;

    use tempfile::tempfile;

    use super::*;
    use crate::message::VhostUserEmptyMessage;
    use crate::message::VhostUserU64;

    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            pub(crate) use super::unix::tests::*;
        } else if #[cfg(windows)] {
            pub(crate) use super::windows::tests::*;
        }
    }

    #[test]
    fn send_header_only() {
        let (master, slave) = create_connection_pair();
        let hdr1 = VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0, 0);
        master.send_header_only_message(&hdr1, None).unwrap();
        let (hdr2, _, files) = slave.recv_message::<VhostUserEmptyMessage>().unwrap();
        assert_eq!(hdr1, hdr2);
        assert!(files.is_empty());
    }

    #[test]
    fn send_data() {
        let (master, slave) = create_connection_pair();
        let hdr1 = VhostUserMsgHeader::new(MasterReq::SET_FEATURES, 0, 8);
        master
            .send_message(&hdr1, &VhostUserU64::new(0xf00dbeefdeadf00d), None)
            .unwrap();
        let (hdr2, body, files) = slave.recv_message::<VhostUserU64>().unwrap();
        assert_eq!(hdr1, hdr2);
        let value = body.value;
        assert_eq!(value, 0xf00dbeefdeadf00d);
        assert!(files.is_empty());
    }

    #[test]
    fn send_fd() {
        let (master, slave) = create_connection_pair();

        let mut fd = tempfile().unwrap();
        write!(fd, "test").unwrap();

        // Normal case for sending/receiving file descriptors
        let hdr1 = VhostUserMsgHeader::new(MasterReq::SET_MEM_TABLE, 0, 0);
        master
            .send_header_only_message(&hdr1, Some(&[fd.as_raw_descriptor()]))
            .unwrap();

        let (hdr2, _, files) = slave.recv_message::<VhostUserEmptyMessage>().unwrap();
        assert_eq!(hdr1, hdr2);
        assert_eq!(files.len(), 1);
        let mut file = &files[0];
        let mut content = String::new();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "test");
    }

    #[test]
    fn test_advance_slices_mut() {
        // Test case from https://doc.rust-lang.org/std/io/struct.IoSliceMut.html#method.advance_slices
        let mut buf1 = [1; 8];
        let mut buf2 = [2; 16];
        let mut buf3 = [3; 8];
        let mut bufs = &mut [&mut buf1[..], &mut buf2[..], &mut buf3[..]][..];
        advance_slices_mut(&mut bufs, 10);
        assert_eq!(bufs[0], [2; 14].as_ref());
        assert_eq!(bufs[1], [3; 8].as_ref());
    }
}
