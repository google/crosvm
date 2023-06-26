// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Common data structures for listener and endpoint.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod socket;
        #[cfg(feature = "vfio-device")]
        pub mod vfio;
        mod unix;
    } else if #[cfg(windows)] {
        mod tube;
        pub use tube::TubeEndpoint;
        mod windows;
    }
}

use std::fs::File;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::mem;
use std::path::Path;

use base::RawDescriptor;
use data_model::DataInit;

use crate::connection::Req;
use crate::message::*;
use crate::Error;
use crate::Result;

/// Listener for accepting connections.
pub trait Listener: Sized {
    /// Type of an object created when a connection is accepted.
    type Connection;
    /// Type of endpoint created when a connection is accepted.
    type Endpoint;

    /// Accept an incoming connection.
    fn accept(&mut self) -> Result<Option<Self::Endpoint>>;

    /// Change blocking status on the listener.
    fn set_nonblocking(&self, block: bool) -> Result<()>;
}

/// Abstracts a vhost-user connection and related operations.
pub trait Endpoint<R: Req>: Send {
    /// Create a new stream by connecting to server at `str`.
    fn connect<P: AsRef<Path>>(path: P) -> Result<Self>
    where
        Self: Sized;

    /// Sends bytes from scatter-gather vectors with optional attached file descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    fn send_iovec(&mut self, iovs: &[IoSlice], fds: Option<&[RawDescriptor]>) -> Result<usize>;

    /// Reads bytes into the given scatter/gather vectors with optional attached file.
    ///
    /// # Arguements
    /// * `bufs` - A slice of buffers to store received data.
    /// * `allow_fd` - Indicates whether we can receive FDs.
    ///
    /// # Return:
    /// * - (number of bytes received, [received files]) on success.
    /// * - `Error::Disconnect` if the client closed.
    fn recv_into_bufs(
        &mut self,
        bufs: &mut [IoSliceMut],
        allow_fd: bool,
    ) -> Result<(usize, Option<Vec<File>>)>;

    /// Constructs the slave request endpoint for self.
    ///
    /// # Arguments
    /// * `files` - Files from which to create the endpoint
    fn create_slave_request_endpoint(
        &mut self,
        files: Option<Vec<File>>,
    ) -> Result<Box<dyn Endpoint<SlaveReq>>>;
}

// Advance the internal cursor of the slices.
// This is same with a nightly API `IoSlice::advance_slices` but for `&[u8]`.
fn advance_slices(bufs: &mut &mut [&[u8]], mut count: usize) {
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
        bufs[0] = &bufs[0][count..];
    }
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

/// Abstracts VVU message parsing, sending and receiving.
pub trait EndpointExt<R: Req>: Endpoint<R> {
    /// Sends all bytes from scatter-gather vectors with optional attached file descriptors. Will
    /// loop until all data has been transfered.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    ///
    /// # TODO
    /// This function takes a slice of `&[u8]` instead of `IoSlice` because the internal
    /// cursor needs to be moved by `advance_slices()`.
    /// Once `IoSlice::advance_slices()` becomes stable, this should be updated.
    /// <https://github.com/rust-lang/rust/issues/62726>.
    fn send_iovec_all(
        &mut self,
        mut iovs: &mut [&[u8]],
        mut fds: Option<&[RawDescriptor]>,
    ) -> Result<usize> {
        // Guarantee that `iovs` becomes empty if it doesn't contain any data.
        advance_slices(&mut iovs, 0);

        let mut data_sent = 0;
        while !iovs.is_empty() {
            let iovec: Vec<_> = iovs.iter_mut().map(|i| IoSlice::new(i)).collect();
            match self.send_iovec(&iovec, fds) {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    data_sent += n;
                    fds = None;
                    advance_slices(&mut iovs, n);
                }
                Err(e) => match e {
                    Error::SocketRetry(_) => {}
                    _ => return Err(e),
                },
            }
        }
        Ok(data_sent)
    }

    /// Sends bytes from a slice with optional attached file descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    #[cfg(test)]
    fn send_slice(&mut self, data: IoSlice, fds: Option<&[RawDescriptor]>) -> Result<usize> {
        self.send_iovec(&[data], fds)
    }

    /// Sends a header-only message with optional attached file descriptors.
    ///
    /// # Return:
    /// * - number of bytes sent on success
    /// * - PartialMessage: received a partial message.
    /// * - backend specific errors
    fn send_header(
        &mut self,
        hdr: &VhostUserMsgHeader<R>,
        fds: Option<&[RawDescriptor]>,
    ) -> Result<()> {
        let mut iovs = [hdr.as_slice()];
        let bytes = self.send_iovec_all(&mut iovs[..], fds)?;
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
    /// * - OversizedMsg: message size is too big.
    /// * - PartialMessage: received a partial message.
    /// * - backend specific errors
    fn send_message<T: Sized + DataInit>(
        &mut self,
        hdr: &VhostUserMsgHeader<R>,
        body: &T,
        fds: Option<&[RawDescriptor]>,
    ) -> Result<()> {
        // We send the header and the body separately here. This is necessary on Windows. Otherwise
        // the recv side cannot read the header independently (the transport is message oriented).
        let mut bytes = self.send_iovec_all(&mut [hdr.as_slice()], fds)?;
        bytes += self.send_iovec_all(&mut [body.as_slice()], None)?;
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
    /// * - OversizedMsg: message size is too big.
    /// * - PartialMessage: received a partial message.
    /// * - IncorrectFds: wrong number of attached fds.
    /// * - backend specific errors
    fn send_message_with_payload<T: Sized + DataInit>(
        &mut self,
        hdr: &VhostUserMsgHeader<R>,
        body: &T,
        payload: &[u8],
        fds: Option<&[RawDescriptor]>,
    ) -> Result<()> {
        if let Some(fd_arr) = fds {
            if fd_arr.len() > MAX_ATTACHED_FD_ENTRIES {
                return Err(Error::IncorrectFds);
            }
        }

        let len = payload.len();
        let total = (mem::size_of::<VhostUserMsgHeader<R>>() + mem::size_of::<T>())
            .checked_add(len)
            .ok_or(Error::OversizedMsg)?;

        // We send the header and the body separately here. This is necessary on Windows. Otherwise
        // the recv side cannot read the header independently (the transport is message oriented).
        let mut len = self.send_iovec_all(&mut [hdr.as_slice()], fds)?;
        len += self.send_iovec_all(&mut [body.as_slice(), payload], None)?;

        if len != total {
            return Err(Error::PartialMessage);
        }
        Ok(())
    }

    /// Reads `len` bytes at most.
    ///
    /// # Return:
    /// * - (number of bytes received, buf) on success
    fn recv_data(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let (data_len, _) =
            self.recv_into_bufs(&mut [IoSliceMut::new(&mut buf)], false /* allow_fd */)?;
        buf.truncate(data_len);
        Ok(buf)
    }

    /// Reads all bytes into the given scatter/gather vectors with optional attached files. Will
    /// loop until all data has been transferred.
    ///
    /// # Return:
    /// * - (number of bytes received, [received fds]) on success
    /// * - `Disconnect` - client is closed
    ///
    /// # TODO
    /// This function takes a slice of `&mut [u8]` instead of `IoSliceMut` because the internal
    /// cursor needs to be moved by `advance_slices_mut()`.
    /// Once `IoSliceMut::advance_slices()` becomes stable, this should be updated.
    /// <https://github.com/rust-lang/rust/issues/62726>.
    fn recv_into_bufs_all(
        &mut self,
        mut bufs: &mut [&mut [u8]],
    ) -> Result<(usize, Option<Vec<File>>)> {
        let data_total: usize = bufs.iter().map(|b| b.len()).sum();
        let mut data_read = 0;
        let mut rfds = None;

        while (data_total - data_read) > 0 {
            let mut slices: Vec<IoSliceMut> = bufs.iter_mut().map(|b| IoSliceMut::new(b)).collect();
            let res = self.recv_into_bufs(&mut slices, true);
            match res {
                Ok((0, _)) => return Ok((data_read, rfds)),
                Ok((n, fds)) => {
                    if data_read == 0 {
                        rfds = fds;
                    }
                    data_read += n;
                    advance_slices_mut(&mut bufs, n);
                }
                Err(e) => match e {
                    Error::SocketRetry(_) => {}
                    _ => return Err(e),
                },
            }
        }
        Ok((data_read, rfds))
    }

    /// Reads bytes into a new buffer with optional attached files. Received file descriptors are
    /// set close-on-exec and converted to `File`.
    ///
    /// # Return:
    /// * - (number of bytes received, buf, [received files]) on success.
    /// * - backend specific errors
    #[cfg(test)]
    fn recv_into_buf(&mut self, buf_size: usize) -> Result<(usize, Vec<u8>, Option<Vec<File>>)> {
        let mut buf = vec![0u8; buf_size];
        let mut slices = [IoSliceMut::new(buf.as_mut_slice())];
        let (bytes, files) = self.recv_into_bufs(&mut slices, true /* allow_fd */)?;
        Ok((bytes, buf, files))
    }

    /// Receive a header-only message with optional attached files.
    /// Note, only the first MAX_ATTACHED_FD_ENTRIES file descriptors will be
    /// accepted and all other file descriptor will be discard silently.
    ///
    /// # Return:
    /// * - (message header, [received files]) on success.
    /// * - Disconnect: the client closed the connection.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    /// * - backend specific errors
    fn recv_header(&mut self) -> Result<(VhostUserMsgHeader<R>, Option<Vec<File>>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let (bytes, files) = self.recv_into_bufs(
            &mut [IoSliceMut::new(hdr.as_mut_slice())],
            true, /* allow_fd */
        )?;

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
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    /// * - backend specific errors
    fn recv_body<T: Sized + DataInit + Default + VhostUserMsgValidator>(
        &mut self,
    ) -> Result<(VhostUserMsgHeader<R>, T, Option<Vec<File>>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let mut body: T = Default::default();
        let mut slices = [hdr.as_mut_slice(), body.as_mut_slice()];
        let (bytes, files) = self.recv_into_bufs_all(&mut slices)?;

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
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    /// * - backend specific errors
    #[cfg(test)]
    fn recv_body_into_buf(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(VhostUserMsgHeader<R>, usize, Option<Vec<File>>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let mut slices = [hdr.as_mut_slice(), buf];
        let (bytes, files) = self.recv_into_bufs_all(&mut slices)?;

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
    /// * - (message header, message body, payload, [received files]) on success.
    /// * - PartialMessage: received a partial message.
    /// * - InvalidMessage: received a invalid message.
    /// * - backend specific errors
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::type_complexity))]
    fn recv_payload_into_buf<T: Sized + DataInit + Default + VhostUserMsgValidator>(
        &mut self,
    ) -> Result<(VhostUserMsgHeader<R>, T, Vec<u8>, Option<Vec<File>>)> {
        let mut hdr = VhostUserMsgHeader::default();
        let mut body: T = Default::default();
        let mut slices = [hdr.as_mut_slice()];
        let (bytes, files) = self.recv_into_bufs_all(&mut slices)?;

        if bytes < mem::size_of::<VhostUserMsgHeader<R>>() {
            return Err(Error::PartialMessage);
        } else if !hdr.is_valid() {
            return Err(Error::InvalidMessage);
        }

        let payload_size = hdr.get_size() as usize - mem::size_of::<T>();
        let mut buf: Vec<u8> = vec![0; payload_size];
        let mut slices = [body.as_mut_slice(), buf.as_mut_slice()];
        let (bytes, more_files) = self.recv_into_bufs_all(&mut slices)?;
        if bytes < hdr.get_size() as usize {
            return Err(Error::PartialMessage);
        } else if !body.is_valid() || more_files.is_some() {
            return Err(Error::InvalidMessage);
        }

        Ok((hdr, body, buf, files))
    }
}

impl<R: Req, E: Endpoint<R> + ?Sized> EndpointExt<R> for E {}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            #[cfg(feature = "vmm")]
            pub(crate) use super::unix::tests::*;
        } else if #[cfg(windows)] {
            #[cfg(feature = "vmm")]
            pub(crate) use windows::tests::*;
        }
    }

    #[test]
    fn test_advance_slices() {
        // Test case from https://doc.rust-lang.org/std/io/struct.IoSlice.html#method.advance_slices
        let buf1 = [1; 8];
        let buf2 = [2; 16];
        let buf3 = [3; 8];
        let mut bufs = &mut [&buf1[..], &buf2[..], &buf3[..]][..];
        advance_slices(&mut bufs, 10);
        assert_eq!(bufs[0], [2; 14].as_ref());
        assert_eq!(bufs[1], [3; 8].as_ref());
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
