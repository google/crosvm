// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows specific code that keeps rest of the code in the crate platform independent.

use std::cmp::min;
use std::fs::File;
use std::io::IoSliceMut;
use std::ptr::copy_nonoverlapping;

use base::AsRawDescriptor;
use base::CloseNotifier;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::ReadNotifier;
use base::SafeDescriptor;
use base::Tube;
use serde::Deserialize;
use serde::Serialize;
use tube_transporter::packed_tube;
pub use TubePlatformConnection as PlatformConnection;

use crate::message::Req;
use crate::Connection;
use crate::Error;
use crate::Frontend;
use crate::FrontendServer;
use crate::Result;

#[derive(Serialize, Deserialize)]
struct RawDescriptorContainer {
    #[serde(with = "base::with_raw_descriptor")]
    rd: RawDescriptor,
}

#[derive(Serialize, Deserialize)]
struct Message {
    rds: Vec<RawDescriptorContainer>,
    data: Vec<u8>,
}

/// Tube based vhost-user connection.
pub struct TubePlatformConnection {
    tube: Tube,
}

impl TubePlatformConnection {
    pub(crate) fn get_tube(&self) -> &Tube {
        &self.tube
    }
}

impl From<Tube> for TubePlatformConnection {
    fn from(tube: Tube) -> Self {
        Self { tube }
    }
}

fn tube_err(e: base::TubeError) -> Error {
    match e {
        base::TubeError::Disconnected => Error::Disconnect,
        e => Error::TubeError(e),
    }
}

impl TubePlatformConnection {
    /// Sends a single message over the socket with optional attached file descriptors.
    ///
    /// - `hdr`: vhost message header
    /// - `body`: vhost message body (may be empty to send a header-only message)
    /// - `payload`: additional bytes to append to `body` (may be empty)
    pub fn send_message(
        &self,
        hdr: &[u8],
        body: &[u8],
        payload: &[u8],
        rds: Option<&[RawDescriptor]>,
    ) -> Result<()> {
        let hdr_msg = Message {
            rds: rds
                .unwrap_or(&[])
                .iter()
                .map(|rd| RawDescriptorContainer { rd: *rd })
                .collect(),
            data: hdr.to_vec(),
        };

        let mut body_data = Vec::with_capacity(body.len() + payload.len());
        body_data.extend_from_slice(body);
        body_data.extend_from_slice(payload);
        let body_msg = Message {
            rds: Vec::new(),
            data: body_data,
        };

        // We send the header and the body separately here. This is necessary on Windows. Otherwise
        // the recv side cannot read the header independently (the transport is message oriented).
        self.tube.send(&hdr_msg).map_err(tube_err)?;
        if !body_msg.data.is_empty() {
            self.tube.send(&body_msg).map_err(tube_err)?;
        }

        Ok(())
    }

    /// Reads bytes from the tube into the given scatter/gather vectors with optional attached
    /// file.
    ///
    /// The underlying communication channel is a Tube. Providing too little recv buffer space will
    /// cause data to get dropped (with an error). This is tricky to fix with Tube backing our
    /// transport layer, and as far as we can tell, is not exercised in practice.
    ///
    /// # Return:
    /// * - (number of bytes received, [received files]) on success
    /// * - RecvBufferTooSmall: Input bufs is too small for the received buffer.
    /// * - TubeError: tube related errors.
    pub fn recv_into_bufs(
        &self,
        bufs: &mut [IoSliceMut],
        _allow_rds: bool,
    ) -> Result<(usize, Option<Vec<File>>)> {
        // TODO(b/221882601): implement "allow_rds"

        let msg: Message = self.tube.recv().map_err(tube_err)?;

        let files = match msg.rds.len() {
            0 => None,
            _ => Some(
                msg.rds
                    .iter()
                    .map(|r|
                        // SAFETY:
                        // Safe because we own r.rd and it is guaranteed valid.
                        unsafe { File::from_raw_descriptor(r.rd) })
                    .collect::<Vec<File>>(),
            ),
        };

        let mut bytes_read = 0;
        for dest_iov in bufs.iter_mut() {
            if bytes_read >= msg.data.len() {
                // We've read all the available data into the iovecs.
                break;
            }

            let copy_count = min(dest_iov.len(), msg.data.len() - bytes_read);

            // SAFETY:
            // Safe because:
            //      1) msg.data and dest_iov do not overlap.
            //      2) copy_count is bounded by dest_iov's length and msg.data.len() so we can't
            //         overrun.
            unsafe {
                copy_nonoverlapping(
                    msg.data.as_ptr().add(bytes_read),
                    dest_iov.as_mut_ptr(),
                    copy_count,
                )
            };
            bytes_read += copy_count;
        }

        if bytes_read != msg.data.len() {
            // User didn't supply enough iov space.
            return Err(Error::RecvBufferTooSmall {
                got: bytes_read,
                want: msg.data.len(),
            });
        }

        Ok((bytes_read, files))
    }
}

impl<R: Req> TryFrom<SafeDescriptor> for Connection<R> {
    type Error = Error;

    fn try_from(fd: SafeDescriptor) -> Result<Self> {
        // SAFETY: Safe because the file represents a packed tube.
        let tube = unsafe { packed_tube::unpack(fd).expect("unpacked Tube") };
        Ok(tube.into())
    }
}

impl<R: Req> From<Tube> for Connection<R> {
    fn from(tube: Tube) -> Self {
        Self(
            PlatformConnection::from(tube),
            std::marker::PhantomData,
            std::marker::PhantomData,
        )
    }
}

impl<R: Req> Connection<R> {
    /// Create a pair of unnamed vhost-user connections connected to each other.
    pub fn pair() -> Result<(Self, Self)> {
        let (client, server) = Tube::pair().map_err(Error::TubeError)?;
        Ok((Self::from(client), Self::from(server)))
    }

    pub fn target_pid(&self) -> Option<u32> {
        self.0.tube.target_pid()
    }
}

impl AsRawDescriptor for TubePlatformConnection {
    /// WARNING: this function does not return a waitable descriptor! Use base::ReadNotifier
    /// instead.
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.tube.as_raw_descriptor()
    }
}

impl CloseNotifier for TubePlatformConnection {
    /// Used for closing.
    fn get_close_notifier(&self) -> &dyn AsRawDescriptor {
        self.tube.get_close_notifier()
    }
}

impl ReadNotifier for TubePlatformConnection {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self.tube.get_close_notifier()
    }
}

impl<S: Frontend> FrontendServer<S> {
    /// Create a `FrontendServer` that uses a Tube internally. Must specify the backend process
    /// which will receive the Tube.
    ///
    /// The returned `SafeDescriptor` is the client side of the tube and should be sent to the
    /// backend using [BackendClient::set_slave_request_fd()].
    ///
    /// [BackendClient::set_slave_request_fd()]: struct.BackendClient.html#method.set_slave_request_fd
    pub fn with_tube(backend: S, backend_pid: u32) -> Result<(Self, SafeDescriptor)> {
        let (tx, rx) = Tube::pair().map_err(Error::TubeError)?;
        let rx_connection = Connection::from(rx);
        // SAFETY:
        // Safe because we expect the tube to be unpacked in the other process.
        let tx = unsafe { packed_tube::pack(tx, backend_pid).expect("packed tube") };
        Ok((Self::new(backend, rx_connection)?, tx))
    }
}

impl<S: Frontend> ReadNotifier for FrontendServer<S> {
    /// Used for polling.
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self.sub_sock.0.get_tube().get_read_notifier()
    }
}

impl<S: Frontend> CloseNotifier for FrontendServer<S> {
    /// Used for closing.
    fn get_close_notifier(&self) -> &dyn AsRawDescriptor {
        self.sub_sock.0.get_tube().get_close_notifier()
    }
}
