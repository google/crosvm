// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    io::IoSlice,
    marker::PhantomData,
    os::unix::prelude::{AsRawFd, RawFd},
    time::Duration,
};

use crate::descriptor::{AsRawDescriptor, FromRawDescriptor, SafeDescriptor};
use crate::{
    platform::{deserialize_with_descriptors, SerializeDescriptors},
    tube::{Error, RecvTube, Result, SendTube},
    RawDescriptor, ReadNotifier, ScmSocket, UnixSeqpacket, UnsyncMarker,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Bidirectional tube that support both send and recv.
#[derive(Serialize, Deserialize)]
pub struct Tube {
    socket: UnixSeqpacket,

    // Windows is !Sync. We share that characteristic to prevent writing cross-platform incompatible
    // code.
    _unsync_marker: UnsyncMarker,
}

impl Tube {
    /// Create a pair of connected tubes. Request is sent in one direction while response is in the
    /// other direction.
    pub fn pair() -> Result<(Tube, Tube)> {
        let (socket1, socket2) = UnixSeqpacket::pair().map_err(Error::Pair)?;
        let tube1 = Tube::new(socket1);
        let tube2 = Tube::new(socket2);
        Ok((tube1, tube2))
    }

    /// Create a new `Tube`.
    pub fn new(socket: UnixSeqpacket) -> Tube {
        Tube {
            socket,
            _unsync_marker: PhantomData,
        }
    }

    /// DO NOT USE this method directly as it will become private soon (b/221484449). Use a
    /// directional Tube pair instead.
    #[deprecated]
    pub fn try_clone(&self) -> Result<Self> {
        self.socket.try_clone().map(Tube::new).map_err(Error::Clone)
    }

    pub fn send<T: Serialize>(&self, msg: &T) -> Result<()> {
        let msg_serialize = SerializeDescriptors::new(&msg);
        let msg_json = serde_json::to_vec(&msg_serialize).map_err(Error::Json)?;
        let msg_descriptors = msg_serialize.into_descriptors();

        self.socket
            .send_with_fds(&[IoSlice::new(&msg_json)], &msg_descriptors)
            .map_err(Error::Send)?;
        Ok(())
    }

    pub fn recv<T: DeserializeOwned>(&self) -> Result<T> {
        let (msg_json, msg_descriptors) =
            self.socket.recv_as_vec_with_fds().map_err(Error::Recv)?;

        if msg_json.is_empty() {
            return Err(Error::Disconnected);
        }

        let mut msg_descriptors_safe = msg_descriptors
            .into_iter()
            .map(|v| {
                Some(unsafe {
                    // Safe because the socket returns new fds that are owned locally by this scope.
                    SafeDescriptor::from_raw_descriptor(v)
                })
            })
            .collect();

        deserialize_with_descriptors(
            || serde_json::from_slice(&msg_json),
            &mut msg_descriptors_safe,
        )
        .map_err(Error::Json)
    }

    pub fn set_send_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.socket
            .set_write_timeout(timeout)
            .map_err(Error::SetSendTimeout)
    }

    pub fn set_recv_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.socket
            .set_read_timeout(timeout)
            .map_err(Error::SetRecvTimeout)
    }
}

impl AsRawDescriptor for Tube {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.socket.as_raw_descriptor()
    }
}

impl AsRawFd for Tube {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl ReadNotifier for Tube {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        &self.socket
    }
}

impl FromRawDescriptor for Tube {
    /// # Safety:
    /// Requirements:
    /// (1) The caller owns rd.
    /// (2) When the call completes, ownership of rd has transferred to the returned value.
    unsafe fn from_raw_descriptor(rd: RawDescriptor) -> Self {
        Self {
            socket: UnixSeqpacket::from_raw_descriptor(rd),
            _unsync_marker: PhantomData,
        }
    }
}

impl AsRawFd for SendTube {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_descriptor()
    }
}

impl AsRawFd for RecvTube {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_descriptor()
    }
}
