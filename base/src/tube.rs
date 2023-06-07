// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

use remain::sorted;
use thiserror::Error as ThisError;

use std::time::Duration;

pub use crate::sys::tube::*;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;

impl Tube {
    /// Given a Tube end, creates two new ends, one each for sending and receiving.
    pub fn split_to_send_recv(self) -> Result<(SendTube, RecvTube)> {
        // Safe because receiving isn't allowd on this end.
        #[allow(deprecated)]
        let send_end = self.try_clone()?;

        Ok((SendTube(send_end), RecvTube(self)))
    }

    /// Creates a Send/Recv pair of Tubes.
    pub fn directional_pair() -> Result<(SendTube, RecvTube)> {
        let (t1, t2) = Self::pair()?;
        Ok((SendTube(t1), RecvTube(t2)))
    }

    pub fn try_clone_send_tube(&self) -> Result<SendTube> {
        // Safe because receiving is only allowed on original Tube.
        #[allow(deprecated)]
        let send_end = self.try_clone()?;
        Ok(SendTube(send_end))
    }
}

use crate::AsRawDescriptor;
use crate::ReadNotifier;

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
/// A Tube end which can only send messages. Cloneable.
pub struct SendTube(pub(crate) Tube);

#[allow(dead_code)]
impl SendTube {
    /// TODO(b/145998747, b/184398671): this method should be removed.
    pub fn set_send_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
        unimplemented!("To be removed/refactored upstream.");
    }

    pub fn send<T: Serialize>(&self, msg: &T) -> Result<()> {
        self.0.send(msg)
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(SendTube(
            #[allow(deprecated)]
            self.0.try_clone()?,
        ))
    }

    /// Never call this function, it is for use by cros_async to provide
    /// directional wrapper types only. Using it in any other context may
    /// violate concurrency assumptions. (Type splitting across crates has put
    /// us in a situation where we can't use Rust privacy to enforce this.)
    #[deprecated]
    pub fn into_tube(self) -> Tube {
        self.0
    }
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
/// A Tube end which can only recv messages.
pub struct RecvTube(pub(crate) Tube);

#[allow(dead_code)]
impl RecvTube {
    pub fn recv<T: DeserializeOwned>(&self) -> Result<T> {
        self.0.recv()
    }

    /// TODO(b/145998747, b/184398671): this method should be removed.
    pub fn set_recv_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
        unimplemented!("To be removed/refactored upstream.");
    }

    /// Never call this function, it is for use by cros_async to provide
    /// directional wrapper types only. Using it in any other context may
    /// violate concurrency assumptions. (Type splitting across crates has put
    /// us in a situation where we can't use Rust privacy to enforce this.)
    #[deprecated]
    pub fn into_tube(self) -> Tube {
        self.0
    }
}

impl ReadNotifier for RecvTube {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self.0.get_read_notifier()
    }
}

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    #[cfg(windows)]
    #[error("attempt to duplicate descriptor via broker failed")]
    BrokerDupDescriptor,
    #[error("failed to clone transport: {0}")]
    Clone(io::Error),
    #[error("tube was disconnected")]
    Disconnected,
    #[error("failed to duplicate descriptor: {0}")]
    DupDescriptor(io::Error),
    #[cfg(windows)]
    #[error("failed to flush named pipe: {0}")]
    Flush(io::Error),
    #[cfg(unix)]
    #[error("byte framing mode is not supported")]
    InvalidFramingMode,
    #[error("failed to serialize/deserialize json from packet: {0}")]
    Json(serde_json::Error),
    #[error("cancelled a queued async operation")]
    OperationCancelled,
    #[error("failed to crate tube pair: {0}")]
    Pair(io::Error),
    #[cfg(any(windows, feature = "proto_tube"))]
    #[error("encountered protobuf error: {0}")]
    Proto(protobuf::Error),
    #[error("failed to receive packet: {0}")]
    Recv(io::Error),
    #[error("Received a message with a zero sized body. This should not happen.")]
    RecvUnexpectedEmptyBody,
    #[error("failed to send packet: {0}")]
    Send(io::Error),
    #[error("failed to write packet to intermediate buffer: {0}")]
    SendIoBuf(io::Error),
    #[error("attempted to send too many file descriptors")]
    SendTooManyFds,
    #[error("failed to set recv timeout: {0}")]
    SetRecvTimeout(io::Error),
    #[error("failed to set send timeout: {0}")]
    SetSendTimeout(io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
