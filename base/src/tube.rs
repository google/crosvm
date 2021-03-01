// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::{self, IoSlice};
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::unix::prelude::{AsRawFd, RawFd};
use std::time::Duration;

use crate::{net::UnixSeqpacket, FromRawDescriptor, SafeDescriptor, ScmSocket, UnsyncMarker};

use cros_async::{Executor, IntoAsync, IoSourceExt};
use serde::{de::DeserializeOwned, Serialize};
use sys_util::{
    deserialize_with_descriptors, AsRawDescriptor, RawDescriptor, SerializeDescriptors,
};
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("failed to serialize/deserialize json from packet: {0}")]
    Json(serde_json::Error),
    #[error("failed to send packet: {0}")]
    Send(sys_util::Error),
    #[error("failed to receive packet: {0}")]
    Recv(io::Error),
    #[error("tube was disconnected")]
    Disconnected,
    #[error("failed to crate tube pair: {0}")]
    Pair(io::Error),
    #[error("failed to set send timeout: {0}")]
    SetSendTimeout(io::Error),
    #[error("failed to set recv timeout: {0}")]
    SetRecvTimeout(io::Error),
    #[error("failed to create async tube: {0}")]
    CreateAsync(cros_async::AsyncError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Bidirectional tube that support both send and recv.
pub struct Tube {
    socket: UnixSeqpacket,
    _unsync_marker: UnsyncMarker,
}

impl Tube {
    /// Create a pair of connected tubes. Request is send in one direction while response is in the
    /// other direction.
    pub fn pair() -> Result<(Tube, Tube)> {
        let (socket1, socket2) = UnixSeqpacket::pair().map_err(Error::Pair)?;
        let tube1 = Tube::new(socket1);
        let tube2 = Tube::new(socket2);
        Ok((tube1, tube2))
    }

    // Create a new `Tube`.
    pub fn new(socket: UnixSeqpacket) -> Tube {
        Tube {
            socket,
            _unsync_marker: PhantomData,
        }
    }

    pub fn into_async_tube(self, ex: &Executor) -> Result<AsyncTube> {
        let inner = ex.async_from(self).map_err(Error::CreateAsync)?;
        Ok(AsyncTube { inner })
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

    /// Returns true if there is a packet ready to `recv` without blocking.
    ///
    /// If there is an error trying to determine if there is a packet ready, this returns false.
    pub fn is_packet_ready(&self) -> bool {
        self.socket.get_readable_bytes().unwrap_or(0) > 0
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

impl IntoAsync for Tube {}

pub struct AsyncTube {
    inner: Box<dyn IoSourceExt<Tube>>,
}

impl AsyncTube {
    pub async fn next<T: DeserializeOwned>(&self) -> Result<T> {
        self.inner.wait_readable().await.unwrap();
        self.inner.as_source().recv()
    }
}

impl Deref for AsyncTube {
    type Target = Tube;

    fn deref(&self) -> &Self::Target {
        self.inner.as_source()
    }
}

impl Into<Tube> for AsyncTube {
    fn into(self) -> Tube {
        self.inner.into_source()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Event;

    use std::collections::HashMap;
    use std::time::Duration;

    use serde::{Deserialize, Serialize};

    #[track_caller]
    fn test_event_pair(send: Event, mut recv: Event) {
        send.write(1).unwrap();
        recv.read_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn send_recv_no_fd() {
        let (s1, s2) = Tube::pair().unwrap();

        let test_msg = "hello world";
        s1.send(&test_msg).unwrap();
        let recv_msg: String = s2.recv().unwrap();

        assert_eq!(test_msg, recv_msg);
    }

    #[test]
    fn send_recv_one_fd() {
        #[derive(Serialize, Deserialize)]
        struct EventStruct {
            x: u32,
            b: Event,
        }

        let (s1, s2) = Tube::pair().unwrap();

        let test_msg = EventStruct {
            x: 100,
            b: Event::new().unwrap(),
        };
        s1.send(&test_msg).unwrap();
        let recv_msg: EventStruct = s2.recv().unwrap();

        assert_eq!(test_msg.x, recv_msg.x);

        test_event_pair(test_msg.b, recv_msg.b);
    }

    #[test]
    fn send_recv_hash_map() {
        let (s1, s2) = Tube::pair().unwrap();

        let mut test_msg = HashMap::new();
        test_msg.insert("Red".to_owned(), Event::new().unwrap());
        test_msg.insert("White".to_owned(), Event::new().unwrap());
        test_msg.insert("Blue".to_owned(), Event::new().unwrap());
        test_msg.insert("Orange".to_owned(), Event::new().unwrap());
        test_msg.insert("Green".to_owned(), Event::new().unwrap());
        s1.send(&test_msg).unwrap();
        let mut recv_msg: HashMap<String, Event> = s2.recv().unwrap();

        let mut test_msg_keys: Vec<_> = test_msg.keys().collect();
        test_msg_keys.sort();
        let mut recv_msg_keys: Vec<_> = recv_msg.keys().collect();
        recv_msg_keys.sort();
        assert_eq!(test_msg_keys, recv_msg_keys);

        for (key, test_event) in test_msg {
            let recv_event = recv_msg.remove(&key).unwrap();
            test_event_pair(test_event, recv_event);
        }
    }
}
