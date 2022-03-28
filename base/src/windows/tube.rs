// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    io::{
        Cursor, Read, Write, {self},
    },
    time::Duration,
};

use crate::descriptor::{AsRawDescriptor, FromRawDescriptor, SafeDescriptor};
use crate::{
    platform::{deserialize_with_descriptors, RawDescriptor, SerializeDescriptors},
    tube::{Error, RecvTube, Result, SendTube},
    BlockingMode, CloseNotifier, FramingMode, PollToken, ReadNotifier, StreamChannel,
};
use data_model::DataInit;
use lazy_static::lazy_static;
use serde::{de::DeserializeOwned, Deserialize, Serialize, Serializer};
use std::{
    mem,
    os::windows::io::{AsRawHandle, RawHandle},
};
use winapi::shared::winerror::ERROR_MORE_DATA;

/// Bidirectional tube that support both send and recv.
///
/// NOTE: serializing this type across processes is slightly involved. Suppose there is a Tube pair
/// (A, B). We wish to send B to another process, and communicate with it using A from the current
/// process:
///     1. B's target_pid must be set to the current PID *before* serialization. There is a
///        serialization hook that sets it to the current PID automatically if target_pid is unset.
///     2. A's target_pid must be set to the PID of the process where B was sent.
///
/// If instead you are sending both A and B to separate processes, then:
///     1. A's target_pid must be set to B's pid, manually.
///     2. B's target_pid must be set to A's pid, manually.
///
/// Automating all of this and getting a completely clean interface is tricky. We would need
/// intercept the serialization of Tubes in any part of Serde messages, and use Weak refs to sync
/// state about PIDs between the ends. There are alternatives like reusing the underlying
/// StreamChannel to share PIDs, or having a separate pipe just for this purpose; however, we've yet
/// to find a compelling solution that isn't a mess to implement. Suggestions are welcome.
#[derive(Serialize, Deserialize, Debug)]
pub struct Tube {
    socket: StreamChannel,

    // Default target_pid to current PID on serialization (see `Tube` comment header for details).
    #[serde(serialize_with = "set_tube_pid_on_serialize")]
    target_pid: Option<u32>,
}

/// For a Tube which has not had its target_pid set, when it is serialized, we should automatically
/// default it to the current process, because the other end will be in the current process.
fn set_tube_pid_on_serialize<S>(
    existing_pid_value: &Option<u32>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match existing_pid_value {
        Some(pid) => serializer.serialize_u32(*pid),
        None => serializer.serialize_u32(ALIAS_PID.lock().unwrap_or(std::process::id())),
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct MsgHeader {
    msg_json_size: usize,
    descriptor_json_size: usize,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for MsgHeader {}

lazy_static! {
    static ref DH_TUBE: sync::Mutex<Option<DuplicateHandleTube>> = sync::Mutex::new(None);
    static ref ALIAS_PID: sync::Mutex<Option<u32>> = sync::Mutex::new(None);
}

/// Set a tube to delegate duplicate handle calls.
pub fn set_duplicate_handle_tube(dh_tube: DuplicateHandleTube) {
    DH_TUBE.lock().replace(dh_tube);
}

/// Set alias pid for use with a DuplicateHandleTube.
pub fn set_alias_pid(alias_pid: u32) {
    ALIAS_PID.lock().replace(alias_pid);
}

impl Tube {
    /// Create a pair of connected tubes. Request is sent in one direction while response is
    /// received in the other direction.
    /// The result is in the form (server, client).
    pub fn pair() -> Result<(Tube, Tube)> {
        let (socket1, socket2) = StreamChannel::pair(BlockingMode::Blocking, FramingMode::Message)
            .map_err(|e| Error::Pair(io::Error::from_raw_os_error(e.errno())))?;

        Ok((Tube::new(socket1), Tube::new(socket2)))
    }

    /// Create a pair of connected tubes with the specified buffer size.
    /// Request is sent in one direction while response is received in the other direction.
    /// The result is in the form (server, client).
    pub fn pair_with_buffer_size(buffer_size: usize) -> Result<(Tube, Tube)> {
        let (socket1, socket2) = StreamChannel::pair_with_buffer_size(
            BlockingMode::Blocking,
            FramingMode::Message,
            buffer_size,
        )
        .map_err(|e| Error::Pair(io::Error::from_raw_os_error(e.errno())))?;
        let tube1 = Tube::new(socket1);
        let tube2 = Tube::new(socket2);
        Ok((tube1, tube2))
    }

    // Create a new `Tube`.
    pub fn new(socket: StreamChannel) -> Tube {
        Tube {
            socket,
            target_pid: None,
        }
    }

    pub(super) fn try_clone(&self) -> Result<Self> {
        Ok(Tube {
            socket: self.socket.try_clone().map_err(Error::Clone)?,
            target_pid: self.target_pid,
        })
    }

    pub fn send<T: Serialize>(&self, msg: &T) -> Result<()> {
        serialize_and_send(|buf| self.socket.write_immutable(buf), msg, self.target_pid)
    }

    pub fn recv<T: DeserializeOwned>(&self) -> Result<T> {
        deserialize_and_recv(|buf| (&self.socket).read(buf))
    }

    /// NOTE: On Windows this will only succeed if called on a server pipe. See #pair
    /// documentation to ensure you have a server pipe before calling.
    #[cfg(windows)]
    pub fn flush_blocking(&mut self) -> Result<()> {
        self.socket.flush_blocking().map_err(Error::Flush)
    }

    /// For Tubes that span processes, this method must be used to set the PID of the other end
    /// of the Tube, otherwise sending handles to the other end won't work.
    pub fn set_target_pid(&mut self, target_pid: u32) {
        self.target_pid = Some(target_pid);
    }

    /// Returns the PID of the process at the other end of the Tube, if any is set.
    pub fn target_pid(&self) -> Option<u32> {
        self.target_pid
    }

    /// TODO(b/145998747, b/184398671): this method should be removed.
    pub fn set_send_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
        unimplemented!("To be removed/refactored upstream.");
    }

    /// TODO(b/145998747, b/184398671): this method should be removed.
    pub fn set_recv_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
        unimplemented!("To be removed/refactored upstream.");
    }
}

pub fn serialize_and_send<T: Serialize, F: Fn(&[u8]) -> io::Result<usize>>(
    write_fn: F,
    msg: &T,
    target_pid: Option<u32>,
) -> Result<()> {
    let msg_serialize = SerializeDescriptors::new(&msg);
    let msg_json = serde_json::to_vec(&msg_serialize).map_err(Error::Json)?;
    let msg_descriptors = msg_serialize.into_descriptors();

    let mut duped_descriptors = Vec::with_capacity(msg_descriptors.len());
    for desc in msg_descriptors {
        // Safe because these handles are guaranteed to be valid. Details:
        // 1. They come from sys_util::descriptor_reflection::with_as_descriptor.
        // 2. with_as_descriptor is intended to be applied to owned descriptor types (e.g. File,
        //    SafeDescriptor).
        // 3. The owning object is borrowed by msg until sending is complete.
        duped_descriptors.push(duplicate_handle(desc, target_pid)? as usize)
    }

    let descriptor_json = if duped_descriptors.is_empty() {
        None
    } else {
        Some(serde_json::to_vec(&duped_descriptors).map_err(Error::Json)?)
    };

    let header = MsgHeader {
        msg_json_size: msg_json.len(),
        descriptor_json_size: descriptor_json.as_ref().map_or(0, |json| json.len()),
    };

    let mut data_packet = Cursor::new(Vec::with_capacity(
        header.as_slice().len() + header.msg_json_size + header.descriptor_json_size,
    ));
    data_packet
        .write(header.as_slice())
        .map_err(Error::SendIoBuf)?;
    data_packet
        .write(msg_json.as_slice())
        .map_err(Error::SendIoBuf)?;
    if let Some(descriptor_json) = descriptor_json {
        data_packet
            .write(descriptor_json.as_slice())
            .map_err(Error::SendIoBuf)?;
    }

    // Multiple writers (producers) are safe because each write is atomic.
    let data_bytes = data_packet.into_inner();

    write_fn(&data_bytes).map_err(Error::SendIo)?;
    Ok(())
}

fn duplicate_handle(desc: RawHandle, target_pid: Option<u32>) -> Result<RawHandle> {
    match target_pid {
        Some(pid) => match &*DH_TUBE.lock() {
            Some(tube) => tube.request_duplicate_handle(pid, desc),
            None => {
                win_util::duplicate_handle_with_target_pid(desc, pid).map_err(Error::DupDescriptor)
            }
        },
        None => win_util::duplicate_handle(desc).map_err(Error::DupDescriptor),
    }
}

/// Reads a part of a Tube packet asserting that it was correctly read. This means:
/// * Treats partial "message" (transport framing) reads are Ok, as long as we filled our buffer.
///   We use this to ignore errors when reading the message header, which has the lengths we need
///   to allocate our buffers for the remainder of the message.
/// * We filled the supplied buffer.
fn perform_read<F: Fn(&mut [u8]) -> io::Result<usize>>(
    read_fn: &F,
    buf: &mut [u8],
) -> io::Result<usize> {
    let res = match read_fn(buf) {
        Ok(s) => Ok(s),
        Err(e)
            if e.raw_os_error()
                .map_or(false, |errno| errno == ERROR_MORE_DATA as i32) =>
        {
            Ok(buf.len())
        }
        Err(e) => Err(e),
    };

    let bytes_read = res?;
    if bytes_read != buf.len() {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
    } else {
        Ok(bytes_read)
    }
}

/// Deserializes a Tube packet by calling the supplied read function. This function MUST
/// assert that the buffer was filled.
pub fn deserialize_and_recv<T: DeserializeOwned, F: Fn(&mut [u8]) -> io::Result<usize>>(
    read_fn: F,
) -> Result<T> {
    let mut header_bytes = vec![0u8; mem::size_of::<MsgHeader>()];
    perform_read(&read_fn, header_bytes.as_mut_slice()).map_err(Error::Recv)?;

    // Safe because the header is always written by the send function, and only that function
    // writes to this channel.
    let header =
        MsgHeader::from_slice(header_bytes.as_slice()).expect("Tube header failed to deserialize.");

    let mut msg_json = vec![0u8; header.msg_json_size];
    perform_read(&read_fn, msg_json.as_mut_slice()).map_err(Error::Recv)?;

    if msg_json.is_empty() {
        // This means we got a message header, but there is no json body (due to a zero size in
        // the header). This should never happen because it means the receiver is getting no
        // data whatsoever from the sender.
        return Err(Error::RecvUnexpectedEmptyBody);
    }

    let msg_descriptors: Vec<RawDescriptor> = if header.descriptor_json_size > 0 {
        let mut msg_descriptors_json = vec![0u8; header.descriptor_json_size];
        perform_read(&read_fn, msg_descriptors_json.as_mut_slice()).map_err(Error::Recv)?;
        let descriptor_usizes: Vec<usize> =
            serde_json::from_slice(msg_descriptors_json.as_slice()).map_err(Error::Json)?;

        // Safe because the usizes are RawDescriptors that were converted to usize in the send
        // method.
        descriptor_usizes
            .iter()
            .map(|item| *item as RawDescriptor)
            .collect()
    } else {
        Vec::new()
    };

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

#[derive(PollToken, Eq, PartialEq, Copy, Clone)]
enum Token {
    SocketReady,
}

impl AsRawDescriptor for Tube {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.socket.as_raw_descriptor()
    }
}

impl AsRawHandle for Tube {
    fn as_raw_handle(&self) -> RawHandle {
        self.as_raw_descriptor()
    }
}

impl ReadNotifier for Tube {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self.socket.get_read_notifier()
    }
}

impl CloseNotifier for Tube {
    fn get_close_notifier(&self) -> &dyn AsRawDescriptor {
        self.socket.get_close_notifier()
    }
}

impl AsRawHandle for SendTube {
    fn as_raw_handle(&self) -> RawHandle {
        self.0.as_raw_descriptor()
    }
}

impl AsRawHandle for RecvTube {
    fn as_raw_handle(&self) -> RawHandle {
        self.0.as_raw_descriptor()
    }
}

/// A request to duplicate a handle to a target process.
#[derive(Serialize, Deserialize, Debug)]
pub struct DuplicateHandleRequest {
    pub target_alias_pid: u32,
    pub handle: usize,
}

/// Contains a duplicated handle or None if an error occurred.
#[derive(Serialize, Deserialize, Debug)]
pub struct DuplicateHandleResponse {
    pub handle: Option<usize>,
}

/// Wrapper for tube which is used to delegate DuplicateHandle function calls to
/// the broker process.
#[derive(Serialize, Deserialize, Debug)]
pub struct DuplicateHandleTube(Tube);

impl DuplicateHandleTube {
    pub fn new(tube: Tube) -> Self {
        Self(tube)
    }

    pub fn request_duplicate_handle(
        &self,
        target_alias_pid: u32,
        handle: RawHandle,
    ) -> Result<RawHandle> {
        let req = DuplicateHandleRequest {
            target_alias_pid,
            handle: handle as usize,
        };
        self.0.send(&req)?;
        let res: DuplicateHandleResponse = self.0.recv()?;
        res.handle
            .map(|h| h as RawHandle)
            .ok_or(Error::BrokerDupDescriptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventContext, EventTrigger, PollToken, ReadNotifier};
    use std::time;

    const EVENT_WAIT_TIME: time::Duration = time::Duration::from_secs(10);

    #[derive(PollToken, Debug, Eq, PartialEq, Copy, Clone)]
    enum Token {
        ReceivedData,
    }

    #[test]
    fn test_serialize_tube() {
        let (tube_1, tube_2) = Tube::pair().unwrap();
        let event_ctx: EventContext<Token> = EventContext::build_with(&[EventTrigger::from(
            tube_2.get_read_notifier(),
            Token::ReceivedData,
        )])
        .unwrap();

        // Serialize the Tube
        let msg_serialize = SerializeDescriptors::new(&tube_1);
        let serialized = serde_json::to_vec(&msg_serialize).unwrap();
        let msg_descriptors = msg_serialize.into_descriptors();

        // Deserialize the Tube
        let mut msg_descriptors_safe = msg_descriptors
            .into_iter()
            .map(|v| Some(unsafe { SafeDescriptor::from_raw_descriptor(v) }))
            .collect();
        let tube_deserialized: Tube = deserialize_with_descriptors(
            || serde_json::from_slice(&serialized),
            &mut msg_descriptors_safe,
        )
        .unwrap();

        // Send a message through deserialized Tube
        tube_deserialized.send(&"hi".to_string()).unwrap();

        assert_eq!(event_ctx.wait_timeout(EVENT_WAIT_TIME).unwrap().len(), 1);
        assert_eq!(tube_2.recv::<String>().unwrap(), "hi");
    }
}
