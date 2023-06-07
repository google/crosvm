// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::mem;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::RawHandle;
use std::time::Duration;

use data_model::DataInit;
use log::warn;
use once_cell::sync::Lazy;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use winapi::shared::winerror::ERROR_MORE_DATA;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::platform::deserialize_with_descriptors;
use crate::platform::RawDescriptor;
use crate::platform::SerializeDescriptors;
use crate::tube::Error;
use crate::tube::RecvTube;
use crate::tube::Result;
use crate::tube::SendTube;
use crate::BlockingMode;
use crate::CloseNotifier;
use crate::EventToken;
use crate::FramingMode;
use crate::PipeConnection;
use crate::ReadNotifier;
use crate::StreamChannel;

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

static DH_TUBE: Lazy<sync::Mutex<Option<DuplicateHandleTube>>> =
    Lazy::new(|| sync::Mutex::new(None));
static ALIAS_PID: Lazy<sync::Mutex<Option<u32>>> = Lazy::new(|| sync::Mutex::new(None));

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

    pub(crate) fn try_clone(&self) -> Result<Self> {
        Ok(Tube {
            socket: self.socket.try_clone().map_err(Error::Clone)?,
            target_pid: self.target_pid,
        })
    }

    fn send_proto<M: protobuf::Message>(&self, msg: &M) -> Result<()> {
        let bytes = msg.write_to_bytes().map_err(Error::Proto)?;
        let size_header = bytes.len();

        let mut data_packet =
            Cursor::new(Vec::with_capacity(mem::size_of::<usize>() + size_header));
        data_packet
            .write(&size_header.to_le_bytes())
            .map_err(Error::from_send_io_buf_error)?;
        data_packet.write(&bytes).map_err(Error::SendIoBuf)?;
        self.socket
            .write_immutable(&data_packet.into_inner())
            .map_err(Error::from_send_error)?;

        Ok(())
    }

    fn recv_proto<M: protobuf::Message>(&self) -> Result<M> {
        let mut header_bytes = [0u8; mem::size_of::<usize>()];
        perform_read(&mut |buf| (&self.socket).read(buf), &mut header_bytes)
            .map_err(Error::from_recv_io_error)?;
        let size_header = usize::from_le_bytes(header_bytes);

        let mut proto_bytes = vec![0u8; size_header];
        perform_read(&mut |buf| (&self.socket).read(buf), &mut proto_bytes)
            .map_err(Error::from_recv_io_error)?;
        protobuf::Message::parse_from_bytes(&proto_bytes).map_err(Error::Proto)
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
        // 1. They come from base::descriptor_reflection::with_as_descriptor.
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

    write_fn(&data_bytes).map_err(Error::from_send_error)?;
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
fn perform_read<F: FnMut(&mut [u8]) -> io::Result<usize>>(
    read_fn: &mut F,
    buf: &mut [u8],
) -> io::Result<usize> {
    let bytes_read = match read_fn(buf) {
        Ok(s) => Ok(s),
        Err(e)
            if e.raw_os_error()
                .map_or(false, |errno| errno == ERROR_MORE_DATA as i32) =>
        {
            Ok(buf.len())
        }
        Err(e) => Err(e),
    }?;

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
pub fn deserialize_and_recv<T: DeserializeOwned, F: FnMut(&mut [u8]) -> io::Result<usize>>(
    mut read_fn: F,
) -> Result<T> {
    let mut header_bytes = vec![0u8; mem::size_of::<MsgHeader>()];
    perform_read(&mut read_fn, header_bytes.as_mut_slice()).map_err(Error::from_recv_io_error)?;

    // Safe because the header is always written by the send function, and only that function
    // writes to this channel.
    let header =
        MsgHeader::from_slice(header_bytes.as_slice()).expect("Tube header failed to deserialize.");

    let mut msg_json = vec![0u8; header.msg_json_size];
    perform_read(&mut read_fn, msg_json.as_mut_slice()).map_err(Error::from_recv_io_error)?;

    if msg_json.is_empty() {
        // This means we got a message header, but there is no json body (due to a zero size in
        // the header). This should never happen because it means the receiver is getting no
        // data whatsoever from the sender.
        return Err(Error::RecvUnexpectedEmptyBody);
    }

    let msg_descriptors: Vec<RawDescriptor> = if header.descriptor_json_size > 0 {
        let mut msg_descriptors_json = vec![0u8; header.descriptor_json_size];
        perform_read(&mut read_fn, msg_descriptors_json.as_mut_slice())
            .map_err(Error::from_recv_io_error)?;
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

#[derive(EventToken, Eq, PartialEq, Copy, Clone)]
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

impl AsRawDescriptor for SendTube {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}

impl AsRawDescriptor for RecvTube {
    fn as_raw_descriptor(&self) -> RawDescriptor {
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

/// Wrapper for Tube used for sending and recving protos. The main usecase is to send a message
/// without serialization bloat caused from `serde-json`.
pub struct ProtoTube(Tube);

impl ProtoTube {
    pub fn pair_with_buffer_size(size: usize) -> Result<(ProtoTube, ProtoTube)> {
        Tube::pair_with_buffer_size(size).map(|(t1, t2)| (ProtoTube(t1), ProtoTube(t2)))
    }

    pub fn send_proto<M: protobuf::Message>(&self, msg: &M) -> Result<()> {
        self.0.send_proto(msg)
    }

    pub fn recv_proto<M: protobuf::Message>(&self) -> Result<M> {
        self.0.recv_proto()
    }
}

impl ReadNotifier for ProtoTube {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self.0.get_read_notifier()
    }
}

/// A wrapper around a named pipe that uses Tube serialization.
///
/// This limited form of `Tube` offers absolutely no notifier support, and can only send/recv
/// blocking messages.
pub struct PipeTube {
    pipe: PipeConnection,

    // Default target_pid to current PID on serialization (see `Tube` comment header for details).
    target_pid: Option<u32>,
}

impl PipeTube {
    pub fn from(pipe: PipeConnection, target_pid: Option<u32>) -> Self {
        Self { pipe, target_pid }
    }

    pub fn send<T: Serialize>(&self, msg: &T) -> Result<()> {
        serialize_and_send(|buf| self.pipe.write(buf), msg, self.target_pid)
    }

    pub fn recv<T: DeserializeOwned>(&self) -> Result<T> {
        deserialize_and_recv(|buf| {
            // SAFETY:
            // 1. We are reading bytes, so no matter what data is on the pipe, it is representable
            //    as bytes.
            // 2. A read is quantized in bytes, so no partial reads are possible.
            unsafe { self.pipe.read(buf) }
        })
    }
}

/// Wrapper around a Tube which is known to be the server end of a named pipe. This wrapper ensures
/// that the Tube is flushed before it is dropped.
pub struct FlushOnDropTube(pub Tube);

impl FlushOnDropTube {
    pub fn from(tube: Tube) -> Self {
        Self(tube)
    }
}

impl Drop for FlushOnDropTube {
    fn drop(&mut self) {
        if let Err(e) = self.0.flush_blocking() {
            warn!("failed to flush Tube: {}", e)
        }
    }
}

impl Error {
    fn map_io_error(e: io::Error, err_ctor: fn(io::Error) -> Error) -> Error {
        if e.kind() == io::ErrorKind::BrokenPipe {
            Error::Disconnected
        } else {
            err_ctor(e)
        }
    }

    fn from_recv_io_error(e: io::Error) -> Error {
        Self::map_io_error(e, Error::Recv)
    }

    fn from_send_error(e: io::Error) -> Error {
        Self::map_io_error(e, Error::Send)
    }

    fn from_send_io_buf_error(e: io::Error) -> Error {
        Self::map_io_error(e, Error::SendIoBuf)
    }
}
