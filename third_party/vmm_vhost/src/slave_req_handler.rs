// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::mem;
use std::slice;
use std::sync::Mutex;

use base::AsRawDescriptor;
use base::RawDescriptor;
use data_model::DataInit;
use zerocopy::AsBytes;

use crate::connection::Endpoint;
use crate::connection::EndpointExt;
use crate::message::*;
use crate::take_single_file;
use crate::Error;
use crate::MasterReqEndpoint;
use crate::Result;
use crate::SystemStream;

#[derive(PartialEq, Eq, Debug)]
/// Vhost-user protocol variants used for the communication.
pub enum Protocol {
    /// Use the regular vhost-user protocol.
    Regular,
    /// Use the virtio-vhost-user protocol, which is proxied through virtqueues.
    /// The protocol is mostly same as the vhost-user protocol but no file transfer is allowed.
    Virtio,
}

impl Protocol {
    /// Returns whether the protocol assumes that messages are sent in stream mode like Unix's SOCK_STREAM.
    ///
    /// In stream mode, the receivers cannot know the size of the entire message in advance so a
    /// message header with the body size and the message body will be sent separately. See
    /// [`SlaveReqHandler::recv_header()`]'s doc comment for more details.
    fn is_stream_mode(&self) -> bool {
        match self {
            Protocol::Regular => true,
            // VVU proxy sends a message header and its payload at once.
            Protocol::Virtio => false,
        }
    }
}

/// Services provided to the master by the slave with interior mutability.
///
/// The [VhostUserSlaveReqHandler] trait defines the services provided to the master by the slave.
/// And the [VhostUserSlaveReqHandlerMut] trait is a helper mirroring [VhostUserSlaveReqHandler],
/// but without interior mutability.
/// The vhost-user specification defines a master communication channel, by which masters could
/// request services from slaves. The [VhostUserSlaveReqHandler] trait defines services provided by
/// slaves, and it's used both on the master side and slave side.
///
/// - on the master side, a stub forwarder implementing [VhostUserSlaveReqHandler] will proxy
///   service requests to slaves.
/// - on the slave side, the [SlaveReqHandler] will forward service requests to a handler
///   implementing [VhostUserSlaveReqHandler].
///
/// The [VhostUserSlaveReqHandler] trait is design with interior mutability to improve performance
/// for multi-threading.
///
/// [VhostUserSlaveReqHandler]: trait.VhostUserSlaveReqHandler.html
/// [VhostUserSlaveReqHandlerMut]: trait.VhostUserSlaveReqHandlerMut.html
/// [SlaveReqHandler]: struct.SlaveReqHandler.html
#[allow(missing_docs)]
pub trait VhostUserSlaveReqHandler {
    /// Returns the type of vhost-user protocol that the handler support.
    fn protocol(&self) -> Protocol;

    fn set_owner(&self) -> Result<()>;
    fn reset_owner(&self) -> Result<()>;
    fn get_features(&self) -> Result<u64>;
    fn set_features(&self, features: u64) -> Result<()>;
    fn set_mem_table(&self, ctx: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()>;
    fn set_vring_num(&self, index: u32, num: u32) -> Result<()>;
    fn set_vring_addr(
        &self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()>;
    fn set_vring_base(&self, index: u32, base: u32) -> Result<()>;
    fn get_vring_base(&self, index: u32) -> Result<VhostUserVringState>;
    fn set_vring_kick(&self, index: u8, fd: Option<File>) -> Result<()>;
    fn set_vring_call(&self, index: u8, fd: Option<File>) -> Result<()>;
    fn set_vring_err(&self, index: u8, fd: Option<File>) -> Result<()>;

    fn get_protocol_features(&self) -> Result<VhostUserProtocolFeatures>;
    fn set_protocol_features(&self, features: u64) -> Result<()>;
    fn get_queue_num(&self) -> Result<u64>;
    fn set_vring_enable(&self, index: u32, enable: bool) -> Result<()>;
    fn get_config(&self, offset: u32, size: u32, flags: VhostUserConfigFlags) -> Result<Vec<u8>>;
    fn set_config(&self, offset: u32, buf: &[u8], flags: VhostUserConfigFlags) -> Result<()>;
    fn set_slave_req_fd(&self, _vu_req: Box<dyn Endpoint<SlaveReq>>) {}
    fn get_inflight_fd(&self, inflight: &VhostUserInflight) -> Result<(VhostUserInflight, File)>;
    fn set_inflight_fd(&self, inflight: &VhostUserInflight, file: File) -> Result<()>;
    fn get_max_mem_slots(&self) -> Result<u64>;
    fn add_mem_region(&self, region: &VhostUserSingleMemoryRegion, fd: File) -> Result<()>;
    fn remove_mem_region(&self, region: &VhostUserSingleMemoryRegion) -> Result<()>;
    fn get_shared_memory_regions(&self) -> Result<Vec<VhostSharedMemoryRegion>>;
}

/// Services provided to the master by the slave without interior mutability.
///
/// This is a helper trait mirroring the [VhostUserSlaveReqHandler] trait.
#[allow(missing_docs)]
pub trait VhostUserSlaveReqHandlerMut {
    /// Returns the type of vhost-user protocol that the handler support.
    fn protocol(&self) -> Protocol;

    fn set_owner(&mut self) -> Result<()>;
    fn reset_owner(&mut self) -> Result<()>;
    fn get_features(&mut self) -> Result<u64>;
    fn set_features(&mut self, features: u64) -> Result<()>;
    fn set_mem_table(&mut self, ctx: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()>;
    fn set_vring_num(&mut self, index: u32, num: u32) -> Result<()>;
    fn set_vring_addr(
        &mut self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()>;
    fn set_vring_base(&mut self, index: u32, base: u32) -> Result<()>;
    fn get_vring_base(&mut self, index: u32) -> Result<VhostUserVringState>;
    fn set_vring_kick(&mut self, index: u8, fd: Option<File>) -> Result<()>;
    fn set_vring_call(&mut self, index: u8, fd: Option<File>) -> Result<()>;
    fn set_vring_err(&mut self, index: u8, fd: Option<File>) -> Result<()>;

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures>;
    fn set_protocol_features(&mut self, features: u64) -> Result<()>;
    fn get_queue_num(&mut self) -> Result<u64>;
    fn set_vring_enable(&mut self, index: u32, enable: bool) -> Result<()>;
    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
    ) -> Result<Vec<u8>>;
    fn set_config(&mut self, offset: u32, buf: &[u8], flags: VhostUserConfigFlags) -> Result<()>;
    fn set_slave_req_fd(&mut self, _vu_req: Box<dyn Endpoint<SlaveReq>>) {}
    fn get_inflight_fd(
        &mut self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)>;
    fn set_inflight_fd(&mut self, inflight: &VhostUserInflight, file: File) -> Result<()>;
    fn get_max_mem_slots(&mut self) -> Result<u64>;
    fn add_mem_region(&mut self, region: &VhostUserSingleMemoryRegion, fd: File) -> Result<()>;
    fn remove_mem_region(&mut self, region: &VhostUserSingleMemoryRegion) -> Result<()>;
    fn get_shared_memory_regions(&mut self) -> Result<Vec<VhostSharedMemoryRegion>>;
}

impl<T: VhostUserSlaveReqHandlerMut> VhostUserSlaveReqHandler for Mutex<T> {
    fn protocol(&self) -> Protocol {
        self.lock().unwrap().protocol()
    }

    fn set_owner(&self) -> Result<()> {
        self.lock().unwrap().set_owner()
    }

    fn reset_owner(&self) -> Result<()> {
        self.lock().unwrap().reset_owner()
    }

    fn get_features(&self) -> Result<u64> {
        self.lock().unwrap().get_features()
    }

    fn set_features(&self, features: u64) -> Result<()> {
        self.lock().unwrap().set_features(features)
    }

    fn set_mem_table(&self, ctx: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()> {
        self.lock().unwrap().set_mem_table(ctx, files)
    }

    fn set_vring_num(&self, index: u32, num: u32) -> Result<()> {
        self.lock().unwrap().set_vring_num(index, num)
    }

    fn set_vring_addr(
        &self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()> {
        self.lock()
            .unwrap()
            .set_vring_addr(index, flags, descriptor, used, available, log)
    }

    fn set_vring_base(&self, index: u32, base: u32) -> Result<()> {
        self.lock().unwrap().set_vring_base(index, base)
    }

    fn get_vring_base(&self, index: u32) -> Result<VhostUserVringState> {
        self.lock().unwrap().get_vring_base(index)
    }

    fn set_vring_kick(&self, index: u8, fd: Option<File>) -> Result<()> {
        self.lock().unwrap().set_vring_kick(index, fd)
    }

    fn set_vring_call(&self, index: u8, fd: Option<File>) -> Result<()> {
        self.lock().unwrap().set_vring_call(index, fd)
    }

    fn set_vring_err(&self, index: u8, fd: Option<File>) -> Result<()> {
        self.lock().unwrap().set_vring_err(index, fd)
    }

    fn get_protocol_features(&self) -> Result<VhostUserProtocolFeatures> {
        self.lock().unwrap().get_protocol_features()
    }

    fn set_protocol_features(&self, features: u64) -> Result<()> {
        self.lock().unwrap().set_protocol_features(features)
    }

    fn get_queue_num(&self) -> Result<u64> {
        self.lock().unwrap().get_queue_num()
    }

    fn set_vring_enable(&self, index: u32, enable: bool) -> Result<()> {
        self.lock().unwrap().set_vring_enable(index, enable)
    }

    fn get_config(&self, offset: u32, size: u32, flags: VhostUserConfigFlags) -> Result<Vec<u8>> {
        self.lock().unwrap().get_config(offset, size, flags)
    }

    fn set_config(&self, offset: u32, buf: &[u8], flags: VhostUserConfigFlags) -> Result<()> {
        self.lock().unwrap().set_config(offset, buf, flags)
    }

    fn set_slave_req_fd(&self, vu_req: Box<dyn Endpoint<SlaveReq>>) {
        self.lock().unwrap().set_slave_req_fd(vu_req)
    }

    fn get_inflight_fd(&self, inflight: &VhostUserInflight) -> Result<(VhostUserInflight, File)> {
        self.lock().unwrap().get_inflight_fd(inflight)
    }

    fn set_inflight_fd(&self, inflight: &VhostUserInflight, file: File) -> Result<()> {
        self.lock().unwrap().set_inflight_fd(inflight, file)
    }

    fn get_max_mem_slots(&self) -> Result<u64> {
        self.lock().unwrap().get_max_mem_slots()
    }

    fn add_mem_region(&self, region: &VhostUserSingleMemoryRegion, fd: File) -> Result<()> {
        self.lock().unwrap().add_mem_region(region, fd)
    }

    fn remove_mem_region(&self, region: &VhostUserSingleMemoryRegion) -> Result<()> {
        self.lock().unwrap().remove_mem_region(region)
    }

    fn get_shared_memory_regions(&self) -> Result<Vec<VhostSharedMemoryRegion>> {
        self.lock().unwrap().get_shared_memory_regions()
    }
}

/// Abstracts |Endpoint| related operations for vhost-user slave implementations.
pub struct SlaveReqHelper<E: Endpoint<MasterReq>> {
    /// Underlying endpoint for communication.
    endpoint: E,

    /// Protocol used for the communication.
    protocol: Protocol,

    /// Sending ack for messages without payload.
    reply_ack_enabled: bool,
}

impl<E: Endpoint<MasterReq>> SlaveReqHelper<E> {
    /// Creates a new |SlaveReqHelper| instance with an |Endpoint| underneath it.
    pub fn new(endpoint: E, protocol: Protocol) -> Self {
        SlaveReqHelper {
            endpoint,
            protocol,
            reply_ack_enabled: false,
        }
    }

    fn new_reply_header<T: Sized>(
        &self,
        req: &VhostUserMsgHeader<MasterReq>,
        payload_size: usize,
    ) -> Result<VhostUserMsgHeader<MasterReq>> {
        if mem::size_of::<T>() > MAX_MSG_SIZE
            || payload_size > MAX_MSG_SIZE
            || mem::size_of::<T>() + payload_size > MAX_MSG_SIZE
        {
            return Err(Error::InvalidParam);
        }

        Ok(VhostUserMsgHeader::new(
            req.get_code(),
            VhostUserHeaderFlag::REPLY.bits(),
            (mem::size_of::<T>() + payload_size) as u32,
        ))
    }

    /// Sends reply back to Vhost Master in response to a message.
    pub fn send_ack_message(
        &mut self,
        req: &VhostUserMsgHeader<MasterReq>,
        success: bool,
    ) -> Result<()> {
        if self.reply_ack_enabled && req.is_need_reply() {
            let hdr = self.new_reply_header::<VhostUserU64>(req, 0)?;
            let val = if success { 0 } else { 1 };
            let msg = VhostUserU64::new(val);
            self.endpoint.send_message(&hdr, &msg, None)?;
        }
        Ok(())
    }

    fn send_reply_message<T: Sized + DataInit>(
        &mut self,
        req: &VhostUserMsgHeader<MasterReq>,
        msg: &T,
    ) -> Result<()> {
        let hdr = self.new_reply_header::<T>(req, 0)?;
        self.endpoint.send_message(&hdr, msg, None)?;
        Ok(())
    }

    fn send_reply_with_payload<T: Sized + DataInit>(
        &mut self,
        req: &VhostUserMsgHeader<MasterReq>,
        msg: &T,
        payload: &[u8],
    ) -> Result<()> {
        let hdr = self.new_reply_header::<T>(req, payload.len())?;
        self.endpoint
            .send_message_with_payload(&hdr, msg, payload, None)?;
        Ok(())
    }

    /// Parses an incoming |SET_VRING_KICK| or |SET_VRING_CALL| message into a
    /// Vring number and an fd.
    pub fn handle_vring_fd_request(
        &mut self,
        buf: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<(u8, Option<File>)> {
        if buf.len() > MAX_MSG_SIZE || buf.len() < mem::size_of::<VhostUserU64>() {
            return Err(Error::InvalidMessage);
        }
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const VhostUserU64) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }

        // Virtio-vhost-user protocol doesn't send FDs.
        if self.protocol == Protocol::Virtio {
            return Ok((msg.value as u8, None));
        }

        // Bits (0-7) of the payload contain the vring index. Bit 8 is the
        // invalid FD flag (VHOST_USER_VRING_NOFD_MASK).
        // This bit is set when there is no file descriptor
        // in the ancillary data. This signals that polling will be used
        // instead of waiting for the call.
        // If Bit 8 is unset, the data must contain a file descriptor.
        let has_fd = (msg.value & 0x100u64) == 0;

        let file = take_single_file(files);

        if has_fd && file.is_none() || !has_fd && file.is_some() {
            return Err(Error::InvalidMessage);
        }

        Ok((msg.value as u8, file))
    }
}

impl<E: Endpoint<MasterReq>> AsRef<E> for SlaveReqHelper<E> {
    fn as_ref(&self) -> &E {
        &self.endpoint
    }
}

impl<E: Endpoint<MasterReq>> AsMut<E> for SlaveReqHelper<E> {
    fn as_mut(&mut self) -> &mut E {
        &mut self.endpoint
    }
}

impl<E: Endpoint<MasterReq> + AsRawDescriptor> AsRawDescriptor for SlaveReqHelper<E> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.endpoint.as_raw_descriptor()
    }
}

/// Server to handle service requests from masters from the master communication channel.
///
/// The [SlaveReqHandler] acts as a server on the slave side, to handle service requests from
/// masters on the master communication channel. It's actually a proxy invoking the registered
/// handler implementing [VhostUserSlaveReqHandler] to do the real work.
///
/// The lifetime of the SlaveReqHandler object should be the same as the underline Unix Domain
/// Socket, so it gets simpler to recover from disconnect.
///
/// [VhostUserSlaveReqHandler]: trait.VhostUserSlaveReqHandler.html
/// [SlaveReqHandler]: struct.SlaveReqHandler.html
pub struct SlaveReqHandler<S: VhostUserSlaveReqHandler, E: Endpoint<MasterReq>> {
    slave_req_helper: SlaveReqHelper<E>,
    // the vhost-user backend device object
    backend: S,

    virtio_features: u64,
    acked_virtio_features: u64,
    protocol_features: VhostUserProtocolFeatures,
    acked_protocol_features: u64,
}

impl<S: VhostUserSlaveReqHandler> SlaveReqHandler<S, MasterReqEndpoint> {
    /// Create a vhost-user slave endpoint from a connected socket.
    pub fn from_stream(socket: SystemStream, backend: S) -> Self {
        Self::new(MasterReqEndpoint::from(socket), backend)
    }
}

impl<S: VhostUserSlaveReqHandler, E: Endpoint<MasterReq>> AsRef<S> for SlaveReqHandler<S, E> {
    fn as_ref(&self) -> &S {
        &self.backend
    }
}

impl<S: VhostUserSlaveReqHandler, E: Endpoint<MasterReq>> SlaveReqHandler<S, E> {
    /// Create a vhost-user slave endpoint.
    pub fn new(endpoint: E, backend: S) -> Self {
        SlaveReqHandler {
            slave_req_helper: SlaveReqHelper::new(endpoint, backend.protocol()),
            backend,
            virtio_features: 0,
            acked_virtio_features: 0,
            protocol_features: VhostUserProtocolFeatures::empty(),
            acked_protocol_features: 0,
        }
    }

    /// Receives and validates a vhost-user message header and optional files.
    ///
    /// Since the length of vhost-user messages are different among message types, regular
    /// vhost-user messages are sent via an underlying communication channel in stream mode.
    /// (e.g. `SOCK_STREAM` in UNIX)
    /// So, the logic of receiving and handling a message consists of the following steps:
    ///
    /// 1. Receives a message header and optional attached file.
    /// 2. Validates the message header.
    /// 3. Check if optional payloads is expected.
    /// 4. Wait for the optional payloads.
    /// 5. Receives optional payloads.
    /// 6. Processes the message.
    ///
    /// This method [`SlaveReqHandler::recv_header()`] is in charge of the step (1) and (2),
    /// [`SlaveReqHandler::needs_wait_for_payload()`] is (3), and
    /// [`SlaveReqHandler::process_message()`] is (5) and (6).
    /// We need to have the three method separately for multi-platform supports;
    /// [`SlaveReqHandler::recv_header()`] and [`SlaveReqHandler::process_message()`] need to be
    /// separated because the way of waiting for incoming messages differs between Unix and Windows
    /// so it's the caller's responsibility to wait before [`SlaveReqHandler::process_message()`].
    ///
    /// Note that some vhost-user protocol variant such as VVU doesn't assume stream mode. In this
    /// case, a message header and its body are sent together so the step (4) is skipped. We handle
    /// this case in [`SlaveReqHandler::needs_wait_for_payload()`].
    ///
    /// The following pseudo code describes how a caller should process incoming vhost-user
    /// messages:
    /// ```ignore
    /// loop {
    ///   // block until a message header comes.
    ///   // The actual code differs, depending on platforms.
    ///   connection.wait_readable().unwrap();
    ///
    ///   // (1) and (2)
    ///   let (hdr, files) = slave_req_handler.recv_header();
    ///
    ///   // (3)
    ///   if slave_req_handler.needs_wait_for_payload(&hdr) {
    ///     // (4) block until a payload comes if needed.
    ///     connection.wait_readable().unwrap();
    ///   }
    ///
    ///   // (5) and (6)
    ///   slave_req_handler.process_message(&hdr, &files).unwrap();
    /// }
    /// ```
    pub fn recv_header(&mut self) -> Result<(VhostUserMsgHeader<MasterReq>, Option<Vec<File>>)> {
        // The underlying communication channel is a Unix domain socket in
        // stream mode, and recvmsg() is a little tricky here. To successfully
        // receive attached file descriptors, we need to receive messages and
        // corresponding attached file descriptors in this way:
        // . recv messsage header and optional attached file
        // . validate message header
        // . recv optional message body and payload according size field in
        //   message header
        // . validate message body and optional payload
        let (hdr, files) = match self.slave_req_helper.endpoint.recv_header() {
            Ok((hdr, files)) => (hdr, files),
            Err(Error::Disconnect) => {
                // If the client closed the connection before sending a header, this should be
                // handled as a legal exit.
                return Err(Error::ClientExit);
            }
            Err(e) => {
                return Err(e);
            }
        };

        self.check_attached_files(&hdr, &files)?;

        Ok((hdr, files))
    }

    /// Returns whether the caller needs to wait for the incoming message before calling
    /// [`SlaveReqHandler::process_message`].
    ///
    /// See [`SlaveReqHandler::recv_header`]'s doc comment for the usage.
    pub fn needs_wait_for_payload(&self, hdr: &VhostUserMsgHeader<MasterReq>) -> bool {
        // For the vhost-user protocols using stream mode, we need to wait until an additional
        // payload is available if exists.
        self.backend.protocol().is_stream_mode() && hdr.get_size() != 0
    }

    /// Main entrance to request from the communication channel.
    ///
    /// Receive and handle one incoming request message from the vmm.
    /// See [`SlaveReqHandler::recv_header`]'s doc comment for the usage.
    ///
    /// # Return:
    /// * - `Ok(())`: one request was successfully handled.
    /// * - `Err(ClientExit)`: the vmm closed the connection properly. This isn't an actual failure.
    /// * - `Err(Disconnect)`: the connection was closed unexpectedly.
    /// * - `Err(InvalidMessage)`: the vmm sent a illegal message.
    /// * - other errors: failed to handle a request.
    pub fn process_message(
        &mut self,
        hdr: VhostUserMsgHeader<MasterReq>,
        files: Option<Vec<File>>,
    ) -> Result<()> {
        let buf = match hdr.get_size() {
            0 => vec![0u8; 0],
            len => {
                let rbuf = self.slave_req_helper.endpoint.recv_data(len as usize)?;
                if rbuf.len() != len as usize {
                    return Err(Error::InvalidMessage);
                }
                rbuf
            }
        };
        let size = buf.len();

        match hdr.get_code() {
            MasterReq::SET_OWNER => {
                self.check_request_size(&hdr, size, 0)?;
                let res = self.backend.set_owner();
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::RESET_OWNER => {
                self.check_request_size(&hdr, size, 0)?;
                let res = self.backend.reset_owner();
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::GET_FEATURES => {
                self.check_request_size(&hdr, size, 0)?;
                let features = self.backend.get_features()?;
                let msg = VhostUserU64::new(features);
                self.slave_req_helper.send_reply_message(&hdr, &msg)?;
                self.virtio_features = features;
                self.update_reply_ack_flag();
            }
            MasterReq::SET_FEATURES => {
                let msg = self.extract_request_body::<VhostUserU64>(&hdr, size, &buf)?;
                let res = self.backend.set_features(msg.value);
                self.acked_virtio_features = msg.value;
                self.update_reply_ack_flag();
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::SET_MEM_TABLE => {
                let res = self.set_mem_table(&hdr, size, &buf, files);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::SET_VRING_NUM => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let res = self.backend.set_vring_num(msg.index, msg.num);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::SET_VRING_ADDR => {
                let msg = self.extract_request_body::<VhostUserVringAddr>(&hdr, size, &buf)?;
                let flags = match VhostUserVringAddrFlags::from_bits(msg.flags) {
                    Some(val) => val,
                    None => return Err(Error::InvalidMessage),
                };
                let res = self.backend.set_vring_addr(
                    msg.index,
                    flags,
                    msg.descriptor,
                    msg.used,
                    msg.available,
                    msg.log,
                );
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::SET_VRING_BASE => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let res = self.backend.set_vring_base(msg.index, msg.num);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::GET_VRING_BASE => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let reply = self.backend.get_vring_base(msg.index)?;
                self.slave_req_helper.send_reply_message(&hdr, &reply)?;
            }
            MasterReq::SET_VRING_CALL => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_call(index, file);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::SET_VRING_KICK => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_kick(index, file);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::SET_VRING_ERR => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_err(index, file);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::GET_PROTOCOL_FEATURES => {
                self.check_request_size(&hdr, size, 0)?;
                let features = self.backend.get_protocol_features()?;
                let msg = VhostUserU64::new(features.bits());
                self.slave_req_helper.send_reply_message(&hdr, &msg)?;
                self.protocol_features = features;
                self.update_reply_ack_flag();
            }
            MasterReq::SET_PROTOCOL_FEATURES => {
                let msg = self.extract_request_body::<VhostUserU64>(&hdr, size, &buf)?;
                let res = self.backend.set_protocol_features(msg.value);
                self.acked_protocol_features = msg.value;
                self.update_reply_ack_flag();
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::GET_QUEUE_NUM => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, 0)?;
                let num = self.backend.get_queue_num()?;
                let msg = VhostUserU64::new(num);
                self.slave_req_helper.send_reply_message(&hdr, &msg)?;
            }
            MasterReq::SET_VRING_ENABLE => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                if self.acked_virtio_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                let enable = match msg.num {
                    1 => true,
                    0 => false,
                    _ => return Err(Error::InvalidParam),
                };

                let res = self.backend.set_vring_enable(msg.index, enable);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::GET_CONFIG => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                self.get_config(&hdr, &buf)?;
            }
            MasterReq::SET_CONFIG => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                let res = self.set_config(size, &buf);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::SET_SLAVE_REQ_FD => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::SLAVE_REQ.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                let res = self.set_slave_req_fd(files);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::GET_INFLIGHT_FD => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }

                let msg = self.extract_request_body::<VhostUserInflight>(&hdr, size, &buf)?;
                let (inflight, file) = self.backend.get_inflight_fd(&msg)?;
                let reply_hdr = self
                    .slave_req_helper
                    .new_reply_header::<VhostUserInflight>(&hdr, 0)?;
                self.slave_req_helper.endpoint.send_message(
                    &reply_hdr,
                    &inflight,
                    Some(&[file.as_raw_descriptor()]),
                )?;
            }
            MasterReq::SET_INFLIGHT_FD => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                let file = take_single_file(files).ok_or(Error::IncorrectFds)?;
                let msg = self.extract_request_body::<VhostUserInflight>(&hdr, size, &buf)?;
                let res = self.backend.set_inflight_fd(&msg, file);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::GET_MAX_MEM_SLOTS => {
                if self.acked_protocol_features
                    & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, 0)?;
                let num = self.backend.get_max_mem_slots()?;
                let msg = VhostUserU64::new(num);
                self.slave_req_helper.send_reply_message(&hdr, &msg)?;
            }
            MasterReq::ADD_MEM_REG => {
                if self.acked_protocol_features
                    & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                let mut files = files.ok_or(Error::InvalidParam)?;
                if files.len() != 1 {
                    return Err(Error::InvalidParam);
                }
                let msg =
                    self.extract_request_body::<VhostUserSingleMemoryRegion>(&hdr, size, &buf)?;
                let res = self.backend.add_mem_region(&msg, files.swap_remove(0));
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::REM_MEM_REG => {
                if self.acked_protocol_features
                    & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }

                let msg =
                    self.extract_request_body::<VhostUserSingleMemoryRegion>(&hdr, size, &buf)?;
                let res = self.backend.remove_mem_region(&msg);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            MasterReq::GET_SHARED_MEMORY_REGIONS => {
                let regions = self.backend.get_shared_memory_regions()?;
                let mut buf = Vec::new();
                let msg = VhostUserU64::new(regions.len() as u64);
                for r in regions {
                    buf.extend_from_slice(r.as_bytes())
                }
                self.slave_req_helper
                    .send_reply_with_payload(&hdr, &msg, buf.as_slice())?;
            }
            _ => {
                return Err(Error::InvalidMessage);
            }
        }
        Ok(())
    }

    fn set_mem_table(
        &mut self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        size: usize,
        buf: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<()> {
        self.check_request_size(hdr, size, hdr.get_size() as usize)?;

        // check message size is consistent
        let hdrsize = mem::size_of::<VhostUserMemory>();
        if size < hdrsize {
            return Err(Error::InvalidMessage);
        }
        let msg = unsafe { &*(buf.as_ptr() as *const VhostUserMemory) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if size != hdrsize + msg.num_regions as usize * mem::size_of::<VhostUserMemoryRegion>() {
            return Err(Error::InvalidMessage);
        }

        let files = match self.slave_req_helper.protocol {
            Protocol::Regular => {
                // validate number of fds matching number of memory regions
                let files = files.ok_or(Error::InvalidMessage)?;
                if files.len() != msg.num_regions as usize {
                    return Err(Error::InvalidMessage);
                }
                files
            }
            Protocol::Virtio => vec![],
        };

        // Validate memory regions
        let regions = unsafe {
            slice::from_raw_parts(
                buf.as_ptr().add(hdrsize) as *const VhostUserMemoryRegion,
                msg.num_regions as usize,
            )
        };
        for region in regions.iter() {
            if !region.is_valid() {
                return Err(Error::InvalidMessage);
            }
        }

        self.backend.set_mem_table(regions, files)
    }

    fn get_config(&mut self, hdr: &VhostUserMsgHeader<MasterReq>, buf: &[u8]) -> Result<()> {
        let payload_offset = mem::size_of::<VhostUserConfig>();
        if buf.len() > MAX_MSG_SIZE || buf.len() < payload_offset {
            return Err(Error::InvalidMessage);
        }
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const VhostUserConfig) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if buf.len() - payload_offset != msg.size as usize {
            return Err(Error::InvalidMessage);
        }
        let flags = match VhostUserConfigFlags::from_bits(msg.flags) {
            Some(val) => val,
            None => return Err(Error::InvalidMessage),
        };
        let res = self.backend.get_config(msg.offset, msg.size, flags);

        // vhost-user slave's payload size MUST match master's request
        // on success, uses zero length of payload to indicate an error
        // to vhost-user master.
        match res {
            Ok(ref buf) if buf.len() == msg.size as usize => {
                let reply = VhostUserConfig::new(msg.offset, buf.len() as u32, flags);
                self.slave_req_helper
                    .send_reply_with_payload(hdr, &reply, buf.as_slice())?;
            }
            Ok(_) => {
                let reply = VhostUserConfig::new(msg.offset, 0, flags);
                self.slave_req_helper.send_reply_message(hdr, &reply)?;
            }
            Err(_) => {
                let reply = VhostUserConfig::new(msg.offset, 0, flags);
                self.slave_req_helper.send_reply_message(hdr, &reply)?;
            }
        }
        Ok(())
    }

    fn set_config(&mut self, size: usize, buf: &[u8]) -> Result<()> {
        if size > MAX_MSG_SIZE || size < mem::size_of::<VhostUserConfig>() {
            return Err(Error::InvalidMessage);
        }
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const VhostUserConfig) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if size - mem::size_of::<VhostUserConfig>() != msg.size as usize {
            return Err(Error::InvalidMessage);
        }
        let flags: VhostUserConfigFlags = match VhostUserConfigFlags::from_bits(msg.flags) {
            Some(val) => val,
            None => return Err(Error::InvalidMessage),
        };

        self.backend.set_config(msg.offset, buf, flags)
    }

    fn set_slave_req_fd(&mut self, files: Option<Vec<File>>) -> Result<()> {
        let ep = self
            .slave_req_helper
            .endpoint
            .create_slave_request_endpoint(files)?;
        self.backend.set_slave_req_fd(ep);
        Ok(())
    }

    fn handle_vring_fd_request(
        &mut self,
        buf: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<(u8, Option<File>)> {
        self.slave_req_helper.handle_vring_fd_request(buf, files)
    }

    fn check_request_size(
        &self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        size: usize,
        expected: usize,
    ) -> Result<()> {
        if hdr.get_size() as usize != expected
            || hdr.is_reply()
            || hdr.get_version() != 0x1
            || size != expected
        {
            return Err(Error::InvalidMessage);
        }
        Ok(())
    }

    fn check_attached_files(
        &self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        files: &Option<Vec<File>>,
    ) -> Result<()> {
        match hdr.get_code() {
            MasterReq::SET_MEM_TABLE
            | MasterReq::SET_VRING_CALL
            | MasterReq::SET_VRING_KICK
            | MasterReq::SET_VRING_ERR
            | MasterReq::SET_LOG_BASE
            | MasterReq::SET_LOG_FD
            | MasterReq::SET_SLAVE_REQ_FD
            | MasterReq::SET_INFLIGHT_FD
            | MasterReq::ADD_MEM_REG => Ok(()),
            _ if files.is_some() => Err(Error::InvalidMessage),
            _ => Ok(()),
        }
    }

    fn extract_request_body<T: Sized + DataInit + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        size: usize,
        buf: &[u8],
    ) -> Result<T> {
        self.check_request_size(hdr, size, mem::size_of::<T>())?;
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const T) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        Ok(msg)
    }

    fn update_reply_ack_flag(&mut self) {
        let vflag = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let pflag = VhostUserProtocolFeatures::REPLY_ACK;
        if (self.virtio_features & vflag) != 0
            && self.protocol_features.contains(pflag)
            && (self.acked_protocol_features & pflag.bits()) != 0
        {
            self.slave_req_helper.reply_ack_enabled = true;
        } else {
            self.slave_req_helper.reply_ack_enabled = false;
        }
    }
}

impl<S: VhostUserSlaveReqHandler, E: AsRawDescriptor + Endpoint<MasterReq>> AsRawDescriptor
    for SlaveReqHandler<S, E>
{
    fn as_raw_descriptor(&self) -> RawDescriptor {
        // TODO(b/221882601): figure out if this used for polling.
        self.slave_req_helper.endpoint.as_raw_descriptor()
    }
}

#[cfg(test)]
mod tests {
    use base::INVALID_DESCRIPTOR;

    use super::*;
    use crate::dummy_slave::DummySlaveReqHandler;
    use crate::MasterReqEndpoint;
    use crate::SystemStream;

    #[test]
    fn test_slave_req_handler_new() {
        let (p1, _p2) = SystemStream::pair().unwrap();
        let endpoint = MasterReqEndpoint::from(p1);
        let backend = Mutex::new(DummySlaveReqHandler::new());
        let handler = SlaveReqHandler::new(endpoint, backend);

        assert!(handler.as_raw_descriptor() != INVALID_DESCRIPTOR);
    }
}
