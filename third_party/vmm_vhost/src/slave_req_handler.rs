// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::mem;

use base::error;
use base::AsRawDescriptor;
use base::RawDescriptor;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::Ref;

use crate::connection::to_system_stream;
use crate::message::*;
use crate::take_single_file;
use crate::Connection;
use crate::Error;
use crate::MasterReq;
use crate::Result;
use crate::SlaveReq;
use crate::SystemStream;

/// Services provided to the master by the slave.
///
/// The [VhostUserSlaveReqHandler] trait defines the services provided to the master by the slave.
/// The vhost-user specification defines a master communication channel, by which masters could
/// request services from slaves. The [VhostUserSlaveReqHandler] trait defines services provided by
/// slaves, and it's used both on the master side and slave side.
///
/// - on the master side, a stub forwarder implementing [VhostUserSlaveReqHandler] will proxy
///   service requests to slaves.
/// - on the slave side, the [SlaveReqHandler] will forward service requests to a handler
///   implementing [VhostUserSlaveReqHandler].
///
/// [VhostUserSlaveReqHandler]: trait.VhostUserSlaveReqHandler.html
/// [SlaveReqHandler]: struct.SlaveReqHandler.html
#[allow(missing_docs)]
pub trait VhostUserSlaveReqHandler {
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
    fn set_slave_req_fd(&mut self, _vu_req: Connection<SlaveReq>) {}
    fn get_inflight_fd(
        &mut self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)>;
    fn set_inflight_fd(&mut self, inflight: &VhostUserInflight, file: File) -> Result<()>;
    fn get_max_mem_slots(&mut self) -> Result<u64>;
    fn add_mem_region(&mut self, region: &VhostUserSingleMemoryRegion, fd: File) -> Result<()>;
    fn remove_mem_region(&mut self, region: &VhostUserSingleMemoryRegion) -> Result<()>;
    fn get_shared_memory_regions(&mut self) -> Result<Vec<VhostSharedMemoryRegion>>;
    /// Request the device to sleep by stopping their workers. This should NOT be called if the
    /// device is already asleep.
    fn sleep(&mut self) -> Result<()>;
    /// Request the device to wake up by starting up their workers. This should NOT be called if the
    /// device is already awake.
    fn wake(&mut self) -> Result<()>;
    fn snapshot(&mut self) -> Result<Vec<u8>>;
    fn restore(&mut self, data_bytes: &[u8], queue_evts: Option<Vec<File>>) -> Result<()>;
}

impl<T> VhostUserSlaveReqHandler for T
where
    T: AsMut<dyn VhostUserSlaveReqHandler>,
{
    fn set_owner(&mut self) -> Result<()> {
        self.as_mut().set_owner()
    }

    fn reset_owner(&mut self) -> Result<()> {
        self.as_mut().reset_owner()
    }

    fn get_features(&mut self) -> Result<u64> {
        self.as_mut().get_features()
    }

    fn set_features(&mut self, features: u64) -> Result<()> {
        self.as_mut().set_features(features)
    }

    fn set_mem_table(&mut self, ctx: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()> {
        self.as_mut().set_mem_table(ctx, files)
    }

    fn set_vring_num(&mut self, index: u32, num: u32) -> Result<()> {
        self.as_mut().set_vring_num(index, num)
    }

    fn set_vring_addr(
        &mut self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()> {
        self.as_mut()
            .set_vring_addr(index, flags, descriptor, used, available, log)
    }

    fn set_vring_base(&mut self, index: u32, base: u32) -> Result<()> {
        self.as_mut().set_vring_base(index, base)
    }

    fn get_vring_base(&mut self, index: u32) -> Result<VhostUserVringState> {
        self.as_mut().get_vring_base(index)
    }

    fn set_vring_kick(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        self.as_mut().set_vring_kick(index, fd)
    }

    fn set_vring_call(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        self.as_mut().set_vring_call(index, fd)
    }

    fn set_vring_err(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        self.as_mut().set_vring_err(index, fd)
    }

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures> {
        self.as_mut().get_protocol_features()
    }

    fn set_protocol_features(&mut self, features: u64) -> Result<()> {
        self.as_mut().set_protocol_features(features)
    }

    fn get_queue_num(&mut self) -> Result<u64> {
        self.as_mut().get_queue_num()
    }

    fn set_vring_enable(&mut self, index: u32, enable: bool) -> Result<()> {
        self.as_mut().set_vring_enable(index, enable)
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
    ) -> Result<Vec<u8>> {
        self.as_mut().get_config(offset, size, flags)
    }

    fn set_config(&mut self, offset: u32, buf: &[u8], flags: VhostUserConfigFlags) -> Result<()> {
        self.as_mut().set_config(offset, buf, flags)
    }

    fn set_slave_req_fd(&mut self, vu_req: Connection<SlaveReq>) {
        self.as_mut().set_slave_req_fd(vu_req)
    }

    fn get_inflight_fd(
        &mut self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)> {
        self.as_mut().get_inflight_fd(inflight)
    }

    fn set_inflight_fd(&mut self, inflight: &VhostUserInflight, file: File) -> Result<()> {
        self.as_mut().set_inflight_fd(inflight, file)
    }

    fn get_max_mem_slots(&mut self) -> Result<u64> {
        self.as_mut().get_max_mem_slots()
    }

    fn add_mem_region(&mut self, region: &VhostUserSingleMemoryRegion, fd: File) -> Result<()> {
        self.as_mut().add_mem_region(region, fd)
    }

    fn remove_mem_region(&mut self, region: &VhostUserSingleMemoryRegion) -> Result<()> {
        self.as_mut().remove_mem_region(region)
    }

    fn get_shared_memory_regions(&mut self) -> Result<Vec<VhostSharedMemoryRegion>> {
        self.as_mut().get_shared_memory_regions()
    }

    fn sleep(&mut self) -> Result<()> {
        self.as_mut().sleep()
    }

    fn wake(&mut self) -> Result<()> {
        self.as_mut().wake()
    }

    fn snapshot(&mut self) -> Result<Vec<u8>> {
        self.as_mut().snapshot()
    }

    fn restore(&mut self, data_bytes: &[u8], queue_evts: Option<Vec<File>>) -> Result<()> {
        self.as_mut().restore(data_bytes, queue_evts)
    }
}

/// Abstracts |Connection| related operations for vhost-user slave implementations.
pub struct SlaveReqHelper {
    /// Underlying connection for communication.
    connection: Connection<MasterReq>,

    /// Sending ack for messages without payload.
    reply_ack_enabled: bool,
}

impl SlaveReqHelper {
    /// Creates a new |SlaveReqHelper| instance with an |Connection| underneath it.
    pub fn new(connection: Connection<MasterReq>) -> Self {
        SlaveReqHelper {
            connection,
            reply_ack_enabled: false,
        }
    }

    fn new_reply_header<T: Sized>(
        &self,
        req: &VhostUserMsgHeader<MasterReq>,
        payload_size: usize,
    ) -> Result<VhostUserMsgHeader<MasterReq>> {
        Ok(VhostUserMsgHeader::new(
            req.get_code().map_err(|_| Error::InvalidMessage)?,
            VhostUserHeaderFlag::REPLY.bits(),
            (mem::size_of::<T>()
                .checked_add(payload_size)
                .ok_or(Error::OversizedMsg)?)
            .try_into()
            .map_err(Error::InvalidCastToInt)?,
        ))
    }

    /// Sends reply back to Vhost Master in response to a message.
    pub fn send_ack_message(
        &mut self,
        req: &VhostUserMsgHeader<MasterReq>,
        success: bool,
    ) -> Result<()> {
        if self.reply_ack_enabled && req.is_need_reply() {
            let hdr: VhostUserMsgHeader<MasterReq> =
                self.new_reply_header::<VhostUserU64>(req, 0)?;
            let val = if success { 0 } else { 1 };
            let msg = VhostUserU64::new(val);
            self.connection.send_message(&hdr, &msg, None)?;
        }
        Ok(())
    }

    fn send_reply_message<T: Sized + AsBytes>(
        &mut self,
        req: &VhostUserMsgHeader<MasterReq>,
        msg: &T,
    ) -> Result<()> {
        let hdr = self.new_reply_header::<T>(req, 0)?;
        self.connection.send_message(&hdr, msg, None)?;
        Ok(())
    }

    fn send_reply_with_payload<T: Sized + AsBytes>(
        &mut self,
        req: &VhostUserMsgHeader<MasterReq>,
        msg: &T,
        payload: &[u8],
    ) -> Result<()> {
        let hdr = self.new_reply_header::<T>(req, payload.len())?;
        self.connection
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
        let msg = VhostUserU64::read_from_prefix(buf).ok_or(Error::InvalidMessage)?;
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
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

impl AsRawDescriptor for SlaveReqHelper {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.connection.as_raw_descriptor()
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
pub struct SlaveReqHandler<S: VhostUserSlaveReqHandler> {
    slave_req_helper: SlaveReqHelper,
    // the vhost-user backend device object
    backend: S,

    virtio_features: u64,
    acked_virtio_features: u64,
    protocol_features: VhostUserProtocolFeatures,
    acked_protocol_features: u64,
}

impl<S: VhostUserSlaveReqHandler> SlaveReqHandler<S> {
    /// Create a vhost-user slave connection from a connected socket.
    pub fn from_stream(socket: SystemStream, backend: S) -> Self {
        Self::new(Connection::from(socket), backend)
    }
}

impl<S: VhostUserSlaveReqHandler> AsRef<S> for SlaveReqHandler<S> {
    fn as_ref(&self) -> &S {
        &self.backend
    }
}

impl<S: VhostUserSlaveReqHandler> SlaveReqHandler<S> {
    /// Create a vhost-user slave connection.
    pub fn new(connection: Connection<MasterReq>, backend: S) -> Self {
        SlaveReqHandler {
            slave_req_helper: SlaveReqHelper::new(connection),
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
        let (hdr, files) = match self.slave_req_helper.connection.recv_header() {
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
        // Since the vhost-user protocol uses stream mode, we need to wait until an additional
        // payload is available if exists.
        hdr.get_size() != 0
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
        let buf = self.slave_req_helper.connection.recv_body_bytes(&hdr)?;
        let size = buf.len();

        match hdr.get_code() {
            Ok(MasterReq::SET_OWNER) => {
                self.check_request_size(&hdr, size, 0)?;
                let res = self.backend.set_owner();
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(MasterReq::RESET_OWNER) => {
                self.check_request_size(&hdr, size, 0)?;
                let res = self.backend.reset_owner();
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(MasterReq::GET_FEATURES) => {
                self.check_request_size(&hdr, size, 0)?;
                let features = self.backend.get_features()?;
                let msg = VhostUserU64::new(features);
                self.slave_req_helper.send_reply_message(&hdr, &msg)?;
                self.virtio_features = features;
                self.update_reply_ack_flag();
            }
            Ok(MasterReq::SET_FEATURES) => {
                let msg = self.extract_request_body::<VhostUserU64>(&hdr, size, &buf)?;
                let res = self.backend.set_features(msg.value);
                self.acked_virtio_features = msg.value;
                self.update_reply_ack_flag();
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(MasterReq::SET_MEM_TABLE) => {
                let res = self.set_mem_table(&hdr, size, &buf, files);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(MasterReq::SET_VRING_NUM) => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let res = self.backend.set_vring_num(msg.index, msg.num);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(MasterReq::SET_VRING_ADDR) => {
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
            Ok(MasterReq::SET_VRING_BASE) => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let res = self.backend.set_vring_base(msg.index, msg.num);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(MasterReq::GET_VRING_BASE) => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let reply = self.backend.get_vring_base(msg.index)?;
                self.slave_req_helper.send_reply_message(&hdr, &reply)?;
            }
            Ok(MasterReq::SET_VRING_CALL) => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_call(index, file);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(MasterReq::SET_VRING_KICK) => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_kick(index, file);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(MasterReq::SET_VRING_ERR) => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_err(index, file);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(MasterReq::GET_PROTOCOL_FEATURES) => {
                self.check_request_size(&hdr, size, 0)?;
                let features = self.backend.get_protocol_features()?;
                let msg = VhostUserU64::new(features.bits());
                self.slave_req_helper.send_reply_message(&hdr, &msg)?;
                self.protocol_features = features;
                self.update_reply_ack_flag();
            }
            Ok(MasterReq::SET_PROTOCOL_FEATURES) => {
                let msg = self.extract_request_body::<VhostUserU64>(&hdr, size, &buf)?;
                let res = self.backend.set_protocol_features(msg.value);
                self.acked_protocol_features = msg.value;
                self.update_reply_ack_flag();
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(MasterReq::GET_QUEUE_NUM) => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, 0)?;
                let num = self.backend.get_queue_num()?;
                let msg = VhostUserU64::new(num);
                self.slave_req_helper.send_reply_message(&hdr, &msg)?;
            }
            Ok(MasterReq::SET_VRING_ENABLE) => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                if self.acked_virtio_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES == 0 {
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
            Ok(MasterReq::GET_CONFIG) => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                self.get_config(&hdr, &buf)?;
            }
            Ok(MasterReq::SET_CONFIG) => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                let res = self.set_config(&buf);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(MasterReq::SET_SLAVE_REQ_FD) => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::SLAVE_REQ.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                let res = self.set_slave_req_fd(files);
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(MasterReq::GET_INFLIGHT_FD) => {
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
                self.slave_req_helper.connection.send_message(
                    &reply_hdr,
                    &inflight,
                    Some(&[file.as_raw_descriptor()]),
                )?;
            }
            Ok(MasterReq::SET_INFLIGHT_FD) => {
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
            Ok(MasterReq::GET_MAX_MEM_SLOTS) => {
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
            Ok(MasterReq::ADD_MEM_REG) => {
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
            Ok(MasterReq::REM_MEM_REG) => {
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
            Ok(MasterReq::GET_SHARED_MEMORY_REGIONS) => {
                let regions = self.backend.get_shared_memory_regions()?;
                let mut buf = Vec::new();
                let msg = VhostUserU64::new(regions.len() as u64);
                for r in regions {
                    buf.extend_from_slice(r.as_bytes())
                }
                self.slave_req_helper
                    .send_reply_with_payload(&hdr, &msg, buf.as_slice())?;
            }
            Ok(MasterReq::SLEEP) => {
                let res = self.backend.sleep();
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
            }
            Ok(MasterReq::WAKE) => {
                let res = self.backend.wake();
                self.slave_req_helper.send_ack_message(&hdr, res.is_ok())?;
            }
            Ok(MasterReq::SNAPSHOT) => {
                let (success_msg, payload) = match self.backend.snapshot() {
                    Ok(snapshot_payload) => (VhostUserSuccess::new(true), snapshot_payload),
                    Err(e) => {
                        error!("Failed to snapshot: {}", e);
                        (VhostUserSuccess::new(false), Vec::new())
                    }
                };
                self.slave_req_helper.send_reply_with_payload(
                    &hdr,
                    &success_msg,
                    payload.as_slice(),
                )?;
            }
            Ok(MasterReq::RESTORE) => {
                let res = self.backend.restore(buf.as_slice(), files);
                let msg = VhostUserSuccess::new(res.is_ok());
                self.slave_req_helper.send_reply_message(&hdr, &msg)?;
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

        let (msg, regions) =
            Ref::<_, VhostUserMemory>::new_from_prefix(buf).ok_or(Error::InvalidMessage)?;
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }

        // validate number of fds matching number of memory regions
        let files = files.ok_or(Error::InvalidMessage)?;
        if files.len() != msg.num_regions as usize {
            return Err(Error::InvalidMessage);
        }

        let (regions, excess) = Ref::<_, [VhostUserMemoryRegion]>::new_slice_from_prefix(
            regions,
            msg.num_regions as usize,
        )
        .ok_or(Error::InvalidMessage)?;
        if !excess.is_empty() {
            return Err(Error::InvalidMessage);
        }

        // Validate memory regions
        for region in regions.iter() {
            if !region.is_valid() {
                return Err(Error::InvalidMessage);
            }
        }

        self.backend.set_mem_table(&regions, files)
    }

    fn get_config(&mut self, hdr: &VhostUserMsgHeader<MasterReq>, buf: &[u8]) -> Result<()> {
        let (msg, payload) =
            Ref::<_, VhostUserConfig>::new_from_prefix(buf).ok_or(Error::InvalidMessage)?;
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if payload.len() != msg.size as usize {
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

    fn set_config(&mut self, buf: &[u8]) -> Result<()> {
        let (msg, payload) =
            Ref::<_, VhostUserConfig>::new_from_prefix(buf).ok_or(Error::InvalidMessage)?;
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if payload.len() != msg.size as usize {
            return Err(Error::InvalidMessage);
        }
        let flags: VhostUserConfigFlags = match VhostUserConfigFlags::from_bits(msg.flags) {
            Some(val) => val,
            None => return Err(Error::InvalidMessage),
        };

        self.backend.set_config(msg.offset, payload, flags)
    }

    fn set_slave_req_fd(&mut self, files: Option<Vec<File>>) -> Result<()> {
        let file = take_single_file(files).ok_or(Error::InvalidMessage)?;
        let fd = file.into();
        // SAFETY: Safe because the protocol promises the file represents the appropriate file type
        // for the platform.
        let stream = unsafe { to_system_stream(fd) }?;
        self.backend.set_slave_req_fd(Connection::from(stream));
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
            Ok(MasterReq::SET_MEM_TABLE)
            | Ok(MasterReq::SET_VRING_CALL)
            | Ok(MasterReq::SET_VRING_KICK)
            | Ok(MasterReq::SET_VRING_ERR)
            | Ok(MasterReq::SET_LOG_BASE)
            | Ok(MasterReq::SET_LOG_FD)
            | Ok(MasterReq::SET_SLAVE_REQ_FD)
            | Ok(MasterReq::SET_INFLIGHT_FD)
            | Ok(MasterReq::RESTORE)
            | Ok(MasterReq::ADD_MEM_REG) => Ok(()),
            Err(_) => Err(Error::InvalidMessage),
            _ if files.is_some() => Err(Error::InvalidMessage),
            _ => Ok(()),
        }
    }

    fn extract_request_body<T: Sized + FromBytes + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        size: usize,
        buf: &[u8],
    ) -> Result<T> {
        self.check_request_size(hdr, size, mem::size_of::<T>())?;
        T::read_from_prefix(buf)
            .filter(T::is_valid)
            .map_or(Err(Error::InvalidMessage), Ok)
    }

    fn update_reply_ack_flag(&mut self) {
        let pflag = VhostUserProtocolFeatures::REPLY_ACK;
        self.slave_req_helper.reply_ack_enabled =
            (self.virtio_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES) != 0
                && self.protocol_features.contains(pflag)
                && (self.acked_protocol_features & pflag.bits()) != 0;
    }
}

impl<S: VhostUserSlaveReqHandler> AsRawDescriptor for SlaveReqHandler<S> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        // TODO(b/221882601): figure out if this used for polling.
        self.slave_req_helper.connection.as_raw_descriptor()
    }
}

#[cfg(test)]
mod tests {
    use base::INVALID_DESCRIPTOR;

    use super::*;
    use crate::dummy_slave::DummySlaveReqHandler;
    use crate::Connection;
    use crate::SystemStream;

    #[test]
    fn test_slave_req_handler_new() {
        let (p1, _p2) = SystemStream::pair().unwrap();
        let connection = Connection::from(p1);
        let backend = DummySlaveReqHandler::new();
        let handler = SlaveReqHandler::new(connection, backend);

        assert!(handler.as_raw_descriptor() != INVALID_DESCRIPTOR);
    }
}
