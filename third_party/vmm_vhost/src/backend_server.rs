// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::mem;

use base::AsRawDescriptor;
use base::RawDescriptor;
use base::SafeDescriptor;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::Ref;

use crate::into_single_file;
use crate::message::*;
use crate::BackendReq;
use crate::Connection;
use crate::Error;
use crate::FrontendReq;
use crate::Result;

/// Trait for vhost-user backends.
///
/// Each method corresponds to a vhost-user protocol method. See the specification for details.
#[allow(missing_docs)]
pub trait Backend {
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
    // TODO: b/331466964 - Argument type is wrong for packed queues.
    fn set_vring_base(&mut self, index: u32, base: u32) -> Result<()>;
    // TODO: b/331466964 - Return type is wrong for packed queues.
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
    fn set_backend_req_fd(&mut self, _vu_req: Connection<BackendReq>) {}
    fn get_inflight_fd(
        &mut self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)>;
    fn set_inflight_fd(&mut self, inflight: &VhostUserInflight, file: File) -> Result<()>;
    fn get_max_mem_slots(&mut self) -> Result<u64>;
    fn add_mem_region(&mut self, region: &VhostUserSingleMemoryRegion, fd: File) -> Result<()>;
    fn remove_mem_region(&mut self, region: &VhostUserSingleMemoryRegion) -> Result<()>;
    fn set_device_state_fd(
        &mut self,
        transfer_direction: VhostUserTransferDirection,
        migration_phase: VhostUserMigrationPhase,
        fd: File,
    ) -> Result<Option<File>>;
    fn check_device_state(&mut self) -> Result<()>;
    fn get_shared_memory_regions(&mut self) -> Result<Vec<VhostSharedMemoryRegion>>;
}

impl<T> Backend for T
where
    T: AsMut<dyn Backend>,
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

    fn set_backend_req_fd(&mut self, vu_req: Connection<BackendReq>) {
        self.as_mut().set_backend_req_fd(vu_req)
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

    fn set_device_state_fd(
        &mut self,
        transfer_direction: VhostUserTransferDirection,
        migration_phase: VhostUserMigrationPhase,
        fd: File,
    ) -> Result<Option<File>> {
        self.as_mut()
            .set_device_state_fd(transfer_direction, migration_phase, fd)
    }

    fn check_device_state(&mut self) -> Result<()> {
        self.as_mut().check_device_state()
    }

    fn get_shared_memory_regions(&mut self) -> Result<Vec<VhostSharedMemoryRegion>> {
        self.as_mut().get_shared_memory_regions()
    }
}

/// Handles requests from a vhost-user connection by dispatching them to [[Backend]] methods.
pub struct BackendServer<S: Backend> {
    /// Underlying connection for communication.
    connection: Connection<FrontendReq>,
    // the vhost-user backend device object
    backend: S,

    virtio_features: u64,
    acked_virtio_features: u64,
    protocol_features: VhostUserProtocolFeatures,
    acked_protocol_features: u64,

    /// Sending ack for messages without payload.
    reply_ack_enabled: bool,
}

impl<S: Backend> AsRef<S> for BackendServer<S> {
    fn as_ref(&self) -> &S {
        &self.backend
    }
}

impl<S: Backend> BackendServer<S> {
    pub fn new(connection: Connection<FrontendReq>, backend: S) -> Self {
        BackendServer {
            connection,
            backend,
            virtio_features: 0,
            acked_virtio_features: 0,
            protocol_features: VhostUserProtocolFeatures::empty(),
            acked_protocol_features: 0,
            reply_ack_enabled: false,
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
    /// This method [`BackendServer::recv_header()`] is in charge of the step (1) and (2),
    /// [`BackendServer::needs_wait_for_payload()`] is (3), and
    /// [`BackendServer::process_message()`] is (5) and (6). We need to have the three method
    /// separately for multi-platform supports; [`BackendServer::recv_header()`] and
    /// [`BackendServer::process_message()`] need to be separated because the way of waiting for
    /// incoming messages differs between Unix and Windows so it's the caller's responsibility to
    /// wait before [`BackendServer::process_message()`].
    ///
    /// Note that some vhost-user protocol variant such as VVU doesn't assume stream mode. In this
    /// case, a message header and its body are sent together so the step (4) is skipped. We handle
    /// this case in [`BackendServer::needs_wait_for_payload()`].
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
    ///   let (hdr, files) = backend_server.recv_header();
    ///
    ///   // (3)
    ///   if backend_server.needs_wait_for_payload(&hdr) {
    ///     // (4) block until a payload comes if needed.
    ///     connection.wait_readable().unwrap();
    ///   }
    ///
    ///   // (5) and (6)
    ///   backend_server.process_message(&hdr, &files).unwrap();
    /// }
    /// ```
    pub fn recv_header(&mut self) -> Result<(VhostUserMsgHeader<FrontendReq>, Vec<File>)> {
        // The underlying communication channel is a Unix domain socket in
        // stream mode, and recvmsg() is a little tricky here. To successfully
        // receive attached file descriptors, we need to receive messages and
        // corresponding attached file descriptors in this way:
        // . recv messsage header and optional attached file
        // . validate message header
        // . recv optional message body and payload according size field in
        //   message header
        // . validate message body and optional payload
        let (hdr, files) = match self.connection.recv_header() {
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

        if !hdr.is_valid() {
            return Err(Error::InvalidMessage);
        }

        self.check_attached_files(&hdr, &files)?;

        Ok((hdr, files))
    }

    /// Returns whether the caller needs to wait for the incoming message before calling
    /// [`BackendServer::process_message`].
    ///
    /// See [`BackendServer::recv_header`]'s doc comment for the usage.
    pub fn needs_wait_for_payload(&self, hdr: &VhostUserMsgHeader<FrontendReq>) -> bool {
        // Since the vhost-user protocol uses stream mode, we need to wait until an additional
        // payload is available if exists.
        hdr.get_size() != 0
    }

    /// Main entrance to request from the communication channel.
    ///
    /// Receive and handle one incoming request message from the frontend.
    /// See [`BackendServer::recv_header`]'s doc comment for the usage.
    ///
    /// # Return:
    /// * `Ok(())`: one request was successfully handled.
    /// * `Err(ClientExit)`: the frontend closed the connection properly. This isn't an actual
    ///   failure.
    /// * `Err(Disconnect)`: the connection was closed unexpectedly.
    /// * `Err(InvalidMessage)`: the vmm sent a illegal message.
    /// * other errors: failed to handle a request.
    pub fn process_message(
        &mut self,
        hdr: VhostUserMsgHeader<FrontendReq>,
        files: Vec<File>,
    ) -> Result<()> {
        let (buf, extra_files) = self.connection.recv_body_bytes(&hdr)?;
        let size = buf.len();
        if !extra_files.is_empty() {
            return Err(Error::InvalidMessage);
        }

        // TODO: The error handling here is inconsistent. Sometimes we report the error to the
        // client and keep going, sometimes we report the error and then close the connection,
        // sometimes we just close the connection.
        match hdr.get_code() {
            Ok(FrontendReq::SET_OWNER) => {
                self.check_request_size(&hdr, size, 0)?;
                let res = self.backend.set_owner();
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::RESET_OWNER) => {
                self.check_request_size(&hdr, size, 0)?;
                let res = self.backend.reset_owner();
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::GET_FEATURES) => {
                self.check_request_size(&hdr, size, 0)?;
                let mut features = self.backend.get_features()?;

                // Don't advertise packed queues even if the device does. We don't handle them
                // properly yet at the protocol layer.
                // TODO: b/331466964 - Remove once support is added.
                features &= !(1 << VIRTIO_F_RING_PACKED);

                let msg = VhostUserU64::new(features);
                self.send_reply_message(&hdr, &msg)?;
                self.virtio_features = features;
                self.update_reply_ack_flag();
            }
            Ok(FrontendReq::SET_FEATURES) => {
                let mut msg = self.extract_request_body::<VhostUserU64>(&hdr, size, &buf)?;

                // Don't allow packed queues even if the device does. We don't handle them
                // properly yet at the protocol layer.
                // TODO: b/331466964 - Remove once support is added.
                msg.value &= !(1 << VIRTIO_F_RING_PACKED);

                let res = self.backend.set_features(msg.value);
                self.acked_virtio_features = msg.value;
                self.update_reply_ack_flag();
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::SET_MEM_TABLE) => {
                let res = self.set_mem_table(&hdr, size, &buf, files);
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::SET_VRING_NUM) => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let res = self.backend.set_vring_num(msg.index, msg.num);
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::SET_VRING_ADDR) => {
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
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::SET_VRING_BASE) => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let res = self.backend.set_vring_base(msg.index, msg.num);
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::GET_VRING_BASE) => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let reply = self.backend.get_vring_base(msg.index)?;
                self.send_reply_message(&hdr, &reply)?;
            }
            Ok(FrontendReq::SET_VRING_CALL) => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_call(index, file);
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::SET_VRING_KICK) => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_kick(index, file);
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::SET_VRING_ERR) => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_err(index, file);
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::GET_PROTOCOL_FEATURES) => {
                self.check_request_size(&hdr, size, 0)?;
                let features = self.backend.get_protocol_features()?;
                let msg = VhostUserU64::new(features.bits());
                self.send_reply_message(&hdr, &msg)?;
                self.protocol_features = features;
                self.update_reply_ack_flag();
            }
            Ok(FrontendReq::SET_PROTOCOL_FEATURES) => {
                let msg = self.extract_request_body::<VhostUserU64>(&hdr, size, &buf)?;
                let res = self.backend.set_protocol_features(msg.value);
                self.acked_protocol_features = msg.value;
                self.update_reply_ack_flag();
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::GET_QUEUE_NUM) => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, 0)?;
                let num = self.backend.get_queue_num()?;
                let msg = VhostUserU64::new(num);
                self.send_reply_message(&hdr, &msg)?;
            }
            Ok(FrontendReq::SET_VRING_ENABLE) => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                if self.acked_virtio_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES == 0 {
                    return Err(Error::InvalidOperation);
                }
                let enable = match msg.num {
                    1 => true,
                    0 => false,
                    _ => {
                        return Err(Error::InvalidParam(
                            "SET_VRING_ENABLE: num out of range (must be [0, 1])",
                        ))
                    }
                };

                let res = self.backend.set_vring_enable(msg.index, enable);
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::GET_CONFIG) => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                self.get_config(&hdr, &buf)?;
            }
            Ok(FrontendReq::SET_CONFIG) => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                let res = self.set_config(&buf);
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::SET_BACKEND_REQ_FD) => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::BACKEND_REQ.bits() == 0
                {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                let res = self.set_backend_req_fd(files);
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::GET_INFLIGHT_FD) => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }

                let msg = self.extract_request_body::<VhostUserInflight>(&hdr, size, &buf)?;
                let (inflight, file) = self.backend.get_inflight_fd(&msg)?;
                let reply_hdr = self.new_reply_header::<VhostUserInflight>(&hdr, 0)?;
                self.connection.send_message(
                    &reply_hdr,
                    &inflight,
                    Some(&[file.as_raw_descriptor()]),
                )?;
            }
            Ok(FrontendReq::SET_INFLIGHT_FD) => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                let file = into_single_file(files).ok_or(Error::IncorrectFds)?;
                let msg = self.extract_request_body::<VhostUserInflight>(&hdr, size, &buf)?;
                let res = self.backend.set_inflight_fd(&msg, file);
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::GET_MAX_MEM_SLOTS) => {
                if self.acked_protocol_features
                    & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, 0)?;
                let num = self.backend.get_max_mem_slots()?;
                let msg = VhostUserU64::new(num);
                self.send_reply_message(&hdr, &msg)?;
            }
            Ok(FrontendReq::ADD_MEM_REG) => {
                if self.acked_protocol_features
                    & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                let file = into_single_file(files).ok_or(Error::InvalidParam(
                    "ADD_MEM_REG: exactly one file must be provided",
                ))?;
                let msg =
                    self.extract_request_body::<VhostUserSingleMemoryRegion>(&hdr, size, &buf)?;
                let res = self.backend.add_mem_region(&msg, file);
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::REM_MEM_REG) => {
                if self.acked_protocol_features
                    & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }

                let msg =
                    self.extract_request_body::<VhostUserSingleMemoryRegion>(&hdr, size, &buf)?;
                let res = self.backend.remove_mem_region(&msg);
                self.send_ack_message(&hdr, res.is_ok())?;
                res?;
            }
            Ok(FrontendReq::SET_DEVICE_STATE_FD) => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::DEVICE_STATE.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                // Read request.
                let msg =
                    self.extract_request_body::<DeviceStateTransferParameters>(&hdr, size, &buf)?;
                let transfer_direction = match msg.transfer_direction {
                    0 => VhostUserTransferDirection::Save,
                    1 => VhostUserTransferDirection::Load,
                    _ => return Err(Error::InvalidMessage),
                };
                let migration_phase = match msg.migration_phase {
                    0 => VhostUserMigrationPhase::Stopped,
                    _ => return Err(Error::InvalidMessage),
                };
                // Call backend.
                let res = self.backend.set_device_state_fd(
                    transfer_direction,
                    migration_phase,
                    files.into_iter().next().ok_or(Error::IncorrectFds)?,
                );
                // Send response.
                let (msg, fds) = match &res {
                    Ok(None) => (VhostUserU64::new(0x100), None),
                    Ok(Some(file)) => (VhostUserU64::new(0), Some(file.as_raw_descriptor())),
                    // Just in case, set the "invalid FD" flag on error.
                    Err(_) => (VhostUserU64::new(0x101), None),
                };
                let reply_hdr: VhostUserMsgHeader<FrontendReq> =
                    self.new_reply_header::<VhostUserU64>(&hdr, 0)?;
                self.connection.send_message(
                    &reply_hdr,
                    &msg,
                    fds.as_ref().map(std::slice::from_ref),
                )?;
                res?;
            }
            Ok(FrontendReq::CHECK_DEVICE_STATE) => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::DEVICE_STATE.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                let res = self.backend.check_device_state();
                let msg = VhostUserU64::new(if res.is_ok() { 0 } else { 1 });
                self.send_reply_message(&hdr, &msg)?;
                res?;
            }
            Ok(FrontendReq::GET_SHARED_MEMORY_REGIONS) => {
                let regions = self.backend.get_shared_memory_regions()?;
                let mut buf = Vec::new();
                let msg = VhostUserU64::new(regions.len() as u64);
                for r in regions {
                    buf.extend_from_slice(r.as_bytes())
                }
                self.send_reply_with_payload(&hdr, &msg, buf.as_slice())?;
            }
            _ => {
                return Err(Error::InvalidMessage);
            }
        }
        Ok(())
    }

    fn new_reply_header<T: Sized>(
        &self,
        req: &VhostUserMsgHeader<FrontendReq>,
        payload_size: usize,
    ) -> Result<VhostUserMsgHeader<FrontendReq>> {
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

    /// Sends reply back to Vhost frontend in response to a message.
    fn send_ack_message(
        &mut self,
        req: &VhostUserMsgHeader<FrontendReq>,
        success: bool,
    ) -> Result<()> {
        if self.reply_ack_enabled && req.is_need_reply() {
            let hdr: VhostUserMsgHeader<FrontendReq> =
                self.new_reply_header::<VhostUserU64>(req, 0)?;
            let val = if success { 0 } else { 1 };
            let msg = VhostUserU64::new(val);
            self.connection.send_message(&hdr, &msg, None)?;
        }
        Ok(())
    }

    fn send_reply_message<T: IntoBytes + Immutable>(
        &mut self,
        req: &VhostUserMsgHeader<FrontendReq>,
        msg: &T,
    ) -> Result<()> {
        let hdr = self.new_reply_header::<T>(req, 0)?;
        self.connection.send_message(&hdr, msg, None)?;
        Ok(())
    }

    fn send_reply_with_payload<T: IntoBytes + Immutable>(
        &mut self,
        req: &VhostUserMsgHeader<FrontendReq>,
        msg: &T,
        payload: &[u8],
    ) -> Result<()> {
        let hdr = self.new_reply_header::<T>(req, payload.len())?;
        self.connection
            .send_message_with_payload(&hdr, msg, payload, None)?;
        Ok(())
    }

    fn set_mem_table(
        &mut self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
        size: usize,
        buf: &[u8],
        files: Vec<File>,
    ) -> Result<()> {
        self.check_request_size(hdr, size, hdr.get_size() as usize)?;

        let (msg, regions) =
            Ref::<_, VhostUserMemory>::from_prefix(buf).map_err(|_| Error::InvalidMessage)?;
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }

        // validate number of fds matching number of memory regions
        if files.len() != msg.num_regions as usize {
            return Err(Error::InvalidMessage);
        }

        let (regions, excess) = Ref::<_, [VhostUserMemoryRegion]>::from_prefix_with_elems(
            regions,
            msg.num_regions as usize,
        )
        .map_err(|_| Error::InvalidMessage)?;
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

    fn get_config(&mut self, hdr: &VhostUserMsgHeader<FrontendReq>, buf: &[u8]) -> Result<()> {
        let (msg, payload) =
            Ref::<_, VhostUserConfig>::from_prefix(buf).map_err(|_| Error::InvalidMessage)?;
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

        // The response payload size MUST match the request payload size on success. A zero length
        // response is used to indicate an error.
        match res {
            Ok(ref buf) if buf.len() == msg.size as usize => {
                let reply = VhostUserConfig::new(msg.offset, buf.len() as u32, flags);
                self.send_reply_with_payload(hdr, &reply, buf.as_slice())?;
            }
            Ok(_) => {
                let reply = VhostUserConfig::new(msg.offset, 0, flags);
                self.send_reply_message(hdr, &reply)?;
            }
            Err(_) => {
                let reply = VhostUserConfig::new(msg.offset, 0, flags);
                self.send_reply_message(hdr, &reply)?;
            }
        }
        Ok(())
    }

    fn set_config(&mut self, buf: &[u8]) -> Result<()> {
        let (msg, payload) =
            Ref::<_, VhostUserConfig>::from_prefix(buf).map_err(|_| Error::InvalidMessage)?;
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

    fn set_backend_req_fd(&mut self, files: Vec<File>) -> Result<()> {
        let file = into_single_file(files).ok_or(Error::InvalidMessage)?;
        let fd: SafeDescriptor = file.into();
        let connection = Connection::try_from(fd).map_err(|_| Error::InvalidMessage)?;
        self.backend.set_backend_req_fd(connection);
        Ok(())
    }

    /// Parses an incoming |SET_VRING_KICK| or |SET_VRING_CALL| message into a
    /// Vring number and an fd.
    fn handle_vring_fd_request(
        &mut self,
        buf: &[u8],
        files: Vec<File>,
    ) -> Result<(u8, Option<File>)> {
        let (msg, _) = VhostUserU64::read_from_prefix(buf).map_err(|_| Error::InvalidMessage)?;
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

        let file = into_single_file(files);

        if has_fd && file.is_none() || !has_fd && file.is_some() {
            return Err(Error::InvalidMessage);
        }

        Ok((msg.value as u8, file))
    }

    fn check_request_size(
        &self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
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
        hdr: &VhostUserMsgHeader<FrontendReq>,
        files: &[File],
    ) -> Result<()> {
        match hdr.get_code() {
            Ok(FrontendReq::SET_MEM_TABLE)
            | Ok(FrontendReq::SET_VRING_CALL)
            | Ok(FrontendReq::SET_VRING_KICK)
            | Ok(FrontendReq::SET_VRING_ERR)
            | Ok(FrontendReq::SET_LOG_BASE)
            | Ok(FrontendReq::SET_LOG_FD)
            | Ok(FrontendReq::SET_BACKEND_REQ_FD)
            | Ok(FrontendReq::SET_INFLIGHT_FD)
            | Ok(FrontendReq::ADD_MEM_REG)
            | Ok(FrontendReq::SET_DEVICE_STATE_FD) => Ok(()),
            Err(_) => Err(Error::InvalidMessage),
            _ if !files.is_empty() => Err(Error::InvalidMessage),
            _ => Ok(()),
        }
    }

    fn extract_request_body<T: Sized + FromBytes + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
        size: usize,
        buf: &[u8],
    ) -> Result<T> {
        self.check_request_size(hdr, size, mem::size_of::<T>())?;
        let (body, _) = T::read_from_prefix(buf).map_err(|_| Error::InvalidMessage)?;
        if body.is_valid() {
            Ok(body)
        } else {
            Err(Error::InvalidMessage)
        }
    }

    fn update_reply_ack_flag(&mut self) {
        let pflag = VhostUserProtocolFeatures::REPLY_ACK;
        self.reply_ack_enabled = (self.virtio_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES) != 0
            && self.protocol_features.contains(pflag)
            && (self.acked_protocol_features & pflag.bits()) != 0;
    }
}

impl<S: Backend> AsRawDescriptor for BackendServer<S> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        // TODO(b/221882601): figure out if this used for polling.
        self.connection.as_raw_descriptor()
    }
}

#[cfg(test)]
mod tests {
    use base::INVALID_DESCRIPTOR;

    use super::*;
    use crate::test_backend::TestBackend;
    use crate::Connection;

    #[test]
    fn test_backend_server_new() {
        let (p1, _p2) = Connection::pair().unwrap();
        let backend = TestBackend::new();
        let handler = BackendServer::new(p1, backend);

        assert!(handler.as_raw_descriptor() != INVALID_DESCRIPTOR);
    }
}
