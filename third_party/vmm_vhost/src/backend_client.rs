// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::mem;

use base::AsRawDescriptor;
#[cfg(windows)]
use base::CloseNotifier;
use base::Event;
use base::RawDescriptor;
use base::ReadNotifier;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

use crate::backend::VhostUserMemoryRegionInfo;
use crate::backend::VringConfigData;
use crate::into_single_file;
use crate::message::*;
use crate::Connection;
use crate::Error as VhostUserError;
use crate::FrontendReq;
use crate::Result as VhostUserResult;
use crate::Result;

/// Client for a vhost-user device. The API is a thin abstraction over the vhost-user protocol.
pub struct BackendClient {
    connection: Connection<FrontendReq>,
}

impl BackendClient {
    /// Create a new instance.
    pub fn new(connection: Connection<FrontendReq>) -> Self {
        BackendClient { connection }
    }

    /// Get a bitmask of supported virtio/vhost features.
    pub fn get_features(&mut self) -> Result<u64> {
        let hdr = self.send_request_header(FrontendReq::GET_FEATURES, None)?;
        let val = self.recv_reply::<VhostUserU64>(&hdr)?;
        Ok(val.value)
    }

    /// Inform the vhost subsystem which features to enable.
    /// This should be a subset of supported features from get_features().
    pub fn set_features(&mut self, features: u64) -> Result<()> {
        let val = VhostUserU64::new(features);
        let hdr = self.send_request_with_body(FrontendReq::SET_FEATURES, &val, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Set the current process as the owner of the vhost backend.
    /// This must be run before any other vhost commands.
    pub fn set_owner(&self) -> Result<()> {
        let hdr = self.send_request_header(FrontendReq::SET_OWNER, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Used to be sent to request disabling all rings
    /// This is no longer used.
    pub fn reset_owner(&self) -> Result<()> {
        let hdr = self.send_request_header(FrontendReq::RESET_OWNER, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Set the memory map regions on the backend so it can translate the vring
    /// addresses. In the ancillary data there is an array of file descriptors
    pub fn set_mem_table(&self, regions: &[VhostUserMemoryRegionInfo]) -> Result<()> {
        let mut ctx = VhostUserMemoryContext::new();
        for region in regions.iter() {
            let reg = VhostUserMemoryRegion {
                guest_phys_addr: region.guest_phys_addr,
                memory_size: region.memory_size,
                user_addr: region.userspace_addr,
                mmap_offset: region.mmap_offset,
            };
            ctx.append(&reg, region.mmap_handle);
        }

        let body = VhostUserMemory::new(ctx.regions.len() as u32);
        let hdr = self.send_request_with_payload(
            FrontendReq::SET_MEM_TABLE,
            &body,
            ctx.regions.as_bytes(),
            Some(ctx.fds.as_slice()),
        )?;
        self.wait_for_ack(&hdr)
    }

    /// Set base address for page modification logging.
    pub fn set_log_base(&self, base: u64, fd: Option<RawDescriptor>) -> Result<()> {
        let val = VhostUserU64::new(base);
        let _ = self.send_request_with_body(
            FrontendReq::SET_LOG_BASE,
            &val,
            fd.as_ref().map(std::slice::from_ref),
        )?;

        Ok(())
    }

    /// Specify an event file descriptor to signal on log write.
    pub fn set_log_fd(&self, fd: RawDescriptor) -> Result<()> {
        let fds = [fd];
        let hdr = self.send_request_header(FrontendReq::SET_LOG_FD, Some(&fds))?;
        self.wait_for_ack(&hdr)
    }

    /// Set the number of descriptors in the vring.
    pub fn set_vring_num(&self, queue_index: usize, num: u16) -> Result<()> {
        let val = VhostUserVringState::new(queue_index as u32, num.into());
        let hdr = self.send_request_with_body(FrontendReq::SET_VRING_NUM, &val, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Set the addresses for a given vring.
    pub fn set_vring_addr(&self, queue_index: usize, config_data: &VringConfigData) -> Result<()> {
        let val = VhostUserVringAddr::from_config_data(queue_index as u32, config_data);
        let hdr = self.send_request_with_body(FrontendReq::SET_VRING_ADDR, &val, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Set the first index to look for available descriptors.
    // TODO: b/331466964 - Arguments and message format are wrong for packed queues.
    pub fn set_vring_base(&self, queue_index: usize, base: u16) -> Result<()> {
        let val = VhostUserVringState::new(queue_index as u32, base.into());
        let hdr = self.send_request_with_body(FrontendReq::SET_VRING_BASE, &val, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Get the available vring base offset.
    // TODO: b/331466964 - Return type is wrong for packed queues.
    pub fn get_vring_base(&self, queue_index: usize) -> Result<u32> {
        let req = VhostUserVringState::new(queue_index as u32, 0);
        let hdr = self.send_request_with_body(FrontendReq::GET_VRING_BASE, &req, None)?;
        let reply = self.recv_reply::<VhostUserVringState>(&hdr)?;
        Ok(reply.num)
    }

    /// Set the event to trigger when buffers have been used by the host.
    ///
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// will be used instead of waiting for the call.
    pub fn set_vring_call(&self, queue_index: usize, event: &Event) -> Result<()> {
        let hdr = self.send_fd_for_vring(
            FrontendReq::SET_VRING_CALL,
            queue_index,
            event.as_raw_descriptor(),
        )?;
        self.wait_for_ack(&hdr)
    }

    /// Set the event that will be signaled by the guest when buffers are available for the host to
    /// process.
    ///
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// should be used instead of waiting for a kick.
    pub fn set_vring_kick(&self, queue_index: usize, event: &Event) -> Result<()> {
        let hdr = self.send_fd_for_vring(
            FrontendReq::SET_VRING_KICK,
            queue_index,
            event.as_raw_descriptor(),
        )?;
        self.wait_for_ack(&hdr)
    }

    /// Set the event that will be signaled by the guest when error happens.
    ///
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data.
    pub fn set_vring_err(&self, queue_index: usize, event: &Event) -> Result<()> {
        let hdr = self.send_fd_for_vring(
            FrontendReq::SET_VRING_ERR,
            queue_index,
            event.as_raw_descriptor(),
        )?;
        self.wait_for_ack(&hdr)
    }

    /// Front-end and back-end negotiate a channel over which to transfer the back-end’s internal
    /// state during migration.
    ///
    /// Requires VHOST_USER_PROTOCOL_F_DEVICE_STATE to be negotiated.
    pub fn set_device_state_fd(
        &self,
        transfer_direction: VhostUserTransferDirection,
        migration_phase: VhostUserMigrationPhase,
        fd: &impl AsRawDescriptor,
    ) -> Result<Option<File>> {
        // Send request.
        let req = DeviceStateTransferParameters {
            transfer_direction: match transfer_direction {
                VhostUserTransferDirection::Save => 0,
                VhostUserTransferDirection::Load => 1,
            },
            migration_phase: match migration_phase {
                VhostUserMigrationPhase::Stopped => 0,
            },
        };
        let hdr = self.send_request_with_body(
            FrontendReq::SET_DEVICE_STATE_FD,
            &req,
            Some(&[fd.as_raw_descriptor()]),
        )?;
        // Receive reply.
        let (reply, files) = self.recv_reply_with_files::<VhostUserU64>(&hdr)?;
        let has_err = reply.value & 0xff != 0;
        let invalid_fd = reply.value & 0x100 != 0;
        if has_err {
            return Err(VhostUserError::BackendInternalError);
        }
        match (invalid_fd, files.len()) {
            (true, 0) => Ok(None),
            (false, 1) => Ok(files.into_iter().next()),
            _ => Err(VhostUserError::IncorrectFds),
        }
    }

    /// After transferring the back-end’s internal state during migration, check whether the
    /// back-end was able to successfully fully process the state.
    pub fn check_device_state(&self) -> Result<()> {
        let hdr = self.send_request_header(FrontendReq::CHECK_DEVICE_STATE, None)?;
        let reply = self.recv_reply::<VhostUserU64>(&hdr)?;
        if reply.value != 0 {
            return Err(VhostUserError::BackendInternalError);
        }
        Ok(())
    }

    /// Get the protocol feature bitmask from the underlying vhost implementation.
    pub fn get_protocol_features(&self) -> Result<VhostUserProtocolFeatures> {
        let hdr = self.send_request_header(FrontendReq::GET_PROTOCOL_FEATURES, None)?;
        let val = self.recv_reply::<VhostUserU64>(&hdr)?;
        Ok(VhostUserProtocolFeatures::from_bits_truncate(val.value))
    }

    /// Enable protocol features in the underlying vhost implementation.
    pub fn set_protocol_features(&mut self, features: VhostUserProtocolFeatures) -> Result<()> {
        let val = VhostUserU64::new(features.bits());
        let hdr = self.send_request_with_body(FrontendReq::SET_PROTOCOL_FEATURES, &val, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Query how many queues the backend supports.
    pub fn get_queue_num(&self) -> Result<u64> {
        let hdr = self.send_request_header(FrontendReq::GET_QUEUE_NUM, None)?;
        let val = self.recv_reply::<VhostUserU64>(&hdr)?;
        Ok(val.value)
    }

    /// Signal backend to enable or disable corresponding vring.
    ///
    /// Backend must not pass data to/from the ring until ring is enabled by
    /// VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has been
    /// disabled by VHOST_USER_SET_VRING_ENABLE with parameter 0.
    pub fn set_vring_enable(&self, queue_index: usize, enable: bool) -> Result<()> {
        let val = VhostUserVringState::new(queue_index as u32, enable.into());
        let hdr = self.send_request_with_body(FrontendReq::SET_VRING_ENABLE, &val, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Fetch the contents of the virtio device configuration space.
    pub fn get_config(
        &self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
        buf: &[u8],
    ) -> Result<(VhostUserConfig, VhostUserConfigPayload)> {
        let body = VhostUserConfig::new(offset, size, flags);

        // vhost-user spec states that:
        // "Request payload: virtio device config space"
        // "Reply payload: virtio device config space"
        let hdr = self.send_request_with_payload(FrontendReq::GET_CONFIG, &body, buf, None)?;
        let (body_reply, buf_reply, rfds) =
            self.recv_reply_with_payload::<VhostUserConfig>(&hdr)?;
        if !rfds.is_empty() {
            return Err(VhostUserError::InvalidMessage);
        } else if body_reply.size == 0 {
            return Err(VhostUserError::BackendInternalError);
        } else if body_reply.size != body.size
            || body_reply.size as usize != buf.len()
            || body_reply.offset != body.offset
        {
            return Err(VhostUserError::InvalidMessage);
        }

        Ok((body_reply, buf_reply))
    }

    /// Change the virtio device configuration space. It also can be used for live migration on the
    /// destination host to set readonly configuration space fields.
    pub fn set_config(&self, offset: u32, flags: VhostUserConfigFlags, buf: &[u8]) -> Result<()> {
        let body = VhostUserConfig::new(
            offset,
            buf.len()
                .try_into()
                .map_err(VhostUserError::InvalidCastToInt)?,
            flags,
        );

        let hdr = self.send_request_with_payload(FrontendReq::SET_CONFIG, &body, buf, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Setup backend communication channel.
    pub fn set_backend_req_fd(&self, fd: &dyn AsRawDescriptor) -> Result<()> {
        let fds = [fd.as_raw_descriptor()];
        let hdr = self.send_request_header(FrontendReq::SET_BACKEND_REQ_FD, Some(&fds))?;
        self.wait_for_ack(&hdr)
    }

    /// Retrieve shared buffer for inflight I/O tracking.
    pub fn get_inflight_fd(
        &self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)> {
        let hdr = self.send_request_with_body(FrontendReq::GET_INFLIGHT_FD, inflight, None)?;
        let (inflight, files) = self.recv_reply_with_files::<VhostUserInflight>(&hdr)?;

        match into_single_file(files) {
            Some(file) => Ok((inflight, file)),
            None => Err(VhostUserError::IncorrectFds),
        }
    }

    /// Set shared buffer for inflight I/O tracking.
    pub fn set_inflight_fd(&self, inflight: &VhostUserInflight, fd: RawDescriptor) -> Result<()> {
        let hdr =
            self.send_request_with_body(FrontendReq::SET_INFLIGHT_FD, inflight, Some(&[fd]))?;
        self.wait_for_ack(&hdr)
    }

    /// Query the maximum amount of memory slots supported by the backend.
    pub fn get_max_mem_slots(&self) -> Result<u64> {
        let hdr = self.send_request_header(FrontendReq::GET_MAX_MEM_SLOTS, None)?;
        let val = self.recv_reply::<VhostUserU64>(&hdr)?;

        Ok(val.value)
    }

    /// Add a new guest memory mapping for vhost to use.
    pub fn add_mem_region(&self, region: &VhostUserMemoryRegionInfo) -> Result<()> {
        let body = VhostUserSingleMemoryRegion::new(
            region.guest_phys_addr,
            region.memory_size,
            region.userspace_addr,
            region.mmap_offset,
        );
        let fds = [region.mmap_handle];
        let hdr = self.send_request_with_body(FrontendReq::ADD_MEM_REG, &body, Some(&fds))?;
        self.wait_for_ack(&hdr)
    }

    /// Remove a guest memory mapping from vhost.
    pub fn remove_mem_region(&self, region: &VhostUserMemoryRegionInfo) -> Result<()> {
        let body = VhostUserSingleMemoryRegion::new(
            region.guest_phys_addr,
            region.memory_size,
            region.userspace_addr,
            region.mmap_offset,
        );
        let hdr = self.send_request_with_body(FrontendReq::REM_MEM_REG, &body, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Get the shared memory configuration.
    pub fn get_shmem_config(&self) -> Result<Vec<u64>> {
        let hdr = self.send_request_header(FrontendReq::GET_SHMEM_CONFIG, None)?;
        let (body_reply, buf_reply, _rfds) =
            self.recv_reply_with_payload::<VhostUserShMemConfigHeader>(&hdr)?;
        let mut memory_sizes = Vec::new();
        for i in 0..body_reply.nregions {
            const U64_SIZE: usize = mem::size_of::<u64>();
            let offset = (i as usize) * U64_SIZE;
            let value =
                VhostUserU64::read_from_bytes(&buf_reply[offset..(offset + U64_SIZE)]).unwrap();
            memory_sizes.push(value.value);
        }
        Ok(memory_sizes)
    }

    fn send_request_header(
        &self,
        code: FrontendReq,
        fds: Option<&[RawDescriptor]>,
    ) -> VhostUserResult<VhostUserMsgHeader<FrontendReq>> {
        let hdr = self.new_request_header(code, 0);
        self.connection.send_header_only_message(&hdr, fds)?;
        Ok(hdr)
    }

    fn send_request_with_body<T: IntoBytes + Immutable>(
        &self,
        code: FrontendReq,
        msg: &T,
        fds: Option<&[RawDescriptor]>,
    ) -> VhostUserResult<VhostUserMsgHeader<FrontendReq>> {
        let hdr = self.new_request_header(code, mem::size_of::<T>() as u32);
        self.connection.send_message(&hdr, msg, fds)?;
        Ok(hdr)
    }

    fn send_request_with_payload<T: IntoBytes + Immutable>(
        &self,
        code: FrontendReq,
        msg: &T,
        payload: &[u8],
        fds: Option<&[RawDescriptor]>,
    ) -> VhostUserResult<VhostUserMsgHeader<FrontendReq>> {
        let len = mem::size_of::<T>()
            .checked_add(payload.len())
            .ok_or(VhostUserError::OversizedMsg)?;
        let hdr = self.new_request_header(
            code,
            len.try_into().map_err(VhostUserError::InvalidCastToInt)?,
        );
        self.connection
            .send_message_with_payload(&hdr, msg, payload, fds)?;
        Ok(hdr)
    }

    fn send_fd_for_vring(
        &self,
        code: FrontendReq,
        queue_index: usize,
        fd: RawDescriptor,
    ) -> VhostUserResult<VhostUserMsgHeader<FrontendReq>> {
        // Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag.
        // This flag is set when there is no file descriptor in the ancillary data. This signals
        // that polling will be used instead of waiting for the call.
        let msg = VhostUserU64::new(queue_index as u64);
        let hdr = self.new_request_header(code, mem::size_of::<VhostUserU64>() as u32);
        self.connection.send_message(&hdr, &msg, Some(&[fd]))?;
        Ok(hdr)
    }

    fn recv_reply<T: Sized + FromBytes + IntoBytes + Default + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
    ) -> VhostUserResult<T> {
        if hdr.is_reply() {
            return Err(VhostUserError::InvalidParam(
                "recv_reply: header is not a reply",
            ));
        }
        let (reply, body, rfds) = self.connection.recv_message::<T>()?;
        if !reply.is_valid() || !reply.is_reply_for(hdr) || !rfds.is_empty() || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }
        Ok(body)
    }

    fn recv_reply_with_files<T: Sized + IntoBytes + FromBytes + Default + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
    ) -> VhostUserResult<(T, Vec<File>)> {
        if hdr.is_reply() {
            return Err(VhostUserError::InvalidParam(
                "with_files: expected a reply, but the header is not marked as a reply",
            ));
        }

        let (reply, body, files) = self.connection.recv_message::<T>()?;
        if !reply.is_valid() || !reply.is_reply_for(hdr) || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }
        Ok((body, files))
    }

    fn recv_reply_with_payload<
        T: Sized + IntoBytes + FromBytes + Default + VhostUserMsgValidator,
    >(
        &self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
    ) -> VhostUserResult<(T, Vec<u8>, Vec<File>)> {
        if hdr.is_reply() {
            return Err(VhostUserError::InvalidParam(
                "with_payload: expected a reply, but the header is not marked as a reply",
            ));
        }

        let (reply, body, buf, files, more_files) =
            self.connection.recv_message_with_payload::<T>()?;
        if !reply.is_valid()
            || !reply.is_reply_for(hdr)
            || !files.is_empty()
            || !more_files.is_empty()
            || !body.is_valid()
        {
            return Err(VhostUserError::InvalidMessage);
        }

        Ok((body, buf, files))
    }

    fn wait_for_ack(&self, hdr: &VhostUserMsgHeader<FrontendReq>) -> VhostUserResult<()> {
        if !hdr.is_need_reply() {
            return Ok(());
        }

        let (reply, body, rfds) = self.connection.recv_message::<VhostUserU64>()?;
        if !reply.is_valid() || !reply.is_reply_for(hdr) || !rfds.is_empty() || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }
        if body.value != 0 {
            return Err(VhostUserError::BackendInternalError);
        }
        Ok(())
    }

    #[inline]
    fn new_request_header(
        &self,
        request: FrontendReq,
        size: u32,
    ) -> VhostUserMsgHeader<FrontendReq> {
        VhostUserMsgHeader::new(request, 0x1, size)
    }
}

#[cfg(windows)]
impl CloseNotifier for BackendClient {
    fn get_close_notifier(&self) -> &dyn AsRawDescriptor {
        self.connection.0.get_close_notifier()
    }
}

impl ReadNotifier for BackendClient {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self.connection.0.get_read_notifier()
    }
}

// TODO(b/221882601): likely need pairs of RDs and/or SharedMemory to represent mmaps on Windows.
/// Context object to pass guest memory configuration to BackendClient::set_mem_table().
struct VhostUserMemoryContext {
    regions: VhostUserMemoryPayload,
    fds: Vec<RawDescriptor>,
}

impl VhostUserMemoryContext {
    /// Create a context object.
    pub fn new() -> Self {
        VhostUserMemoryContext {
            regions: VhostUserMemoryPayload::new(),
            fds: Vec::new(),
        }
    }

    /// Append a user memory region and corresponding RawDescriptor into the context object.
    pub fn append(&mut self, region: &VhostUserMemoryRegion, fd: RawDescriptor) {
        self.regions.push(*region);
        self.fds.push(fd);
    }
}

#[cfg(test)]
mod tests {
    use base::INVALID_DESCRIPTOR;

    use super::*;

    const BUFFER_SIZE: usize = 0x1001;
    const INVALID_PROTOCOL_FEATURE: u64 = 1 << 63;

    fn create_pair() -> (BackendClient, Connection<FrontendReq>) {
        let (client_connection, server_connection) = Connection::pair().unwrap();
        let backend_client = BackendClient::new(client_connection);
        (backend_client, server_connection)
    }

    #[test]
    fn create_backend_client() {
        let (backend_client, peer) = create_pair();

        assert!(backend_client.connection.as_raw_descriptor() != INVALID_DESCRIPTOR);
        // Send two messages continuously
        backend_client.set_owner().unwrap();
        backend_client.reset_owner().unwrap();

        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code(), Ok(FrontendReq::SET_OWNER));
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_empty());

        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code(), Ok(FrontendReq::RESET_OWNER));
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_empty());
    }

    #[test]
    fn test_features() {
        let (mut backend_client, peer) = create_pair();

        backend_client.set_owner().unwrap();
        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code(), Ok(FrontendReq::SET_OWNER));
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_empty());

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(0x15);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = backend_client.get_features().unwrap();
        assert_eq!(features, 0x15u64);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_empty());

        let hdr = VhostUserMsgHeader::new(FrontendReq::SET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(0x15);
        peer.send_message(&hdr, &msg, None).unwrap();
        backend_client.set_features(0x15).unwrap();
        let (_hdr, msg, rfds) = peer.recv_message::<VhostUserU64>().unwrap();
        assert!(rfds.is_empty());
        let val = msg.value;
        assert_eq!(val, 0x15);

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_FEATURES, 0x4, 8);
        let msg = 0x15u32;
        peer.send_message(&hdr, &msg, None).unwrap();
        assert!(backend_client.get_features().is_err());
    }

    #[test]
    fn test_protocol_features() {
        let (mut backend_client, peer) = create_pair();

        backend_client.set_owner().unwrap();
        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code(), Ok(FrontendReq::SET_OWNER));
        assert!(rfds.is_empty());

        let pfeatures = VhostUserProtocolFeatures::all();
        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_PROTOCOL_FEATURES, 0x4, 8);
        // Unknown feature bits should be ignored.
        let msg = VhostUserU64::new(pfeatures.bits() | INVALID_PROTOCOL_FEATURE);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = backend_client.get_protocol_features().unwrap();
        assert_eq!(features, pfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_empty());

        backend_client
            .set_protocol_features(VhostUserProtocolFeatures::all())
            .unwrap();
        let (_hdr, msg, rfds) = peer.recv_message::<VhostUserU64>().unwrap();
        assert!(rfds.is_empty());
        let val = msg.value;
        assert_eq!(val, pfeatures.bits());

        let vfeatures = 0x15 | 1 << VHOST_USER_F_PROTOCOL_FEATURES;
        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(vfeatures);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = backend_client.get_features().unwrap();
        assert_eq!(features, vfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_empty());

        backend_client.set_features(vfeatures).unwrap();
        let (_hdr, msg, rfds) = peer.recv_message::<VhostUserU64>().unwrap();
        assert!(rfds.is_empty());
        let val = msg.value;
        assert_eq!(val, vfeatures);

        let pfeatures = VhostUserProtocolFeatures::all();
        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_PROTOCOL_FEATURES, 0x4, 8);
        // Unknown feature bits should be ignored.
        let msg = VhostUserU64::new(pfeatures.bits() | INVALID_PROTOCOL_FEATURE);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = backend_client.get_protocol_features().unwrap();
        assert_eq!(features, pfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_empty());

        backend_client.set_protocol_features(pfeatures).unwrap();
        let (_hdr, msg, rfds) = peer.recv_message::<VhostUserU64>().unwrap();
        assert!(rfds.is_empty());
        let val = msg.value;
        assert_eq!(val, pfeatures.bits());

        let hdr = VhostUserMsgHeader::new(FrontendReq::SET_PROTOCOL_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(pfeatures.bits());
        peer.send_message(&hdr, &msg, None).unwrap();
        assert!(backend_client.get_protocol_features().is_err());
    }

    #[test]
    fn test_backend_client_get_config_negative0() {
        let (backend_client, peer) = create_pair();
        let buf = vec![0x0; BUFFER_SIZE];

        let mut hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        hdr.set_code(FrontendReq::GET_FEATURES);
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
        hdr.set_code(FrontendReq::GET_CONFIG);
    }

    #[test]
    fn test_backend_client_get_config_negative1() {
        let (backend_client, peer) = create_pair();
        let buf = vec![0x0; BUFFER_SIZE];

        let mut hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        hdr.set_reply(false);
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_backend_client_get_config_negative2() {
        let (backend_client, peer) = create_pair();
        let buf = vec![0x0; BUFFER_SIZE];

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());
    }

    #[test]
    fn test_backend_client_get_config_negative3() {
        let (backend_client, peer) = create_pair();
        let buf = vec![0x0; BUFFER_SIZE];

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.offset = 0;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_backend_client_get_config_negative4() {
        let (backend_client, peer) = create_pair();
        let buf = vec![0x0; BUFFER_SIZE];

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.offset = 0x101;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_backend_client_get_config_negative5() {
        let (backend_client, peer) = create_pair();
        let buf = vec![0x0; BUFFER_SIZE];

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.offset = (BUFFER_SIZE) as u32;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_backend_client_get_config_negative6() {
        let (backend_client, peer) = create_pair();
        let buf = vec![0x0; BUFFER_SIZE];

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.size = 6;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..6], None)
            .unwrap();
        assert!(backend_client
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }
}
