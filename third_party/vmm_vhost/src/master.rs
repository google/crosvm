// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Traits and Struct for vhost-user master.

use std::fs::File;
use std::mem;
use std::path::Path;

use anyhow::anyhow;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use base::INVALID_DESCRIPTOR;
use data_model::zerocopy_from_reader;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::backend::VhostUserMemoryRegionInfo;
use crate::backend::VringConfigData;
use crate::into_single_file;
use crate::message::*;
use crate::Connection;
use crate::Error as VhostUserError;
use crate::MasterReq;
use crate::Result as VhostUserResult;
use crate::Result;
use crate::SystemStream;

/// Client for a vhost-user device. The API is a thin abstraction over the vhost-user protocol.
pub struct Master {
    // Used to send requests to the slave.
    main_sock: Connection<MasterReq>,
    // Cached virtio features from the slave.
    virtio_features: u64,
    // Cached acked virtio features from the driver.
    acked_virtio_features: u64,
    // Cached vhost-user protocol features.
    acked_protocol_features: u64,
}

impl Master {
    /// Create a new instance from a Unix stream socket.
    pub fn from_stream(sock: SystemStream) -> Self {
        Self::new(Connection::from(sock))
    }

    /// Create a new instance.
    fn new(ep: Connection<MasterReq>) -> Self {
        Master {
            main_sock: ep,
            virtio_features: 0,
            acked_virtio_features: 0,
            acked_protocol_features: 0,
        }
    }

    /// Create a new vhost-user master connection.
    ///
    /// Will retry as the backend may not be ready to accept the connection.
    ///
    /// # Arguments
    /// * `path` - path of Unix domain socket listener to connect to
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut retry_count = 5;
        let connection = loop {
            match Connection::connect(&path) {
                Ok(connection) => break Ok(connection),
                Err(e) => match &e {
                    VhostUserError::SocketConnect(why) => {
                        if why.kind() == std::io::ErrorKind::ConnectionRefused && retry_count > 0 {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                            retry_count -= 1;
                            continue;
                        } else {
                            break Err(e);
                        }
                    }
                    _ => break Err(e),
                },
            }
        }?;

        Ok(Self::new(connection))
    }

    /// Get a bitmask of supported virtio/vhost features.
    pub fn get_features(&mut self) -> Result<u64> {
        let hdr = self.send_request_header(MasterReq::GET_FEATURES, None)?;
        let val = self.recv_reply::<VhostUserU64>(&hdr)?;
        self.virtio_features = val.value;
        Ok(self.virtio_features)
    }

    /// Inform the vhost subsystem which features to enable.
    /// This should be a subset of supported features from get_features().
    pub fn set_features(&mut self, features: u64) -> Result<()> {
        let val = VhostUserU64::new(features);
        let hdr = self.send_request_with_body(MasterReq::SET_FEATURES, &val, None)?;
        self.acked_virtio_features = features & self.virtio_features;
        self.wait_for_ack(&hdr)
    }

    /// Set the current process as the owner of the vhost backend.
    /// This must be run before any other vhost commands.
    pub fn set_owner(&self) -> Result<()> {
        let hdr = self.send_request_header(MasterReq::SET_OWNER, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Used to be sent to request disabling all rings
    /// This is no longer used.
    pub fn reset_owner(&self) -> Result<()> {
        let hdr = self.send_request_header(MasterReq::RESET_OWNER, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Set the memory map regions on the slave so it can translate the vring
    /// addresses. In the ancillary data there is an array of file descriptors
    pub fn set_mem_table(&self, regions: &[VhostUserMemoryRegionInfo]) -> Result<()> {
        if regions.is_empty() || regions.len() > MAX_ATTACHED_FD_ENTRIES {
            return Err(VhostUserError::InvalidParam);
        }

        let mut ctx = VhostUserMemoryContext::new();
        for region in regions.iter() {
            if region.memory_size == 0 || region.mmap_handle == INVALID_DESCRIPTOR {
                return Err(VhostUserError::InvalidParam);
            }

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
            MasterReq::SET_MEM_TABLE,
            &body,
            ctx.regions.as_bytes(),
            Some(ctx.fds.as_slice()),
        )?;
        self.wait_for_ack(&hdr)
    }

    /// Set base address for page modification logging.
    pub fn set_log_base(&self, base: u64, fd: Option<RawDescriptor>) -> Result<()> {
        let val = VhostUserU64::new(base);

        let should_have_fd =
            self.acked_protocol_features & VhostUserProtocolFeatures::LOG_SHMFD.bits() != 0;
        if should_have_fd != fd.is_some() {
            return Err(VhostUserError::InvalidParam);
        }

        let _ = self.send_request_with_body(
            MasterReq::SET_LOG_BASE,
            &val,
            fd.as_ref().map(std::slice::from_ref),
        )?;

        Ok(())
    }

    /// Specify an event file descriptor to signal on log write.
    pub fn set_log_fd(&self, fd: RawDescriptor) -> Result<()> {
        let fds = [fd];
        let hdr = self.send_request_header(MasterReq::SET_LOG_FD, Some(&fds))?;
        self.wait_for_ack(&hdr)
    }

    /// Set the number of descriptors in the vring.
    pub fn set_vring_num(&self, queue_index: usize, num: u16) -> Result<()> {
        let val = VhostUserVringState::new(queue_index as u32, num.into());
        let hdr = self.send_request_with_body(MasterReq::SET_VRING_NUM, &val, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Set the addresses for a given vring.
    pub fn set_vring_addr(&self, queue_index: usize, config_data: &VringConfigData) -> Result<()> {
        if config_data.flags & !(VhostUserVringAddrFlags::all().bits()) != 0 {
            return Err(VhostUserError::InvalidParam);
        }

        let val = VhostUserVringAddr::from_config_data(queue_index as u32, config_data);
        let hdr = self.send_request_with_body(MasterReq::SET_VRING_ADDR, &val, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Set the first index to look for available descriptors.
    pub fn set_vring_base(&self, queue_index: usize, base: u16) -> Result<()> {
        let val = VhostUserVringState::new(queue_index as u32, base.into());
        let hdr = self.send_request_with_body(MasterReq::SET_VRING_BASE, &val, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Get the available vring base offset.
    pub fn get_vring_base(&self, queue_index: usize) -> Result<u32> {
        let req = VhostUserVringState::new(queue_index as u32, 0);
        let hdr = self.send_request_with_body(MasterReq::GET_VRING_BASE, &req, None)?;
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
            MasterReq::SET_VRING_CALL,
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
            MasterReq::SET_VRING_KICK,
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
            MasterReq::SET_VRING_ERR,
            queue_index,
            event.as_raw_descriptor(),
        )?;
        self.wait_for_ack(&hdr)
    }

    /// Put the device to sleep.
    pub fn sleep(&self) -> Result<()> {
        let hdr = self.send_request_header(MasterReq::SLEEP, None)?;
        let reply = self.recv_reply::<VhostUserSuccess>(&hdr)?;
        if !reply.success() {
            Err(VhostUserError::SleepError(anyhow!(
                "Device process responded with a failure on SLEEP."
            )))
        } else {
            Ok(())
        }
    }

    /// Wake the device up.
    pub fn wake(&self) -> Result<()> {
        let hdr = self.send_request_header(MasterReq::WAKE, None)?;
        let reply = self.recv_reply::<VhostUserSuccess>(&hdr)?;
        if !reply.success() {
            Err(VhostUserError::WakeError(anyhow!(
                "Device process responded with a failure on WAKE."
            )))
        } else {
            Ok(())
        }
    }

    /// Snapshot the device and receive serialized state of the device.
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        let hdr = self.send_request_header(MasterReq::SNAPSHOT, None)?;
        let (success_msg, buf_reply, _) = self.recv_reply_with_payload::<VhostUserSuccess>(&hdr)?;
        if !success_msg.success() {
            Err(VhostUserError::SnapshotError(anyhow!(
                "Device process responded with a failure on SNAPSHOT."
            )))
        } else {
            Ok(buf_reply)
        }
    }

    /// Restore the device.
    pub fn restore(&mut self, data_bytes: &[u8], queue_evts: Option<Vec<Event>>) -> Result<()> {
        let body = VhostUserEmptyMsg;

        let queue_evt_fds: Option<Vec<RawDescriptor>> = queue_evts.as_ref().map(|queue_evts| {
            queue_evts
                .iter()
                .map(|queue_evt| queue_evt.as_raw_descriptor())
                .collect()
        });

        let hdr = self.send_request_with_payload(
            MasterReq::RESTORE,
            &body,
            data_bytes,
            queue_evt_fds.as_deref(),
        )?;
        let reply = self.recv_reply::<VhostUserSuccess>(&hdr)?;
        if !reply.success() {
            Err(VhostUserError::RestoreError(anyhow!(
                "Device process responded with a failure on RESTORE."
            )))
        } else {
            Ok(())
        }
    }

    /// Get the protocol feature bitmask from the underlying vhost implementation.
    pub fn get_protocol_features(&self) -> Result<VhostUserProtocolFeatures> {
        if self.virtio_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES == 0 {
            return Err(VhostUserError::InvalidOperation);
        }
        let hdr = self.send_request_header(MasterReq::GET_PROTOCOL_FEATURES, None)?;
        let val = self.recv_reply::<VhostUserU64>(&hdr)?;
        // Should we support forward compatibility?
        // If so just mask out unrecognized flags instead of return errors.
        match VhostUserProtocolFeatures::from_bits(val.value) {
            Some(val) => Ok(val),
            None => Err(VhostUserError::InvalidMessage),
        }
    }

    /// Enable protocol features in the underlying vhost implementation.
    pub fn set_protocol_features(&mut self, features: VhostUserProtocolFeatures) -> Result<()> {
        if self.virtio_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES == 0 {
            return Err(VhostUserError::InvalidOperation);
        }
        if features.contains(VhostUserProtocolFeatures::SHARED_MEMORY_REGIONS)
            && !features.contains(VhostUserProtocolFeatures::SLAVE_REQ)
        {
            return Err(VhostUserError::FeatureMismatch);
        }
        let val = VhostUserU64::new(features.bits());
        let hdr = self.send_request_with_body(MasterReq::SET_PROTOCOL_FEATURES, &val, None)?;
        // Don't wait for ACK here because the protocol feature negotiation process hasn't been
        // completed yet.
        self.acked_protocol_features = features.bits();
        self.wait_for_ack(&hdr)
    }

    /// Query how many queues the backend supports.
    pub fn get_queue_num(&self) -> Result<u64> {
        if !self.is_feature_mq_available() {
            return Err(VhostUserError::InvalidOperation);
        }

        let hdr = self.send_request_header(MasterReq::GET_QUEUE_NUM, None)?;
        let val = self.recv_reply::<VhostUserU64>(&hdr)?;
        if val.value > VHOST_USER_MAX_VRINGS {
            return Err(VhostUserError::InvalidMessage);
        }
        Ok(val.value)
    }

    /// Signal slave to enable or disable corresponding vring.
    ///
    /// Slave must not pass data to/from the backend until ring is enabled by
    /// VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has been
    /// disabled by VHOST_USER_SET_VRING_ENABLE with parameter 0.
    pub fn set_vring_enable(&self, queue_index: usize, enable: bool) -> Result<()> {
        // set_vring_enable() is supported only when PROTOCOL_FEATURES has been enabled.
        if self.acked_virtio_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES == 0 {
            return Err(VhostUserError::InvalidOperation);
        }

        let val = VhostUserVringState::new(queue_index as u32, enable.into());
        let hdr = self.send_request_with_body(MasterReq::SET_VRING_ENABLE, &val, None)?;
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
        if !body.is_valid() {
            return Err(VhostUserError::InvalidParam);
        }

        // depends on VhostUserProtocolFeatures::CONFIG
        if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
            return Err(VhostUserError::InvalidOperation);
        }

        // vhost-user spec states that:
        // "Master payload: virtio device config space"
        // "Slave payload: virtio device config space"
        let hdr = self.send_request_with_payload(MasterReq::GET_CONFIG, &body, buf, None)?;
        let (body_reply, buf_reply, rfds) =
            self.recv_reply_with_payload::<VhostUserConfig>(&hdr)?;
        if !rfds.is_empty() {
            return Err(VhostUserError::InvalidMessage);
        } else if body_reply.size == 0 {
            return Err(VhostUserError::SlaveInternalError);
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
        if !body.is_valid() {
            return Err(VhostUserError::InvalidParam);
        }

        // depends on VhostUserProtocolFeatures::CONFIG
        if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
            return Err(VhostUserError::InvalidOperation);
        }

        let hdr = self.send_request_with_payload(MasterReq::SET_CONFIG, &body, buf, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Setup slave communication channel.
    pub fn set_slave_request_fd(&self, fd: &dyn AsRawDescriptor) -> Result<()> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::SLAVE_REQ.bits() == 0 {
            return Err(VhostUserError::InvalidOperation);
        }
        let fds = [fd.as_raw_descriptor()];
        let hdr = self.send_request_header(MasterReq::SET_SLAVE_REQ_FD, Some(&fds))?;
        self.wait_for_ack(&hdr)
    }

    /// Retrieve shared buffer for inflight I/O tracking.
    pub fn get_inflight_fd(
        &self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits() == 0 {
            return Err(VhostUserError::InvalidOperation);
        }

        let hdr = self.send_request_with_body(MasterReq::GET_INFLIGHT_FD, inflight, None)?;
        let (inflight, files) = self.recv_reply_with_files::<VhostUserInflight>(&hdr)?;

        match into_single_file(files) {
            Some(file) => Ok((inflight, file)),
            None => Err(VhostUserError::IncorrectFds),
        }
    }

    /// Set shared buffer for inflight I/O tracking.
    pub fn set_inflight_fd(&self, inflight: &VhostUserInflight, fd: RawDescriptor) -> Result<()> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits() == 0 {
            return Err(VhostUserError::InvalidOperation);
        }

        if inflight.mmap_size == 0
            || inflight.num_queues == 0
            || inflight.queue_size == 0
            || fd == INVALID_DESCRIPTOR
        {
            return Err(VhostUserError::InvalidParam);
        }

        let hdr = self.send_request_with_body(MasterReq::SET_INFLIGHT_FD, inflight, Some(&[fd]))?;
        self.wait_for_ack(&hdr)
    }

    /// Query the maximum amount of memory slots supported by the backend.
    pub fn get_max_mem_slots(&self) -> Result<u64> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits() == 0
        {
            return Err(VhostUserError::InvalidOperation);
        }

        let hdr = self.send_request_header(MasterReq::GET_MAX_MEM_SLOTS, None)?;
        let val = self.recv_reply::<VhostUserU64>(&hdr)?;

        Ok(val.value)
    }

    /// Add a new guest memory mapping for vhost to use.
    pub fn add_mem_region(&self, region: &VhostUserMemoryRegionInfo) -> Result<()> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits() == 0
        {
            return Err(VhostUserError::InvalidOperation);
        }

        if region.memory_size == 0 || region.mmap_handle == INVALID_DESCRIPTOR {
            return Err(VhostUserError::InvalidParam);
        }

        let body = VhostUserSingleMemoryRegion::new(
            region.guest_phys_addr,
            region.memory_size,
            region.userspace_addr,
            region.mmap_offset,
        );
        let fds = [region.mmap_handle];
        let hdr = self.send_request_with_body(MasterReq::ADD_MEM_REG, &body, Some(&fds))?;
        self.wait_for_ack(&hdr)
    }

    /// Remove a guest memory mapping from vhost.
    pub fn remove_mem_region(&self, region: &VhostUserMemoryRegionInfo) -> Result<()> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits() == 0
        {
            return Err(VhostUserError::InvalidOperation);
        }
        if region.memory_size == 0 {
            return Err(VhostUserError::InvalidParam);
        }

        let body = VhostUserSingleMemoryRegion::new(
            region.guest_phys_addr,
            region.memory_size,
            region.userspace_addr,
            region.mmap_offset,
        );
        let hdr = self.send_request_with_body(MasterReq::REM_MEM_REG, &body, None)?;
        self.wait_for_ack(&hdr)
    }

    /// Gets the shared memory regions used by the device.
    pub fn get_shared_memory_regions(&self) -> Result<Vec<VhostSharedMemoryRegion>> {
        let hdr = self.send_request_header(MasterReq::GET_SHARED_MEMORY_REGIONS, None)?;
        let (body_reply, buf_reply, rfds) = self.recv_reply_with_payload::<VhostUserU64>(&hdr)?;
        let struct_size = mem::size_of::<VhostSharedMemoryRegion>();
        if !rfds.is_empty() || buf_reply.len() != body_reply.value as usize * struct_size {
            return Err(VhostUserError::InvalidMessage);
        }
        let mut regions = Vec::new();
        let mut offset = 0;
        for _ in 0..body_reply.value {
            regions.push(
                // Can't fail because the input is the correct size.
                zerocopy_from_reader(&buf_reply[offset..(offset + struct_size)]).unwrap(),
            );
            offset += struct_size;
        }
        Ok(regions)
    }

    fn send_request_header(
        &self,
        code: MasterReq,
        fds: Option<&[RawDescriptor]>,
    ) -> VhostUserResult<VhostUserMsgHeader<MasterReq>> {
        let hdr = self.new_request_header(code, 0);
        self.main_sock.send_header_only_message(&hdr, fds)?;
        Ok(hdr)
    }

    fn send_request_with_body<T: Sized + AsBytes>(
        &self,
        code: MasterReq,
        msg: &T,
        fds: Option<&[RawDescriptor]>,
    ) -> VhostUserResult<VhostUserMsgHeader<MasterReq>> {
        let hdr = self.new_request_header(code, mem::size_of::<T>() as u32);
        self.main_sock.send_message(&hdr, msg, fds)?;
        Ok(hdr)
    }

    fn send_request_with_payload<T: Sized + AsBytes>(
        &self,
        code: MasterReq,
        msg: &T,
        payload: &[u8],
        fds: Option<&[RawDescriptor]>,
    ) -> VhostUserResult<VhostUserMsgHeader<MasterReq>> {
        if let Some(fd_arr) = fds {
            if fd_arr.len() > MAX_ATTACHED_FD_ENTRIES {
                return Err(VhostUserError::InvalidParam);
            }
        }
        let len = mem::size_of::<T>()
            .checked_add(payload.len())
            .ok_or(VhostUserError::OversizedMsg)?;
        let hdr = self.new_request_header(
            code,
            len.try_into().map_err(VhostUserError::InvalidCastToInt)?,
        );
        self.main_sock
            .send_message_with_payload(&hdr, msg, payload, fds)?;
        Ok(hdr)
    }

    fn send_fd_for_vring(
        &self,
        code: MasterReq,
        queue_index: usize,
        fd: RawDescriptor,
    ) -> VhostUserResult<VhostUserMsgHeader<MasterReq>> {
        // Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag.
        // This flag is set when there is no file descriptor in the ancillary data. This signals
        // that polling will be used instead of waiting for the call.
        let msg = VhostUserU64::new(queue_index as u64);
        let hdr = self.new_request_header(code, mem::size_of::<VhostUserU64>() as u32);
        self.main_sock.send_message(&hdr, &msg, Some(&[fd]))?;
        Ok(hdr)
    }

    fn recv_reply<T: Sized + FromBytes + AsBytes + Default + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<MasterReq>,
    ) -> VhostUserResult<T> {
        if hdr.is_reply() {
            return Err(VhostUserError::InvalidParam);
        }
        let (reply, body, rfds) = self.main_sock.recv_message::<T>()?;
        if !reply.is_reply_for(hdr) || !rfds.is_empty() || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }
        Ok(body)
    }

    fn recv_reply_with_files<T: Sized + AsBytes + FromBytes + Default + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<MasterReq>,
    ) -> VhostUserResult<(T, Vec<File>)> {
        if hdr.is_reply() {
            return Err(VhostUserError::InvalidParam);
        }

        let (reply, body, files) = self.main_sock.recv_message::<T>()?;
        if !reply.is_reply_for(hdr) || files.is_empty() || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }
        Ok((body, files))
    }

    fn recv_reply_with_payload<T: Sized + AsBytes + FromBytes + Default + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<MasterReq>,
    ) -> VhostUserResult<(T, Vec<u8>, Vec<File>)> {
        if hdr.is_reply() {
            return Err(VhostUserError::InvalidParam);
        }

        let (reply, body, buf, files) = self.main_sock.recv_message_with_payload::<T>()?;
        if !reply.is_reply_for(hdr) || !files.is_empty() || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }

        Ok((body, buf, files))
    }

    fn wait_for_ack(&self, hdr: &VhostUserMsgHeader<MasterReq>) -> VhostUserResult<()> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::REPLY_ACK.bits() == 0
            || !hdr.is_need_reply()
        {
            return Ok(());
        }

        let (reply, body, rfds) = self.main_sock.recv_message::<VhostUserU64>()?;
        if !reply.is_reply_for(hdr) || !rfds.is_empty() || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }
        if body.value != 0 {
            return Err(VhostUserError::SlaveInternalError);
        }
        Ok(())
    }

    fn is_feature_mq_available(&self) -> bool {
        self.acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0
    }

    #[inline]
    fn new_request_header(&self, request: MasterReq, size: u32) -> VhostUserMsgHeader<MasterReq> {
        VhostUserMsgHeader::new(request, 0x1, size)
    }
}

// TODO(b/221882601): likely need pairs of RDs and/or SharedMemory to represent mmaps on Windows.
/// Context object to pass guest memory configuration to Master::set_mem_table().
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
    use tempfile::tempfile;

    use super::*;
    use crate::connection::tests::create_pair;

    const BUFFER_SIZE: usize = 0x1001;

    #[test]
    fn create_master() {
        let (master, slave) = create_pair();

        assert!(master.main_sock.as_raw_descriptor() != INVALID_DESCRIPTOR);
        // Send two messages continuously
        master.set_owner().unwrap();
        master.reset_owner().unwrap();

        let (hdr, rfds) = slave.recv_header().unwrap();
        assert_eq!(hdr.get_code(), Ok(MasterReq::SET_OWNER));
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_empty());

        let (hdr, rfds) = slave.recv_header().unwrap();
        assert_eq!(hdr.get_code(), Ok(MasterReq::RESET_OWNER));
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_empty());
    }

    #[test]
    fn test_features() {
        let (mut master, peer) = create_pair();

        master.set_owner().unwrap();
        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code(), Ok(MasterReq::SET_OWNER));
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_empty());

        let hdr = VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(0x15);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = master.get_features().unwrap();
        assert_eq!(features, 0x15u64);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_empty());

        let hdr = VhostUserMsgHeader::new(MasterReq::SET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(0x15);
        peer.send_message(&hdr, &msg, None).unwrap();
        master.set_features(0x15).unwrap();
        let (_hdr, msg, rfds) = peer.recv_message::<VhostUserU64>().unwrap();
        assert!(rfds.is_empty());
        let val = msg.value;
        assert_eq!(val, 0x15);

        let hdr = VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0x4, 8);
        let msg = 0x15u32;
        peer.send_message(&hdr, &msg, None).unwrap();
        assert!(master.get_features().is_err());
    }

    #[test]
    fn test_protocol_features() {
        let (mut master, peer) = create_pair();

        master.set_owner().unwrap();
        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code(), Ok(MasterReq::SET_OWNER));
        assert!(rfds.is_empty());

        assert!(master.get_protocol_features().is_err());
        assert!(master
            .set_protocol_features(VhostUserProtocolFeatures::all())
            .is_err());

        let vfeatures = 0x15 | 1 << VHOST_USER_F_PROTOCOL_FEATURES;
        let hdr = VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(vfeatures);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = master.get_features().unwrap();
        assert_eq!(features, vfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_empty());

        master.set_features(vfeatures).unwrap();
        let (_hdr, msg, rfds) = peer.recv_message::<VhostUserU64>().unwrap();
        assert!(rfds.is_empty());
        let val = msg.value;
        assert_eq!(val, vfeatures);

        let pfeatures = VhostUserProtocolFeatures::all();
        let hdr = VhostUserMsgHeader::new(MasterReq::GET_PROTOCOL_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(pfeatures.bits());
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = master.get_protocol_features().unwrap();
        assert_eq!(features, pfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_empty());

        master.set_protocol_features(pfeatures).unwrap();
        let (_hdr, msg, rfds) = peer.recv_message::<VhostUserU64>().unwrap();
        assert!(rfds.is_empty());
        let val = msg.value;
        assert_eq!(val, pfeatures.bits());

        let hdr = VhostUserMsgHeader::new(MasterReq::SET_PROTOCOL_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(pfeatures.bits());
        peer.send_message(&hdr, &msg, None).unwrap();
        assert!(master.get_protocol_features().is_err());
    }

    #[test]
    fn test_master_set_config_negative() {
        let (mut master, _peer) = create_pair();
        let buf = vec![0x0; BUFFER_SIZE];

        master
            .set_config(0x100, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .unwrap_err();

        master.virtio_features = 0xffff_ffff;
        master.acked_virtio_features = 0xffff_ffff;
        master.acked_protocol_features = 0xffff_ffff;

        master
            .set_config(0, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .unwrap();
        master
            .set_config(
                VHOST_USER_CONFIG_SIZE,
                VhostUserConfigFlags::WRITABLE,
                &buf[0..4],
            )
            .unwrap_err();
        master
            .set_config(0x1000, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .unwrap_err();
        master
            .set_config(
                0x100,
                VhostUserConfigFlags::from_bits_retain(0xffff_ffff),
                &buf[0..4],
            )
            .unwrap_err();
        master
            .set_config(VHOST_USER_CONFIG_SIZE, VhostUserConfigFlags::WRITABLE, &buf)
            .unwrap_err();
        master
            .set_config(VHOST_USER_CONFIG_SIZE, VhostUserConfigFlags::WRITABLE, &[])
            .unwrap_err();
    }

    fn create_pair2() -> (Master, Connection<MasterReq>) {
        let (mut master, peer) = create_pair();

        master.virtio_features = 0xffff_ffff;
        master.acked_virtio_features = 0xffff_ffff;
        master.acked_protocol_features = 0xffff_ffff;

        (master, peer)
    }

    #[test]
    fn test_master_get_config_negative0() {
        let (master, peer) = create_pair2();
        let buf = vec![0x0; BUFFER_SIZE];

        let mut hdr = VhostUserMsgHeader::new(MasterReq::GET_CONFIG, 0x4, 16);
        let msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        hdr.set_code(MasterReq::GET_FEATURES);
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
        hdr.set_code(MasterReq::GET_CONFIG);
    }

    #[test]
    fn test_master_get_config_negative1() {
        let (master, peer) = create_pair2();
        let buf = vec![0x0; BUFFER_SIZE];

        let mut hdr = VhostUserMsgHeader::new(MasterReq::GET_CONFIG, 0x4, 16);
        let msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        hdr.set_reply(false);
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_master_get_config_negative2() {
        let (master, peer) = create_pair2();
        let buf = vec![0x0; BUFFER_SIZE];

        let hdr = VhostUserMsgHeader::new(MasterReq::GET_CONFIG, 0x4, 16);
        let msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());
    }

    #[test]
    fn test_master_get_config_negative3() {
        let (master, peer) = create_pair2();
        let buf = vec![0x0; BUFFER_SIZE];

        let hdr = VhostUserMsgHeader::new(MasterReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.offset = 0;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_master_get_config_negative4() {
        let (master, peer) = create_pair2();
        let buf = vec![0x0; BUFFER_SIZE];

        let hdr = VhostUserMsgHeader::new(MasterReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.offset = 0x101;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_master_get_config_negative5() {
        let (master, peer) = create_pair2();
        let buf = vec![0x0; BUFFER_SIZE];

        let hdr = VhostUserMsgHeader::new(MasterReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.offset = (BUFFER_SIZE) as u32;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_master_get_config_negative6() {
        let (master, peer) = create_pair2();
        let buf = vec![0x0; BUFFER_SIZE];

        let hdr = VhostUserMsgHeader::new(MasterReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.size = 6;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..6], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_maset_set_mem_table_failure() {
        let (master, _peer) = create_pair2();

        // set_mem_table() with 0 regions is invalid
        master.set_mem_table(&[]).unwrap_err();

        // set_mem_table() with more than MAX_ATTACHED_FD_ENTRIES is invalid
        let files: Vec<File> = (0..MAX_ATTACHED_FD_ENTRIES + 1)
            .map(|_| tempfile().unwrap())
            .collect();
        let tables: Vec<VhostUserMemoryRegionInfo> = files
            .iter()
            .map(|f| VhostUserMemoryRegionInfo {
                guest_phys_addr: 0,
                memory_size: 0x100000,
                userspace_addr: 0x800000,
                mmap_offset: 0,
                mmap_handle: f.as_raw_descriptor(),
            })
            .collect();
        master.set_mem_table(&tables).unwrap_err();
    }
}
