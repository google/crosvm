// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Traits and Struct for vhost-user master.

use std::fs::File;
use std::mem;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use base::INVALID_DESCRIPTOR;
use data_model::zerocopy_from_reader;
use data_model::DataInit;

use crate::backend::VhostBackend;
use crate::backend::VhostUserMemoryRegionInfo;
use crate::backend::VringConfigData;
use crate::connection::Endpoint;
use crate::connection::EndpointExt;
use crate::message::*;
use crate::take_single_file;
use crate::Error as VhostUserError;
use crate::Result as VhostUserResult;
use crate::Result;
use crate::SystemStream;

/// Trait for vhost-user master to provide extra methods not covered by the VhostBackend yet.
pub trait VhostUserMaster: VhostBackend {
    /// Get the protocol feature bitmask from the underlying vhost implementation.
    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures>;

    /// Enable protocol features in the underlying vhost implementation.
    fn set_protocol_features(&mut self, features: VhostUserProtocolFeatures) -> Result<()>;

    /// Query how many queues the backend supports.
    fn get_queue_num(&mut self) -> Result<u64>;

    /// Signal slave to enable or disable corresponding vring.
    ///
    /// Slave must not pass data to/from the backend until ring is enabled by
    /// VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has been
    /// disabled by VHOST_USER_SET_VRING_ENABLE with parameter 0.
    fn set_vring_enable(&mut self, queue_index: usize, enable: bool) -> Result<()>;

    /// Fetch the contents of the virtio device configuration space.
    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
        buf: &[u8],
    ) -> Result<(VhostUserConfig, VhostUserConfigPayload)>;

    /// Change the virtio device configuration space. It also can be used for live migration on the
    /// destination host to set readonly configuration space fields.
    fn set_config(&mut self, offset: u32, flags: VhostUserConfigFlags, buf: &[u8]) -> Result<()>;

    /// Setup slave communication channel.
    fn set_slave_request_fd(&mut self, fd: &dyn AsRawDescriptor) -> Result<()>;

    /// Retrieve shared buffer for inflight I/O tracking.
    fn get_inflight_fd(
        &mut self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)>;

    /// Set shared buffer for inflight I/O tracking.
    fn set_inflight_fd(&mut self, inflight: &VhostUserInflight, fd: RawDescriptor) -> Result<()>;

    /// Query the maximum amount of memory slots supported by the backend.
    fn get_max_mem_slots(&mut self) -> Result<u64>;

    /// Add a new guest memory mapping for vhost to use.
    fn add_mem_region(&mut self, region: &VhostUserMemoryRegionInfo) -> Result<()>;

    /// Remove a guest memory mapping from vhost.
    fn remove_mem_region(&mut self, region: &VhostUserMemoryRegionInfo) -> Result<()>;

    /// Gets the shared memory regions used by the device.
    fn get_shared_memory_regions(&self) -> Result<Vec<VhostSharedMemoryRegion>>;
}

/// Struct for the vhost-user master endpoint.
#[derive(Clone)]
pub struct Master<E: Endpoint<MasterReq>> {
    node: Arc<Mutex<MasterInternal<E>>>,
}

impl<E: Endpoint<MasterReq> + From<SystemStream>> Master<E> {
    /// Create a new instance from a Unix stream socket.
    pub fn from_stream(sock: SystemStream, max_queue_num: u64) -> Self {
        Self::new(E::from(sock), max_queue_num)
    }
}

impl<E: Endpoint<MasterReq>> Master<E> {
    /// Create a new instance.
    fn new(ep: E, max_queue_num: u64) -> Self {
        Master {
            node: Arc::new(Mutex::new(MasterInternal {
                main_sock: ep,
                virtio_features: 0,
                acked_virtio_features: 0,
                protocol_features: 0,
                acked_protocol_features: 0,
                protocol_features_ready: false,
                max_queue_num,
                hdr_flags: VhostUserHeaderFlag::empty(),
            })),
        }
    }

    fn node(&self) -> MutexGuard<MasterInternal<E>> {
        self.node.lock().unwrap()
    }

    /// Create a new vhost-user master endpoint.
    ///
    /// Will retry as the backend may not be ready to accept the connection.
    ///
    /// # Arguments
    /// * `path` - path of Unix domain socket listener to connect to
    pub fn connect<P: AsRef<Path>>(path: P, max_queue_num: u64) -> Result<Self> {
        let mut retry_count = 5;
        let endpoint = loop {
            match E::connect(&path) {
                Ok(endpoint) => break Ok(endpoint),
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

        Ok(Self::new(endpoint, max_queue_num))
    }

    /// Set the header flags that should be applied to all following messages.
    pub fn set_hdr_flags(&self, flags: VhostUserHeaderFlag) {
        let mut node = self.node();
        node.hdr_flags = flags;
    }
}

impl<E: Endpoint<MasterReq>> VhostBackend for Master<E> {
    /// Get from the underlying vhost implementation the feature bitmask.
    fn get_features(&self) -> Result<u64> {
        let mut node = self.node();
        let hdr = node.send_request_header(MasterReq::GET_FEATURES, None)?;
        let val = node.recv_reply::<VhostUserU64>(&hdr)?;
        node.virtio_features = val.value;
        Ok(node.virtio_features)
    }

    /// Enable features in the underlying vhost implementation using a bitmask.
    fn set_features(&self, features: u64) -> Result<()> {
        let mut node = self.node();
        let val = VhostUserU64::new(features);
        let hdr = node.send_request_with_body(MasterReq::SET_FEATURES, &val, None)?;
        node.acked_virtio_features = features & node.virtio_features;
        node.wait_for_ack(&hdr)
    }

    /// Set the current Master as an owner of the session.
    fn set_owner(&self) -> Result<()> {
        // We unwrap() the return value to assert that we are not expecting threads to ever fail
        // while holding the lock.
        let mut node = self.node();
        let hdr = node.send_request_header(MasterReq::SET_OWNER, None)?;
        node.wait_for_ack(&hdr)
    }

    fn reset_owner(&self) -> Result<()> {
        let mut node = self.node();
        let hdr = node.send_request_header(MasterReq::RESET_OWNER, None)?;
        node.wait_for_ack(&hdr)
    }

    /// Set the memory map regions on the slave so it can translate the vring
    /// addresses. In the ancillary data there is an array of file descriptors
    fn set_mem_table(&self, regions: &[VhostUserMemoryRegionInfo]) -> Result<()> {
        if regions.is_empty() || regions.len() > MAX_ATTACHED_FD_ENTRIES {
            return Err(VhostUserError::InvalidParam);
        }

        let mut ctx = VhostUserMemoryContext::new();
        for region in regions.iter() {
            // TODO(b/221882601): once mmap handle cross platform story exists, update this null
            // check.
            if region.memory_size == 0 || (region.mmap_handle as isize) < 0 {
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

        let mut node = self.node();
        let body = VhostUserMemory::new(ctx.regions.len() as u32);
        let (_, payload, _) = unsafe { ctx.regions.align_to::<u8>() };
        let hdr = node.send_request_with_payload(
            MasterReq::SET_MEM_TABLE,
            &body,
            payload,
            Some(ctx.fds.as_slice()),
        )?;
        node.wait_for_ack(&hdr)
    }

    // Clippy doesn't seem to know that if let with && is still experimental
    #[allow(clippy::unnecessary_unwrap)]
    fn set_log_base(&self, base: u64, fd: Option<RawDescriptor>) -> Result<()> {
        let mut node = self.node();
        let val = VhostUserU64::new(base);

        if node.acked_protocol_features & VhostUserProtocolFeatures::LOG_SHMFD.bits() != 0
            && fd.is_some()
        {
            let fds = [fd.unwrap()];
            let _ = node.send_request_with_body(MasterReq::SET_LOG_BASE, &val, Some(&fds))?;
        } else {
            let _ = node.send_request_with_body(MasterReq::SET_LOG_BASE, &val, None)?;
        }
        Ok(())
    }

    fn set_log_fd(&self, fd: RawDescriptor) -> Result<()> {
        let mut node = self.node();
        let fds = [fd];
        let hdr = node.send_request_header(MasterReq::SET_LOG_FD, Some(&fds))?;
        node.wait_for_ack(&hdr)
    }

    /// Set the size of the queue.
    fn set_vring_num(&self, queue_index: usize, num: u16) -> Result<()> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num {
            return Err(VhostUserError::InvalidParam);
        }

        let val = VhostUserVringState::new(queue_index as u32, num.into());
        let hdr = node.send_request_with_body(MasterReq::SET_VRING_NUM, &val, None)?;
        node.wait_for_ack(&hdr)
    }

    /// Sets the addresses of the different aspects of the vring.
    fn set_vring_addr(&self, queue_index: usize, config_data: &VringConfigData) -> Result<()> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num
            || config_data.flags & !(VhostUserVringAddrFlags::all().bits()) != 0
        {
            return Err(VhostUserError::InvalidParam);
        }

        let val = VhostUserVringAddr::from_config_data(queue_index as u32, config_data);
        let hdr = node.send_request_with_body(MasterReq::SET_VRING_ADDR, &val, None)?;
        node.wait_for_ack(&hdr)
    }

    /// Sets the base offset in the available vring.
    fn set_vring_base(&self, queue_index: usize, base: u16) -> Result<()> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num {
            return Err(VhostUserError::InvalidParam);
        }

        let val = VhostUserVringState::new(queue_index as u32, base.into());
        let hdr = node.send_request_with_body(MasterReq::SET_VRING_BASE, &val, None)?;
        node.wait_for_ack(&hdr)
    }

    fn get_vring_base(&self, queue_index: usize) -> Result<u32> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num {
            return Err(VhostUserError::InvalidParam);
        }

        let req = VhostUserVringState::new(queue_index as u32, 0);
        let hdr = node.send_request_with_body(MasterReq::GET_VRING_BASE, &req, None)?;
        let reply = node.recv_reply::<VhostUserVringState>(&hdr)?;
        Ok(reply.num)
    }

    /// Set the event file descriptor to signal when buffers are used.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// will be used instead of waiting for the call.
    fn set_vring_call(&self, queue_index: usize, event: &Event) -> Result<()> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num {
            return Err(VhostUserError::InvalidParam);
        }
        let hdr = node.send_fd_for_vring(
            MasterReq::SET_VRING_CALL,
            queue_index,
            event.as_raw_descriptor(),
        )?;
        node.wait_for_ack(&hdr)
    }

    /// Set the event file descriptor for adding buffers to the vring.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// should be used instead of waiting for a kick.
    fn set_vring_kick(&self, queue_index: usize, event: &Event) -> Result<()> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num {
            return Err(VhostUserError::InvalidParam);
        }
        let hdr = node.send_fd_for_vring(
            MasterReq::SET_VRING_KICK,
            queue_index,
            event.as_raw_descriptor(),
        )?;
        node.wait_for_ack(&hdr)
    }

    /// Set the event file descriptor to signal when error occurs.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data.
    fn set_vring_err(&self, queue_index: usize, event: &Event) -> Result<()> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num {
            return Err(VhostUserError::InvalidParam);
        }
        let hdr = node.send_fd_for_vring(
            MasterReq::SET_VRING_ERR,
            queue_index,
            event.as_raw_descriptor(),
        )?;
        node.wait_for_ack(&hdr)
    }

    fn sleep(&self) -> Result<()> {
        let mut node = self.node();
        let hdr = node.send_request_header(MasterReq::SLEEP, None)?;
        node.wait_for_ack(&hdr)
    }

    fn wake(&self) -> Result<()> {
        let mut node = self.node();
        let hdr = node.send_request_header(MasterReq::WAKE, None)?;
        node.wait_for_ack(&hdr)
    }
}

impl<E: Endpoint<MasterReq>> VhostUserMaster for Master<E> {
    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures> {
        let mut node = self.node();
        let flag = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        if node.virtio_features & flag == 0 {
            return Err(VhostUserError::InvalidOperation);
        }
        let hdr = node.send_request_header(MasterReq::GET_PROTOCOL_FEATURES, None)?;
        let val = node.recv_reply::<VhostUserU64>(&hdr)?;
        node.protocol_features = val.value;
        // Should we support forward compatibility?
        // If so just mask out unrecognized flags instead of return errors.
        match VhostUserProtocolFeatures::from_bits(node.protocol_features) {
            Some(val) => Ok(val),
            None => Err(VhostUserError::InvalidMessage),
        }
    }

    fn set_protocol_features(&mut self, features: VhostUserProtocolFeatures) -> Result<()> {
        let mut node = self.node();
        let flag = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        if node.virtio_features & flag == 0 {
            return Err(VhostUserError::InvalidOperation);
        }
        if features.contains(VhostUserProtocolFeatures::SHARED_MEMORY_REGIONS)
            && !features.contains(VhostUserProtocolFeatures::SLAVE_REQ)
        {
            return Err(VhostUserError::FeatureMismatch);
        }
        let val = VhostUserU64::new(features.bits());
        let hdr = node.send_request_with_body(MasterReq::SET_PROTOCOL_FEATURES, &val, None)?;
        // Don't wait for ACK here because the protocol feature negotiation process hasn't been
        // completed yet.
        node.acked_protocol_features = features.bits();
        node.protocol_features_ready = true;
        node.wait_for_ack(&hdr)
    }

    fn get_queue_num(&mut self) -> Result<u64> {
        let mut node = self.node();
        if !node.is_feature_mq_available() {
            return Err(VhostUserError::InvalidOperation);
        }

        let hdr = node.send_request_header(MasterReq::GET_QUEUE_NUM, None)?;
        let val = node.recv_reply::<VhostUserU64>(&hdr)?;
        if val.value > VHOST_USER_MAX_VRINGS {
            return Err(VhostUserError::InvalidMessage);
        }
        node.max_queue_num = val.value;
        Ok(node.max_queue_num)
    }

    fn set_vring_enable(&mut self, queue_index: usize, enable: bool) -> Result<()> {
        let mut node = self.node();
        // set_vring_enable() is supported only when PROTOCOL_FEATURES has been enabled.
        if node.acked_virtio_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0 {
            return Err(VhostUserError::InvalidOperation);
        } else if queue_index as u64 >= node.max_queue_num {
            return Err(VhostUserError::InvalidParam);
        }

        let val = VhostUserVringState::new(queue_index as u32, enable.into());
        let hdr = node.send_request_with_body(MasterReq::SET_VRING_ENABLE, &val, None)?;
        node.wait_for_ack(&hdr)
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
        buf: &[u8],
    ) -> Result<(VhostUserConfig, VhostUserConfigPayload)> {
        let body = VhostUserConfig::new(offset, size, flags);
        if !body.is_valid() {
            return Err(VhostUserError::InvalidParam);
        }

        let mut node = self.node();
        // depends on VhostUserProtocolFeatures::CONFIG
        if node.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
            return Err(VhostUserError::InvalidOperation);
        }

        // vhost-user spec states that:
        // "Master payload: virtio device config space"
        // "Slave payload: virtio device config space"
        let hdr = node.send_request_with_payload(MasterReq::GET_CONFIG, &body, buf, None)?;
        let (body_reply, buf_reply, rfds) =
            node.recv_reply_with_payload::<VhostUserConfig>(&hdr)?;
        if rfds.is_some() {
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

    fn set_config(&mut self, offset: u32, flags: VhostUserConfigFlags, buf: &[u8]) -> Result<()> {
        if buf.len() > MAX_MSG_SIZE {
            return Err(VhostUserError::InvalidParam);
        }
        let body = VhostUserConfig::new(offset, buf.len() as u32, flags);
        if !body.is_valid() {
            return Err(VhostUserError::InvalidParam);
        }

        let mut node = self.node();
        // depends on VhostUserProtocolFeatures::CONFIG
        if node.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
            return Err(VhostUserError::InvalidOperation);
        }

        let hdr = node.send_request_with_payload(MasterReq::SET_CONFIG, &body, buf, None)?;
        node.wait_for_ack(&hdr)
    }

    fn set_slave_request_fd(&mut self, fd: &dyn AsRawDescriptor) -> Result<()> {
        let mut node = self.node();
        if node.acked_protocol_features & VhostUserProtocolFeatures::SLAVE_REQ.bits() == 0 {
            return Err(VhostUserError::InvalidOperation);
        }
        let fds = [fd.as_raw_descriptor()];
        let hdr = node.send_request_header(MasterReq::SET_SLAVE_REQ_FD, Some(&fds))?;
        node.wait_for_ack(&hdr)
    }

    fn get_inflight_fd(
        &mut self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)> {
        let mut node = self.node();
        if node.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits() == 0 {
            return Err(VhostUserError::InvalidOperation);
        }

        let hdr = node.send_request_with_body(MasterReq::GET_INFLIGHT_FD, inflight, None)?;
        let (inflight, files) = node.recv_reply_with_files::<VhostUserInflight>(&hdr)?;

        match take_single_file(files) {
            Some(file) => Ok((inflight, file)),
            None => Err(VhostUserError::IncorrectFds),
        }
    }

    fn set_inflight_fd(&mut self, inflight: &VhostUserInflight, fd: RawDescriptor) -> Result<()> {
        let mut node = self.node();
        if node.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits() == 0 {
            return Err(VhostUserError::InvalidOperation);
        }

        if inflight.mmap_size == 0
            || inflight.num_queues == 0
            || inflight.queue_size == 0
            || fd == INVALID_DESCRIPTOR
        {
            return Err(VhostUserError::InvalidParam);
        }

        let hdr = node.send_request_with_body(MasterReq::SET_INFLIGHT_FD, inflight, Some(&[fd]))?;
        node.wait_for_ack(&hdr)
    }

    fn get_max_mem_slots(&mut self) -> Result<u64> {
        let mut node = self.node();
        if node.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits() == 0
        {
            return Err(VhostUserError::InvalidOperation);
        }

        let hdr = node.send_request_header(MasterReq::GET_MAX_MEM_SLOTS, None)?;
        let val = node.recv_reply::<VhostUserU64>(&hdr)?;

        Ok(val.value)
    }

    fn add_mem_region(&mut self, region: &VhostUserMemoryRegionInfo) -> Result<()> {
        let mut node = self.node();
        if node.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits() == 0
        {
            return Err(VhostUserError::InvalidOperation);
        }
        // TODO(b/221882601): once mmap handle cross platform story exists, update this null check.
        if region.memory_size == 0 || (region.mmap_handle as isize) < 0 {
            return Err(VhostUserError::InvalidParam);
        }

        let body = VhostUserSingleMemoryRegion::new(
            region.guest_phys_addr,
            region.memory_size,
            region.userspace_addr,
            region.mmap_offset,
        );
        let fds = [region.mmap_handle];
        let hdr = node.send_request_with_body(MasterReq::ADD_MEM_REG, &body, Some(&fds))?;
        node.wait_for_ack(&hdr)
    }

    fn remove_mem_region(&mut self, region: &VhostUserMemoryRegionInfo) -> Result<()> {
        let mut node = self.node();
        if node.acked_protocol_features & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits() == 0
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
        let hdr = node.send_request_with_body(MasterReq::REM_MEM_REG, &body, None)?;
        node.wait_for_ack(&hdr)
    }

    fn get_shared_memory_regions(&self) -> Result<Vec<VhostSharedMemoryRegion>> {
        let mut node = self.node();
        let hdr = node.send_request_header(MasterReq::GET_SHARED_MEMORY_REGIONS, None)?;
        let (body_reply, buf_reply, rfds) = node.recv_reply_with_payload::<VhostUserU64>(&hdr)?;
        let struct_size = mem::size_of::<VhostSharedMemoryRegion>();
        if rfds.is_some() || buf_reply.len() != body_reply.value as usize * struct_size {
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
}

impl<E: Endpoint<MasterReq> + AsRawDescriptor> AsRawDescriptor for Master<E> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        let node = self.node();
        // TODO(b/221882601): why is this here? The underlying Tube needs to use a read notifier
        // if this is for polling.
        node.main_sock.as_raw_descriptor()
    }
}

// TODO(b/221882601): likely need pairs of RDs and/or SharedMemory to represent mmaps on Windows.
/// Context object to pass guest memory configuration to VhostUserMaster::set_mem_table().
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

struct MasterInternal<E: Endpoint<MasterReq>> {
    // Used to send requests to the slave.
    main_sock: E,
    // Cached virtio features from the slave.
    virtio_features: u64,
    // Cached acked virtio features from the driver.
    acked_virtio_features: u64,
    // Cached vhost-user protocol features from the slave.
    protocol_features: u64,
    // Cached vhost-user protocol features.
    acked_protocol_features: u64,
    // Cached vhost-user protocol features are ready to use.
    protocol_features_ready: bool,
    // Cached maxinum number of queues supported from the slave.
    max_queue_num: u64,
    // List of header flags.
    hdr_flags: VhostUserHeaderFlag,
}

impl<E: Endpoint<MasterReq>> MasterInternal<E> {
    fn send_request_header(
        &mut self,
        code: MasterReq,
        fds: Option<&[RawDescriptor]>,
    ) -> VhostUserResult<VhostUserMsgHeader<MasterReq>> {
        let hdr = self.new_request_header(code, 0);
        self.main_sock.send_header(&hdr, fds)?;
        Ok(hdr)
    }

    fn send_request_with_body<T: Sized + DataInit>(
        &mut self,
        code: MasterReq,
        msg: &T,
        fds: Option<&[RawDescriptor]>,
    ) -> VhostUserResult<VhostUserMsgHeader<MasterReq>> {
        if mem::size_of::<T>() > MAX_MSG_SIZE {
            return Err(VhostUserError::InvalidParam);
        }
        let hdr = self.new_request_header(code, mem::size_of::<T>() as u32);
        self.main_sock.send_message(&hdr, msg, fds)?;
        Ok(hdr)
    }

    fn send_request_with_payload<T: Sized + DataInit>(
        &mut self,
        code: MasterReq,
        msg: &T,
        payload: &[u8],
        fds: Option<&[RawDescriptor]>,
    ) -> VhostUserResult<VhostUserMsgHeader<MasterReq>> {
        let len = mem::size_of::<T>() + payload.len();
        if len > MAX_MSG_SIZE {
            return Err(VhostUserError::InvalidParam);
        }
        if let Some(fd_arr) = fds {
            if fd_arr.len() > MAX_ATTACHED_FD_ENTRIES {
                return Err(VhostUserError::InvalidParam);
            }
        }
        let hdr = self.new_request_header(code, len as u32);
        self.main_sock
            .send_message_with_payload(&hdr, msg, payload, fds)?;
        Ok(hdr)
    }

    fn send_fd_for_vring(
        &mut self,
        code: MasterReq,
        queue_index: usize,
        fd: RawDescriptor,
    ) -> VhostUserResult<VhostUserMsgHeader<MasterReq>> {
        if queue_index as u64 >= self.max_queue_num {
            return Err(VhostUserError::InvalidParam);
        }
        // Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag.
        // This flag is set when there is no file descriptor in the ancillary data. This signals
        // that polling will be used instead of waiting for the call.
        let msg = VhostUserU64::new(queue_index as u64);
        let hdr = self.new_request_header(code, mem::size_of::<VhostUserU64>() as u32);
        self.main_sock.send_message(&hdr, &msg, Some(&[fd]))?;
        Ok(hdr)
    }

    fn recv_reply<T: Sized + DataInit + Default + VhostUserMsgValidator>(
        &mut self,
        hdr: &VhostUserMsgHeader<MasterReq>,
    ) -> VhostUserResult<T> {
        if mem::size_of::<T>() > MAX_MSG_SIZE || hdr.is_reply() {
            return Err(VhostUserError::InvalidParam);
        }
        let (reply, body, rfds) = self.main_sock.recv_body::<T>()?;
        if !reply.is_reply_for(hdr) || rfds.is_some() || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }
        Ok(body)
    }

    fn recv_reply_with_files<T: Sized + DataInit + Default + VhostUserMsgValidator>(
        &mut self,
        hdr: &VhostUserMsgHeader<MasterReq>,
    ) -> VhostUserResult<(T, Option<Vec<File>>)> {
        if mem::size_of::<T>() > MAX_MSG_SIZE || hdr.is_reply() {
            return Err(VhostUserError::InvalidParam);
        }

        let (reply, body, files) = self.main_sock.recv_body::<T>()?;
        if !reply.is_reply_for(hdr) || files.is_none() || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }
        Ok((body, files))
    }

    fn recv_reply_with_payload<T: Sized + DataInit + Default + VhostUserMsgValidator>(
        &mut self,
        hdr: &VhostUserMsgHeader<MasterReq>,
    ) -> VhostUserResult<(T, Vec<u8>, Option<Vec<File>>)> {
        if mem::size_of::<T>() > MAX_MSG_SIZE || hdr.is_reply() {
            return Err(VhostUserError::InvalidParam);
        }

        let (reply, body, buf, files) = self.main_sock.recv_payload_into_buf::<T>()?;
        if !reply.is_reply_for(hdr) || files.is_some() || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }

        Ok((body, buf, files))
    }

    fn wait_for_ack(&mut self, hdr: &VhostUserMsgHeader<MasterReq>) -> VhostUserResult<()> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::REPLY_ACK.bits() == 0
            || !hdr.is_need_reply()
        {
            return Ok(());
        }

        let (reply, body, rfds) = self.main_sock.recv_body::<VhostUserU64>()?;
        if !reply.is_reply_for(hdr) || rfds.is_some() || !body.is_valid() {
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
        VhostUserMsgHeader::new(request, self.hdr_flags.bits() | 0x1, size)
    }
}

#[cfg(test)]
mod tests {
    use base::INVALID_DESCRIPTOR;

    use super::*;
    use crate::connection::tests::create_pair;
    use crate::connection::tests::TestEndpoint;
    use crate::connection::tests::TestMaster;

    #[test]
    fn create_master() {
        let (master, mut slave) = create_pair();

        assert!(master.as_raw_descriptor() != INVALID_DESCRIPTOR);
        // Send two messages continuously
        master.set_owner().unwrap();
        master.reset_owner().unwrap();

        let (hdr, rfds) = slave.recv_header().unwrap();
        assert_eq!(hdr.get_code(), MasterReq::SET_OWNER);
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_none());

        let (hdr, rfds) = slave.recv_header().unwrap();
        assert_eq!(hdr.get_code(), MasterReq::RESET_OWNER);
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_none());
    }

    #[test]
    fn test_features() {
        let (master, mut peer) = create_pair();

        master.set_owner().unwrap();
        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code(), MasterReq::SET_OWNER);
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_none());

        let hdr = VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(0x15);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = master.get_features().unwrap();
        assert_eq!(features, 0x15u64);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_none());

        let hdr = VhostUserMsgHeader::new(MasterReq::SET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(0x15);
        peer.send_message(&hdr, &msg, None).unwrap();
        master.set_features(0x15).unwrap();
        let (_hdr, msg, rfds) = peer.recv_body::<VhostUserU64>().unwrap();
        assert!(rfds.is_none());
        let val = msg.value;
        assert_eq!(val, 0x15);

        let hdr = VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0x4, 8);
        let msg = 0x15u32;
        peer.send_message(&hdr, &msg, None).unwrap();
        assert!(master.get_features().is_err());
    }

    #[test]
    fn test_protocol_features() {
        let (mut master, mut peer) = create_pair();

        master.set_owner().unwrap();
        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code(), MasterReq::SET_OWNER);
        assert!(rfds.is_none());

        assert!(master.get_protocol_features().is_err());
        assert!(master
            .set_protocol_features(VhostUserProtocolFeatures::all())
            .is_err());

        let vfeatures = 0x15 | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let hdr = VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(vfeatures);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = master.get_features().unwrap();
        assert_eq!(features, vfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_none());

        master.set_features(vfeatures).unwrap();
        let (_hdr, msg, rfds) = peer.recv_body::<VhostUserU64>().unwrap();
        assert!(rfds.is_none());
        let val = msg.value;
        assert_eq!(val, vfeatures);

        let pfeatures = VhostUserProtocolFeatures::all();
        let hdr = VhostUserMsgHeader::new(MasterReq::GET_PROTOCOL_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(pfeatures.bits());
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = master.get_protocol_features().unwrap();
        assert_eq!(features, pfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_none());

        master.set_protocol_features(pfeatures).unwrap();
        let (_hdr, msg, rfds) = peer.recv_body::<VhostUserU64>().unwrap();
        assert!(rfds.is_none());
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
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

        master
            .set_config(0x100, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .unwrap_err();

        {
            let mut node = master.node();
            node.virtio_features = 0xffff_ffff;
            node.acked_virtio_features = 0xffff_ffff;
            node.protocol_features = 0xffff_ffff;
            node.acked_protocol_features = 0xffff_ffff;
        }

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

    fn create_pair2() -> (TestMaster, TestEndpoint) {
        let (master, peer) = create_pair();
        {
            let mut node = master.node();
            node.virtio_features = 0xffff_ffff;
            node.acked_virtio_features = 0xffff_ffff;
            node.protocol_features = 0xffff_ffff;
            node.acked_protocol_features = 0xffff_ffff;
        }

        (master, peer)
    }

    #[test]
    fn test_master_get_config_negative0() {
        let (mut master, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

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
        let (mut master, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

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
        let (mut master, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

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
        let (mut master, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

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
        let (mut master, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

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
        let (mut master, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

        let hdr = VhostUserMsgHeader::new(MasterReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.offset = (MAX_MSG_SIZE + 1) as u32;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(master
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_master_get_config_negative6() {
        let (mut master, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

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

        master.set_mem_table(&[]).unwrap_err();
        let tables = vec![VhostUserMemoryRegionInfo::default(); MAX_ATTACHED_FD_ENTRIES + 1];
        master.set_mem_table(&tables).unwrap_err();
    }
}
