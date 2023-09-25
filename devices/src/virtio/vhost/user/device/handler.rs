// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Library for implementing vhost-user device executables.
//!
//! This crate provides
//! * `VhostUserBackend` trait, which is a collection of methods to handle vhost-user requests, and
//! * `DeviceRequestHandler` struct, which makes a connection to a VMM and starts an event loop.
//!
//! They are expected to be used as follows:
//!
//! 1. Define a struct and implement `VhostUserBackend` for it.
//! 2. Create a `DeviceRequestHandler` with the backend struct.
//! 3. Drive the `DeviceRequestHandler::run` async fn with an executor.
//!
//! ```ignore
//! struct MyBackend {
//!   /* fields */
//! }
//!
//! impl VhostUserBackend for MyBackend {
//!   /* implement methods */
//! }
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!   let backend = MyBackend { /* initialize fields */ };
//!   let handler = DeviceRequestHandler::new(backend);
//!   let socket = std::path::Path("/path/to/socket");
//!   let ex = cros_async::Executor::new()?;
//!
//!   if let Err(e) = ex.run_until(handler.run(socket, &ex)) {
//!     eprintln!("error happened: {}", e);
//!   }
//!   Ok(())
//! }
//! ```
//!
// Implementation note:
// This code lets us take advantage of the vmm_vhost low level implementation of the vhost user
// protocol. DeviceRequestHandler implements the VhostUserSlaveReqHandlerMut trait from vmm_vhost,
// and includes some common code for setting up guest memory and managing partially configured
// vrings. DeviceRequestHandler::run watches the vhost-user socket and then calls handle_request()
// when it becomes readable. handle_request() reads and parses the message and then calls one of the
// VhostUserSlaveReqHandlerMut trait methods. These dispatch back to the supplied VhostUserBackend
// implementation (this is what our devices implement).

pub(super) mod sys;

use std::collections::BTreeMap;
use std::convert::From;
use std::fs::File;
use std::num::Wrapping;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
#[cfg(unix)]
use base::clear_fd_flags;
use base::error;
use base::Event;
use base::FromRawDescriptor;
use base::IntoRawDescriptor;
use base::Protection;
use base::SafeDescriptor;
use base::SharedMemory;
use cros_async::TaskHandle;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error as ThisError;
use vm_control::VmMemorySource;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::MemoryRegion;
use vmm_vhost::connection::Endpoint;
use vmm_vhost::message::SlaveReq;
use vmm_vhost::message::VhostSharedMemoryRegion;
use vmm_vhost::message::VhostUserConfigFlags;
use vmm_vhost::message::VhostUserGpuMapMsg;
use vmm_vhost::message::VhostUserInflight;
use vmm_vhost::message::VhostUserMemoryRegion;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserShmemMapMsg;
use vmm_vhost::message::VhostUserShmemMapMsgFlags;
use vmm_vhost::message::VhostUserShmemUnmapMsg;
use vmm_vhost::message::VhostUserSingleMemoryRegion;
use vmm_vhost::message::VhostUserVringAddrFlags;
use vmm_vhost::message::VhostUserVringState;
use vmm_vhost::Error as VhostError;
use vmm_vhost::Result as VhostResult;
use vmm_vhost::Slave;
use vmm_vhost::VhostUserMasterReqHandler;
use vmm_vhost::VhostUserSlaveReqHandlerMut;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;

use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::QueueConfig;
use crate::virtio::SharedMemoryMapper;
use crate::virtio::SharedMemoryRegion;

/// Keeps a mapping from the vmm's virtual addresses to guest addresses.
/// used to translate messages from the vmm to guest offsets.
#[derive(Default)]
pub struct MappingInfo {
    pub vmm_addr: u64,
    pub guest_phys: u64,
    pub size: u64,
}

pub fn vmm_va_to_gpa(maps: &[MappingInfo], vmm_va: u64) -> VhostResult<GuestAddress> {
    for map in maps {
        if vmm_va >= map.vmm_addr && vmm_va < map.vmm_addr + map.size {
            return Ok(GuestAddress(vmm_va - map.vmm_addr + map.guest_phys));
        }
    }
    Err(VhostError::InvalidMessage)
}

/// Trait for vhost-user backend.
pub trait VhostUserBackend {
    /// The maximum number of queues that this backend can manage.
    fn max_queue_num(&self) -> usize;

    /// The set of feature bits that this backend supports.
    fn features(&self) -> u64;

    /// Acknowledges that this set of features should be enabled.
    fn ack_features(&mut self, value: u64) -> anyhow::Result<()>;

    /// Returns the set of enabled features.
    fn acked_features(&self) -> u64;

    /// The set of protocol feature bits that this backend supports.
    fn protocol_features(&self) -> VhostUserProtocolFeatures;

    /// Acknowledges that this set of protocol features should be enabled.
    fn ack_protocol_features(&mut self, _value: u64) -> anyhow::Result<()>;

    /// Returns the set of enabled protocol features.
    fn acked_protocol_features(&self) -> u64;

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, dst: &mut [u8]);

    /// writes `data` to this device's configuration space at `offset`.
    fn write_config(&self, _offset: u64, _data: &[u8]) {}

    /// Indicates that the backend should start processing requests for virtio queue number `idx`.
    /// This method must not block the current thread so device backends should either spawn an
    /// async task or another thread to handle messages from the Queue.
    fn start_queue(
        &mut self,
        idx: usize,
        queue: Queue,
        mem: GuestMemory,
        doorbell: Interrupt,
    ) -> anyhow::Result<()>;

    /// Indicates that the backend should stop processing requests for virtio queue number `idx`.
    /// This method should return the queue passed to `start_queue` for the corresponding `idx`.
    /// This method will only be called for queues that were previously started by `start_queue`.
    fn stop_queue(&mut self, idx: usize) -> anyhow::Result<Queue>;

    /// Resets the vhost-user backend.
    fn reset(&mut self);

    /// Returns the device's shared memory region if present.
    fn get_shared_memory_region(&self) -> Option<SharedMemoryRegion> {
        None
    }

    /// Accepts `VhostBackendReqConnection` to conduct Vhost backend to frontend message
    /// handling.
    ///
    /// This method will be called when `VhostUserProtocolFeatures::SLAVE_REQ` is
    /// negotiated.
    fn set_backend_req_connection(&mut self, _conn: VhostBackendReqConnection) {
        error!("set_backend_req_connection is not implemented");
    }

    /// Used to stop non queue workers that `VhostUserBackend::stop_queue` can't stop.
    fn stop_non_queue_workers(&mut self) -> anyhow::Result<()> {
        error!("sleep not implemented for vhost user device");
        // TODO(rizhang): Return error once basic devices support this.
        Ok(())
    }

    /// Snapshot device and return serialized bytes.
    fn snapshot(&self) -> anyhow::Result<Vec<u8>> {
        error!("snapshot not implemented for vhost user device");
        // TODO(rizhang): Return error once basic devices support this.
        Ok(Vec::new())
    }

    fn restore(&mut self, _data: Vec<u8>) -> anyhow::Result<()> {
        error!("restore not implemented for vhost user device");
        // TODO(rizhang): Return error once basic devices support this.
        Ok(())
    }
}

/// A virtio ring entry.
struct Vring {
    // The queue config. This doesn't get mutated by the queue workers.
    queue: QueueConfig,
    doorbell: Option<Interrupt>,
    enabled: bool,
    // Active queue that is only `Some` when the device is sleeping.
    paused_queue: Option<Queue>,
}

#[derive(Serialize, Deserialize)]
struct VringSnapshot {
    // Snapshot of queue config.
    queue: serde_json::Value,
    // Snapshot of the activated queue state.
    paused_queue: Option<serde_json::Value>,
    enabled: bool,
}

impl Vring {
    fn new(max_size: u16, features: u64) -> Self {
        Self {
            queue: QueueConfig::new(max_size, features),
            doorbell: None,
            enabled: false,
            paused_queue: None,
        }
    }

    fn reset(&mut self) {
        self.queue.reset();
        self.doorbell = None;
        self.enabled = false;
        self.paused_queue = None;
    }

    fn snapshot(&self) -> anyhow::Result<VringSnapshot> {
        Ok(VringSnapshot {
            queue: self.queue.snapshot()?,
            enabled: self.enabled,
            paused_queue: self
                .paused_queue
                .as_ref()
                .map(Queue::snapshot)
                .transpose()?,
        })
    }

    fn restore(
        &mut self,
        vring_snapshot: VringSnapshot,
        mem: &GuestMemory,
        event: Option<Event>,
    ) -> anyhow::Result<()> {
        self.queue.restore(vring_snapshot.queue)?;
        self.enabled = vring_snapshot.enabled;
        self.paused_queue = vring_snapshot
            .paused_queue
            .map(|value| {
                Queue::restore(
                    &self.queue,
                    value,
                    mem,
                    event.context("missing queue event")?,
                )
            })
            .transpose()?;
        Ok(())
    }
}

/// Trait for defining vhost-user ops that are platform-dependent.
pub trait VhostUserPlatformOps {
    /// Create the guest memory for the backend.
    ///
    /// `contexts` and `files` must be the same size, and provide a description of the memory
    /// regions to map as well as the file descriptors from which to obtain the memory backing these
    /// regions, respectively.
    ///
    /// The returned tuple contains the constructed `GuestMemory` from these memory contexts, as
    /// well as a vector describing all the mappings described by these contexts.

    fn set_mem_table(
        &mut self,
        contexts: &[VhostUserMemoryRegion],
        files: Vec<File>,
    ) -> VhostResult<(GuestMemory, Vec<MappingInfo>)>;

    /// Return an `Event` that will be signaled by the frontend whenever vring `index` should be
    /// processed.
    ///
    /// For protocols that support providing that event using a file descriptor (`Regular`), it is
    /// provided by `file`. For other protocols, `file` will be `None`.
    fn set_vring_kick(&mut self, index: u8, file: Option<File>) -> VhostResult<Event>;

    /// Return an `Interrupt` that the backend will signal whenever it puts used buffers for vring
    /// `index`.
    ///
    /// For protocols that support listening to a file descriptor (`Regular`), `file` provides a
    /// file descriptor from which the `Interrupt` should be built. For other protocols, it will be
    /// `None`.
    fn set_vring_call(&mut self, index: u8, file: Option<File>) -> VhostResult<Interrupt>;
}

/// Ops for running vhost-user over a stream (i.e. regular protocol).
pub(super) struct VhostUserRegularOps;

impl VhostUserPlatformOps for VhostUserRegularOps {
    fn set_mem_table(
        &mut self,
        contexts: &[VhostUserMemoryRegion],
        files: Vec<File>,
    ) -> VhostResult<(GuestMemory, Vec<MappingInfo>)> {
        if files.len() != contexts.len() {
            return Err(VhostError::InvalidParam);
        }

        let mut regions = Vec::with_capacity(files.len());
        for (region, file) in contexts.iter().zip(files.into_iter()) {
            let region = MemoryRegion::new_from_shm(
                region.memory_size,
                GuestAddress(region.guest_phys_addr),
                region.mmap_offset,
                Arc::new(
                    SharedMemory::from_safe_descriptor(
                        SafeDescriptor::from(file),
                        region.memory_size,
                    )
                    .unwrap(),
                ),
            )
            .map_err(|e| {
                error!("failed to create a memory region: {}", e);
                VhostError::InvalidOperation
            })?;
            regions.push(region);
        }
        let guest_mem = GuestMemory::from_regions(regions).map_err(|e| {
            error!("failed to create guest memory: {}", e);
            VhostError::InvalidOperation
        })?;

        let vmm_maps = contexts
            .iter()
            .map(|region| MappingInfo {
                vmm_addr: region.user_addr,
                guest_phys: region.guest_phys_addr,
                size: region.memory_size,
            })
            .collect();
        Ok((guest_mem, vmm_maps))
    }

    fn set_vring_kick(&mut self, _index: u8, file: Option<File>) -> VhostResult<Event> {
        let file = file.ok_or(VhostError::InvalidParam)?;
        // Remove O_NONBLOCK from kick_fd. Otherwise, uring_executor will fails when we read
        // values via `next_val()` later.
        // This is only required (and can only be done) on Unix platforms.
        #[cfg(unix)]
        if let Err(e) = clear_fd_flags(file.as_raw_fd(), libc::O_NONBLOCK) {
            error!("failed to remove O_NONBLOCK for kick fd: {}", e);
            return Err(VhostError::InvalidParam);
        }

        // Safe because we own the file.
        Ok(unsafe { Event::from_raw_descriptor(file.into_raw_descriptor()) })
    }

    fn set_vring_call(&mut self, _index: u8, file: Option<File>) -> VhostResult<Interrupt> {
        let file = file.ok_or(VhostError::InvalidParam)?;

        // Safe because we own the file.
        let call_evt = unsafe { Event::from_raw_descriptor(file.into_raw_descriptor()) };
        Ok(Interrupt::new_vhost_user(call_evt))
    }
}

/// A request handler for devices implementing `VhostUserBackend`.
pub struct DeviceRequestHandler {
    vrings: Vec<Vring>,
    owned: bool,
    vmm_maps: Option<Vec<MappingInfo>>,
    mem: Option<GuestMemory>,
    backend: Box<dyn VhostUserBackend>,
    ops: Box<dyn VhostUserPlatformOps>,
}

#[derive(Serialize, Deserialize)]
pub struct DeviceRequestHandlerSnapshot {
    vrings: Vec<VringSnapshot>,
    backend: Vec<u8>,
}

impl DeviceRequestHandler {
    /// Creates a vhost-user handler instance for `backend` with a different set of platform ops
    /// than the regular vhost-user ones.
    pub(crate) fn new(
        backend: Box<dyn VhostUserBackend>,
        ops: Box<dyn VhostUserPlatformOps>,
    ) -> Self {
        let mut vrings = Vec::with_capacity(backend.max_queue_num());
        for _ in 0..backend.max_queue_num() {
            vrings.push(Vring::new(Queue::MAX_SIZE, backend.features()));
        }

        DeviceRequestHandler {
            vrings,
            owned: false,
            vmm_maps: None,
            mem: None,
            backend,
            ops,
        }
    }
}

impl VhostUserSlaveReqHandlerMut for DeviceRequestHandler {
    fn set_owner(&mut self) -> VhostResult<()> {
        if self.owned {
            return Err(VhostError::InvalidOperation);
        }
        self.owned = true;
        Ok(())
    }

    fn reset_owner(&mut self) -> VhostResult<()> {
        self.owned = false;
        self.backend.reset();
        Ok(())
    }

    fn get_features(&mut self) -> VhostResult<u64> {
        let features = self.backend.features();
        Ok(features)
    }

    fn set_features(&mut self, features: u64) -> VhostResult<()> {
        if !self.owned {
            return Err(VhostError::InvalidOperation);
        }

        if (features & !(self.backend.features())) != 0 {
            return Err(VhostError::InvalidParam);
        }

        if let Err(e) = self.backend.ack_features(features) {
            error!("failed to acknowledge features 0x{:x}: {}", features, e);
            return Err(VhostError::InvalidOperation);
        }

        // If VHOST_USER_F_PROTOCOL_FEATURES has not been negotiated, the ring is initialized in an
        // enabled state.
        // If VHOST_USER_F_PROTOCOL_FEATURES has been negotiated, the ring is initialized in a
        // disabled state.
        // Client must not pass data to/from the backend until ring is enabled by
        // VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has been disabled by
        // VHOST_USER_SET_VRING_ENABLE with parameter 0.
        let acked_features = self.backend.acked_features();
        let vring_enabled = acked_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES != 0;
        for v in &mut self.vrings {
            v.enabled = vring_enabled;
        }

        Ok(())
    }

    fn get_protocol_features(&mut self) -> VhostResult<VhostUserProtocolFeatures> {
        Ok(self.backend.protocol_features())
    }

    fn set_protocol_features(&mut self, features: u64) -> VhostResult<()> {
        if let Err(e) = self.backend.ack_protocol_features(features) {
            error!("failed to set protocol features 0x{:x}: {}", features, e);
            return Err(VhostError::InvalidOperation);
        }
        Ok(())
    }

    fn set_mem_table(
        &mut self,
        contexts: &[VhostUserMemoryRegion],
        files: Vec<File>,
    ) -> VhostResult<()> {
        let (guest_mem, vmm_maps) = self.ops.set_mem_table(contexts, files)?;
        self.mem = Some(guest_mem);
        self.vmm_maps = Some(vmm_maps);
        Ok(())
    }

    fn get_queue_num(&mut self) -> VhostResult<u64> {
        Ok(self.vrings.len() as u64)
    }

    fn set_vring_num(&mut self, index: u32, num: u32) -> VhostResult<()> {
        if index as usize >= self.vrings.len() || num == 0 || num > Queue::MAX_SIZE.into() {
            return Err(VhostError::InvalidParam);
        }
        self.vrings[index as usize].queue.set_size(num as u16);

        Ok(())
    }

    fn set_vring_addr(
        &mut self,
        index: u32,
        _flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        _log: u64,
    ) -> VhostResult<()> {
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam);
        }

        let vmm_maps = self.vmm_maps.as_ref().ok_or(VhostError::InvalidParam)?;
        let vring = &mut self.vrings[index as usize];
        vring
            .queue
            .set_desc_table(vmm_va_to_gpa(vmm_maps, descriptor)?);
        vring
            .queue
            .set_avail_ring(vmm_va_to_gpa(vmm_maps, available)?);
        vring.queue.set_used_ring(vmm_va_to_gpa(vmm_maps, used)?);

        Ok(())
    }

    fn set_vring_base(&mut self, index: u32, base: u32) -> VhostResult<()> {
        if index as usize >= self.vrings.len() || base >= Queue::MAX_SIZE.into() {
            return Err(VhostError::InvalidParam);
        }

        let vring = &mut self.vrings[index as usize];
        vring.queue.set_next_avail(Wrapping(base as u16));
        vring.queue.set_next_used(Wrapping(base as u16));

        Ok(())
    }

    fn get_vring_base(&mut self, index: u32) -> VhostResult<VhostUserVringState> {
        let vring = self
            .vrings
            .get_mut(index as usize)
            .ok_or(VhostError::InvalidParam)?;

        // Quotation from vhost-user spec:
        // "The back-end must [...] stop ring upon receiving VHOST_USER_GET_VRING_BASE."
        // We only call `queue.set_ready()` when starting the queue, so if the queue is ready, that
        // means it is started and should be stopped.
        if vring.queue.ready() {
            if let Err(e) = self.backend.stop_queue(index as usize) {
                error!("Failed to stop queue in get_vring_base: {:#}", e);
            }

            vring.reset();
        }

        Ok(VhostUserVringState::new(
            index,
            vring.queue.next_avail().0 as u32,
        ))
    }

    fn set_vring_kick(&mut self, index: u8, file: Option<File>) -> VhostResult<()> {
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam);
        }

        let vring = &mut self.vrings[index as usize];
        if vring.queue.ready() {
            error!("kick fd cannot replaced after queue is started");
            return Err(VhostError::InvalidOperation);
        }

        let kick_evt = self.ops.set_vring_kick(index, file)?;

        // Enable any virtqueue features that were negotiated (like VIRTIO_RING_F_EVENT_IDX).
        vring.queue.ack_features(self.backend.acked_features());
        vring.queue.set_ready(true);

        let mem = self
            .mem
            .as_ref()
            .cloned()
            .ok_or(VhostError::InvalidOperation)?;

        let queue = match vring.queue.activate(&mem, kick_evt) {
            Ok(queue) => queue,
            Err(e) => {
                error!("failed to activate vring: {:#}", e);
                return Err(VhostError::SlaveInternalError);
            }
        };

        let doorbell = vring.doorbell.clone().ok_or(VhostError::InvalidOperation)?;

        if let Err(e) = self
            .backend
            .start_queue(index as usize, queue, mem, doorbell)
        {
            error!("Failed to start queue {}: {}", index, e);
            return Err(VhostError::SlaveInternalError);
        }

        Ok(())
    }

    fn set_vring_call(&mut self, index: u8, file: Option<File>) -> VhostResult<()> {
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam);
        }

        let doorbell = self.ops.set_vring_call(index, file)?;
        self.vrings[index as usize].doorbell = Some(doorbell);
        Ok(())
    }

    fn set_vring_err(&mut self, _index: u8, _fd: Option<File>) -> VhostResult<()> {
        // TODO
        Ok(())
    }

    fn set_vring_enable(&mut self, index: u32, enable: bool) -> VhostResult<()> {
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam);
        }

        // This request should be handled only when VHOST_USER_F_PROTOCOL_FEATURES
        // has been negotiated.
        if self.backend.acked_features() & 1 << VHOST_USER_F_PROTOCOL_FEATURES == 0 {
            return Err(VhostError::InvalidOperation);
        }

        // Slave must not pass data to/from the backend until ring is
        // enabled by VHOST_USER_SET_VRING_ENABLE with parameter 1,
        // or after it has been disabled by VHOST_USER_SET_VRING_ENABLE
        // with parameter 0.
        self.vrings[index as usize].enabled = enable;

        Ok(())
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        _flags: VhostUserConfigFlags,
    ) -> VhostResult<Vec<u8>> {
        let mut data = vec![0; size as usize];
        self.backend.read_config(u64::from(offset), &mut data);
        Ok(data)
    }

    fn set_config(
        &mut self,
        offset: u32,
        buf: &[u8],
        _flags: VhostUserConfigFlags,
    ) -> VhostResult<()> {
        self.backend.write_config(u64::from(offset), buf);
        Ok(())
    }

    fn set_slave_req_fd(&mut self, ep: Box<dyn Endpoint<SlaveReq>>) {
        let conn = VhostBackendReqConnection::new(
            Slave::new(ep),
            self.backend.get_shared_memory_region().map(|r| r.id),
        );
        self.backend.set_backend_req_connection(conn);
    }

    fn get_inflight_fd(
        &mut self,
        _inflight: &VhostUserInflight,
    ) -> VhostResult<(VhostUserInflight, File)> {
        unimplemented!("get_inflight_fd");
    }

    fn set_inflight_fd(&mut self, _inflight: &VhostUserInflight, _file: File) -> VhostResult<()> {
        unimplemented!("set_inflight_fd");
    }

    fn get_max_mem_slots(&mut self) -> VhostResult<u64> {
        //TODO
        Ok(0)
    }

    fn add_mem_region(
        &mut self,
        _region: &VhostUserSingleMemoryRegion,
        _fd: File,
    ) -> VhostResult<()> {
        //TODO
        Ok(())
    }

    fn remove_mem_region(&mut self, _region: &VhostUserSingleMemoryRegion) -> VhostResult<()> {
        //TODO
        Ok(())
    }

    fn get_shared_memory_regions(&mut self) -> VhostResult<Vec<VhostSharedMemoryRegion>> {
        Ok(if let Some(r) = self.backend.get_shared_memory_region() {
            vec![VhostSharedMemoryRegion::new(r.id, r.length)]
        } else {
            Vec::new()
        })
    }

    fn sleep(&mut self) -> VhostResult<()> {
        for (index, vring) in self
            .vrings
            .iter_mut()
            .enumerate()
            .filter(|(_index, vring)| vring.queue.ready())
        {
            match self.backend.stop_queue(index) {
                Ok(queue) => vring.paused_queue = Some(queue),
                Err(e) => return Err(VhostError::StopQueueError(e)),
            }
        }
        self.backend
            .stop_non_queue_workers()
            .map_err(VhostError::SleepError)
    }

    fn wake(&mut self) -> VhostResult<()> {
        for (index, vring) in self.vrings.iter_mut().enumerate() {
            if let Some(queue) = vring.paused_queue.take() {
                let mem = self.mem.clone().ok_or(VhostError::SlaveInternalError)?;
                let doorbell = vring.doorbell.clone().expect("Failed to clone doorbell");

                if let Err(e) = self.backend.start_queue(index, queue, mem, doorbell) {
                    error!("Failed to start queue {}: {}", index, e);
                    return Err(VhostError::SlaveInternalError);
                }
            }
        }
        Ok(())
    }

    fn snapshot(&mut self) -> VhostResult<Vec<u8>> {
        match serde_json::to_vec(&DeviceRequestHandlerSnapshot {
            vrings: self
                .vrings
                .iter()
                .map(|vring| vring.snapshot())
                .collect::<anyhow::Result<Vec<VringSnapshot>>>()
                .map_err(VhostError::SnapshotError)?,
            backend: self.backend.snapshot().map_err(VhostError::SnapshotError)?,
        }) {
            Ok(serialized_json) => Ok(serialized_json),
            Err(e) => {
                error!("Failed to serialize DeviceRequestHandlerSnapshot: {}", e);
                Err(VhostError::SerializationFailed)
            }
        }
    }

    fn restore(&mut self, data_bytes: &[u8], queue_evts: Option<Vec<File>>) -> VhostResult<()> {
        let device_request_handler_snapshot: DeviceRequestHandlerSnapshot =
            serde_json::from_slice(data_bytes).map_err(|e| {
                error!("Failed to deserialize DeviceRequestHandlerSnapshot: {}", e);
                VhostError::DeserializationFailed
            })?;

        let mem = self.mem.as_ref().ok_or(VhostError::InvalidOperation)?;

        let snapshotted_vrings = device_request_handler_snapshot.vrings;
        assert_eq!(snapshotted_vrings.len(), self.vrings.len());

        let mut queue_evts_iter = queue_evts.map(Vec::into_iter);

        for (index, (vring, snapshotted_vring)) in self
            .vrings
            .iter_mut()
            .zip(snapshotted_vrings.into_iter())
            .enumerate()
        {
            let queue_evt = if let Some(queue_evts_iter) = &mut queue_evts_iter {
                // TODO(b/288596005): It is assumed that the index of `queue_evts` should map to the
                // index of `self.vrings`. However, this assumption may break in the future, so a
                // Map of indexes to queue_evt should be used to support sparse activated queues.
                let queue_evt_file = queue_evts_iter
                    .next()
                    .ok_or(VhostError::VringIndexNotFound(index))?;
                Some(self.ops.set_vring_kick(index as u8, Some(queue_evt_file))?)
            } else {
                None
            };

            vring
                .restore(snapshotted_vring, mem, queue_evt)
                .map_err(VhostError::RestoreError)?;
        }

        self.backend
            .restore(device_request_handler_snapshot.backend)
            .map_err(VhostError::RestoreError)?;

        Ok(())
    }
}

/// Indicates the state of backend request connection
pub enum VhostBackendReqConnectionState {
    /// A backend request connection (`VhostBackendReqConnection`) is established
    Connected(VhostBackendReqConnection),
    /// No backend request connection has been established yet
    NoConnection,
}

/// Keeps track of Vhost user backend request connection.
pub struct VhostBackendReqConnection {
    conn: Slave,
    shmem_info: Option<ShmemInfo>,
}

#[derive(Clone)]
struct ShmemInfo {
    shmid: u8,
    mapped_regions: BTreeMap<u64 /* offset */, u64 /* size */>,
}

impl VhostBackendReqConnection {
    pub fn new(conn: Slave, shmid: Option<u8>) -> Self {
        let shmem_info = shmid.map(|shmid| ShmemInfo {
            shmid,
            mapped_regions: BTreeMap::new(),
        });
        Self { conn, shmem_info }
    }

    /// Send `VHOST_USER_CONFIG_CHANGE_MSG` to the frontend
    pub fn send_config_changed(&self) -> anyhow::Result<()> {
        self.conn
            .handle_config_change()
            .context("Could not send config change message")?;
        Ok(())
    }

    /// Create a SharedMemoryMapper trait object from the ShmemInfo.
    pub fn take_shmem_mapper(&mut self) -> anyhow::Result<Box<dyn SharedMemoryMapper>> {
        let shmem_info = self
            .shmem_info
            .take()
            .context("could not take shared memory mapper information")?;

        Ok(Box::new(VhostShmemMapper {
            conn: self.conn.clone(),
            shmem_info,
        }))
    }
}

struct VhostShmemMapper {
    conn: Slave,
    shmem_info: ShmemInfo,
}

impl SharedMemoryMapper for VhostShmemMapper {
    fn add_mapping(
        &mut self,
        source: VmMemorySource,
        offset: u64,
        prot: Protection,
    ) -> anyhow::Result<()> {
        // True if we should send gpu_map instead of shmem_map.
        let is_gpu = matches!(&source, &VmMemorySource::Vulkan { .. });

        let size = if is_gpu {
            match source {
                VmMemorySource::Vulkan {
                    descriptor,
                    handle_type,
                    memory_idx,
                    device_uuid,
                    driver_uuid,
                    size,
                } => {
                    let msg = VhostUserGpuMapMsg::new(
                        self.shmem_info.shmid,
                        offset,
                        size,
                        memory_idx,
                        handle_type,
                        device_uuid,
                        driver_uuid,
                    );
                    self.conn
                        .gpu_map(&msg, &descriptor)
                        .context("failed to map memory")?;
                    size
                }
                _ => unreachable!("inconsistent pattern match"),
            }
        } else {
            let (descriptor, fd_offset, size) = match source {
                VmMemorySource::Descriptor {
                    descriptor,
                    offset,
                    size,
                } => (descriptor, offset, size),
                VmMemorySource::SharedMemory(shmem) => {
                    let size = shmem.size();
                    // Safe because we own shmem.
                    let descriptor =
                        unsafe { SafeDescriptor::from_raw_descriptor(shmem.into_raw_descriptor()) };
                    (descriptor, 0, size)
                }
                _ => bail!("unsupported source"),
            };
            let flags = VhostUserShmemMapMsgFlags::from(prot);
            let msg =
                VhostUserShmemMapMsg::new(self.shmem_info.shmid, offset, fd_offset, size, flags);
            self.conn
                .shmem_map(&msg, &descriptor)
                .context("failed to map memory")?;
            size
        };

        self.shmem_info.mapped_regions.insert(offset, size);
        Ok(())
    }

    fn remove_mapping(&mut self, offset: u64) -> anyhow::Result<()> {
        let size = self
            .shmem_info
            .mapped_regions
            .remove(&offset)
            .context("unknown offset")?;
        let msg = VhostUserShmemUnmapMsg::new(self.shmem_info.shmid, offset, size);
        self.conn
            .shmem_unmap(&msg)
            .context("failed to map memory")
            .map(|_| ())
    }
}

pub(crate) struct WorkerState<T, U> {
    pub(crate) queue_task: TaskHandle<U>,
    pub(crate) queue: T,
}

/// Errors for device operations
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("worker not found when stopping queue")]
    WorkerNotFound,
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::channel;
    use std::sync::Barrier;
    use std::sync::Mutex;

    use anyhow::anyhow;
    use anyhow::bail;
    use base::Event;
    use vmm_vhost::message::MasterReq;
    use vmm_vhost::SlaveReqHandler;
    use vmm_vhost::VhostUserSlaveReqHandler;
    use zerocopy::AsBytes;
    use zerocopy::FromBytes;

    use super::sys::test_helpers;
    use super::*;
    use crate::virtio::vhost::user::vmm::VhostUserHandler;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, AsBytes, FromBytes)]
    #[repr(C, packed(4))]
    struct FakeConfig {
        x: u32,
        y: u64,
    }

    const FAKE_CONFIG_DATA: FakeConfig = FakeConfig { x: 1, y: 2 };

    pub(super) struct FakeBackend {
        avail_features: u64,
        acked_features: u64,
        acked_protocol_features: VhostUserProtocolFeatures,
        active_queues: Vec<Option<Queue>>,
    }

    impl FakeBackend {
        const MAX_QUEUE_NUM: usize = 16;

        pub(super) fn new() -> Self {
            let mut active_queues = Vec::new();
            active_queues.resize_with(Self::MAX_QUEUE_NUM, Default::default);
            Self {
                avail_features: 1 << VHOST_USER_F_PROTOCOL_FEATURES,
                acked_features: 0,
                acked_protocol_features: VhostUserProtocolFeatures::empty(),
                active_queues,
            }
        }
    }

    impl VhostUserBackend for FakeBackend {
        fn max_queue_num(&self) -> usize {
            Self::MAX_QUEUE_NUM
        }

        fn features(&self) -> u64 {
            self.avail_features
        }

        fn ack_features(&mut self, value: u64) -> anyhow::Result<()> {
            let unrequested_features = value & !self.avail_features;
            if unrequested_features != 0 {
                bail!(
                    "invalid protocol features are given: 0x{:x}",
                    unrequested_features
                );
            }
            self.acked_features |= value;
            Ok(())
        }

        fn acked_features(&self) -> u64 {
            self.acked_features
        }

        fn protocol_features(&self) -> VhostUserProtocolFeatures {
            VhostUserProtocolFeatures::CONFIG
        }

        fn ack_protocol_features(&mut self, features: u64) -> anyhow::Result<()> {
            let features = VhostUserProtocolFeatures::from_bits(features).ok_or(anyhow!(
                "invalid protocol features are given: 0x{:x}",
                features
            ))?;
            let supported = self.protocol_features();
            self.acked_protocol_features = features & supported;
            Ok(())
        }

        fn acked_protocol_features(&self) -> u64 {
            self.acked_protocol_features.bits()
        }

        fn read_config(&self, offset: u64, dst: &mut [u8]) {
            dst.copy_from_slice(&FAKE_CONFIG_DATA.as_bytes()[offset as usize..]);
        }

        fn reset(&mut self) {}

        fn start_queue(
            &mut self,
            idx: usize,
            queue: Queue,
            _mem: GuestMemory,
            _doorbell: Interrupt,
        ) -> anyhow::Result<()> {
            self.active_queues[idx] = Some(queue);
            Ok(())
        }

        fn stop_queue(&mut self, idx: usize) -> anyhow::Result<Queue> {
            Ok(self.active_queues[idx]
                .take()
                .ok_or(Error::WorkerNotFound)?)
        }
    }

    #[test]
    fn test_vhost_user_activate() {
        const QUEUES_NUM: usize = 2;

        let (dev, vmm) = test_helpers::setup();

        let vmm_bar = Arc::new(Barrier::new(2));
        let dev_bar = vmm_bar.clone();

        let (tx, rx) = channel();

        std::thread::spawn(move || {
            // VMM side
            rx.recv().unwrap(); // Ensure the device is ready.

            let allow_features = 1 << VHOST_USER_F_PROTOCOL_FEATURES;
            let allow_protocol_features = VhostUserProtocolFeatures::CONFIG;
            let connection = test_helpers::connect(vmm);

            let mut vmm_handler =
                VhostUserHandler::new(connection, allow_features, allow_protocol_features).unwrap();

            println!("read_config");
            let mut buf = vec![0; std::mem::size_of::<FakeConfig>()];
            vmm_handler.read_config(0, &mut buf).unwrap();
            // Check if the obtained config data is correct.
            let config = FakeConfig::read_from(buf.as_bytes()).unwrap();
            assert_eq!(config, FAKE_CONFIG_DATA);

            println!("set_mem_table");
            let mem = GuestMemory::new(&[(GuestAddress(0x0), 0x10000)]).unwrap();
            vmm_handler.set_mem_table(&mem).unwrap();

            for idx in 0..QUEUES_NUM {
                println!("activate_mem_table: queue_index={}", idx);
                let mut queue = QueueConfig::new(0x10, 0);
                queue.set_ready(true);
                let queue = queue
                    .activate(&mem, Event::new().unwrap())
                    .expect("QueueConfig::activate");
                let irqfd = Event::new().unwrap();

                vmm_handler
                    .activate_vring(&mem, idx, &queue, &irqfd)
                    .unwrap();
            }

            vmm_handler.sleep().unwrap();

            vmm_handler.wake().unwrap();

            // The VMM side is supposed to stop before the device side.
            drop(vmm_handler);

            vmm_bar.wait();
        });

        // Device side
        let handler = Mutex::new(DeviceRequestHandler::new(
            Box::new(FakeBackend::new()),
            Box::new(VhostUserRegularOps),
        ));

        // Notify listener is ready.
        tx.send(()).unwrap();

        let mut req_handler = test_helpers::listen(dev, handler);

        // VhostUserHandler::new()
        handle_request(&mut req_handler).expect("set_owner");
        handle_request(&mut req_handler).expect("get_features");
        handle_request(&mut req_handler).expect("set_features");
        handle_request(&mut req_handler).expect("get_protocol_features");
        handle_request(&mut req_handler).expect("set_protocol_features");

        // VhostUserHandler::read_config()
        handle_request(&mut req_handler).expect("get_config");

        // VhostUserHandler::set_mem_table()
        handle_request(&mut req_handler).expect("set_mem_table");

        for _ in 0..QUEUES_NUM {
            // VhostUserHandler::activate_vring()
            handle_request(&mut req_handler).expect("set_vring_num");
            handle_request(&mut req_handler).expect("set_vring_addr");
            handle_request(&mut req_handler).expect("set_vring_base");
            handle_request(&mut req_handler).expect("set_vring_call");
            handle_request(&mut req_handler).expect("set_vring_kick");
            handle_request(&mut req_handler).expect("set_vring_enable");
        }

        // sleep
        handle_request(&mut req_handler).expect("sleep");

        // wake
        handle_request(&mut req_handler).expect("wake");

        dev_bar.wait();

        match handle_request(&mut req_handler) {
            Err(VhostError::ClientExit) => (),
            r => panic!("expected Err(ClientExit) but got {:?}", r),
        }
    }

    fn handle_request<S: VhostUserSlaveReqHandler, E: Endpoint<MasterReq>>(
        handler: &mut SlaveReqHandler<S, E>,
    ) -> Result<(), VhostError> {
        let (hdr, files) = handler.recv_header()?;
        handler.process_message(hdr, files)
    }
}
