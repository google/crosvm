// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Library for implementing vhost-user device executables.
//!
//! This crate provides
//! * `VhostUserDevice` trait, which is a collection of methods to handle vhost-user requests, and
//! * `DeviceRequestHandler` struct, which makes a connection to a VMM and starts an event loop.
//!
//! They are expected to be used as follows:
//!
//! 1. Define a struct and implement `VhostUserDevice` for it.
//! 2. Create a `DeviceRequestHandler` with the backend struct.
//! 3. Drive the `DeviceRequestHandler::run` async fn with an executor.
//!
//! ```ignore
//! struct MyBackend {
//!   /* fields */
//! }
//!
//! impl VhostUserDevice for MyBackend {
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
// Implementation note:
// This code lets us take advantage of the vmm_vhost low level implementation of the vhost user
// protocol. DeviceRequestHandler implements the Backend trait from vmm_vhost, and includes some
// common code for setting up guest memory and managing partially configured vrings.
// DeviceRequestHandler::run watches the vhost-user socket and then calls handle_request() when it
// becomes readable. handle_request() reads and parses the message and then calls one of the
// Backend trait methods. These dispatch back to the supplied VhostUserDevice implementation (this
// is what our devices implement).

pub(super) mod sys;

use std::collections::BTreeMap;
use std::convert::From;
use std::fs::File;
use std::io::BufReader;
use std::io::Write;
use std::num::Wrapping;
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
#[cfg(any(target_os = "android", target_os = "linux"))]
use base::clear_fd_flags;
use base::error;
use base::trace;
use base::warn;
use base::Event;
use base::Protection;
use base::SafeDescriptor;
use base::SharedMemory;
use base::WorkerThread;
use cros_async::TaskHandle;
use hypervisor::MemCacheType;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
use sync::Mutex;
use thiserror::Error as ThisError;
use vm_control::VmMemorySource;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::MemoryRegion;
use vmm_vhost::message::VhostSharedMemoryRegion;
use vmm_vhost::message::VhostUserConfigFlags;
use vmm_vhost::message::VhostUserExternalMapMsg;
use vmm_vhost::message::VhostUserGpuMapMsg;
use vmm_vhost::message::VhostUserInflight;
use vmm_vhost::message::VhostUserMemoryRegion;
use vmm_vhost::message::VhostUserMigrationPhase;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserShmemMapMsg;
use vmm_vhost::message::VhostUserShmemMapMsgFlags;
use vmm_vhost::message::VhostUserShmemUnmapMsg;
use vmm_vhost::message::VhostUserSingleMemoryRegion;
use vmm_vhost::message::VhostUserTransferDirection;
use vmm_vhost::message::VhostUserVringAddrFlags;
use vmm_vhost::message::VhostUserVringState;
use vmm_vhost::BackendReq;
use vmm_vhost::Connection;
use vmm_vhost::Error as VhostError;
use vmm_vhost::Frontend;
use vmm_vhost::FrontendClient;
use vmm_vhost::Result as VhostResult;
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

/// Trait for vhost-user devices. Analogous to the `VirtioDevice` trait.
///
/// In contrast with [[vmm_vhost::Backend]], which closely matches the vhost-user spec, this trait
/// is designed to follow crosvm conventions for implementing devices.
pub trait VhostUserDevice {
    /// The maximum number of queues that this backend can manage.
    fn max_queue_num(&self) -> usize;

    /// The set of feature bits that this backend supports.
    fn features(&self) -> u64;

    /// Acknowledges that this set of features should be enabled.
    ///
    /// Implementations only need to handle device-specific feature bits; the `DeviceRequestHandler`
    /// framework will manage generic vhost and vring features.
    ///
    /// `DeviceRequestHandler` checks for valid features before calling this function, so the
    /// features in `value` will always be a subset of those advertised by `features()`.
    fn ack_features(&mut self, _value: u64) -> anyhow::Result<()> {
        Ok(())
    }

    /// The set of protocol feature bits that this backend supports.
    fn protocol_features(&self) -> VhostUserProtocolFeatures;

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, dst: &mut [u8]);

    /// writes `data` to this device's configuration space at `offset`.
    fn write_config(&self, _offset: u64, _data: &[u8]) {}

    /// Indicates that the backend should start processing requests for virtio queue number `idx`.
    /// This method must not block the current thread so device backends should either spawn an
    /// async task or another thread to handle messages from the Queue.
    fn start_queue(&mut self, idx: usize, queue: Queue, mem: GuestMemory) -> anyhow::Result<()>;

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
    /// This method will be called when `VhostUserProtocolFeatures::BACKEND_REQ` is
    /// negotiated.
    fn set_backend_req_connection(&mut self, _conn: VhostBackendReqConnection) {}

    /// Enter the "suspended device state" described in the vhost-user spec. See the spec for
    /// requirements.
    ///
    /// One reasonably foolproof way to satisfy the requirements is to stop all worker threads.
    ///
    /// Called after a `stop_queue` call if there are no running queues left. Also called soon
    /// after device creation to ensure the device is acting suspended immediately on construction.
    ///
    /// The next `start_queue` call implicitly exits the "suspend device state".
    ///
    /// * Ok(())    => device successfully suspended
    /// * Err(_)    => unrecoverable error
    fn enter_suspended_state(&mut self) -> anyhow::Result<()>;

    /// Snapshot device and return serialized state.
    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot>;

    /// Restore device state from a snapshot.
    fn restore(&mut self, data: AnySnapshot) -> anyhow::Result<()>;
}

/// A virtio ring entry.
struct Vring {
    // The queue config. This doesn't get mutated by the queue workers.
    queue: QueueConfig,
    doorbell: Option<Interrupt>,
    enabled: bool,
}

impl Vring {
    fn new(max_size: u16, features: u64) -> Self {
        Self {
            queue: QueueConfig::new(max_size, features),
            doorbell: None,
            enabled: false,
        }
    }

    fn reset(&mut self) {
        self.queue.reset();
        self.doorbell = None;
        self.enabled = false;
    }
}

/// Ops for running vhost-user over a stream (i.e. regular protocol).
pub(super) struct VhostUserRegularOps;

impl VhostUserRegularOps {
    pub fn set_mem_table(
        contexts: &[VhostUserMemoryRegion],
        files: Vec<File>,
    ) -> VhostResult<(GuestMemory, Vec<MappingInfo>)> {
        if files.len() != contexts.len() {
            return Err(VhostError::InvalidParam(
                "number of files & contexts was not equal",
            ));
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
}

/// An adapter that implements `vmm_vhost::Backend` for any type implementing `VhostUserDevice`.
pub struct DeviceRequestHandler<T: VhostUserDevice> {
    vrings: Vec<Vring>,
    owned: bool,
    vmm_maps: Option<Vec<MappingInfo>>,
    mem: Option<GuestMemory>,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
    backend: T,
    backend_req_connection: Option<VhostBackendReqConnection>,
    // Thread processing active device state FD.
    device_state_thread: Option<DeviceStateThread>,
}

enum DeviceStateThread {
    Save(WorkerThread<Result<(), ciborium::ser::Error<std::io::Error>>>),
    Load(WorkerThread<Result<DeviceRequestHandlerSnapshot, ciborium::de::Error<std::io::Error>>>),
}

#[derive(Serialize, Deserialize)]
pub struct DeviceRequestHandlerSnapshot {
    acked_features: u64,
    acked_protocol_features: u64,
    backend: AnySnapshot,
}

impl<T: VhostUserDevice> DeviceRequestHandler<T> {
    /// Creates a vhost-user handler instance for `backend`.
    pub(crate) fn new(mut backend: T) -> Self {
        let mut vrings = Vec::with_capacity(backend.max_queue_num());
        for _ in 0..backend.max_queue_num() {
            vrings.push(Vring::new(Queue::MAX_SIZE, backend.features()));
        }

        // VhostUserDevice implementations must support `enter_suspended_state()`.
        // Call it on startup to ensure it works and to initialize the device in a suspended state.
        backend
            .enter_suspended_state()
            .expect("enter_suspended_state failed on device init");

        DeviceRequestHandler {
            vrings,
            owned: false,
            vmm_maps: None,
            mem: None,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            backend,
            backend_req_connection: None,
            device_state_thread: None,
        }
    }

    /// Check if all queues are stopped.
    ///
    /// The device can be suspended with `enter_suspended_state()` only when all queues are stopped.
    fn all_queues_stopped(&self) -> bool {
        self.vrings.iter().all(|vring| !vring.queue.ready())
    }
}

impl<T: VhostUserDevice> Drop for DeviceRequestHandler<T> {
    fn drop(&mut self) {
        for (index, vring) in self.vrings.iter().enumerate() {
            if vring.queue.ready() {
                if let Err(e) = self.backend.stop_queue(index) {
                    error!("Failed to stop queue {} during drop: {:#}", index, e);
                }
            }
        }
    }
}

impl<T: VhostUserDevice> AsRef<T> for DeviceRequestHandler<T> {
    fn as_ref(&self) -> &T {
        &self.backend
    }
}

impl<T: VhostUserDevice> AsMut<T> for DeviceRequestHandler<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.backend
    }
}

impl<T: VhostUserDevice> vmm_vhost::Backend for DeviceRequestHandler<T> {
    fn set_owner(&mut self) -> VhostResult<()> {
        if self.owned {
            return Err(VhostError::InvalidOperation);
        }
        self.owned = true;
        Ok(())
    }

    fn reset_owner(&mut self) -> VhostResult<()> {
        self.owned = false;
        self.acked_features = 0;
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

        let unexpected_features = features & !self.backend.features();
        if unexpected_features != 0 {
            error!("unexpected set_features {:#x}", unexpected_features);
            return Err(VhostError::InvalidParam("unexpected set_features"));
        }

        if let Err(e) = self.backend.ack_features(features) {
            error!("failed to acknowledge features 0x{:x}: {}", features, e);
            return Err(VhostError::InvalidOperation);
        }

        self.acked_features |= features;

        // If VHOST_USER_F_PROTOCOL_FEATURES has not been negotiated, the ring is initialized in an
        // enabled state.
        // If VHOST_USER_F_PROTOCOL_FEATURES has been negotiated, the ring is initialized in a
        // disabled state.
        // Client must not pass data to/from the backend until ring is enabled by
        // VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has been disabled by
        // VHOST_USER_SET_VRING_ENABLE with parameter 0.
        let vring_enabled = self.acked_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES != 0;
        for v in &mut self.vrings {
            v.enabled = vring_enabled;
        }

        Ok(())
    }

    fn get_protocol_features(&mut self) -> VhostResult<VhostUserProtocolFeatures> {
        Ok(self.backend.protocol_features())
    }

    fn set_protocol_features(&mut self, features: u64) -> VhostResult<()> {
        let features = match VhostUserProtocolFeatures::from_bits(features) {
            Some(proto_features) => proto_features,
            None => {
                error!(
                    "unsupported bits in VHOST_USER_SET_PROTOCOL_FEATURES: {:#x}",
                    features
                );
                return Err(VhostError::InvalidOperation);
            }
        };
        let supported = self.backend.protocol_features();
        self.acked_protocol_features = features & supported;
        Ok(())
    }

    fn set_mem_table(
        &mut self,
        contexts: &[VhostUserMemoryRegion],
        files: Vec<File>,
    ) -> VhostResult<()> {
        let (guest_mem, vmm_maps) = VhostUserRegularOps::set_mem_table(contexts, files)?;
        self.mem = Some(guest_mem);
        self.vmm_maps = Some(vmm_maps);
        Ok(())
    }

    fn get_queue_num(&mut self) -> VhostResult<u64> {
        Ok(self.vrings.len() as u64)
    }

    fn set_vring_num(&mut self, index: u32, num: u32) -> VhostResult<()> {
        if index as usize >= self.vrings.len() || num == 0 || num > Queue::MAX_SIZE.into() {
            return Err(VhostError::InvalidParam(
                "set_vring_num: invalid index or num",
            ));
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
            return Err(VhostError::InvalidParam(
                "set_vring_addr: index out of range",
            ));
        }

        let vmm_maps = self
            .vmm_maps
            .as_ref()
            .ok_or(VhostError::InvalidParam("set_vring_addr: missing vmm_maps"))?;
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
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam(
                "set_vring_base: index out of range",
            ));
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
            .ok_or(VhostError::InvalidParam(
                "get_vring_base: index out of range",
            ))?;

        // Quotation from vhost-user spec:
        // "The back-end must [...] stop ring upon receiving VHOST_USER_GET_VRING_BASE."
        // We only call `queue.set_ready()` when starting the queue, so if the queue is ready, that
        // means it is started and should be stopped.
        let vring_base = if vring.queue.ready() {
            let queue = match self.backend.stop_queue(index as usize) {
                Ok(q) => q,
                Err(e) => {
                    error!("Failed to stop queue in get_vring_base: {:#}", e);
                    return Err(VhostError::BackendInternalError);
                }
            };

            trace!("stopped queue {index}");
            vring.reset();

            if self.all_queues_stopped() {
                trace!("all queues stopped; entering suspended state");
                self.backend
                    .enter_suspended_state()
                    .map_err(VhostError::EnterSuspendedState)?;
            }

            queue.next_avail_to_process()
        } else {
            0
        };

        Ok(VhostUserVringState::new(index, vring_base.into()))
    }

    fn set_vring_kick(&mut self, index: u8, file: Option<File>) -> VhostResult<()> {
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam(
                "set_vring_kick: index out of range",
            ));
        }

        let vring = &mut self.vrings[index as usize];
        if vring.queue.ready() {
            error!("kick fd cannot replaced after queue is started");
            return Err(VhostError::InvalidOperation);
        }

        let file = file.ok_or(VhostError::InvalidParam("missing file for set_vring_kick"))?;

        // Remove O_NONBLOCK from kick_fd. Otherwise, uring_executor will fails when we read
        // values via `next_val()` later.
        // This is only required (and can only be done) on Unix platforms.
        #[cfg(any(target_os = "android", target_os = "linux"))]
        if let Err(e) = clear_fd_flags(file.as_raw_fd(), libc::O_NONBLOCK) {
            error!("failed to remove O_NONBLOCK for kick fd: {}", e);
            return Err(VhostError::InvalidParam(
                "could not remove O_NONBLOCK from vring_kick",
            ));
        }

        let kick_evt = Event::from(SafeDescriptor::from(file));

        // Enable any virtqueue features that were negotiated (like VIRTIO_RING_F_EVENT_IDX).
        vring.queue.ack_features(self.acked_features);
        vring.queue.set_ready(true);

        let mem = self
            .mem
            .as_ref()
            .cloned()
            .ok_or(VhostError::InvalidOperation)?;

        let doorbell = vring.doorbell.clone().ok_or(VhostError::InvalidOperation)?;

        let queue = match vring.queue.activate(&mem, kick_evt, doorbell) {
            Ok(queue) => queue,
            Err(e) => {
                error!("failed to activate vring: {:#}", e);
                return Err(VhostError::BackendInternalError);
            }
        };

        if let Err(e) = self.backend.start_queue(index as usize, queue, mem) {
            error!("Failed to start queue {}: {}", index, e);
            return Err(VhostError::BackendInternalError);
        }
        trace!("started queue {index}");

        Ok(())
    }

    fn set_vring_call(&mut self, index: u8, file: Option<File>) -> VhostResult<()> {
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam(
                "set_vring_call: index out of range",
            ));
        }

        let backend_req_conn = self.backend_req_connection.clone();
        let signal_config_change_fn = Box::new(move || {
            if let Some(frontend) = backend_req_conn.as_ref() {
                if let Err(e) = frontend.send_config_changed() {
                    error!("Failed to notify config change: {:#}", e);
                }
            } else {
                error!("No Backend request connection found");
            }
        });

        let file = file.ok_or(VhostError::InvalidParam("missing file for set_vring_call"))?;
        self.vrings[index as usize].doorbell = Some(Interrupt::new_vhost_user(
            Event::from(SafeDescriptor::from(file)),
            signal_config_change_fn,
        ));
        Ok(())
    }

    fn set_vring_err(&mut self, _index: u8, _fd: Option<File>) -> VhostResult<()> {
        // TODO
        Ok(())
    }

    fn set_vring_enable(&mut self, index: u32, enable: bool) -> VhostResult<()> {
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam(
                "set_vring_enable: index out of range",
            ));
        }

        // This request should be handled only when VHOST_USER_F_PROTOCOL_FEATURES
        // has been negotiated.
        if self.acked_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES == 0 {
            return Err(VhostError::InvalidOperation);
        }

        // Backend must not pass data to/from the ring until ring is enabled by
        // VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has been disabled by
        // VHOST_USER_SET_VRING_ENABLE with parameter 0.
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

    fn set_backend_req_fd(&mut self, ep: Connection<BackendReq>) {
        let conn = VhostBackendReqConnection::new(
            FrontendClient::new(ep),
            self.backend.get_shared_memory_region().map(|r| r.id),
        );

        if self.backend_req_connection.is_some() {
            warn!("Backend Request Connection already established. Overwriting");
        }
        self.backend_req_connection = Some(conn.clone());

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

    fn set_device_state_fd(
        &mut self,
        transfer_direction: VhostUserTransferDirection,
        migration_phase: VhostUserMigrationPhase,
        fd: File,
    ) -> VhostResult<Option<File>> {
        if migration_phase != VhostUserMigrationPhase::Stopped {
            return Err(VhostError::InvalidOperation);
        }
        if !self.all_queues_stopped() {
            return Err(VhostError::InvalidOperation);
        }
        if self.device_state_thread.is_some() {
            error!("must call check_device_state before starting new state transfer");
            return Err(VhostError::InvalidOperation);
        }
        // `set_device_state_fd` is designed to allow snapshot/restore concurrently with other
        // methods, but, for simplicitly, we do those operations inline and only spawn a thread to
        // handle the serialization and data transfer (the latter which seems necessary to
        // implement the API correctly without, e.g., deadlocking because a pipe is full).
        match transfer_direction {
            VhostUserTransferDirection::Save => {
                // Snapshot the state.
                let snapshot = DeviceRequestHandlerSnapshot {
                    acked_features: self.acked_features,
                    acked_protocol_features: self.acked_protocol_features.bits(),
                    backend: self.backend.snapshot().map_err(VhostError::SnapshotError)?,
                };
                // Spawn thread to write the serialized bytes.
                self.device_state_thread = Some(DeviceStateThread::Save(WorkerThread::start(
                    "device_state_save",
                    move |_kill_event| -> Result<(), ciborium::ser::Error<std::io::Error>> {
                        let mut w = std::io::BufWriter::new(fd);
                        ciborium::into_writer(&snapshot, &mut w)?;
                        w.flush()?;
                        Ok(())
                    },
                )));
                Ok(None)
            }
            VhostUserTransferDirection::Load => {
                // Spawn a thread to read the bytes and deserialize. Restore will happen in
                // `check_device_state`.
                self.device_state_thread = Some(DeviceStateThread::Load(WorkerThread::start(
                    "device_state_load",
                    move |_kill_event| ciborium::from_reader(&mut BufReader::new(fd)),
                )));
                Ok(None)
            }
        }
    }

    fn check_device_state(&mut self) -> VhostResult<()> {
        let Some(thread) = self.device_state_thread.take() else {
            error!("check_device_state: no active state transfer");
            return Err(VhostError::InvalidOperation);
        };
        match thread {
            DeviceStateThread::Save(worker) => {
                worker.stop().map_err(|e| {
                    error!("device state save thread failed: {:#}", e);
                    VhostError::BackendInternalError
                })?;
                Ok(())
            }
            DeviceStateThread::Load(worker) => {
                let snapshot = worker.stop().map_err(|e| {
                    error!("device state load thread failed: {:#}", e);
                    VhostError::BackendInternalError
                })?;
                self.acked_features = snapshot.acked_features;
                self.acked_protocol_features =
                    VhostUserProtocolFeatures::from_bits(snapshot.acked_protocol_features)
                        .with_context(|| {
                            format!(
                                "unsupported bits in acked_protocol_features: {:#x}",
                                snapshot.acked_protocol_features
                            )
                        })
                        .map_err(VhostError::RestoreError)?;
                self.backend
                    .restore(snapshot.backend)
                    .map_err(VhostError::RestoreError)?;
                Ok(())
            }
        }
    }

    fn get_shared_memory_regions(&mut self) -> VhostResult<Vec<VhostSharedMemoryRegion>> {
        Ok(if let Some(r) = self.backend.get_shared_memory_region() {
            vec![VhostSharedMemoryRegion::new(r.id, r.length)]
        } else {
            Vec::new()
        })
    }
}

/// Keeps track of Vhost user backend request connection.
#[derive(Clone)]
pub struct VhostBackendReqConnection {
    shared: Arc<Mutex<VhostBackendReqConnectionShared>>,
    shmid: Option<u8>,
}

struct VhostBackendReqConnectionShared {
    conn: FrontendClient,
    mapped_regions: BTreeMap<u64 /* offset */, u64 /* size */>,
}

impl VhostBackendReqConnection {
    fn new(conn: FrontendClient, shmid: Option<u8>) -> Self {
        Self {
            shared: Arc::new(Mutex::new(VhostBackendReqConnectionShared {
                conn,
                mapped_regions: BTreeMap::new(),
            })),
            shmid,
        }
    }

    /// Send `VHOST_USER_CONFIG_CHANGE_MSG` to the frontend
    fn send_config_changed(&self) -> anyhow::Result<()> {
        let mut shared = self.shared.lock();
        shared
            .conn
            .handle_config_change()
            .context("Could not send config change message")?;
        Ok(())
    }

    /// Create a SharedMemoryMapper trait object using this backend request connection.
    pub fn shmem_mapper(&self) -> Option<Box<dyn SharedMemoryMapper>> {
        if let Some(shmid) = self.shmid {
            Some(Box::new(VhostShmemMapper {
                shared: self.shared.clone(),
                shmid,
            }))
        } else {
            None
        }
    }
}

#[derive(Clone)]
struct VhostShmemMapper {
    shared: Arc<Mutex<VhostBackendReqConnectionShared>>,
    shmid: u8,
}

impl SharedMemoryMapper for VhostShmemMapper {
    fn add_mapping(
        &mut self,
        source: VmMemorySource,
        offset: u64,
        prot: Protection,
        _cache: MemCacheType,
    ) -> anyhow::Result<()> {
        let mut shared = self.shared.lock();
        let size = match source {
            VmMemorySource::Vulkan {
                descriptor,
                handle_type,
                memory_idx,
                device_uuid,
                driver_uuid,
                size,
            } => {
                let msg = VhostUserGpuMapMsg::new(
                    self.shmid,
                    offset,
                    size,
                    memory_idx,
                    handle_type,
                    device_uuid,
                    driver_uuid,
                );
                shared
                    .conn
                    .gpu_map(&msg, &descriptor)
                    .context("map GPU memory")?;
                size
            }
            VmMemorySource::ExternalMapping { ptr, size } => {
                let msg = VhostUserExternalMapMsg::new(self.shmid, offset, size, ptr);
                shared
                    .conn
                    .external_map(&msg)
                    .context("create external mapping")?;
                size
            }
            source => {
                // The last two sources use the same VhostUserShmemMapMsg, continue matching here
                // on the aliased `source` above.
                let (descriptor, fd_offset, size) = match source {
                    VmMemorySource::Descriptor {
                        descriptor,
                        offset,
                        size,
                    } => (descriptor, offset, size),
                    VmMemorySource::SharedMemory(shmem) => {
                        let size = shmem.size();
                        let descriptor = SafeDescriptor::from(shmem);
                        (descriptor, 0, size)
                    }
                    _ => bail!("unsupported source"),
                };
                let flags = VhostUserShmemMapMsgFlags::from(prot);
                let msg = VhostUserShmemMapMsg::new(self.shmid, offset, fd_offset, size, flags);
                shared
                    .conn
                    .shmem_map(&msg, &descriptor)
                    .context("map shmem")?;
                size
            }
        };

        shared.mapped_regions.insert(offset, size);
        Ok(())
    }

    fn remove_mapping(&mut self, offset: u64) -> anyhow::Result<()> {
        let mut shared = self.shared.lock();
        let size = shared
            .mapped_regions
            .remove(&offset)
            .context("unknown offset")?;
        let msg = VhostUserShmemUnmapMsg::new(self.shmid, offset, size);
        shared
            .conn
            .shmem_unmap(&msg)
            .context("unmap shmem")
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

    use anyhow::bail;
    use base::Event;
    use vmm_vhost::BackendServer;
    use vmm_vhost::FrontendReq;
    use zerocopy::FromBytes;
    use zerocopy::FromZeros;
    use zerocopy::Immutable;
    use zerocopy::IntoBytes;
    use zerocopy::KnownLayout;

    use super::*;
    use crate::virtio::vhost_user_frontend::VhostUserFrontend;
    use crate::virtio::DeviceType;
    use crate::virtio::VirtioDevice;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, Immutable, IntoBytes, KnownLayout)]
    #[repr(C, packed(4))]
    struct FakeConfig {
        x: u32,
        y: u64,
    }

    const FAKE_CONFIG_DATA: FakeConfig = FakeConfig { x: 1, y: 2 };

    pub(super) struct FakeBackend {
        avail_features: u64,
        acked_features: u64,
        active_queues: Vec<Option<Queue>>,
        allow_backend_req: bool,
        backend_conn: Option<VhostBackendReqConnection>,
    }

    #[derive(Deserialize, Serialize)]
    struct FakeBackendSnapshot {
        data: Vec<u8>,
    }

    impl FakeBackend {
        const MAX_QUEUE_NUM: usize = 16;

        pub(super) fn new() -> Self {
            let mut active_queues = Vec::new();
            active_queues.resize_with(Self::MAX_QUEUE_NUM, Default::default);
            Self {
                avail_features: 1 << VHOST_USER_F_PROTOCOL_FEATURES,
                acked_features: 0,
                active_queues,
                allow_backend_req: false,
                backend_conn: None,
            }
        }
    }

    impl VhostUserDevice for FakeBackend {
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

        fn protocol_features(&self) -> VhostUserProtocolFeatures {
            let mut features =
                VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::DEVICE_STATE;
            if self.allow_backend_req {
                features |= VhostUserProtocolFeatures::BACKEND_REQ;
            }
            features
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
        ) -> anyhow::Result<()> {
            self.active_queues[idx] = Some(queue);
            Ok(())
        }

        fn stop_queue(&mut self, idx: usize) -> anyhow::Result<Queue> {
            Ok(self.active_queues[idx]
                .take()
                .ok_or(Error::WorkerNotFound)?)
        }

        fn set_backend_req_connection(&mut self, conn: VhostBackendReqConnection) {
            self.backend_conn = Some(conn);
        }

        fn enter_suspended_state(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
            AnySnapshot::to_any(FakeBackendSnapshot {
                data: vec![1, 2, 3],
            })
            .context("failed to serialize snapshot")
        }

        fn restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
            let snapshot: FakeBackendSnapshot =
                AnySnapshot::from_any(data).context("failed to deserialize snapshot")?;
            assert_eq!(snapshot.data, vec![1, 2, 3], "bad snapshot data");
            Ok(())
        }
    }

    #[test]
    fn test_vhost_user_lifecycle() {
        test_vhost_user_lifecycle_parameterized(false);
    }

    #[test]
    #[cfg(not(windows))] // Windows requries more complex connection setup.
    fn test_vhost_user_lifecycle_with_backend_req() {
        test_vhost_user_lifecycle_parameterized(true);
    }

    fn test_vhost_user_lifecycle_parameterized(allow_backend_req: bool) {
        const QUEUES_NUM: usize = 2;

        let (client_connection, server_connection) =
            vmm_vhost::Connection::<FrontendReq>::pair().unwrap();

        let vmm_bar = Arc::new(Barrier::new(2));
        let dev_bar = vmm_bar.clone();

        let (ready_tx, ready_rx) = channel();
        let (shutdown_tx, shutdown_rx) = channel();
        let (vm_evt_wrtube, _vm_evt_rdtube) = base::Tube::directional_pair().unwrap();

        std::thread::spawn(move || {
            // VMM side
            ready_rx.recv().unwrap(); // Ensure the device is ready.

            let mut vmm_device = VhostUserFrontend::new(
                DeviceType::Console,
                0,
                client_connection,
                vm_evt_wrtube,
                None,
                None,
            )
            .unwrap();

            println!("read_config");
            let mut config = FakeConfig::new_zeroed();
            vmm_device.read_config(0, config.as_mut_bytes());
            // Check if the obtained config data is correct.
            assert_eq!(config, FAKE_CONFIG_DATA);

            let activate = |vmm_device: &mut VhostUserFrontend| {
                let mem = GuestMemory::new(&[(GuestAddress(0x0), 0x10000)]).unwrap();
                let interrupt = Interrupt::new_for_test_with_msix();

                let mut queues = BTreeMap::new();
                for idx in 0..QUEUES_NUM {
                    let mut queue = QueueConfig::new(0x10, 0);
                    queue.set_ready(true);
                    let queue = queue
                        .activate(&mem, Event::new().unwrap(), interrupt.clone())
                        .expect("QueueConfig::activate");
                    queues.insert(idx, queue);
                }

                println!("activate");
                vmm_device.activate(mem, interrupt, queues).unwrap();
            };

            activate(&mut vmm_device);

            println!("reset");
            let reset_result = vmm_device.reset();
            assert!(
                reset_result.is_ok(),
                "reset failed: {:#}",
                reset_result.unwrap_err()
            );

            activate(&mut vmm_device);

            println!("virtio_sleep");
            let queues = vmm_device
                .virtio_sleep()
                .unwrap()
                .expect("virtio_sleep unexpectedly returned None");

            println!("virtio_snapshot");
            let snapshot = vmm_device
                .virtio_snapshot()
                .expect("virtio_snapshot failed");
            println!("virtio_restore");
            vmm_device
                .virtio_restore(snapshot)
                .expect("virtio_restore failed");

            println!("virtio_wake");
            let mem = GuestMemory::new(&[(GuestAddress(0x0), 0x10000)]).unwrap();
            let interrupt = Interrupt::new_for_test_with_msix();
            vmm_device
                .virtio_wake(Some((mem, interrupt, queues)))
                .unwrap();

            println!("wait for shutdown signal");
            shutdown_rx.recv().unwrap();

            // The VMM side is supposed to stop before the device side.
            println!("drop");
            drop(vmm_device);

            vmm_bar.wait();
        });

        // Device side
        let mut handler = DeviceRequestHandler::new(FakeBackend::new());
        handler.as_mut().allow_backend_req = allow_backend_req;

        // Notify listener is ready.
        ready_tx.send(()).unwrap();

        let mut req_handler = BackendServer::new(server_connection, handler);

        // VhostUserFrontend::new()
        handle_request(&mut req_handler, FrontendReq::SET_OWNER).unwrap();
        handle_request(&mut req_handler, FrontendReq::GET_FEATURES).unwrap();
        handle_request(&mut req_handler, FrontendReq::GET_PROTOCOL_FEATURES).unwrap();
        handle_request(&mut req_handler, FrontendReq::SET_PROTOCOL_FEATURES).unwrap();
        if allow_backend_req {
            handle_request(&mut req_handler, FrontendReq::SET_BACKEND_REQ_FD).unwrap();
        }

        // VhostUserFrontend::read_config()
        handle_request(&mut req_handler, FrontendReq::GET_CONFIG).unwrap();

        // VhostUserFrontend::activate()
        handle_request(&mut req_handler, FrontendReq::SET_FEATURES).unwrap();
        handle_request(&mut req_handler, FrontendReq::SET_MEM_TABLE).unwrap();
        for _ in 0..QUEUES_NUM {
            handle_request(&mut req_handler, FrontendReq::SET_VRING_NUM).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_ADDR).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_BASE).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_CALL).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_KICK).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_ENABLE).unwrap();
        }

        // VhostUserFrontend::reset()
        for _ in 0..QUEUES_NUM {
            handle_request(&mut req_handler, FrontendReq::SET_VRING_ENABLE).unwrap();
            handle_request(&mut req_handler, FrontendReq::GET_VRING_BASE).unwrap();
        }

        // VhostUserFrontend::activate()
        handle_request(&mut req_handler, FrontendReq::SET_FEATURES).unwrap();
        handle_request(&mut req_handler, FrontendReq::SET_MEM_TABLE).unwrap();
        for _ in 0..QUEUES_NUM {
            handle_request(&mut req_handler, FrontendReq::SET_VRING_NUM).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_ADDR).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_BASE).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_CALL).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_KICK).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_ENABLE).unwrap();
        }

        if allow_backend_req {
            // Make sure the connection still works even after reset/reactivate.
            req_handler
                .as_ref()
                .as_ref()
                .backend_conn
                .as_ref()
                .expect("backend_conn missing")
                .send_config_changed()
                .expect("send_config_changed failed");
        }

        // VhostUserFrontend::virtio_sleep()
        for _ in 0..QUEUES_NUM {
            handle_request(&mut req_handler, FrontendReq::SET_VRING_ENABLE).unwrap();
            handle_request(&mut req_handler, FrontendReq::GET_VRING_BASE).unwrap();
        }

        // VhostUserFrontend::virtio_snapshot()
        handle_request(&mut req_handler, FrontendReq::SET_DEVICE_STATE_FD).unwrap();
        handle_request(&mut req_handler, FrontendReq::CHECK_DEVICE_STATE).unwrap();
        // VhostUserFrontend::virtio_restore()
        handle_request(&mut req_handler, FrontendReq::SET_DEVICE_STATE_FD).unwrap();
        handle_request(&mut req_handler, FrontendReq::CHECK_DEVICE_STATE).unwrap();

        // VhostUserFrontend::virtio_wake()
        handle_request(&mut req_handler, FrontendReq::SET_MEM_TABLE).unwrap();
        for _ in 0..QUEUES_NUM {
            handle_request(&mut req_handler, FrontendReq::SET_VRING_NUM).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_ADDR).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_BASE).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_CALL).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_KICK).unwrap();
            handle_request(&mut req_handler, FrontendReq::SET_VRING_ENABLE).unwrap();
        }

        if allow_backend_req {
            // Make sure the connection still works even after sleep/wake.
            req_handler
                .as_ref()
                .as_ref()
                .backend_conn
                .as_ref()
                .expect("backend_conn missing")
                .send_config_changed()
                .expect("send_config_changed failed");
        }

        // Ask the client to shutdown, then wait to it to finish.
        shutdown_tx.send(()).unwrap();
        dev_bar.wait();

        // Verify recv_header fails with `ClientExit` after the client has disconnected.
        match req_handler.recv_header() {
            Err(VhostError::ClientExit) => (),
            r => panic!("expected Err(ClientExit) but got {:?}", r),
        }
    }

    fn handle_request<S: vmm_vhost::Backend>(
        handler: &mut BackendServer<S>,
        expected_message_type: FrontendReq,
    ) -> Result<(), VhostError> {
        let (hdr, files) = handler.recv_header()?;
        assert_eq!(hdr.get_code(), Ok(expected_message_type));
        handler.process_message(hdr, files)
    }
}
