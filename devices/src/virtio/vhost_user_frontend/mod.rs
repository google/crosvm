// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! VirtioDevice implementation for the VMM side of a vhost-user connection.

mod error;
mod handler;
mod sys;
mod worker;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Read;
use std::io::Write;

use anyhow::bail;
use anyhow::Context;
use base::error;
use base::trace;
use base::AsRawDescriptor;
#[cfg(windows)]
use base::CloseNotifier;
use base::Event;
use base::RawDescriptor;
use base::ReadNotifier;
use base::SafeDescriptor;
use base::WorkerThread;
use snapshot::AnySnapshot;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserConfigFlags;
use vmm_vhost::message::VhostUserMigrationPhase;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserTransferDirection;
use vmm_vhost::BackendClient;
use vmm_vhost::VhostUserMemoryRegionInfo;
use vmm_vhost::VringConfigData;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;

use crate::virtio::device_constants::VIRTIO_DEVICE_TYPE_SPECIFIC_FEATURES_MASK;
use crate::virtio::vhost_user_frontend::error::Error;
use crate::virtio::vhost_user_frontend::error::Result;
use crate::virtio::vhost_user_frontend::handler::BackendReqHandler;
use crate::virtio::vhost_user_frontend::handler::BackendReqHandlerImpl;
use crate::virtio::vhost_user_frontend::sys::create_backend_req_handler;
use crate::virtio::vhost_user_frontend::worker::Worker;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::SharedMemoryMapper;
use crate::virtio::SharedMemoryRegion;
use crate::virtio::VirtioDevice;
use crate::PciAddress;

pub struct VhostUserFrontend {
    device_type: DeviceType,
    worker_thread: Option<WorkerThread<Option<BackendReqHandler>>>,

    backend_client: BackendClient,
    avail_features: u64,
    acked_features: u64,
    sent_set_features: bool,
    protocol_features: VhostUserProtocolFeatures,
    // `backend_req_handler` is only present if the backend supports BACKEND_REQ. `worker_thread`
    // takes ownership of `backend_req_handler` when it starts. The worker thread will always
    // return ownershp of the handler when stopped.
    backend_req_handler: Option<BackendReqHandler>,
    // Shared memory region info. IPC result from backend is saved with outer Option.
    shmem_region: RefCell<Option<Option<SharedMemoryRegion>>>,

    queue_sizes: Vec<u16>,
    expose_shmem_descriptors_with_viommu: bool,
    pci_address: Option<PciAddress>,

    // Queues that have been sent to the backend. Always `Some` when active and not asleep. Saved
    // for use in `virtio_sleep`. Since the backend is managing them, the local state of the queue
    // is likely stale.
    sent_queues: Option<BTreeMap<usize, Queue>>,
}

// Returns the largest power of two that is less than or equal to `val`.
fn power_of_two_le(val: u16) -> Option<u16> {
    if val == 0 {
        None
    } else if val.is_power_of_two() {
        Some(val)
    } else {
        val.checked_next_power_of_two()
            .map(|next_pow_two| next_pow_two / 2)
    }
}

impl VhostUserFrontend {
    /// Create a new VirtioDevice for a vhost-user device frontend.
    ///
    /// # Arguments
    ///
    /// - `device_type`: virtio device type
    /// - `base_features`: base virtio device features (e.g. `VIRTIO_F_VERSION_1`)
    /// - `connection`: connection to the device backend
    /// - `max_queue_size`: maximum number of entries in each queue (default: [`Queue::MAX_SIZE`])
    pub fn new(
        device_type: DeviceType,
        mut base_features: u64,
        connection: vmm_vhost::Connection<vmm_vhost::FrontendReq>,
        max_queue_size: Option<u16>,
        pci_address: Option<PciAddress>,
    ) -> Result<VhostUserFrontend> {
        // Don't allow packed queues even if requested. We don't handle them properly yet at the
        // protocol layer.
        // TODO: b/331466964 - Remove once packed queue support is added to BackendClient.
        if base_features & (1 << virtio_sys::virtio_config::VIRTIO_F_RING_PACKED) != 0 {
            base_features &= !(1 << virtio_sys::virtio_config::VIRTIO_F_RING_PACKED);
            base::warn!(
                "VIRTIO_F_RING_PACKED requested, but not yet supported by vhost-user frontend. \
                Automatically disabled."
            );
        }

        #[cfg(windows)]
        let backend_pid = connection.target_pid();

        let mut backend_client = BackendClient::new(connection);

        backend_client.set_owner().map_err(Error::SetOwner)?;

        let allow_features = VIRTIO_DEVICE_TYPE_SPECIFIC_FEATURES_MASK
            | base_features
            | 1 << VHOST_USER_F_PROTOCOL_FEATURES;
        let avail_features =
            allow_features & backend_client.get_features().map_err(Error::GetFeatures)?;
        let mut acked_features = 0;

        let mut allow_protocol_features = VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::BACKEND_REQ
            | VhostUserProtocolFeatures::DEVICE_STATE;

        // HACK: the crosvm vhost-user GPU backend supports the non-standard
        // VHOST_USER_PROTOCOL_FEATURE_SHARED_MEMORY_REGIONS. This should either be standardized
        // (and enabled for all device types) or removed.
        let expose_shmem_descriptors_with_viommu = if device_type == DeviceType::Gpu {
            allow_protocol_features |= VhostUserProtocolFeatures::SHARED_MEMORY_REGIONS;
            true
        } else {
            false
        };

        let mut protocol_features = VhostUserProtocolFeatures::empty();
        if avail_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES != 0 {
            // The vhost-user backend supports VHOST_USER_F_PROTOCOL_FEATURES.
            // Per the vhost-user protocol, the backend must support
            // `VHOST_USER_GET_PROTOCOL_FEATURES` and `VHOST_USER_SET_PROTOCOL_FEATURES` even
            // before acknowledging the feature, so we don't need to call `set_features()` yet
            // (and doing so before driver feature negotiation may confuse some backends),
            // but add it to `acked_features` so it will be included in any future
            // `set_features()` calls.
            acked_features |= 1 << VHOST_USER_F_PROTOCOL_FEATURES;

            let avail_protocol_features = backend_client
                .get_protocol_features()
                .map_err(Error::GetProtocolFeatures)?;
            protocol_features = allow_protocol_features & avail_protocol_features;
            backend_client
                .set_protocol_features(protocol_features)
                .map_err(Error::SetProtocolFeatures)?;
        }

        // if protocol feature `VhostUserProtocolFeatures::BACKEND_REQ` is negotiated.
        let backend_req_handler =
            if protocol_features.contains(VhostUserProtocolFeatures::BACKEND_REQ) {
                let (handler, tx_fd) = create_backend_req_handler(
                    BackendReqHandlerImpl::new(),
                    #[cfg(windows)]
                    backend_pid,
                )?;
                backend_client
                    .set_backend_req_fd(&tx_fd)
                    .map_err(Error::SetDeviceRequestChannel)?;
                Some(handler)
            } else {
                None
            };

        // If the device supports VHOST_USER_PROTOCOL_F_MQ, use VHOST_USER_GET_QUEUE_NUM to
        // determine the number of queues supported. Otherwise, use the minimum number of queues
        // required by the spec for this device type.
        let num_queues = if protocol_features.contains(VhostUserProtocolFeatures::MQ) {
            trace!("backend supports VHOST_USER_PROTOCOL_F_MQ");
            let num_queues = backend_client.get_queue_num().map_err(Error::GetQueueNum)?;
            trace!("VHOST_USER_GET_QUEUE_NUM returned {num_queues}");
            num_queues as usize
        } else {
            trace!("backend does not support VHOST_USER_PROTOCOL_F_MQ");
            device_type.min_queues()
        };

        // Clamp the maximum queue size to the largest power of 2 <= max_queue_size.
        let max_queue_size = max_queue_size
            .and_then(power_of_two_le)
            .unwrap_or(Queue::MAX_SIZE);

        trace!(
            "vhost-user {device_type} frontend with {num_queues} queues x {max_queue_size} entries\
            {}",
            if let Some(pci_address) = pci_address {
                format!(" pci-address {pci_address}")
            } else {
                "".to_string()
            }
        );

        let queue_sizes = vec![max_queue_size; num_queues];

        Ok(VhostUserFrontend {
            device_type,
            worker_thread: None,
            backend_client,
            avail_features,
            acked_features,
            sent_set_features: false,
            protocol_features,
            backend_req_handler,
            shmem_region: RefCell::new(None),
            queue_sizes,
            expose_shmem_descriptors_with_viommu,
            pci_address,
            sent_queues: None,
        })
    }

    fn set_mem_table(&mut self, mem: &GuestMemory) -> Result<()> {
        let regions: Vec<_> = mem
            .regions()
            .map(|region| VhostUserMemoryRegionInfo {
                guest_phys_addr: region.guest_addr.0,
                memory_size: region.size as u64,
                userspace_addr: region.host_addr as u64,
                mmap_offset: region.shm_offset,
                mmap_handle: region.shm.as_raw_descriptor(),
            })
            .collect();

        self.backend_client
            .set_mem_table(regions.as_slice())
            .map_err(Error::SetMemTable)?;

        Ok(())
    }

    /// Activates a vring for the given `queue`.
    fn activate_vring(
        &mut self,
        mem: &GuestMemory,
        queue_index: usize,
        queue: &Queue,
        irqfd: &Event,
    ) -> Result<()> {
        self.backend_client
            .set_vring_num(queue_index, queue.size())
            .map_err(Error::SetVringNum)?;

        let config_data = VringConfigData {
            queue_size: queue.size(),
            flags: 0u32,
            desc_table_addr: mem
                .get_host_address(queue.desc_table())
                .map_err(Error::GetHostAddress)? as u64,
            used_ring_addr: mem
                .get_host_address(queue.used_ring())
                .map_err(Error::GetHostAddress)? as u64,
            avail_ring_addr: mem
                .get_host_address(queue.avail_ring())
                .map_err(Error::GetHostAddress)? as u64,
            log_addr: None,
        };
        self.backend_client
            .set_vring_addr(queue_index, &config_data)
            .map_err(Error::SetVringAddr)?;

        self.backend_client
            .set_vring_base(queue_index, queue.next_avail_to_process())
            .map_err(Error::SetVringBase)?;

        self.backend_client
            .set_vring_call(queue_index, irqfd)
            .map_err(Error::SetVringCall)?;
        self.backend_client
            .set_vring_kick(queue_index, queue.event())
            .map_err(Error::SetVringKick)?;

        // Per protocol documentation, `VHOST_USER_SET_VRING_ENABLE` should be sent only when
        // `VHOST_USER_F_PROTOCOL_FEATURES` has been negotiated.
        if self.acked_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES != 0 {
            self.backend_client
                .set_vring_enable(queue_index, true)
                .map_err(Error::SetVringEnable)?;
        }

        Ok(())
    }

    /// Stops the vring for the given `queue`, returning its base index.
    fn deactivate_vring(&self, queue_index: usize) -> Result<u16> {
        if self.acked_features & 1 << VHOST_USER_F_PROTOCOL_FEATURES != 0 {
            self.backend_client
                .set_vring_enable(queue_index, false)
                .map_err(Error::SetVringEnable)?;
        }

        let vring_base = self
            .backend_client
            .get_vring_base(queue_index)
            .map_err(Error::GetVringBase)?;

        vring_base
            .try_into()
            .map_err(|_| Error::VringBaseTooBig(vring_base))
    }

    /// Helper to start up the worker thread that will be used with handling interrupts and requests
    /// from the device process.
    fn start_worker(&mut self, interrupt: Interrupt, non_msix_evt: Event) {
        assert!(
            self.worker_thread.is_none(),
            "BUG: attempted to start worker twice"
        );

        let label = self.debug_label();

        let mut backend_req_handler = self.backend_req_handler.take();
        if let Some(handler) = &mut backend_req_handler {
            // Using unwrap here to get the mutex protected value
            handler.frontend_mut().set_interrupt(interrupt.clone());
        }

        let backend_client_read_notifier =
            SafeDescriptor::try_from(self.backend_client.get_read_notifier())
                .expect("failed to get backend read notifier");
        #[cfg(windows)]
        let backend_client_close_notifier =
            SafeDescriptor::try_from(self.backend_client.get_close_notifier())
                .expect("failed to get backend close notifier");

        self.worker_thread = Some(WorkerThread::start(label.clone(), move |kill_evt| {
            let mut worker = Worker {
                kill_evt,
                non_msix_evt,
                backend_req_handler,
                backend_client_read_notifier,
                #[cfg(windows)]
                backend_client_close_notifier,
            };
            worker
                .run(interrupt)
                .with_context(|| format!("{label}: vhost_user_frontend worker failed"))
                .unwrap();
            worker.backend_req_handler
        }));
    }
}

impl VirtioDevice for VhostUserFrontend {
    // Override the default debug label to differentiate vhost-user devices from virtio.
    fn debug_label(&self) -> String {
        format!("vu-{}", self.device_type())
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn device_type(&self) -> DeviceType {
        self.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, features: u64) {
        let features = (features & self.avail_features) | self.acked_features;
        if let Err(e) = self
            .backend_client
            .set_features(features)
            .map_err(Error::SetFeatures)
        {
            error!("failed to enable features 0x{:x}: {}", features, e);
            return;
        }
        self.acked_features = features;
        self.sent_set_features = true;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let Ok(offset) = offset.try_into() else {
            error!("failed to read config: invalid config offset is given: {offset}");
            return;
        };
        let Ok(data_len) = data.len().try_into() else {
            error!(
                "failed to read config: invalid config length is given: {}",
                data.len()
            );
            return;
        };
        let (_, config) = match self.backend_client.get_config(
            offset,
            data_len,
            VhostUserConfigFlags::WRITABLE,
            data,
        ) {
            Ok(x) => x,
            Err(e) => {
                error!("failed to read config: {}", Error::GetConfig(e));
                return;
            }
        };
        data.copy_from_slice(&config);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let Ok(offset) = offset.try_into() else {
            error!("failed to write config: invalid config offset is given: {offset}");
            return;
        };
        if let Err(e) = self
            .backend_client
            .set_config(offset, VhostUserConfigFlags::empty(), data)
            .map_err(Error::SetConfig)
        {
            error!("failed to write config: {}", e);
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        // Ensure at least one `VHOST_USER_SET_FEATURES` is sent before activation.
        if !self.sent_set_features {
            self.ack_features(self.acked_features);
        }

        self.set_mem_table(&mem)?;

        let msix_config_opt = interrupt
            .get_msix_config()
            .as_ref()
            .ok_or(Error::MsixConfigUnavailable)?;
        let msix_config = msix_config_opt.lock();

        let non_msix_evt = Event::new().map_err(Error::CreateEvent)?;
        for (&queue_index, queue) in queues.iter() {
            let irqfd = msix_config
                .get_irqfd(queue.vector() as usize)
                .unwrap_or(&non_msix_evt);
            self.activate_vring(&mem, queue_index, queue, irqfd)?;
        }

        self.sent_queues = Some(queues);

        drop(msix_config);

        self.start_worker(interrupt, non_msix_evt);
        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        if let Some(sent_queues) = self.sent_queues.take() {
            for queue_index in sent_queues.into_keys() {
                let _vring_base = self
                    .deactivate_vring(queue_index)
                    .context("deactivate_vring failed during reset")?;
            }
        }

        if let Some(w) = self.worker_thread.take() {
            self.backend_req_handler = w.stop();
        }

        self.sent_set_features = false;

        Ok(())
    }

    fn pci_address(&self) -> Option<PciAddress> {
        self.pci_address
    }

    fn get_shared_memory_region(&self) -> Option<SharedMemoryRegion> {
        if !self
            .protocol_features
            .contains(VhostUserProtocolFeatures::SHARED_MEMORY_REGIONS)
        {
            return None;
        }
        if let Some(r) = self.shmem_region.borrow().as_ref() {
            return r.clone();
        }
        let regions = match self
            .backend_client
            .get_shared_memory_regions()
            .map_err(Error::ShmemRegions)
        {
            Ok(x) => x,
            Err(e) => {
                error!("Failed to get shared memory regions {}", e);
                return None;
            }
        };
        let region = match regions.len() {
            0 => None,
            1 => Some(SharedMemoryRegion {
                id: regions[0].id,
                length: regions[0].length,
            }),
            n => {
                error!(
                    "Failed to get shared memory regions {}",
                    Error::TooManyShmemRegions(n)
                );
                return None;
            }
        };

        *self.shmem_region.borrow_mut() = Some(region.clone());
        region
    }

    fn set_shared_memory_mapper(&mut self, mapper: Box<dyn SharedMemoryMapper>) {
        // Return error if backend request handler is not available. This indicates
        // that `VhostUserProtocolFeatures::BACKEND_REQ` is not negotiated.
        let Some(backend_req_handler) = self.backend_req_handler.as_mut() else {
            error!(
                "Error setting shared memory mapper {}",
                Error::ProtocolFeatureNotNegoiated(VhostUserProtocolFeatures::BACKEND_REQ)
            );
            return;
        };

        // The virtio framework will only call this if get_shared_memory_region returned a region
        let shmid = self
            .shmem_region
            .borrow()
            .clone()
            .flatten()
            .expect("missing shmid")
            .id;

        backend_req_handler
            .frontend_mut()
            .set_shared_mapper_state(mapper, shmid);
    }

    fn expose_shmem_descriptors_with_viommu(&self) -> bool {
        self.expose_shmem_descriptors_with_viommu
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        let Some(mut queues) = self.sent_queues.take() else {
            return Ok(None);
        };

        for (&queue_index, queue) in queues.iter_mut() {
            let vring_base = self
                .deactivate_vring(queue_index)
                .context("deactivate_vring failed during sleep")?;
            queue.vhost_user_reclaim(vring_base);
        }

        if let Some(w) = self.worker_thread.take() {
            self.backend_req_handler = w.stop();
        }

        Ok(Some(queues))
    }

    fn virtio_wake(
        &mut self,
        // Vhost user doesn't need to pass queue_states back to the device process, since it will
        // already have it.
        queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        if let Some((mem, interrupt, queues)) = queues_state {
            self.activate(mem, interrupt, queues)?;
        }
        Ok(())
    }

    fn virtio_snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        if !self
            .protocol_features
            .contains(VhostUserProtocolFeatures::DEVICE_STATE)
        {
            bail!("snapshot requires VHOST_USER_PROTOCOL_F_DEVICE_STATE");
        }
        // Send the backend an FD to write the device state to. If it gives us an FD back, then
        // we need to read from that instead.
        let (mut r, w) = new_pipe_pair()?;
        let backend_r = self
            .backend_client
            .set_device_state_fd(
                VhostUserTransferDirection::Save,
                VhostUserMigrationPhase::Stopped,
                &w,
            )
            .context("failed to negotiate device state fd")?;
        // EOF signals end of the device state bytes, so it is important to close our copy of
        // the write FD before we start reading.
        std::mem::drop(w);
        // Read the device state.
        let mut snapshot_bytes = Vec::new();
        if let Some(mut backend_r) = backend_r {
            backend_r.read_to_end(&mut snapshot_bytes)
        } else {
            r.read_to_end(&mut snapshot_bytes)
        }
        .context("failed to read device state")?;
        // Call `check_device_state` to ensure the data transfer was successful.
        self.backend_client
            .check_device_state()
            .context("failed to transfer device state")?;
        Ok(AnySnapshot::to_any(snapshot_bytes).map_err(Error::SliceToSerdeValue)?)
    }

    fn virtio_restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        // Ensure features are negotiated before restoring.
        if !self.sent_set_features {
            self.ack_features(self.acked_features);
        }

        if !self
            .protocol_features
            .contains(VhostUserProtocolFeatures::DEVICE_STATE)
        {
            bail!("restore requires VHOST_USER_PROTOCOL_F_DEVICE_STATE");
        }

        let data_bytes: Vec<u8> = AnySnapshot::from_any(data).map_err(Error::SerdeValueToSlice)?;
        // Send the backend an FD to read the device state from. If it gives us an FD back,
        // then we need to write to that instead.
        let (r, w) = new_pipe_pair()?;
        let backend_w = self
            .backend_client
            .set_device_state_fd(
                VhostUserTransferDirection::Load,
                VhostUserMigrationPhase::Stopped,
                &r,
            )
            .context("failed to negotiate device state fd")?;
        // Write the device state.
        {
            // EOF signals the end of the device state bytes, so we need to ensure the write
            // objects are dropped before the `check_device_state` call. Done here by moving
            // them into this scope.
            let backend_w = backend_w;
            let mut w = w;
            if let Some(mut backend_w) = backend_w {
                backend_w.write_all(data_bytes.as_slice())
            } else {
                w.write_all(data_bytes.as_slice())
            }
            .context("failed to write device state")?;
        }
        // Call `check_device_state` to ensure the data transfer was successful.
        self.backend_client
            .check_device_state()
            .context("failed to transfer device state")?;
        Ok(())
    }
}

#[cfg(unix)]
fn new_pipe_pair() -> anyhow::Result<(impl AsRawDescriptor + Read, impl AsRawDescriptor + Write)> {
    base::pipe().context("failed to create pipe")
}

#[cfg(windows)]
fn new_pipe_pair() -> anyhow::Result<(impl AsRawDescriptor + Read, impl AsRawDescriptor + Write)> {
    base::named_pipes::pair(
        &base::named_pipes::FramingMode::Byte,
        &base::named_pipes::BlockingMode::Wait,
        /* timeout= */ 0,
    )
    .context("failed to create named pipes")
}
