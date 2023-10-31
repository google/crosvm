// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! VirtioDevice implementation for the VMM side of a vhost-user connection.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context;
use base::error;
use base::trace;
use base::Event;
use base::RawDescriptor;
use base::WorkerThread;
use serde_json::Value;
use sync::Mutex;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;

use crate::pci::MsixConfig;
use crate::virtio::copy_config;
use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserHandler;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::QueueConfig;
use crate::virtio::SharedMemoryMapper;
use crate::virtio::SharedMemoryRegion;
use crate::virtio::VirtioDevice;

pub struct VhostUserVirtioDevice {
    device_type: DeviceType,
    worker_thread: Option<WorkerThread<()>>,
    handler: RefCell<VhostUserHandler>,
    queue_sizes: Vec<u16>,
    cfg: Option<Vec<u8>>,
    expose_shmem_descriptors_with_viommu: bool,
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

impl VhostUserVirtioDevice {
    /// Create a new VirtioDevice for a vhost-user device frontend.
    ///
    /// # Arguments
    ///
    /// - `connection`: connection to the device backend
    /// - `device_type`: virtio device type
    /// - `default_queues`: number of queues if the backend does not support the MQ feature
    /// - `max_queue_size`: maximum number of entries in each queue (default: [`Queue::MAX_SIZE`])
    /// - `allow_features`: allowed virtio device features
    /// - `allow_protocol_features`: allowed vhost-user protocol features
    /// - `base_features`: base virtio device features (e.g. `VIRTIO_F_VERSION_1`)
    /// - `cfg`: bytes to return for the virtio configuration space (queried from device if not
    ///   specified)
    pub fn new(
        connection: Connection,
        device_type: DeviceType,
        default_queues: usize,
        max_queue_size: Option<u16>,
        allow_features: u64,
        allow_protocol_features: VhostUserProtocolFeatures,
        base_features: u64,
        cfg: Option<&[u8]>,
        expose_shmem_descriptors_with_viommu: bool,
    ) -> Result<VhostUserVirtioDevice> {
        let allow_features = allow_features | base_features | 1 << VHOST_USER_F_PROTOCOL_FEATURES;

        let handler = VhostUserHandler::new(connection, allow_features, allow_protocol_features)?;

        // If the device supports VHOST_USER_PROTOCOL_F_MQ, use VHOST_USER_GET_QUEUE_NUM to
        // determine the number of queues supported. Otherwise, use the `default_queues` value
        // provided by the frontend.
        let num_queues = handler.num_queues()?.unwrap_or(default_queues);

        // Clamp the maximum queue size to the largest power of 2 <= max_queue_size.
        let max_queue_size = max_queue_size
            .and_then(power_of_two_le)
            .unwrap_or(Queue::MAX_SIZE);

        trace!(
            "vhost-user {device_type} frontend with {num_queues} queues x {max_queue_size} entries"
        );

        let queue_sizes = vec![max_queue_size; num_queues];

        Ok(VhostUserVirtioDevice {
            device_type,
            worker_thread: None,
            handler: RefCell::new(handler),
            queue_sizes,
            cfg: cfg.map(|cfg| cfg.to_vec()),
            expose_shmem_descriptors_with_viommu,
        })
    }
}

impl VirtioDevice for VhostUserVirtioDevice {
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
        self.handler.borrow().avail_features
    }

    fn ack_features(&mut self, features: u64) {
        if let Err(e) = self.handler.borrow_mut().ack_features(features) {
            error!("failed to enable features 0x{:x}: {}", features, e);
        }
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if let Some(cfg) = &self.cfg {
            copy_config(data, 0, cfg, offset);
        } else if let Err(e) = self.handler.borrow_mut().read_config(offset, data) {
            error!("failed to read config: {}", e);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        if let Err(e) = self.handler.borrow_mut().write_config(offset, data) {
            error!("failed to write config: {}", e);
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        let worker_thread = self
            .handler
            .borrow_mut()
            .activate(mem, interrupt, queues, &format!("{}", self.device_type))
            .context("failed to activate queues")?;
        self.worker_thread = Some(worker_thread);
        Ok(())
    }

    fn reset(&mut self) -> bool {
        if let Err(e) = self.handler.borrow_mut().reset(self.queue_sizes.len()) {
            error!("Failed to reset device: {}", e);
            false
        } else {
            true
        }
    }

    fn get_shared_memory_region(&self) -> Option<SharedMemoryRegion> {
        match self.handler.borrow_mut().get_shared_memory_region() {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to get shared memory regions {}", e);
                None
            }
        }
    }

    fn set_shared_memory_mapper(&mut self, mapper: Box<dyn SharedMemoryMapper>) {
        if let Err(e) = self.handler.borrow_mut().set_shared_memory_mapper(mapper) {
            error!("Error setting shared memory mapper {}", e);
        }
    }

    fn expose_shmem_descriptors_with_viommu(&self) -> bool {
        self.expose_shmem_descriptors_with_viommu
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        self.handler
            .borrow_mut()
            .sleep()
            .context("Failed to sleep device.")?;

        // Vhost user devices won't return queues on sleep, so return an empty Vec so that
        // VirtioPciDevice can set the sleep state properly.
        Ok(Some(BTreeMap::new()))
    }

    fn virtio_wake(
        &mut self,
        // Vhost user doesn't need to pass queue_states back to the device process, since it will
        // already have it.
        _queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        self.handler
            .borrow_mut()
            .wake()
            .context("Failed to wake device.")
    }

    fn virtio_snapshot(&mut self) -> anyhow::Result<Value> {
        self.handler
            .borrow_mut()
            .snapshot()
            .context("failed to snapshot vu device")
    }

    fn virtio_restore(&mut self, _data: Value) -> anyhow::Result<()> {
        panic!("virtio_restore should not be called for vhost-user devices.")
    }

    fn is_vhost_user(&self) -> bool {
        true
    }

    fn vhost_user_restore(
        &mut self,
        data: Value,
        queue_configs: &[QueueConfig],
        queue_evts: Option<Vec<Event>>,
        interrupt: Option<Interrupt>,
        mem: GuestMemory,
        msix_config: &Arc<Mutex<MsixConfig>>,
        device_activated: bool,
    ) -> anyhow::Result<()> {
        // Other aspects of the restore operation will depend on the mem table
        // being set.
        self.handler.borrow_mut().set_mem_table(&mem)?;

        if device_activated {
            let non_msix_evt = Event::new().context("Failed to create event")?;
            queue_configs
                .iter()
                .enumerate()
                .filter(|(_, q)| q.ready())
                .try_for_each(|(queue_index, queue)| {
                    let msix_lock = msix_config.lock();
                    let irqfd = msix_lock
                        .get_irqfd(queue.vector() as usize)
                        .unwrap_or(&non_msix_evt);

                    self.handler
                        .borrow_mut()
                        .restore_irqfd(queue_index, irqfd)
                        .context("Failed to restore irqfd")?;

                    Ok::<(), anyhow::Error>(())
                })?;

            anyhow::ensure!(
                self.worker_thread.is_none(),
                "self.worker_thread is some, but that should not be possible since only cold restore \
                is supported."
            );
            self.worker_thread = Some(
                self.handler
                    .borrow_mut()
                    .start_worker(
                        interrupt.expect(
                            "Interrupt doesn't exist. This shouldn't \
                        happen since the device is activated.",
                        ),
                        &format!("{}", self.device_type),
                        mem,
                        non_msix_evt,
                    )
                    .context("Failed to start worker on restore.")?,
            );
        }

        Ok(self.handler.borrow_mut().restore(data, queue_evts)?)
    }
}
