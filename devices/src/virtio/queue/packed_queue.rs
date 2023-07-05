// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use std::num::Wrapping;
use std::sync::atomic::fence;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::warn;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use virtio_sys::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::virtio::descriptor_chain::DescriptorChain;
use crate::virtio::descriptor_chain::PackedDesc;
use crate::virtio::descriptor_chain::PackedDescEvent;
use crate::virtio::descriptor_chain::PackedDescriptorChain;
use crate::virtio::descriptor_chain::PackedNotificationType;
use crate::virtio::descriptor_chain::RING_EVENT_FLAGS_DESC;
use crate::virtio::descriptor_chain::VIRTQ_DESC_F_AVAIL;
use crate::virtio::descriptor_chain::VIRTQ_DESC_F_USED;
use crate::virtio::descriptor_chain::VIRTQ_DESC_F_WRITE;
use crate::virtio::ipc_memory_mapper::ExportedRegion;
use crate::virtio::ipc_memory_mapper::IpcMemoryMapper;
use crate::virtio::memory_util::read_obj_from_addr_wrapper;
use crate::virtio::memory_util::write_obj_at_addr_wrapper;
use crate::virtio::Interrupt;
use crate::virtio::QueueConfig;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
struct PackedQueueIndex {
    wrap_counter: bool,
    index: Wrapping<u16>,
}
impl PackedQueueIndex {
    pub fn new(wrap_counter: bool, index: u16) -> Self {
        Self {
            wrap_counter,
            index: Wrapping(index),
        }
    }

    pub fn new_from_desc(desc: u16) -> Self {
        let wrap_counter: bool = (desc >> 15) == 1;
        let mask: u16 = 0x7fff;
        let index = desc & mask;
        Self::new(wrap_counter, index)
    }

    pub fn to_desc(self) -> PackedDescEvent {
        let flag = RING_EVENT_FLAGS_DESC;
        let mut desc = self.index.0;
        if self.wrap_counter {
            desc |= 1 << 15;
        }
        PackedDescEvent {
            desc: desc.into(),
            flag: flag.into(),
        }
    }

    fn add_index(&mut self, index_value: u16, size: u16) {
        let new_index = self.index.0 + index_value;
        if new_index < size {
            self.index = Wrapping(new_index);
        } else {
            self.index = Wrapping(new_index - size);
            self.wrap_counter = !self.wrap_counter;
        }
    }
}

impl Default for PackedQueueIndex {
    fn default() -> Self {
        Self::new(true, 0)
    }
}

#[derive(Clone)]
pub struct PackedQueue {
    // The queue size in elements the driver selected
    size: u16,

    // MSI-X vector for the queue. Don't care for INTx
    vector: u16,

    // Internal index counter to keep track of where to poll
    avail_index: PackedQueueIndex,
    use_index: PackedQueueIndex,
    peeked_index: PackedQueueIndex,
    signalled_used_index: PackedQueueIndex,

    // Device feature bits accepted by the driver
    features: u64,

    // Guest physical address of the descriptor table
    desc_table: GuestAddress,

    // Write-only by the device, Including information for reducing the number of device events
    device_event_suppression: GuestAddress,

    // Read-only by the device, Includes information for reducing the number of driver events
    driver_event_suppression: GuestAddress,

    // exported regions used to access the underlying GPAs.
    iommu: Option<Arc<Mutex<IpcMemoryMapper>>>,
    exported_desc_table: Option<ExportedRegion>,
    exported_device_area: Option<ExportedRegion>,
    exported_driver_area: Option<ExportedRegion>,
}

#[derive(Serialize, Deserialize)]
pub struct PackedQueueSnapshot {
    size: u16,
    vector: u16,
    avail_index: PackedQueueIndex,
    use_index: PackedQueueIndex,
    peeked_index: PackedQueueIndex,
    signalled_used_index: PackedQueueIndex,
    features: u64,
    desc_table: GuestAddress,
    device_event_suppression: GuestAddress,
    driver_event_suppression: GuestAddress,
}

impl PackedQueue {
    /// Constructs an empty virtio queue with the given `max_size`.
    pub fn new(config: &QueueConfig) -> Result<Self> {
        let size = config.size();

        let desc_table = config.desc_table();
        let driver_area = config.avail_ring();
        let device_area = config.used_ring();

        // Validate addresses and queue size to ensure that address calculation won't overflow.
        let ring_sizes = Self::area_sizes(size, desc_table, driver_area, device_area);
        let rings = ring_sizes.iter().zip(vec![
            "descriptor table",
            "driver_event_suppression",
            "device_event_suppression",
        ]);

        for ((addr, size), name) in rings {
            if addr.checked_add(*size as u64).is_none() {
                bail!(
                    "virtio queue {} goes out of bounds: start:0x{:08x} size:0x{:08x}",
                    name,
                    addr.offset(),
                    size,
                );
            }
        }

        Ok(PackedQueue {
            size,
            vector: config.vector(),
            desc_table: config.desc_table(),
            driver_event_suppression: config.avail_ring(),
            device_event_suppression: config.used_ring(),
            features: config.acked_features(),
            iommu: config.iommu(),
            exported_desc_table: None,
            exported_driver_area: None,
            exported_device_area: None,
            avail_index: PackedQueueIndex::default(),
            use_index: PackedQueueIndex::default(),
            peeked_index: PackedQueueIndex::default(),
            signalled_used_index: PackedQueueIndex::default(),
        })
    }

    /// Return the actual size of the queue, as the driver may not set up a
    /// queue as big as the device allows.
    pub fn size(&self) -> u16 {
        self.size
    }

    /// Getter for vector field
    pub fn vector(&self) -> u16 {
        self.vector
    }

    /// Getter for descriptor area
    pub fn desc_table(&self) -> GuestAddress {
        self.desc_table
    }

    /// Getter for driver area
    pub fn avail_ring(&self) -> GuestAddress {
        self.driver_event_suppression
    }

    /// Getter for device area
    pub fn used_ring(&self) -> GuestAddress {
        self.device_event_suppression
    }

    fn area_sizes(
        queue_size: u16,
        desc_table: GuestAddress,
        driver_area: GuestAddress,
        device_area: GuestAddress,
    ) -> Vec<(GuestAddress, usize)> {
        vec![
            (desc_table, 16 * queue_size as usize),
            (driver_area, 4),
            (device_area, 4),
        ]
    }

    /// Reset queue's counters.
    /// This method doesn't change the queue's metadata so it's reusable without initializing it
    /// again.
    pub fn reset_counters(&mut self) {
        self.avail_index = PackedQueueIndex::default();
        self.use_index = PackedQueueIndex::default();
        self.peeked_index = PackedQueueIndex::default();
        self.signalled_used_index = PackedQueueIndex::default();
    }

    /// If this queue is for a device that sits behind a virtio-iommu device, exports
    /// this queue's memory. After the queue becomes ready, this must be called before
    /// using the queue, to convert the IOVA-based configuration to GuestAddresses.
    pub fn export_memory(&mut self, mem: &GuestMemory) -> Result<()> {
        if self.exported_desc_table.is_some()
            || self.exported_device_area.is_some()
            || self.exported_driver_area.is_some()
        {
            bail!("memory already exported");
        }

        let iommu = self.iommu.as_ref().context("no iommu to export with")?;

        let area_sizes = Self::area_sizes(
            self.size,
            self.desc_table,
            self.driver_event_suppression,
            self.device_event_suppression,
        );
        let areas = area_sizes.iter().zip(vec![
            &mut self.exported_desc_table,
            &mut self.exported_device_area,
            &mut self.exported_driver_area,
        ]);

        for ((addr, size), region) in areas {
            *region = Some(
                ExportedRegion::new(mem, iommu.clone(), addr.offset(), *size as u64)
                    .context("failed to export region")?,
            );
        }
        Ok(())
    }

    /// Releases memory exported by a previous call to [`PackedQueue::export_memory()`].
    pub fn release_exported_memory(&mut self) {
        self.exported_desc_table = None;
        self.exported_device_area = None;
        self.exported_driver_area = None;
    }

    /// Set the device event suppression
    ///
    // This field is used to specify the timing of when the driver notifies the
    // device that the descriptor table is ready to be processed.
    fn set_avail_event(&mut self, mem: &GuestMemory, event: PackedDescEvent) {
        fence(Ordering::SeqCst);
        write_obj_at_addr_wrapper(
            mem,
            self.exported_device_area.as_ref(),
            event,
            self.device_event_suppression,
        )
        .unwrap();
    }

    // Get the driver event suppression.
    // This field is used to specify the timing of when the device notifies the
    // driver that the descriptor table is ready to be processed.
    fn get_driver_event(&self, mem: &GuestMemory) -> PackedDescEvent {
        fence(Ordering::SeqCst);

        let desc: PackedDescEvent = read_obj_from_addr_wrapper(
            mem,
            self.exported_driver_area.as_ref(),
            self.driver_event_suppression,
        )
        .unwrap();
        desc
    }

    /// Get the first available descriptor chain without removing it from the queue.
    /// Call `pop_peeked` to remove the returned descriptor chain from the queue.
    pub fn peek(&mut self, mem: &GuestMemory) -> Option<DescriptorChain> {
        let desc_addr = self
            .desc_table
            .checked_add((self.avail_index.index.0 as u64) * 16)
            .expect("peeked address will not overflow");

        let desc = read_obj_from_addr_wrapper::<PackedDesc>(
            mem,
            self.exported_desc_table.as_ref(),
            desc_addr,
        )
        .map_err(|e| {
            error!("failed to read desc {:#x}", desc_addr.offset());
            e
        })
        .ok()?;

        if !desc.is_available(self.avail_index.wrap_counter as u16) {
            return None;
        }

        // This fence ensures that subsequent reads from the descriptor do not
        // get reordered and happen only after verifying the descriptor table is
        // available.
        fence(Ordering::SeqCst);

        let iommu = self.iommu.as_ref().map(Arc::clone);
        let chain = PackedDescriptorChain::new(
            mem,
            self.desc_table,
            self.size,
            self.avail_index.wrap_counter,
            self.avail_index.index.0,
            self.exported_desc_table.as_ref(),
        );

        match DescriptorChain::new(chain, mem, self.avail_index.index.0, iommu) {
            Ok(descriptor_chain) => {
                let chain_count = descriptor_chain.count;

                self.peeked_index = self.avail_index;
                self.peeked_index.add_index(chain_count, self.size());

                Some(descriptor_chain)
            }
            Err(e) => {
                error!("{:#}", e);
                None
            }
        }
    }

    /// If a new DescriptorHead is available, returns one and removes it from the queue.
    pub fn pop_peeked(&mut self, mem: &GuestMemory) {
        self.avail_index = self.peeked_index;
        if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) != 0 {
            self.set_avail_event(mem, self.avail_index.to_desc());
        }
    }

    /// Write to first descriptor in descriptor chain to mark descriptor chain as used
    pub fn add_used(&mut self, mem: &GuestMemory, desc_chain: DescriptorChain, len: u32) {
        let desc_index = desc_chain.index();
        if desc_index >= self.size {
            error!(
                "attempted to add out of bounds descriptor to used ring: {}",
                desc_index
            );
            return;
        }

        let chain_id = desc_chain
            .id
            .expect("Packed descriptor chain should have id");

        let desc_addr = self
            .desc_table
            .checked_add(self.use_index.index.0 as u64 * 16)
            .expect("Descriptor address should not overflow.");

        // Write to len field
        write_obj_at_addr_wrapper(
            mem,
            self.exported_desc_table.as_ref(),
            len,
            desc_addr
                .checked_add(8)
                .expect("Descriptor address should not overflow."),
        )
        .unwrap();

        // Write to id field
        write_obj_at_addr_wrapper(
            mem,
            self.exported_desc_table.as_ref(),
            chain_id,
            desc_addr
                .checked_add(12)
                .expect("Descriptor address should not overflow."),
        )
        .unwrap();

        let wrap_counter = self.use_index.wrap_counter;

        let mut flags: u16 = 0;
        if wrap_counter {
            flags = flags | VIRTQ_DESC_F_USED | VIRTQ_DESC_F_AVAIL;
        }
        if len > 0 {
            flags |= VIRTQ_DESC_F_WRITE;
        }

        // Writing to flags should come at the very end to avoid showing the
        // driver fragmented descriptor data
        fence(Ordering::SeqCst);

        write_obj_at_addr_wrapper(
            mem,
            self.exported_desc_table.as_ref(),
            flags,
            desc_addr.unchecked_add(14),
        )
        .unwrap();

        self.use_index.add_index(desc_chain.count, self.size());
    }

    /// Returns if the queue should have an interrupt sent based on its state.
    fn queue_wants_interrupt(&mut self, mem: &GuestMemory) -> bool {
        let driver_event = self.get_driver_event(mem);
        match driver_event.notification_type() {
            PackedNotificationType::Enable => true,
            PackedNotificationType::Disable => false,
            PackedNotificationType::Desc(desc) => {
                if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) == 0 {
                    warn!("This is undefined behavior. We should actually send error in this case");
                    return true;
                }

                // Reserved current use_index for next notify
                let old = self.signalled_used_index;
                self.signalled_used_index = self.use_index;

                // Get desc_event_off and desc_event_wrap from driver event suppress area
                let event_index: PackedQueueIndex = PackedQueueIndex::new_from_desc(desc);

                let event_idx = event_index.index;
                let old_idx = old.index;
                let new_idx = self.use_index.index;

                // In qemu's implementation, there's an additional calculation,
                // need to verify its correctness.
                // if event_index.wrap_counter != self.use_index.wrap_counter {
                //     event_idx -= self.size() as u16;
                // }

                (new_idx - event_idx - Wrapping(1)) < (new_idx - old_idx)
            }
        };
        true
    }

    /// inject interrupt into guest on this queue
    /// return true: interrupt is injected into guest for this queue
    ///        false: interrupt isn't injected
    pub fn trigger_interrupt(&mut self, mem: &GuestMemory, interrupt: &Interrupt) -> bool {
        if self.queue_wants_interrupt(mem) {
            interrupt.signal_used_queue(self.vector);
            true
        } else {
            false
        }
    }

    /// Acknowledges that this set of features should be enabled on this queue.
    pub fn ack_features(&mut self, features: u64) {
        self.features |= features;
    }

    /// TODO: b/290307056 - Implement snapshot for packed virtqueue,
    /// add tests to validate.
    pub fn snapshot(&self) -> Result<serde_json::Value> {
        bail!("Snapshot for packed virtqueue not implemented.");
    }

    /// TODO: b/290307056 - Implement restore for packed virtqueue,
    /// add tests to validate.
    pub fn restore(_queue_value: serde_json::Value) -> Result<PackedQueue> {
        bail!("Restore for packed virtqueue not implemented.");
    }
}
