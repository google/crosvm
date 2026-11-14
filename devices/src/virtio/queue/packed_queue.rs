// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use std::num::Wrapping;
use std::sync::atomic::fence;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;

use anyhow::bail;
use anyhow::Result;
use base::error;
use base::warn;
use base::Event;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
use virtio_sys::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::virtio::descriptor_chain::DescriptorChain;
use crate::virtio::descriptor_chain::VIRTQ_DESC_F_AVAIL;
use crate::virtio::descriptor_chain::VIRTQ_DESC_F_USED;
use crate::virtio::descriptor_chain::VIRTQ_DESC_F_WRITE;
use crate::virtio::queue::packed_descriptor_chain::PackedDesc;
use crate::virtio::queue::packed_descriptor_chain::PackedDescEvent;
use crate::virtio::queue::packed_descriptor_chain::PackedDescriptorChain;
use crate::virtio::queue::packed_descriptor_chain::PackedNotificationType;
use crate::virtio::queue::packed_descriptor_chain::RING_EVENT_FLAGS_DESC;
use crate::virtio::queue::validate_queue_area;
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

#[derive(Debug)]
pub struct PackedQueue {
    mem: GuestMemory,

    event: Event,
    interrupt: Interrupt,

    // The queue size in elements the driver selected
    size: u16,

    // MSI-X vector for the queue. Don't care for INTx
    vector: u16,

    // Internal index counter to keep track of where to poll
    avail_index: PackedQueueIndex,
    use_index: PackedQueueIndex,
    signalled_used_index: PackedQueueIndex,

    // Device feature bits accepted by the driver
    features: u64,

    // Guest physical address of the descriptor table
    desc_table: GuestAddress,

    // Write-only by the device, Including information for reducing the number of device events
    device_event_suppression: GuestAddress,

    // Read-only by the device, Includes information for reducing the number of driver events
    driver_event_suppression: GuestAddress,
}

#[derive(Serialize, Deserialize)]
pub struct PackedQueueSnapshot {
    size: u16,
    vector: u16,
    avail_index: PackedQueueIndex,
    use_index: PackedQueueIndex,
    signalled_used_index: PackedQueueIndex,
    features: u64,
    desc_table: GuestAddress,
    device_event_suppression: GuestAddress,
    driver_event_suppression: GuestAddress,
}

impl PackedQueue {
    /// Constructs an empty virtio queue with the given `max_size`.
    pub fn new(
        config: &QueueConfig,
        mem: &GuestMemory,
        event: Event,
        interrupt: Interrupt,
    ) -> Result<Self> {
        let size = config.size();
        if size == 0 {
            bail!("packed queue size {size} is zero");
        }

        let desc_table = config.desc_table();
        let driver_area = config.avail_ring();
        let device_area = config.used_ring();

        // Validate addresses and queue size don't overflow and are within guest memory.
        let ring_sizes = Self::area_sizes(size, desc_table, driver_area, device_area);
        let rings = ring_sizes.iter().zip(vec![
            "descriptor table",
            "driver_event_suppression",
            "device_event_suppression",
        ]);

        for ((addr, size), name) in rings {
            validate_queue_area(mem, *addr, *size, 1, name)?;
        }

        Ok(PackedQueue {
            mem: mem.clone(),
            event,
            interrupt,
            size,
            vector: config.vector(),
            desc_table: config.desc_table(),
            driver_event_suppression: config.avail_ring(),
            device_event_suppression: config.used_ring(),
            features: config.acked_features(),
            avail_index: PackedQueueIndex::default(),
            use_index: PackedQueueIndex::default(),
            signalled_used_index: PackedQueueIndex::default(),
        })
    }

    pub fn vhost_user_reclaim(&mut self, _vring_base: u16) {
        // TODO: b/331466964 - Need more than `vring_base` to reclaim a packed virtqueue.
        unimplemented!()
    }

    pub fn next_avail_to_process(&self) -> u16 {
        self.avail_index.index.0
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

    /// Get a reference to the queue's "kick event"
    pub fn event(&self) -> &Event {
        &self.event
    }

    /// Get a reference to the queue's interrupt
    pub fn interrupt(&self) -> &Interrupt {
        &self.interrupt
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

    /// Set the device event suppression
    ///
    /// This field is used to specify the timing of when the driver notifies the
    /// device that the descriptor table is ready to be processed.
    fn set_avail_event(&mut self, event: PackedDescEvent) {
        fence(Ordering::SeqCst);
        // This unwrap cannot fail since `new` checked this area is in `self.mem`.
        self.mem
            .write_obj_at_addr_volatile(event, self.device_event_suppression)
            .unwrap();
    }

    // Get the driver event suppression.
    // This field is used to specify the timing of when the device notifies the
    // driver that the descriptor table is ready to be processed.
    fn get_driver_event(&self) -> PackedDescEvent {
        fence(Ordering::SeqCst);

        // This unwrap cannot fail since `new` checked this area is in `self.mem`.
        let desc: PackedDescEvent = self
            .mem
            .read_obj_from_addr_volatile(self.driver_event_suppression)
            .unwrap();
        desc
    }

    /// Get the first available descriptor chain without removing it from the queue.
    /// Call `pop_peeked` to remove the returned descriptor chain from the queue.
    pub fn peek(&mut self) -> Option<DescriptorChain> {
        let desc_addr = self
            .desc_table
            .checked_add((self.avail_index.index.0 as u64) * 16)
            .expect("peeked address will not overflow");

        let desc = self
            .mem
            .read_obj_from_addr::<PackedDesc>(desc_addr)
            .inspect_err(|_e| {
                error!("failed to read desc {:#x}", desc_addr.offset());
            })
            .ok()?;

        if !desc.is_available(self.avail_index.wrap_counter as u16) {
            return None;
        }

        // This fence ensures that subsequent reads from the descriptor do not
        // get reordered and happen only after verifying the descriptor table is
        // available.
        fence(Ordering::SeqCst);

        let chain = PackedDescriptorChain::new(
            self.desc_table,
            self.size,
            self.avail_index.wrap_counter,
            self.avail_index.index.0,
        );

        match DescriptorChain::new(chain, &self.mem, self.avail_index.index.0) {
            Ok(descriptor_chain) => Some(descriptor_chain),
            Err(e) => {
                error!("{:#}", e);
                None
            }
        }
    }

    /// Remove the first available descriptor chain from the queue.
    /// This function should only be called immediately following `peek` and must be passed a
    /// reference to the same `DescriptorChain` returned by the most recent `peek`.
    pub(super) fn pop_peeked(&mut self, descriptor_chain: &DescriptorChain) {
        self.avail_index
            .add_index(descriptor_chain.count, self.size());
        if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) != 0 {
            self.set_avail_event(self.avail_index.to_desc());
        }
    }

    /// Puts multiple available descriptor heads into the used ring for use by the guest.
    pub fn add_used_with_bytes_written_batch(
        &mut self,
        desc_chains: impl IntoIterator<Item = (DescriptorChain, u32)>,
    ) {
        // Get a `VolatileSlice` covering the descriptor table. This ensures that the raw pointers
        // generated below point into valid `GuestMemory` regions.
        let desc_table_size = size_of::<PackedDesc>() * usize::from(self.size);
        // This unwrap cannot fail since `new` checked this table is in `self.mem`.
        let desc_table_vslice = self
            .mem
            .get_slice_at_addr(self.desc_table, desc_table_size)
            .unwrap();

        let desc_table_ptr = desc_table_vslice.as_mut_ptr() as *mut PackedDesc;

        for (desc_chain, len) in desc_chains {
            debug_assert!(desc_chain.index() < self.size);

            let chain_id = desc_chain
                .id
                .expect("Packed descriptor chain should have id");

            let wrap_counter = self.use_index.wrap_counter;

            let mut flags: u16 = 0;
            if wrap_counter {
                flags = flags | VIRTQ_DESC_F_USED | VIRTQ_DESC_F_AVAIL;
            }
            if len > 0 {
                flags |= VIRTQ_DESC_F_WRITE;
            }

            // SAFETY: `desc_ptr` is always a valid pointer
            let desc_ptr = unsafe { desc_table_ptr.add(usize::from(self.use_index.index.0)) };

            // SAFETY: `desc_ptr` is always a valid pointer
            unsafe {
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*desc_ptr).len), len.into());
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*desc_ptr).id), chain_id.into());
            }

            // Writing to flags should come at the very end to avoid showing the
            // driver fragmented descriptor data
            fence(Ordering::Release);

            // SAFETY: `desc_ptr` is always a valid pointer
            let desc_flags_atomic = unsafe {
                AtomicU16::from_ptr(std::ptr::addr_of_mut!((*desc_ptr).flags) as *mut u16)
            };
            desc_flags_atomic.store(u16::to_le(flags), Ordering::Relaxed);

            self.use_index.add_index(desc_chain.count, self.size());
        }
    }

    /// Returns if the queue should have an interrupt sent based on its state.
    fn queue_wants_interrupt(&mut self) -> bool {
        let driver_event = self.get_driver_event();
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
    pub fn trigger_interrupt(&mut self) -> bool {
        if self.queue_wants_interrupt() {
            self.interrupt.signal_used_queue(self.vector);
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
    pub fn snapshot(&self) -> Result<AnySnapshot> {
        bail!("Snapshot for packed virtqueue not implemented.");
    }

    /// TODO: b/290307056 - Implement restore for packed virtqueue,
    /// add tests to validate.
    pub fn restore(
        _queue_value: AnySnapshot,
        _mem: &GuestMemory,
        _event: Event,
        _interrupt: Interrupt,
    ) -> Result<PackedQueue> {
        bail!("Restore for packed virtqueue not implemented.");
    }
}

#[cfg(test)]
mod tests {
    use data_model::Le16;
    use data_model::Le32;
    use data_model::Le64;
    use virtio_sys::virtio_config::VIRTIO_F_RING_PACKED;

    use super::*;
    use crate::virtio::descriptor_chain::VIRTQ_DESC_F_NEXT;
    use crate::virtio::Queue;

    const GUEST_MEMORY_SIZE: u64 = 0x10000;
    const DESC_OFFSET: u64 = 0;
    const DRIVER_EVENT_OFFSET: u64 = 0x200;
    const DEVICE_EVENT_OFFSET: u64 = 0x400;
    const QUEUE_SIZE: u16 = 0x10;
    const BUFFER_OFFSET: u64 = 0x8000;
    const BUFFER_LEN: u32 = 0x400;

    fn setup_packed_queue(mem: &GuestMemory) -> PackedQueue {
        let features = (1u64 << VIRTIO_RING_F_EVENT_IDX) | (1u64 << VIRTIO_F_RING_PACKED);
        let mut config = QueueConfig::new(QUEUE_SIZE, features);
        config.set_desc_table(GuestAddress(DESC_OFFSET));
        config.set_avail_ring(GuestAddress(DRIVER_EVENT_OFFSET));
        config.set_used_ring(GuestAddress(DEVICE_EVENT_OFFSET));
        config.ack_features(features);
        config.set_ready(true);
        match config.activate(mem, Event::new().unwrap(), Interrupt::new_for_test()) {
            Ok(Queue::PackedVirtQueue(queue)) => queue,
            _ => panic!("expected a packed queue"),
        }
    }

    // Write descriptor `index` in the first lap of the ring, available or not.
    fn write_desc(mem: &GuestMemory, index: u16, flags: u16, available: bool) {
        let avail_used = if available {
            VIRTQ_DESC_F_AVAIL
        } else {
            VIRTQ_DESC_F_USED
        };
        let desc = PackedDesc {
            addr: Le64::from(BUFFER_OFFSET + u64::from(index) * u64::from(BUFFER_LEN)),
            len: Le32::from(BUFFER_LEN),
            id: Le16::from(index),
            flags: Le16::from(flags | avail_used),
        };
        let desc_addr =
            GuestAddress(DESC_OFFSET + u64::from(index) * size_of::<PackedDesc>() as u64);
        mem.write_obj_at_addr(desc, desc_addr).unwrap();
    }

    #[test]
    fn rejects_unavailable_desc_in_chain() {
        let mem = GuestMemory::new(&[(GuestAddress(0), GUEST_MEMORY_SIZE)]).unwrap();
        let mut queue = setup_packed_queue(&mem);

        // The head has NEXT but descriptor 1 isn't available.
        write_desc(&mem, 1, VIRTQ_DESC_F_WRITE, false);
        write_desc(&mem, 0, VIRTQ_DESC_F_NEXT, true);
        assert!(queue.peek().is_none());

        // Once it is, the whole chain is used.
        write_desc(&mem, 1, VIRTQ_DESC_F_WRITE, true);
        let chain = queue.peek().unwrap();
        assert_eq!(chain.count, 2);
        assert_eq!(chain.id, Some(1));
    }

    #[test]
    fn rejects_chain_ending_with_next() {
        let mem = GuestMemory::new(&[(GuestAddress(0), GUEST_MEMORY_SIZE)]).unwrap();
        let mut queue = setup_packed_queue(&mem);

        // The last descriptor has NEXT, so the chain runs into descriptor 2, which isn't
        // available.
        write_desc(&mem, 1, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT, true);
        write_desc(&mem, 0, VIRTQ_DESC_F_NEXT, true);
        assert!(queue.peek().is_none());

        write_desc(&mem, 1, VIRTQ_DESC_F_WRITE, true);
        let chain = queue.peek().unwrap();
        assert_eq!(chain.count, 2);
        assert_eq!(chain.id, Some(1));
    }

    fn activate_packed(
        mem: &GuestMemory,
        config: &mut QueueConfig,
        features: u64,
    ) -> anyhow::Result<Queue> {
        config.ack_features(features);
        config.set_ready(true);
        config.activate(mem, Event::new().unwrap(), Interrupt::new_for_test())
    }

    #[test]
    fn rejects_zero_queue_size() {
        let mem = GuestMemory::new(&[(GuestAddress(0), GUEST_MEMORY_SIZE)]).unwrap();
        let features = 1u64 << VIRTIO_F_RING_PACKED;
        let mut config = QueueConfig::new(QUEUE_SIZE, features);
        config.set_size(0);
        config.set_desc_table(GuestAddress(DESC_OFFSET));
        config.set_avail_ring(GuestAddress(DRIVER_EVENT_OFFSET));
        config.set_used_ring(GuestAddress(DEVICE_EVENT_OFFSET));

        let err = activate_packed(&mem, &mut config, features).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("packed queue size 0 is zero"), "{msg}");
    }

    #[test]
    fn rejects_ring_areas_outside_guest_memory() {
        let mem = GuestMemory::new(&[(GuestAddress(0), GUEST_MEMORY_SIZE)]).unwrap();
        let features = (1u64 << VIRTIO_RING_F_EVENT_IDX) | (1u64 << VIRTIO_F_RING_PACKED);
        // Move one area outside RAM at a time so that each area's check is exercised. The table
        // starts in RAM but does not fit.
        let areas = [
            (
                QueueConfig::set_desc_table as fn(&mut QueueConfig, GuestAddress),
                "descriptor table",
                GUEST_MEMORY_SIZE - size_of::<PackedDesc>() as u64,
            ),
            (
                QueueConfig::set_avail_ring,
                "driver_event_suppression",
                GUEST_MEMORY_SIZE,
            ),
            (
                QueueConfig::set_used_ring,
                "device_event_suppression",
                GUEST_MEMORY_SIZE,
            ),
        ];
        for (set_addr, name, addr) in areas {
            let mut config = QueueConfig::new(QUEUE_SIZE, features);
            config.set_desc_table(GuestAddress(DESC_OFFSET));
            config.set_avail_ring(GuestAddress(DRIVER_EVENT_OFFSET));
            config.set_used_ring(GuestAddress(DEVICE_EVENT_OFFSET));
            set_addr(&mut config, GuestAddress(addr));

            let err = activate_packed(&mem, &mut config, features).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains(&format!("{name} is not in guest memory")),
                "{msg}"
            );
        }
    }

    #[test]
    fn rejects_ring_area_overflow() {
        let mem = GuestMemory::new(&[(GuestAddress(0), GUEST_MEMORY_SIZE)]).unwrap();
        let features = 1u64 << VIRTIO_F_RING_PACKED;
        let mut config = QueueConfig::new(QUEUE_SIZE, features);
        config.set_desc_table(GuestAddress(u64::MAX - 8));
        config.set_avail_ring(GuestAddress(DRIVER_EVENT_OFFSET));
        config.set_used_ring(GuestAddress(DEVICE_EVENT_OFFSET));

        let err = activate_packed(&mem, &mut config, features).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("descriptor table is not in guest memory"),
            "{msg}"
        );
    }
}
