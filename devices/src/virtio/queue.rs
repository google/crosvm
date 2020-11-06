// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::cmp::min;
use std::num::Wrapping;
use std::rc::Rc;
use std::sync::atomic::{fence, Ordering};

use base::error;
use cros_async::{AsyncError, EventAsync};
use virtio_sys::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{GuestAddress, GuestMemory};

use super::{Interrupt, VIRTIO_MSI_NO_VECTOR};

const VIRTQ_DESC_F_NEXT: u16 = 0x1;
const VIRTQ_DESC_F_WRITE: u16 = 0x2;
#[allow(dead_code)]
const VIRTQ_DESC_F_INDIRECT: u16 = 0x4;

const VIRTQ_USED_F_NO_NOTIFY: u16 = 0x1;
const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 0x1;

/// An iterator over a single descriptor chain.  Not to be confused with AvailIter,
/// which iterates over the descriptor chain heads in a queue.
pub struct DescIter {
    next: Option<DescriptorChain>,
}

impl DescIter {
    /// Returns an iterator that only yields the readable descriptors in the chain.
    pub fn readable(self) -> impl Iterator<Item = DescriptorChain> {
        self.take_while(DescriptorChain::is_read_only)
    }

    /// Returns an iterator that only yields the writable descriptors in the chain.
    pub fn writable(self) -> impl Iterator<Item = DescriptorChain> {
        self.skip_while(DescriptorChain::is_read_only)
    }
}

impl Iterator for DescIter {
    type Item = DescriptorChain;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current) = self.next.take() {
            self.next = current.next_descriptor();
            Some(current)
        } else {
            None
        }
    }
}

/// A virtio descriptor chain.
#[derive(Clone)]
pub struct DescriptorChain {
    mem: GuestMemory,
    desc_table: GuestAddress,
    queue_size: u16,
    ttl: u16, // used to prevent infinite chain cycles

    /// Index into the descriptor table
    pub index: u16,

    /// Guest physical address of device specific data
    pub addr: GuestAddress,

    /// Length of device specific data
    pub len: u32,

    /// Includes next, write, and indirect bits
    pub flags: u16,

    /// Index into the descriptor table of the next descriptor if flags has
    /// the next bit set
    pub next: u16,
}

impl DescriptorChain {
    pub(crate) fn checked_new(
        mem: &GuestMemory,
        desc_table: GuestAddress,
        queue_size: u16,
        index: u16,
        required_flags: u16,
    ) -> Option<DescriptorChain> {
        if index >= queue_size {
            return None;
        }

        let desc_head = match mem.checked_offset(desc_table, (index as u64) * 16) {
            Some(a) => a,
            None => return None,
        };
        // These reads can't fail unless Guest memory is hopelessly broken.
        let addr = GuestAddress(mem.read_obj_from_addr::<u64>(desc_head).unwrap() as u64);
        if mem.checked_offset(desc_head, 16).is_none() {
            return None;
        }
        let len: u32 = mem.read_obj_from_addr(desc_head.unchecked_add(8)).unwrap();
        let flags: u16 = mem.read_obj_from_addr(desc_head.unchecked_add(12)).unwrap();
        let next: u16 = mem.read_obj_from_addr(desc_head.unchecked_add(14)).unwrap();
        let chain = DescriptorChain {
            mem: mem.clone(),
            desc_table,
            queue_size,
            ttl: queue_size,
            index,
            addr,
            len,
            flags,
            next,
        };

        if chain.is_valid() && chain.flags & required_flags == required_flags {
            Some(chain)
        } else {
            None
        }
    }

    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        if self.len > 0
            && self
                .mem
                .checked_offset(self.addr, self.len as u64 - 1u64)
                .is_none()
        {
            false
        } else if self.has_next() && self.next >= self.queue_size {
            false
        } else {
            true
        }
    }

    /// Gets if this descriptor chain has another descriptor chain linked after it.
    pub fn has_next(&self) -> bool {
        self.flags & VIRTQ_DESC_F_NEXT != 0 && self.ttl > 1
    }

    /// If the driver designated this as a write only descriptor.
    ///
    /// If this is false, this descriptor is read only.
    /// Write only means the the emulated device can write and the driver can read.
    pub fn is_write_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }

    /// If the driver designated this as a read only descriptor.
    ///
    /// If this is false, this descriptor is write only.
    /// Read only means the emulated device can read and the driver can write.
    pub fn is_read_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE == 0
    }

    /// Gets the next descriptor in this descriptor chain, if there is one.
    ///
    /// Note that this is distinct from the next descriptor chain returned by `AvailIter`, which is
    /// the head of the next _available_ descriptor chain.
    pub fn next_descriptor(&self) -> Option<DescriptorChain> {
        if self.has_next() {
            // Once we see a write-only descriptor, all subsequent descriptors must be write-only.
            let required_flags = self.flags & VIRTQ_DESC_F_WRITE;
            DescriptorChain::checked_new(
                &self.mem,
                self.desc_table,
                self.queue_size,
                self.next,
                required_flags,
            )
            .map(|mut c| {
                c.ttl = self.ttl - 1;
                c
            })
        } else {
            None
        }
    }

    /// Produces an iterator over all the descriptors in this chain.
    pub fn into_iter(self) -> DescIter {
        DescIter { next: Some(self) }
    }
}

/// Consuming iterator over all available descriptor chain heads in the queue.
pub struct AvailIter<'a, 'b> {
    mem: &'a GuestMemory,
    queue: &'b mut Queue,
}

impl<'a, 'b> Iterator for AvailIter<'a, 'b> {
    type Item = DescriptorChain;

    fn next(&mut self) -> Option<Self::Item> {
        self.queue.pop(self.mem)
    }
}

#[derive(Clone)]
/// A virtio queue's parameters.
pub struct Queue {
    /// The maximal size in elements offered by the device
    pub max_size: u16,

    /// The queue size in elements the driver selected
    pub size: u16,

    /// Inidcates if the queue is finished with configuration
    pub ready: bool,

    /// MSI-X vector for the queue. Don't care for INTx
    pub vector: u16,

    /// Guest physical address of the descriptor table
    pub desc_table: GuestAddress,

    /// Guest physical address of the available ring
    pub avail_ring: GuestAddress,

    /// Guest physical address of the used ring
    pub used_ring: GuestAddress,

    next_avail: Wrapping<u16>,
    next_used: Wrapping<u16>,

    // Device feature bits accepted by the driver
    features: u64,
    last_used: Wrapping<u16>,

    // Count of notification disables. Users of the queue can disable guest notification while
    // processing requests. This is the count of how many are in flight(could be several contexts
    // handling requests in parallel). When this count is zero, notifications are re-enabled.
    notification_disable_count: usize,
}

impl Queue {
    /// Constructs an empty virtio queue with the given `max_size`.
    pub fn new(max_size: u16) -> Queue {
        Queue {
            max_size,
            size: max_size,
            ready: false,
            vector: VIRTIO_MSI_NO_VECTOR,
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
            features: 0,
            last_used: Wrapping(0),
            notification_disable_count: 0,
        }
    }

    /// Return the actual size of the queue, as the driver may not set up a
    /// queue as big as the device allows.
    pub fn actual_size(&self) -> u16 {
        min(self.size, self.max_size)
    }

    /// Reset queue to a clean state
    pub fn reset(&mut self) {
        self.ready = false;
        self.size = self.max_size;
        self.vector = VIRTIO_MSI_NO_VECTOR;
        self.desc_table = GuestAddress(0);
        self.avail_ring = GuestAddress(0);
        self.used_ring = GuestAddress(0);
        self.next_avail = Wrapping(0);
        self.next_used = Wrapping(0);
        self.features = 0;
        self.last_used = Wrapping(0);
    }

    pub fn is_valid(&self, mem: &GuestMemory) -> bool {
        let queue_size = self.actual_size() as usize;
        let desc_table = self.desc_table;
        let desc_table_size = 16 * queue_size;
        let avail_ring = self.avail_ring;
        let avail_ring_size = 6 + 2 * queue_size;
        let used_ring = self.used_ring;
        let used_ring_size = 6 + 8 * queue_size;
        if !self.ready {
            error!("attempt to use virtio queue that is not marked ready");
            false
        } else if self.size > self.max_size || self.size == 0 || (self.size & (self.size - 1)) != 0
        {
            error!("virtio queue with invalid size: {}", self.size);
            false
        } else if desc_table
            .checked_add(desc_table_size as u64)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue descriptor table goes out of bounds: start:0x{:08x} size:0x{:08x}",
                desc_table.offset(),
                desc_table_size
            );
            false
        } else if avail_ring
            .checked_add(avail_ring_size as u64)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue available ring goes out of bounds: start:0x{:08x} size:0x{:08x}",
                avail_ring.offset(),
                avail_ring_size
            );
            false
        } else if used_ring
            .checked_add(used_ring_size as u64)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            error!(
                "virtio queue used ring goes out of bounds: start:0x{:08x} size:0x{:08x}",
                used_ring.offset(),
                used_ring_size
            );
            false
        } else {
            true
        }
    }

    /// Get the first available descriptor chain without removing it from the queue.
    /// Call `pop_peeked` to remove the returned descriptor chain from the queue.
    pub fn peek(&mut self, mem: &GuestMemory) -> Option<DescriptorChain> {
        if !self.is_valid(mem) {
            return None;
        }

        let queue_size = self.actual_size();
        let avail_index_addr = mem.checked_offset(self.avail_ring, 2).unwrap();
        let avail_index: u16 = mem.read_obj_from_addr(avail_index_addr).unwrap();
        // make sure desc_index read doesn't bypass avail_index read
        fence(Ordering::Acquire);
        let avail_len = Wrapping(avail_index) - self.next_avail;

        if avail_len.0 > queue_size || self.next_avail == Wrapping(avail_index) {
            return None;
        }

        let desc_idx_addr_offset = 4 + (u64::from(self.next_avail.0 % queue_size) * 2);
        let desc_idx_addr = mem.checked_offset(self.avail_ring, desc_idx_addr_offset)?;

        // This index is checked below in checked_new.
        let descriptor_index: u16 = mem.read_obj_from_addr(desc_idx_addr).unwrap();

        DescriptorChain::checked_new(mem, self.desc_table, queue_size, descriptor_index, 0)
    }

    /// Remove the first available descriptor chain from the queue.
    /// This function should only be called immediately following `peek`.
    pub fn pop_peeked(&mut self, mem: &GuestMemory) {
        self.next_avail += Wrapping(1);
        if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) != 0 {
            let avail_event_off = self
                .used_ring
                .unchecked_add((4 + 8 * self.actual_size()).into());
            mem.write_obj_at_addr(self.next_avail.0 as u16, avail_event_off)
                .unwrap();
        }
    }

    /// If a new DescriptorHead is available, returns one and removes it from the queue.
    pub fn pop(&mut self, mem: &GuestMemory) -> Option<DescriptorChain> {
        let descriptor_chain = self.peek(mem);
        if descriptor_chain.is_some() {
            self.pop_peeked(mem);
        }
        descriptor_chain
    }

    /// A consuming iterator over all available descriptor chain heads offered by the driver.
    pub fn iter<'a, 'b>(&'b mut self, mem: &'a GuestMemory) -> AvailIter<'a, 'b> {
        AvailIter { mem, queue: self }
    }

    /// Asynchronously read the next descriptor chain from the queue.
    /// Returns a `DescriptorChain` when it is `await`ed.
    pub async fn next_async(
        &mut self,
        mem: &GuestMemory,
        eventfd: &mut EventAsync,
    ) -> std::result::Result<DescriptorChain, AsyncError> {
        loop {
            // Check if there are more descriptors available.
            if let Some(chain) = self.pop(mem) {
                return Ok(chain);
            }
            eventfd.next_val().await?;
        }
    }

    /// Puts an available descriptor head into the used ring for use by the guest.
    pub fn add_used(&mut self, mem: &GuestMemory, desc_index: u16, len: u32) {
        if desc_index >= self.actual_size() {
            error!(
                "attempted to add out of bounds descriptor to used ring: {}",
                desc_index
            );
            return;
        }

        let used_ring = self.used_ring;
        let next_used = (self.next_used.0 % self.actual_size()) as usize;
        let used_elem = used_ring.unchecked_add((4 + next_used * 8) as u64);

        // These writes can't fail as we are guaranteed to be within the descriptor ring.
        mem.write_obj_at_addr(desc_index as u32, used_elem).unwrap();
        mem.write_obj_at_addr(len as u32, used_elem.unchecked_add(4))
            .unwrap();

        self.next_used += Wrapping(1);

        // This fence ensures all descriptor writes are visible before the index update is.
        fence(Ordering::Release);

        mem.write_obj_at_addr(self.next_used.0 as u16, used_ring.unchecked_add(2))
            .unwrap();
    }

    /// Enable / Disable guest notify device that requests are available on
    /// the descriptor chain.
    pub fn set_notify(&mut self, mem: &GuestMemory, enable: bool) {
        if enable {
            self.notification_disable_count -= 1;
        } else {
            self.notification_disable_count += 1;
        }

        if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) != 0 {
            let avail_index_addr = mem.checked_offset(self.avail_ring, 2).unwrap();
            let avail_index: u16 = mem.read_obj_from_addr(avail_index_addr).unwrap();
            let avail_event_off = self
                .used_ring
                .unchecked_add((4 + 8 * self.actual_size()).into());
            mem.write_obj_at_addr(avail_index, avail_event_off).unwrap();
        } else {
            let mut used_flags: u16 = mem.read_obj_from_addr(self.used_ring).unwrap();
            if self.notification_disable_count == 0 {
                used_flags &= !VIRTQ_USED_F_NO_NOTIFY;
            } else {
                used_flags |= VIRTQ_USED_F_NO_NOTIFY;
            }
            mem.write_obj_at_addr(used_flags, self.used_ring).unwrap();
        }
    }

    // Check Whether guest enable interrupt injection or not.
    fn available_interrupt_enabled(&self, mem: &GuestMemory) -> bool {
        if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) != 0 {
            let used_event_off = self
                .avail_ring
                .unchecked_add((4 + 2 * self.actual_size()).into());
            let used_event: u16 = mem.read_obj_from_addr(used_event_off).unwrap();
            // if used_event >= self.last_used, driver handle interrupt quickly enough, new
            // interrupt could be injected.
            // if used_event < self.last_used, driver hasn't finished the last interrupt,
            // so no need to inject new interrupt.
            if self.next_used - Wrapping(used_event) - Wrapping(1) < self.next_used - self.last_used
            {
                true
            } else {
                false
            }
        } else {
            let avail_flags: u16 = mem.read_obj_from_addr(self.avail_ring).unwrap();
            if avail_flags & VIRTQ_AVAIL_F_NO_INTERRUPT == VIRTQ_AVAIL_F_NO_INTERRUPT {
                false
            } else {
                true
            }
        }
    }

    /// inject interrupt into guest on this queue
    /// return true: interrupt is injected into guest for this queue
    ///        false: interrupt isn't injected
    pub fn trigger_interrupt(&mut self, mem: &GuestMemory, interrupt: &Interrupt) -> bool {
        if self.available_interrupt_enabled(mem) {
            self.last_used = self.next_used;
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
}

/// Used to temporarily disable notifications while processing a request. Notification will be
/// re-enabled on drop.
pub struct NotifyGuard {
    queue: Rc<RefCell<Queue>>,
    mem: GuestMemory,
}

impl NotifyGuard {
    /// Disable notifications for the lifetime of the returned guard. Useful when the caller is
    /// processing a descriptor and doesn't need notifications of further messages from the guest.
    pub fn new(queue: Rc<RefCell<Queue>>, mem: GuestMemory) -> Self {
        // Disable notification until we're done processing the next request.
        queue.borrow_mut().set_notify(&mem, false);
        NotifyGuard { queue, mem }
    }
}

impl Drop for NotifyGuard {
    fn drop(&mut self) {
        self.queue.borrow_mut().set_notify(&self.mem, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::Event;
    use data_model::{DataInit, Le16, Le32, Le64};
    use std::convert::TryInto;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    const GUEST_MEMORY_SIZE: u64 = 0x10000;
    const DESC_OFFSET: u64 = 0;
    const AVAIL_OFFSET: u64 = 0x200;
    const USED_OFFSET: u64 = 0x400;
    const QUEUE_SIZE: usize = 0x10;
    const BUFFER_OFFSET: u64 = 0x8000;
    const BUFFER_LEN: u32 = 0x400;

    #[derive(Copy, Clone, Debug)]
    #[repr(C)]
    struct Desc {
        addr: Le64,
        len: Le32,
        flags: Le16,
        next: Le16,
    }
    // Safe as this only runs in test
    unsafe impl DataInit for Desc {}

    #[derive(Copy, Clone, Debug)]
    #[repr(C)]
    struct Avail {
        flags: Le16,
        idx: Le16,
        ring: [Le16; QUEUE_SIZE],
        used_event: Le16,
    }
    // Safe as this only runs in test
    unsafe impl DataInit for Avail {}
    impl Default for Avail {
        fn default() -> Self {
            Avail {
                flags: Le16::from(0u16),
                idx: Le16::from(0u16),
                ring: [Le16::from(0u16); QUEUE_SIZE],
                used_event: Le16::from(0u16),
            }
        }
    }

    #[derive(Copy, Clone, Debug)]
    #[repr(C)]
    struct UsedElem {
        id: Le32,
        len: Le32,
    }
    // Safe as this only runs in test
    unsafe impl DataInit for UsedElem {}
    impl Default for UsedElem {
        fn default() -> Self {
            UsedElem {
                id: Le32::from(0u32),
                len: Le32::from(0u32),
            }
        }
    }

    #[derive(Copy, Clone, Debug)]
    #[repr(C)]
    struct Used {
        flags: Le16,
        idx: Le16,
        used_elem_ring: [UsedElem; QUEUE_SIZE],
        avail_event: Le16,
    }
    // Safe as this only runs in test
    unsafe impl DataInit for Used {}
    impl Default for Used {
        fn default() -> Self {
            Used {
                flags: Le16::from(0u16),
                idx: Le16::from(0u16),
                used_elem_ring: [UsedElem::default(); QUEUE_SIZE],
                avail_event: Le16::from(0u16),
            }
        }
    }

    fn setup_vq(queue: &mut Queue, mem: &GuestMemory) {
        let desc = Desc {
            addr: Le64::from(BUFFER_OFFSET),
            len: Le32::from(BUFFER_LEN),
            flags: Le16::from(0u16),
            next: Le16::from(1u16),
        };
        let _ = mem.write_obj_at_addr(desc, GuestAddress(DESC_OFFSET));

        let avail = Avail::default();
        let _ = mem.write_obj_at_addr(avail, GuestAddress(AVAIL_OFFSET));

        let used = Used::default();
        let _ = mem.write_obj_at_addr(used, GuestAddress(USED_OFFSET));

        queue.desc_table = GuestAddress(DESC_OFFSET);
        queue.avail_ring = GuestAddress(AVAIL_OFFSET);
        queue.used_ring = GuestAddress(USED_OFFSET);
        queue.ack_features((1u64) << VIRTIO_RING_F_EVENT_IDX);
    }

    #[test]
    fn queue_event_id_guest_fast() {
        let mut queue = Queue::new(QUEUE_SIZE.try_into().unwrap());
        let memory_start_addr = GuestAddress(0x0);
        let mem = GuestMemory::new(&vec![(memory_start_addr, GUEST_MEMORY_SIZE)]).unwrap();
        setup_vq(&mut queue, &mem);

        let interrupt = Interrupt::new(
            Arc::new(AtomicUsize::new(0)),
            Event::new().unwrap(),
            Event::new().unwrap(),
            None,
            10,
        );

        // Calculating the offset of used_event within Avail structure
        let used_event_offset: u64 =
            unsafe { &(*(::std::ptr::null::<Avail>())).used_event as *const _ as u64 };
        let used_event_address = GuestAddress(AVAIL_OFFSET + used_event_offset);

        // Assume driver submit 0x100 req to device,
        // device has handled them, so increase self.next_used to 0x100
        let mut device_generate: Wrapping<u16> = Wrapping(0x100);
        for _ in 0..device_generate.0 {
            queue.add_used(&mem, 0x0, BUFFER_LEN);
        }

        // At this moment driver hasn't handled any interrupts yet, so it
        // should inject interrupt.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), true);

        // Driver handle all the interrupts and update avail.used_event to 0x100
        let mut driver_handled = device_generate;
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver have handled all the interrupts, and
        // device doesn't generate more data, so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // Assume driver submit another u16::MAX - 0x100 req to device,
        // Device has handled all of them, so increase self.next_used to u16::MAX
        for _ in device_generate.0..u16::max_value() {
            queue.add_used(&mem, 0x0, BUFFER_LEN);
        }
        device_generate = Wrapping(u16::max_value());

        // At this moment driver just handled 0x100 interrupts, so it
        // should inject interrupt.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), true);

        // driver handle all the interrupts and update avail.used_event to u16::MAX
        driver_handled = device_generate;
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver have handled all the interrupts, and
        // device doesn't generate more data, so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // Assume driver submit another 1 request,
        // device has handled it, so wrap self.next_used to 0
        queue.add_used(&mem, 0x0, BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver has handled all the previous interrupts, so it
        // should inject interrupt again.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), true);

        // driver handle that interrupts and update avail.used_event to 0
        driver_handled = device_generate;
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver have handled all the interrupts, and
        // device doesn't generate more data, so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);
    }

    #[test]
    fn queue_event_id_guest_slow() {
        let mut queue = Queue::new(QUEUE_SIZE.try_into().unwrap());
        let memory_start_addr = GuestAddress(0x0);
        let mem = GuestMemory::new(&vec![(memory_start_addr, GUEST_MEMORY_SIZE)]).unwrap();
        setup_vq(&mut queue, &mem);

        let interrupt = Interrupt::new(
            Arc::new(AtomicUsize::new(0)),
            Event::new().unwrap(),
            Event::new().unwrap(),
            None,
            10,
        );

        // Calculating the offset of used_event within Avail structure
        let used_event_offset: u64 =
            unsafe { &(*(::std::ptr::null::<Avail>())).used_event as *const _ as u64 };
        let used_event_address = GuestAddress(AVAIL_OFFSET + used_event_offset);

        // Assume driver submit 0x100 req to device,
        // device have handled 0x100 req, so increase self.next_used to 0x100
        let mut device_generate: Wrapping<u16> = Wrapping(0x100);
        for _ in 0..device_generate.0 {
            queue.add_used(&mem, 0x0, BUFFER_LEN);
        }

        // At this moment driver hasn't handled any interrupts yet, so it
        // should inject interrupt.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), true);

        // Driver handle part of the interrupts and update avail.used_event to 0x80
        let mut driver_handled = Wrapping(0x80);
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver hasn't finished last interrupt yet,
        // so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // Assume driver submit another 1 request,
        // device has handled it, so increment self.next_used.
        queue.add_used(&mem, 0x0, BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver hasn't finished last interrupt yet,
        // so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // Assume driver submit another u16::MAX - 0x101 req to device,
        // Device has handled all of them, so increase self.next_used to u16::MAX
        for _ in device_generate.0..u16::max_value() {
            queue.add_used(&mem, 0x0, BUFFER_LEN);
        }
        device_generate = Wrapping(u16::max_value());

        // At this moment driver hasn't finished last interrupt yet,
        // so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // driver handle most of the interrupts and update avail.used_event to u16::MAX - 1,
        driver_handled = device_generate - Wrapping(1);
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // Assume driver submit another 1 request,
        // device has handled it, so wrap self.next_used to 0
        queue.add_used(&mem, 0x0, BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver has already finished the last interrupt(0x100),
        // and device service other request, so new interrupt is needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), true);

        // Assume driver submit another 1 request,
        // device has handled it, so increment self.next_used to 1
        queue.add_used(&mem, 0x0, BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver hasn't finished last interrupt((Wrapping(0)) yet,
        // so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // driver handle all the remain interrupts and wrap avail.used_event to 0x1.
        driver_handled = device_generate;
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver has handled all the interrupts, and
        // device doesn't generate more data, so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), false);

        // Assume driver submit another 1 request,
        // device has handled it, so increase self.next_used.
        queue.add_used(&mem, 0x0, BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver has finished all the previous interrupts, so it
        // should inject interrupt again.
        assert_eq!(queue.trigger_interrupt(&mem, &interrupt), true);
    }
}
