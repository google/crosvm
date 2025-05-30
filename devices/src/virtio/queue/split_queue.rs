// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::num::Wrapping;
use std::sync::atomic::fence;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::Event;
use data_model::Le32;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
use virtio_sys::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use crate::virtio::DescriptorChain;
use crate::virtio::Interrupt;
use crate::virtio::QueueConfig;
use crate::virtio::SplitDescriptorChain;

#[allow(dead_code)]
const VIRTQ_USED_F_NO_NOTIFY: u16 = 0x1;
#[allow(dead_code)]
const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 0x1;

/// An activated virtio queue with split queue layout.
#[derive(Debug)]
pub struct SplitQueue {
    mem: GuestMemory,

    event: Event,
    interrupt: Interrupt,

    /// The queue size in elements the driver selected. This is always guaranteed to be a power of
    /// two, as required for split virtqueues.
    size: u16,

    /// MSI-X vector for the queue. Don't care for INTx
    vector: u16,

    /// Guest physical address of the descriptor table
    desc_table: GuestAddress,

    /// Guest physical address of the available ring
    avail_ring: GuestAddress,

    /// Guest physical address of the used ring
    used_ring: GuestAddress,

    next_avail: Wrapping<u16>,
    next_used: Wrapping<u16>,

    // Device feature bits accepted by the driver
    features: u64,
    last_used: Wrapping<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct SplitQueueSnapshot {
    size: u16,
    vector: u16,
    desc_table: GuestAddress,
    avail_ring: GuestAddress,
    used_ring: GuestAddress,
    next_avail: Wrapping<u16>,
    next_used: Wrapping<u16>,
    features: u64,
    last_used: Wrapping<u16>,
}

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, KnownLayout)]
struct virtq_used_elem {
    id: Le32,
    len: Le32,
}

impl SplitQueue {
    /// Constructs an activated split virtio queue with the given configuration.
    pub fn new(
        config: &QueueConfig,
        mem: &GuestMemory,
        event: Event,
        interrupt: Interrupt,
    ) -> Result<SplitQueue> {
        let size = config.size();
        if !size.is_power_of_two() {
            bail!("split queue size {size} is not a power of 2");
        }

        let desc_table = config.desc_table();
        let avail_ring = config.avail_ring();
        let used_ring = config.used_ring();

        // Validate addresses and queue size to ensure that address calculation won't overflow.
        let ring_sizes = Self::ring_sizes(size, desc_table, avail_ring, used_ring);
        let rings = ring_sizes
            .iter()
            .zip(vec!["descriptor table", "available ring", "used ring"]);

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

        Ok(SplitQueue {
            mem: mem.clone(),
            event,
            interrupt,
            size,
            vector: config.vector(),
            desc_table: config.desc_table(),
            avail_ring: config.avail_ring(),
            used_ring: config.used_ring(),
            features: config.acked_features(),
            next_avail: config.next_avail(),
            next_used: config.next_used(),

            // WARNING: last_used controls interrupt suppression
            // (VIRTIO_RING_F_EVENT_IDX). The only safe value initial value is
            // zero (unless restoring a snapshot and the value that was stored
            // on the device is known; however we do not bother with that in our
            // snapshot system since it is much simpler to just use the zero
            // value and send a potentially spurious interrupt on restore).
            last_used: Wrapping(0),
        })
    }

    pub fn vhost_user_reclaim(&mut self, vring_base: u16) {
        self.next_avail = Wrapping(vring_base);
        // The vhost-user spec says:
        //
        //     For the Used Ring, the device only needs the next descriptor index at which to put
        //     new descriptors, which is the value in the vring structure in memory, so this value
        //     is not covered by this message.
        //
        // So, we read the value from guest memory.
        let used_index_addr = self.used_ring.unchecked_add(2);
        self.next_used = self
            .mem
            .read_obj_from_addr_volatile(used_index_addr)
            .unwrap();

        // Since the backend has not told us what its actual last_used value
        // was, we have to assume that an interrupt must be sent when next
        // available descriptor is used, so we set this to zero.
        //
        // But wait, one might ask, why can't we just assume the vhost-user
        // backend has already sent interrupts for any descriptors it marked
        // used before it stopped processing the queue? Then we could just
        // initialize last_used as `last_used == next_used`, which would skip
        // spurious interrupts and be more efficient. Right?
        //
        // If VIRTIO_RING_F_EVENT_IDX is enabled, then no. The reason is the
        // device could be in an interrupt suppressed state and so it may indeed
        // have marked some descriptors used, but not yet sent an interrupt for
        // them. Once we set last_used = next_used, no interrupts will be sent
        // to the driver until the driver updates next_used (see
        // queue_wants_interrupt for details), but the driver will
        // never wake up the device isn't sending any interrupts. Thus, the
        // device stalls.
        //
        // NOTE: this value is not used by the snapshot/restore process, but we
        // still want to pick a reasonable value here in case it is used in the
        // future.
        self.last_used = Wrapping(0);
    }

    pub fn next_avail_to_process(&self) -> u16 {
        self.next_avail.0
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
        self.avail_ring
    }

    /// Getter for device area
    pub fn used_ring(&self) -> GuestAddress {
        self.used_ring
    }

    /// Get a reference to the queue's "kick event"
    pub fn event(&self) -> &Event {
        &self.event
    }

    /// Get a reference to the queue's interrupt
    pub fn interrupt(&self) -> &Interrupt {
        &self.interrupt
    }

    // Return `index` modulo the currently configured queue size.
    fn wrap_queue_index(&self, index: Wrapping<u16>) -> u16 {
        // We know that `self.size` is a power of two (enforced by `new()`), so the modulus can
        // be calculated with a bitmask rather than actual division.
        debug_assert!(self.size.is_power_of_two());
        index.0 & self.size.wrapping_sub(1)
    }

    fn ring_sizes(
        queue_size: u16,
        desc_table: GuestAddress,
        avail_ring: GuestAddress,
        used_ring: GuestAddress,
    ) -> Vec<(GuestAddress, usize)> {
        let queue_size = queue_size as usize;
        vec![
            (desc_table, 16 * queue_size),
            (avail_ring, 6 + 2 * queue_size),
            (used_ring, 6 + 8 * queue_size),
        ]
    }

    // Set the `avail_event` field in the used ring.
    //
    // This allows the device to inform the driver that driver-to-device notification
    // (kicking the ring) is not necessary until the driver reaches the `avail_index` descriptor.
    //
    // This value is only used if the `VIRTIO_F_EVENT_IDX` feature has been negotiated.
    fn set_avail_event(&mut self, avail_index: Wrapping<u16>) {
        fence(Ordering::SeqCst);

        let avail_event_addr = self.used_ring.unchecked_add(4 + 8 * u64::from(self.size));
        self.mem
            .write_obj_at_addr_volatile(avail_index.0, avail_event_addr)
            .unwrap();
    }

    // Query the value of a single-bit flag in the available ring.
    //
    // Returns `true` if `flag` is currently set (by the driver) in the available ring flags.
    fn get_avail_flag(&self, flag: u16) -> bool {
        fence(Ordering::SeqCst);

        let avail_flags: u16 = self
            .mem
            .read_obj_from_addr_volatile(self.avail_ring)
            .unwrap();

        avail_flags & flag == flag
    }

    // Get the `used_event` field in the available ring.
    //
    // The returned value is the index of the next descriptor chain entry for which the driver
    // needs to be notified upon use.  Entries before this index may be used without notifying
    // the driver.
    //
    // This value is only valid if the `VIRTIO_F_EVENT_IDX` feature has been negotiated.
    fn get_used_event(&self) -> Wrapping<u16> {
        fence(Ordering::SeqCst);

        let used_event_addr = self.avail_ring.unchecked_add(4 + 2 * u64::from(self.size));
        let used_event: u16 = self
            .mem
            .read_obj_from_addr_volatile(used_event_addr)
            .unwrap();

        Wrapping(used_event)
    }

    /// Get the first available descriptor chain without removing it from the queue.
    /// Call `pop_peeked` to remove the returned descriptor chain from the queue.
    pub fn peek(&mut self) -> Option<DescriptorChain> {
        // Get a `VolatileSlice` covering the `struct virtq_avail` fixed header (`flags` and `idx`)
        // and variable-length `ring`. This ensures that the raw pointers generated below point into
        // valid `GuestMemory` regions.
        let avail_ring_size = 2 * size_of::<u16>() + (size_of::<u16>() * usize::from(self.size));
        let avail_ring_vslice = self
            .mem
            .get_slice_at_addr(self.avail_ring, avail_ring_size)
            .unwrap();

        // SAFETY: offset of `virtq_avail.idx` (2) is always within the `VolatileSlice` bounds.
        let avail_index_ptr = unsafe { avail_ring_vslice.as_mut_ptr().add(2) } as *mut u16;
        // SAFETY: `GuestMemory::get_slice_at_addr()` returns a valid `VolatileSlice`, and
        // `avail_index_ptr` is a valid `*mut u16` contained within that slice.
        let avail_index_atomic = unsafe { AtomicU16::from_ptr(avail_index_ptr) };

        // Check if the driver has published any new descriptors beyond `self.next_avail`. This uses
        // a `Relaxed` load because we do not need a memory barrier if there are no new descriptors.
        // If the ring is not empty, the `fence()` below will provide the necessary ordering,
        // pairing with the write memory barrier in the driver.
        let avail_index: u16 = avail_index_atomic.load(Ordering::Relaxed);
        let next_avail = self.next_avail;
        if next_avail.0 == avail_index {
            return None;
        }

        // This fence ensures that subsequent reads from the descriptor do not
        // get reordered and happen only after fetching the available_index and
        // checking that there is a slot available.
        fence(Ordering::Acquire);

        // Calculate the offset of `ring[next_avail % size]` within `struct virtq_avail`.
        let ring_offset = 4 + (usize::from(self.wrap_queue_index(next_avail)) * 2);
        debug_assert!(ring_offset + size_of::<u16>() <= avail_ring_size);
        // SAFETY: The available ring index was wrapped to fall within the queue size above, so
        // `ring_offset` is always in bounds.
        let ring_ptr = unsafe { avail_ring_vslice.as_ptr().add(ring_offset) } as *const u16;
        // SAFETY: `ring_ptr` is a valid `*const u16` within `avail_ring_vslice`.
        let descriptor_index: u16 = unsafe { std::ptr::read_volatile(ring_ptr) };

        let chain =
            SplitDescriptorChain::new(&self.mem, self.desc_table, self.size, descriptor_index);
        DescriptorChain::new(chain, &self.mem, descriptor_index)
            .map_err(|e| {
                error!("{:#}", e);
                e
            })
            .ok()
    }

    /// Remove the first available descriptor chain from the queue.
    /// This function should only be called immediately following `peek` and must be passed a
    /// reference to the same `DescriptorChain` returned by the most recent `peek`.
    pub(super) fn pop_peeked(&mut self, _descriptor_chain: &DescriptorChain) {
        self.next_avail += Wrapping(1);
        if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) != 0 {
            self.set_avail_event(self.next_avail);
        }
    }

    pub(super) fn try_pop_length(&mut self, length: usize) -> Option<Vec<DescriptorChain>> {
        let mut remain_len = length;
        let mut descriptors = vec![];
        while remain_len > 0 {
            match self.peek() {
                Some(desc) => {
                    let available_bytes = desc.writer.available_bytes();
                    descriptors.push(desc);
                    self.next_avail += Wrapping(1);
                    if available_bytes >= remain_len {
                        if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) != 0 {
                            self.set_avail_event(self.next_avail);
                        }
                        return Some(descriptors);
                    } else {
                        remain_len -= available_bytes;
                    }
                }
                None => {
                    if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) != 0 {
                        self.set_avail_event(self.next_avail);
                    }
                    // Reverse the effect of pop
                    self.next_avail -= Wrapping(descriptors.len() as u16);
                    return None;
                }
            }
        }
        None
    }

    /// Puts multiple available descriptor heads into the used ring for use by the guest.
    pub fn add_used_with_bytes_written_batch(
        &mut self,
        desc_chains: impl IntoIterator<Item = (DescriptorChain, u32)>,
    ) {
        // Get a `VolatileSlice` covering the `struct virtq_used` fixed header (`flags` and `idx`)
        // and variable-length `ring`. This ensures that the raw pointers generated below point into
        // valid `GuestMemory` regions.
        let used_ring_size =
            2 * size_of::<u16>() + (size_of::<virtq_used_elem>() * usize::from(self.size));
        let used_ring_vslice = self
            .mem
            .get_slice_at_addr(self.used_ring, used_ring_size)
            .unwrap();

        // SAFETY: `elems_ptr` is always a valid pointer due to `used_ring_vslice()`.
        let elems_ptr = unsafe { used_ring_vslice.as_mut_ptr().add(4) } as *mut virtq_used_elem;

        // SAFETY: `used_index_ptr` is always a valid pointer due to `used_ring_vslice()`.
        let used_index_ptr = unsafe { used_ring_vslice.as_mut_ptr().add(2) } as *mut u16;

        // SAFETY: `used_index_ptr` is always a valid pointer
        let used_index_atomic = unsafe { AtomicU16::from_ptr(used_index_ptr) };

        let mut next_used = self.next_used;
        for (desc_chain, len) in desc_chains {
            let desc_index = desc_chain.index();
            debug_assert!(desc_index < self.size);
            let id = Le32::from(u32::from(desc_index));
            let len = Le32::from(len);

            let wrapped_index = usize::from(self.wrap_queue_index(next_used));
            // SAFETY: `wrapped_index` is always in bounds due to `wrap_queue_index()`.
            let elem_ptr = unsafe { elems_ptr.add(wrapped_index) };

            // SAFETY: `elem_ptr` is always a valid pointer
            unsafe {
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*elem_ptr).id), id);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*elem_ptr).len), len);
            };

            next_used += Wrapping(1);
        }

        if next_used != self.next_used {
            fence(Ordering::Release);
            used_index_atomic.store(next_used.0, Ordering::Relaxed);
            self.next_used = next_used;
        }
    }

    /// Returns if the queue should have an interrupt sent based on its state.
    ///
    /// This function implements `VIRTIO_RING_F_EVENT_IDX`, otherwise known as
    /// interrupt suppression. The virtio spec provides the driver with a field,
    /// `used_event`, which says that once we write that descriptor (or several
    /// in the case of a flurry of `add_used` calls), we should send a
    /// notification. Because the values involved wrap around `u16::MAX`, and to
    /// avoid checking the condition on every `add_used` call, the math is a
    /// little complicated.
    ///
    /// The critical inequality is:
    /// ```text
    ///      (next_used - 1) - used_event < next_used - last_used
    /// ```
    ///
    /// For illustration purposes, we label it as `A < B`, where
    /// `A = (next_used -1) - used_event`, and `B = next_used - last_used`.
    ///
    /// `A` and `B` represent two distances, measured in a wrapping ring of size
    /// `u16::MAX`. In the "send intr" case, the inequality is true. In the
    /// "don't send intr" case, the inequality is false. We must be very careful
    /// in assigning a direction to the ring, so that when we
    /// graph the subtraction operations, we are measuring the right distance
    /// (similar to how DC circuits are analyzed).
    ///
    /// The two distances are as follows:
    ///  * `A` is the distance between the driver's requested notification point, and the current
    ///    position in the ring.
    ///
    ///  * `B` is the distance between the last time we notified the guest, and the current position
    ///    in the ring.
    ///
    /// If we graph these distances for the situation where we want to notify
    /// the guest, and when we don't want to notify the guest, we see that
    /// `A < B` becomes true the moment `next_used - 1` passes `used_event`. See
    /// the graphs at the bottom of this comment block for a more visual
    /// explanation.
    ///
    /// Once an interrupt is sent, we have a final useful property: last_used
    /// moves up next_used, which causes the inequality to be false. Thus, we
    /// won't send notifications again until `used_event` is moved forward by
    /// the driver.
    ///
    /// Finally, let's talk about a couple of ways to write this inequality
    /// that don't work, and critically, explain *why*.
    ///
    /// First, a naive reading of the virtio spec might lead us to ask: why not
    /// just use the following inequality:
    /// ```text
    ///      next_used - 1 >= used_event
    /// ```
    ///
    /// because that's much simpler, right? The trouble is that the ring wraps,
    /// so it could be that a smaller index is actually ahead of a larger one.
    /// That's why we have to use distances in the ring instead.
    ///
    /// Second, one might look at the correct inequality:
    /// ```text
    ///      (next_used - 1) - used_event < next_used - last_used
    /// ```
    ///
    /// And try to simplify it to:
    /// ```text
    ///      last_used - 1 < used_event
    /// ```
    ///
    /// Functionally, this won't work because next_used isn't present at all
    /// anymore. (Notifications will never be sent.) But why is that? The algebra
    /// here *appears* to work out, but all semantic meaning is lost. There are
    /// two explanations for why this happens:
    /// * The intuitive one: the terms in the inequality are not actually separable; in other words,
    ///   (next_used - last_used) is an inseparable term, so subtracting next_used from both sides
    ///   of the original inequality and zeroing them out is semantically invalid. But why aren't
    ///   they separable? See below.
    /// * The theoretical one: canceling like terms relies a vector space law: a + x = b + x => a =
    ///   b (cancellation law). For congruences / equality under modulo, this law is satisfied, but
    ///   for inequalities under mod, it is not; therefore, we cannot cancel like terms.
    ///
    /// ```text
    /// ┌──────────────────────────────────┐
    /// │                                  │
    /// │                                  │
    /// │                                  │
    /// │           ┌────────────  next_used - 1
    /// │           │A                   x
    /// │           │       ┌────────────x────────────┐
    /// │           │       │            x            │
    /// │           │       │                         │
    /// │           │       │               │         │
    /// │           │       │               │         │
    /// │     used_event  xxxx        + ◄───┘       xxxxx last_used
    /// │                   │                         │      │
    /// │                   │        Send intr        │      │
    /// │                   │                         │      │
    /// │                   └─────────────────────────┘      │
    /// │                                                    │
    /// │ B                                                  │
    /// └────────────────────────────────────────────────────┘
    ///
    ///             ┌───────────────────────────────────────────────────┐
    ///             │                                                 A │
    ///             │       ┌────────────────────────┐                  │
    ///             │       │                        │                  │
    ///             │       │                        │                  │
    ///             │       │              │         │                  │
    ///             │       │              │         │                  │
    ///       used_event  xxxx             │       xxxxx last_used      │
    ///                     │        + ◄───┘         │       │          │
    ///                     │                        │       │          │
    ///                     │     Don't send intr    │       │          │
    ///                     │                        │       │          │
    ///                     └───────────x────────────┘       │          │
    ///                                 x                    │          │
    ///                              next_used - 1           │          │
    ///                              │  │                  B │          │
    ///                              │  └────────────────────┘          │
    ///                              │                                  │
    ///                              └──────────────────────────────────┘
    /// ```
    fn queue_wants_interrupt(&self) -> bool {
        if self.features & ((1u64) << VIRTIO_RING_F_EVENT_IDX) != 0 {
            let used_event = self.get_used_event();
            self.next_used - used_event - Wrapping(1) < self.next_used - self.last_used
        } else {
            !self.get_avail_flag(VIRTQ_AVAIL_F_NO_INTERRUPT)
        }
    }

    /// inject interrupt into guest on this queue
    /// return true: interrupt is injected into guest for this queue
    ///        false: interrupt isn't injected
    pub fn trigger_interrupt(&mut self) -> bool {
        if self.queue_wants_interrupt() {
            self.last_used = self.next_used;
            self.interrupt.signal_used_queue(self.vector);
            true
        } else {
            false
        }
    }

    pub fn snapshot(&self) -> anyhow::Result<AnySnapshot> {
        AnySnapshot::to_any(SplitQueueSnapshot {
            size: self.size,
            vector: self.vector,
            desc_table: self.desc_table,
            avail_ring: self.avail_ring,
            used_ring: self.used_ring,
            next_avail: self.next_avail,
            next_used: self.next_used,
            features: self.features,
            last_used: self.last_used,
        })
        .context("failed to serialize MsixConfigSnapshot")
    }

    pub fn restore(
        queue_value: AnySnapshot,
        mem: &GuestMemory,
        event: Event,
        interrupt: Interrupt,
    ) -> anyhow::Result<SplitQueue> {
        let s: SplitQueueSnapshot = AnySnapshot::from_any(queue_value)?;
        let queue = SplitQueue {
            mem: mem.clone(),
            event,
            interrupt,
            size: s.size,
            vector: s.vector,
            desc_table: s.desc_table,
            avail_ring: s.avail_ring,
            used_ring: s.used_ring,
            next_avail: s.next_avail,
            next_used: s.next_used,
            features: s.features,
            last_used: s.last_used,
        };
        Ok(queue)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::mem::offset_of;

    use data_model::Le16;
    use data_model::Le32;
    use data_model::Le64;
    use zerocopy::FromBytes;
    use zerocopy::Immutable;
    use zerocopy::IntoBytes;
    use zerocopy::KnownLayout;

    use super::*;
    use crate::virtio::create_descriptor_chain;
    use crate::virtio::Desc;
    use crate::virtio::Interrupt;
    use crate::virtio::Queue;

    const GUEST_MEMORY_SIZE: u64 = 0x10000;
    const DESC_OFFSET: u64 = 0;
    const AVAIL_OFFSET: u64 = 0x200;
    const USED_OFFSET: u64 = 0x400;
    const QUEUE_SIZE: usize = 0x10;
    const BUFFER_OFFSET: u64 = 0x8000;
    const BUFFER_LEN: u32 = 0x400;

    #[derive(Copy, Clone, Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
    #[repr(C)]
    struct Avail {
        flags: Le16,
        idx: Le16,
        ring: [Le16; QUEUE_SIZE],
        used_event: Le16,
    }

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

    #[derive(Copy, Clone, Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
    #[repr(C)]
    struct UsedElem {
        id: Le32,
        len: Le32,
    }

    impl Default for UsedElem {
        fn default() -> Self {
            UsedElem {
                id: Le32::from(0u32),
                len: Le32::from(0u32),
            }
        }
    }

    #[derive(Copy, Clone, Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
    #[repr(C, packed)]
    struct Used {
        flags: Le16,
        idx: Le16,
        used_elem_ring: [UsedElem; QUEUE_SIZE],
        avail_event: Le16,
    }

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

    fn setup_vq(queue: &mut QueueConfig, mem: &GuestMemory) -> Queue {
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

        queue.set_desc_table(GuestAddress(DESC_OFFSET));
        queue.set_avail_ring(GuestAddress(AVAIL_OFFSET));
        queue.set_used_ring(GuestAddress(USED_OFFSET));
        queue.ack_features((1u64) << VIRTIO_RING_F_EVENT_IDX);
        queue.set_ready(true);

        queue
            .activate(mem, Event::new().unwrap(), Interrupt::new_for_test())
            .expect("QueueConfig::activate failed")
    }

    fn fake_desc_chain(mem: &GuestMemory) -> DescriptorChain {
        create_descriptor_chain(mem, GuestAddress(0), GuestAddress(0), Vec::new(), 0)
            .expect("failed to create descriptor chain")
    }

    #[test]
    fn queue_event_id_guest_fast() {
        let mut queue =
            QueueConfig::new(QUEUE_SIZE.try_into().unwrap(), 1 << VIRTIO_RING_F_EVENT_IDX);
        let memory_start_addr = GuestAddress(0x0);
        let mem = GuestMemory::new(&[(memory_start_addr, GUEST_MEMORY_SIZE)]).unwrap();
        let mut queue = setup_vq(&mut queue, &mem);

        // Offset of used_event within Avail structure
        let used_event_offset = offset_of!(Avail, used_event) as u64;
        let used_event_address = GuestAddress(AVAIL_OFFSET + used_event_offset);

        // Assume driver submit 0x100 req to device,
        // device has handled them, so increase self.next_used to 0x100
        let mut device_generate: Wrapping<u16> = Wrapping(0x100);
        for _ in 0..device_generate.0 {
            queue.add_used_with_bytes_written(fake_desc_chain(&mem), BUFFER_LEN);
        }

        // At this moment driver hasn't handled any interrupts yet, so it
        // should inject interrupt.
        assert_eq!(queue.trigger_interrupt(), true);

        // Driver handle all the interrupts and update avail.used_event to 0x100
        let mut driver_handled = device_generate;
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver have handled all the interrupts, and
        // device doesn't generate more data, so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(), false);

        // Assume driver submit another u16::MAX - 0x100 req to device,
        // Device has handled all of them, so increase self.next_used to u16::MAX
        for _ in device_generate.0..u16::MAX {
            queue.add_used_with_bytes_written(fake_desc_chain(&mem), BUFFER_LEN);
        }
        device_generate = Wrapping(u16::MAX);

        // At this moment driver just handled 0x100 interrupts, so it
        // should inject interrupt.
        assert_eq!(queue.trigger_interrupt(), true);

        // driver handle all the interrupts and update avail.used_event to u16::MAX
        driver_handled = device_generate;
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver have handled all the interrupts, and
        // device doesn't generate more data, so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(), false);

        // Assume driver submit another 1 request,
        // device has handled it, so wrap self.next_used to 0
        queue.add_used_with_bytes_written(fake_desc_chain(&mem), BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver has handled all the previous interrupts, so it
        // should inject interrupt again.
        assert_eq!(queue.trigger_interrupt(), true);

        // driver handle that interrupts and update avail.used_event to 0
        driver_handled = device_generate;
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver have handled all the interrupts, and
        // device doesn't generate more data, so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(), false);
    }

    #[test]
    fn queue_event_id_guest_slow() {
        let mut queue =
            QueueConfig::new(QUEUE_SIZE.try_into().unwrap(), 1 << VIRTIO_RING_F_EVENT_IDX);
        let memory_start_addr = GuestAddress(0x0);
        let mem = GuestMemory::new(&[(memory_start_addr, GUEST_MEMORY_SIZE)]).unwrap();
        let mut queue = setup_vq(&mut queue, &mem);

        // Offset of used_event within Avail structure
        let used_event_offset = offset_of!(Avail, used_event) as u64;
        let used_event_address = GuestAddress(AVAIL_OFFSET + used_event_offset);

        // Assume driver submit 0x100 req to device,
        // device have handled 0x100 req, so increase self.next_used to 0x100
        let mut device_generate: Wrapping<u16> = Wrapping(0x100);
        for _ in 0..device_generate.0 {
            queue.add_used_with_bytes_written(fake_desc_chain(&mem), BUFFER_LEN);
        }

        // At this moment driver hasn't handled any interrupts yet, so it
        // should inject interrupt.
        assert_eq!(queue.trigger_interrupt(), true);

        // Driver handle part of the interrupts and update avail.used_event to 0x80
        let mut driver_handled = Wrapping(0x80);
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver hasn't finished last interrupt yet,
        // so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(), false);

        // Assume driver submit another 1 request,
        // device has handled it, so increment self.next_used.
        queue.add_used_with_bytes_written(fake_desc_chain(&mem), BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver hasn't finished last interrupt yet,
        // so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(), false);

        // Assume driver submit another u16::MAX - 0x101 req to device,
        // Device has handled all of them, so increase self.next_used to u16::MAX
        for _ in device_generate.0..u16::MAX {
            queue.add_used_with_bytes_written(fake_desc_chain(&mem), BUFFER_LEN);
        }
        device_generate = Wrapping(u16::MAX);

        // At this moment driver hasn't finished last interrupt yet,
        // so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(), false);

        // driver handle most of the interrupts and update avail.used_event to u16::MAX - 1,
        driver_handled = device_generate - Wrapping(1);
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // Assume driver submit another 1 request,
        // device has handled it, so wrap self.next_used to 0
        queue.add_used_with_bytes_written(fake_desc_chain(&mem), BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver has already finished the last interrupt(0x100),
        // and device service other request, so new interrupt is needed.
        assert_eq!(queue.trigger_interrupt(), true);

        // Assume driver submit another 1 request,
        // device has handled it, so increment self.next_used to 1
        queue.add_used_with_bytes_written(fake_desc_chain(&mem), BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver hasn't finished last interrupt((Wrapping(0)) yet,
        // so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(), false);

        // driver handle all the remain interrupts and wrap avail.used_event to 0x1.
        driver_handled = device_generate;
        let _ = mem.write_obj_at_addr(Le16::from(driver_handled.0), used_event_address);

        // At this moment driver has handled all the interrupts, and
        // device doesn't generate more data, so interrupt isn't needed.
        assert_eq!(queue.trigger_interrupt(), false);

        // Assume driver submit another 1 request,
        // device has handled it, so increase self.next_used.
        queue.add_used_with_bytes_written(fake_desc_chain(&mem), BUFFER_LEN);
        device_generate += Wrapping(1);

        // At this moment driver has finished all the previous interrupts, so it
        // should inject interrupt again.
        assert_eq!(queue.trigger_interrupt(), true);
    }
}
