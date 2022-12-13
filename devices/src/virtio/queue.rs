// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! virtqueue interface

#![deny(missing_docs)]

pub mod packed_descriptor_chain;
mod packed_queue;
pub mod split_descriptor_chain;
mod split_queue;

use std::num::Wrapping;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::warn;
use base::Event;
use cros_async::AsyncError;
use cros_async::EventAsync;
use futures::channel::oneshot;
use futures::select_biased;
use futures::FutureExt;
use packed_queue::PackedQueue;
use serde::Deserialize;
use serde::Serialize;
use split_queue::SplitQueue;
use sync::Mutex;
use virtio_sys::virtio_config::VIRTIO_F_RING_PACKED;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::virtio::ipc_memory_mapper::IpcMemoryMapper;
use crate::virtio::DescriptorChain;
use crate::virtio::Interrupt;
use crate::virtio::VIRTIO_MSI_NO_VECTOR;

/// A virtio queue's parameters.
///
/// `QueueConfig` can be converted into a running `Queue` by calling [`QueueConfig::activate()`].
pub struct QueueConfig {
    /// Whether this queue has already been activated.
    activated: bool,

    /// The maximal size in elements offered by the device
    max_size: u16,

    /// The queue size in elements the driver selected. This is always guaranteed to be a power of
    /// two less than or equal to `max_size`, as required for split virtqueues. These invariants are
    /// enforced by `set_size()`.
    size: u16,

    /// Indicates if the queue is finished with configuration
    ready: bool,

    /// MSI-X vector for the queue. Don't care for INTx
    vector: u16,

    /// Ring features (e.g. `VIRTIO_RING_F_EVENT_IDX`, `VIRTIO_F_RING_PACKED`) offered by the device
    features: u64,

    // Device feature bits accepted by the driver
    acked_features: u64,

    /// Guest physical address of the descriptor table
    desc_table: GuestAddress,

    /// Guest physical address of the available ring (driver area)
    ///
    /// TODO(b/290657008): update field and accessor names to match the current virtio spec
    avail_ring: GuestAddress,

    /// Guest physical address of the used ring (device area)
    used_ring: GuestAddress,

    /// Initial available ring index when the queue is activated.
    next_avail: Wrapping<u16>,

    /// Initial used ring index when the queue is activated.
    next_used: Wrapping<u16>,

    /// If present, `iommu` is used to translate guest addresses from IOVA to GPA.
    iommu: Option<Arc<Mutex<IpcMemoryMapper>>>,
}

#[derive(Serialize, Deserialize)]
struct QueueConfigSnapshot {
    activated: bool,
    max_size: u16,
    size: u16,
    ready: bool,
    vector: u16,
    features: u64,
    acked_features: u64,
    desc_table: GuestAddress,
    avail_ring: GuestAddress,
    used_ring: GuestAddress,
    next_avail: Wrapping<u16>,
    next_used: Wrapping<u16>,
}

impl QueueConfig {
    /// Constructs a virtio queue configuration with the given `max_size`.
    pub fn new(max_size: u16, features: u64) -> Self {
        assert!(max_size > 0);
        assert!(max_size <= Queue::MAX_SIZE);
        QueueConfig {
            activated: false,
            max_size,
            size: max_size,
            ready: false,
            vector: VIRTIO_MSI_NO_VECTOR,
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
            features,
            acked_features: 0,
            next_used: Wrapping(0),
            next_avail: Wrapping(0),
            iommu: None,
        }
    }

    /// Returns the maximum size of this queue.
    pub fn max_size(&self) -> u16 {
        self.max_size
    }

    /// Returns the currently configured size of the queue.
    pub fn size(&self) -> u16 {
        self.size
    }

    /// Sets the queue size.
    pub fn set_size(&mut self, val: u16) {
        if self.ready {
            warn!("ignoring write to size on ready queue");
            return;
        }

        if val > self.max_size {
            warn!(
                "requested queue size {} is larger than max_size {}",
                val, self.max_size
            );
            return;
        }

        self.size = val;
    }

    /// Returns the currently configured interrupt vector.
    pub fn vector(&self) -> u16 {
        self.vector
    }

    /// Sets the interrupt vector for this queue.
    pub fn set_vector(&mut self, val: u16) {
        if self.ready {
            warn!("ignoring write to vector on ready queue");
            return;
        }

        self.vector = val;
    }

    /// Getter for descriptor area
    pub fn desc_table(&self) -> GuestAddress {
        self.desc_table
    }

    /// Setter for descriptor area
    pub fn set_desc_table(&mut self, val: GuestAddress) {
        if self.ready {
            warn!("ignoring write to desc_table on ready queue");
            return;
        }

        self.desc_table = val;
    }

    /// Getter for driver area
    pub fn avail_ring(&self) -> GuestAddress {
        self.avail_ring
    }

    /// Setter for driver area
    pub fn set_avail_ring(&mut self, val: GuestAddress) {
        if self.ready {
            warn!("ignoring write to avail_ring on ready queue");
            return;
        }

        self.avail_ring = val;
    }

    /// Getter for device area
    pub fn used_ring(&self) -> GuestAddress {
        self.used_ring
    }

    /// Setter for device area
    pub fn set_used_ring(&mut self, val: GuestAddress) {
        if self.ready {
            warn!("ignoring write to used_ring on ready queue");
            return;
        }

        self.used_ring = val;
    }

    /// Getter for next_avail index
    pub fn next_avail(&self) -> Wrapping<u16> {
        self.next_avail
    }

    /// Setter for next_avail index
    pub fn set_next_avail(&mut self, val: Wrapping<u16>) {
        if self.ready {
            warn!("ignoring write to next_avail on ready queue");
            return;
        }

        self.next_avail = val;
    }

    /// Getter for next_used index
    pub fn next_used(&self) -> Wrapping<u16> {
        self.next_used
    }

    /// Setter for next_used index
    pub fn set_next_used(&mut self, val: Wrapping<u16>) {
        if self.ready {
            warn!("ignoring write to next_used on ready queue");
            return;
        }

        self.next_used = val;
    }

    /// Returns the features that have been acknowledged by the driver.
    pub fn acked_features(&self) -> u64 {
        self.acked_features
    }

    /// Acknowledges that this set of features should be enabled on this queue.
    pub fn ack_features(&mut self, features: u64) {
        self.acked_features |= features & self.features;
    }

    /// Return whether the driver has enabled this queue.
    pub fn ready(&self) -> bool {
        self.ready
    }

    /// Signal that the driver has completed queue configuration.
    pub fn set_ready(&mut self, enable: bool) {
        self.ready = enable;
    }

    /// Convert the queue configuration into an active queue.
    pub fn activate(&mut self, mem: &GuestMemory, event: Event) -> Result<Queue> {
        if !self.ready {
            bail!("attempted to activate a non-ready queue");
        }

        if self.activated {
            bail!("queue is already activated");
        }
        // If VIRTIO_F_RING_PACKED feature bit is set, create a packed queue, otherwise create a split queue
        let queue: Queue = if ((self.acked_features >> VIRTIO_F_RING_PACKED) & 1) != 0 {
            let pq =
                PackedQueue::new(self, mem, event).context("Failed to create a packed queue.")?;
            Queue::PackedVirtQueue(pq)
        } else {
            let sq =
                SplitQueue::new(self, mem, event).context("Failed to create a split queue.")?;
            Queue::SplitVirtQueue(sq)
        };

        self.activated = true;
        Ok(queue)
    }

    /// Reset queue to a clean state
    pub fn reset(&mut self) {
        self.activated = false;
        self.ready = false;
        self.size = self.max_size;
        self.vector = VIRTIO_MSI_NO_VECTOR;
        self.desc_table = GuestAddress(0);
        self.avail_ring = GuestAddress(0);
        self.used_ring = GuestAddress(0);
        self.next_avail = Wrapping(0);
        self.next_used = Wrapping(0);
        self.acked_features = 0;
    }

    /// Get IPC memory mapper for iommu
    pub fn iommu(&self) -> Option<Arc<Mutex<IpcMemoryMapper>>> {
        self.iommu.as_ref().map(Arc::clone)
    }

    /// Set IPC memory mapper for iommu
    pub fn set_iommu(&mut self, iommu: Arc<Mutex<IpcMemoryMapper>>) {
        self.iommu = Some(iommu);
    }

    /// Take snapshot of queue configuration
    pub fn snapshot(&self) -> Result<serde_json::Value> {
        serde_json::to_value(QueueConfigSnapshot {
            activated: self.activated,
            max_size: self.max_size,
            size: self.size,
            ready: self.ready,
            vector: self.vector,
            features: self.features,
            acked_features: self.acked_features,
            desc_table: self.desc_table,
            avail_ring: self.avail_ring,
            used_ring: self.used_ring,
            next_avail: self.next_avail,
            next_used: self.next_used,
        })
        .context("error serializing")
    }

    /// Restore queue configuration from snapshot
    pub fn restore(&mut self, data: serde_json::Value) -> Result<()> {
        let snap: QueueConfigSnapshot =
            serde_json::from_value(data).context("error deserializing")?;
        self.activated = snap.activated;
        self.max_size = snap.max_size;
        self.size = snap.size;
        self.ready = snap.ready;
        self.vector = snap.vector;
        self.features = snap.features;
        self.acked_features = snap.acked_features;
        self.desc_table = snap.desc_table;
        self.avail_ring = snap.avail_ring;
        self.used_ring = snap.used_ring;
        self.next_avail = snap.next_avail;
        self.next_used = snap.next_used;
        Ok(())
    }
}

/// Usage: define_queue_method!(method_name, return_type[, mut][, arg1: arg1_type, arg2: arg2_type, ...])
///
/// - `method_name`: The name of the method to be defined (as an identifier).
/// - `return_type`: The return type of the method.
/// - `mut` (optional): Include this keyword if the method requires a mutable reference to `self` (`&mut self`).
/// - `arg1: arg1_type, arg2: arg2_type, ...` (optional): Include method parameters as a comma-separated list
///   of `name: type` pairs, if the method takes any arguments.
macro_rules! define_queue_method {
    (
        $(#[$doc:meta])*
        $method:ident, $return_type:ty, $( $var:ident : $vartype:ty ),*
    ) => {
        $(#[$doc])*
        pub fn $method(&self, $($var: $vartype),*) -> $return_type {
            match self {
                Queue::SplitVirtQueue(sq) => sq.$method($($var),*),
                Queue::PackedVirtQueue(pq) => pq.$method($($var),*),
            }
        }
    };
    (
        $(#[$doc:meta])*
        $method:ident, $return_type:ty, mut, $( $var:ident : $vartype:ty ),*
    ) => {
        $(#[$doc])*
        pub fn $method(&mut self, $($var: $vartype),*) -> $return_type {
            match self {
                Queue::SplitVirtQueue(sq) => sq.$method($($var),*),
                Queue::PackedVirtQueue(pq) => pq.$method($($var),*),
            }
        }
    };
}

/// Virtqueue interface representing different types of virtqueues
/// The struct of each queue type is wrapped in the enum variants
#[derive(Debug)]
pub enum Queue {
    /// Split virtqueue type in virtio v1.2 spec: <https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-350007>
    SplitVirtQueue(SplitQueue),
    /// Packed virtqueue type in virtio v1.2 spec: <https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-720008>
    PackedVirtQueue(PackedQueue),
}

impl Queue {
    /// Largest valid number of entries in a virtqueue.
    pub const MAX_SIZE: u16 = 32768;

    /// Asynchronously read the next descriptor chain from the queue.
    /// Returns a `DescriptorChain` when it is `await`ed.
    pub async fn next_async(
        &mut self,
        eventfd: &mut EventAsync,
    ) -> std::result::Result<DescriptorChain, AsyncError> {
        loop {
            // Check if there are more descriptors available.
            if let Some(chain) = self.pop() {
                return Ok(chain);
            }
            eventfd.next_val().await?;
        }
    }

    /// If a new DescriptorHead is available, returns one and removes it from the queue.
    pub fn pop(&mut self) -> Option<DescriptorChain> {
        let descriptor_chain = self.peek();
        if descriptor_chain.is_some() {
            self.pop_peeked();
        }
        descriptor_chain
    }

    /// Returns `None` if stop_rx receives a value; otherwise returns the result
    /// of waiting for the next descriptor.
    pub async fn next_async_interruptable(
        &mut self,
        queue_event: &mut EventAsync,
        mut stop_rx: &mut oneshot::Receiver<()>,
    ) -> std::result::Result<Option<DescriptorChain>, AsyncError> {
        select_biased! {
            avail_desc_res = self.next_async(queue_event).fuse() => {
                Ok(Some(avail_desc_res?))
            }
            _ = stop_rx => Ok(None),
        }
    }

    /// inject interrupt into guest on this queue
    /// return true: interrupt is injected into guest for this queue
    ///        false: interrupt isn't injected
    pub fn trigger_interrupt(&mut self, interrupt: &Interrupt) -> bool {
        match self {
            Queue::SplitVirtQueue(sq) => sq.trigger_interrupt(interrupt),
            Queue::PackedVirtQueue(pq) => pq.trigger_interrupt(interrupt),
        }
    }

    /// Restore queue from snapshot
    pub fn restore(
        queue_config: &QueueConfig,
        queue_value: serde_json::Value,
        mem: &GuestMemory,
        event: Event,
    ) -> anyhow::Result<Queue> {
        if queue_config.acked_features & 1 << VIRTIO_F_RING_PACKED != 0 {
            PackedQueue::restore(queue_value, mem, event).map(Queue::PackedVirtQueue)
        } else {
            SplitQueue::restore(queue_value, mem, event).map(Queue::SplitVirtQueue)
        }
    }

    define_queue_method!(
        /// Getter for vector field
        vector,
        u16,
    );

    define_queue_method!(
        /// Getter for descriptor area
        desc_table,
        GuestAddress,
    );

    define_queue_method!(
        /// Getter for driver area
        avail_ring,
        GuestAddress,
    );

    define_queue_method!(
        /// Getter for device area
        used_ring,
        GuestAddress,
    );

    define_queue_method!(
        /// Return the actual size of the queue, as the driver may not set up a
        /// queue as big as the device allows.
        size,
        u16,
    );

    define_queue_method!(
        /// Get a reference to the queue's event.
        event,
        &Event,
    );

    define_queue_method!(
        /// Reset queue's counters.
        /// This method doesn't change the queue's metadata so it's reusable without initializing it
        /// again.
        reset_counters,
        (),
        mut,
    );

    define_queue_method!(
        /// If this queue is for a device that sits behind a virtio-iommu device, exports
        /// this queue's memory. After the queue becomes ready, this must be called before
        /// using the queue, to convert the IOVA-based configuration to GuestAddresses.
        export_memory,
        Result<()>,
        mut,
    );

    define_queue_method!(
        /// Releases memory exported by a previous call to [`Queue::export_memory()`].
        release_exported_memory,
        (),
        mut,
    );

    define_queue_method!(
        /// Get the first available descriptor chain without removing it from the queue.
        /// Call `pop_peeked` to remove the returned descriptor chain from the queue.
        peek,
        Option<DescriptorChain>,
        mut,
    );

    define_queue_method!(
        /// If a new DescriptorHead is available, returns one and removes it from the queue.
        pop_peeked,
        (),
        mut,
    );

    define_queue_method!(
        /// Puts an available descriptor head into the used ring for use by the guest.
        add_used,
        (),
        mut,
        desc_chain: DescriptorChain,
        len: u32
    );

    define_queue_method!(
        /// Take snapshot of queue's current status
        snapshot,
        Result<serde_json::Value>,
    );
}
