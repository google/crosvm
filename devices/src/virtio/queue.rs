// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// !virtqueue interface

#![deny(missing_docs)]

mod split_queue;

use std::num::Wrapping;
use std::sync::Arc;

use anyhow::Result;
use cros_async::AsyncError;
use cros_async::EventAsync;
use futures::channel::oneshot;
use futures::select_biased;
use futures::FutureExt;
use split_queue::SplitQueue;
use sync::Mutex;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::virtio::ipc_memory_mapper::IpcMemoryMapper;
use crate::virtio::DescriptorChain;
use crate::virtio::SignalableInterrupt;

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
            }
        }
    };
}

/// Virtqueue interface representing different types of virtqueues
/// The struct of each queue type is wrapped in the enum variants
pub enum Queue {
    /// Split virtqueue type in virtio v1.2 spec: <https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-350007>
    SplitVirtQueue(SplitQueue),
}

/// This enum is used to specify the type of virtqueue (split or packed).
pub enum QueueType {
    /// Split Virtqueue type
    Split,
}

impl Queue {
    /// Constructs an empty virtio queue with the given `max_size`.
    pub fn new(queue_type: QueueType, max_size: u16) -> Self {
        match queue_type {
            QueueType::Split => Self::SplitVirtQueue(SplitQueue::new(max_size)),
        }
    }

    /// Convert the queue configuration into an active queue.
    pub fn activate(&mut self) -> Result<Queue> {
        match self {
            Queue::SplitVirtQueue(sq) => sq.activate().map(Queue::SplitVirtQueue),
        }
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

    /// If a new DescriptorHead is available, returns one and removes it from the queue.
    pub fn pop(&mut self, mem: &GuestMemory) -> Option<DescriptorChain> {
        let descriptor_chain = self.peek(mem);
        if descriptor_chain.is_some() {
            self.pop_peeked(mem);
        }
        descriptor_chain
    }

    /// Returns `None` if stop_rx receives a value; otherwise returns the result
    /// of waiting for the next descriptor.
    pub async fn next_async_interruptable(
        &mut self,
        mem: &GuestMemory,
        queue_event: &mut EventAsync,
        mut stop_rx: &mut oneshot::Receiver<()>,
    ) -> std::result::Result<Option<DescriptorChain>, AsyncError> {
        select_biased! {
            avail_desc_res = self.next_async(mem, queue_event).fuse() => {
                Ok(Some(avail_desc_res?))
            }
            _ = stop_rx => Ok(None),
        }
    }

    /// inject interrupt into guest on this queue
    /// return true: interrupt is injected into guest for this queue
    ///        false: interrupt isn't injected
    pub fn trigger_interrupt<I: SignalableInterrupt>(
        &mut self,
        mem: &GuestMemory,
        interrupt: &I,
    ) -> bool {
        match self {
            Queue::SplitVirtQueue(sq) => sq.trigger_interrupt(mem, interrupt),
        }
    }

    /// Restore queue from snapshot
    pub fn restore(queue_type: QueueType, queue_value: serde_json::Value) -> anyhow::Result<Queue> {
        match queue_type {
            QueueType::Split => SplitQueue::restore(queue_value).map(Queue::SplitVirtQueue),
        }
    }

    define_queue_method!(
        /// Getter for vector field
        vector,
        u16,
    );

    define_queue_method!(
        /// Setter for vector field
        set_vector,
        (),
        mut,
        val: u16
    );

    define_queue_method!(
        /// Getter for descriptor area
        desc_table,
        GuestAddress,
    );

    define_queue_method!(
        /// Setter for descriptor area
        set_desc_table,
        (),
        mut,
        val: GuestAddress
    );

    define_queue_method!(
        /// Getter for driver area
        avail_ring,
        GuestAddress,
    );

    define_queue_method!(
        /// Setter for driver area
        set_avail_ring,
        (),
        mut,
        val: GuestAddress
    );

    define_queue_method!(
        /// Getter for device area
        used_ring,
        GuestAddress,
    );

    define_queue_method!(
        /// Setter for device area
        set_used_ring,
        (),
        mut,
        val: GuestAddress
    );

    define_queue_method!(
        /// Getter for next_avial index
        next_avail,
        Wrapping<u16>,
    );

    define_queue_method!(
        /// Setter for next_avial index
        set_next_avail,
        (),
        mut,
        val: Wrapping<u16>
    );

    define_queue_method!(
        /// Getter for next_used index
        next_used,
        Wrapping<u16>,
    );

    define_queue_method!(
        /// Setter for next_used index
        set_next_used,
        (),
        mut,
        val: Wrapping<u16>
    );

    define_queue_method!(
        /// Return the maximum size of this queue.
        max_size,
        u16,
    );

    define_queue_method!(
        /// Return the actual size of the queue, as the driver may not set up a
        /// queue as big as the device allows.
        size,
        u16,
    );

    define_queue_method!(
        /// Set the queue size requested by the driver, which may be smaller than the maximum size.
        set_size,
        (),
        mut,
        val: u16
    );

    define_queue_method!(
        /// Return whether the driver has enabled this queue.
        ready,
        bool,
    );

    define_queue_method!(
        /// Signal that the driver has completed queue configuration.
        set_ready,
        (),
        mut,
        enable: bool
    );

    define_queue_method!(
        /// Reset queue to a clean state
        reset,
        (),
        mut,
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
        mem: &GuestMemory
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
        mem: &GuestMemory
    );

    define_queue_method!(
        /// If a new DescriptorHead is available, returns one and removes it from the queue.
        pop_peeked,
        (),
        mut,
        _mem: &GuestMemory
    );

    define_queue_method!(
        /// Puts an available descriptor head into the used ring for use by the guest.
        add_used,
        (),
        mut,
        mem: &GuestMemory,
        desc_chain: DescriptorChain,
        len: u32
    );

    define_queue_method!(
        /// Acknowledges that this set of features should be enabled on this queue.
        ack_features,
        (),
        mut,
        features: u64
    );

    define_queue_method!(
        /// Set IPC memory mapper for iommu
        set_iommu,
        (),
        mut,
        iommu: Arc<Mutex<IpcMemoryMapper>>
    );

    define_queue_method!(
        /// Take snapshot of queue's current status
        snapshot,
        Result<serde_json::Value>,
    );
}
