// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Packed virtqueue descriptor chain iterator

#![deny(missing_docs)]

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::trace;
use data_model::Le16;
use data_model::Le32;
use data_model::Le64;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::virtio::descriptor_chain::Descriptor;
use crate::virtio::descriptor_chain::DescriptorAccess;
use crate::virtio::descriptor_chain::DescriptorChainIter;
use crate::virtio::descriptor_chain::VIRTQ_DESC_F_AVAIL;
use crate::virtio::descriptor_chain::VIRTQ_DESC_F_NEXT;
use crate::virtio::descriptor_chain::VIRTQ_DESC_F_USED;
use crate::virtio::descriptor_chain::VIRTQ_DESC_F_WRITE;

/// Enable events
pub const RING_EVENT_FLAGS_ENABLE: u16 = 0x0;
/// Disable events
pub const RING_EVENT_FLAGS_DISABLE: u16 = 0x1;

/// Enable events for a specific descriptor.
/// Only valid if VIRTIO_F_RING_EVENT_IDX has been negotiated.
pub const RING_EVENT_FLAGS_DESC: u16 = 0x2;

/// A packed virtio packed queue descriptor (`struct pvirtq_desc` in the spec).
#[derive(Copy, Clone, Debug, FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
pub struct PackedDesc {
    /// Guest address of memory buffer address
    pub addr: Le64,

    /// Memory buffer length in bytes
    pub len: Le32,

    /// Buffer ID
    pub id: Le16,

    /// The flags depending on descriptor type
    pub flags: Le16,
}

impl PackedDesc {
    pub fn addr(&self) -> u64 {
        self.addr.into()
    }

    pub fn len(&self) -> u32 {
        self.len.into()
    }

    pub fn flags(&self) -> u16 {
        self.flags.into()
    }

    pub fn id(&self) -> u16 {
        self.id.into()
    }

    pub fn has_next(&self) -> bool {
        self.flags() & VIRTQ_DESC_F_NEXT != 0
    }

    pub fn is_available(&self, wrap_value: u16) -> bool {
        let avail = (self.flags() & VIRTQ_DESC_F_AVAIL) != 0;
        let used = (self.flags() & VIRTQ_DESC_F_USED) != 0;
        let wrap = wrap_value != 0;
        avail != used && avail == wrap
    }
}

#[derive(Copy, Clone, Debug, FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
pub struct PackedDescEvent {
    pub desc: Le16,
    pub flag: Le16,
}

impl PackedDescEvent {
    pub fn notification_type(&self) -> PackedNotificationType {
        let flag: u16 = self.flag.into();

        if flag == RING_EVENT_FLAGS_DISABLE {
            PackedNotificationType::Disable
        } else if flag == RING_EVENT_FLAGS_DESC {
            PackedNotificationType::Desc(self.desc.into())
        } else if flag == RING_EVENT_FLAGS_ENABLE {
            PackedNotificationType::Enable
        } else {
            let desc: u16 = self.desc.into();
            error!("Unknown packed desc event flag:{:x}, desc:{:x}", flag, desc);
            PackedNotificationType::Enable
        }
    }
}

pub enum PackedNotificationType {
    Enable,
    Disable,
    Desc(u16),
}

pub struct PackedDescriptorChain<'m> {
    avail_wrap_counter: bool,

    /// Current descriptor index within `desc_table`, or `None` if the iterator is exhausted.
    index: Option<u16>,

    /// Number of descriptors returned by the iterator already.
    /// If `count` reaches `queue_size`, the chain has a loop and is therefore invalid.
    count: u16,

    /// Buffer Id, which locates at the last descriptor in the chain
    id: Option<u16>,

    queue_size: u16,

    /// If `writable` is true, a writable descriptor has already been encountered.
    /// Valid descriptor chains must consist of readable descriptors followed by writable
    /// descriptors.
    writable: bool,

    mem: &'m GuestMemory,
    desc_table: GuestAddress,
}

impl<'m> PackedDescriptorChain<'m> {
    /// Construct a new iterator over a split virtqueue descriptor chain.
    ///
    /// # Arguments
    /// * `mem` - The [`GuestMemory`] containing the descriptor chain.
    /// * `desc_table` - Guest physical address of the descriptor table.
    /// * `queue_size` - Total number of entries in the descriptor table.
    /// * `index` - The index of the first descriptor in the chain.
    pub fn new(
        mem: &'m GuestMemory,
        desc_table: GuestAddress,
        queue_size: u16,
        avail_wrap_counter: bool,
        index: u16,
    ) -> PackedDescriptorChain<'m> {
        trace!("starting packed descriptor chain head={index}");
        PackedDescriptorChain {
            index: Some(index),
            count: 0,
            id: None,
            queue_size,
            writable: false,
            mem,
            desc_table,
            avail_wrap_counter,
        }
    }
}

impl DescriptorChainIter for PackedDescriptorChain<'_> {
    fn next(&mut self) -> Result<Option<Descriptor>> {
        let index = match self.index {
            Some(index) => index,
            None => {
                return Ok(None);
            }
        };

        if index >= self.queue_size {
            bail!(
                "out of bounds descriptor index {} for queue size {}",
                index,
                self.queue_size
            );
        }

        if self.count >= self.queue_size {
            bail!("descriptor chain loop detected");
        }

        let desc_addr = self
            .desc_table
            .checked_add((index as u64) * 16)
            .context("integer overflow")?;
        let desc = self
            .mem
            .read_obj_from_addr::<PackedDesc>(desc_addr)
            .with_context(|| format!("failed to read desc {:#x}", desc_addr.offset()))?;

        let address: u64 = desc.addr();
        let len: u32 = desc.len();
        let flags: u16 = desc.flags();

        trace!("{index:5}: addr={address:#016x} len={len:#08x} flags={flags:#x}");

        if !desc.is_available(self.avail_wrap_counter as u16) {
            return Ok(None);
        }

        if len == 0 {
            bail!("invalid zero-length descriptor");
        }

        let unexpected_flags = flags
            & !(VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_AVAIL | VIRTQ_DESC_F_USED);
        if unexpected_flags != 0 {
            bail!("unexpected flags in descriptor {index}: {unexpected_flags:#x}")
        }

        let access = if flags & VIRTQ_DESC_F_WRITE != 0 {
            DescriptorAccess::DeviceWrite
        } else {
            DescriptorAccess::DeviceRead
        };

        if access == DescriptorAccess::DeviceRead && self.writable {
            bail!("invalid device-readable descriptor following writable descriptors");
        } else if access == DescriptorAccess::DeviceWrite {
            self.writable = true;
        }

        // If VIRTQ_DESC_F_NEXT exists, the next descriptor in descriptor chain
        // is the next element in descriptor table. When index reaches the end of
        // descriptor table, we need to flip avail_wrap_counter.
        if desc.has_next() {
            if index + 1 < self.queue_size {
                self.index = Some(index + 1);
            } else {
                self.index = Some(0);
                self.avail_wrap_counter = !self.avail_wrap_counter;
            }
        } else {
            self.id = Some(desc.id());
            self.index = None;
        }

        self.count += 1;

        Ok(Some(Descriptor {
            address,
            len,
            access,
        }))
    }

    fn count(&self) -> u16 {
        self.count
    }

    fn id(&self) -> Option<u16> {
        self.id
    }
}
