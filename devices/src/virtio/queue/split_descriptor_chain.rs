// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Split virtqueue descriptor chain iterator

#![deny(missing_docs)]

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::trace;
use data_model::Le16;
use data_model::Le32;
use data_model::Le64;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::virtio::descriptor_chain::Descriptor;
use crate::virtio::descriptor_chain::DescriptorAccess;
use crate::virtio::descriptor_chain::DescriptorChainIter;
use crate::virtio::descriptor_chain::VIRTQ_DESC_F_NEXT;
use crate::virtio::descriptor_chain::VIRTQ_DESC_F_WRITE;

/// A single virtio split queue descriptor (`struct virtq_desc` in the spec).
#[derive(Copy, Clone, Debug, FromBytes, AsBytes)]
#[repr(C)]
pub struct Desc {
    /// Guest address of memory described by this descriptor.
    pub addr: Le64,

    /// Length of this descriptor's memory region in bytes.
    pub len: Le32,

    /// `VIRTQ_DESC_F_*` flags for this descriptor.
    pub flags: Le16,

    /// Index of the next descriptor in the chain (only valid if `flags & VIRTQ_DESC_F_NEXT`).
    pub next: Le16,
}

/// Iterator over the descriptors of a split virtqueue descriptor chain.
pub struct SplitDescriptorChain<'m> {
    /// Current descriptor index within `desc_table`, or `None` if the iterator is exhausted.
    index: Option<u16>,

    /// Number of descriptors returned by the iterator already.
    /// If `count` reaches `queue_size`, the chain has a loop and is therefore invalid.
    count: u16,

    queue_size: u16,

    /// If `writable` is true, a writable descriptor has already been encountered.
    /// Valid descriptor chains must consist of readable descriptors followed by writable
    /// descriptors.
    writable: bool,

    mem: &'m GuestMemory,
    desc_table: GuestAddress,
}

impl<'m> SplitDescriptorChain<'m> {
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
        index: u16,
    ) -> SplitDescriptorChain<'m> {
        trace!("starting split descriptor chain head={index}");
        SplitDescriptorChain {
            index: Some(index),
            count: 0,
            queue_size,
            writable: false,
            mem,
            desc_table,
        }
    }
}

impl DescriptorChainIter for SplitDescriptorChain<'_> {
    fn next(&mut self) -> Result<Option<Descriptor>> {
        let index = match self.index {
            Some(index) => index,
            None => return Ok(None),
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
        self.count += 1;

        let desc_addr = self
            .desc_table
            .checked_add((index as u64) * 16)
            .context("integer overflow")?;
        let desc = self
            .mem
            .read_obj_from_addr::<Desc>(desc_addr)
            .with_context(|| format!("failed to read desc {:#x}", desc_addr.offset()))?;

        let address: u64 = desc.addr.into();
        let len: u32 = desc.len.into();
        let flags: u16 = desc.flags.into();
        let next: u16 = desc.next.into();

        trace!("{index:5}: addr={address:#016x} len={len:#08x} flags={flags:#x}");

        let unexpected_flags = flags & !(VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT);
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

        self.index = if flags & VIRTQ_DESC_F_NEXT != 0 {
            Some(next)
        } else {
            None
        };

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
        None
    }
}
