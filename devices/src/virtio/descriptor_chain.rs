// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtqueue descriptor chain abstraction

#![deny(missing_docs)]

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::trace;
use cros_async::MemRegion;
use smallvec::SmallVec;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::virtio::descriptor_utils::Reader;
use crate::virtio::descriptor_utils::Writer;

/// Virtio flag indicating there is a next descriptor in descriptor chain
pub const VIRTQ_DESC_F_NEXT: u16 = 0x1;
/// Virtio flag indicating descriptor is write-only
pub const VIRTQ_DESC_F_WRITE: u16 = 0x2;

/// Packed virtqueue flags
pub const VIRTQ_DESC_F_AVAIL: u16 = 0x80;
pub const VIRTQ_DESC_F_USED: u16 = 0x8000;

/// Type of access allowed for a single virtio descriptor within a descriptor chain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DescriptorAccess {
    /// Descriptor is readable by the device (written by the driver before putting the descriptor
    /// chain on the available queue).
    DeviceRead,
    /// Descriptor is writable by the device (read by the driver after the device puts the
    /// descriptor chain on the used queue).
    DeviceWrite,
}

/// A virtio descriptor chain.
///
/// This is a low-level representation of the memory regions in a descriptor chain. Most code should
/// use [`virtio::Reader`](crate::virtio::Reader) and [`virtio::Writer`](crate::virtio::Writer)
/// rather than working with `DescriptorChain` memory regions directly.
pub struct DescriptorChain {
    mem: GuestMemory,

    /// Index into the descriptor table.
    index: u16,

    /// The readable memory regions that make up the descriptor chain.
    pub reader: Reader,

    /// The writable memory regions that make up the descriptor chain.
    pub writer: Writer,

    /// The descriptor chain id(only if it is a packed virtqueue descriptor chain)
    pub id: Option<u16>,

    ///  Number of descriptor in descriptor chain
    pub count: u16,
}

impl DescriptorChain {
    /// Read all descriptors from `chain` into a new `DescriptorChain` instance.
    ///
    /// This function validates the following properties of the descriptor chain:
    /// * The chain contains at least one descriptor.
    /// * Each descriptor has a non-zero length.
    /// * Each descriptor's memory falls entirely within a contiguous region of `mem`.
    /// * The total length of the descriptor chain data is representable in `u32`.
    ///
    /// If these properties do not hold, `Err` will be returned.
    ///
    /// # Arguments
    ///
    /// * `chain` - Iterator that will be walked to retrieve all of the descriptors in the chain.
    /// * `mem` - The [`GuestMemory`] backing the descriptor table and descriptor memory regions.
    /// * `index` - The index of the first descriptor in the chain.
    pub fn new(
        mut chain: impl DescriptorChainIter,
        mem: &GuestMemory,
        index: u16,
    ) -> Result<DescriptorChain> {
        let mut readable_regions = SmallVec::new();
        let mut writable_regions = SmallVec::new();

        while let Some(desc) = chain.next()? {
            if desc.len == 0 {
                bail!("invalid zero-length descriptor");
            }

            Self::add_descriptor(&mut readable_regions, &mut writable_regions, desc)?;
        }

        let count = chain.count();
        let id = chain.id();

        Self::validate_mem_regions(mem, &readable_regions, &writable_regions)
            .context("invalid descriptor chain memory regions")?;

        trace!(
            "Descriptor chain created, index:{index}, count:{count}, buffer id:{:?}, readable:{}, writable:{}",
            id,
            readable_regions.len(),
            writable_regions.len()
        );

        let reader = Reader::new_from_regions(mem, readable_regions);
        let writer = Writer::new_from_regions(mem, writable_regions);

        let desc_chain = DescriptorChain {
            mem: mem.clone(),
            index,
            reader,
            writer,
            id,
            count,
        };

        Ok(desc_chain)
    }

    fn add_descriptor(
        readable_regions: &mut SmallVec<[MemRegion; 2]>,
        writable_regions: &mut SmallVec<[MemRegion; 2]>,
        desc: Descriptor,
    ) -> Result<()> {
        let region = MemRegion {
            offset: desc.address,
            len: desc.len as usize,
        };

        match desc.access {
            DescriptorAccess::DeviceRead => readable_regions.push(region),
            DescriptorAccess::DeviceWrite => writable_regions.push(region),
        }

        Ok(())
    }

    fn validate_mem_regions(
        mem: &GuestMemory,
        readable_regions: &[MemRegion],
        writable_regions: &[MemRegion],
    ) -> Result<()> {
        let mut total_len: u32 = 0;
        for r in readable_regions.iter().chain(writable_regions.iter()) {
            // This cast is safe because the virtio descriptor length field is u32.
            let len = r.len as u32;

            // Check that all the regions are totally contained in GuestMemory.
            if !mem.is_valid_range(GuestAddress(r.offset), len.into()) {
                bail!(
                    "descriptor address range out of bounds: addr={:#x} len={:#x}",
                    r.offset,
                    r.len
                );
            }

            // Verify that summing the descriptor sizes does not overflow.
            // This can happen if a driver tricks a device into reading/writing more data than
            // fits in a `u32`.
            total_len = total_len
                .checked_add(len)
                .context("descriptor chain length overflow")?;
        }

        if total_len == 0 {
            bail!("invalid zero-length descriptor chain");
        }

        Ok(())
    }

    /// Returns a reference to the [`GuestMemory`] instance.
    pub fn mem(&self) -> &GuestMemory {
        &self.mem
    }

    /// Returns the index of the first descriptor in the chain.
    pub fn index(&self) -> u16 {
        self.index
    }
}

/// A single descriptor within a [`DescriptorChain`].
pub struct Descriptor {
    /// Guest memory address of this descriptor.
    /// If IOMMU is enabled, this is an IOVA, which must be translated via the IOMMU to get a
    /// guest physical address.
    pub address: u64,

    /// Length of the descriptor in bytes.
    pub len: u32,

    /// Whether this descriptor should be treated as writable or readable by the device.
    pub access: DescriptorAccess,
}

/// Iterator over the descriptors of a descriptor chain.
pub trait DescriptorChainIter {
    /// Return the next descriptor in the chain, or `None` if there are no more descriptors.
    fn next(&mut self) -> Result<Option<Descriptor>>;

    /// Return the number of descriptor has been iterated in the chain
    fn count(&self) -> u16;

    /// Return Packed descriptor chain buffer id if iterator reaches end, otherwise return None
    /// SplitDescriptorChainIter should return None.
    fn id(&self) -> Option<u16>;
}
