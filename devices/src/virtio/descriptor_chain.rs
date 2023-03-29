// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtqueue descriptor chain abstraction

#![deny(missing_docs)]

use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::trace;
use base::Protection;
use cros_async::MemRegion;
use data_model::Le16;
use data_model::Le32;
use data_model::Le64;
use smallvec::SmallVec;
use sync::Mutex;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::virtio::ipc_memory_mapper::ExportedRegion;
use crate::virtio::ipc_memory_mapper::IpcMemoryMapper;
use crate::virtio::memory_util::read_obj_from_addr_wrapper;

const VIRTQ_DESC_F_NEXT: u16 = 0x1;
const VIRTQ_DESC_F_WRITE: u16 = 0x2;

/// A single virtio split queue descriptor (`struct virtq_desc` in the spec).
#[derive(Copy, Clone, Debug, FromBytes, AsBytes)]
#[repr(C)]
pub struct Desc {
    /// Guest address of memory described by this descriptor.
    pub addr: Le64,

    /// Length of this descriptor's memory region in byutes.
    pub len: Le32,

    /// `VIRTQ_DESC_F_*` flags for this descriptor.
    pub flags: Le16,

    /// Index of the next descriptor in the chain (only valid if `flags & VIRTQ_DESC_F_NEXT`).
    pub next: Le16,
}

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

    /// The memory regions that make up the descriptor chain.
    readable_regions: SmallVec<[MemRegion; 2]>,
    writable_regions: SmallVec<[MemRegion; 2]>,

    /// The exported iommu regions of the descriptors. Non-empty iff iommu is enabled.
    exported_regions: Vec<ExportedRegion>,
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
    /// * `iommu` - An optional IOMMU to use for mapping descriptor memory regions. If `iommu` is
    ///   specified, the descriptor memory regions will be mapped for the lifetime of this
    ///   `DescriptorChain` object.
    pub fn new(
        mut chain: impl DescriptorChainIter,
        mem: &GuestMemory,
        index: u16,
        iommu: Option<Arc<Mutex<IpcMemoryMapper>>>,
    ) -> Result<DescriptorChain> {
        let mut desc_chain = DescriptorChain {
            mem: mem.clone(),
            index,
            readable_regions: SmallVec::new(),
            writable_regions: SmallVec::new(),
            exported_regions: Vec::new(),
        };

        while let Some(desc) = chain.next()? {
            if desc.len == 0 {
                bail!("invalid zero-length descriptor");
            }

            if let Some(iommu) = iommu.as_ref() {
                desc_chain.add_descriptor_iommu(desc, iommu)?;
            } else {
                desc_chain.add_descriptor(desc)?;
            }
        }

        desc_chain
            .validate_mem_regions()
            .context("invalid descriptor chain memory regions")?;

        trace!(
            "DescriptorChain readable={} writable={}",
            desc_chain.readable_mem_regions().len(),
            desc_chain.writable_mem_regions().len(),
        );

        Ok(desc_chain)
    }

    fn add_descriptor(&mut self, desc: Descriptor) -> Result<()> {
        let region = MemRegion {
            offset: desc.address,
            len: desc.len as usize,
        };

        match desc.access {
            DescriptorAccess::DeviceRead => self.readable_regions.push(region),
            DescriptorAccess::DeviceWrite => self.writable_regions.push(region),
        }

        Ok(())
    }

    fn add_descriptor_iommu(
        &mut self,
        desc: Descriptor,
        iommu: &Arc<Mutex<IpcMemoryMapper>>,
    ) -> Result<()> {
        let exported_region =
            ExportedRegion::new(&self.mem, iommu.clone(), desc.address, u64::from(desc.len))
                .context("failed to get mem regions")?;

        let regions = exported_region.get_mem_regions();

        let required_prot = match desc.access {
            DescriptorAccess::DeviceRead => Protection::read(),
            DescriptorAccess::DeviceWrite => Protection::write(),
        };
        if !regions.iter().all(|r| r.prot.allows(&required_prot)) {
            bail!("missing RW permissions for descriptor");
        }

        let regions_iter = regions.iter().map(|r| MemRegion {
            offset: r.gpa.offset(),
            len: r.len as usize,
        });

        match desc.access {
            DescriptorAccess::DeviceRead => self.readable_regions.extend(regions_iter),
            DescriptorAccess::DeviceWrite => self.writable_regions.extend(regions_iter),
        }

        self.exported_regions.push(exported_region);

        Ok(())
    }

    fn validate_mem_regions(&self) -> Result<()> {
        let mut total_len: u32 = 0;
        for r in self
            .readable_mem_regions()
            .iter()
            .chain(self.writable_mem_regions().iter())
        {
            // This cast is safe because the virtio descriptor length field is u32.
            let len = r.len as u32;

            // Check that all the regions are totally contained in GuestMemory.
            if !self.mem.is_valid_range(GuestAddress(r.offset), len.into()) {
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

    /// Returns the driver-readable memory regions of this descriptor chain.
    ///
    /// Each `MemRegion` is a contiguous range of guest physical memory.
    pub fn readable_mem_regions(&self) -> &[MemRegion] {
        &self.readable_regions
    }

    /// Returns the driver-writable memory regions of this descriptor chain.
    ///
    /// Each `MemRegion` is a contiguous range of guest physical memory.
    pub fn writable_mem_regions(&self) -> &[MemRegion] {
        &self.writable_regions
    }

    /// Returns the IOMMU memory mapper regions for the memory regions in this chain.
    ///
    /// Empty if IOMMU is not enabled.
    pub fn exported_regions(&self) -> &[ExportedRegion] {
        &self.exported_regions
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
}

/// Iterator over the descriptors of a split virtqueue descriptor chain.
pub struct SplitDescriptorChain<'m, 'd> {
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
    exported_desc_table: Option<&'d ExportedRegion>,
}

impl<'m, 'd> SplitDescriptorChain<'m, 'd> {
    /// Construct a new iterator over a split virtqueue descriptor chain.
    ///
    /// # Arguments
    /// * `mem` - The [`GuestMemory`] containing the descriptor chain.
    /// * `desc_table` - Guest physical address of the descriptor table.
    /// * `queue_size` - Total number of entries in the descriptor table.
    /// * `index` - The index of the first descriptor in the chain.
    /// * `exported_desc_table` - If specified, contains the IOMMU mapping of the descriptor table
    ///   region.
    pub fn new(
        mem: &'m GuestMemory,
        desc_table: GuestAddress,
        queue_size: u16,
        index: u16,
        exported_desc_table: Option<&'d ExportedRegion>,
    ) -> SplitDescriptorChain<'m, 'd> {
        trace!("starting split descriptor chain head={index}");
        SplitDescriptorChain {
            index: Some(index),
            count: 0,
            queue_size,
            writable: false,
            mem,
            desc_table,
            exported_desc_table,
        }
    }
}

impl DescriptorChainIter for SplitDescriptorChain<'_, '_> {
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
        let desc =
            read_obj_from_addr_wrapper::<Desc>(self.mem, self.exported_desc_table, desc_addr)
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
}
