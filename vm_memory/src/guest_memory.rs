// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Track memory regions that are mapped to the guest VM.

use std::convert::AsRef;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::marker::Send;
use std::marker::Sync;
use std::result;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use base::pagesize;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::Error as SysError;
use base::MappedRegion;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::MmapError;
use base::RawDescriptor;
use base::SharedMemory;
use base::VolatileMemory;
use base::VolatileMemoryError;
use base::VolatileSlice;
use cros_async::mem;
use cros_async::BackingMemory;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;
use snapshot::AnySnapshot;
use thiserror::Error;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

use crate::guest_address::GuestAddress;

mod sys;
pub use sys::MemoryPolicy;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to map guest memory to file: {0}")]
    FiledBackedMemoryMappingFailed(#[source] MmapError),
    #[error("failed to open file for file backed mapping: {0}")]
    FiledBackedOpenFailed(#[source] std::io::Error),
    #[error("invalid guest address {0}")]
    InvalidGuestAddress(GuestAddress),
    #[error("invalid guest range at {0} of size {1}")]
    InvalidGuestRange(GuestAddress, u64),
    #[error("invalid offset {0}")]
    InvalidOffset(u64),
    #[error("size {0} must not be zero")]
    InvalidSize(usize),
    #[error("invalid guest memory access at addr={0}: {1}")]
    MemoryAccess(GuestAddress, #[source] MmapError),
    #[error("failed to set seals on shm region: {0}")]
    MemoryAddSealsFailed(#[source] SysError),
    #[error("failed to create shm region: {0}")]
    MemoryCreationFailed(#[source] SysError),
    #[error("failed to map guest memory: {0}")]
    MemoryMappingFailed(#[source] MmapError),
    #[error("guest memory region {0}+{1:#x} is not page aligned")]
    MemoryNotAligned(GuestAddress, u64),
    #[error("memory regions overlap")]
    MemoryRegionOverlap,
    #[error("memory region size {0} is too large")]
    MemoryRegionTooLarge(u128),
    #[error("punch hole failed {0}")]
    PunchHole(#[source] base::Error),
    #[error("incomplete read of {completed} instead of {expected} bytes")]
    ShortRead { expected: usize, completed: usize },
    #[error("incomplete write of {completed} instead of {expected} bytes")]
    ShortWrite { expected: usize, completed: usize },
    #[error("DescriptorChain split is out of bounds: {0}")]
    SplitOutOfBounds(usize),
    #[error("{0}")]
    VolatileMemoryAccess(#[source] VolatileMemoryError),
}

pub type Result<T> = result::Result<T, Error>;

/// A file-like object backing `MemoryRegion`.
#[derive(Clone, Debug)]
pub enum BackingObject {
    Shm(Arc<SharedMemory>),
    File(Arc<File>),
}

impl AsRawDescriptor for BackingObject {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        match self {
            Self::Shm(shm) => shm.as_raw_descriptor(),
            Self::File(f) => f.as_raw_descriptor(),
        }
    }
}

impl AsRef<dyn AsRawDescriptor + Sync + Send> for BackingObject {
    fn as_ref(&self) -> &(dyn AsRawDescriptor + Sync + Send + 'static) {
        match self {
            BackingObject::Shm(shm) => shm.as_ref(),
            BackingObject::File(f) => f.as_ref(),
        }
    }
}

/// For MemoryRegion::regions
pub struct MemoryRegionInformation<'a> {
    pub index: usize,
    pub guest_addr: GuestAddress,
    pub size: usize,
    pub host_addr: usize,
    pub shm: &'a BackingObject,
    pub shm_offset: u64,
    pub options: MemoryRegionOptions,
}

#[sorted]
#[derive(Clone, Copy, Debug, Default, PartialOrd, PartialEq, Eq, Ord)]
pub enum MemoryRegionPurpose {
    /// BIOS/firmware ROM
    Bios,

    /// General purpose guest memory
    #[default]
    GuestMemoryRegion,

    /// PVMFW
    ProtectedFirmwareRegion,

    /// An area that should be backed by a GuestMemory region but reported as reserved to the
    /// guest.
    ReservedMemory,

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    StaticSwiotlbRegion,
}

#[derive(Clone, Debug, Serialize, Deserialize, FromKeyValues, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct FileBackedMappingParameters {
    pub path: std::path::PathBuf,
    #[serde(rename = "addr")]
    pub address: u64,
    pub size: u64,
    #[serde(default)]
    pub offset: u64,
    #[serde(rename = "rw", default)]
    pub writable: bool,
    #[serde(default)]
    pub sync: bool,
    #[serde(default)]
    pub align: bool,
    /// Whether the mapping is for RAM or MMIO.
    #[serde(default)]
    pub ram: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemoryRegionOptions {
    /// Some hypervisors (presently: Gunyah) need explicit knowledge about
    /// which memory region is used for protected firwmare, static swiotlb,
    /// or general purpose guest memory.
    pub purpose: MemoryRegionPurpose,
    /// Alignment for the mapping of this region. This intends to be used for
    /// arm64 KVM support where a block alignment is required for transparent
    /// huge-pages support
    pub align: u64,
    /// Backing file params.
    pub file_backed: Option<FileBackedMappingParameters>,
}

impl MemoryRegionOptions {
    pub fn new() -> MemoryRegionOptions {
        Default::default()
    }

    pub fn purpose(mut self, purpose: MemoryRegionPurpose) -> Self {
        self.purpose = purpose;
        self
    }

    pub fn align(mut self, alignment: u64) -> Self {
        self.align = alignment;
        self
    }

    pub fn file_backed(mut self, params: FileBackedMappingParameters) -> Self {
        self.file_backed = Some(params);
        self
    }
}

/// A regions of memory mapped memory.
/// Holds the memory mapping with its offset in guest memory.
/// Also holds the backing object for the mapping and the offset in that object of the mapping.
#[derive(Debug)]
pub struct MemoryRegion {
    mapping: MemoryMapping,
    guest_base: GuestAddress,

    shared_obj: BackingObject,
    obj_offset: u64,

    options: MemoryRegionOptions,
}

impl MemoryRegion {
    /// Creates a new MemoryRegion using the given SharedMemory object to later be attached to a VM
    /// at `guest_base` address in the guest.
    pub fn new_from_shm(
        size: u64,
        guest_base: GuestAddress,
        offset: u64,
        shm: Arc<SharedMemory>,
    ) -> Result<Self> {
        let mapping = MemoryMappingBuilder::new(size as usize)
            .from_shared_memory(shm.as_ref())
            .offset(offset)
            .build()
            .map_err(Error::MemoryMappingFailed)?;
        Ok(MemoryRegion {
            mapping,
            guest_base,
            shared_obj: BackingObject::Shm(shm),
            obj_offset: offset,
            options: Default::default(),
        })
    }

    /// Creates a new MemoryRegion using the given file to get available later at `guest_base`
    /// address in the guest.
    pub fn new_from_file(
        size: u64,
        guest_base: GuestAddress,
        offset: u64,
        file: Arc<File>,
    ) -> Result<Self> {
        let mapping = MemoryMappingBuilder::new(size as usize)
            .from_file(&file)
            .offset(offset)
            .build()
            .map_err(Error::MemoryMappingFailed)?;
        Ok(MemoryRegion {
            mapping,
            guest_base,
            shared_obj: BackingObject::File(file),
            obj_offset: offset,
            options: Default::default(),
        })
    }

    fn start(&self) -> GuestAddress {
        self.guest_base
    }

    fn end(&self) -> GuestAddress {
        // unchecked_add is safe as the region bounds were checked when it was created.
        self.guest_base.unchecked_add(self.mapping.size() as u64)
    }

    fn contains(&self, addr: GuestAddress) -> bool {
        addr >= self.guest_base && addr < self.end()
    }

    #[cfg(any(target_os = "android", target_os = "linux"))] // unused on windows
    fn contains_range(&self, addr: GuestAddress, size: u64) -> bool {
        let Some(end_addr) = addr.checked_add(size) else {
            return false;
        };
        addr >= self.guest_base && end_addr <= self.end()
    }
}

/// Tracks memory regions and where they are mapped in the guest, along with shm
/// descriptors of the underlying memory regions.
#[derive(Clone, Debug)]
pub struct GuestMemory {
    regions: Arc<[MemoryRegion]>,
    locked: bool,
    use_punchhole_locked: bool,
}

impl AsRawDescriptors for GuestMemory {
    /// USE WITH CAUTION, the descriptors returned here are not necessarily
    /// files!
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        self.regions
            .iter()
            .map(|r| r.shared_obj.as_raw_descriptor())
            .collect()
    }
}

impl GuestMemory {
    /// Creates backing shm for GuestMemory regions
    fn create_shm(ranges: &[(GuestAddress, u64, MemoryRegionOptions)]) -> Result<SharedMemory> {
        let mut aligned_size = 0;
        let pg_size = pagesize();
        for range in ranges {
            if range.2.file_backed.is_some() {
                // Regions with a backing file don't use part of the `SharedMemory`.
                continue;
            }
            if range.1 % pg_size as u64 != 0 {
                return Err(Error::MemoryNotAligned(range.0, range.1));
            }

            aligned_size += range.1;
        }

        // NOTE: Some tests rely on the GuestMemory's name when capturing metrics.
        let name = "crosvm_guest";
        // Shm must be mut even though it is only updated on Unix systems.
        #[allow(unused_mut)]
        let mut shm = SharedMemory::new(name, aligned_size).map_err(Error::MemoryCreationFailed)?;

        sys::finalize_shm(&mut shm)?;

        Ok(shm)
    }

    /// Creates a container for guest memory regions.
    /// Valid memory regions are specified as a Vec of (Address, Size, MemoryRegionOptions)
    pub fn new_with_options(
        ranges: &[(GuestAddress, u64, MemoryRegionOptions)],
    ) -> Result<GuestMemory> {
        // Create shm
        let shm = Arc::new(GuestMemory::create_shm(ranges)?);

        // Create memory regions
        let mut regions = Vec::<MemoryRegion>::new();
        let mut shm_offset = 0;

        for range in ranges {
            if let Some(last) = regions.last() {
                if last
                    .guest_base
                    .checked_add(last.mapping.size() as u64)
                    .map_or(true, |a| a > range.0)
                {
                    return Err(Error::MemoryRegionOverlap);
                }
            }

            let size = usize::try_from(range.1)
                .map_err(|_| Error::MemoryRegionTooLarge(range.1 as u128))?;
            if let Some(file_backed) = &range.2.file_backed {
                assert_eq!(usize::try_from(file_backed.size).unwrap(), size);
                let file = file_backed.open().map_err(Error::FiledBackedOpenFailed)?;
                let mapping = MemoryMappingBuilder::new(size)
                    .from_file(&file)
                    .offset(file_backed.offset)
                    .align(range.2.align)
                    .protection(if file_backed.writable {
                        base::Protection::read_write()
                    } else {
                        base::Protection::read()
                    })
                    .build()
                    .map_err(Error::FiledBackedMemoryMappingFailed)?;
                regions.push(MemoryRegion {
                    mapping,
                    guest_base: range.0,
                    shared_obj: BackingObject::File(Arc::new(file)),
                    obj_offset: file_backed.offset,
                    options: range.2.clone(),
                });
            } else {
                let mapping = MemoryMappingBuilder::new(size)
                    .from_shared_memory(shm.as_ref())
                    .offset(shm_offset)
                    .align(range.2.align)
                    .build()
                    .map_err(Error::MemoryMappingFailed)?;
                regions.push(MemoryRegion {
                    mapping,
                    guest_base: range.0,
                    shared_obj: BackingObject::Shm(shm.clone()),
                    obj_offset: shm_offset,
                    options: range.2.clone(),
                });
                shm_offset += size as u64;
            }
        }

        Ok(GuestMemory {
            regions: Arc::from(regions),
            locked: false,
            use_punchhole_locked: false,
        })
    }

    /// Creates a container for guest memory regions.
    /// Valid memory regions are specified as a Vec of (Address, Size) tuples sorted by Address.
    pub fn new(ranges: &[(GuestAddress, u64)]) -> Result<GuestMemory> {
        GuestMemory::new_with_options(
            ranges
                .iter()
                .map(|(addr, size)| (*addr, *size, Default::default()))
                .collect::<Vec<(GuestAddress, u64, MemoryRegionOptions)>>()
                .as_slice(),
        )
    }

    /// Creates a `GuestMemory` from a collection of MemoryRegions.
    pub fn from_regions(mut regions: Vec<MemoryRegion>) -> Result<Self> {
        // Sort the regions and ensure non overlap.
        regions.sort_by(|a, b| a.guest_base.cmp(&b.guest_base));

        if regions.len() > 1 {
            let mut prev_end = regions[0]
                .guest_base
                .checked_add(regions[0].mapping.size() as u64)
                .ok_or(Error::MemoryRegionOverlap)?;
            for region in &regions[1..] {
                if prev_end > region.guest_base {
                    return Err(Error::MemoryRegionOverlap);
                }
                prev_end = region
                    .guest_base
                    .checked_add(region.mapping.size() as u64)
                    .ok_or(Error::MemoryRegionTooLarge(
                        region.guest_base.0 as u128 + region.mapping.size() as u128,
                    ))?;
            }
        }

        Ok(GuestMemory {
            regions: Arc::from(regions),
            locked: false,
            use_punchhole_locked: false,
        })
    }

    // Whether `MemoryPolicy::LOCK_GUEST_MEMORY` was set.
    pub fn locked(&self) -> bool {
        self.locked
    }

    // Whether `MemoryPolicy::USE_PUNCHHOLE_LOCKED` was set.
    pub fn use_punchhole_locked(&self) -> bool {
        self.use_punchhole_locked
    }

    /// Returns the end address of memory.
    ///
    /// # Examples
    ///
    /// ```
    /// # use base::MemoryMapping;
    /// # use vm_memory::{GuestAddress, GuestMemory};
    /// # fn test_end_addr() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     assert_eq!(start_addr.checked_add(0x400), Some(gm.end_addr()));
    ///     Ok(())
    /// # }
    /// ```
    pub fn end_addr(&self) -> GuestAddress {
        self.regions
            .iter()
            .max_by_key(|region| region.start())
            .map_or(GuestAddress(0), MemoryRegion::end)
    }

    /// Returns the total size of memory in bytes.
    pub fn memory_size(&self) -> u64 {
        self.regions
            .iter()
            .map(|region| region.mapping.size() as u64)
            .sum()
    }

    /// Returns true if the given address is within the memory range available to the guest.
    pub fn address_in_range(&self, addr: GuestAddress) -> bool {
        self.regions.iter().any(|region| region.contains(addr))
    }

    /// Returns true if the given range (start, end) is overlap with the memory range
    /// available to the guest.
    pub fn range_overlap(&self, start: GuestAddress, end: GuestAddress) -> bool {
        self.regions
            .iter()
            .any(|region| region.start() < end && start < region.end())
    }

    /// Returns an address `addr + offset` if it's in range.
    ///
    /// This function doesn't care whether a region `[addr, addr + offset)` is in range or not. To
    /// guarantee it's a valid range, use `is_valid_range()` instead.
    pub fn checked_offset(&self, addr: GuestAddress, offset: u64) -> Option<GuestAddress> {
        addr.checked_add(offset).and_then(|a| {
            if self.address_in_range(a) {
                Some(a)
            } else {
                None
            }
        })
    }

    /// Returns true if the given range `[start, start + length)` is a valid contiguous memory
    /// range available to the guest and it's backed by a single underlying memory region.
    pub fn is_valid_range(&self, start: GuestAddress, length: u64) -> bool {
        if length == 0 {
            return false;
        }

        let end = if let Some(end) = start.checked_add(length - 1) {
            end
        } else {
            return false;
        };

        self.regions
            .iter()
            .any(|region| region.start() <= start && end < region.end())
    }

    /// Returns the size of the memory region in bytes.
    pub fn num_regions(&self) -> u64 {
        self.regions.len() as u64
    }

    pub fn regions(&self) -> impl Iterator<Item = MemoryRegionInformation> {
        self.regions
            .iter()
            .enumerate()
            .map(|(index, region)| MemoryRegionInformation {
                index,
                guest_addr: region.start(),
                size: region.mapping.size(),
                host_addr: region.mapping.as_ptr() as usize,
                shm: &region.shared_obj,
                shm_offset: region.obj_offset,
                options: region.options.clone(),
            })
    }

    /// Writes a slice to guest memory at the specified guest address.
    /// Returns the number of bytes written.  The number of bytes written can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Write a slice at guestaddress 0x200.
    ///
    /// ```
    /// # use base::MemoryMapping;
    /// # use vm_memory::{GuestAddress, GuestMemory};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     let res = gm.write_at_addr(&[1,2,3,4,5], GuestAddress(0x200)).map_err(|_| ())?;
    ///     assert_eq!(5, res);
    ///     Ok(())
    /// # }
    /// ```
    pub fn write_at_addr(&self, buf: &[u8], guest_addr: GuestAddress) -> Result<usize> {
        let (mapping, offset, _) = self.find_region(guest_addr)?;
        mapping
            .write_slice(buf, offset)
            .map_err(|e| Error::MemoryAccess(guest_addr, e))
    }

    /// Writes the entire contents of a slice to guest memory at the specified
    /// guest address.
    ///
    /// Returns an error if there isn't enough room in the memory region to
    /// complete the entire write. Part of the data may have been written
    /// nevertheless.
    ///
    /// # Examples
    ///
    /// ```
    /// use vm_memory::{guest_memory, GuestAddress, GuestMemory};
    ///
    /// fn test_write_all() -> guest_memory::Result<()> {
    ///     let ranges = &[(GuestAddress(0x1000), 0x400)];
    ///     let gm = GuestMemory::new(ranges)?;
    ///     gm.write_all_at_addr(b"zyxwvut", GuestAddress(0x1200))
    /// }
    /// ```
    pub fn write_all_at_addr(&self, buf: &[u8], guest_addr: GuestAddress) -> Result<()> {
        let expected = buf.len();
        let completed = self.write_at_addr(buf, guest_addr)?;
        if expected == completed {
            Ok(())
        } else {
            Err(Error::ShortWrite {
                expected,
                completed,
            })
        }
    }

    /// Reads to a slice from guest memory at the specified guest address.
    /// Returns the number of bytes read.  The number of bytes read can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Read a slice of length 16 at guestaddress 0x200.
    ///
    /// ```
    /// # use base::MemoryMapping;
    /// # use vm_memory::{GuestAddress, GuestMemory};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     let buf = &mut [0u8; 16];
    ///     let res = gm.read_at_addr(buf, GuestAddress(0x200)).map_err(|_| ())?;
    ///     assert_eq!(16, res);
    ///     Ok(())
    /// # }
    /// ```
    pub fn read_at_addr(&self, buf: &mut [u8], guest_addr: GuestAddress) -> Result<usize> {
        let (mapping, offset, _) = self.find_region(guest_addr)?;
        mapping
            .read_slice(buf, offset)
            .map_err(|e| Error::MemoryAccess(guest_addr, e))
    }

    /// Reads from guest memory at the specified address to fill the entire
    /// buffer.
    ///
    /// Returns an error if there isn't enough room in the memory region to fill
    /// the entire buffer. Part of the buffer may have been filled nevertheless.
    ///
    /// # Examples
    ///
    /// ```
    /// use vm_memory::{guest_memory, GuestAddress, GuestMemory};
    ///
    /// fn test_read_exact() -> guest_memory::Result<()> {
    ///     let ranges = &[(GuestAddress(0x1000), 0x400)];
    ///     let gm = GuestMemory::new(ranges)?;
    ///     let mut buffer = [0u8; 0x200];
    ///     gm.read_exact_at_addr(&mut buffer, GuestAddress(0x1200))
    /// }
    /// ```
    pub fn read_exact_at_addr(&self, buf: &mut [u8], guest_addr: GuestAddress) -> Result<()> {
        let expected = buf.len();
        let completed = self.read_at_addr(buf, guest_addr)?;
        if expected == completed {
            Ok(())
        } else {
            Err(Error::ShortRead {
                expected,
                completed,
            })
        }
    }

    /// Reads an object from guest memory at the given guest address.
    ///
    /// # Examples
    /// * Read a u64 from two areas of guest memory backed by separate mappings.
    ///
    /// ```
    /// # use vm_memory::{GuestAddress, GuestMemory};
    /// # fn test_read_u64() -> Result<u64, ()> {
    /// #     let start_addr1 = GuestAddress(0x0);
    /// #     let start_addr2 = GuestAddress(0x400);
    /// #     let mut gm = GuestMemory::new(&vec![(start_addr1, 0x400), (start_addr2, 0x400)])
    /// #         .map_err(|_| ())?;
    ///       let num1: u64 = gm.read_obj_from_addr(GuestAddress(32)).map_err(|_| ())?;
    ///       let num2: u64 = gm.read_obj_from_addr(GuestAddress(0x400+32)).map_err(|_| ())?;
    /// #     Ok(num1 + num2)
    /// # }
    /// ```
    pub fn read_obj_from_addr<T: FromBytes>(&self, guest_addr: GuestAddress) -> Result<T> {
        let (mapping, offset, _) = self.find_region(guest_addr)?;
        mapping
            .read_obj(offset)
            .map_err(|e| Error::MemoryAccess(guest_addr, e))
    }

    /// Reads an object from guest memory at the given guest address.
    /// Reading from a volatile area isn't strictly safe as it could change
    /// mid-read.  However, as long as the type T is plain old data and can
    /// handle random initialization, everything will be OK.
    ///
    /// The read operation will be volatile, i.e. it will not be reordered by
    /// the compiler and is suitable for I/O, but must be aligned. When reading
    /// from regular memory, prefer [`GuestMemory::read_obj_from_addr`].
    ///
    /// # Examples
    /// * Read a u64 from two areas of guest memory backed by separate mappings.
    ///
    /// ```
    /// # use vm_memory::{GuestAddress, GuestMemory};
    /// # fn test_read_u64() -> Result<u64, ()> {
    /// #     let start_addr1 = GuestAddress(0x0);
    /// #     let start_addr2 = GuestAddress(0x400);
    /// #     let mut gm = GuestMemory::new(&vec![(start_addr1, 0x400), (start_addr2, 0x400)])
    /// #         .map_err(|_| ())?;
    ///       let num1: u64 = gm.read_obj_from_addr_volatile(GuestAddress(32)).map_err(|_| ())?;
    ///       let num2: u64 = gm.read_obj_from_addr_volatile(GuestAddress(0x400+32)).map_err(|_| ())?;
    /// #     Ok(num1 + num2)
    /// # }
    /// ```
    pub fn read_obj_from_addr_volatile<T: FromBytes>(&self, guest_addr: GuestAddress) -> Result<T> {
        let (mapping, offset, _) = self.find_region(guest_addr)?;
        mapping
            .read_obj_volatile(offset)
            .map_err(|e| Error::MemoryAccess(guest_addr, e))
    }

    /// Writes an object to the memory region at the specified guest address.
    /// Returns Ok(()) if the object fits, or Err if it extends past the end.
    ///
    /// # Examples
    /// * Write a u64 at guest address 0x1100.
    ///
    /// ```
    /// # use vm_memory::{GuestAddress, GuestMemory};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     gm.write_obj_at_addr(55u64, GuestAddress(0x1100))
    ///         .map_err(|_| ())
    /// # }
    /// ```
    pub fn write_obj_at_addr<T: IntoBytes + Immutable>(
        &self,
        val: T,
        guest_addr: GuestAddress,
    ) -> Result<()> {
        let (mapping, offset, _) = self.find_region(guest_addr)?;
        mapping
            .write_obj(val, offset)
            .map_err(|e| Error::MemoryAccess(guest_addr, e))
    }

    /// Writes an object to the memory region at the specified guest address.
    /// Returns Ok(()) if the object fits, or Err if it extends past the end.
    ///
    /// The write operation will be volatile, i.e. it will not be reordered by
    /// the compiler and is suitable for I/O, but must be aligned. When writing
    /// to regular memory, prefer [`GuestMemory::write_obj_at_addr`].
    /// # Examples
    /// * Write a u64 at guest address 0x1100.
    ///
    /// ```
    /// # use vm_memory::{GuestAddress, GuestMemory};
    /// # fn test_write_u64() -> Result<(), ()> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)]).map_err(|_| ())?;
    ///     gm.write_obj_at_addr_volatile(55u64, GuestAddress(0x1100))
    ///         .map_err(|_| ())
    /// # }
    /// ```
    pub fn write_obj_at_addr_volatile<T: IntoBytes + Immutable>(
        &self,
        val: T,
        guest_addr: GuestAddress,
    ) -> Result<()> {
        let (mapping, offset, _) = self.find_region(guest_addr)?;
        mapping
            .write_obj_volatile(val, offset)
            .map_err(|e| Error::MemoryAccess(guest_addr, e))
    }

    /// Returns a `VolatileSlice` of `len` bytes starting at `addr`. Returns an error if the slice
    /// is not a subset of this `GuestMemory`.
    ///
    /// # Examples
    /// * Write `99` to 30 bytes starting at guest address 0x1010.
    ///
    /// ```
    /// # use base::MemoryMapping;
    /// # use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError};
    /// # fn test_volatile_slice() -> Result<(), GuestMemoryError> {
    /// #   let start_addr = GuestAddress(0x1000);
    /// #   let mut gm = GuestMemory::new(&vec![(start_addr, 0x400)])?;
    ///     let vslice = gm.get_slice_at_addr(GuestAddress(0x1010), 30)?;
    ///     vslice.write_bytes(99);
    /// #   Ok(())
    /// # }
    /// ```
    pub fn get_slice_at_addr(&self, addr: GuestAddress, len: usize) -> Result<VolatileSlice> {
        self.regions
            .iter()
            .find(|region| region.contains(addr))
            .ok_or(Error::InvalidGuestAddress(addr))
            .and_then(|region| {
                // The cast to a usize is safe here because we know that `region.contains(addr)` and
                // it's not possible for a memory region to be larger than what fits in a usize.
                region
                    .mapping
                    .get_slice(addr.offset_from(region.start()) as usize, len)
                    .map_err(Error::VolatileMemoryAccess)
            })
    }
    /// Convert a GuestAddress into a pointer in the address space of this
    /// process. This should only be necessary for giving addresses to the
    /// kernel, as with vhost ioctls. Normal reads/writes to guest memory should
    /// be done through `write_obj_at_addr`, `read_obj_from_addr`, etc.
    ///
    /// # Arguments
    /// * `guest_addr` - Guest address to convert.
    ///
    /// # Examples
    ///
    /// ```
    /// # use vm_memory::{GuestAddress, GuestMemory};
    /// # fn test_host_addr() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemory::new(&vec![(start_addr, 0x500)]).map_err(|_| ())?;
    ///     let addr = gm.get_host_address(GuestAddress(0x1200)).unwrap();
    ///     println!("Host address is {:p}", addr);
    ///     Ok(())
    /// # }
    /// ```
    pub fn get_host_address(&self, guest_addr: GuestAddress) -> Result<*const u8> {
        let (mapping, offset, _) = self.find_region(guest_addr)?;
        Ok(
            // SAFETY:
            // This is safe; `find_region` already checks that offset is in
            // bounds.
            unsafe { mapping.as_ptr().add(offset) } as *const u8,
        )
    }

    /// Convert a GuestAddress into a pointer in the address space of this
    /// process, and verify that the provided size define a valid range within
    /// a single memory region. Similar to get_host_address(), this should only
    /// be used for giving addresses to the kernel.
    ///
    /// # Arguments
    /// * `guest_addr` - Guest address to convert.
    /// * `size` - Size of the address range to be converted.
    ///
    /// # Examples
    ///
    /// ```
    /// # use vm_memory::{GuestAddress, GuestMemory};
    /// # fn test_host_addr() -> Result<(), ()> {
    ///     let start_addr = GuestAddress(0x1000);
    ///     let mut gm = GuestMemory::new(&vec![(start_addr, 0x500)]).map_err(|_| ())?;
    ///     let addr = gm.get_host_address_range(GuestAddress(0x1200), 0x200).unwrap();
    ///     println!("Host address is {:p}", addr);
    ///     Ok(())
    /// # }
    /// ```
    pub fn get_host_address_range(
        &self,
        guest_addr: GuestAddress,
        size: usize,
    ) -> Result<*const u8> {
        if size == 0 {
            return Err(Error::InvalidSize(size));
        }

        // Assume no overlap among regions
        let (mapping, offset, _) = self.find_region(guest_addr)?;

        if mapping
            .size()
            .checked_sub(offset)
            .map_or(true, |v| v < size)
        {
            return Err(Error::InvalidGuestAddress(guest_addr));
        }

        Ok(
            //SAFETY:
            // This is safe; `find_region` already checks that offset is in
            // bounds.
            unsafe { mapping.as_ptr().add(offset) } as *const u8,
        )
    }

    /// Returns a reference to the region that backs the given address.
    pub fn shm_region(
        &self,
        guest_addr: GuestAddress,
    ) -> Result<&(dyn AsRawDescriptor + Send + Sync)> {
        self.regions
            .iter()
            .find(|region| region.contains(guest_addr))
            .ok_or(Error::InvalidGuestAddress(guest_addr))
            .map(|region| region.shared_obj.as_ref())
    }

    /// Returns the region that contains the memory at `offset` from the base of guest memory.
    pub fn offset_region(&self, offset: u64) -> Result<&(dyn AsRawDescriptor + Send + Sync)> {
        self.shm_region(
            self.checked_offset(self.regions[0].guest_base, offset)
                .ok_or(Error::InvalidOffset(offset))?,
        )
    }

    /// Loops over all guest memory regions of `self`, and returns the
    /// target region that contains `guest_addr`. On success, this
    /// function returns a tuple with the following fields:
    ///
    /// (i) the memory mapping associated with the target region.
    /// (ii) the relative offset from the start of the target region to `guest_addr`.
    /// (iii) the absolute offset from the start of the backing object to the target region.
    ///
    /// If no target region is found, an error is returned.
    pub fn find_region(&self, guest_addr: GuestAddress) -> Result<(&MemoryMapping, usize, u64)> {
        self.regions
            .iter()
            .find(|region| region.contains(guest_addr))
            .ok_or(Error::InvalidGuestAddress(guest_addr))
            .map(|region| {
                (
                    &region.mapping,
                    guest_addr.offset_from(region.start()) as usize,
                    region.obj_offset,
                )
            })
    }

    /// Convert a GuestAddress into an offset within the associated shm region.
    ///
    /// A `GuestMemory` may have multiple backing objects and the offset is
    /// only meaningful in relation to the associated backing object, so a
    /// reference to it is included in the return value.
    ///
    /// Due to potential gaps within GuestMemory, it is helpful to know the
    /// offset within the shm where a given address is found. This offset
    /// can then be passed to another process mapping the shm to read data
    /// starting at that address.
    ///
    /// # Arguments
    /// * `guest_addr` - Guest address to convert.
    ///
    /// # Examples
    ///
    /// ```
    /// # use vm_memory::{GuestAddress, GuestMemory};
    /// let addr_a = GuestAddress(0x10000);
    /// let addr_b = GuestAddress(0x80000);
    /// let mut gm = GuestMemory::new(&vec![
    ///     (addr_a, 0x20000),
    ///     (addr_b, 0x30000)]).expect("failed to create GuestMemory");
    /// let (_backing_object, offset) = gm.offset_from_base(GuestAddress(0x95000))
    ///                .expect("failed to get offset");
    /// assert_eq!(offset, 0x35000);
    /// ```
    pub fn offset_from_base(
        &self,
        guest_addr: GuestAddress,
    ) -> Result<(&(dyn AsRawDescriptor + Send + Sync), u64)> {
        self.regions
            .iter()
            .find(|region| region.contains(guest_addr))
            .ok_or(Error::InvalidGuestAddress(guest_addr))
            .map(|region| {
                (
                    region.shared_obj.as_ref(),
                    region.obj_offset + guest_addr.offset_from(region.start()),
                )
            })
    }

    /// Copy all guest memory into `w`.
    ///
    /// # Safety
    /// Must have exclusive access to the guest memory for the duration of the
    /// call (e.g. all vCPUs and devices must be stopped).
    ///
    /// Returns a JSON object that contains metadata about the underlying memory regions to allow
    /// validation checks at restore time.
    #[deny(unsafe_op_in_unsafe_fn)]
    pub unsafe fn snapshot<T: Write>(
        &self,
        w: &mut T,
        compress: bool,
    ) -> anyhow::Result<AnySnapshot> {
        fn go(
            this: &GuestMemory,
            w: &mut impl Write,
        ) -> anyhow::Result<Vec<MemoryRegionSnapshotMetadata>> {
            let mut regions = Vec::new();
            for region in this.regions.iter() {
                let data_ranges = region
                    .find_data_ranges()
                    .context("find_data_ranges failed")?;
                for range in &data_ranges {
                    let region_vslice = region
                        .mapping
                        .get_slice(range.start, range.end - range.start)?;
                    // SAFETY:
                    // 1. The data is guaranteed to be present & of expected length by the
                    //    `VolatileSlice`.
                    // 2. Aliasing the `VolatileSlice`'s memory is safe because a. The only mutable
                    //    reference to it is held by the guest, and the guest's VCPUs are stopped
                    //    (guaranteed by caller), so that mutable reference can be ignored (aliasing
                    //    is only an issue if temporal overlap occurs, and it does not here). b.
                    //    Some host code does manipulate guest memory through raw pointers. This
                    //    aliases the underlying memory of the slice, so we must ensure that host
                    //    code is not running (the caller guarantees this).
                    w.write_all(unsafe {
                        std::slice::from_raw_parts(region_vslice.as_ptr(), region_vslice.size())
                    })?;
                }
                regions.push(MemoryRegionSnapshotMetadata {
                    guest_base: region.guest_base.0,
                    size: region.mapping.size(),
                    data_ranges,
                });
            }
            Ok(regions)
        }

        let regions = if compress {
            let mut w = lz4_flex::frame::FrameEncoder::new(w);
            let regions = go(self, &mut w)?;
            w.finish()?;
            regions
        } else {
            go(self, w)?
        };

        AnySnapshot::to_any(MemorySnapshotMetadata {
            regions,
            compressed: compress,
        })
    }

    /// Restore the guest memory using the bytes from `r`.
    ///
    /// # Safety
    /// Must have exclusive access to the guest memory for the duration of the
    /// call (e.g. all vCPUs and devices must be stopped).
    ///
    /// Returns an error if `metadata` doesn't match the configuration of the `GuestMemory` or if
    /// `r` doesn't produce exactly as many bytes as needed.
    #[deny(unsafe_op_in_unsafe_fn)]
    pub unsafe fn restore<T: Read>(&self, metadata: AnySnapshot, r: &mut T) -> anyhow::Result<()> {
        let metadata: MemorySnapshotMetadata = AnySnapshot::from_any(metadata)?;

        let mut r: Box<dyn Read> = if metadata.compressed {
            Box::new(lz4_flex::frame::FrameDecoder::new(r))
        } else {
            Box::new(r)
        };

        if self.regions.len() != metadata.regions.len() {
            bail!(
                "snapshot expected {} memory regions but VM has {}",
                metadata.regions.len(),
                self.regions.len()
            );
        }
        for (region, metadata) in self.regions.iter().zip(metadata.regions.iter()) {
            let MemoryRegionSnapshotMetadata {
                guest_base,
                size,
                data_ranges,
            } = metadata;
            if region.guest_base.0 != *guest_base || region.mapping.size() != *size {
                bail!("snapshot memory regions don't match VM memory regions");
            }

            let mut prev_end = 0;
            for range in data_ranges {
                let hole_size = range
                    .start
                    .checked_sub(prev_end)
                    .context("invalid data range")?;
                if hole_size > 0 {
                    region.zero_range(prev_end, hole_size)?;
                }
                let region_vslice = region
                    .mapping
                    .get_slice(range.start, range.end - range.start)?;

                // SAFETY:
                // See `Self::snapshot` for the detailed safety statement, and
                // note that both mutable and non-mutable aliasing is safe.
                r.read_exact(unsafe {
                    std::slice::from_raw_parts_mut(region_vslice.as_mut_ptr(), region_vslice.size())
                })?;

                prev_end = range.end;
            }
            let hole_size = region
                .mapping
                .size()
                .checked_sub(prev_end)
                .context("invalid data range")?;
            if hole_size > 0 {
                region.zero_range(prev_end, hole_size)?;
            }
        }

        // Should always be at EOF at this point.
        let mut buf = [0];
        if r.read(&mut buf)? != 0 {
            bail!("too many bytes");
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct MemorySnapshotMetadata {
    regions: Vec<MemoryRegionSnapshotMetadata>,
    compressed: bool,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct MemoryRegionSnapshotMetadata {
    guest_base: u64,
    size: usize,
    // Ranges of the mmap that are stored in the snapshot file. All other ranges of the region are
    // zeros.
    data_ranges: Vec<std::ops::Range<usize>>,
}

// SAFETY:
// It is safe to implement BackingMemory because GuestMemory can be mutated any time already.
unsafe impl BackingMemory for GuestMemory {
    fn get_volatile_slice(
        &self,
        mem_range: cros_async::MemRegion,
    ) -> mem::Result<VolatileSlice<'_>> {
        self.get_slice_at_addr(GuestAddress(mem_range.offset), mem_range.len)
            .map_err(|_| mem::Error::InvalidOffset(mem_range.offset, mem_range.len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alignment() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x10000);

        assert!(GuestMemory::new(&[(start_addr1, 0x100), (start_addr2, 0x400)]).is_err());
        assert!(GuestMemory::new(&[(start_addr1, 0x10000), (start_addr2, 0x10000)]).is_ok());
    }

    #[test]
    fn two_regions() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x10000);
        // The memory regions are `[0x0, 0x10000)`, `[0x10000, 0x20000)`.
        let gm = GuestMemory::new(&[(start_addr1, 0x10000), (start_addr2, 0x10000)]).unwrap();

        // Although each address in `[0x0, 0x20000)` is valid, `is_valid_range()` returns false for
        // a range that is across multiple underlying regions.
        assert!(gm.is_valid_range(GuestAddress(0x5000), 0x5000));
        assert!(gm.is_valid_range(GuestAddress(0x10000), 0x5000));
        assert!(!gm.is_valid_range(GuestAddress(0x5000), 0x10000));
    }

    #[test]
    fn overlap_memory() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x10000);
        assert!(GuestMemory::new(&[(start_addr1, 0x20000), (start_addr2, 0x20000)]).is_err());
    }

    #[test]
    fn region_hole() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x40000);
        // The memory regions are `[0x0, 0x20000)`, `[0x40000, 0x60000)`.
        let gm = GuestMemory::new(&[(start_addr1, 0x20000), (start_addr2, 0x20000)]).unwrap();

        assert!(gm.address_in_range(GuestAddress(0x10000)));
        assert!(!gm.address_in_range(GuestAddress(0x30000)));
        assert!(gm.address_in_range(GuestAddress(0x50000)));
        assert!(!gm.address_in_range(GuestAddress(0x60000)));
        assert!(!gm.address_in_range(GuestAddress(0x60000)));
        assert!(gm.range_overlap(GuestAddress(0x10000), GuestAddress(0x30000)),);
        assert!(!gm.range_overlap(GuestAddress(0x30000), GuestAddress(0x40000)),);
        assert!(gm.range_overlap(GuestAddress(0x30000), GuestAddress(0x70000)),);
        assert_eq!(gm.checked_offset(GuestAddress(0x10000), 0x10000), None);
        assert_eq!(
            gm.checked_offset(GuestAddress(0x50000), 0x8000),
            Some(GuestAddress(0x58000))
        );
        assert_eq!(gm.checked_offset(GuestAddress(0x50000), 0x10000), None);
        assert!(gm.is_valid_range(GuestAddress(0x0), 0x10000));
        assert!(gm.is_valid_range(GuestAddress(0x0), 0x20000));
        assert!(!gm.is_valid_range(GuestAddress(0x0), 0x20000 + 1));

        // While `checked_offset(GuestAddress(0x10000), 0x40000)` succeeds because 0x50000 is a
        // valid address, `is_valid_range(GuestAddress(0x10000), 0x40000)` returns `false`
        // because there is a hole inside of [0x10000, 0x50000).
        assert_eq!(
            gm.checked_offset(GuestAddress(0x10000), 0x40000),
            Some(GuestAddress(0x50000))
        );
        assert!(!gm.is_valid_range(GuestAddress(0x10000), 0x40000));
    }

    #[test]
    fn test_read_u64() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x10000);
        let gm = GuestMemory::new(&[(start_addr1, 0x10000), (start_addr2, 0x10000)]).unwrap();

        let val1: u64 = 0xaa55aa55aa55aa55;
        let val2: u64 = 0x55aa55aa55aa55aa;
        gm.write_obj_at_addr(val1, GuestAddress(0x500)).unwrap();
        gm.write_obj_at_addr(val2, GuestAddress(0x10000 + 32))
            .unwrap();
        let num1: u64 = gm.read_obj_from_addr(GuestAddress(0x500)).unwrap();
        let num2: u64 = gm.read_obj_from_addr(GuestAddress(0x10000 + 32)).unwrap();
        assert_eq!(val1, num1);
        assert_eq!(val2, num2);
    }

    #[test]
    fn test_memory_size() {
        let start_region1 = GuestAddress(0x0);
        let size_region1 = 0x10000;
        let start_region2 = GuestAddress(0x10000);
        let size_region2 = 0x20000;
        let gm = GuestMemory::new(&[(start_region1, size_region1), (start_region2, size_region2)])
            .unwrap();

        let mem_size = gm.memory_size();
        assert_eq!(mem_size, size_region1 + size_region2);
    }

    // Get the base address of the mapping for a GuestAddress.
    fn get_mapping(mem: &GuestMemory, addr: GuestAddress) -> Result<*const u8> {
        Ok(mem.find_region(addr)?.0.as_ptr() as *const u8)
    }

    #[test]
    fn guest_to_host() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x10000);
        let mem = GuestMemory::new(&[(start_addr1, 0x10000), (start_addr2, 0x40000)]).unwrap();

        // Verify the host addresses match what we expect from the mappings.
        let addr1_base = get_mapping(&mem, start_addr1).unwrap();
        let addr2_base = get_mapping(&mem, start_addr2).unwrap();
        let host_addr1 = mem.get_host_address(start_addr1).unwrap();
        let host_addr2 = mem.get_host_address(start_addr2).unwrap();
        assert_eq!(host_addr1, addr1_base);
        assert_eq!(host_addr2, addr2_base);

        // Check that a bad address returns an error.
        let bad_addr = GuestAddress(0x123456);
        assert!(mem.get_host_address(bad_addr).is_err());
    }

    #[test]
    fn guest_to_host_range() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x10000);
        let mem = GuestMemory::new(&[(start_addr1, 0x10000), (start_addr2, 0x40000)]).unwrap();

        // Verify the host addresses match what we expect from the mappings.
        let addr1_base = get_mapping(&mem, start_addr1).unwrap();
        let addr2_base = get_mapping(&mem, start_addr2).unwrap();
        let host_addr1 = mem.get_host_address_range(start_addr1, 0x10000).unwrap();
        let host_addr2 = mem.get_host_address_range(start_addr2, 0x10000).unwrap();
        assert_eq!(host_addr1, addr1_base);
        assert_eq!(host_addr2, addr2_base);

        let host_addr3 = mem.get_host_address_range(start_addr2, 0x20000).unwrap();
        assert_eq!(host_addr3, addr2_base);

        // Check that a valid guest address with an invalid size returns an error.
        assert!(mem.get_host_address_range(start_addr1, 0x20000).is_err());

        // Check that a bad address returns an error.
        let bad_addr = GuestAddress(0x123456);
        assert!(mem.get_host_address_range(bad_addr, 0x10000).is_err());
    }

    #[test]
    fn shm_offset() {
        let start_region1 = GuestAddress(0x0);
        let size_region1 = 0x10000;
        let start_region2 = GuestAddress(0x10000);
        let size_region2 = 0x20000;
        let gm = GuestMemory::new(&[(start_region1, size_region1), (start_region2, size_region2)])
            .unwrap();

        gm.write_obj_at_addr(0x1337u16, GuestAddress(0x0)).unwrap();
        gm.write_obj_at_addr(0x0420u16, GuestAddress(0x10000))
            .unwrap();

        for region in gm.regions() {
            let shm = match region.shm {
                BackingObject::Shm(s) => s,
                _ => {
                    panic!("backing object isn't SharedMemory");
                }
            };
            let mmap = MemoryMappingBuilder::new(region.size)
                .from_shared_memory(shm)
                .offset(region.shm_offset)
                .build()
                .unwrap();

            if region.index == 0 {
                assert!(mmap.read_obj::<u16>(0x0).unwrap() == 0x1337u16);
            }

            if region.index == 1 {
                assert!(mmap.read_obj::<u16>(0x0).unwrap() == 0x0420u16);
            }
        }
    }

    #[test]
    // Disabled for non-x86 because test infra uses qemu-user, which doesn't support MADV_REMOVE.
    #[cfg(target_arch = "x86_64")]
    fn snapshot_restore() {
        let regions = &[
            // Hole at start.
            (GuestAddress(0x0), 0x10000),
            // Hole at end.
            (GuestAddress(0x10000), 0x10000),
            // Hole in middle.
            (GuestAddress(0x20000), 0x10000),
            // All holes.
            (GuestAddress(0x30000), 0x10000),
            // No holes.
            (GuestAddress(0x40000), 0x1000),
        ];
        let writes = &[
            (GuestAddress(0x0FFF0), 1u64),
            (GuestAddress(0x10000), 2u64),
            (GuestAddress(0x29000), 3u64),
            (GuestAddress(0x40000), 4u64),
        ];

        let gm = GuestMemory::new(regions).unwrap();
        for &(addr, value) in writes {
            gm.write_obj_at_addr(value, addr).unwrap();
        }

        let mut data = tempfile::tempfile().unwrap();
        // SAFETY:
        // no vm is running
        let metadata_json = unsafe { gm.snapshot(&mut data, false).unwrap() };
        let metadata: MemorySnapshotMetadata =
            AnySnapshot::from_any(metadata_json.clone()).unwrap();

        #[cfg(unix)]
        assert_eq!(
            metadata,
            MemorySnapshotMetadata {
                regions: vec![
                    MemoryRegionSnapshotMetadata {
                        guest_base: 0,
                        size: 0x10000,
                        data_ranges: vec![0x0F000..0x10000],
                    },
                    MemoryRegionSnapshotMetadata {
                        guest_base: 0x10000,
                        size: 0x10000,
                        data_ranges: vec![0x00000..0x01000],
                    },
                    MemoryRegionSnapshotMetadata {
                        guest_base: 0x20000,
                        size: 0x10000,
                        data_ranges: vec![0x09000..0x0A000],
                    },
                    MemoryRegionSnapshotMetadata {
                        guest_base: 0x30000,
                        size: 0x10000,
                        data_ranges: vec![],
                    },
                    MemoryRegionSnapshotMetadata {
                        guest_base: 0x40000,
                        size: 0x1000,
                        data_ranges: vec![0x00000..0x01000],
                    }
                ],
                compressed: false,
            }
        );
        // We can't detect the holes on Windows yet.
        #[cfg(windows)]
        assert_eq!(
            metadata,
            MemorySnapshotMetadata {
                regions: vec![
                    MemoryRegionSnapshotMetadata {
                        guest_base: 0,
                        size: 0x10000,
                        data_ranges: vec![0x00000..0x10000],
                    },
                    MemoryRegionSnapshotMetadata {
                        guest_base: 0x10000,
                        size: 0x10000,
                        data_ranges: vec![0x00000..0x10000],
                    },
                    MemoryRegionSnapshotMetadata {
                        guest_base: 0x20000,
                        size: 0x10000,
                        data_ranges: vec![0x00000..0x10000],
                    },
                    MemoryRegionSnapshotMetadata {
                        guest_base: 0x30000,
                        size: 0x10000,
                        data_ranges: vec![0x00000..0x10000],
                    },
                    MemoryRegionSnapshotMetadata {
                        guest_base: 0x40000,
                        size: 0x1000,
                        data_ranges: vec![0x00000..0x01000],
                    }
                ],
                compressed: false,
            }
        );

        std::mem::drop(gm);

        let gm2 = GuestMemory::new(regions).unwrap();

        // Write to a hole so we can assert the restore zeroes it.
        let hole_addr = GuestAddress(0x30000);
        gm2.write_obj_at_addr(8u64, hole_addr).unwrap();

        use std::io::Seek;
        data.seek(std::io::SeekFrom::Start(0)).unwrap();
        // SAFETY:
        // no vm is running
        unsafe { gm2.restore(metadata_json, &mut data).unwrap() };

        assert_eq!(gm2.read_obj_from_addr::<u64>(hole_addr).unwrap(), 0);
        for &(addr, value) in writes {
            assert_eq!(gm2.read_obj_from_addr::<u64>(addr).unwrap(), value);
        }
    }
}
