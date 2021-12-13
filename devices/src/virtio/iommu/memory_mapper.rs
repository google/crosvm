// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! MemoryMapper trait and basic impl for virtio-iommu implementation
//!
//! All the addr/range ends in this file are exclusive.

use std::collections::BTreeMap;
use std::result;

use base::{error, AsRawDescriptors, RawDescriptor, TubeError};
use remain::sorted;
use thiserror::Error;
use vm_memory::{GuestAddress, GuestMemoryError};

use crate::vfio::VfioError;

#[repr(u8)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Permission {
    Read = 1,
    Write = 2,
    RW = 3,
}

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("address not aligned")]
    AddrNotAligned,
    #[error("address start ({0} is greater than or equal to end {1}")]
    AddrStartGeEnd(u64, u64),
    #[error("failed getting host address: {0}")]
    GetHostAddress(GuestMemoryError),
    #[error("integer overflow")]
    IntegerOverflow,
    #[error("invalid iova: {0}, length: {1}")]
    InvalidIOVA(u64, u64),
    #[error("iommu dma error")]
    IommuDma,
    #[error("iova partial overlap")]
    IovaPartialOverlap,
    #[error("size is zero")]
    SizeIsZero,
    #[error("source region overlap {0}")]
    SrcRegionOverlap(u64),
    #[error("tube error: {0}")]
    Tube(TubeError),
    #[error("unimplemented")]
    Unimplemented,
    #[error{"vfio error: {0}"}]
    Vfio(VfioError),
}

pub type Result<T> = result::Result<T, Error>;

/// Manages the mapping from a guest IO virtual address space to the guest physical address space
#[derive(Debug)]
pub struct MappingInfo {
    pub iova: u64,
    pub gpa: GuestAddress,
    pub size: u64,
    pub perm: Permission,
}

impl MappingInfo {
    #[allow(dead_code)]
    fn new(iova: u64, gpa: GuestAddress, size: u64, perm: Permission) -> Result<Self> {
        if size == 0 {
            return Err(Error::SizeIsZero);
        }
        iova.checked_add(size).ok_or(Error::IntegerOverflow)?;
        gpa.checked_add(size).ok_or(Error::IntegerOverflow)?;
        Ok(Self {
            iova,
            gpa,
            size,
            perm,
        })
    }
}

// A basic iommu. It is designed as a building block for virtio-iommu.
pub struct BasicMemoryMapper {
    maps: BTreeMap<u64, MappingInfo>, // key = MappingInfo.iova
    mask: u64,
}

/// A generic interface for vfio and other iommu backends
pub trait MemoryMapper: Send {
    fn add_map(&mut self, new_map: MappingInfo) -> Result<()>;
    fn remove_map(&mut self, iova_start: u64, size: u64) -> Result<()>;
    fn get_mask(&self) -> Result<u64>;
    fn translate(&self, iova: u64, size: u64) -> Result<GuestAddress>;
}

pub trait MemoryMapperDescriptors: MemoryMapper + AsRawDescriptors {}
impl<T: MemoryMapper + AsRawDescriptors> MemoryMapperDescriptors for T {}

impl BasicMemoryMapper {
    pub fn new(mask: u64) -> BasicMemoryMapper {
        BasicMemoryMapper {
            maps: BTreeMap::new(),
            mask,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.maps.len()
    }
}

impl MemoryMapper for BasicMemoryMapper {
    fn add_map(&mut self, new_map: MappingInfo) -> Result<()> {
        let new_iova_end = new_map
            .iova
            .checked_add(new_map.size)
            .ok_or(Error::IntegerOverflow)?;
        let mut iter = self.maps.range(..new_iova_end);
        if let Some((_, map)) = iter.next_back() {
            if map.iova + map.size > new_map.iova {
                return Err(Error::SrcRegionOverlap(new_map.iova));
            }
        }
        self.maps.insert(new_map.iova, new_map);
        Ok(())
    }

    fn remove_map(&mut self, iova_start: u64, size: u64) -> Result<()> {
        // From the virtio-iommu spec
        //
        // If a mapping affected by the range is not covered in its entirety by the
        // range (the UNMAP request would split the mapping), then the device SHOULD
        // set the request \field{status} to VIRTIO_IOMMU_S_RANGE, and SHOULD NOT
        // remove any mapping.
        //
        // Therefore, this func checks for partial overlap first before removing the maps.
        let iova_end = iova_start.checked_add(size).ok_or(Error::IntegerOverflow)?;

        let mut to_be_removed = Vec::new();
        for (key, map) in self.maps.range(..iova_end).rev() {
            let map_iova_end = map.iova + map.size;
            if map_iova_end <= iova_start {
                // no overlap
                break;
            }
            if iova_start <= map.iova && map_iova_end <= iova_end {
                to_be_removed.push(*key);
            } else {
                return Err(Error::IovaPartialOverlap);
            }
        }
        for key in to_be_removed {
            self.maps.remove(&key).expect("map should contain key");
        }
        Ok(())
    }

    fn get_mask(&self) -> Result<u64> {
        Ok(self.mask)
    }

    // Mappings of contiguous iovas and gpas are considered as 1 map.
    fn translate(&self, iova: u64, size: u64) -> Result<GuestAddress> {
        let iova_end = iova.checked_add(size).ok_or(Error::IntegerOverflow)?;
        let mut iter = self.maps.range(..iova_end);
        let map = iter.next_back().ok_or(Error::InvalidIOVA(iova, size))?.1;
        if iova_end > map.iova + map.size {
            return Err(Error::InvalidIOVA(iova, size));
        }
        if iova >= map.iova {
            return map
                .gpa
                .checked_add(iova - map.iova)
                .ok_or(Error::IntegerOverflow);
        }
        // iova < map.iova
        let mut last_map_iova = map.iova;
        let mut last_map_gpa = map.gpa;
        while let Some((_, map)) = iter.next_back() {
            if map.iova + map.size != last_map_iova
                || map
                    .gpa
                    .checked_add(map.size)
                    .ok_or(Error::IntegerOverflow)?
                    != last_map_gpa
            {
                // Discontiguous iova and/or gpa
                return Err(Error::InvalidIOVA(iova, size));
            }
            if iova >= map.iova {
                // Contiguous iova and gpa, spanned across multiple mappings
                return map
                    .gpa
                    .checked_add(iova - map.iova)
                    .ok_or(Error::IntegerOverflow);
            }
            last_map_iova = map.iova;
            last_map_gpa = map.gpa;
        }

        Err(Error::InvalidIOVA(iova, size))
    }
}

impl AsRawDescriptors for BasicMemoryMapper {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_overlap() {
        let mut mapper = BasicMemoryMapper::new(u64::MAX);
        mapper
            .add_map(MappingInfo::new(10, GuestAddress(1000), 10, Permission::RW).unwrap())
            .unwrap();
        mapper
            .add_map(MappingInfo::new(14, GuestAddress(1000), 1, Permission::RW).unwrap())
            .unwrap_err();
        mapper
            .add_map(MappingInfo::new(0, GuestAddress(1000), 12, Permission::RW).unwrap())
            .unwrap_err();
        mapper
            .add_map(MappingInfo::new(16, GuestAddress(1000), 6, Permission::RW).unwrap())
            .unwrap_err();
        mapper
            .add_map(MappingInfo::new(5, GuestAddress(1000), 20, Permission::RW).unwrap())
            .unwrap_err();
    }

    #[test]
    // This test is taken from the virtio_iommu spec with translate() calls added
    fn test_map_unmap() {
        // #1
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            mapper.remove_map(0, 4).unwrap();
        }
        // #2
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            mapper
                .add_map(MappingInfo::new(0, GuestAddress(1000), 9, Permission::RW).unwrap())
                .unwrap();
            assert_eq!(mapper.translate(0, 1).unwrap(), GuestAddress(1000));
            assert_eq!(mapper.translate(8, 1).unwrap(), GuestAddress(1008));
            mapper.translate(9, 1).unwrap_err();
            mapper.remove_map(0, 9).unwrap();
            mapper.translate(0, 1).unwrap_err();
        }
        // #3
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            mapper
                .add_map(MappingInfo::new(0, GuestAddress(1000), 4, Permission::RW).unwrap())
                .unwrap();
            mapper
                .add_map(MappingInfo::new(5, GuestAddress(50), 4, Permission::RW).unwrap())
                .unwrap();
            assert_eq!(mapper.translate(0, 1).unwrap(), GuestAddress(1000));
            assert_eq!(mapper.translate(6, 1).unwrap(), GuestAddress(51));
            mapper.remove_map(0, 9).unwrap();
            mapper.translate(0, 1).unwrap_err();
            mapper.translate(6, 1).unwrap_err();
        }
        // #4
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            mapper
                .add_map(MappingInfo::new(0, GuestAddress(1000), 9, Permission::RW).unwrap())
                .unwrap();
            mapper.remove_map(0, 4).unwrap_err();
            assert_eq!(mapper.translate(5, 1).unwrap(), GuestAddress(1005));
        }
        // #5
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            mapper
                .add_map(MappingInfo::new(0, GuestAddress(1000), 4, Permission::RW).unwrap())
                .unwrap();
            mapper
                .add_map(MappingInfo::new(5, GuestAddress(50), 4, Permission::RW).unwrap())
                .unwrap();
            assert_eq!(mapper.translate(0, 1).unwrap(), GuestAddress(1000));
            assert_eq!(mapper.translate(5, 1).unwrap(), GuestAddress(50));
            mapper.remove_map(0, 4).unwrap();
            mapper.translate(0, 1).unwrap_err();
            mapper.translate(4, 1).unwrap_err();
            assert_eq!(mapper.translate(5, 1).unwrap(), GuestAddress(50));
        }
        // #6
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            mapper
                .add_map(MappingInfo::new(0, GuestAddress(1000), 4, Permission::RW).unwrap())
                .unwrap();
            assert_eq!(mapper.translate(0, 1).unwrap(), GuestAddress(1000));
            mapper.translate(9, 1).unwrap_err();
            mapper.remove_map(0, 9).unwrap();
            mapper.translate(0, 1).unwrap_err();
            mapper.translate(9, 1).unwrap_err();
        }
        // #7
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            mapper
                .add_map(MappingInfo::new(0, GuestAddress(1000), 4, Permission::Read).unwrap())
                .unwrap();
            mapper
                .add_map(MappingInfo::new(10, GuestAddress(50), 4, Permission::RW).unwrap())
                .unwrap();
            assert_eq!(mapper.translate(0, 1).unwrap(), GuestAddress(1000));
            assert_eq!(mapper.translate(3, 1).unwrap(), GuestAddress(1003));
            mapper.translate(4, 1).unwrap_err();
            assert_eq!(mapper.translate(10, 1).unwrap(), GuestAddress(50));
            assert_eq!(mapper.translate(13, 1).unwrap(), GuestAddress(53));
            mapper.remove_map(0, 14).unwrap();
            mapper.translate(0, 1).unwrap_err();
            mapper.translate(3, 1).unwrap_err();
            mapper.translate(4, 1).unwrap_err();
            mapper.translate(10, 1).unwrap_err();
            mapper.translate(13, 1).unwrap_err();
        }
    }
    #[test]
    fn test_remove_map() {
        let mut mapper = BasicMemoryMapper::new(u64::MAX);
        mapper
            .add_map(MappingInfo::new(1, GuestAddress(1000), 4, Permission::Read).unwrap())
            .unwrap();
        mapper
            .add_map(MappingInfo::new(5, GuestAddress(50), 4, Permission::RW).unwrap())
            .unwrap();
        mapper
            .add_map(MappingInfo::new(9, GuestAddress(50), 4, Permission::RW).unwrap())
            .unwrap();
        assert_eq!(mapper.len(), 3);
        mapper.remove_map(0, 6).unwrap_err();
        assert_eq!(mapper.len(), 3);
        mapper.remove_map(1, 5).unwrap_err();
        assert_eq!(mapper.len(), 3);
        mapper.remove_map(1, 9).unwrap_err();
        assert_eq!(mapper.len(), 3);
        mapper.remove_map(6, 4).unwrap_err();
        assert_eq!(mapper.len(), 3);
        mapper.remove_map(6, 14).unwrap_err();
        assert_eq!(mapper.len(), 3);
        mapper.remove_map(5, 4).unwrap();
        assert_eq!(mapper.len(), 2);
        mapper.remove_map(1, 9).unwrap_err();
        assert_eq!(mapper.len(), 2);
        mapper.remove_map(0, 15).unwrap();
        assert_eq!(mapper.len(), 0);
    }

    #[test]
    fn test_translate_len() {
        let mut mapper = BasicMemoryMapper::new(u64::MAX);
        // [1, 5) -> [1000, 1004)
        mapper
            .add_map(MappingInfo::new(1, GuestAddress(1000), 4, Permission::Read).unwrap())
            .unwrap();
        mapper.translate(1, 0).unwrap_err();
        assert_eq!(mapper.translate(1, 1).unwrap(), GuestAddress(1000));
        assert_eq!(mapper.translate(1, 2).unwrap(), GuestAddress(1000));
        assert_eq!(mapper.translate(1, 3).unwrap(), GuestAddress(1000));
        assert_eq!(mapper.translate(1, 4).unwrap(), GuestAddress(1000));
        mapper.translate(1, 5).unwrap_err();
        // [1, 9) -> [1000, 1008)
        mapper
            .add_map(MappingInfo::new(5, GuestAddress(1004), 4, Permission::Read).unwrap())
            .unwrap();
        // Spanned across 2 maps
        assert_eq!(mapper.translate(2, 5).unwrap(), GuestAddress(1001));
        assert_eq!(mapper.translate(2, 6).unwrap(), GuestAddress(1001));
        assert_eq!(mapper.translate(2, 7).unwrap(), GuestAddress(1001));
        mapper.translate(2, 8).unwrap_err();
        mapper.translate(3, 10).unwrap_err();
        // [1, 9) -> [1000, 1008), [11, 17) -> [1010, 1016)
        mapper
            .add_map(MappingInfo::new(11, GuestAddress(1010), 6, Permission::Read).unwrap())
            .unwrap();
        // Discontiguous iova
        mapper.translate(3, 10).unwrap_err();
        // [1, 17) -> [1000, 1016)
        mapper
            .add_map(MappingInfo::new(9, GuestAddress(1008), 2, Permission::Read).unwrap())
            .unwrap();
        // Spanned across 4 maps
        assert_eq!(mapper.translate(3, 10).unwrap(), GuestAddress(1002));
        assert_eq!(mapper.translate(1, 16).unwrap(), GuestAddress(1000));
        mapper.translate(1, 17).unwrap_err();
        mapper.translate(0, 16).unwrap_err();
        // [0, 1) -> [5, 6), [1, 17) -> [1000, 1016)
        mapper
            .add_map(MappingInfo::new(0, GuestAddress(5), 1, Permission::Read).unwrap())
            .unwrap();
        assert_eq!(mapper.translate(0, 1).unwrap(), GuestAddress(5));
        // Discontiguous gpa
        mapper.translate(0, 2).unwrap_err();
        mapper.translate(0, 16).unwrap_err();
        mapper.translate(0, 500).unwrap_err();
    }
}
