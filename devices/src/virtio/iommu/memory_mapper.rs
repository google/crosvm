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
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vm_memory::{GuestAddress, GuestMemoryError};

use crate::vfio::VfioError;
use crate::vfio_wrapper::VfioWrapper;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    Read = 1,
    Write = 2,
    RW = 3,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemRegion {
    pub gpa: GuestAddress,
    pub len: u64,
    pub perm: Permission,
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
    #[error("iova region overlap")]
    IovaRegionOverlap,
    #[error("size is zero")]
    SizeIsZero,
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

    /// Trait for generic MemoryMapper abstraction, that is, all reside on MemoryMapper and want to
    /// be converted back to its original type. Each must provide as_XXX_wrapper() +
    /// as_XXX_wrapper_mut() + into_XXX_wrapper(), default impl methods return None.
    fn as_vfio_wrapper(&self) -> Option<&VfioWrapper> {
        None
    }
    fn as_vfio_wrapper_mut(&mut self) -> Option<&mut VfioWrapper> {
        None
    }
    fn into_vfio_wrapper(self: Box<Self>) -> Option<Box<VfioWrapper>> {
        None
    }
}

pub trait Translate {
    /// Multiple MemRegions should be returned when the gpa is discontiguous or perms are different.
    fn translate(&self, iova: u64, size: u64) -> Result<Vec<MemRegion>>;
}

pub trait MemoryMapperTrait: MemoryMapper + Translate + AsRawDescriptors {}
impl<T: MemoryMapper + Translate + AsRawDescriptors> MemoryMapperTrait for T {}

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
        if new_map.size == 0 {
            return Err(Error::SizeIsZero);
        }
        let new_iova_end = new_map
            .iova
            .checked_add(new_map.size)
            .ok_or(Error::IntegerOverflow)?;
        new_map
            .gpa
            .checked_add(new_map.size)
            .ok_or(Error::IntegerOverflow)?;
        let mut iter = self.maps.range(..new_iova_end);
        if let Some((_, map)) = iter.next_back() {
            if map.iova + map.size > new_map.iova {
                return Err(Error::IovaRegionOverlap);
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
        if size == 0 {
            return Err(Error::SizeIsZero);
        }
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
}

impl Translate for BasicMemoryMapper {
    /// Regions of contiguous iovas and gpas, and identical permission are merged
    fn translate(&self, iova: u64, size: u64) -> Result<Vec<MemRegion>> {
        if size == 0 {
            return Err(Error::SizeIsZero);
        }
        let iova_end = iova.checked_add(size).ok_or(Error::IntegerOverflow)?;
        let mut iter = self.maps.range(..iova_end);
        let mut last_iova = iova_end;
        let mut regions: Vec<MemRegion> = Vec::new();
        while let Some((_, map)) = iter.next_back() {
            if last_iova > map.iova + map.size {
                break;
            }
            let mut new_region = true;

            // This is the last region to be inserted / first to be returned when iova >= map.iova
            let region_len = last_iova - std::cmp::max::<u64>(map.iova, iova);
            if let Some(last) = regions.last_mut() {
                if map.gpa.unchecked_add(map.size) == last.gpa && map.perm == last.perm {
                    last.gpa = map.gpa;
                    last.len += region_len;
                    new_region = false;
                }
            }
            if new_region {
                // If this is the only region to be returned, region_len == size (arg of this
                // function)
                // iova_end = iova + size
                // last_iova = iova_end
                // region_len = last_iova - max(map.iova, iova)
                //            = iova + size - iova
                //            = size
                regions.push(MemRegion {
                    gpa: map.gpa,
                    len: region_len,
                    perm: map.perm,
                });
            }
            if iova >= map.iova {
                regions.reverse();
                // The gpa of the first region has to be offseted
                regions[0].gpa = map
                    .gpa
                    .checked_add(iova - map.iova)
                    .ok_or(Error::IntegerOverflow)?;
                return Ok(regions);
            }
            last_iova = map.iova;
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
    use std::fmt::Debug;

    #[test]
    fn test_mapping_info() {
        // Overflow
        MappingInfo::new(u64::MAX - 1, GuestAddress(1), 2, Permission::Read).unwrap_err();
        MappingInfo::new(1, GuestAddress(u64::MAX - 1), 2, Permission::Read).unwrap_err();
        MappingInfo::new(u64::MAX, GuestAddress(1), 2, Permission::Read).unwrap_err();
        MappingInfo::new(1, GuestAddress(u64::MAX), 2, Permission::Read).unwrap_err();
        MappingInfo::new(5, GuestAddress(5), u64::MAX, Permission::Read).unwrap_err();
        // size = 0
        MappingInfo::new(1, GuestAddress(5), 0, Permission::Read).unwrap_err();
    }

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
            assert_eq!(
                mapper.translate(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    perm: Permission::RW
                }
            );
            assert_eq!(
                mapper.translate(8, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1008),
                    len: 1,
                    perm: Permission::RW
                }
            );
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
            assert_eq!(
                mapper.translate(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    perm: Permission::RW
                }
            );
            assert_eq!(
                mapper.translate(6, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(51),
                    len: 1,
                    perm: Permission::RW
                }
            );
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
            assert_eq!(
                mapper.translate(5, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1005),
                    len: 1,
                    perm: Permission::RW
                }
            );
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
            assert_eq!(
                mapper.translate(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    perm: Permission::RW
                }
            );
            assert_eq!(
                mapper.translate(5, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(50),
                    len: 1,
                    perm: Permission::RW
                }
            );
            mapper.remove_map(0, 4).unwrap();
            mapper.translate(0, 1).unwrap_err();
            mapper.translate(4, 1).unwrap_err();
            assert_eq!(
                mapper.translate(5, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(50),
                    len: 1,
                    perm: Permission::RW
                }
            );
        }
        // #6
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            mapper
                .add_map(MappingInfo::new(0, GuestAddress(1000), 4, Permission::RW).unwrap())
                .unwrap();
            assert_eq!(
                mapper.translate(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    perm: Permission::RW
                }
            );
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
            assert_eq!(
                mapper.translate(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    perm: Permission::Read
                }
            );
            assert_eq!(
                mapper.translate(3, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1003),
                    len: 1,
                    perm: Permission::Read
                }
            );
            mapper.translate(4, 1).unwrap_err();
            assert_eq!(
                mapper.translate(10, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(50),
                    len: 1,
                    perm: Permission::RW
                }
            );
            assert_eq!(
                mapper.translate(13, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(53),
                    len: 1,
                    perm: Permission::RW
                }
            );
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

    fn assert_vec_eq<T: std::cmp::PartialEq + Debug>(a: Vec<T>, b: Vec<T>) {
        assert_eq!(a.len(), b.len());
        for (x, y) in a.into_iter().zip(b.into_iter()) {
            assert_eq!(x, y);
        }
    }

    #[test]
    fn test_translate_len() {
        let mut mapper = BasicMemoryMapper::new(u64::MAX);
        // [1, 5) -> [1000, 1004)
        mapper
            .add_map(MappingInfo::new(1, GuestAddress(1000), 4, Permission::Read).unwrap())
            .unwrap();
        mapper.translate(1, 0).unwrap_err();
        assert_eq!(
            mapper.translate(1, 1).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1000),
                len: 1,
                perm: Permission::Read
            }
        );
        assert_eq!(
            mapper.translate(1, 2).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1000),
                len: 2,
                perm: Permission::Read
            }
        );
        assert_eq!(
            mapper.translate(1, 3).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1000),
                len: 3,
                perm: Permission::Read
            }
        );
        assert_eq!(
            mapper.translate(2, 1).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 1,
                perm: Permission::Read
            }
        );
        assert_eq!(
            mapper.translate(2, 2).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 2,
                perm: Permission::Read
            }
        );
        mapper.translate(1, 5).unwrap_err();
        // [1, 9) -> [1000, 1008)
        mapper
            .add_map(MappingInfo::new(5, GuestAddress(1004), 4, Permission::Read).unwrap())
            .unwrap();
        // Spanned across 2 maps
        assert_eq!(
            mapper.translate(2, 5).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 5,
                perm: Permission::Read
            }
        );
        assert_eq!(
            mapper.translate(2, 6).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 6,
                perm: Permission::Read
            }
        );
        assert_eq!(
            mapper.translate(2, 7).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 7,
                perm: Permission::Read
            }
        );
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
        assert_eq!(
            mapper.translate(3, 10).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1002),
                len: 10,
                perm: Permission::Read
            }
        );
        assert_eq!(
            mapper.translate(1, 16).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1000),
                len: 16,
                perm: Permission::Read
            }
        );
        mapper.translate(1, 17).unwrap_err();
        mapper.translate(0, 16).unwrap_err();
        // [0, 1) -> [5, 6), [1, 17) -> [1000, 1016)
        mapper
            .add_map(MappingInfo::new(0, GuestAddress(5), 1, Permission::Read).unwrap())
            .unwrap();
        assert_eq!(
            mapper.translate(0, 1).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(5),
                len: 1,
                perm: Permission::Read
            }
        );
        // Discontiguous gpa
        assert_vec_eq(
            mapper.translate(0, 2).unwrap(),
            vec![
                MemRegion {
                    gpa: GuestAddress(5),
                    len: 1,
                    perm: Permission::Read,
                },
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    perm: Permission::Read,
                },
            ],
        );
        assert_vec_eq(
            mapper.translate(0, 16).unwrap(),
            vec![
                MemRegion {
                    gpa: GuestAddress(5),
                    len: 1,
                    perm: Permission::Read,
                },
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 15,
                    perm: Permission::Read,
                },
            ],
        );
        // [0, 1) -> [5, 6), [1, 17) -> [1000, 1016), [17, 18) -> [1016, 1017) <RW>
        mapper
            .add_map(MappingInfo::new(17, GuestAddress(1016), 2, Permission::RW).unwrap())
            .unwrap();
        // Contiguous iova and gpa, but different perm
        assert_vec_eq(
            mapper.translate(1, 17).unwrap(),
            vec![
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 16,
                    perm: Permission::Read,
                },
                MemRegion {
                    gpa: GuestAddress(1016),
                    len: 1,
                    perm: Permission::RW,
                },
            ],
        );
        // Contiguous iova and gpa, but different perm
        assert_vec_eq(
            mapper.translate(2, 16).unwrap(),
            vec![
                MemRegion {
                    gpa: GuestAddress(1001),
                    len: 15,
                    perm: Permission::Read,
                },
                MemRegion {
                    gpa: GuestAddress(1016),
                    len: 1,
                    perm: Permission::RW,
                },
            ],
        );
        assert_vec_eq(
            mapper.translate(2, 17).unwrap(),
            vec![
                MemRegion {
                    gpa: GuestAddress(1001),
                    len: 15,
                    perm: Permission::Read,
                },
                MemRegion {
                    gpa: GuestAddress(1016),
                    len: 2,
                    perm: Permission::RW,
                },
            ],
        );
        mapper.translate(2, 500).unwrap_err();
        mapper.translate(500, 5).unwrap_err();
    }
}
