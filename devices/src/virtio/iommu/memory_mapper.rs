// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! MemoryMapper trait and basic impl for virtio-iommu implementation
//!
//! All the addr/range ends in this file are exclusive.

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{anyhow, bail, Context, Result};
use base::{AsRawDescriptors, Protection, RawDescriptor};
use serde::{Deserialize, Serialize};
use vm_memory::GuestAddress;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemRegion {
    pub gpa: GuestAddress,
    pub len: u64,
    pub prot: Protection,
}

/// Manages the mapping from a guest IO virtual address space to the guest physical address space
#[derive(Debug)]
pub struct MappingInfo {
    pub iova: u64,
    pub gpa: GuestAddress,
    pub size: u64,
    pub prot: Protection,
}

impl MappingInfo {
    #[allow(dead_code)]
    fn new(iova: u64, gpa: GuestAddress, size: u64, prot: Protection) -> Result<Self> {
        if size == 0 {
            bail!("can't create 0 sized region");
        }
        iova.checked_add(size).context("iova overflow")?;
        gpa.checked_add(size).context("gpa overflow")?;
        Ok(Self {
            iova,
            gpa,
            size,
            prot,
        })
    }
}

// A basic iommu. It is designed as a building block for virtio-iommu.
pub struct BasicMemoryMapper {
    maps: BTreeMap<u64, MappingInfo>, // key = MappingInfo.iova
    mask: u64,
    id: u32,
}

#[derive(PartialEq, Debug)]
pub enum AddMapResult {
    Ok,
    OverlapFailure,
}

/// A generic interface for vfio and other iommu backends
pub trait MemoryMapper: Send {
    /// Creates a new mapping. If the mapping overlaps with an existing
    /// mapping, return Ok(false).
    fn add_map(&mut self, new_map: MappingInfo) -> Result<AddMapResult>;

    /// Removes all mappings within the specified range.
    ///
    /// If a mapped region partially overlaps what is being unmapped, implementations
    /// SHOULD return Ok(false) without removing any mappings.
    fn remove_map(&mut self, iova_start: u64, size: u64) -> Result<bool>;

    fn get_mask(&self) -> Result<u64>;

    /// Whether or not endpoints can be safely detached from this mapper.
    fn supports_detach(&self) -> bool;
    /// Resets the mapper's domain back into its initial state. Only necessary
    /// if |supports_detach| returns true.
    fn reset_domain(&mut self) {}

    /// Gets an identifier for the MemoryMapper instance. Must be unique among
    /// instances of the same trait implementation.
    fn id(&self) -> u32;

    /// Multiple MemRegions should be returned when the gpa is discontiguous or perms are different.
    fn translate(&self, _iova: u64, _size: u64) -> Result<Vec<MemRegion>> {
        bail!("not supported");
    }
}

pub trait MemoryMapperTrait: MemoryMapper + AsRawDescriptors + Any {}
impl<T: MemoryMapper + AsRawDescriptors + Any> MemoryMapperTrait for T {}

impl BasicMemoryMapper {
    pub fn new(mask: u64) -> BasicMemoryMapper {
        static NEXT_ID: AtomicU32 = AtomicU32::new(0);
        BasicMemoryMapper {
            maps: BTreeMap::new(),
            mask,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.maps.len()
    }
}

impl MemoryMapper for BasicMemoryMapper {
    fn add_map(&mut self, new_map: MappingInfo) -> Result<AddMapResult> {
        if new_map.size == 0 {
            bail!("can't map 0 sized region");
        }
        let new_iova_end = new_map
            .iova
            .checked_add(new_map.size)
            .context("iova overflow")?;
        new_map
            .gpa
            .checked_add(new_map.size)
            .context("gpa overflow")?;
        let mut iter = self.maps.range(..new_iova_end);
        if let Some((_, map)) = iter.next_back() {
            if map.iova + map.size > new_map.iova {
                return Ok(AddMapResult::OverlapFailure);
            }
        }
        self.maps.insert(new_map.iova, new_map);
        Ok(AddMapResult::Ok)
    }

    fn remove_map(&mut self, iova_start: u64, size: u64) -> Result<bool> {
        if size == 0 {
            bail!("can't unmap 0 sized region");
        }
        let iova_end = iova_start.checked_add(size).context("iova overflow")?;

        // So that we invalid requests can be rejected w/o modifying things, check
        // for partial overlap before removing the maps.
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
                return Ok(false);
            }
        }
        for key in to_be_removed {
            self.maps.remove(&key).expect("map should contain key");
        }
        Ok(true)
    }

    fn get_mask(&self) -> Result<u64> {
        Ok(self.mask)
    }

    fn supports_detach(&self) -> bool {
        true
    }

    fn reset_domain(&mut self) {
        self.maps.clear();
    }

    fn id(&self) -> u32 {
        self.id
    }

    /// Regions of contiguous iovas and gpas, and identical permission are merged
    fn translate(&self, iova: u64, size: u64) -> Result<Vec<MemRegion>> {
        if size == 0 {
            bail!("can't translate 0 sized region");
        }
        let iova_end = iova.checked_add(size).context("iova overflow")?;
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
                if map.gpa.unchecked_add(map.size) == last.gpa && map.prot == last.prot {
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
                    prot: map.prot,
                });
            }
            if iova >= map.iova {
                regions.reverse();
                // The gpa of the first region has to be offseted
                regions[0].gpa = map
                    .gpa
                    .checked_add(iova - map.iova)
                    .context("gpa overflow")?;
                return Ok(regions);
            }
            last_iova = map.iova;
        }

        Err(anyhow!("invalid iova {:x} {:x}", iova, size))
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
        MappingInfo::new(u64::MAX - 1, GuestAddress(1), 2, Protection::read()).unwrap_err();
        MappingInfo::new(1, GuestAddress(u64::MAX - 1), 2, Protection::read()).unwrap_err();
        MappingInfo::new(u64::MAX, GuestAddress(1), 2, Protection::read()).unwrap_err();
        MappingInfo::new(1, GuestAddress(u64::MAX), 2, Protection::read()).unwrap_err();
        MappingInfo::new(5, GuestAddress(5), u64::MAX, Protection::read()).unwrap_err();
        // size = 0
        MappingInfo::new(1, GuestAddress(5), 0, Protection::read()).unwrap_err();
    }

    #[test]
    fn test_map_overlap() {
        let mut mapper = BasicMemoryMapper::new(u64::MAX);
        mapper
            .add_map(
                MappingInfo::new(10, GuestAddress(1000), 10, Protection::read_write()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            mapper
                .add_map(
                    MappingInfo::new(14, GuestAddress(1000), 1, Protection::read_write()).unwrap()
                )
                .unwrap(),
            AddMapResult::OverlapFailure
        );
        assert_eq!(
            mapper
                .add_map(
                    MappingInfo::new(0, GuestAddress(1000), 12, Protection::read_write()).unwrap()
                )
                .unwrap(),
            AddMapResult::OverlapFailure
        );
        assert_eq!(
            mapper
                .add_map(
                    MappingInfo::new(16, GuestAddress(1000), 6, Protection::read_write()).unwrap()
                )
                .unwrap(),
            AddMapResult::OverlapFailure
        );
        assert_eq!(
            mapper
                .add_map(
                    MappingInfo::new(5, GuestAddress(1000), 20, Protection::read_write()).unwrap()
                )
                .unwrap(),
            AddMapResult::OverlapFailure
        );
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
                .add_map(
                    MappingInfo::new(0, GuestAddress(1000), 9, Protection::read_write()).unwrap(),
                )
                .unwrap();
            assert_eq!(
                mapper.translate(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            assert_eq!(
                mapper.translate(8, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1008),
                    len: 1,
                    prot: Protection::read_write()
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
                .add_map(
                    MappingInfo::new(0, GuestAddress(1000), 4, Protection::read_write()).unwrap(),
                )
                .unwrap();
            mapper
                .add_map(
                    MappingInfo::new(5, GuestAddress(50), 4, Protection::read_write()).unwrap(),
                )
                .unwrap();
            assert_eq!(
                mapper.translate(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            assert_eq!(
                mapper.translate(6, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(51),
                    len: 1,
                    prot: Protection::read_write()
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
                .add_map(
                    MappingInfo::new(0, GuestAddress(1000), 9, Protection::read_write()).unwrap(),
                )
                .unwrap();
            assert!(!mapper.remove_map(0, 4).unwrap());
            assert_eq!(
                mapper.translate(5, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1005),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
        }
        // #5
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            mapper
                .add_map(
                    MappingInfo::new(0, GuestAddress(1000), 4, Protection::read_write()).unwrap(),
                )
                .unwrap();
            mapper
                .add_map(
                    MappingInfo::new(5, GuestAddress(50), 4, Protection::read_write()).unwrap(),
                )
                .unwrap();
            assert_eq!(
                mapper.translate(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            assert_eq!(
                mapper.translate(5, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(50),
                    len: 1,
                    prot: Protection::read_write()
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
                    prot: Protection::read_write()
                }
            );
        }
        // #6
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            mapper
                .add_map(
                    MappingInfo::new(0, GuestAddress(1000), 4, Protection::read_write()).unwrap(),
                )
                .unwrap();
            assert_eq!(
                mapper.translate(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    prot: Protection::read_write()
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
                .add_map(MappingInfo::new(0, GuestAddress(1000), 4, Protection::read()).unwrap())
                .unwrap();
            mapper
                .add_map(
                    MappingInfo::new(10, GuestAddress(50), 4, Protection::read_write()).unwrap(),
                )
                .unwrap();
            assert_eq!(
                mapper.translate(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    prot: Protection::read()
                }
            );
            assert_eq!(
                mapper.translate(3, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1003),
                    len: 1,
                    prot: Protection::read()
                }
            );
            mapper.translate(4, 1).unwrap_err();
            assert_eq!(
                mapper.translate(10, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(50),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            assert_eq!(
                mapper.translate(13, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(53),
                    len: 1,
                    prot: Protection::read_write()
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
            .add_map(MappingInfo::new(1, GuestAddress(1000), 4, Protection::read()).unwrap())
            .unwrap();
        mapper
            .add_map(MappingInfo::new(5, GuestAddress(50), 4, Protection::read_write()).unwrap())
            .unwrap();
        mapper
            .add_map(MappingInfo::new(9, GuestAddress(50), 4, Protection::read_write()).unwrap())
            .unwrap();
        assert_eq!(mapper.len(), 3);
        assert!(!mapper.remove_map(0, 6).unwrap());
        assert_eq!(mapper.len(), 3);
        assert!(!mapper.remove_map(1, 5).unwrap());
        assert_eq!(mapper.len(), 3);
        assert!(!mapper.remove_map(1, 9).unwrap());
        assert_eq!(mapper.len(), 3);
        assert!(!mapper.remove_map(6, 4).unwrap());
        assert_eq!(mapper.len(), 3);
        assert!(!mapper.remove_map(6, 14).unwrap());
        assert_eq!(mapper.len(), 3);
        mapper.remove_map(5, 4).unwrap();
        assert_eq!(mapper.len(), 2);
        assert!(!mapper.remove_map(1, 9).unwrap());
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
            .add_map(MappingInfo::new(1, GuestAddress(1000), 4, Protection::read()).unwrap())
            .unwrap();
        mapper.translate(1, 0).unwrap_err();
        assert_eq!(
            mapper.translate(1, 1).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1000),
                len: 1,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.translate(1, 2).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1000),
                len: 2,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.translate(1, 3).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1000),
                len: 3,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.translate(2, 1).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 1,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.translate(2, 2).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 2,
                prot: Protection::read()
            }
        );
        mapper.translate(1, 5).unwrap_err();
        // [1, 9) -> [1000, 1008)
        mapper
            .add_map(MappingInfo::new(5, GuestAddress(1004), 4, Protection::read()).unwrap())
            .unwrap();
        // Spanned across 2 maps
        assert_eq!(
            mapper.translate(2, 5).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 5,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.translate(2, 6).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 6,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.translate(2, 7).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 7,
                prot: Protection::read()
            }
        );
        mapper.translate(2, 8).unwrap_err();
        mapper.translate(3, 10).unwrap_err();
        // [1, 9) -> [1000, 1008), [11, 17) -> [1010, 1016)
        mapper
            .add_map(MappingInfo::new(11, GuestAddress(1010), 6, Protection::read()).unwrap())
            .unwrap();
        // Discontiguous iova
        mapper.translate(3, 10).unwrap_err();
        // [1, 17) -> [1000, 1016)
        mapper
            .add_map(MappingInfo::new(9, GuestAddress(1008), 2, Protection::read()).unwrap())
            .unwrap();
        // Spanned across 4 maps
        assert_eq!(
            mapper.translate(3, 10).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1002),
                len: 10,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.translate(1, 16).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1000),
                len: 16,
                prot: Protection::read()
            }
        );
        mapper.translate(1, 17).unwrap_err();
        mapper.translate(0, 16).unwrap_err();
        // [0, 1) -> [5, 6), [1, 17) -> [1000, 1016)
        mapper
            .add_map(MappingInfo::new(0, GuestAddress(5), 1, Protection::read()).unwrap())
            .unwrap();
        assert_eq!(
            mapper.translate(0, 1).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(5),
                len: 1,
                prot: Protection::read()
            }
        );
        // Discontiguous gpa
        assert_vec_eq(
            mapper.translate(0, 2).unwrap(),
            vec![
                MemRegion {
                    gpa: GuestAddress(5),
                    len: 1,
                    prot: Protection::read(),
                },
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    prot: Protection::read(),
                },
            ],
        );
        assert_vec_eq(
            mapper.translate(0, 16).unwrap(),
            vec![
                MemRegion {
                    gpa: GuestAddress(5),
                    len: 1,
                    prot: Protection::read(),
                },
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 15,
                    prot: Protection::read(),
                },
            ],
        );
        // [0, 1) -> [5, 6), [1, 17) -> [1000, 1016), [17, 18) -> [1016, 1017) <RW>
        mapper
            .add_map(MappingInfo::new(17, GuestAddress(1016), 2, Protection::read_write()).unwrap())
            .unwrap();
        // Contiguous iova and gpa, but different perm
        assert_vec_eq(
            mapper.translate(1, 17).unwrap(),
            vec![
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 16,
                    prot: Protection::read(),
                },
                MemRegion {
                    gpa: GuestAddress(1016),
                    len: 1,
                    prot: Protection::read_write(),
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
                    prot: Protection::read(),
                },
                MemRegion {
                    gpa: GuestAddress(1016),
                    len: 1,
                    prot: Protection::read_write(),
                },
            ],
        );
        assert_vec_eq(
            mapper.translate(2, 17).unwrap(),
            vec![
                MemRegion {
                    gpa: GuestAddress(1001),
                    len: 15,
                    prot: Protection::read(),
                },
                MemRegion {
                    gpa: GuestAddress(1016),
                    len: 2,
                    prot: Protection::read_write(),
                },
            ],
        );
        mapper.translate(2, 500).unwrap_err();
        mapper.translate(500, 5).unwrap_err();
    }
}
