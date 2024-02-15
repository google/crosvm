// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! MemoryMapper trait and basic impl for virtio-iommu implementation
//!
//! All the addr/range ends in this file are exclusive.

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::warn;
use base::AsRawDescriptors;
use base::Event;
use base::Protection;
use base::RawDescriptor;
use cros_async::EventAsync;
use cros_async::Executor;
use resources::AddressRange;
use serde::Deserialize;
use serde::Serialize;
use vm_memory::GuestAddress;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

struct ExportState {
    // List of exported regions. Exported regions can overlap.
    exported: Vec<AddressRange>,

    // Event used to signal the client device when there is a fault.
    fault_event: Event,

    // Event used to signal virtio-iommu when the fault is resolved.
    fault_resolved_event_internal: Event,
    // Clone of the above event returned to virtio-iommu when a fault occurs.
    fault_resolved_event_external: Option<EventAsync>,
}

impl ExportState {
    fn new(ex: &Executor) -> Result<(Self, Event)> {
        let fault_event = Event::new().context("failed to create fault_event")?;
        let fault_resolved_event = Event::new().context("failed to create resolve event")?;

        Ok((
            Self {
                exported: Vec::new(),
                fault_event: fault_event
                    .try_clone()
                    .context("failed to clone fault event")?,
                fault_resolved_event_internal: fault_resolved_event
                    .try_clone()
                    .context("failed to clone resolve event")?,
                fault_resolved_event_external: Some(
                    EventAsync::new(fault_resolved_event, ex)
                        .context("failed to create async resolve event")?,
                ),
            },
            fault_event,
        ))
    }

    fn on_fault(&mut self) -> Option<EventAsync> {
        let ret = self.fault_resolved_event_external.take();
        if ret.is_some() {
            self.fault_event.signal().expect("failed to signal fault");
        }
        ret
    }

    fn can_export(&self) -> bool {
        self.fault_resolved_event_external.is_some()
    }
}

// A basic iommu. It is designed as a building block for virtio-iommu.
pub struct BasicMemoryMapper {
    maps: BTreeMap<u64, MappingInfo>, // key = MappingInfo.iova
    mask: u64,
    id: u32,
    export_state: Option<ExportState>,
}

pub enum RemoveMapResult {
    // The removal was successful. If the event is Some, it must be waited on before
    // informing the guest that the unmapping completed.
    Success(Option<EventAsync>),
    // The removal failed because the range partially overlapped a mapping.
    OverlapFailure,
}

#[derive(PartialEq, Eq, Debug)]
pub enum AddMapResult {
    Ok,
    OverlapFailure,
}

/// A generic interface for vfio and other iommu backends
///
/// This interface includes APIs to supports allowing clients within crosvm (e.g.
/// the VVU proxy) which are configured to sit behind a virtio-iommu device to
/// access memory via IO virtual address (IOVA). This is done by exporting mapped
/// memory to the client. The virtio-iommu device can manage many mappers
/// simultaneously. The current implementation has a 1-to-1 relationship between
/// mappers and clients, although this may be extended to 1-to-N to fully support
/// the virtio-iommu API.
///
/// Clients must only access memory while it is mapped into the virtio-iommu device.
/// As such, this interface has a concept of an "IOMMU fault".  An IOMMU fault is
/// triggered when the guest removes a mapping that includes memory that is exported
/// but not yet released. This includes if |reset_domain| is called while any memory
/// is exported. When an IOMMU fault occurs, the event returned by
/// |start_export_session| is signaled, and the client must immediately release any
/// exported memory.
///
/// From the virtio-iommu's perspective, if |remove_map| or |reset_domain| triggers
/// an IOMMU fault, then an eventfd will be returned. It must wait on that event
/// until all exported regions have been released, at which point it can complete
/// the virtio request that triggered the fault.
///
/// As such, the flow of a fault is:
///  1) The guest sends an virtio-iommu message that triggers a fault. Faults can be triggered by
///     unmap or detach messages, or by attach messages if such messages are re-attaching an
///     endpoint to a new domain. One example of a guest event that can trigger such a message is a
///     userspace VVU device process crashing and triggering the guest kernel to re-attach the VVU
///     device to the null endpoint.
///  2) The viommu device removes an exported mapping from the mapper.
///  3) The mapper signals the IOMMU fault eventfd and returns the fault resolution event to the
///     viommu device.
///  4) The viommu device starts waiting on the fault resolution event. Note that although the
///     viommu device and mapper are both running on the same executor, this wait is async. This
///     means that although further processing of virtio-iommu requests is paused, the mapper
///     continues to run.
///  5) The client receives the IOMMU fault.
///  6) The client releases all exported regions.
///  7) Once the mapper receives the final release message from the client, it signals the fault
///     resolution event that the viommu device is waiting on.
///  8) The viommu device finishes processing the original virtio iommu request and sends a reply to
///     the guest.
pub trait MemoryMapper: Send {
    /// Creates a new mapping. If the mapping overlaps with an existing
    /// mapping, return Ok(false).
    fn add_map(&mut self, new_map: MappingInfo) -> Result<AddMapResult>;

    /// Removes all mappings within the specified range.
    fn remove_map(&mut self, iova_start: u64, size: u64) -> Result<RemoveMapResult>;

    fn get_mask(&self) -> Result<u64>;

    /// Whether or not endpoints can be safely detached from this mapper.
    fn supports_detach(&self) -> bool;
    /// Resets the mapper's domain back into its initial state. Only necessary
    /// if |supports_detach| returns true.
    fn reset_domain(&mut self) -> Option<EventAsync> {
        None
    }

    /// Gets an identifier for the MemoryMapper instance. Must be unique among
    /// instances of the same trait implementation.
    fn id(&self) -> u32;

    /// Starts an export session with the mapper.
    ///
    /// Returns an event which is signaled if exported memory is unmapped (i.e. if
    /// a fault occurs). Once a fault occurs, no new regions may be exported for
    /// that session. The client must watch for this event and immediately release
    /// all exported regions.
    ///
    /// Only one session can be active at a time. A new session can only be created if
    /// the previous session has no remaining exported regions.
    fn start_export_session(&mut self, _ex: &Executor) -> Result<Event> {
        bail!("not supported");
    }

    /// Exports the specified IO region.
    ///
    /// # Safety
    ///
    /// The memory in the region specified by hva and size must be
    /// memory external to rust.
    unsafe fn vfio_dma_map(
        &mut self,
        _iova: u64,
        _hva: u64,
        _size: u64,
        _prot: Protection,
    ) -> Result<AddMapResult> {
        bail!("not supported");
    }

    /// Multiple MemRegions should be returned when the gpa is discontiguous or perms are different.
    fn export(&mut self, _iova: u64, _size: u64) -> Result<Vec<MemRegion>> {
        bail!("not supported");
    }

    /// Releases a previously exported region.
    ///
    /// If a given IO region is exported multiple times, it must be released multiple times.
    fn release(&mut self, _iova: u64, _size: u64) -> Result<()> {
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
            export_state: None,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.maps.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.maps.is_empty()
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

    fn remove_map(&mut self, iova_start: u64, size: u64) -> Result<RemoveMapResult> {
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
                return Ok(RemoveMapResult::OverlapFailure);
            }
        }
        for key in to_be_removed {
            self.maps.remove(&key).expect("map should contain key");
        }
        if let Some(export_state) = self.export_state.as_mut() {
            let removed = AddressRange::from_start_and_size(iova_start, size).unwrap();
            for export in &export_state.exported {
                if export.overlaps(removed) {
                    return Ok(RemoveMapResult::Success(export_state.on_fault()));
                }
            }
        }
        Ok(RemoveMapResult::Success(None))
    }

    fn get_mask(&self) -> Result<u64> {
        Ok(self.mask)
    }

    fn supports_detach(&self) -> bool {
        true
    }

    fn reset_domain(&mut self) -> Option<EventAsync> {
        self.maps.clear();
        if let Some(export_state) = self.export_state.as_mut() {
            if !export_state.exported.is_empty() {
                return export_state.on_fault();
            }
        }
        None
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn start_export_session(&mut self, ex: &Executor) -> Result<Event> {
        if let Some(export_state) = self.export_state.as_ref() {
            if !export_state.exported.is_empty() {
                bail!("previous export session still active");
            }
        }

        let (export_state, fault_event) = ExportState::new(ex)?;
        self.export_state = Some(export_state);
        Ok(fault_event)
    }

    fn export(&mut self, iova: u64, size: u64) -> Result<Vec<MemRegion>> {
        let export_state = self.export_state.as_mut().context("no export state")?;
        if !export_state.can_export() {
            bail!("broken export state");
        }
        if size == 0 {
            bail!("can't translate 0 sized region");
        }

        // Regions of contiguous iovas and gpas, and identical permission are merged
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

                export_state
                    .exported
                    .push(AddressRange::from_start_and_end(iova, iova_end - 1));

                return Ok(regions);
            }
            last_iova = map.iova;
        }

        Err(anyhow!("invalid iova {:x} {:x}", iova, size))
    }

    fn release(&mut self, iova: u64, size: u64) -> Result<()> {
        let to_remove = AddressRange::from_start_and_size(iova, size).context("iova overflow")?;
        let state = self.export_state.as_mut().context("no export state")?;

        match state.exported.iter().position(|r| r == &to_remove) {
            Some(idx) => {
                state.exported.swap_remove(idx);
            }
            None => {
                warn!("tried to release unknown range: {:?}", to_remove);
                return Ok(());
            }
        }

        if state.exported.is_empty() && state.fault_resolved_event_external.is_none() {
            state
                .fault_resolved_event_internal
                .signal()
                .expect("failed to resolve fault");
        }

        Ok(())
    }
}

impl AsRawDescriptors for BasicMemoryMapper {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;

    fn assert_overlap_failure(val: RemoveMapResult) {
        match val {
            RemoveMapResult::OverlapFailure => (),
            _ => unreachable!(),
        }
    }

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
        let ex = Executor::new().expect("Failed to create an executor");
        // #1
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            mapper.remove_map(0, 4).unwrap();
        }
        // #2
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            let _ = mapper.start_export_session(&ex);
            mapper
                .add_map(
                    MappingInfo::new(0, GuestAddress(1000), 9, Protection::read_write()).unwrap(),
                )
                .unwrap();
            assert_eq!(
                mapper.export(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            assert_eq!(
                mapper.export(8, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1008),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            mapper.export(9, 1).unwrap_err();
            mapper.remove_map(0, 9).unwrap();
            mapper.export(0, 1).unwrap_err();
        }
        // #3
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            let _ = mapper.start_export_session(&ex);
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
                mapper.export(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            assert_eq!(
                mapper.export(6, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(51),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            mapper.remove_map(0, 9).unwrap();
            mapper.export(0, 1).unwrap_err();
            mapper.export(6, 1).unwrap_err();
        }
        // #4
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            let _ = mapper.start_export_session(&ex);
            mapper
                .add_map(
                    MappingInfo::new(0, GuestAddress(1000), 9, Protection::read_write()).unwrap(),
                )
                .unwrap();
            assert_overlap_failure(mapper.remove_map(0, 4).unwrap());
            assert_eq!(
                mapper.export(5, 1).unwrap()[0],
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
            let _ = mapper.start_export_session(&ex);
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
                mapper.export(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            assert_eq!(
                mapper.export(5, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(50),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            mapper.remove_map(0, 4).unwrap();
            mapper.export(0, 1).unwrap_err();
            mapper.export(4, 1).unwrap_err();
            mapper.export(5, 1).unwrap_err();
        }
        // #6
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            let _ = mapper.start_export_session(&ex);
            mapper
                .add_map(
                    MappingInfo::new(0, GuestAddress(1000), 4, Protection::read_write()).unwrap(),
                )
                .unwrap();
            assert_eq!(
                mapper.export(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            mapper.export(9, 1).unwrap_err();
            mapper.remove_map(0, 9).unwrap();
            mapper.export(0, 1).unwrap_err();
            mapper.export(9, 1).unwrap_err();
        }
        // #7
        {
            let mut mapper = BasicMemoryMapper::new(u64::MAX);
            let _ = mapper.start_export_session(&ex);
            mapper
                .add_map(MappingInfo::new(0, GuestAddress(1000), 4, Protection::read()).unwrap())
                .unwrap();
            mapper
                .add_map(
                    MappingInfo::new(10, GuestAddress(50), 4, Protection::read_write()).unwrap(),
                )
                .unwrap();
            assert_eq!(
                mapper.export(0, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1000),
                    len: 1,
                    prot: Protection::read()
                }
            );
            assert_eq!(
                mapper.export(3, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(1003),
                    len: 1,
                    prot: Protection::read()
                }
            );
            mapper.export(4, 1).unwrap_err();
            assert_eq!(
                mapper.export(10, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(50),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            assert_eq!(
                mapper.export(13, 1).unwrap()[0],
                MemRegion {
                    gpa: GuestAddress(53),
                    len: 1,
                    prot: Protection::read_write()
                }
            );
            mapper.remove_map(0, 14).unwrap();
            mapper.export(0, 1).unwrap_err();
            mapper.export(3, 1).unwrap_err();
            mapper.export(4, 1).unwrap_err();
            mapper.export(10, 1).unwrap_err();
            mapper.export(13, 1).unwrap_err();
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
        assert_overlap_failure(mapper.remove_map(0, 6).unwrap());
        assert_eq!(mapper.len(), 3);
        assert_overlap_failure(mapper.remove_map(1, 5).unwrap());
        assert_eq!(mapper.len(), 3);
        assert_overlap_failure(mapper.remove_map(1, 9).unwrap());
        assert_eq!(mapper.len(), 3);
        assert_overlap_failure(mapper.remove_map(6, 4).unwrap());
        assert_eq!(mapper.len(), 3);
        assert_overlap_failure(mapper.remove_map(6, 14).unwrap());
        assert_eq!(mapper.len(), 3);
        mapper.remove_map(5, 4).unwrap();
        assert_eq!(mapper.len(), 2);
        assert_overlap_failure(mapper.remove_map(1, 9).unwrap());
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
        let ex = Executor::new().expect("Failed to create an executor");
        let _ = mapper.start_export_session(&ex);
        // [1, 5) -> [1000, 1004)
        mapper
            .add_map(MappingInfo::new(1, GuestAddress(1000), 4, Protection::read()).unwrap())
            .unwrap();
        mapper.export(1, 0).unwrap_err();
        assert_eq!(
            mapper.export(1, 1).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1000),
                len: 1,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.export(1, 2).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1000),
                len: 2,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.export(1, 3).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1000),
                len: 3,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.export(2, 1).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 1,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.export(2, 2).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 2,
                prot: Protection::read()
            }
        );
        mapper.export(1, 5).unwrap_err();
        // [1, 9) -> [1000, 1008)
        mapper
            .add_map(MappingInfo::new(5, GuestAddress(1004), 4, Protection::read()).unwrap())
            .unwrap();
        // Spanned across 2 maps
        assert_eq!(
            mapper.export(2, 5).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 5,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.export(2, 6).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 6,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.export(2, 7).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1001),
                len: 7,
                prot: Protection::read()
            }
        );
        mapper.export(2, 8).unwrap_err();
        mapper.export(3, 10).unwrap_err();
        // [1, 9) -> [1000, 1008), [11, 17) -> [1010, 1016)
        mapper
            .add_map(MappingInfo::new(11, GuestAddress(1010), 6, Protection::read()).unwrap())
            .unwrap();
        // Discontiguous iova
        mapper.export(3, 10).unwrap_err();
        // [1, 17) -> [1000, 1016)
        mapper
            .add_map(MappingInfo::new(9, GuestAddress(1008), 2, Protection::read()).unwrap())
            .unwrap();
        // Spanned across 4 maps
        assert_eq!(
            mapper.export(3, 10).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1002),
                len: 10,
                prot: Protection::read()
            }
        );
        assert_eq!(
            mapper.export(1, 16).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(1000),
                len: 16,
                prot: Protection::read()
            }
        );
        mapper.export(1, 17).unwrap_err();
        mapper.export(0, 16).unwrap_err();
        // [0, 1) -> [5, 6), [1, 17) -> [1000, 1016)
        mapper
            .add_map(MappingInfo::new(0, GuestAddress(5), 1, Protection::read()).unwrap())
            .unwrap();
        assert_eq!(
            mapper.export(0, 1).unwrap()[0],
            MemRegion {
                gpa: GuestAddress(5),
                len: 1,
                prot: Protection::read()
            }
        );
        // Discontiguous gpa
        assert_vec_eq(
            mapper.export(0, 2).unwrap(),
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
            mapper.export(0, 16).unwrap(),
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
            mapper.export(1, 17).unwrap(),
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
            mapper.export(2, 16).unwrap(),
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
            mapper.export(2, 17).unwrap(),
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
        mapper.export(2, 500).unwrap_err();
        mapper.export(500, 5).unwrap_err();
    }
}
