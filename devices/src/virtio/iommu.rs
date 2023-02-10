// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod ipc_memory_mapper;
pub mod memory_mapper;
pub mod memory_util;
pub mod protocol;
pub(crate) mod sys;

use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::io;
use std::io::Write;
use std::mem::size_of;
use std::ops::RangeInclusive;
use std::rc::Rc;
use std::result;
use std::sync::Arc;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use acpi_tables::sdt::SDT;
use anyhow::anyhow;
use anyhow::Context;
use base::debug;
use base::error;
use base::pagesize;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use base::warn;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::Event;
use base::MappedRegion;
use base::MemoryMapping;
use base::Protection;
use base::RawDescriptor;
use base::Result as SysResult;
use base::Tube;
use base::TubeError;
use base::WorkerThread;
use cros_async::AsyncError;
use cros_async::AsyncTube;
use cros_async::EventAsync;
use cros_async::Executor;
use data_model::Le64;
use futures::select;
use futures::FutureExt;
use hypervisor::MemSlot;
use remain::sorted;
use sync::Mutex;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::pci::PciAddress;
use crate::virtio::async_utils;
use crate::virtio::copy_config;
use crate::virtio::iommu::ipc_memory_mapper::*;
use crate::virtio::iommu::memory_mapper::*;
use crate::virtio::iommu::protocol::*;
use crate::virtio::DescriptorChain;
use crate::virtio::DescriptorError;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::Reader;
use crate::virtio::SignalableInterrupt;
use crate::virtio::VirtioDevice;
use crate::virtio::Writer;
use crate::Suspendable;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

// Size of struct virtio_iommu_probe_property
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const IOMMU_PROBE_SIZE: usize = size_of::<virtio_iommu_probe_resv_mem>();

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const VIRTIO_IOMMU_VIOT_NODE_PCI_RANGE: u8 = 1;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const VIRTIO_IOMMU_VIOT_NODE_VIRTIO_IOMMU_PCI: u8 = 3;

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes)]
#[repr(C, packed)]
struct VirtioIommuViotHeader {
    node_count: u16,
    node_offset: u16,
    reserved: [u8; 8],
}

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes)]
#[repr(C, packed)]
struct VirtioIommuViotVirtioPciNode {
    type_: u8,
    reserved: [u8; 1],
    length: u16,
    segment: u16,
    bdf: u16,
    reserved2: [u8; 8],
}

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes)]
#[repr(C, packed)]
struct VirtioIommuViotPciRangeNode {
    type_: u8,
    reserved: [u8; 1],
    length: u16,
    endpoint_start: u32,
    segment_start: u16,
    segment_end: u16,
    bdf_start: u16,
    bdf_end: u16,
    output_node: u16,
    reserved2: [u8; 2],
    reserved3: [u8; 4],
}

type Result<T> = result::Result<T, IommuError>;

#[sorted]
#[derive(Error, Debug)]
pub enum IommuError {
    #[error("async executor error: {0}")]
    AsyncExec(AsyncError),
    #[error("failed to create reader: {0}")]
    CreateReader(DescriptorError),
    #[error("failed to create wait context: {0}")]
    CreateWaitContext(SysError),
    #[error("failed to create writer: {0}")]
    CreateWriter(DescriptorError),
    #[error("failed getting host address: {0}")]
    GetHostAddress(GuestMemoryError),
    #[error("failed to read from guest address: {0}")]
    GuestMemoryRead(io::Error),
    #[error("failed to write to guest address: {0}")]
    GuestMemoryWrite(io::Error),
    #[error("memory mapper failed: {0}")]
    MemoryMapper(anyhow::Error),
    #[error("Failed to read descriptor asynchronously: {0}")]
    ReadAsyncDesc(AsyncError),
    #[error("failed to read from virtio queue Event: {0}")]
    ReadQueueEvent(SysError),
    #[error("tube error: {0}")]
    Tube(TubeError),
    #[error("unexpected descriptor error")]
    UnexpectedDescriptor,
    #[error("failed to receive virtio-iommu control request: {0}")]
    VirtioIOMMUReqError(TubeError),
    #[error("failed to send virtio-iommu control response: {0}")]
    VirtioIOMMUResponseError(TubeError),
    #[error("failed to wait for events: {0}")]
    WaitError(SysError),
    #[error("write buffer length too small")]
    WriteBufferTooSmall,
}

// key: domain ID
// value: reference counter and MemoryMapperTrait
type DomainMap = BTreeMap<u32, (u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>)>;

struct DmabufRegionEntry {
    mmap: MemoryMapping,
    mem_slot: MemSlot,
    len: u64,
}

// Shared state for the virtio-iommu device.
struct State {
    mem: GuestMemory,
    page_mask: u64,
    // Hot-pluggable PCI endpoints ranges
    // RangeInclusive: (start endpoint PCI address .. =end endpoint PCI address)
    #[cfg_attr(windows, allow(dead_code))]
    hp_endpoints_ranges: Vec<RangeInclusive<u32>>,
    // All PCI endpoints that attach to certain IOMMU domain
    // key: endpoint PCI address
    // value: attached domain ID
    endpoint_map: BTreeMap<u32, u32>,
    // All attached domains
    domain_map: DomainMap,
    // Contains all pass-through endpoints that attach to this IOMMU device
    // key: endpoint PCI address
    // value: reference counter and MemoryMapperTrait
    endpoints: BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
    // Contains dmabuf regions
    // key: guest physical address
    dmabuf_mem: BTreeMap<u64, DmabufRegionEntry>,
}

impl State {
    // Detach the given endpoint if possible, and return whether or not the endpoint
    // was actually detached. If a successfully detached endpoint has exported
    // memory, returns an event that will be signaled once all exported memory is released.
    //
    // The device MUST ensure that after being detached from a domain, the endpoint
    // cannot access any mapping from that domain.
    //
    // Currently, we only support detaching an endpoint if it is the only endpoint attached
    // to its domain.
    fn detach_endpoint(
        endpoint_map: &mut BTreeMap<u32, u32>,
        domain_map: &mut DomainMap,
        endpoint: u32,
    ) -> (bool, Option<EventAsync>) {
        let mut evt = None;
        // The endpoint has attached to an IOMMU domain
        if let Some(attached_domain) = endpoint_map.get(&endpoint) {
            // Remove the entry or update the domain reference count
            if let Entry::Occupied(o) = domain_map.entry(*attached_domain) {
                let (refs, mapper) = o.get();
                if !mapper.lock().supports_detach() {
                    return (false, None);
                }

                match refs {
                    0 => unreachable!(),
                    1 => {
                        evt = mapper.lock().reset_domain();
                        o.remove();
                    }
                    _ => return (false, None),
                }
            }
        }

        endpoint_map.remove(&endpoint);
        (true, evt)
    }

    // Processes an attach request. This may require detaching the endpoint from
    // its current endpoint before attaching it to a new endpoint. If that happens
    // while the endpoint has exported memory, this function returns an event that
    // will be signaled once all exported memory is released.
    //
    // Notes: if a VFIO group contains multiple devices, it could violate the follow
    // requirement from the virtio IOMMU spec: If the VIRTIO_IOMMU_F_BYPASS feature
    // is negotiated, all accesses from unattached endpoints are allowed and translated
    // by the IOMMU using the identity function. If the feature is not negotiated, any
    // memory access from an unattached endpoint fails.
    //
    // This happens after the virtio-iommu device receives a VIRTIO_IOMMU_T_ATTACH
    // request for the first endpoint in a VFIO group, any not yet attached endpoints
    // in the VFIO group will be able to access the domain.
    //
    // This violation is benign for current virtualization use cases. Since device
    // topology in the guest matches topology in the host, the guest doesn't expect
    // the device in the same VFIO group are isolated from each other in the first place.
    fn process_attach_request(
        &mut self,
        reader: &mut Reader,
        tail: &mut virtio_iommu_req_tail,
    ) -> Result<(usize, Option<EventAsync>)> {
        let req: virtio_iommu_req_attach =
            reader.read_obj().map_err(IommuError::GuestMemoryRead)?;
        let mut fault_resolved_event = None;

        // If the reserved field of an ATTACH request is not zero,
        // the device MUST reject the request and set status to
        // VIRTIO_IOMMU_S_INVAL.
        if req.reserved.iter().any(|&x| x != 0) {
            tail.status = VIRTIO_IOMMU_S_INVAL;
            return Ok((0, None));
        }

        let domain: u32 = req.domain.into();
        let endpoint: u32 = req.endpoint.into();

        if let Some(mapper) = self.endpoints.get(&endpoint) {
            // The same mapper can't be used for two domains at the same time,
            // since that would result in conflicts/permission leaks between
            // the two domains.
            let mapper_id = {
                let m = mapper.lock();
                ((**m).type_id(), m.id())
            };
            for (other_endpoint, other_mapper) in self.endpoints.iter() {
                if *other_endpoint == endpoint {
                    continue;
                }
                let other_id = {
                    let m = other_mapper.lock();
                    ((**m).type_id(), m.id())
                };
                if mapper_id == other_id {
                    if !self
                        .endpoint_map
                        .get(other_endpoint)
                        .map_or(true, |d| d == &domain)
                    {
                        tail.status = VIRTIO_IOMMU_S_UNSUPP;
                        return Ok((0, None));
                    }
                }
            }

            // If the endpoint identified by `endpoint` is already attached
            // to another domain, then the device SHOULD first detach it
            // from that domain and attach it to the one identified by domain.
            if self.endpoint_map.contains_key(&endpoint) {
                // In that case the device SHOULD behave as if the driver issued
                // a DETACH request with this endpoint, followed by the ATTACH
                // request. If the device cannot do so, it MUST reject the request
                // and set status to VIRTIO_IOMMU_S_UNSUPP.
                let (detached, evt) =
                    Self::detach_endpoint(&mut self.endpoint_map, &mut self.domain_map, endpoint);
                if !detached {
                    tail.status = VIRTIO_IOMMU_S_UNSUPP;
                    return Ok((0, None));
                }
                fault_resolved_event = evt;
            }

            let new_ref = match self.domain_map.get(&domain) {
                None => 1,
                Some(val) => val.0 + 1,
            };

            self.endpoint_map.insert(endpoint, domain);
            self.domain_map.insert(domain, (new_ref, mapper.clone()));
        } else {
            // If the endpoint identified by endpoint doesn’t exist,
            // the device MUST reject the request and set status to
            // VIRTIO_IOMMU_S_NOENT.
            tail.status = VIRTIO_IOMMU_S_NOENT;
        }

        Ok((0, fault_resolved_event))
    }

    fn process_detach_request(
        &mut self,
        reader: &mut Reader,
        tail: &mut virtio_iommu_req_tail,
    ) -> Result<(usize, Option<EventAsync>)> {
        let req: virtio_iommu_req_detach =
            reader.read_obj().map_err(IommuError::GuestMemoryRead)?;

        // If the endpoint identified by |req.endpoint| doesn’t exist,
        // the device MUST reject the request and set status to
        // VIRTIO_IOMMU_S_NOENT.
        let endpoint: u32 = req.endpoint.into();
        if !self.endpoints.contains_key(&endpoint) {
            tail.status = VIRTIO_IOMMU_S_NOENT;
            return Ok((0, None));
        }

        let (detached, evt) =
            Self::detach_endpoint(&mut self.endpoint_map, &mut self.domain_map, endpoint);
        if !detached {
            tail.status = VIRTIO_IOMMU_S_UNSUPP;
        }
        Ok((0, evt))
    }

    fn process_dma_map_request(
        &mut self,
        reader: &mut Reader,
        tail: &mut virtio_iommu_req_tail,
    ) -> Result<usize> {
        let req: virtio_iommu_req_map = reader.read_obj().map_err(IommuError::GuestMemoryRead)?;

        // If virt_start, phys_start or (virt_end + 1) is not aligned
        // on the page granularity, the device SHOULD reject the
        // request and set status to VIRTIO_IOMMU_S_RANGE
        if self.page_mask & u64::from(req.phys_start) != 0
            || self.page_mask & u64::from(req.virt_start) != 0
            || self.page_mask & (u64::from(req.virt_end) + 1) != 0
        {
            tail.status = VIRTIO_IOMMU_S_RANGE;
            return Ok(0);
        }

        // If the device doesn’t recognize a flags bit, it MUST reject
        // the request and set status to VIRTIO_IOMMU_S_INVAL.
        if u32::from(req.flags) & !VIRTIO_IOMMU_MAP_F_MASK != 0 {
            tail.status = VIRTIO_IOMMU_S_INVAL;
            return Ok(0);
        }

        let domain: u32 = req.domain.into();
        if !self.domain_map.contains_key(&domain) {
            // If domain does not exist, the device SHOULD reject
            // the request and set status to VIRTIO_IOMMU_S_NOENT.
            tail.status = VIRTIO_IOMMU_S_NOENT;
            return Ok(0);
        }

        // The device MUST NOT allow writes to a range mapped
        // without the VIRTIO_IOMMU_MAP_F_WRITE flag.
        let write_en = u32::from(req.flags) & VIRTIO_IOMMU_MAP_F_WRITE != 0;

        if let Some(mapper) = self.domain_map.get(&domain) {
            let size = u64::from(req.virt_end) - u64::from(req.virt_start) + 1u64;

            let dmabuf_map = self
                .dmabuf_mem
                .range(..=u64::from(req.phys_start))
                .next_back()
                .and_then(|(addr, region)| {
                    if u64::from(req.phys_start) + size <= addr + region.len {
                        Some(region.mmap.as_ptr() as u64 + (u64::from(req.phys_start) - addr))
                    } else {
                        None
                    }
                });

            let prot = match write_en {
                true => Protection::read_write(),
                false => Protection::read(),
            };

            let vfio_map_result = match dmabuf_map {
                // Safe because [dmabuf_map, dmabuf_map + size) refers to an external mmap'ed region.
                Some(dmabuf_map) => unsafe {
                    mapper.1.lock().vfio_dma_map(
                        req.virt_start.into(),
                        dmabuf_map as u64,
                        size,
                        prot,
                    )
                },
                None => mapper.1.lock().add_map(MappingInfo {
                    iova: req.virt_start.into(),
                    gpa: GuestAddress(req.phys_start.into()),
                    size,
                    prot,
                }),
            };

            match vfio_map_result {
                Ok(AddMapResult::Ok) => (),
                Ok(AddMapResult::OverlapFailure) => {
                    // If a mapping already exists in the requested range,
                    // the device SHOULD reject the request and set status
                    // to VIRTIO_IOMMU_S_INVAL.
                    tail.status = VIRTIO_IOMMU_S_INVAL;
                }
                Err(e) => return Err(IommuError::MemoryMapper(e)),
            }
        }

        Ok(0)
    }

    fn process_dma_unmap_request(
        &mut self,
        reader: &mut Reader,
        tail: &mut virtio_iommu_req_tail,
    ) -> Result<(usize, Option<EventAsync>)> {
        let req: virtio_iommu_req_unmap = reader.read_obj().map_err(IommuError::GuestMemoryRead)?;

        let domain: u32 = req.domain.into();
        let fault_resolved_event = if let Some(mapper) = self.domain_map.get(&domain) {
            let size = u64::from(req.virt_end) - u64::from(req.virt_start) + 1;
            let res = mapper
                .1
                .lock()
                .remove_map(u64::from(req.virt_start), size)
                .map_err(IommuError::MemoryMapper)?;
            match res {
                RemoveMapResult::Success(evt) => evt,
                RemoveMapResult::OverlapFailure => {
                    // If a mapping affected by the range is not covered in its entirety by the
                    // range (the UNMAP request would split the mapping), then the device SHOULD
                    // set the request `status` to VIRTIO_IOMMU_S_RANGE, and SHOULD NOT remove
                    // any mapping.
                    tail.status = VIRTIO_IOMMU_S_RANGE;
                    None
                }
            }
        } else {
            // If domain does not exist, the device SHOULD set the
            // request status to VIRTIO_IOMMU_S_NOENT
            tail.status = VIRTIO_IOMMU_S_NOENT;
            None
        };

        Ok((0, fault_resolved_event))
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn process_probe_request(
        &mut self,
        reader: &mut Reader,
        writer: &mut Writer,
        tail: &mut virtio_iommu_req_tail,
    ) -> Result<usize> {
        let req: virtio_iommu_req_probe = reader.read_obj().map_err(IommuError::GuestMemoryRead)?;
        let endpoint: u32 = req.endpoint.into();

        // If the endpoint identified by endpoint doesn’t exist,
        // then the device SHOULD reject the request and set status
        // to VIRTIO_IOMMU_S_NOENT.
        if !self.endpoints.contains_key(&endpoint) {
            tail.status = VIRTIO_IOMMU_S_NOENT;
        }

        let properties_size = writer.available_bytes() - size_of::<virtio_iommu_req_tail>();

        // It's OK if properties_size is larger than probe_size
        // We are good even if properties_size is 0
        if properties_size < IOMMU_PROBE_SIZE {
            // If the properties list is smaller than probe_size, the device
            // SHOULD NOT write any property. It SHOULD reject the request
            // and set status to VIRTIO_IOMMU_S_INVAL.
            tail.status = VIRTIO_IOMMU_S_INVAL;
        } else if tail.status == VIRTIO_IOMMU_S_OK {
            const VIRTIO_IOMMU_PROBE_T_RESV_MEM: u16 = 1;
            const VIRTIO_IOMMU_RESV_MEM_T_MSI: u8 = 1;
            const PROBE_PROPERTY_SIZE: u16 = 4;
            const X86_MSI_IOVA_START: u64 = 0xfee0_0000;
            const X86_MSI_IOVA_END: u64 = 0xfeef_ffff;

            let properties = virtio_iommu_probe_resv_mem {
                head: virtio_iommu_probe_property {
                    type_: VIRTIO_IOMMU_PROBE_T_RESV_MEM.into(),
                    length: (IOMMU_PROBE_SIZE as u16 - PROBE_PROPERTY_SIZE).into(),
                },
                subtype: VIRTIO_IOMMU_RESV_MEM_T_MSI,
                start: X86_MSI_IOVA_START.into(),
                end: X86_MSI_IOVA_END.into(),
                ..Default::default()
            };
            writer
                .write_all(properties.as_bytes())
                .map_err(IommuError::GuestMemoryWrite)?;
        }

        // If the device doesn’t fill all probe_size bytes with properties,
        // it SHOULD fill the remaining bytes of properties with zeroes.
        let remaining_bytes = writer.available_bytes() - size_of::<virtio_iommu_req_tail>();

        if remaining_bytes > 0 {
            let buffer: Vec<u8> = vec![0; remaining_bytes];
            writer
                .write_all(buffer.as_slice())
                .map_err(IommuError::GuestMemoryWrite)?;
        }

        Ok(properties_size)
    }

    fn execute_request(
        &mut self,
        avail_desc: &DescriptorChain,
    ) -> Result<(usize, Option<EventAsync>)> {
        let mut reader =
            Reader::new(self.mem.clone(), avail_desc.clone()).map_err(IommuError::CreateReader)?;
        let mut writer =
            Writer::new(self.mem.clone(), avail_desc.clone()).map_err(IommuError::CreateWriter)?;

        // at least we need space to write VirtioIommuReqTail
        if writer.available_bytes() < size_of::<virtio_iommu_req_tail>() {
            return Err(IommuError::WriteBufferTooSmall);
        }

        let req_head: virtio_iommu_req_head =
            reader.read_obj().map_err(IommuError::GuestMemoryRead)?;

        let mut tail = virtio_iommu_req_tail {
            status: VIRTIO_IOMMU_S_OK,
            ..Default::default()
        };

        let (reply_len, fault_resolved_event) = match req_head.type_ {
            VIRTIO_IOMMU_T_ATTACH => self.process_attach_request(&mut reader, &mut tail)?,
            VIRTIO_IOMMU_T_DETACH => self.process_detach_request(&mut reader, &mut tail)?,
            VIRTIO_IOMMU_T_MAP => (self.process_dma_map_request(&mut reader, &mut tail)?, None),
            VIRTIO_IOMMU_T_UNMAP => self.process_dma_unmap_request(&mut reader, &mut tail)?,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            VIRTIO_IOMMU_T_PROBE => (
                self.process_probe_request(&mut reader, &mut writer, &mut tail)?,
                None,
            ),
            _ => return Err(IommuError::UnexpectedDescriptor),
        };

        writer
            .write_all(tail.as_bytes())
            .map_err(IommuError::GuestMemoryWrite)?;
        Ok((
            (reply_len as usize) + size_of::<virtio_iommu_req_tail>(),
            fault_resolved_event,
        ))
    }
}

async fn request_queue<I: SignalableInterrupt>(
    state: &Rc<RefCell<State>>,
    mut queue: Queue,
    mut queue_event: EventAsync,
    interrupt: I,
) -> Result<()> {
    loop {
        let mem = state.borrow().mem.clone();
        let avail_desc = queue
            .next_async(&mem, &mut queue_event)
            .await
            .map_err(IommuError::ReadAsyncDesc)?;
        let desc_index = avail_desc.index;

        let (len, fault_resolved_event) = match state.borrow_mut().execute_request(&avail_desc) {
            Ok(res) => res,
            Err(e) => {
                error!("execute_request failed: {}", e);

                // If a request type is not recognized, the device SHOULD NOT write
                // the buffer and SHOULD set the used length to zero
                (0, None)
            }
        };

        if let Some(fault_resolved_event) = fault_resolved_event {
            debug!("waiting for iommu fault resolution");
            fault_resolved_event
                .next_val()
                .await
                .expect("failed waiting for fault");
            debug!("iommu fault resolved");
        }

        queue.add_used(&mem, desc_index, len as u32);
        queue.trigger_interrupt(&mem, &interrupt);
    }
}

fn run(
    state: State,
    iommu_device_tube: Tube,
    mut queues: Vec<(Queue, Event)>,
    kill_evt: Event,
    interrupt: Interrupt,
    translate_response_senders: Option<BTreeMap<u32, Tube>>,
    translate_request_rx: Option<Tube>,
) -> Result<()> {
    let state = Rc::new(RefCell::new(state));
    let ex = Executor::new().expect("Failed to create an executor");

    let (req_queue, req_evt) = queues.remove(0);
    let req_evt = EventAsync::new(req_evt, &ex).expect("Failed to create async event for queue");

    let f_resample = async_utils::handle_irq_resample(&ex, interrupt.clone());
    let f_kill = async_utils::await_and_exit(&ex, kill_evt);

    let request_tube = translate_request_rx
        .map(|t| AsyncTube::new(&ex, t).expect("Failed to create async tube for rx"));
    let response_tubes = translate_response_senders.map(|m| {
        m.into_iter()
            .map(|x| {
                (
                    x.0,
                    AsyncTube::new(&ex, x.1).expect("Failed to create async tube"),
                )
            })
            .collect()
    });

    let f_handle_translate_request =
        sys::handle_translate_request(&ex, &state, request_tube, response_tubes);
    let f_request = request_queue(&state, req_queue, req_evt, interrupt);

    let command_tube = AsyncTube::new(&ex, iommu_device_tube).unwrap();
    // Future to handle command messages from host, such as passing vfio containers.
    let f_cmd = sys::handle_command_tube(&state, command_tube);

    let done = async {
        select! {
            res = f_request.fuse() => res.context("error in handling request queue"),
            res = f_resample.fuse() => res.context("error in handle_irq_resample"),
            res = f_kill.fuse() => res.context("error in await_and_exit"),
            res = f_handle_translate_request.fuse() => {
                res.context("error in handle_translate_request")
            }
            res = f_cmd.fuse() => res.context("error in handling host request"),
        }
    };
    match ex.run_until(done) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!("Error in worker: {:#}", e),
        Err(e) => return Err(IommuError::AsyncExec(e)),
    }

    Ok(())
}

/// Virtio device for IOMMU memory management.
pub struct Iommu {
    worker_thread: Option<WorkerThread<()>>,
    config: virtio_iommu_config,
    avail_features: u64,
    // Attached endpoints
    // key: endpoint PCI address
    // value: reference counter and MemoryMapperTrait
    endpoints: BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
    // Hot-pluggable PCI endpoints ranges
    // RangeInclusive: (start endpoint PCI address .. =end endpoint PCI address)
    hp_endpoints_ranges: Vec<RangeInclusive<u32>>,
    translate_response_senders: Option<BTreeMap<u32, Tube>>,
    translate_request_rx: Option<Tube>,
    iommu_device_tube: Option<Tube>,
}

impl Iommu {
    /// Create a new virtio IOMMU device.
    pub fn new(
        base_features: u64,
        endpoints: BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
        iova_max_addr: u64,
        hp_endpoints_ranges: Vec<RangeInclusive<u32>>,
        translate_response_senders: Option<BTreeMap<u32, Tube>>,
        translate_request_rx: Option<Tube>,
        iommu_device_tube: Option<Tube>,
    ) -> SysResult<Iommu> {
        let mut page_size_mask = !((pagesize() as u64) - 1);
        for (_, container) in endpoints.iter() {
            page_size_mask &= container
                .lock()
                .get_mask()
                .map_err(|_e| SysError::new(libc::EIO))?;
        }

        if page_size_mask == 0 {
            return Err(SysError::new(libc::EIO));
        }

        let input_range = virtio_iommu_range_64 {
            start: Le64::from(0),
            end: iova_max_addr.into(),
        };

        let config = virtio_iommu_config {
            page_size_mask: page_size_mask.into(),
            input_range,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            probe_size: (IOMMU_PROBE_SIZE as u32).into(),
            ..Default::default()
        };

        let mut avail_features: u64 = base_features;
        avail_features |= 1 << VIRTIO_IOMMU_F_MAP_UNMAP
            | 1 << VIRTIO_IOMMU_F_INPUT_RANGE
            | 1 << VIRTIO_IOMMU_F_MMIO;

        if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
            avail_features |= 1 << VIRTIO_IOMMU_F_PROBE;
        }

        Ok(Iommu {
            worker_thread: None,
            config,
            avail_features,
            endpoints,
            hp_endpoints_ranges,
            translate_response_senders,
            translate_request_rx,
            iommu_device_tube,
        })
    }
}

impl VirtioDevice for Iommu {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = Vec::new();

        for (_, mapper) in self.endpoints.iter() {
            rds.append(&mut mapper.lock().as_raw_descriptors());
        }
        if let Some(senders) = &self.translate_response_senders {
            for (_, tube) in senders.iter() {
                rds.push(tube.as_raw_descriptor());
            }
        }
        if let Some(rx) = &self.translate_request_rx {
            rds.push(rx.as_raw_descriptor());
        }

        if let Some(iommu_device_tube) = &self.iommu_device_tube {
            rds.push(iommu_device_tube.as_raw_descriptor());
        }

        rds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Iommu
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut config: Vec<u8> = Vec::new();
        config.extend_from_slice(self.config.as_bytes());
        copy_config(data, 0, config.as_slice(), offset);
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<(Queue, Event)>,
    ) -> anyhow::Result<()> {
        if queues.len() != QUEUE_SIZES.len() {
            return Err(anyhow!(
                "expected {} queues, got {}",
                QUEUE_SIZES.len(),
                queues.len()
            ));
        }

        // The least significant bit of page_size_masks defines the page
        // granularity of IOMMU mappings
        let page_mask = (1u64 << u64::from(self.config.page_size_mask).trailing_zeros()) - 1;
        let eps = self.endpoints.clone();
        let hp_endpoints_ranges = self.hp_endpoints_ranges.to_owned();

        let translate_response_senders = self.translate_response_senders.take();
        let translate_request_rx = self.translate_request_rx.take();

        let iommu_device_tube = self
            .iommu_device_tube
            .take()
            .context("failed to start virtio-iommu worker: No control tube")?;

        self.worker_thread = Some(WorkerThread::start("v_iommu", move |kill_evt| {
            let state = State {
                mem,
                page_mask,
                hp_endpoints_ranges,
                endpoint_map: BTreeMap::new(),
                domain_map: BTreeMap::new(),
                endpoints: eps,
                dmabuf_mem: BTreeMap::new(),
            };
            let result = run(
                state,
                iommu_device_tube,
                queues,
                kill_evt,
                interrupt,
                translate_response_senders,
                translate_request_rx,
            );
            if let Err(e) = result {
                error!("virtio-iommu worker thread exited with error: {}", e);
            }
        }));
        Ok(())
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn generate_acpi(
        &mut self,
        pci_address: &Option<PciAddress>,
        mut sdts: Vec<SDT>,
    ) -> Option<Vec<SDT>> {
        const OEM_REVISION: u32 = 1;
        const VIOT_REVISION: u8 = 0;

        for sdt in sdts.iter() {
            // there should only be one VIOT table
            if sdt.is_signature(b"VIOT") {
                warn!("vIOMMU: duplicate VIOT table detected");
                return None;
            }
        }

        let mut viot = SDT::new(
            *b"VIOT",
            acpi_tables::HEADER_LEN,
            VIOT_REVISION,
            *b"CROSVM",
            *b"CROSVMDT",
            OEM_REVISION,
        );
        viot.append(VirtioIommuViotHeader {
            // # of PCI range nodes + 1 virtio-pci node
            node_count: (self.endpoints.len() + self.hp_endpoints_ranges.len() + 1) as u16,
            node_offset: (viot.len() + std::mem::size_of::<VirtioIommuViotHeader>()) as u16,
            ..Default::default()
        });

        let bdf = pci_address
            .or_else(|| {
                error!("vIOMMU device has no PCI address");
                None
            })?
            .to_u32() as u16;
        let iommu_offset = viot.len();

        viot.append(VirtioIommuViotVirtioPciNode {
            type_: VIRTIO_IOMMU_VIOT_NODE_VIRTIO_IOMMU_PCI,
            length: size_of::<VirtioIommuViotVirtioPciNode>() as u16,
            bdf,
            ..Default::default()
        });

        for (endpoint, _) in self.endpoints.iter() {
            viot.append(VirtioIommuViotPciRangeNode {
                type_: VIRTIO_IOMMU_VIOT_NODE_PCI_RANGE,
                length: size_of::<VirtioIommuViotPciRangeNode>() as u16,
                endpoint_start: *endpoint,
                bdf_start: *endpoint as u16,
                bdf_end: *endpoint as u16,
                output_node: iommu_offset as u16,
                ..Default::default()
            });
        }

        for endpoints_range in self.hp_endpoints_ranges.iter() {
            let (endpoint_start, endpoint_end) = endpoints_range.clone().into_inner();
            viot.append(VirtioIommuViotPciRangeNode {
                type_: VIRTIO_IOMMU_VIOT_NODE_PCI_RANGE,
                length: size_of::<VirtioIommuViotPciRangeNode>() as u16,
                endpoint_start,
                bdf_start: endpoint_start as u16,
                bdf_end: endpoint_end as u16,
                output_node: iommu_offset as u16,
                ..Default::default()
            });
        }

        sdts.push(viot);
        Some(sdts)
    }
}

impl Suspendable for Iommu {}
