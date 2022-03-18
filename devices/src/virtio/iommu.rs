// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Write};
use std::mem::size_of;
use std::ops::RangeInclusive;
use std::rc::Rc;
use std::sync::Arc;
use std::{result, thread};

use acpi_tables::sdt::SDT;
use anyhow::Context;
use base::{
    error, pagesize, warn, AsRawDescriptor, Error as SysError, Event, RawDescriptor,
    Result as SysResult, Tube, TubeError,
};
use cros_async::{AsyncError, AsyncTube, EventAsync, Executor};
use data_model::{DataInit, Le64};
use futures::{select, FutureExt};
use remain::sorted;
use sync::Mutex;
use thiserror::Error;
use vm_control::{
    VirtioIOMMURequest, VirtioIOMMUResponse, VirtioIOMMUVfioCommand, VirtioIOMMUVfioResult,
};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError};

use crate::pci::PciAddress;
use crate::virtio::{
    async_utils, copy_config, DescriptorChain, DescriptorError, Interrupt, Queue, Reader,
    SignalableInterrupt, VirtioDevice, Writer, TYPE_IOMMU,
};
use crate::VfioContainer;

pub mod protocol;
use crate::virtio::iommu::protocol::*;
pub mod ipc_memory_mapper;
use crate::virtio::iommu::ipc_memory_mapper::*;
pub mod memory_mapper;
pub mod memory_util;
pub mod vfio_wrapper;
use crate::virtio::iommu::memory_mapper::{Error as MemoryMapperError, *};

use self::vfio_wrapper::VfioWrapper;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

// Size of struct virtio_iommu_probe_property
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const IOMMU_PROBE_SIZE: usize = size_of::<virtio_iommu_probe_resv_mem>();

const VIRTIO_IOMMU_VIOT_NODE_PCI_RANGE: u8 = 1;
const VIRTIO_IOMMU_VIOT_NODE_VIRTIO_IOMMU_PCI: u8 = 3;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuViotHeader {
    node_count: u16,
    node_offset: u16,
    reserved: [u8; 8],
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuViotHeader {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuViotVirtioPciNode {
    type_: u8,
    reserved: [u8; 1],
    length: u16,
    segment: u16,
    bdf: u16,
    reserved2: [u8; 8],
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuViotVirtioPciNode {}

#[derive(Copy, Clone, Debug, Default)]
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

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuViotPciRangeNode {}

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
    MemoryMapper(MemoryMapperError),
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

struct Worker {
    mem: GuestMemory,
    page_mask: u64,
    // Hot-pluggable PCI endpoints ranges
    // RangeInclusive: (start endpoint PCI address .. =end endpoint PCI address)
    hp_endpoints_ranges: Vec<RangeInclusive<u32>>,
    // All PCI endpoints that attach to certain IOMMU domain
    // key: endpoint PCI address
    // value: attached domain ID
    endpoint_map: BTreeMap<u32, u32>,
    // All attached domains
    // key: domain ID
    // value: reference counter and MemoryMapperTrait
    domain_map: BTreeMap<u32, (u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>)>,
}

impl Worker {
    // Remove the endpoint from the endpoint_map and
    // decrement the reference counter (or remove the entry if the ref count is 1)
    // from domain_map
    fn detach_endpoint(&mut self, endpoint: u32) {
        // The endpoint has attached to an IOMMU domain
        if let Some(attached_domain) = self.endpoint_map.get(&endpoint) {
            // Remove the entry or update the domain reference count
            if let Some(dm_val) = self.domain_map.get(attached_domain) {
                match dm_val.0 {
                    0 => unreachable!(),
                    1 => self.domain_map.remove(attached_domain),
                    _ => {
                        let new_refs = dm_val.0 - 1;
                        let vfio = dm_val.1.clone();
                        self.domain_map.insert(*attached_domain, (new_refs, vfio))
                    }
                };
            }
        }

        self.endpoint_map.remove(&endpoint);
    }

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
        endpoints: &Rc<RefCell<BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>>>,
    ) -> Result<usize> {
        let req: virtio_iommu_req_attach =
            reader.read_obj().map_err(IommuError::GuestMemoryRead)?;

        // If the reserved field of an ATTACH request is not zero,
        // the device MUST reject the request and set status to
        // VIRTIO_IOMMU_S_INVAL.
        if req.reserved.iter().any(|&x| x != 0) {
            tail.status = VIRTIO_IOMMU_S_INVAL;
            return Ok(0);
        }

        // If the endpoint identified by endpoint doesn’t exist,
        // the device MUST reject the request and set status to
        // VIRTIO_IOMMU_S_NOENT.
        let domain: u32 = req.domain.into();
        let endpoint: u32 = req.endpoint.into();
        if !endpoints.borrow().contains_key(&endpoint) {
            tail.status = VIRTIO_IOMMU_S_NOENT;
            return Ok(0);
        }

        // If the endpoint identified by endpoint is already attached
        // to another domain, then the device SHOULD first detach it
        // from that domain and attach it to the one identified by domain.
        if self.endpoint_map.contains_key(&endpoint) {
            self.detach_endpoint(endpoint);
        }

        if let Some(vfio_container) = endpoints.borrow_mut().get(&endpoint) {
            let new_ref = match self.domain_map.get(&domain) {
                None => 1,
                Some(val) => val.0 + 1,
            };

            self.endpoint_map.insert(endpoint, domain);
            self.domain_map
                .insert(domain, (new_ref, vfio_container.clone()));
        }

        Ok(0)
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

            let vfio_map_result = mapper.1.lock().add_map(MappingInfo {
                iova: req.virt_start.into(),
                gpa: GuestAddress(req.phys_start.into()),
                size,
                perm: match write_en {
                    true => Permission::RW,
                    false => Permission::Read,
                },
            });

            match vfio_map_result {
                Ok(()) => (),
                Err(e) => match e {
                    MemoryMapperError::IovaRegionOverlap => {
                        // If a mapping already exists in the requested range,
                        // the device SHOULD reject the request and set status
                        // to VIRTIO_IOMMU_S_INVAL.
                        tail.status = VIRTIO_IOMMU_S_INVAL;
                        return Ok(0);
                    }
                    _ => return Err(IommuError::MemoryMapper(e)),
                },
            }
        }

        Ok(0)
    }

    fn process_dma_unmap_request(
        &mut self,
        reader: &mut Reader,
        tail: &mut virtio_iommu_req_tail,
    ) -> Result<usize> {
        let req: virtio_iommu_req_unmap = reader.read_obj().map_err(IommuError::GuestMemoryRead)?;

        let domain: u32 = req.domain.into();
        if let Some(mapper) = self.domain_map.get(&domain) {
            let size = u64::from(req.virt_end) - u64::from(req.virt_start) + 1;
            mapper
                .1
                .lock()
                .remove_map(u64::from(req.virt_start), size)
                .map_err(IommuError::MemoryMapper)?;
        } else {
            // If domain does not exist, the device SHOULD set the
            // request status to VIRTIO_IOMMU_S_NOENT
            tail.status = VIRTIO_IOMMU_S_NOENT;
        }

        Ok(0)
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn process_probe_request(
        &mut self,
        reader: &mut Reader,
        writer: &mut Writer,
        tail: &mut virtio_iommu_req_tail,
        endpoints: &Rc<RefCell<BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>>>,
    ) -> Result<usize> {
        let req: virtio_iommu_req_probe = reader.read_obj().map_err(IommuError::GuestMemoryRead)?;
        let endpoint: u32 = req.endpoint.into();

        // If the endpoint identified by endpoint doesn’t exist,
        // then the device SHOULD reject the request and set status
        // to VIRTIO_IOMMU_S_NOENT.
        if !endpoints.borrow().contains_key(&endpoint) {
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
                .write_all(properties.as_slice())
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
        endpoints: &Rc<RefCell<BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>>>,
    ) -> Result<usize> {
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

        let reply_len = match req_head.type_ {
            VIRTIO_IOMMU_T_ATTACH => {
                self.process_attach_request(&mut reader, &mut tail, endpoints)?
            }
            VIRTIO_IOMMU_T_DETACH => {
                // A few reasons why we don't support VIRTIO_IOMMU_T_DETACH for now:
                //
                // 1. Linux virtio IOMMU front-end driver doesn't implement VIRTIO_IOMMU_T_DETACH request
                // 2. Seems it's not possible to dynamically attach and detach a IOMMU domain if the
                //    virtio IOMMU device is running on top of VFIO
                // 3. Even if VIRTIO_IOMMU_T_DETACH is implemented in front-end driver, it could violate
                //    the following virtio IOMMU spec: Detach an endpoint from a domain. when this request
                //    completes, the endpoint cannot access any mapping from that domain anymore.
                //
                //    This is because VFIO doesn't support detaching a single device. When the virtio-iommu
                //    device receives a VIRTIO_IOMMU_T_DETACH request, it can either to:
                //    - detach a group: any other endpoints in the group lose access to the domain.
                //    - do not detach the group at all: this breaks the above mentioned spec.
                tail.status = VIRTIO_IOMMU_S_UNSUPP;
                0
            }
            VIRTIO_IOMMU_T_MAP => self.process_dma_map_request(&mut reader, &mut tail)?,
            VIRTIO_IOMMU_T_UNMAP => self.process_dma_unmap_request(&mut reader, &mut tail)?,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            VIRTIO_IOMMU_T_PROBE => {
                self.process_probe_request(&mut reader, &mut writer, &mut tail, endpoints)?
            }
            _ => return Err(IommuError::UnexpectedDescriptor),
        };

        writer
            .write_all(tail.as_slice())
            .map_err(IommuError::GuestMemoryWrite)?;
        Ok((reply_len as usize) + size_of::<virtio_iommu_req_tail>())
    }

    async fn request_queue<I: SignalableInterrupt>(
        &mut self,
        mut queue: Queue,
        mut queue_event: EventAsync,
        interrupt: &I,
        endpoints: &Rc<RefCell<BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>>>,
    ) -> Result<()> {
        loop {
            let avail_desc = queue
                .next_async(&self.mem, &mut queue_event)
                .await
                .map_err(IommuError::ReadAsyncDesc)?;
            let desc_index = avail_desc.index;

            let len = match self.execute_request(&avail_desc, endpoints) {
                Ok(len) => len as u32,
                Err(e) => {
                    error!("execute_request failed: {}", e);

                    // If a request type is not recognized, the device SHOULD NOT write
                    // the buffer and SHOULD set the used length to zero
                    0
                }
            };

            queue.add_used(&self.mem, desc_index, len as u32);
            queue.trigger_interrupt(&self.mem, interrupt);
        }
    }

    fn handle_add_vfio_device(
        mem: &GuestMemory,
        endpoint_addr: u32,
        container_fd: File,
        endpoints: &Rc<RefCell<BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>>>,
        hp_endpoints_ranges: &Rc<Vec<RangeInclusive<u32>>>,
    ) -> VirtioIOMMUVfioResult {
        let exists = |endpoint_addr: u32| -> bool {
            for endpoints_range in hp_endpoints_ranges.iter() {
                if endpoints_range.contains(&endpoint_addr) {
                    return true;
                }
            }
            false
        };

        if !exists(endpoint_addr) {
            return VirtioIOMMUVfioResult::NotInPCIRanges;
        }

        let vfio_container = match VfioContainer::new_from_container(container_fd) {
            Ok(vfio_container) => vfio_container,
            Err(e) => {
                error!("failed to verify the new container: {}", e);
                return VirtioIOMMUVfioResult::NoAvailableContainer;
            }
        };
        endpoints.borrow_mut().insert(
            endpoint_addr,
            Arc::new(Mutex::new(Box::new(VfioWrapper::new(
                Arc::new(Mutex::new(vfio_container)),
                mem.clone(),
            )))),
        );
        VirtioIOMMUVfioResult::Ok
    }

    fn handle_del_vfio_device(
        pci_address: u32,
        endpoints: &Rc<RefCell<BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>>>,
    ) -> VirtioIOMMUVfioResult {
        if endpoints.borrow_mut().remove(&pci_address).is_none() {
            error!("There is no vfio container of {}", pci_address);
            return VirtioIOMMUVfioResult::NoSuchDevice;
        }
        VirtioIOMMUVfioResult::Ok
    }

    fn handle_vfio(
        mem: &GuestMemory,
        vfio_cmd: VirtioIOMMUVfioCommand,
        endpoints: &Rc<RefCell<BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>>>,
        hp_endpoints_ranges: &Rc<Vec<RangeInclusive<u32>>>,
    ) -> VirtioIOMMUResponse {
        use VirtioIOMMUVfioCommand::*;
        let vfio_result = match vfio_cmd {
            VfioDeviceAdd {
                endpoint_addr,
                container,
            } => Self::handle_add_vfio_device(
                mem,
                endpoint_addr,
                container,
                endpoints,
                hp_endpoints_ranges,
            ),
            VfioDeviceDel { endpoint_addr } => {
                Self::handle_del_vfio_device(endpoint_addr, endpoints)
            }
        };
        VirtioIOMMUResponse::VfioResponse(vfio_result)
    }

    // Async task that handles messages from the host
    async fn handle_command_tube(
        mem: &GuestMemory,
        command_tube: AsyncTube,
        endpoints: &Rc<RefCell<BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>>>,
        hp_endpoints_ranges: &Rc<Vec<RangeInclusive<u32>>>,
    ) -> Result<()> {
        loop {
            match command_tube.next::<VirtioIOMMURequest>().await {
                Ok(command) => {
                    let response: VirtioIOMMUResponse = match command {
                        VirtioIOMMURequest::VfioCommand(vfio_cmd) => {
                            Self::handle_vfio(mem, vfio_cmd, endpoints, hp_endpoints_ranges)
                        }
                    };
                    if let Err(e) = command_tube.send(response).await {
                        error!("{}", IommuError::VirtioIOMMUResponseError(e));
                    }
                }
                Err(e) => {
                    return Err(IommuError::VirtioIOMMUReqError(e));
                }
            }
        }
    }

    fn run(
        &mut self,
        iommu_device_tube: Tube,
        mut queues: Vec<Queue>,
        queue_evts: Vec<Event>,
        kill_evt: Event,
        interrupt: Interrupt,
        endpoints: BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
        translate_response_senders: Option<BTreeMap<u32, Tube>>,
        translate_request_rx: Option<Tube>,
    ) -> Result<()> {
        let ex = Executor::new().expect("Failed to create an executor");

        let mut evts_async: Vec<EventAsync> = queue_evts
            .into_iter()
            .map(|e| EventAsync::new(e.0, &ex).expect("Failed to create async event for queue"))
            .collect();
        let interrupt = Rc::new(RefCell::new(interrupt));
        let interrupt_ref = &*interrupt.borrow();

        let (req_queue, req_evt) = (queues.remove(0), evts_async.remove(0));

        let hp_endpoints_ranges = Rc::new(self.hp_endpoints_ranges.clone());
        let mem = Rc::new(self.mem.clone());
        // contains all pass-through endpoints that attach to this IOMMU device
        // key: endpoint PCI address
        // value: reference counter and MemoryMapperTrait
        let endpoints: Rc<RefCell<BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>>> =
            Rc::new(RefCell::new(endpoints));

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
            handle_translate_request(&endpoints, request_tube, response_tubes);
        let f_request = self.request_queue(req_queue, req_evt, interrupt_ref, &endpoints);

        let command_tube = AsyncTube::new(&ex, iommu_device_tube).unwrap();
        // Future to handle command messages from host, such as passing vfio containers.
        let f_cmd = Self::handle_command_tube(&mem, command_tube, &endpoints, &hp_endpoints_ranges);

        let done = async {
            select! {
                res = f_request.fuse() => res.context("error in handling request queue"),
                res = f_resample.fuse() => res.context("error in handle_irq_resample"),
                res = f_kill.fuse() => res.context("error in await_and_exit"),
                res = f_handle_translate_request.fuse() => res.context("error in handle_translate_request"),
                res = f_cmd.fuse() => res.context("error in handling host request"),
            }
        };
        match ex.run_until(done) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!("Error in worker: {}", e),
            Err(e) => return Err(IommuError::AsyncExec(e)),
        }

        Ok(())
    }
}

async fn handle_translate_request(
    endpoints: &Rc<RefCell<BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>>>,
    request_tube: Option<AsyncTube>,
    response_tubes: Option<BTreeMap<u32, AsyncTube>>,
) -> Result<()> {
    let request_tube = match request_tube {
        Some(r) => r,
        None => {
            let () = futures::future::pending().await;
            return Ok(());
        }
    };
    let response_tubes = response_tubes.unwrap();
    loop {
        let TranslateRequest {
            endpoint_id,
            iova,
            size,
        } = request_tube.next().await.map_err(IommuError::Tube)?;
        if let Some(mapper) = endpoints.borrow_mut().get(&endpoint_id) {
            response_tubes
                .get(&endpoint_id)
                .unwrap()
                .send(
                    mapper
                        .lock()
                        .translate(iova, size)
                        .map_err(|e| {
                            error!("Failed to handle TranslateRequest: {}", e);
                            e
                        })
                        .ok(),
                )
                .await
                .map_err(IommuError::Tube)?;
        } else {
            error!("endpoint_id {} not found", endpoint_id)
        }
    }
}

/// Virtio device for IOMMU memory management.
pub struct Iommu {
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
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
        phys_max_addr: u64,
        hp_endpoints_ranges: Vec<RangeInclusive<u32>>,
        translate_response_senders: Option<BTreeMap<u32, Tube>>,
        translate_request_rx: Option<Tube>,
        iommu_device_tube: Option<Tube>,
    ) -> SysResult<Iommu> {
        let mut page_size_mask = !0_u64;
        for (_, container) in endpoints.iter() {
            page_size_mask &= container
                .lock()
                .get_mask()
                .map_err(|_e| SysError::new(libc::EIO))?;
        }

        if page_size_mask == 0 {
            // In case no endpoints bounded to vIOMMU during system booting,
            // assume IOVA page size is the same as page_size
            page_size_mask = (pagesize() as u64) - 1;
        }

        let input_range = virtio_iommu_range_64 {
            start: Le64::from(0),
            end: phys_max_addr.into(),
        };

        let config = virtio_iommu_config {
            page_size_mask: page_size_mask.into(),
            input_range,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            probe_size: (IOMMU_PROBE_SIZE as u32).into(),
            ..Default::default()
        };

        let mut avail_features: u64 = base_features;
        avail_features |= 1 << VIRTIO_IOMMU_F_MAP_UNMAP | 1 << VIRTIO_IOMMU_F_INPUT_RANGE;

        if cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
            avail_features |= 1 << VIRTIO_IOMMU_F_PROBE;
        }

        Ok(Iommu {
            kill_evt: None,
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

impl Drop for Iommu {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            let _ = kill_evt.write(1);
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
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

    fn device_type(&self) -> u32 {
        TYPE_IOMMU
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut config: Vec<u8> = Vec::new();
        config.extend_from_slice(self.config.as_slice());
        copy_config(data, 0, config.as_slice(), offset);
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
    ) {
        if queues.len() != QUEUE_SIZES.len() || queue_evts.len() != QUEUE_SIZES.len() {
            return;
        }

        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed to create kill Event pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        // The least significant bit of page_size_masks defines the page
        // granularity of IOMMU mappings
        let page_mask = (1u64 << u64::from(self.config.page_size_mask).trailing_zeros()) - 1;
        let eps = self.endpoints.clone();
        let hp_endpoints_ranges = self.hp_endpoints_ranges.to_owned();

        let translate_response_senders = self.translate_response_senders.take();
        let translate_request_rx = self.translate_request_rx.take();

        match self.iommu_device_tube.take() {
            Some(iommu_device_tube) => {
                let worker_result = thread::Builder::new()
                    .name("virtio_iommu".to_string())
                    .spawn(move || {
                        let mut worker = Worker {
                            mem,
                            page_mask,
                            hp_endpoints_ranges,
                            endpoint_map: BTreeMap::new(),
                            domain_map: BTreeMap::new(),
                        };
                        let result = worker.run(
                            iommu_device_tube,
                            queues,
                            queue_evts,
                            kill_evt,
                            interrupt,
                            eps,
                            translate_response_senders,
                            translate_request_rx,
                        );
                        if let Err(e) = result {
                            error!("virtio-iommu worker thread exited with error: {}", e);
                        }
                        worker
                    });

                match worker_result {
                    Err(e) => error!("failed to spawn virtio_iommu worker thread: {}", e),
                    Ok(join_handle) => self.worker_thread = Some(join_handle),
                }
            }
            None => {
                error!("failed to start virtio-iommu worker: No control tube");
                return;
            }
        }
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
