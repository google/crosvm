// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::{
    copy_config, DescriptorChain, DescriptorError, Interrupt, Queue, Reader, SignalableInterrupt,
    VirtioDevice, Writer, TYPE_IOMMU,
};
use crate::pci::PciAddress;
use crate::vfio::{VfioContainer, VfioError};
use acpi_tables::sdt::SDT;
use base::{
    error, warn, AsRawDescriptor, Error as SysError, Event, PollToken, RawDescriptor,
    Result as SysResult, WaitContext,
};
use data_model::DataInit;
use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::io::{self, Write};
use std::mem::size_of;
use std::sync::Arc;
use std::{result, thread};
use sync::Mutex;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError};

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

/// Virtio IOMMU features
const VIRTIO_IOMMU_F_INPUT_RANGE: u32 = 0;
const VIRTIO_IOMMU_F_MAP_UNMAP: u32 = 2;
const VIRTIO_IOMMU_F_PROBE: u32 = 4;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuRange64 {
    start: u64,
    end: u64,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuRange64 {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuConfig {
    page_size_mask: u64,
    input_range: VirtioIommuRange64,
    domain_range: [u32; 2],
    probe_size: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuConfig {}

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

/// Virtio IOMMU request type
const VIRTIO_IOMMU_T_ATTACH: u8 = 1;
const VIRTIO_IOMMU_T_DETACH: u8 = 2;
const VIRTIO_IOMMU_T_MAP: u8 = 3;
const VIRTIO_IOMMU_T_UNMAP: u8 = 4;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const VIRTIO_IOMMU_T_PROBE: u8 = 5;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqHead {
    type_: u8,
    reserved: [u8; 3],
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuReqHead {}

const VIRTIO_IOMMU_S_OK: u8 = 0;
const VIRTIO_IOMMU_S_UNSUPP: u8 = 2;
const VIRTIO_IOMMU_S_INVAL: u8 = 4;
const VIRTIO_IOMMU_S_RANGE: u8 = 5;
const VIRTIO_IOMMU_S_NOENT: u8 = 6;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqTail {
    status: u8,
    reserved: [u8; 3],
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuReqTail {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqAttach {
    domain: u32,
    endpoint: u32,
    reserved: [u8; 8],
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuReqAttach {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqDetach {
    domain: u32,
    endpoint: u32,
    reserved: [u8; 8],
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuReqDetach {}

const VIRTIO_IOMMU_MAP_F_READ: u32 = 1;
const VIRTIO_IOMMU_MAP_F_WRITE: u32 = 2;
const VIRTIO_IOMMU_MAP_F_MASK: u32 = VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqMap {
    domain: u32,
    virt_start: u64,
    virt_end: u64,
    phys_start: u64,
    flags: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuReqMap {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqUnmap {
    domain: u32,
    virt_start: u64,
    virt_end: u64,
    reserved: [u8; 4],
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuReqUnmap {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuReqProbe {
    endpoint: u32,
    reserved: [u64; 8],
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuReqProbe {}

// Size of struct virtio_iommu_probe_property
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const IOMMU_PROBE_SIZE: usize = size_of::<VirtioIommuProbeResvMem>();

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioIommuProbeResvMem {
    type_: u16,
    length: u16,
    subtype: u8,
    reserved: [u8; 3],
    start: u64,
    end: u64,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VirtioIommuProbeResvMem {}

#[derive(Debug)]
pub enum IommuError {
    CreateWaitContext(SysError),
    WaitError(SysError),
    GuestMemoryRead(io::Error),
    GuestMemoryWrite(io::Error),
    CreateReader(DescriptorError),
    CreateWriter(DescriptorError),
    ReadQueueEvent(SysError),
    UnexpectedDescriptor,
    WriteBufferTooSmall,
    VfioContainerError(VfioError),
    GetHostAddress(GuestMemoryError),
}

impl Display for IommuError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::IommuError::*;

        match self {
            CreateWaitContext(e) => write!(f, "failed to create wait context: {}", e),
            WaitError(err) => write!(f, "failed to wait for events: {}", err),
            GuestMemoryWrite(e) => write!(f, "failed to write to guest address: {}", e),
            GuestMemoryRead(e) => write!(f, "failed to read from guest address: {}", e),
            CreateReader(e) => write!(f, "failed to create reader: {}", e),
            CreateWriter(e) => write!(f, "failed to create writer: {}", e),
            ReadQueueEvent(err) => write!(f, "failed to read from virtio queue Event: {}", err),
            UnexpectedDescriptor => write!(f, "unexpected descriptor error"),
            WriteBufferTooSmall => write!(f, "write buffer length too small"),
            VfioContainerError(e) => write!(f, "failed on VFIO ioctl call: {}", e),
            GetHostAddress(e) => write!(f, "failed getting host address: {}", e),
        }
    }
}

struct Worker {
    interrupt: Interrupt,
    mem: GuestMemory,
    page_mask: u64,
    // contains all pass-through endpoints that attach to the IOMMU device
    endpoints: BTreeMap<u32, Arc<Mutex<VfioContainer>>>,
    // All PCI endpoints that attach to certain IOMMU domain
    // key: endpoint PCI address
    // value: attached domain ID
    endpoint_map: BTreeMap<u32, u32>,
    // All attached domains
    // key: domain ID
    // value: reference counter and VfioContainer
    domain_map: BTreeMap<u32, (u32, Arc<Mutex<VfioContainer>>)>,
}

impl Worker {
    // Remove the endpoint from the endpoint_map and
    // decrement the reference counter (or remove the entry if the ref count is 1)
    // from domain_map
    fn dettach_endpoint(&mut self, endpoint: u32) {
        // The endpoint has attached to an IOMMU domain
        if let Some(attached_domain) = self.endpoint_map.get(&endpoint) {
            // Remove the entry or update the domain reference count
            if let Some(dm_val) = self.domain_map.get(&attached_domain) {
                match dm_val.0 {
                    0 => unreachable!(),
                    1 => self.domain_map.remove(&attached_domain),
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
        tail: &mut VirtioIommuReqTail,
    ) -> result::Result<usize, IommuError> {
        let req: VirtioIommuReqAttach = reader.read_obj().map_err(IommuError::GuestMemoryRead)?;

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
        let domain = req.domain;
        let endpoint = req.endpoint;
        if !self.endpoints.contains_key(&endpoint) {
            tail.status = VIRTIO_IOMMU_S_NOENT;
            return Ok(0);
        }

        // If the endpoint identified by endpoint is already attached
        // to another domain, then the device SHOULD first detach it
        // from that domain and attach it to the one identified by domain.
        if self.endpoint_map.contains_key(&endpoint) {
            self.dettach_endpoint(endpoint);
        }

        if let Some(vfio_container) = self.endpoints.get(&endpoint) {
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
        tail: &mut VirtioIommuReqTail,
    ) -> result::Result<usize, IommuError> {
        let req: VirtioIommuReqMap = reader.read_obj().map_err(IommuError::GuestMemoryRead)?;

        // If virt_start, phys_start or (virt_end + 1) is not aligned
        // on the page granularity, the device SHOULD reject the
        // request and set status to VIRTIO_IOMMU_S_RANGE
        if self.page_mask & req.phys_start != 0
            || self.page_mask & req.virt_start != 0
            || self.page_mask & (req.virt_end + 1) != 0
        {
            tail.status = VIRTIO_IOMMU_S_RANGE;
            return Ok(0);
        }

        // If the device doesn’t recognize a flags bit, it MUST reject
        // the request and set status to VIRTIO_IOMMU_S_INVAL.
        if req.flags & !VIRTIO_IOMMU_MAP_F_MASK != 0 {
            tail.status = VIRTIO_IOMMU_S_INVAL;
            return Ok(0);
        }

        let domain = req.domain;
        if !self.domain_map.contains_key(&domain) {
            // If domain does not exist, the device SHOULD reject
            // the request and set status to VIRTIO_IOMMU_S_NOENT.
            tail.status = VIRTIO_IOMMU_S_NOENT;
            return Ok(0);
        }

        // The device MUST NOT allow writes to a range mapped
        // without the VIRTIO_IOMMU_MAP_F_WRITE flag.
        let write_en = req.flags & VIRTIO_IOMMU_MAP_F_WRITE != 0;

        if let Some(vfio_container) = self.domain_map.get(&domain) {
            let size = req.virt_end - req.virt_start + 1u64;
            let host_addr = self
                .mem
                .get_host_address_range(GuestAddress(req.phys_start), size as usize)
                .map_err(IommuError::GetHostAddress)?;

            // Safe because both guest and host address are guaranteed by
            // get_host_address_range() to be valid
            let vfio_map_result = unsafe {
                vfio_container.1.lock().vfio_dma_map(
                    req.virt_start,
                    size,
                    host_addr as u64,
                    write_en,
                )
            };

            match vfio_map_result {
                Ok(()) => (),
                Err(e) => match sys_util::Error::last() {
                    err if err.errno() == libc::EEXIST => {
                        // If a mapping already exists in the requested range,
                        // the device SHOULD reject the request and set status
                        // to VIRTIO_IOMMU_S_INVAL.
                        tail.status = VIRTIO_IOMMU_S_INVAL;
                        return Ok(0);
                    }
                    _ => return Err(IommuError::VfioContainerError(e)),
                },
            }
        }

        Ok(0)
    }

    fn process_dma_unmap_request(
        &mut self,
        reader: &mut Reader,
        tail: &mut VirtioIommuReqTail,
    ) -> result::Result<usize, IommuError> {
        let req: VirtioIommuReqUnmap = reader.read_obj().map_err(IommuError::GuestMemoryRead)?;

        let domain = req.domain;
        if let Some(vfio_container) = self.domain_map.get(&domain) {
            let size = req.virt_end - req.virt_start + 1;
            vfio_container
                .1
                .lock()
                .vfio_dma_unmap(req.virt_start, size)
                .map_err(IommuError::VfioContainerError)?;
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
        tail: &mut VirtioIommuReqTail,
    ) -> result::Result<usize, IommuError> {
        let req: VirtioIommuReqProbe = reader.read_obj().map_err(IommuError::GuestMemoryRead)?;
        let endpoint = req.endpoint;

        // If the endpoint identified by endpoint doesn’t exist,
        // then the device SHOULD reject the request and set status
        // to VIRTIO_IOMMU_S_NOENT.
        if !self.endpoints.contains_key(&endpoint) {
            tail.status = VIRTIO_IOMMU_S_NOENT;
        }

        let properties_size = writer.available_bytes() - size_of::<VirtioIommuReqTail>();

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

            let properties = VirtioIommuProbeResvMem {
                type_: VIRTIO_IOMMU_PROBE_T_RESV_MEM,
                length: IOMMU_PROBE_SIZE as u16 - PROBE_PROPERTY_SIZE,
                subtype: VIRTIO_IOMMU_RESV_MEM_T_MSI,
                start: X86_MSI_IOVA_START,
                end: X86_MSI_IOVA_END,
                ..Default::default()
            };
            writer
                .write_all(properties.as_slice())
                .map_err(IommuError::GuestMemoryWrite)?;
        }

        // If the device doesn’t fill all probe_size bytes with properties,
        // it SHOULD fill the remaining bytes of properties with zeroes.
        let remaining_bytes = writer.available_bytes() - size_of::<VirtioIommuReqTail>();

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
    ) -> result::Result<usize, IommuError> {
        let mut reader =
            Reader::new(self.mem.clone(), avail_desc.clone()).map_err(IommuError::CreateReader)?;
        let mut writer =
            Writer::new(self.mem.clone(), avail_desc.clone()).map_err(IommuError::CreateWriter)?;

        // at least we need space to write VirtioIommuReqTail
        if writer.available_bytes() < size_of::<VirtioIommuReqTail>() {
            return Err(IommuError::WriteBufferTooSmall);
        }

        let req_head: VirtioIommuReqHead =
            reader.read_obj().map_err(IommuError::GuestMemoryRead)?;

        let mut tail = VirtioIommuReqTail {
            status: VIRTIO_IOMMU_S_OK,
            ..Default::default()
        };

        let reply_len = match req_head.type_ {
            VIRTIO_IOMMU_T_ATTACH => self.process_attach_request(&mut reader, &mut tail)?,
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
                self.process_probe_request(&mut reader, &mut writer, &mut tail)?
            }
            _ => return Err(IommuError::UnexpectedDescriptor),
        };

        writer
            .write_all(tail.as_slice())
            .map_err(IommuError::GuestMemoryWrite)?;
        Ok((reply_len as usize) + size_of::<VirtioIommuReqTail>())
    }

    fn request_queue(&mut self, req_queue: &mut Queue) -> bool {
        let mut needs_interrupt = false;
        while let Some(avail_desc) = req_queue.pop(&self.mem) {
            let desc_index = avail_desc.index;

            let len = match self.execute_request(&avail_desc) {
                Ok(len) => len as u32,
                Err(e) => {
                    error!("{}", e);

                    // If a request type is not recognized, the device SHOULD NOT write
                    // the buffer and SHOULD set the used length to zero
                    0
                }
            };

            req_queue.add_used(&self.mem, desc_index, len as u32);
            needs_interrupt = true;
        }

        needs_interrupt
    }

    fn run(
        &mut self,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<Event>,
        kill_evt: Event,
    ) -> Result<(), IommuError> {
        #[derive(PollToken)]
        enum Token {
            RequestQueue,
            InterruptResample,
            Kill,
        }

        let (mut req_queue, req_evt) = (queues.remove(0), queue_evts.remove(0));
        let wait_ctx: WaitContext<Token> =
            WaitContext::build_with(&[(&req_evt, Token::RequestQueue), (&kill_evt, Token::Kill)])
                .map_err(IommuError::CreateWaitContext)?;

        if let Some(resample_evt) = self.interrupt.get_resample_evt() {
            wait_ctx
                .add(resample_evt, Token::InterruptResample)
                .map_err(IommuError::CreateWaitContext)?;
        }

        'wait: loop {
            let mut needs_interrupt = false;
            let events = wait_ctx.wait().map_err(IommuError::WaitError)?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::RequestQueue => {
                        req_evt.read().map_err(IommuError::ReadQueueEvent)?;
                        needs_interrupt |= self.request_queue(&mut req_queue);
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => break 'wait,
                }
            }
            if needs_interrupt {
                req_queue.trigger_interrupt(&self.mem, &self.interrupt);
            }
        }
        Ok(())
    }
}

/// Virtio device for IOMMU memory management.
pub struct Iommu {
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
    config: VirtioIommuConfig,
    avail_features: u64,
    endpoints: BTreeMap<u32, Arc<Mutex<VfioContainer>>>,
}

impl Iommu {
    /// Create a new virtio IOMMU device.
    pub fn new(
        base_features: u64,
        endpoints: BTreeMap<u32, Arc<Mutex<VfioContainer>>>,
        phys_max_addr: u64,
    ) -> SysResult<Iommu> {
        let mut page_size_mask = !0_u64;
        for (_, container) in endpoints.iter() {
            page_size_mask &= container
                .lock()
                .vfio_get_iommu_page_size_mask()
                .map_err(|_e| SysError::new(libc::EIO))?;
        }

        if page_size_mask == 0 {
            error!("failed to get IOMMU device valid page size masks");
            return Err(SysError::new(libc::EIO));
        }

        let input_range = VirtioIommuRange64 {
            start: 0_u64,
            end: phys_max_addr,
        };

        let config = VirtioIommuConfig {
            page_size_mask,
            input_range,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            probe_size: IOMMU_PROBE_SIZE as u32,
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

        for (_, vfio) in self.endpoints.iter() {
            rds.push(vfio.lock().as_raw_descriptor());
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
        let page_mask = (1u64 << self.config.page_size_mask.trailing_zeros()) - 1;
        let eps = self.endpoints.clone();
        let worker_result = thread::Builder::new()
            .name("virtio_iommu".to_string())
            .spawn(move || {
                let mut worker = Worker {
                    interrupt,
                    mem,
                    page_mask,
                    endpoints: eps,
                    endpoint_map: BTreeMap::new(),
                    domain_map: BTreeMap::new(),
                };
                let result = worker.run(queues, queue_evts, kill_evt);
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
            node_count: (self.endpoints.len() + 1) as u16,
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
        sdts.push(viot);
        Some(sdts)
    }
}
