// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This is the CoIOMMU backend implementation. CoIOMMU is a virtual device
//! which provide fine-grained pinning for the VFIO pci-passthrough device
//! so that hypervisor doesn't need to pin the enter VM's memory to improve
//! the memory utilization. CoIOMMU doesn't provide the intra-guest protection
//! so it can only be used for the TRUSTED passthrough devices.
//!
//! CoIOMMU is presented at KVM forum 2020:
//! https://kvmforum2020.sched.com/event/eE2z/a-virtual-iommu-with-cooperative
//! -dma-buffer-tracking-yu-zhang-intel
//!
//! Also presented at usenix ATC20:
//! https://www.usenix.org/conference/atc20/presentation/tian

use std::convert::TryInto;
use std::default::Default;
use std::panic;
use std::sync::atomic::{fence, AtomicU32, Ordering};
use std::sync::Arc;
use std::{mem, thread};

use anyhow::{anyhow, bail, ensure, Context, Result};
use base::{
    error, info, AsRawDescriptor, Event, MemoryMapping, MemoryMappingBuilder, PollToken,
    RawDescriptor, SafeDescriptor, SharedMemory, Tube, WaitContext,
};
use data_model::DataInit;
use hypervisor::Datamatch;
use resources::{Alloc, MmioType, SystemAllocator};
use sync::Mutex;
use thiserror::Error as ThisError;

use vm_control::{VmMemoryRequest, VmMemoryResponse};
use vm_memory::{GuestAddress, GuestMemory};

use crate::pci::pci_configuration::{
    PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciClassCode, PciConfiguration,
    PciHeaderType, PciOtherSubclass, COMMAND_REG, COMMAND_REG_MEMORY_SPACE_MASK,
};
use crate::pci::pci_device::{PciDevice, Result as PciResult};
use crate::pci::{PciAddress, PciDeviceError};
use crate::vfio::VfioContainer;

const PCI_VENDOR_ID_COIOMMU: u16 = 0x1234;
const PCI_DEVICE_ID_COIOMMU: u16 = 0xabcd;
const COIOMMU_REVISION_ID: u8 = 0x10;
const COIOMMU_MMIO_BAR: u8 = 0;
const COIOMMU_MMIO_BAR_SIZE: u64 = 0x2000;
const COIOMMU_NOTIFYMAP_BAR: u8 = 2;
const COIOMMU_NOTIFYMAP_SIZE: usize = 0x2000;
const COIOMMU_TOPOLOGYMAP_BAR: u8 = 4;
const COIOMMU_TOPOLOGYMAP_SIZE: usize = 0x2000;
const PAGE_SIZE_4K: u64 = 4096;
const PAGE_SHIFT_4K: u64 = 12;
const PIN_PAGES_IN_BATCH: u64 = 1 << 63;

const DTTE_PINNED_FLAG: u32 = 1 << 31;
const DTT_ENTRY_PRESENT: u64 = 1;
const DTT_ENTRY_PFN_SHIFT: u64 = 12;

#[derive(ThisError, Debug)]
enum Error {
    #[error("CoIommu failed to create shared memory")]
    CreateSharedMemory,
    #[error("Failed to get DTT entry")]
    GetDTTEntry,
    #[error("Tube error")]
    TubeError,
}

#[derive(Default, Debug, Copy, Clone)]
struct CoIommuReg {
    dtt_root: u64,
    cmd: u64,
    dtt_level: u64,
}

unsafe fn vfio_map(
    vfio_container: &Arc<Mutex<VfioContainer>>,
    iova: u64,
    size: u64,
    user_addr: u64,
) -> bool {
    match vfio_container
        .lock()
        .vfio_dma_map(iova, size, user_addr, true)
    {
        Ok(_) => true,
        Err(e) => {
            if let Some(errno) = std::io::Error::last_os_error().raw_os_error() {
                if errno == libc::EEXIST {
                    // Already pinned. set PINNED flag
                    error!("CoIommu: iova 0x{:x} already pinned", iova);
                    return true;
                }
            }
            error!("CoIommu: failed to map iova 0x{:x}: {}", iova, e);
            false
        }
    }
}

#[derive(Default, Debug, Copy, Clone)]
#[repr(C)]
struct PinPageInfo {
    bdf: u16,
    pad: [u16; 3],
    nr_pages: u64,
}
// Safe because the PinPageInfo structure is raw data
unsafe impl DataInit for PinPageInfo {}

const COIOMMU_UPPER_LEVEL_STRIDE: u64 = 9;
const COIOMMU_UPPER_LEVEL_MASK: u64 = (1 << COIOMMU_UPPER_LEVEL_STRIDE) - 1;
const COIOMMU_PT_LEVEL_STRIDE: u64 = 10;
const COIOMMU_PT_LEVEL_MASK: u64 = (1 << COIOMMU_PT_LEVEL_STRIDE) - 1;

fn level_to_offset(gfn: u64, level: u64) -> Result<u64> {
    if level == 1 {
        return Ok(gfn & COIOMMU_PT_LEVEL_MASK);
    }

    if level == 0 {
        bail!("Invalid level for gfn 0x{:x}", gfn);
    }

    let offset = COIOMMU_PT_LEVEL_STRIDE + (level - 2) * COIOMMU_UPPER_LEVEL_STRIDE;

    Ok((gfn >> offset) & COIOMMU_UPPER_LEVEL_MASK)
}

struct DTTIter {
    ptr: *const u8,
    gfn: u64,
}

impl Default for DTTIter {
    fn default() -> Self {
        DTTIter {
            ptr: std::ptr::null(),
            gfn: 0,
        }
    }
}

// Get a DMA Tracking Table(DTT) entry associated with the gfn.
//
// There are two ways to get the entry:
// #1. Walking the DMA Tracking Table(DTT) by the GFN to get the
// corresponding entry. The DTT is shared between frontend and
// backend. It is page-table-like strctures and the entry is indexed
// by GFN. The argument dtt_root represents the root page
// pga and dtt_level represents the maximum page table level.
//
// #2. Calculate the entry address via the argument dtt_iter. dtt_iter
// stores an entry address and the associated gfn. If the target gfn is
// in the same page table page with the gfn in dtt_iter, then can
// calculate the target entry address based on the entry address in
// dtt_iter.
//
// As the DTT entry is shared between frontend and backend, the accessing
// should be atomic. So the returned value is converted to an AtomicU32
// pointer.
fn gfn_to_dtt_pte(
    mem: &GuestMemory,
    dtt_level: u64,
    dtt_root: u64,
    dtt_iter: &mut DTTIter,
    gfn: u64,
) -> Result<*const AtomicU32> {
    let ptr = if dtt_iter.ptr.is_null()
        || dtt_iter.gfn >> COIOMMU_PT_LEVEL_STRIDE != gfn >> COIOMMU_PT_LEVEL_STRIDE
    {
        // Slow path to walk the DTT to get the pte entry
        let mut level = dtt_level;
        let mut pt_gpa = dtt_root;
        let dtt_nonleaf_entry_size = mem::size_of::<u64>() as u64;

        while level != 1 {
            let index = level_to_offset(gfn, level)? * dtt_nonleaf_entry_size;
            let parent_pt = mem
                .read_obj_from_addr::<u64>(GuestAddress(pt_gpa + index))
                .context(Error::GetDTTEntry)?;

            if (parent_pt & DTT_ENTRY_PRESENT) == 0 {
                bail!("DTT absent at level {} for gfn 0x{:x}", level, gfn);
            }

            pt_gpa = (parent_pt >> DTT_ENTRY_PFN_SHIFT) << PAGE_SHIFT_4K;
            level -= 1;
        }

        let index = level_to_offset(gfn, level)? * mem::size_of::<u32>() as u64;

        mem.get_host_address(GuestAddress(pt_gpa + index))
            .context(Error::GetDTTEntry)?
    } else {
        // Safe because we checked that dtt_iter.ptr is valid and that the dtt_pte
        // for gfn lies on the same dtt page as the dtt_pte for dtt_iter.gfn, which
        // means the calculated ptr will point to the same page as dtt_iter.ptr
        if gfn > dtt_iter.gfn {
            unsafe {
                dtt_iter
                    .ptr
                    .add(mem::size_of::<AtomicU32>() * (gfn - dtt_iter.gfn) as usize)
            }
        } else {
            unsafe {
                dtt_iter
                    .ptr
                    .sub(mem::size_of::<AtomicU32>() * (dtt_iter.gfn - gfn) as usize)
            }
        }
    };

    dtt_iter.ptr = ptr;
    dtt_iter.gfn = gfn;

    Ok(ptr as *const AtomicU32)
}

fn pin_page(
    vfio_container: &Arc<Mutex<VfioContainer>>,
    mem: &GuestMemory,
    dtt_level: u64,
    dtt_root: u64,
    dtt_iter: &mut DTTIter,
    gfn: u64,
) -> Result<()> {
    let leaf_entry = gfn_to_dtt_pte(mem, dtt_level, dtt_root, dtt_iter, gfn)?;

    let gpa = (gfn << PAGE_SHIFT_4K) as u64;
    let host_addr = mem
        .get_host_address_range(GuestAddress(gpa), PAGE_SIZE_4K as usize)
        .context("failed to get host address")? as u64;

    // Safe because ptr is valid and guaranteed by the gfn_to_dtt_pte.
    // Test PINNED flag
    if (unsafe { (*leaf_entry).load(Ordering::Relaxed) } & DTTE_PINNED_FLAG) != 0 {
        info!("CoIommu: gfn 0x{:x} already pinned", gfn);
        return Ok(());
    }

    // Safe because the gpa is valid from the gfn_to_dtt_pte and the host_addr
    // is guaranteed by MemoryMapping interface.
    if unsafe { vfio_map(vfio_container, gpa, PAGE_SIZE_4K, host_addr) } {
        // Safe because ptr is valid and guaranteed by the gfn_to_dtt_pte.
        // set PINNED flag
        unsafe { (*leaf_entry).fetch_or(DTTE_PINNED_FLAG, Ordering::SeqCst) };
    }

    Ok(())
}

struct PinWorker {
    mem: GuestMemory,
    endpoints: Vec<u16>,
    notifymap_mmap: Arc<MemoryMapping>,
    dtt_level: u64,
    dtt_root: u64,
    ioevents: Vec<Event>,
    vfio_container: Arc<Mutex<VfioContainer>>,
}

impl PinWorker {
    fn debug_label(&self) -> &'static str {
        "CoIommuPinWorker"
    }

    fn run(&mut self, kill_evt: Event) {
        #[derive(PollToken)]
        enum Token {
            Kill,
            Pin { index: usize },
        }

        let wait_ctx: WaitContext<Token> =
            match WaitContext::build_with(&[(&kill_evt, Token::Kill)]) {
                Ok(pc) => pc,
                Err(e) => {
                    error!("{}: failed creating WaitContext: {}", self.debug_label(), e);
                    return;
                }
            };

        for (index, event) in self.ioevents.iter().enumerate() {
            match wait_ctx.add(event, Token::Pin { index }) {
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "{}: failed to add ioevent for index {}: {}",
                        self.debug_label(),
                        index,
                        e
                    );
                    return;
                }
            }
        }

        'wait: loop {
            let events = match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("{}: failed polling for events: {}", self.debug_label(), e);
                    break;
                }
            };

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::Kill => break 'wait,
                    Token::Pin { index } => {
                        let offset = index * mem::size_of::<u64>() as usize;
                        if let Some(event) = self.ioevents.get(index) {
                            if let Err(e) = event.read() {
                                error!(
                                    "{}: failed reading event {}: {}",
                                    self.debug_label(),
                                    index,
                                    e
                                );
                                self.notifymap_mmap.write_obj::<u64>(0, offset).unwrap();
                                break 'wait;
                            }
                        }
                        if let Ok(data) = self.notifymap_mmap.read_obj::<u64>(offset) {
                            if let Err(e) = self.pin_pages(data) {
                                error!("{}: {}", self.debug_label(), e);
                            }
                        }
                        fence(Ordering::SeqCst);
                        self.notifymap_mmap.write_obj::<u64>(0, offset).unwrap();
                    }
                }
            }
        }
    }

    fn pin_pages_in_batch(&mut self, gpa: u64) -> Result<()> {
        let pin_page_info = self
            .mem
            .read_obj_from_addr::<PinPageInfo>(GuestAddress(gpa))
            .context("failed to get pin page info")?;

        let bdf = pin_page_info.bdf;
        ensure!(
            self.endpoints.iter().any(|&x| x == bdf),
            "pin page for unexpected bdf 0x{:x}",
            bdf
        );

        let mut nr_pages = pin_page_info.nr_pages;
        let mut offset = mem::size_of::<PinPageInfo>() as u64;
        let mut dtt_iter: DTTIter = Default::default();
        while nr_pages > 0 {
            let gfn = self
                .mem
                .read_obj_from_addr::<u64>(GuestAddress(gpa + offset))
                .context("failed to get pin page gfn")?;

            pin_page(
                &self.vfio_container,
                &self.mem,
                self.dtt_level,
                self.dtt_root,
                &mut dtt_iter,
                gfn,
            )?;

            offset += mem::size_of::<u64>() as u64;
            nr_pages -= 1;
        }

        Ok(())
    }

    fn pin_pages(&mut self, gfn_bdf: u64) -> Result<()> {
        if gfn_bdf & PIN_PAGES_IN_BATCH != 0 {
            let gpa = gfn_bdf & !PIN_PAGES_IN_BATCH;
            self.pin_pages_in_batch(gpa)
        } else {
            let bdf = (gfn_bdf & 0xffff) as u16;
            let gfn = gfn_bdf >> 16;
            let mut dtt_iter: DTTIter = Default::default();
            ensure!(
                self.endpoints.iter().any(|&x| x == bdf),
                "pin page for unexpected bdf 0x{:x}",
                bdf
            );

            pin_page(
                &self.vfio_container,
                &self.mem,
                self.dtt_level,
                self.dtt_root,
                &mut dtt_iter,
                gfn,
            )
        }
    }
}

#[allow(dead_code)]
struct UnpinWorker {
    mem: GuestMemory,
    dtt_level: u64,
    dtt_root: u64,
    vfio_container: Arc<Mutex<VfioContainer>>,
}

impl UnpinWorker {
    fn debug_label(&self) -> &'static str {
        "CoIommuUnpinWorker"
    }
    // Currently the event is just the kill event but in future will extend with other
    // events. So allow never_loop temporarily
    #[allow(clippy::never_loop)]
    fn run(&mut self, kill_evt: Event) {
        #[derive(PollToken)]
        enum Token {
            Kill,
        }

        let wait_ctx: WaitContext<Token> =
            match WaitContext::build_with(&[(&kill_evt, Token::Kill)]) {
                Ok(pc) => pc,
                Err(e) => {
                    error!("{}: failed creating WaitContext: {}", self.debug_label(), e);
                    return;
                }
            };

        'wait: loop {
            let events = match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("{}: failed polling for events: {}", self.debug_label(), e);
                    break;
                }
            };

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::Kill => break 'wait,
                }
            }
        }
    }
}

pub struct CoIommuDev {
    config_regs: PciConfiguration,
    pci_address: Option<PciAddress>,
    mem: GuestMemory,
    coiommu_reg: CoIommuReg,
    endpoints: Vec<u16>,
    notifymap_mem: SafeDescriptor,
    notifymap_mmap: Arc<MemoryMapping>,
    notifymap_addr: Option<u64>,
    topologymap_mem: SafeDescriptor,
    topologymap_addr: Option<u64>,
    mmapped: bool,
    device_tube: Tube,
    pin_thread: Option<thread::JoinHandle<PinWorker>>,
    pin_kill_evt: Option<Event>,
    unpin_thread: Option<thread::JoinHandle<UnpinWorker>>,
    unpin_kill_evt: Option<Event>,
    ioevents: Vec<Event>,
    vfio_container: Arc<Mutex<VfioContainer>>,
}

impl CoIommuDev {
    pub fn new(
        mem: GuestMemory,
        vfio_container: Arc<Mutex<VfioContainer>>,
        device_tube: Tube,
        endpoints: Vec<u16>,
        vcpu_count: u64,
    ) -> Result<Self> {
        let config_regs = PciConfiguration::new(
            PCI_VENDOR_ID_COIOMMU,
            PCI_DEVICE_ID_COIOMMU,
            PciClassCode::Other,
            &PciOtherSubclass::Other,
            None, // No Programming interface.
            PciHeaderType::Device,
            PCI_VENDOR_ID_COIOMMU,
            PCI_DEVICE_ID_COIOMMU,
            COIOMMU_REVISION_ID,
        );

        // notifymap_mem is used as Bar2 for Guest to check if request is completed by coIOMMU.
        let notifymap_mem = SharedMemory::named("coiommu_notifymap", COIOMMU_NOTIFYMAP_SIZE as u64)
            .context(Error::CreateSharedMemory)?;
        let notifymap_mmap = Arc::new(
            MemoryMappingBuilder::new(COIOMMU_NOTIFYMAP_SIZE)
                .from_shared_memory(&notifymap_mem)
                .offset(0)
                .build()?,
        );

        // topologymap_mem is used as Bar4 for Guest to check which device is on top of coIOMMU.
        let topologymap_mem =
            SharedMemory::named("coiommu_topologymap", COIOMMU_TOPOLOGYMAP_SIZE as u64)
                .context(Error::CreateSharedMemory)?;
        let topologymap_mmap = Arc::new(
            MemoryMappingBuilder::new(COIOMMU_TOPOLOGYMAP_SIZE)
                .from_shared_memory(&topologymap_mem)
                .offset(0)
                .build()?,
        );

        ensure!(
            (endpoints.len() + 1) * mem::size_of::<u16>() <= COIOMMU_TOPOLOGYMAP_SIZE,
            "Coiommu: too many endpoints"
        );
        topologymap_mmap.write_obj::<u16>(endpoints.len() as u16, 0)?;
        for (index, endpoint) in endpoints.iter().enumerate() {
            topologymap_mmap.write_obj::<u16>(*endpoint, (index + 1) * mem::size_of::<u16>())?;
        }

        let mut ioevents = Vec::new();
        for _ in 0..vcpu_count {
            ioevents.push(Event::new().context("CoIommu failed to create event fd")?);
        }

        Ok(Self {
            config_regs,
            pci_address: None,
            mem,
            coiommu_reg: Default::default(),
            endpoints,
            notifymap_mem: notifymap_mem.into(),
            notifymap_mmap,
            notifymap_addr: None,
            topologymap_mem: topologymap_mem.into(),
            topologymap_addr: None,
            mmapped: false,
            device_tube,
            pin_thread: None,
            pin_kill_evt: None,
            unpin_thread: None,
            unpin_kill_evt: None,
            ioevents,
            vfio_container,
        })
    }

    fn send_msg(&self, msg: &VmMemoryRequest) -> Result<()> {
        self.device_tube.send(msg).context(Error::TubeError)?;
        let res = self.device_tube.recv().context(Error::TubeError)?;
        match res {
            VmMemoryResponse::RegisterMemory { .. } => Ok(()),
            VmMemoryResponse::Err(e) => Err(anyhow!("Receive msg err {}", e)),
            _ => Err(anyhow!("Msg cannot be handled")),
        }
    }

    fn register_mmap(
        &self,
        descriptor: SafeDescriptor,
        size: usize,
        offset: u64,
        gpa: u64,
        read_only: bool,
    ) -> Result<()> {
        let request = VmMemoryRequest::RegisterMmapMemory {
            descriptor,
            size,
            offset,
            gpa,
            read_only,
        };
        self.send_msg(&request)
    }

    fn mmap(&mut self) {
        if self.mmapped {
            return;
        }

        if let Some(gpa) = self.notifymap_addr {
            match self.register_mmap(
                self.notifymap_mem.try_clone().unwrap(),
                COIOMMU_NOTIFYMAP_SIZE,
                0,
                gpa,
                false,
            ) {
                Ok(_) => {}
                Err(e) => {
                    panic!("{}: map notifymap failed: {}", self.debug_label(), e);
                }
            }
        }

        if let Some(gpa) = self.topologymap_addr {
            match self.register_mmap(
                self.topologymap_mem.try_clone().unwrap(),
                COIOMMU_TOPOLOGYMAP_SIZE,
                0,
                gpa,
                true,
            ) {
                Ok(_) => {}
                Err(e) => {
                    panic!("{}: map topologymap failed: {}", self.debug_label(), e);
                }
            }
        }

        self.mmapped = true;
    }

    fn start_workers(&mut self) {
        if self.pin_thread.is_none() {
            self.start_pin_thread();
        }

        if self.unpin_thread.is_none() {
            self.start_unpin_thread();
        }
    }

    fn start_pin_thread(&mut self) {
        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "{}: failed creating kill Event pair: {}",
                    self.debug_label(),
                    e
                );
                return;
            }
        };

        let mem = self.mem.clone();
        let endpoints = self.endpoints.to_vec();
        let notifymap_mmap = self.notifymap_mmap.clone();
        let dtt_root = self.coiommu_reg.dtt_root;
        let dtt_level = self.coiommu_reg.dtt_level;
        let ioevents = self
            .ioevents
            .iter()
            .map(|e| e.try_clone().unwrap())
            .collect();
        let vfio_container = self.vfio_container.clone();

        let worker_result = thread::Builder::new()
            .name("coiommu_pin".to_string())
            .spawn(move || {
                let mut worker = PinWorker {
                    mem,
                    endpoints,
                    notifymap_mmap,
                    dtt_root,
                    dtt_level,
                    ioevents,
                    vfio_container,
                };
                worker.run(kill_evt);
                worker
            });

        match worker_result {
            Err(e) => error!(
                "{}: failed to spawn coiommu pin worker: {}",
                self.debug_label(),
                e
            ),
            Ok(join_handle) => {
                self.pin_thread = Some(join_handle);
                self.pin_kill_evt = Some(self_kill_evt);
            }
        }
    }

    fn start_unpin_thread(&mut self) {
        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "{}: failed creating kill Event pair: {}",
                    self.debug_label(),
                    e
                );
                return;
            }
        };

        let mem = self.mem.clone();
        let dtt_root = self.coiommu_reg.dtt_root;
        let dtt_level = self.coiommu_reg.dtt_level;
        let vfio_container = self.vfio_container.clone();
        let worker_result = thread::Builder::new()
            .name("coiommu_unpin".to_string())
            .spawn(move || {
                let mut worker = UnpinWorker {
                    mem,
                    dtt_level,
                    dtt_root,
                    vfio_container,
                };
                worker.run(kill_evt);
                worker
            });

        match worker_result {
            Err(e) => {
                error!(
                    "{}: failed to spawn coiommu unpin worker: {}",
                    self.debug_label(),
                    e
                );
            }
            Ok(join_handle) => {
                self.unpin_thread = Some(join_handle);
                self.unpin_kill_evt = Some(self_kill_evt);
            }
        }
    }

    fn allocate_bar_address(
        &mut self,
        resources: &mut SystemAllocator,
        address: PciAddress,
        size: u64,
        bar_num: u8,
        name: &str,
    ) -> PciResult<u64> {
        let addr = resources
            .mmio_allocator(MmioType::High)
            .allocate_with_align(
                size,
                Alloc::PciBar {
                    bus: address.bus,
                    dev: address.dev,
                    func: address.func,
                    bar: bar_num,
                },
                name.to_string(),
                size,
            )
            .map_err(|e| PciDeviceError::IoAllocationFailed(size, e))?;

        let bar = PciBarConfiguration::new(
            bar_num as usize,
            size,
            PciBarRegionType::Memory64BitRegion,
            PciBarPrefetchable::Prefetchable,
        )
        .set_address(addr);

        self.config_regs
            .add_pci_bar(bar)
            .map_err(|e| PciDeviceError::IoRegistrationFailed(addr, e))?;

        Ok(addr)
    }

    fn read_mmio(&mut self, addr: u64, data: &mut [u8]) {
        let bar = self.config_regs.get_bar_addr(COIOMMU_MMIO_BAR as usize);
        let offset = addr - bar;
        if offset >= mem::size_of::<CoIommuReg>() as u64 {
            error!(
                "{}: read_mmio: invalid addr 0x{:x} bar 0x{:x} offset 0x{:x}",
                self.debug_label(),
                addr,
                bar,
                offset
            );
            return;
        }

        // Sanity check, must be 64bit aligned accessing
        if offset % 8 != 0 || data.len() != 8 {
            error!(
                "{}: read_mmio: unaligned accessing: offset 0x{:x} actual len {} expect len 8",
                self.debug_label(),
                offset,
                data.len()
            );
            return;
        }

        let v = match offset / 8 {
            0 => self.coiommu_reg.dtt_root,
            1 => self.coiommu_reg.cmd,
            2 => self.coiommu_reg.dtt_level,
            _ => return,
        };

        data.copy_from_slice(&v.to_ne_bytes());
    }

    fn write_mmio(&mut self, addr: u64, data: &[u8]) {
        let bar = self.config_regs.get_bar_addr(COIOMMU_MMIO_BAR as usize);
        let mmio_len = mem::size_of::<CoIommuReg>() as u64;
        let offset = addr - bar;
        if offset >= mmio_len {
            if data.len() != 1 {
                error!(
                    "{}: write_mmio: unaligned accessing: offset 0x{:x} actual len {} expect len 1",
                    self.debug_label(),
                    offset,
                    data.len()
                );
                return;
            }

            // Usually will not be here as this is for the per-vcpu notify
            // register which is monitored by the ioevents. For the notify
            // register which is not covered by the ioevents, they are not
            // be used by the frontend driver. In case the frontend driver
            // went here, do a simple handle to make sure the frontend driver
            // will not be blocked, and through an error log.
            let index = (offset - mmio_len) as usize * mem::size_of::<u64>();
            self.notifymap_mmap.write_obj::<u64>(0, index).unwrap();
            error!(
                "{}: No page will be pinned as driver is accessing unused trigger register: offset 0x{:x}",
                self.debug_label(),
                offset
            );
            return;
        }

        // Sanity check, must be 64bit aligned accessing for CoIommuReg
        if offset % 8 != 0 || data.len() != 8 {
            error!(
                "{}: write_mmio: unaligned accessing: offset 0x{:x} actual len {} expect len 8",
                self.debug_label(),
                offset,
                data.len()
            );
            return;
        }

        let index = offset / 8;
        let v = u64::from_ne_bytes(data.try_into().unwrap());
        match index {
            0 => {
                if self.coiommu_reg.dtt_root == 0 {
                    self.coiommu_reg.dtt_root = v;
                    if self.coiommu_reg.dtt_level != 0 {
                        self.start_workers();
                    }
                }
            }
            2 => {
                if self.coiommu_reg.dtt_level == 0 {
                    self.coiommu_reg.dtt_level = v;
                    if self.coiommu_reg.dtt_root != 0 {
                        self.start_workers();
                    }
                }
            }
            _ => {}
        }
    }
}

impl PciDevice for CoIommuDev {
    fn debug_label(&self) -> String {
        "CoIommu".to_owned()
    }

    fn allocate_address(&mut self, resources: &mut SystemAllocator) -> PciResult<PciAddress> {
        if self.pci_address.is_none() {
            self.pci_address = match resources.allocate_pci(0, self.debug_label()) {
                Some(Alloc::PciBar {
                    bus,
                    dev,
                    func,
                    bar: _,
                }) => Some(PciAddress { bus, dev, func }),
                _ => None,
            }
        }
        self.pci_address.ok_or(PciDeviceError::PciAllocationFailed)
    }

    fn allocate_io_bars(&mut self, resources: &mut SystemAllocator) -> PciResult<Vec<(u64, u64)>> {
        let address = self
            .pci_address
            .expect("allocate_address must be called prior to allocate_io_bars");

        // Allocate one bar for the structures pointed to by the capability structures.
        let mut ranges = Vec::new();

        let mmio_addr = self.allocate_bar_address(
            resources,
            address,
            COIOMMU_MMIO_BAR_SIZE as u64,
            COIOMMU_MMIO_BAR,
            "coiommu-mmiobar",
        )?;

        ranges.push((mmio_addr, COIOMMU_MMIO_BAR_SIZE));

        Ok(ranges)
    }

    fn allocate_device_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> PciResult<Vec<(u64, u64)>> {
        let address = self
            .pci_address
            .expect("allocate_address must be called prior to allocate_device_bars");

        let mut ranges = Vec::new();

        let topologymap_addr = self.allocate_bar_address(
            resources,
            address,
            COIOMMU_TOPOLOGYMAP_SIZE as u64,
            COIOMMU_TOPOLOGYMAP_BAR,
            "coiommu-topology",
        )?;
        self.topologymap_addr = Some(topologymap_addr);
        ranges.push((topologymap_addr, COIOMMU_TOPOLOGYMAP_SIZE as u64));

        let notifymap_addr = self.allocate_bar_address(
            resources,
            address,
            COIOMMU_NOTIFYMAP_SIZE as u64,
            COIOMMU_NOTIFYMAP_BAR,
            "coiommu-notifymap",
        )?;
        self.notifymap_addr = Some(notifymap_addr);
        ranges.push((notifymap_addr, COIOMMU_NOTIFYMAP_SIZE as u64));

        Ok(ranges)
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        self.config_regs.read_reg(reg_idx)
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        if reg_idx == COMMAND_REG
            && data.len() == 2
            && data[0] & COMMAND_REG_MEMORY_SPACE_MASK as u8 != 0
            && !self.mmapped
        {
            self.mmap();
        }

        (&mut self.config_regs).write_reg(reg_idx, offset, data);
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        vec![
            self.vfio_container.lock().as_raw_descriptor(),
            self.device_tube.as_raw_descriptor(),
            self.notifymap_mem.as_raw_descriptor(),
            self.topologymap_mem.as_raw_descriptor(),
        ]
    }

    fn read_bar(&mut self, addr: u64, data: &mut [u8]) {
        let mmio_bar = self.config_regs.get_bar_addr(COIOMMU_MMIO_BAR as usize);
        let notifymap = self
            .config_regs
            .get_bar_addr(COIOMMU_NOTIFYMAP_BAR as usize);
        match addr {
            o if mmio_bar <= o && o < mmio_bar + COIOMMU_MMIO_BAR_SIZE as u64 => {
                self.read_mmio(addr, data);
            }
            o if notifymap <= o && o < notifymap + COIOMMU_NOTIFYMAP_SIZE as u64 => {
                // With coiommu device activated, the accessing the notifymap bar
                // won't cause vmexit. If goes here, means the coiommu device is
                // deactivated, and will not do the pin/unpin work. Thus no need
                // to handle this notifymap read.
            }
            _ => {}
        }
    }

    fn write_bar(&mut self, addr: u64, data: &[u8]) {
        let mmio_bar = self.config_regs.get_bar_addr(COIOMMU_MMIO_BAR as usize);
        let notifymap = self
            .config_regs
            .get_bar_addr(COIOMMU_NOTIFYMAP_BAR as usize);
        match addr {
            o if mmio_bar <= o && o < mmio_bar + COIOMMU_MMIO_BAR_SIZE as u64 => {
                self.write_mmio(addr, data);
            }
            o if notifymap <= o && o < notifymap + COIOMMU_NOTIFYMAP_SIZE as u64 => {
                // With coiommu device activated, the accessing the notifymap bar
                // won't cause vmexit. If goes here, means the coiommu device is
                // deactivated, and will not do the pin/unpin work. Thus no need
                // to handle this notifymap write.
            }
            _ => {}
        }
    }

    fn ioevents(&self) -> Vec<(&Event, u64, Datamatch)> {
        let bar0 = self.config_regs.get_bar_addr(COIOMMU_MMIO_BAR as usize);
        let notify_base = bar0 + mem::size_of::<CoIommuReg>() as u64;
        self.ioevents
            .iter()
            .enumerate()
            .map(|(i, event)| (event, notify_base + i as u64, Datamatch::AnyLength))
            .collect()
    }

    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        self.config_regs.get_bar_configuration(bar_num)
    }
}

impl Drop for CoIommuDev {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.pin_kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            if kill_evt.write(1).is_ok() {
                if let Some(worker_thread) = self.pin_thread.take() {
                    let _ = worker_thread.join();
                }
            } else {
                error!("CoIOMMU: failed to write to kill_evt to stop pin_thread");
            }
        }

        if let Some(kill_evt) = self.unpin_kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            if kill_evt.write(1).is_ok() {
                if let Some(worker_thread) = self.unpin_thread.take() {
                    let _ = worker_thread.join();
                }
            } else {
                error!("CoIOMMU: failed to write to kill_evt to stop unpin_thread");
            }
        }
    }
}
