// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This is the CoIOMMU backend implementation. CoIOMMU is a virtual device
//! which provide fine-grained pinning for the VFIO pci-passthrough device
//! so that hypervisor doesn't need to pin the enter VM's memory to improve
//! the memory utilization. CoIOMMU doesn't provide the intra-guest protection
//! so it can only be used for the TRUSTED passthrough devices.
//!
//! CoIOMMU is presented at KVM forum 2020:
//! <https://kvmforum2020.sched.com/event/eE2z/a-virtual-iommu-with-cooperative-dma-buffer-tracking-yu-zhang-intel>
//!
//! Also presented at usenix ATC20:
//! <https://www.usenix.org/conference/atc20/presentation/tian>

use std::collections::VecDeque;
use std::convert::TryInto;
use std::default::Default;
use std::fmt;
use std::mem;
use std::panic;
use std::sync::atomic::fence;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::bail;
use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
use base::AsRawDescriptor;
use base::Event;
use base::EventToken;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::Protection;
use base::RawDescriptor;
use base::SafeDescriptor;
use base::SharedMemory;
use base::Timer;
use base::Tube;
use base::TubeError;
use base::WaitContext;
use base::WorkerThread;
use hypervisor::Datamatch;
use resources::Alloc;
use resources::AllocOptions;
use resources::SystemAllocator;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;
use sync::Mutex;
use thiserror::Error as ThisError;
use vm_control::api::VmMemoryClient;
use vm_control::VmMemoryDestination;
use vm_control::VmMemorySource;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::pci::pci_configuration::PciBarConfiguration;
use crate::pci::pci_configuration::PciBarPrefetchable;
use crate::pci::pci_configuration::PciBarRegionType;
use crate::pci::pci_configuration::PciClassCode;
use crate::pci::pci_configuration::PciConfiguration;
use crate::pci::pci_configuration::PciHeaderType;
use crate::pci::pci_configuration::PciOtherSubclass;
use crate::pci::pci_configuration::COMMAND_REG;
use crate::pci::pci_configuration::COMMAND_REG_MEMORY_SPACE_MASK;
use crate::pci::pci_device::BarRange;
use crate::pci::pci_device::PciDevice;
use crate::pci::pci_device::Result as PciResult;
use crate::pci::PciAddress;
use crate::pci::PciBarIndex;
use crate::pci::PciDeviceError;
use crate::vfio::VfioContainer;
use crate::Suspendable;
use crate::UnpinRequest;
use crate::UnpinResponse;

const PCI_VENDOR_ID_COIOMMU: u16 = 0x1234;
const PCI_DEVICE_ID_COIOMMU: u16 = 0xabcd;
const COIOMMU_CMD_DEACTIVATE: u64 = 0;
const COIOMMU_CMD_ACTIVATE: u64 = 1;
const COIOMMU_CMD_PARK_UNPIN: u64 = 2;
const COIOMMU_CMD_UNPARK_UNPIN: u64 = 3;
const COIOMMU_REVISION_ID: u8 = 0x10;
const COIOMMU_MMIO_BAR: PciBarIndex = 0;
const COIOMMU_MMIO_BAR_SIZE: u64 = 0x2000;
const COIOMMU_NOTIFYMAP_BAR: PciBarIndex = 2;
const COIOMMU_NOTIFYMAP_SIZE: usize = 0x2000;
const COIOMMU_TOPOLOGYMAP_BAR: u8 = 4;
const COIOMMU_TOPOLOGYMAP_SIZE: usize = 0x2000;
const PAGE_SIZE_4K: u64 = 4096;
const PAGE_SHIFT_4K: u64 = 12;
const PIN_PAGES_IN_BATCH: u64 = 1 << 63;

const DTTE_PINNED_FLAG: u32 = 1 << 31;
const DTTE_ACCESSED_FLAG: u32 = 1 << 30;
const DTT_ENTRY_PRESENT: u64 = 1;
const DTT_ENTRY_PFN_SHIFT: u64 = 12;

#[derive(ThisError, Debug)]
enum Error {
    #[error("CoIommu failed to create shared memory")]
    CreateSharedMemory,
    #[error("Failed to get DTT entry")]
    GetDTTEntry,
}

//default interval is 60s
const UNPIN_DEFAULT_INTERVAL: Duration = Duration::from_secs(60);
const UNPIN_GEN_DEFAULT_THRES: u64 = 10;
/// Holds the coiommu unpin policy
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoIommuUnpinPolicy {
    #[default]
    Off,
    Lru,
}

impl fmt::Display for CoIommuUnpinPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::CoIommuUnpinPolicy::*;

        match self {
            Off => write!(f, "off"),
            Lru => write!(f, "lru"),
        }
    }
}

fn deserialize_unpin_interval<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Duration, D::Error> {
    let secs = u64::deserialize(deserializer)?;

    Ok(Duration::from_secs(secs))
}

fn deserialize_unpin_limit<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    let limit = u64::deserialize(deserializer)?;

    match limit {
        0 => Err(serde::de::Error::custom(
            "Please use non-zero unpin_limit value",
        )),
        limit => Ok(Some(limit)),
    }
}

fn unpin_interval_default() -> Duration {
    UNPIN_DEFAULT_INTERVAL
}

fn unpin_gen_threshold_default() -> u64 {
    UNPIN_GEN_DEFAULT_THRES
}

/// Holds the parameters for a coiommu device
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields)]
pub struct CoIommuParameters {
    #[serde(default)]
    pub unpin_policy: CoIommuUnpinPolicy,
    #[serde(
        deserialize_with = "deserialize_unpin_interval",
        default = "unpin_interval_default"
    )]
    pub unpin_interval: Duration,
    #[serde(deserialize_with = "deserialize_unpin_limit", default)]
    pub unpin_limit: Option<u64>,
    // Number of unpin intervals a pinned page must be busy for to be aged into the
    // older, less frequently checked generation.
    #[serde(default = "unpin_gen_threshold_default")]
    pub unpin_gen_threshold: u64,
}

impl Default for CoIommuParameters {
    fn default() -> Self {
        Self {
            unpin_policy: CoIommuUnpinPolicy::Off,
            unpin_interval: UNPIN_DEFAULT_INTERVAL,
            unpin_limit: None,
            unpin_gen_threshold: UNPIN_GEN_DEFAULT_THRES,
        }
    }
}

#[derive(Default, Debug, Copy, Clone)]
struct CoIommuReg {
    dtt_root: u64,
    cmd: u64,
    dtt_level: u64,
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
struct PinnedPageInfo {
    gfn: u64,
    unpin_busy_cnt: u64,
}

impl PinnedPageInfo {
    fn new(gfn: u64, unpin_busy_cnt: u64) -> Self {
        PinnedPageInfo {
            gfn,
            unpin_busy_cnt,
        }
    }
}

#[derive(PartialEq, Debug, Eq)]
enum UnpinThreadState {
    Unparked,
    Parked,
}

struct CoIommuPinState {
    new_gen_pinned_pages: VecDeque<PinnedPageInfo>,
    old_gen_pinned_pages: VecDeque<u64>,
    unpin_thread_state: UnpinThreadState,
    unpin_park_count: u64,
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

fn vfio_unmap(vfio_container: &Arc<Mutex<VfioContainer>>, iova: u64, size: u64) -> bool {
    match vfio_container.lock().vfio_dma_unmap(iova, size) {
        Ok(_) => true,
        Err(e) => {
            error!("CoIommu: failed to unmap iova 0x{:x}: {}", iova, e);
            false
        }
    }
}

#[derive(Default, Debug, Copy, Clone, FromBytes, AsBytes)]
#[repr(C)]
struct PinPageInfo {
    bdf: u16,
    pad: [u16; 3],
    nr_pages: u64,
}

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
    pinstate: &mut CoIommuPinState,
    policy: CoIommuUnpinPolicy,
    vfio_container: &Arc<Mutex<VfioContainer>>,
    mem: &GuestMemory,
    dtt_level: u64,
    dtt_root: u64,
    dtt_iter: &mut DTTIter,
    gfn: u64,
) -> Result<()> {
    let leaf_entry = gfn_to_dtt_pte(mem, dtt_level, dtt_root, dtt_iter, gfn)?;

    let gpa = gfn << PAGE_SHIFT_4K;
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
        if policy == CoIommuUnpinPolicy::Lru {
            pinstate
                .new_gen_pinned_pages
                .push_back(PinnedPageInfo::new(gfn, 0));
        }
    }

    Ok(())
}

#[derive(PartialEq, Debug, Eq)]
enum UnpinResult {
    UnpinlistEmpty,
    Unpinned,
    NotPinned,
    NotUnpinned,
    FailedUnpin,
    UnpinParked,
}

fn unpin_page(
    pinstate: &mut CoIommuPinState,
    vfio_container: &Arc<Mutex<VfioContainer>>,
    mem: &GuestMemory,
    dtt_level: u64,
    dtt_root: u64,
    dtt_iter: &mut DTTIter,
    gfn: u64,
    force: bool,
) -> UnpinResult {
    if pinstate.unpin_thread_state == UnpinThreadState::Parked {
        return UnpinResult::UnpinParked;
    }

    let leaf_entry = match gfn_to_dtt_pte(mem, dtt_level, dtt_root, dtt_iter, gfn) {
        Ok(v) => v,
        Err(_) => {
            // The case force == true may try to unpin a page which is not
            // mapped in the dtt. For such page, the pte doesn't exist yet
            // thus don't need to report any error log.
            // The case force == false is used by coiommu to periodically
            // unpin the pages which have been mapped in dtt, thus the pte
            // for such page does exist. However with the unpin request from
            // virtio balloon, such pages can be unpinned already and the DTT
            // pages might be reclaimed by the Guest OS kernel as well, thus
            // it is also possible to be here. Not to report an error log.
            return UnpinResult::NotPinned;
        }
    };

    if force {
        // Safe because leaf_entry is valid and guaranteed by the gfn_to_dtt_pte.
        // This case is for balloon to evict pages so these pages should
        // already been locked by balloon and no device driver in VM is
        // able to access these pages, so just clear ACCESSED flag first
        // to make sure the following unpin can be success.
        unsafe { (*leaf_entry).fetch_and(!DTTE_ACCESSED_FLAG, Ordering::SeqCst) };
    }

    // Safe because leaf_entry is valid and guaranteed by the gfn_to_dtt_pte.
    if let Err(entry) = unsafe {
        (*leaf_entry).compare_exchange(DTTE_PINNED_FLAG, 0, Ordering::SeqCst, Ordering::SeqCst)
    } {
        // The compare_exchange failed as the original leaf entry is
        // not DTTE_PINNED_FLAG so cannot do the unpin.
        if entry == 0 {
            // The GFN is already unpinned. This is very similar to the
            // gfn_to_dtt_pte error case, with the only difference being
            // that the dtt_pte happens to be on a present page table.
            UnpinResult::NotPinned
        } else {
            if !force {
                // Safe because leaf_entry is valid and guaranteed by the gfn_to_dtt_pte.
                // The ACCESSED_FLAG is set by the guest if guest requires DMA map for
                // this page. It represents whether or not this page is touched by the
                // guest. By clearing this flag after an unpin work, we can detect if
                // this page has been touched by the guest in the next round of unpin
                // work. If the ACCESSED_FLAG is set at the next round, unpin this page
                // will be failed and we will be here again to clear this flag. If this
                // flag is not set at the next round, unpin this page will be probably
                // success.
                unsafe { (*leaf_entry).fetch_and(!DTTE_ACCESSED_FLAG, Ordering::SeqCst) };
            } else {
                // If we're here, then the guest is trying to release a page via the
                // balloon that it still has pinned. This most likely that something is
                // wrong in the guest kernel. Just leave the page pinned and log
                // an error.
                // This failure blocks the balloon from removing the page, which ensures
                // that the guest's view of memory will remain consistent with device
                // DMA's view of memory. Also note that the host kernel maintains an
                // elevated refcount for pinned pages, which is a second guarantee the
                // pages accessible by device DMA won't be freed until after they are
                // unpinned.
                error!(
                    "CoIommu: force case cannot pin gfn 0x{:x} entry 0x{:x}",
                    gfn, entry
                );
            }
            // GFN cannot be unpinned either because the unmap count
            // is non-zero or the it has accessed flag set.
            UnpinResult::NotUnpinned
        }
    } else {
        // The compare_exchange success as the original leaf entry is
        // DTTE_PINNED_FLAG and the new leaf entry is 0 now. Unpin the
        // page.
        let gpa = gfn << PAGE_SHIFT_4K;
        if vfio_unmap(vfio_container, gpa, PAGE_SIZE_4K) {
            UnpinResult::Unpinned
        } else {
            // Safe because leaf_entry is valid and guaranteed by the gfn_to_dtt_pte.
            // make sure the pinned flag is set
            unsafe { (*leaf_entry).fetch_or(DTTE_PINNED_FLAG, Ordering::SeqCst) };
            // need to put this gfn back to pinned vector
            UnpinResult::FailedUnpin
        }
    }
}

struct PinWorker {
    mem: GuestMemory,
    endpoints: Vec<u16>,
    notifymap_mmap: Arc<MemoryMapping>,
    dtt_level: u64,
    dtt_root: u64,
    ioevents: Vec<Event>,
    vfio_container: Arc<Mutex<VfioContainer>>,
    pinstate: Arc<Mutex<CoIommuPinState>>,
    params: CoIommuParameters,
}

impl PinWorker {
    fn debug_label(&self) -> &'static str {
        "CoIommuPinWorker"
    }

    fn run(&mut self, kill_evt: Event) {
        #[derive(EventToken)]
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
                        let offset = index * mem::size_of::<u64>();
                        if let Some(event) = self.ioevents.get(index) {
                            if let Err(e) = event.wait() {
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
        let mut pinstate = self.pinstate.lock();
        while nr_pages > 0 {
            let gfn = self
                .mem
                .read_obj_from_addr::<u64>(GuestAddress(gpa + offset))
                .context("failed to get pin page gfn")?;

            pin_page(
                &mut pinstate,
                self.params.unpin_policy,
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

            let mut pinstate = self.pinstate.lock();
            pin_page(
                &mut pinstate,
                self.params.unpin_policy,
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

struct UnpinWorker {
    mem: GuestMemory,
    dtt_level: u64,
    dtt_root: u64,
    vfio_container: Arc<Mutex<VfioContainer>>,
    unpin_tube: Option<Tube>,
    pinstate: Arc<Mutex<CoIommuPinState>>,
    params: CoIommuParameters,
    unpin_gen_threshold: u64,
}

impl UnpinWorker {
    fn debug_label(&self) -> &'static str {
        "CoIommuUnpinWorker"
    }

    fn run(&mut self, kill_evt: Event) {
        #[derive(EventToken)]
        enum Token {
            UnpinTimer,
            UnpinReq,
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

        if let Some(tube) = &self.unpin_tube {
            if let Err(e) = wait_ctx.add(tube, Token::UnpinReq) {
                error!("{}: failed creating WaitContext: {}", self.debug_label(), e);
                return;
            }
        }

        let mut unpin_timer = if self.params.unpin_policy != CoIommuUnpinPolicy::Off
            && !self.params.unpin_interval.is_zero()
        {
            let duration = self.params.unpin_interval;
            let interval = Some(self.params.unpin_interval);
            let mut timer = match Timer::new() {
                Ok(t) => t,
                Err(e) => {
                    error!(
                        "{}: failed to create the unpin timer: {}",
                        self.debug_label(),
                        e
                    );
                    return;
                }
            };
            if let Err(e) = timer.reset(duration, interval) {
                error!(
                    "{}: failed to start the unpin timer: {}",
                    self.debug_label(),
                    e
                );
                return;
            }
            if let Err(e) = wait_ctx.add(&timer, Token::UnpinTimer) {
                error!("{}: failed creating WaitContext: {}", self.debug_label(), e);
                return;
            }
            Some(timer)
        } else {
            None
        };

        let unpin_tube = self.unpin_tube.take();
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
                    Token::UnpinTimer => {
                        self.unpin_pages();
                        if let Some(timer) = &mut unpin_timer {
                            if let Err(e) = timer.mark_waited() {
                                error!(
                                    "{}: failed to clear unpin timer: {}",
                                    self.debug_label(),
                                    e
                                );
                                break 'wait;
                            }
                        }
                    }
                    Token::UnpinReq => {
                        if let Some(tube) = &unpin_tube {
                            match tube.recv::<UnpinRequest>() {
                                Ok(req) => {
                                    let mut unpin_done = true;
                                    for range in req.ranges {
                                        // Locking with respect to pin_pages isn't necessary
                                        // for this case because the unpinned pages in the range
                                        // should all be in the balloon and so nothing will attempt
                                        // to pin them.
                                        if !self.unpin_pages_in_range(range.0, range.1) {
                                            unpin_done = false;
                                            break;
                                        }
                                    }
                                    let resp = if unpin_done {
                                        UnpinResponse::Success
                                    } else {
                                        UnpinResponse::Failed
                                    };
                                    if let Err(e) = tube.send(&resp) {
                                        error!(
                                            "{}: failed to send unpin response {}",
                                            self.debug_label(),
                                            e
                                        );
                                    }
                                }
                                Err(e) => {
                                    if let TubeError::Disconnected = e {
                                        if let Err(e) = wait_ctx.delete(tube) {
                                            error!(
                                                "{}: failed to remove unpin_tube: {}",
                                                self.debug_label(),
                                                e
                                            );
                                        }
                                    } else {
                                        error!(
                                            "{}: failed to recv Unpin Request: {}",
                                            self.debug_label(),
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Token::Kill => break 'wait,
                }
            }
        }
        self.unpin_tube = unpin_tube;
    }

    fn unpin_pages(&mut self) {
        if self.params.unpin_policy == CoIommuUnpinPolicy::Lru {
            self.lru_unpin_pages();
        }
    }

    fn lru_unpin_page(
        &mut self,
        dtt_iter: &mut DTTIter,
        new_gen: bool,
    ) -> (UnpinResult, Option<PinnedPageInfo>) {
        let mut pinstate = self.pinstate.lock();
        let pageinfo = if new_gen {
            pinstate.new_gen_pinned_pages.pop_front()
        } else {
            pinstate
                .old_gen_pinned_pages
                .pop_front()
                .map(|gfn| PinnedPageInfo::new(gfn, 0))
        };

        pageinfo.map_or((UnpinResult::UnpinlistEmpty, None), |pageinfo| {
            (
                unpin_page(
                    &mut pinstate,
                    &self.vfio_container,
                    &self.mem,
                    self.dtt_level,
                    self.dtt_root,
                    dtt_iter,
                    pageinfo.gfn,
                    false,
                ),
                Some(pageinfo),
            )
        })
    }

    fn lru_unpin_pages_in_loop(&mut self, unpin_limit: Option<u64>, new_gen: bool) -> u64 {
        let mut not_unpinned_new_gen_pages = VecDeque::new();
        let mut not_unpinned_old_gen_pages = VecDeque::new();
        let mut unpinned_count = 0;
        let has_limit = unpin_limit.is_some();
        let limit_count = unpin_limit.unwrap_or(0);
        let mut dtt_iter: DTTIter = Default::default();

        // If has_limit is true but limit_count is 0, will not do the unpin
        while !has_limit || unpinned_count != limit_count {
            let (result, pinned_page) = self.lru_unpin_page(&mut dtt_iter, new_gen);
            match result {
                UnpinResult::UnpinlistEmpty => break,
                UnpinResult::Unpinned => unpinned_count += 1,
                UnpinResult::NotPinned => {}
                UnpinResult::NotUnpinned => {
                    if let Some(mut page) = pinned_page {
                        if self.params.unpin_gen_threshold != 0 {
                            page.unpin_busy_cnt += 1;
                            // Unpin from new_gen queue but not
                            // successfully unpinned. Need to check
                            // the unpin_gen threshold. If reach, put
                            // it to old_gen queue.
                            // And if it is not from new_gen, directly
                            // put into old_gen queue.
                            if !new_gen || page.unpin_busy_cnt >= self.params.unpin_gen_threshold {
                                not_unpinned_old_gen_pages.push_back(page.gfn);
                            } else {
                                not_unpinned_new_gen_pages.push_back(page);
                            }
                        }
                    }
                }
                UnpinResult::FailedUnpin | UnpinResult::UnpinParked => {
                    // Although UnpinParked means we didn't actually try to unpin
                    // gfn, it's not worth specifically handing since parking is
                    // expected to be relatively rare.
                    if let Some(page) = pinned_page {
                        if new_gen {
                            not_unpinned_new_gen_pages.push_back(page);
                        } else {
                            not_unpinned_old_gen_pages.push_back(page.gfn);
                        }
                    }
                    if result == UnpinResult::UnpinParked {
                        thread::park();
                    }
                }
            }
        }

        if !not_unpinned_new_gen_pages.is_empty() {
            let mut pinstate = self.pinstate.lock();
            pinstate
                .new_gen_pinned_pages
                .append(&mut not_unpinned_new_gen_pages);
        }

        if !not_unpinned_old_gen_pages.is_empty() {
            let mut pinstate = self.pinstate.lock();
            pinstate
                .old_gen_pinned_pages
                .append(&mut not_unpinned_old_gen_pages);
        }

        unpinned_count
    }

    fn lru_unpin_pages(&mut self) {
        let mut unpin_count = 0;
        if self.params.unpin_gen_threshold != 0 {
            self.unpin_gen_threshold += 1;
            if self.unpin_gen_threshold == self.params.unpin_gen_threshold {
                self.unpin_gen_threshold = 0;
                // Try to unpin inactive queue first if reaches the thres hold
                unpin_count = self.lru_unpin_pages_in_loop(self.params.unpin_limit, false);
            }
        }
        // Unpin the new_gen queue with the updated unpin_limit after unpin old_gen queue
        self.lru_unpin_pages_in_loop(
            self.params
                .unpin_limit
                .map(|limit| limit.saturating_sub(unpin_count)),
            true,
        );
    }

    fn unpin_pages_in_range(&self, gfn: u64, count: u64) -> bool {
        let mut dtt_iter: DTTIter = Default::default();
        let mut index = 0;
        while index != count {
            let mut pinstate = self.pinstate.lock();
            let result = unpin_page(
                &mut pinstate,
                &self.vfio_container,
                &self.mem,
                self.dtt_level,
                self.dtt_root,
                &mut dtt_iter,
                gfn + index,
                true,
            );
            drop(pinstate);

            match result {
                UnpinResult::Unpinned | UnpinResult::NotPinned => {}
                UnpinResult::UnpinParked => {
                    thread::park();
                    continue;
                }
                _ => {
                    error!("coiommu: force unpin failed by {:?}", result);
                    return false;
                }
            }
            index += 1;
        }
        true
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
    vm_memory_client: VmMemoryClient,
    pin_thread: Option<WorkerThread<PinWorker>>,
    unpin_thread: Option<WorkerThread<UnpinWorker>>,
    unpin_tube: Option<Tube>,
    ioevents: Vec<Event>,
    vfio_container: Arc<Mutex<VfioContainer>>,
    pinstate: Arc<Mutex<CoIommuPinState>>,
    params: CoIommuParameters,
}

impl CoIommuDev {
    pub fn new(
        mem: GuestMemory,
        vfio_container: Arc<Mutex<VfioContainer>>,
        vm_memory_client: VmMemoryClient,
        unpin_tube: Option<Tube>,
        endpoints: Vec<u16>,
        vcpu_count: u64,
        params: CoIommuParameters,
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
        let notifymap_mem = SharedMemory::new("coiommu_notifymap", COIOMMU_NOTIFYMAP_SIZE as u64)
            .context(Error::CreateSharedMemory)?;
        let notifymap_mmap = Arc::new(
            MemoryMappingBuilder::new(COIOMMU_NOTIFYMAP_SIZE)
                .from_shared_memory(&notifymap_mem)
                .offset(0)
                .build()?,
        );

        // topologymap_mem is used as Bar4 for Guest to check which device is on top of coIOMMU.
        let topologymap_mem =
            SharedMemory::new("coiommu_topologymap", COIOMMU_TOPOLOGYMAP_SIZE as u64)
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
            vm_memory_client,
            pin_thread: None,
            unpin_thread: None,
            unpin_tube,
            ioevents,
            vfio_container,
            pinstate: Arc::new(Mutex::new(CoIommuPinState {
                new_gen_pinned_pages: VecDeque::new(),
                old_gen_pinned_pages: VecDeque::new(),
                unpin_thread_state: UnpinThreadState::Unparked,
                unpin_park_count: 0,
            })),
            params,
        })
    }

    fn register_mmap(
        &self,
        descriptor: SafeDescriptor,
        size: usize,
        offset: u64,
        gpa: u64,
        prot: Protection,
    ) -> Result<()> {
        let _region = self
            .vm_memory_client
            .register_memory(
                VmMemorySource::Descriptor {
                    descriptor,
                    offset,
                    size: size as u64,
                },
                VmMemoryDestination::GuestPhysicalAddress(gpa),
                prot,
            )
            .context("register_mmap register_memory failed")?;
        Ok(())
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
                Protection::read_write(),
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
                Protection::read(),
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
        let mem = self.mem.clone();
        let endpoints = self.endpoints.to_vec();
        let notifymap_mmap = self.notifymap_mmap.clone();
        let dtt_root = self.coiommu_reg.dtt_root;
        let dtt_level = self.coiommu_reg.dtt_level;
        let ioevents: Vec<Event> = self
            .ioevents
            .iter()
            .map(|e| e.try_clone().unwrap())
            .collect();

        let bar0 = self.config_regs.get_bar_addr(COIOMMU_MMIO_BAR);
        let notify_base = bar0 + mem::size_of::<CoIommuReg>() as u64;
        for (i, evt) in self.ioevents.iter().enumerate() {
            self.vm_memory_client
                .register_io_event(
                    evt.try_clone().expect("failed to clone event"),
                    notify_base + i as u64,
                    Datamatch::AnyLength,
                )
                .expect("failed to register ioevent");
        }

        let vfio_container = self.vfio_container.clone();
        let pinstate = self.pinstate.clone();
        let params = self.params;

        self.pin_thread = Some(WorkerThread::start("coiommu_pin", move |kill_evt| {
            let mut worker = PinWorker {
                mem,
                endpoints,
                notifymap_mmap,
                dtt_root,
                dtt_level,
                ioevents,
                vfio_container,
                pinstate,
                params,
            };
            worker.run(kill_evt);
            worker
        }));
    }

    fn start_unpin_thread(&mut self) {
        let mem = self.mem.clone();
        let dtt_root = self.coiommu_reg.dtt_root;
        let dtt_level = self.coiommu_reg.dtt_level;
        let vfio_container = self.vfio_container.clone();
        let unpin_tube = self.unpin_tube.take();
        let pinstate = self.pinstate.clone();
        let params = self.params;
        self.unpin_thread = Some(WorkerThread::start("coiommu_unpin", move |kill_evt| {
            let mut worker = UnpinWorker {
                mem,
                dtt_level,
                dtt_root,
                vfio_container,
                unpin_tube,
                pinstate,
                params,
                unpin_gen_threshold: 0,
            };
            worker.run(kill_evt);
            worker
        }));
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
            .allocate_mmio(
                size,
                Alloc::PciBar {
                    bus: address.bus,
                    dev: address.dev,
                    func: address.func,
                    bar: bar_num,
                },
                name.to_string(),
                AllocOptions::new().prefetchable(true).align(size),
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

    fn read_mmio(&mut self, offset: u64, data: &mut [u8]) {
        if offset >= mem::size_of::<CoIommuReg>() as u64 {
            error!(
                "{}: read_mmio: invalid offset 0x{:x}",
                self.debug_label(),
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

    fn write_mmio(&mut self, offset: u64, data: &[u8]) {
        let mmio_len = mem::size_of::<CoIommuReg>() as u64;
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
            let index = (offset - mmio_len) as usize;
            if let Some(event) = self.ioevents.get(index) {
                let _ = event.signal();
            } else {
                self.notifymap_mmap
                    .write_obj::<u64>(0, index * mem::size_of::<u64>())
                    .unwrap();
                error!(
                    "{}: No page will be pinned as driver is accessing unused trigger register: offset 0x{:x}",
                    self.debug_label(),
                    offset
                );
            }
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
                }
            }
            1 => match v {
                // Deactivate can happen if the frontend driver in the guest
                // fails during probing or if the CoIommu device is removed
                // by the guest. Neither of these cases is expected, and if
                // either happens the guest will be non-functional due to
                // pass-through devices which rely on CoIommu not working.
                // So just fail hard and panic.
                COIOMMU_CMD_DEACTIVATE => {
                    panic!("{}: Deactivate is not supported", self.debug_label())
                }
                COIOMMU_CMD_ACTIVATE => {
                    if self.coiommu_reg.dtt_root != 0 && self.coiommu_reg.dtt_level != 0 {
                        self.start_workers();
                    }
                }
                COIOMMU_CMD_PARK_UNPIN => {
                    let mut pinstate = self.pinstate.lock();
                    pinstate.unpin_thread_state = UnpinThreadState::Parked;
                    if let Some(v) = pinstate.unpin_park_count.checked_add(1) {
                        pinstate.unpin_park_count = v;
                    } else {
                        panic!("{}: Park request overflowing", self.debug_label());
                    }
                }
                COIOMMU_CMD_UNPARK_UNPIN => {
                    let mut pinstate = self.pinstate.lock();
                    if pinstate.unpin_thread_state == UnpinThreadState::Parked {
                        if let Some(v) = pinstate.unpin_park_count.checked_sub(1) {
                            pinstate.unpin_park_count = v;
                            if pinstate.unpin_park_count == 0 {
                                if let Some(worker_thread) = &self.unpin_thread {
                                    worker_thread.thread().unpark();
                                }
                                pinstate.unpin_thread_state = UnpinThreadState::Unparked;
                            }
                        } else {
                            error!("{}: Park count is already reached to 0", self.debug_label());
                        }
                    }
                }
                _ => {}
            },
            2 => {
                if self.coiommu_reg.dtt_level == 0 {
                    self.coiommu_reg.dtt_level = v;
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

    fn allocate_io_bars(&mut self, resources: &mut SystemAllocator) -> PciResult<Vec<BarRange>> {
        let address = self
            .pci_address
            .expect("allocate_address must be called prior to allocate_io_bars");

        // Allocate one bar for the structures pointed to by the capability structures.
        let mut ranges: Vec<BarRange> = Vec::new();

        let mmio_addr = self.allocate_bar_address(
            resources,
            address,
            COIOMMU_MMIO_BAR_SIZE,
            COIOMMU_MMIO_BAR as u8,
            "coiommu-mmiobar",
        )?;

        ranges.push(BarRange {
            addr: mmio_addr,
            size: COIOMMU_MMIO_BAR_SIZE,
            prefetchable: false,
        });

        Ok(ranges)
    }

    fn allocate_device_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> PciResult<Vec<BarRange>> {
        let address = self
            .pci_address
            .expect("allocate_address must be called prior to allocate_device_bars");

        let mut ranges: Vec<BarRange> = Vec::new();

        let topologymap_addr = self.allocate_bar_address(
            resources,
            address,
            COIOMMU_TOPOLOGYMAP_SIZE as u64,
            COIOMMU_TOPOLOGYMAP_BAR,
            "coiommu-topology",
        )?;
        self.topologymap_addr = Some(topologymap_addr);
        ranges.push(BarRange {
            addr: topologymap_addr,
            size: COIOMMU_TOPOLOGYMAP_SIZE as u64,
            prefetchable: false,
        });

        let notifymap_addr = self.allocate_bar_address(
            resources,
            address,
            COIOMMU_NOTIFYMAP_SIZE as u64,
            COIOMMU_NOTIFYMAP_BAR as u8,
            "coiommu-notifymap",
        )?;
        self.notifymap_addr = Some(notifymap_addr);
        ranges.push(BarRange {
            addr: notifymap_addr,
            size: COIOMMU_NOTIFYMAP_SIZE as u64,
            prefetchable: false,
        });

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

        self.config_regs.write_reg(reg_idx, offset, data);
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = vec![
            self.vfio_container.lock().as_raw_descriptor(),
            self.vm_memory_client.as_raw_descriptor(),
            self.notifymap_mem.as_raw_descriptor(),
            self.topologymap_mem.as_raw_descriptor(),
        ];
        if let Some(unpin_tube) = &self.unpin_tube {
            rds.push(unpin_tube.as_raw_descriptor());
        }
        rds.extend(self.ioevents.iter().map(Event::as_raw_descriptor));
        rds
    }

    fn read_bar(&mut self, bar_index: PciBarIndex, offset: u64, data: &mut [u8]) {
        match bar_index {
            COIOMMU_MMIO_BAR => self.read_mmio(offset, data),
            COIOMMU_NOTIFYMAP_BAR => {
                // With coiommu device activated, the accessing the notifymap bar
                // won't cause vmexit. If goes here, means the coiommu device is
                // deactivated, and will not do the pin/unpin work. Thus no need
                // to handle this notifymap read.
            }
            _ => {}
        }
    }

    fn write_bar(&mut self, bar_index: PciBarIndex, offset: u64, data: &[u8]) {
        match bar_index {
            COIOMMU_MMIO_BAR => self.write_mmio(offset, data),
            COIOMMU_NOTIFYMAP_BAR => {
                // With coiommu device activated, the accessing the notifymap bar
                // won't cause vmexit. If goes here, means the coiommu device is
                // deactivated, and will not do the pin/unpin work. Thus no need
                // to handle this notifymap write.
            }
            _ => {}
        }
    }

    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        self.config_regs.get_bar_configuration(bar_num)
    }
}

impl Suspendable for CoIommuDev {}
