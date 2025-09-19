// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::max;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use acpi_tables::aml::Aml;
use base::debug;
use base::error;
use base::pagesize;
use base::warn;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::Event;
use base::EventToken;
use base::MemoryMapping;
use base::Protection;
use base::RawDescriptor;
use base::Tube;
use base::WaitContext;
use base::WorkerThread;
use hypervisor::MemCacheType;
use resources::AddressRange;
use resources::Alloc;
use resources::AllocOptions;
use resources::MmioType;
use resources::SystemAllocator;
use sync::Mutex;
use vfio_sys::vfio::VFIO_PCI_ACPI_NTFY_IRQ_INDEX;
use vfio_sys::*;
use vm_control::api::VmMemoryClient;
use vm_control::HotPlugDeviceInfo;
use vm_control::HotPlugDeviceType;
use vm_control::VmMemoryDestination;
use vm_control::VmMemoryRegionId;
use vm_control::VmMemorySource;
use vm_control::VmRequest;
use vm_control::VmResponse;

use crate::pci::acpi::DeviceVcfgRegister;
use crate::pci::acpi::DsmMethod;
use crate::pci::acpi::PowerResourceMethod;
use crate::pci::acpi::SHM_OFFSET;
use crate::pci::msi::MsiConfig;
use crate::pci::msi::MsiStatus;
use crate::pci::msi::PCI_MSI_FLAGS;
use crate::pci::msi::PCI_MSI_FLAGS_64BIT;
use crate::pci::msi::PCI_MSI_FLAGS_MASKBIT;
use crate::pci::msi::PCI_MSI_NEXT_POINTER;
use crate::pci::msix::MsixConfig;
use crate::pci::msix::MsixStatus;
use crate::pci::msix::BITS_PER_PBA_ENTRY;
use crate::pci::msix::MSIX_PBA_ENTRIES_MODULO;
use crate::pci::msix::MSIX_TABLE_ENTRIES_MODULO;
use crate::pci::pci_device::BarRange;
use crate::pci::pci_device::Error as PciDeviceError;
use crate::pci::pci_device::PciDevice;
use crate::pci::pci_device::PreferredIrq;
use crate::pci::pm::PciPmCap;
use crate::pci::pm::PmConfig;
use crate::pci::pm::PM_CAP_LENGTH;
use crate::pci::PciAddress;
use crate::pci::PciBarConfiguration;
use crate::pci::PciBarIndex;
use crate::pci::PciBarPrefetchable;
use crate::pci::PciBarRegionType;
use crate::pci::PciCapabilityID;
use crate::pci::PciClassCode;
use crate::pci::PciId;
use crate::pci::PciInterruptPin;
use crate::pci::PCI_VCFG_DSM;
use crate::pci::PCI_VCFG_NOTY;
use crate::pci::PCI_VCFG_PM;
use crate::pci::PCI_VENDOR_ID_INTEL;
use crate::vfio::VfioDevice;
use crate::vfio::VfioError;
use crate::vfio::VfioIrqType;
use crate::vfio::VfioPciConfig;
use crate::IrqLevelEvent;
use crate::Suspendable;

const PCI_VENDOR_ID: u32 = 0x0;
const PCI_DEVICE_ID: u32 = 0x2;
const PCI_COMMAND: u32 = 0x4;
const PCI_COMMAND_MEMORY: u8 = 0x2;
const PCI_BASE_CLASS_CODE: u32 = 0x0B;
const PCI_INTERRUPT_NUM: u32 = 0x3C;
const PCI_INTERRUPT_PIN: u32 = 0x3D;

const PCI_CAPABILITY_LIST: u32 = 0x34;
const PCI_CAP_ID_MSI: u8 = 0x05;
const PCI_CAP_ID_MSIX: u8 = 0x11;
const PCI_CAP_ID_PM: u8 = 0x01;

// Size of the standard PCI config space
const PCI_CONFIG_SPACE_SIZE: u32 = 0x100;
// Size of the standard PCIe config space: 4KB
const PCIE_CONFIG_SPACE_SIZE: u32 = 0x1000;

// Extended Capabilities
const PCI_EXT_CAP_ID_CAC: u16 = 0x0C;
const PCI_EXT_CAP_ID_ARI: u16 = 0x0E;
const PCI_EXT_CAP_ID_SRIOV: u16 = 0x10;
const PCI_EXT_CAP_ID_REBAR: u16 = 0x15;

struct VfioPmCap {
    offset: u32,
    capabilities: u32,
    config: PmConfig,
}

impl VfioPmCap {
    fn new(config: &VfioPciConfig, cap_start: u32) -> Self {
        let mut capabilities: u32 = config.read_config(cap_start);
        capabilities |= (PciPmCap::default_cap() as u32) << 16;
        VfioPmCap {
            offset: cap_start,
            capabilities,
            config: PmConfig::new(false),
        }
    }

    pub fn should_trigger_pme(&mut self) -> bool {
        self.config.should_trigger_pme()
    }

    fn is_pm_reg(&self, offset: u32) -> bool {
        (offset >= self.offset) && (offset < self.offset + PM_CAP_LENGTH as u32)
    }

    pub fn read(&self, offset: u32) -> u32 {
        let offset = offset - self.offset;
        if offset == 0 {
            self.capabilities
        } else {
            let mut data = 0;
            self.config.read(&mut data);
            data
        }
    }

    pub fn write(&mut self, offset: u64, data: &[u8]) {
        let offset = offset - self.offset as u64;
        if offset >= std::mem::size_of::<u32>() as u64 {
            let offset = offset - std::mem::size_of::<u32>() as u64;
            self.config.write(offset, data);
        }
    }
}

enum VfioMsiChange {
    Disable,
    Enable,
    FunctionChanged,
}

struct VfioMsiCap {
    config: MsiConfig,
    offset: u32,
}

impl VfioMsiCap {
    fn new(
        config: &VfioPciConfig,
        msi_cap_start: u32,
        vm_socket_irq: Tube,
        device_id: u32,
        device_name: String,
    ) -> Self {
        let msi_ctl: u16 = config.read_config(msi_cap_start + PCI_MSI_FLAGS);
        let is_64bit = (msi_ctl & PCI_MSI_FLAGS_64BIT) != 0;
        let mask_cap = (msi_ctl & PCI_MSI_FLAGS_MASKBIT) != 0;

        VfioMsiCap {
            config: MsiConfig::new(is_64bit, mask_cap, vm_socket_irq, device_id, device_name),
            offset: msi_cap_start,
        }
    }

    fn is_msi_reg(&self, index: u64, len: usize) -> bool {
        self.config.is_msi_reg(self.offset, index, len)
    }

    fn write_msi_reg(&mut self, index: u64, data: &[u8]) -> Option<VfioMsiChange> {
        let offset = index as u32 - self.offset;
        match self.config.write_msi_capability(offset, data) {
            MsiStatus::Enabled => Some(VfioMsiChange::Enable),
            MsiStatus::Disabled => Some(VfioMsiChange::Disable),
            MsiStatus::NothingToDo => None,
        }
    }

    fn get_msi_irqfd(&self) -> Option<&Event> {
        self.config.get_irqfd()
    }

    fn destroy(&mut self) {
        self.config.destroy()
    }
}

// MSI-X registers in MSI-X capability
const PCI_MSIX_FLAGS: u32 = 0x02; // Message Control
const PCI_MSIX_FLAGS_QSIZE: u16 = 0x07FF; // Table size
const PCI_MSIX_TABLE: u32 = 0x04; // Table offset
const PCI_MSIX_TABLE_BIR: u32 = 0x07; // BAR index
const PCI_MSIX_TABLE_OFFSET: u32 = 0xFFFFFFF8; // Offset into specified BAR
const PCI_MSIX_PBA: u32 = 0x08; // Pending bit Array offset
const PCI_MSIX_PBA_BIR: u32 = 0x07; // BAR index
const PCI_MSIX_PBA_OFFSET: u32 = 0xFFFFFFF8; // Offset into specified BAR

struct VfioMsixCap {
    config: MsixConfig,
    offset: u32,
    table_size: u16,
    table_pci_bar: PciBarIndex,
    table_offset: u64,
    table_size_bytes: u64,
    pba_pci_bar: PciBarIndex,
    pba_offset: u64,
    pba_size_bytes: u64,
    msix_interrupt_evt: Vec<Event>,
}

impl VfioMsixCap {
    fn new(
        config: &VfioPciConfig,
        msix_cap_start: u32,
        vm_socket_irq: Tube,
        pci_id: u32,
        device_name: String,
    ) -> Self {
        let msix_ctl: u16 = config.read_config(msix_cap_start + PCI_MSIX_FLAGS);
        let table: u32 = config.read_config(msix_cap_start + PCI_MSIX_TABLE);
        let table_pci_bar = (table & PCI_MSIX_TABLE_BIR) as PciBarIndex;
        let table_offset = (table & PCI_MSIX_TABLE_OFFSET) as u64;
        let pba: u32 = config.read_config(msix_cap_start + PCI_MSIX_PBA);
        let pba_pci_bar = (pba & PCI_MSIX_PBA_BIR) as PciBarIndex;
        let pba_offset = (pba & PCI_MSIX_PBA_OFFSET) as u64;

        let mut table_size = (msix_ctl & PCI_MSIX_FLAGS_QSIZE) as u64 + 1;
        if table_pci_bar == pba_pci_bar
            && pba_offset > table_offset
            && (table_offset + table_size * MSIX_TABLE_ENTRIES_MODULO) > pba_offset
        {
            table_size = (pba_offset - table_offset) / MSIX_TABLE_ENTRIES_MODULO;
        }

        let table_size_bytes = table_size * MSIX_TABLE_ENTRIES_MODULO;
        let pba_size_bytes =
            table_size.div_ceil(BITS_PER_PBA_ENTRY as u64) * MSIX_PBA_ENTRIES_MODULO;
        let mut msix_interrupt_evt = Vec::new();
        for _ in 0..table_size {
            msix_interrupt_evt.push(Event::new().expect("failed to create msix interrupt"));
        }
        VfioMsixCap {
            config: MsixConfig::new(table_size as u16, vm_socket_irq, pci_id, device_name),
            offset: msix_cap_start,
            table_size: table_size as u16,
            table_pci_bar,
            table_offset,
            table_size_bytes,
            pba_pci_bar,
            pba_offset,
            pba_size_bytes,
            msix_interrupt_evt,
        }
    }

    // only msix control register is writable and need special handle in pci r/w
    fn is_msix_control_reg(&self, offset: u32, size: u32) -> bool {
        let control_start = self.offset + PCI_MSIX_FLAGS;
        let control_end = control_start + 2;

        offset < control_end && offset + size > control_start
    }

    fn read_msix_control(&self, data: &mut u32) {
        *data = self.config.read_msix_capability(*data);
    }

    fn write_msix_control(&mut self, data: &[u8]) -> Option<VfioMsiChange> {
        let old_enabled = self.config.enabled();
        let old_masked = self.config.masked();

        self.config
            .write_msix_capability(PCI_MSIX_FLAGS.into(), data);

        let new_enabled = self.config.enabled();
        let new_masked = self.config.masked();

        if !old_enabled && new_enabled {
            Some(VfioMsiChange::Enable)
        } else if old_enabled && !new_enabled {
            Some(VfioMsiChange::Disable)
        } else if new_enabled && old_masked != new_masked {
            Some(VfioMsiChange::FunctionChanged)
        } else {
            None
        }
    }

    fn is_msix_table(&self, bar_index: PciBarIndex, offset: u64) -> bool {
        bar_index == self.table_pci_bar
            && offset >= self.table_offset
            && offset < self.table_offset + self.table_size_bytes
    }

    fn get_msix_table(&self, bar_index: PciBarIndex) -> Option<AddressRange> {
        if bar_index == self.table_pci_bar {
            AddressRange::from_start_and_size(self.table_offset, self.table_size_bytes)
        } else {
            None
        }
    }

    fn read_table(&self, offset: u64, data: &mut [u8]) {
        let offset = offset - self.table_offset;
        self.config.read_msix_table(offset, data);
    }

    fn write_table(&mut self, offset: u64, data: &[u8]) -> MsixStatus {
        let offset = offset - self.table_offset;
        self.config.write_msix_table(offset, data)
    }

    fn is_msix_pba(&self, bar_index: PciBarIndex, offset: u64) -> bool {
        bar_index == self.pba_pci_bar
            && offset >= self.pba_offset
            && offset < self.pba_offset + self.pba_size_bytes
    }

    fn get_msix_pba(&self, bar_index: PciBarIndex) -> Option<AddressRange> {
        if bar_index == self.pba_pci_bar {
            AddressRange::from_start_and_size(self.pba_offset, self.pba_size_bytes)
        } else {
            None
        }
    }

    fn read_pba(&self, offset: u64, data: &mut [u8]) {
        let offset = offset - self.pba_offset;
        self.config.read_pba_entries(offset, data);
    }

    fn write_pba(&mut self, offset: u64, data: &[u8]) {
        let offset = offset - self.pba_offset;
        self.config.write_pba_entries(offset, data);
    }

    fn get_msix_irqfd(&self, index: usize) -> Option<&Event> {
        let irqfd = self.config.get_irqfd(index);
        if let Some(fd) = irqfd {
            if self.msix_vector_masked(index) {
                Some(&self.msix_interrupt_evt[index])
            } else {
                Some(fd)
            }
        } else {
            None
        }
    }

    fn get_msix_irqfds(&self) -> Vec<Option<&Event>> {
        let mut irqfds = Vec::new();

        for i in 0..self.table_size {
            irqfds.push(self.get_msix_irqfd(i as usize));
        }

        irqfds
    }

    fn table_size(&self) -> usize {
        self.table_size.into()
    }

    fn clone_msix_evt(&self) -> Vec<Event> {
        self.msix_interrupt_evt
            .iter()
            .map(|irq| irq.try_clone().unwrap())
            .collect()
    }

    fn msix_vector_masked(&self, index: usize) -> bool {
        !self.config.enabled() || self.config.masked() || self.config.table_masked(index)
    }

    fn trigger(&mut self, index: usize) {
        self.config.trigger(index as u16);
    }

    fn destroy(&mut self) {
        self.config.destroy()
    }
}

impl AsRawDescriptors for VfioMsixCap {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        let mut rds = vec![self.config.as_raw_descriptor()];
        rds.extend(
            self.msix_interrupt_evt
                .iter()
                .map(|evt| evt.as_raw_descriptor()),
        );
        rds
    }
}

struct VfioResourceAllocator {
    // The region that is not allocated yet.
    regions: BTreeSet<AddressRange>,
}

impl VfioResourceAllocator {
    // Creates a new `VfioResourceAllocator` for managing VFIO resources.
    // Can return `Err` if `base` + `size` overflows a u64.
    //
    // * `base` - The starting address of the range to manage.
    // * `size` - The size of the address range in bytes.
    fn new(pool: AddressRange) -> Result<Self, PciDeviceError> {
        if pool.is_empty() {
            return Err(PciDeviceError::SizeZero);
        }
        let mut regions = BTreeSet::new();
        regions.insert(pool);
        Ok(VfioResourceAllocator { regions })
    }

    fn internal_allocate_from_slot(
        &mut self,
        slot: AddressRange,
        range: AddressRange,
    ) -> Result<u64, PciDeviceError> {
        let slot_was_present = self.regions.remove(&slot);
        assert!(slot_was_present);

        let (before, after) = slot.non_overlapping_ranges(range);

        if !before.is_empty() {
            self.regions.insert(before);
        }
        if !after.is_empty() {
            self.regions.insert(after);
        }

        Ok(range.start)
    }

    // Allocates a range of addresses from the managed region with a minimal alignment.
    // Overlapping with a previous allocation is _not_ allowed.
    // Returns allocated address.
    fn allocate_with_align(&mut self, size: u64, alignment: u64) -> Result<u64, PciDeviceError> {
        if size == 0 {
            return Err(PciDeviceError::SizeZero);
        }
        if !alignment.is_power_of_two() {
            return Err(PciDeviceError::BadAlignment);
        }

        // finds first region matching alignment and size.
        let region = self.regions.iter().find(|range| {
            match range.start % alignment {
                0 => range.start.checked_add(size - 1),
                r => range.start.checked_add(size - 1 + alignment - r),
            }
            .is_some_and(|end| end <= range.end)
        });

        match region {
            Some(&slot) => {
                let start = match slot.start % alignment {
                    0 => slot.start,
                    r => slot.start + alignment - r,
                };
                let end = start + size - 1;
                let range = AddressRange::from_start_and_end(start, end);

                self.internal_allocate_from_slot(slot, range)
            }
            None => Err(PciDeviceError::OutOfSpace),
        }
    }

    // Allocates a range of addresses from the managed region with a required location.
    // Overlapping with a previous allocation is allowed.
    fn allocate_at_can_overlap(&mut self, range: AddressRange) -> Result<(), PciDeviceError> {
        if range.is_empty() {
            return Err(PciDeviceError::SizeZero);
        }

        while let Some(&slot) = self
            .regions
            .iter()
            .find(|avail_range| avail_range.overlaps(range))
        {
            let _address = self.internal_allocate_from_slot(slot, range)?;
        }
        Ok(())
    }
}

struct VfioPciWorker {
    address: PciAddress,
    sysfs_path: PathBuf,
    vm_socket: Tube,
    name: String,
    pm_cap: Option<Arc<Mutex<VfioPmCap>>>,
    msix_cap: Option<Arc<Mutex<VfioMsixCap>>>,
}

impl VfioPciWorker {
    fn run(
        &mut self,
        req_irq_evt: Event,
        wakeup_evt: Event,
        acpi_notify_evt: Event,
        kill_evt: Event,
        msix_evt: Vec<Event>,
        is_in_low_power: Arc<Mutex<bool>>,
        gpe: Option<u32>,
        notification_val: Arc<Mutex<Vec<u32>>>,
    ) {
        #[derive(EventToken, Debug)]
        enum Token {
            ReqIrq,
            WakeUp,
            AcpiNotifyEvent,
            Kill,
            MsixIrqi { index: usize },
        }

        let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
            (&req_irq_evt, Token::ReqIrq),
            (&wakeup_evt, Token::WakeUp),
            (&acpi_notify_evt, Token::AcpiNotifyEvent),
            (&kill_evt, Token::Kill),
        ]) {
            Ok(pc) => pc,
            Err(e) => {
                error!(
                    "{} failed creating vfio WaitContext: {}",
                    self.name.clone(),
                    e
                );
                return;
            }
        };

        for (index, msix_int) in msix_evt.iter().enumerate() {
            wait_ctx
                .add(msix_int, Token::MsixIrqi { index })
                .expect("Failed to create vfio WaitContext for msix interrupt event")
        }

        'wait: loop {
            let events = match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("{} failed polling vfio events: {}", self.name.clone(), e);
                    break;
                }
            };

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::MsixIrqi { index } => {
                        if let Some(msix_cap) = &self.msix_cap {
                            msix_cap.lock().trigger(index);
                        }
                    }
                    Token::ReqIrq => {
                        let device = HotPlugDeviceInfo {
                            device_type: HotPlugDeviceType::EndPoint,
                            path: self.sysfs_path.clone(),
                            hp_interrupt: false,
                        };

                        let request = VmRequest::HotPlugVfioCommand { device, add: false };
                        if self.vm_socket.send(&request).is_ok() {
                            if let Err(e) = self.vm_socket.recv::<VmResponse>() {
                                error!("{} failed to remove vfio_device: {}", self.name.clone(), e);
                            } else {
                                break 'wait;
                            }
                        }
                    }
                    Token::WakeUp => {
                        let _ = wakeup_evt.wait();

                        if *is_in_low_power.lock() {
                            if let Some(pm_cap) = &self.pm_cap {
                                if pm_cap.lock().should_trigger_pme() {
                                    let request =
                                        VmRequest::PciPme(self.address.pme_requester_id());
                                    if self.vm_socket.send(&request).is_ok() {
                                        if let Err(e) = self.vm_socket.recv::<VmResponse>() {
                                            error!(
                                                "{} failed to send PME: {}",
                                                self.name.clone(),
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Token::AcpiNotifyEvent => {
                        if let Some(gpe) = gpe {
                            if let Ok(val) = base::EventExt::read_count(&acpi_notify_evt) {
                                notification_val.lock().push(val as u32);
                                let request = VmRequest::Gpe {
                                    gpe,
                                    clear_evt: None,
                                };
                                if self.vm_socket.send(&request).is_ok() {
                                    if let Err(e) = self.vm_socket.recv::<VmResponse>() {
                                        error!("{} failed to send GPE: {}", self.name.clone(), e);
                                    }
                                }
                            } else {
                                error!("{} failed to read acpi_notify_evt", self.name.clone());
                            }
                        }
                    }
                    Token::Kill => break 'wait,
                }
            }
        }
    }
}

fn get_next_from_extcap_header(cap_header: u32) -> u32 {
    (cap_header >> 20) & 0xffc
}

fn is_skipped_ext_cap(cap_id: u16) -> bool {
    matches!(
        cap_id,
        // SR-IOV/ARI/Resizable_BAR capabilities are not well handled and should not be exposed
        PCI_EXT_CAP_ID_ARI | PCI_EXT_CAP_ID_SRIOV | PCI_EXT_CAP_ID_REBAR
    )
}

enum DeviceData {
    IntelGfxData { opregion_index: u32 },
}

/// PCI Express Extended Capabilities information
#[derive(Copy, Clone)]
struct ExtCap {
    /// cap offset in Configuration Space
    offset: u32,
    /// cap size
    size: u32,
    /// next offset, set next non-skipped offset for non-skipped ext cap
    next: u16,
    /// whether to be exposed to guest
    is_skipped: bool,
}

/// Implements the Vfio Pci device, then a pci device is added into vm
pub struct VfioPciDevice {
    device: Arc<VfioDevice>,
    config: VfioPciConfig,
    hotplug: bool,
    hotplug_bus_number: Option<u8>,
    preferred_address: PciAddress,
    pci_address: Option<PciAddress>,
    interrupt_evt: Option<IrqLevelEvent>,
    acpi_notification_evt: Option<Event>,
    mmio_regions: Vec<PciBarConfiguration>,
    io_regions: Vec<PciBarConfiguration>,
    pm_cap: Option<Arc<Mutex<VfioPmCap>>>,
    msi_cap: Option<VfioMsiCap>,
    msix_cap: Option<Arc<Mutex<VfioMsixCap>>>,
    irq_type: Option<VfioIrqType>,
    vm_memory_client: VmMemoryClient,
    device_data: Option<DeviceData>,
    pm_evt: Option<Event>,
    is_in_low_power: Arc<Mutex<bool>>,
    worker_thread: Option<WorkerThread<VfioPciWorker>>,
    vm_socket_vm: Option<Tube>,
    sysfs_path: PathBuf,
    // PCI Express Extended Capabilities
    ext_caps: Vec<ExtCap>,
    vcfg_shm_mmap: Option<MemoryMapping>,
    mapped_mmio_bars: BTreeMap<PciBarIndex, (u64, Vec<VmMemoryRegionId>)>,
    activated: bool,
    acpi_notifier_val: Arc<Mutex<Vec<u32>>>,
    gpe: Option<u32>,
    base_class_code: PciClassCode,
}

impl VfioPciDevice {
    /// Constructs a new Vfio Pci device for the give Vfio device
    pub fn new(
        sysfs_path: &Path,
        device: VfioDevice,
        hotplug: bool,
        hotplug_bus_number: Option<u8>,
        guest_address: Option<PciAddress>,
        vfio_device_socket_msi: Tube,
        vfio_device_socket_msix: Tube,
        vm_memory_client: VmMemoryClient,
        vfio_device_socket_vm: Tube,
    ) -> Result<Self, PciDeviceError> {
        let preferred_address = if let Some(bus_num) = hotplug_bus_number {
            debug!("hotplug bus {}", bus_num);
            PciAddress {
                // Caller specify pcie bus number for hotplug device
                bus: bus_num,
                // devfn should be 0, otherwise pcie root port couldn't detect it
                dev: 0,
                func: 0,
            }
        } else if let Some(guest_address) = guest_address {
            debug!("guest PCI address {}", guest_address);
            guest_address
        } else {
            let addr = PciAddress::from_str(device.device_name()).map_err(|e| {
                PciDeviceError::PciAddressParseFailure(device.device_name().clone(), e)
            })?;
            debug!("parsed device PCI address {}", addr);
            addr
        };

        let dev = Arc::new(device);
        let config = VfioPciConfig::new(Arc::clone(&dev));
        let mut msi_socket = Some(vfio_device_socket_msi);
        let mut msix_socket = Some(vfio_device_socket_msix);
        let mut msi_cap: Option<VfioMsiCap> = None;
        let mut msix_cap: Option<Arc<Mutex<VfioMsixCap>>> = None;
        let mut pm_cap: Option<Arc<Mutex<VfioPmCap>>> = None;

        let mut is_pcie = false;
        let mut cap_next: u32 = config.read_config::<u8>(PCI_CAPABILITY_LIST).into();
        let vendor_id: u16 = config.read_config(PCI_VENDOR_ID);
        let device_id: u16 = config.read_config(PCI_DEVICE_ID);
        let base_class_code = PciClassCode::try_from(config.read_config::<u8>(PCI_BASE_CLASS_CODE))
            .unwrap_or(PciClassCode::Other);

        let pci_id = PciId::new(vendor_id, device_id);

        while cap_next != 0 {
            let cap_id: u8 = config.read_config(cap_next);
            if cap_id == PCI_CAP_ID_PM {
                pm_cap = Some(Arc::new(Mutex::new(VfioPmCap::new(&config, cap_next))));
            } else if cap_id == PCI_CAP_ID_MSI {
                if let Some(msi_socket) = msi_socket.take() {
                    msi_cap = Some(VfioMsiCap::new(
                        &config,
                        cap_next,
                        msi_socket,
                        pci_id.into(),
                        dev.device_name().to_string(),
                    ));
                }
            } else if cap_id == PCI_CAP_ID_MSIX {
                if let Some(msix_socket) = msix_socket.take() {
                    msix_cap = Some(Arc::new(Mutex::new(VfioMsixCap::new(
                        &config,
                        cap_next,
                        msix_socket,
                        pci_id.into(),
                        dev.device_name().to_string(),
                    ))));
                }
            } else if cap_id == PciCapabilityID::PciExpress as u8 {
                is_pcie = true;
            }
            let offset = cap_next + PCI_MSI_NEXT_POINTER;
            cap_next = config.read_config::<u8>(offset).into();
        }

        let mut ext_caps: Vec<ExtCap> = Vec::new();
        if is_pcie {
            let mut ext_cap_next: u32 = PCI_CONFIG_SPACE_SIZE;
            while ext_cap_next != 0 {
                let ext_cap_config: u32 = config.read_config::<u32>(ext_cap_next);
                if ext_cap_config == 0 {
                    break;
                }
                ext_caps.push(ExtCap {
                    offset: ext_cap_next,
                    // Calculate the size later
                    size: 0,
                    // init as the real value
                    next: get_next_from_extcap_header(ext_cap_config) as u16,
                    is_skipped: is_skipped_ext_cap((ext_cap_config & 0xffff) as u16),
                });
                ext_cap_next = get_next_from_extcap_header(ext_cap_config);
            }

            // Manage extended caps
            //
            // Extended capabilities are chained with each pointing to the next, so
            // we can drop anything other than the head of the chain simply by
            // modifying the previous next pointer. For the head of the chain, we
            // can modify the capability ID to something that cannot match a valid
            // capability. ID PCI_EXT_CAP_ID_CAC is for this since it is no longer
            // supported.
            //
            // reverse order by offset
            ext_caps.sort_by(|a, b| b.offset.cmp(&a.offset));
            let mut next_offset: u32 = PCIE_CONFIG_SPACE_SIZE;
            let mut non_skipped_next: u16 = 0;
            for ext_cap in ext_caps.iter_mut() {
                if !ext_cap.is_skipped {
                    ext_cap.next = non_skipped_next;
                    non_skipped_next = ext_cap.offset as u16;
                } else if ext_cap.offset == PCI_CONFIG_SPACE_SIZE {
                    ext_cap.next = non_skipped_next;
                }
                ext_cap.size = next_offset - ext_cap.offset;
                next_offset = ext_cap.offset;
            }
            // order by offset
            ext_caps.reverse();
        }

        let is_intel_gfx =
            base_class_code == PciClassCode::DisplayController && vendor_id == PCI_VENDOR_ID_INTEL;
        let device_data = if is_intel_gfx {
            Some(DeviceData::IntelGfxData {
                opregion_index: u32::MAX,
            })
        } else {
            None
        };

        Ok(VfioPciDevice {
            device: dev,
            config,
            hotplug,
            hotplug_bus_number,
            preferred_address,
            pci_address: None,
            interrupt_evt: None,
            acpi_notification_evt: None,
            mmio_regions: Vec::new(),
            io_regions: Vec::new(),
            pm_cap,
            msi_cap,
            msix_cap,
            irq_type: None,
            vm_memory_client,
            device_data,
            pm_evt: None,
            is_in_low_power: Arc::new(Mutex::new(false)),
            worker_thread: None,
            vm_socket_vm: Some(vfio_device_socket_vm),
            sysfs_path: sysfs_path.to_path_buf(),
            ext_caps,
            vcfg_shm_mmap: None,
            mapped_mmio_bars: BTreeMap::new(),
            activated: false,
            acpi_notifier_val: Arc::new(Mutex::new(Vec::new())),
            gpe: None,
            base_class_code,
        })
    }

    /// Gets the pci address of the device, if one has already been allocated.
    pub fn pci_address(&self) -> Option<PciAddress> {
        self.pci_address
    }

    pub fn is_gfx(&self) -> bool {
        self.base_class_code == PciClassCode::DisplayController
    }

    fn is_intel_gfx(&self) -> bool {
        matches!(self.device_data, Some(DeviceData::IntelGfxData { .. }))
    }

    fn enable_acpi_notification(&mut self) -> Result<(), PciDeviceError> {
        if let Some(ref acpi_notification_evt) = self.acpi_notification_evt {
            return self
                .device
                .acpi_notification_evt_enable(acpi_notification_evt, VFIO_PCI_ACPI_NTFY_IRQ_INDEX)
                .map_err(|_| PciDeviceError::AcpiNotifySetupFailed);
        }
        Err(PciDeviceError::AcpiNotifySetupFailed)
    }

    #[allow(dead_code)]
    fn disable_acpi_notification(&mut self) -> Result<(), PciDeviceError> {
        if let Some(ref _acpi_notification_evt) = self.acpi_notification_evt {
            return self
                .device
                .acpi_notification_disable(VFIO_PCI_ACPI_NTFY_IRQ_INDEX)
                .map_err(|_| PciDeviceError::AcpiNotifyDeactivationFailed);
        }
        Err(PciDeviceError::AcpiNotifyDeactivationFailed)
    }

    #[allow(dead_code)]
    fn test_acpi_notification(&mut self, val: u32) -> Result<(), PciDeviceError> {
        if let Some(ref _acpi_notification_evt) = self.acpi_notification_evt {
            return self
                .device
                .acpi_notification_test(VFIO_PCI_ACPI_NTFY_IRQ_INDEX, val)
                .map_err(|_| PciDeviceError::AcpiNotifyTestFailed);
        }
        Err(PciDeviceError::AcpiNotifyTestFailed)
    }

    fn enable_intx(&mut self) {
        if let Some(ref interrupt_evt) = self.interrupt_evt {
            if let Err(e) = self.device.irq_enable(
                &[Some(interrupt_evt.get_trigger())],
                VFIO_PCI_INTX_IRQ_INDEX,
                0,
            ) {
                error!("{} Intx enable failed: {}", self.debug_label(), e);
                return;
            }
            if let Err(e) = self.device.irq_mask(VFIO_PCI_INTX_IRQ_INDEX) {
                error!("{} Intx mask failed: {}", self.debug_label(), e);
                self.disable_intx();
                return;
            }
            if let Err(e) = self
                .device
                .resample_virq_enable(interrupt_evt.get_resample(), VFIO_PCI_INTX_IRQ_INDEX)
            {
                error!("{} resample enable failed: {}", self.debug_label(), e);
                self.disable_intx();
                return;
            }
            if let Err(e) = self.device.irq_unmask(VFIO_PCI_INTX_IRQ_INDEX) {
                error!("{} Intx unmask failed: {}", self.debug_label(), e);
                self.disable_intx();
                return;
            }
            self.irq_type = Some(VfioIrqType::Intx);
        }
    }

    fn disable_intx(&mut self) {
        if let Err(e) = self.device.irq_disable(VFIO_PCI_INTX_IRQ_INDEX) {
            error!("{} Intx disable failed: {}", self.debug_label(), e);
        }
        self.irq_type = None;
    }

    fn disable_irqs(&mut self) {
        match self.irq_type {
            Some(VfioIrqType::Msi) => self.disable_msi(),
            Some(VfioIrqType::Msix) => self.disable_msix(),
            _ => (),
        }

        // Above disable_msi() or disable_msix() will enable intx again.
        // so disable_intx here again.
        if let Some(VfioIrqType::Intx) = self.irq_type {
            self.disable_intx();
        }
    }

    fn enable_msi(&mut self) {
        self.disable_irqs();

        let irqfd = match &self.msi_cap {
            Some(cap) => {
                if let Some(fd) = cap.get_msi_irqfd() {
                    fd
                } else {
                    self.enable_intx();
                    return;
                }
            }
            None => {
                self.enable_intx();
                return;
            }
        };

        if let Err(e) = self
            .device
            .irq_enable(&[Some(irqfd)], VFIO_PCI_MSI_IRQ_INDEX, 0)
        {
            error!("{} failed to enable msi: {}", self.debug_label(), e);
            self.enable_intx();
            return;
        }

        self.irq_type = Some(VfioIrqType::Msi);
    }

    fn disable_msi(&mut self) {
        if let Err(e) = self.device.irq_disable(VFIO_PCI_MSI_IRQ_INDEX) {
            error!("{} failed to disable msi: {}", self.debug_label(), e);
            return;
        }
        self.irq_type = None;

        self.enable_intx();
    }

    fn enable_msix(&mut self) {
        if self.msix_cap.is_none() {
            return;
        }

        self.disable_irqs();
        let cap = self.msix_cap.as_ref().unwrap().lock();
        let vector_in_use = cap.get_msix_irqfds().iter().any(|&irq| irq.is_some());

        let mut failed = false;
        if !vector_in_use {
            // If there are no msix vectors currently in use, we explicitly assign a new eventfd
            // to vector 0. Then we enable it and immediately disable it, so that vfio will
            // activate physical device. If there are available msix vectors, just enable them
            // instead.
            let fd = Event::new().expect("failed to create event");
            let table_size = cap.table_size();
            let mut irqfds = vec![None; table_size];
            irqfds[0] = Some(&fd);
            for fd in irqfds.iter_mut().skip(1) {
                *fd = None;
            }
            if let Err(e) = self.device.irq_enable(&irqfds, VFIO_PCI_MSIX_IRQ_INDEX, 0) {
                error!("{} failed to enable msix: {}", self.debug_label(), e);
                failed = true;
            }
            irqfds[0] = None;
            if let Err(e) = self.device.irq_enable(&irqfds, VFIO_PCI_MSIX_IRQ_INDEX, 0) {
                error!("{} failed to enable msix: {}", self.debug_label(), e);
                failed = true;
            }
        } else {
            let result = self
                .device
                .irq_enable(&cap.get_msix_irqfds(), VFIO_PCI_MSIX_IRQ_INDEX, 0);
            if let Err(e) = result {
                error!("{} failed to enable msix: {}", self.debug_label(), e);
                failed = true;
            }
        }

        std::mem::drop(cap);
        if failed {
            self.enable_intx();
            return;
        }
        self.irq_type = Some(VfioIrqType::Msix);
    }

    fn disable_msix(&mut self) {
        if self.msix_cap.is_none() {
            return;
        }
        if let Err(e) = self.device.irq_disable(VFIO_PCI_MSIX_IRQ_INDEX) {
            error!("{} failed to disable msix: {}", self.debug_label(), e);
            return;
        }
        self.irq_type = None;
        self.enable_intx();
    }

    fn msix_vectors_update(&self) -> Result<(), VfioError> {
        if let Some(cap) = &self.msix_cap {
            self.device
                .irq_enable(&cap.lock().get_msix_irqfds(), VFIO_PCI_MSIX_IRQ_INDEX, 0)?;
        }
        Ok(())
    }

    fn msix_vector_update(&self, index: usize, irqfd: Option<&Event>) {
        if let Err(e) = self
            .device
            .irq_enable(&[irqfd], VFIO_PCI_MSIX_IRQ_INDEX, index as u32)
        {
            error!(
                "{} failed to update msix vector {}: {}",
                self.debug_label(),
                index,
                e
            );
        }
    }

    fn adjust_bar_mmap(
        &self,
        bar_mmaps: Vec<vfio_region_sparse_mmap_area>,
        remove_mmaps: &[AddressRange],
    ) -> Vec<vfio_region_sparse_mmap_area> {
        let mut mmaps: Vec<vfio_region_sparse_mmap_area> = Vec::with_capacity(bar_mmaps.len());
        let pgmask = (pagesize() as u64) - 1;

        for mmap in bar_mmaps.iter() {
            let mmap_range = if let Some(mmap_range) =
                AddressRange::from_start_and_size(mmap.offset, mmap.size)
            {
                mmap_range
            } else {
                continue;
            };
            let mut to_mmap = match VfioResourceAllocator::new(mmap_range) {
                Ok(a) => a,
                Err(e) => {
                    error!("{} adjust_bar_mmap failed: {}", self.debug_label(), e);
                    mmaps.clear();
                    return mmaps;
                }
            };

            for &(mut remove_range) in remove_mmaps.iter() {
                remove_range = remove_range.intersect(mmap_range);
                if !remove_range.is_empty() {
                    // align offsets to page size
                    let begin = remove_range.start & !pgmask;
                    let end = ((remove_range.end + 1 + pgmask) & !pgmask) - 1;
                    let remove_range = AddressRange::from_start_and_end(begin, end);
                    if let Err(e) = to_mmap.allocate_at_can_overlap(remove_range) {
                        error!("{} adjust_bar_mmap failed: {}", self.debug_label(), e);
                    }
                }
            }

            for mmap in to_mmap.regions {
                mmaps.push(vfio_region_sparse_mmap_area {
                    offset: mmap.start,
                    size: mmap.end - mmap.start + 1,
                });
            }
        }

        mmaps
    }

    fn remove_bar_mmap_msix(
        &self,
        bar_index: PciBarIndex,
        bar_mmaps: Vec<vfio_region_sparse_mmap_area>,
    ) -> Vec<vfio_region_sparse_mmap_area> {
        let msix_cap = &self.msix_cap.as_ref().unwrap().lock();
        let mut msix_regions = Vec::new();

        if let Some(t) = msix_cap.get_msix_table(bar_index) {
            msix_regions.push(t);
        }
        if let Some(p) = msix_cap.get_msix_pba(bar_index) {
            msix_regions.push(p);
        }

        if msix_regions.is_empty() {
            return bar_mmaps;
        }

        self.adjust_bar_mmap(bar_mmaps, &msix_regions)
    }

    fn add_bar_mmap(&self, index: PciBarIndex, bar_addr: u64) -> Vec<VmMemoryRegionId> {
        let mut mmaps_ids: Vec<VmMemoryRegionId> = Vec::new();
        if self.device.get_region_flags(index) & VFIO_REGION_INFO_FLAG_MMAP != 0 {
            // the bar storing msix table and pba couldn't mmap.
            // these bars should be trapped, so that msix could be emulated.
            let mut mmaps = self.device.get_region_mmap(index);

            if self.msix_cap.is_some() {
                mmaps = self.remove_bar_mmap_msix(index, mmaps);
            }
            if mmaps.is_empty() {
                return mmaps_ids;
            }

            for mmap in mmaps.iter() {
                let mmap_offset = mmap.offset;
                let mmap_size = mmap.size;
                let guest_map_start = bar_addr + mmap_offset;
                let region_offset = self.device.get_region_offset(index);
                let offset = region_offset + mmap_offset;
                let descriptor = match self.device.device_file().try_clone() {
                    Ok(device_file) => device_file.into(),
                    Err(_) => break,
                };
                match self.vm_memory_client.register_memory(
                    VmMemorySource::Descriptor {
                        descriptor,
                        offset,
                        size: mmap_size,
                    },
                    VmMemoryDestination::GuestPhysicalAddress(guest_map_start),
                    Protection::read_write(),
                    MemCacheType::CacheCoherent,
                ) {
                    Ok(id) => {
                        mmaps_ids.push(id);
                    }
                    Err(e) => {
                        error!("register_memory failed: {}", e);
                        break;
                    }
                }
            }
        }

        mmaps_ids
    }

    fn remove_bar_mmap(&self, mmap_ids: &[VmMemoryRegionId]) {
        for mmap_id in mmap_ids {
            if let Err(e) = self.vm_memory_client.unregister_memory(*mmap_id) {
                error!("unregister_memory failed: {}", e);
            }
        }
    }

    fn disable_bars_mmap(&mut self) {
        for (_, (_, mmap_ids)) in self.mapped_mmio_bars.iter() {
            self.remove_bar_mmap(mmap_ids);
        }
        self.mapped_mmio_bars.clear();
    }

    fn commit_bars_mmap(&mut self) {
        // Unmap all bars before remapping bars, to prevent issues with overlap
        let mut needs_map = Vec::new();
        for mmio_info in self.mmio_regions.iter() {
            let bar_idx = mmio_info.bar_index();
            let addr = mmio_info.address();

            if let Some((cur_addr, ids)) = self.mapped_mmio_bars.remove(&bar_idx) {
                if cur_addr == addr {
                    self.mapped_mmio_bars.insert(bar_idx, (cur_addr, ids));
                    continue;
                } else {
                    self.remove_bar_mmap(&ids);
                }
            }

            if addr != 0 {
                needs_map.push((bar_idx, addr));
            }
        }

        for (bar_idx, addr) in needs_map.iter() {
            let ids = self.add_bar_mmap(*bar_idx, *addr);
            self.mapped_mmio_bars.insert(*bar_idx, (*addr, ids));
        }
    }

    fn close(&mut self) {
        if let Some(msi) = self.msi_cap.as_mut() {
            msi.destroy();
        }
        if let Some(msix) = &self.msix_cap {
            msix.lock().destroy();
        }
        self.disable_bars_mmap();
        self.device.close();
    }

    fn start_work_thread(&mut self) {
        let vm_socket = match self.vm_socket_vm.take() {
            Some(socket) => socket,
            None => return,
        };

        let req_evt = match Event::new() {
            Ok(evt) => {
                if let Err(e) = self
                    .device
                    .irq_enable(&[Some(&evt)], VFIO_PCI_REQ_IRQ_INDEX, 0)
                {
                    error!("{} enable req_irq failed: {}", self.debug_label(), e);
                    return;
                }
                evt
            }
            Err(_) => return,
        };

        let (self_pm_evt, pm_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "{} failed creating PM Event pair: {}",
                    self.debug_label(),
                    e
                );
                return;
            }
        };
        self.pm_evt = Some(self_pm_evt);

        let (self_acpi_notify_evt, acpi_notify_evt) =
            match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        "{} failed creating ACPI Event pair: {}",
                        self.debug_label(),
                        e
                    );
                    return;
                }
            };
        self.acpi_notification_evt = Some(self_acpi_notify_evt);

        if let Err(e) = self.enable_acpi_notification() {
            error!("{}: {}", self.debug_label(), e);
        }

        let mut msix_evt = Vec::new();
        if let Some(msix_cap) = &self.msix_cap {
            msix_evt = msix_cap.lock().clone_msix_evt();
        }

        let name = self.device.device_name().to_string();
        let address = self.pci_address.expect("Unassigned PCI Address.");
        let sysfs_path = self.sysfs_path.clone();
        let pm_cap = self.pm_cap.clone();
        let msix_cap = self.msix_cap.clone();
        let is_in_low_power = self.is_in_low_power.clone();
        let gpe_nr = self.gpe;
        let notification_val = self.acpi_notifier_val.clone();
        self.worker_thread = Some(WorkerThread::start("vfio_pci", move |kill_evt| {
            let mut worker = VfioPciWorker {
                address,
                sysfs_path,
                vm_socket,
                name,
                pm_cap,
                msix_cap,
            };
            worker.run(
                req_evt,
                pm_evt,
                acpi_notify_evt,
                kill_evt,
                msix_evt,
                is_in_low_power,
                gpe_nr,
                notification_val,
            );
            worker
        }));
        self.activated = true;
    }

    fn collect_bars(&mut self) -> Vec<PciBarConfiguration> {
        let mut i = VFIO_PCI_BAR0_REGION_INDEX;
        let mut mem_bars: Vec<PciBarConfiguration> = Vec::new();

        while i <= VFIO_PCI_ROM_REGION_INDEX {
            let mut low: u32 = 0xffffffff;
            let offset: u32 = if i == VFIO_PCI_ROM_REGION_INDEX {
                0x30
            } else {
                0x10 + i * 4
            };
            self.config.write_config(low, offset);
            low = self.config.read_config(offset);

            let low_flag = low & 0xf;
            let is_64bit = low_flag & 0x4 == 0x4;
            if (low_flag & 0x1 == 0 || i == VFIO_PCI_ROM_REGION_INDEX) && low != 0 {
                let mut upper: u32 = 0xffffffff;
                if is_64bit {
                    self.config.write_config(upper, offset + 4);
                    upper = self.config.read_config(offset + 4);
                }

                low &= 0xffff_fff0;
                let mut size: u64 = u64::from(upper);
                size <<= 32;
                size |= u64::from(low);
                size = !size + 1;
                let region_type = if is_64bit {
                    PciBarRegionType::Memory64BitRegion
                } else {
                    PciBarRegionType::Memory32BitRegion
                };
                let prefetch = if low_flag & 0x8 == 0x8 {
                    PciBarPrefetchable::Prefetchable
                } else {
                    PciBarPrefetchable::NotPrefetchable
                };
                mem_bars.push(PciBarConfiguration::new(
                    i as usize,
                    size,
                    region_type,
                    prefetch,
                ));
            } else if low_flag & 0x1 == 0x1 {
                let size = !(low & 0xffff_fffc) + 1;
                self.io_regions.push(PciBarConfiguration::new(
                    i as usize,
                    size.into(),
                    PciBarRegionType::IoRegion,
                    PciBarPrefetchable::NotPrefetchable,
                ));
            }

            if is_64bit {
                i += 2;
            } else {
                i += 1;
            }
        }
        mem_bars
    }

    fn configure_barmem(&mut self, bar_info: &PciBarConfiguration, bar_addr: u64) {
        let offset: u32 = bar_info.reg_index() as u32 * 4;
        let mmio_region = *bar_info;
        self.mmio_regions.push(mmio_region.set_address(bar_addr));

        let val: u32 = self.config.read_config(offset);
        let low = ((bar_addr & !0xf) as u32) | (val & 0xf);
        self.config.write_config(low, offset);
        if bar_info.is_64bit_memory() {
            let upper = (bar_addr >> 32) as u32;
            self.config.write_config(upper, offset + 4);
        }
    }

    fn allocate_root_barmem(
        &mut self,
        mem_bars: &[PciBarConfiguration],
        resources: &mut SystemAllocator,
    ) -> Result<Vec<BarRange>, PciDeviceError> {
        let address = self.pci_address.unwrap();
        let mut ranges: Vec<BarRange> = Vec::new();
        for mem_bar in mem_bars {
            let bar_size = mem_bar.size();
            let mut bar_addr: u64 = 0;
            // Don't allocate mmio for hotplug device, OS will allocate it from
            // its parent's bridge window.
            if !self.hotplug {
                bar_addr = resources
                    .allocate_mmio(
                        bar_size,
                        Alloc::PciBar {
                            bus: address.bus,
                            dev: address.dev,
                            func: address.func,
                            bar: mem_bar.bar_index() as u8,
                        },
                        "vfio_bar".to_string(),
                        AllocOptions::new()
                            .prefetchable(mem_bar.is_prefetchable())
                            .max_address(if mem_bar.is_64bit_memory() {
                                u64::MAX
                            } else {
                                u32::MAX.into()
                            })
                            .align(bar_size),
                    )
                    .map_err(|e| PciDeviceError::IoAllocationFailed(bar_size, e))?;
                ranges.push(BarRange {
                    addr: bar_addr,
                    size: bar_size,
                    prefetchable: mem_bar.is_prefetchable(),
                });
            }
            self.configure_barmem(mem_bar, bar_addr);
        }
        Ok(ranges)
    }

    fn allocate_nonroot_barmem(
        &mut self,
        mem_bars: &mut [PciBarConfiguration],
        resources: &mut SystemAllocator,
    ) -> Result<Vec<BarRange>, PciDeviceError> {
        const NON_PREFETCHABLE: usize = 0;
        const PREFETCHABLE: usize = 1;
        const ARRAY_SIZE: usize = 2;
        let mut membars: [Vec<PciBarConfiguration>; ARRAY_SIZE] = [Vec::new(), Vec::new()];
        let mut allocator: [VfioResourceAllocator; ARRAY_SIZE] = [
            match VfioResourceAllocator::new(AddressRange::from_start_and_end(0, u32::MAX as u64)) {
                Ok(a) => a,
                Err(e) => {
                    error!(
                        "{} init nonroot VfioResourceAllocator failed: {}",
                        self.debug_label(),
                        e
                    );
                    return Err(e);
                }
            },
            match VfioResourceAllocator::new(AddressRange::from_start_and_end(0, u64::MAX)) {
                Ok(a) => a,
                Err(e) => {
                    error!(
                        "{} init nonroot VfioResourceAllocator failed: {}",
                        self.debug_label(),
                        e
                    );
                    return Err(e);
                }
            },
        ];
        let mut memtype: [MmioType; ARRAY_SIZE] = [MmioType::Low, MmioType::High];
        // the window must be 1M-aligned as per the PCI spec
        let mut window_sz: [u64; ARRAY_SIZE] = [0; 2];
        let mut alignment: [u64; ARRAY_SIZE] = [0x100000; 2];

        // Descend by bar size, this could reduce allocated size for all the bars.
        mem_bars.sort_by_key(|a| Reverse(a.size()));
        for mem_bar in mem_bars {
            let prefetchable = mem_bar.is_prefetchable();
            let is_64bit = mem_bar.is_64bit_memory();

            // if one prefetchable bar is 32bit, all the prefetchable bars should be in Low MMIO,
            // as all the prefetchable bars should be in one region
            if prefetchable && !is_64bit {
                memtype[PREFETCHABLE] = MmioType::Low;
            }
            let i = if prefetchable {
                PREFETCHABLE
            } else {
                NON_PREFETCHABLE
            };
            let bar_size = mem_bar.size();
            let start = match allocator[i].allocate_with_align(bar_size, bar_size) {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "{} nonroot allocate_wit_align failed: {}",
                        self.debug_label(),
                        e
                    );
                    return Err(e);
                }
            };
            window_sz[i] = max(window_sz[i], start + bar_size);
            alignment[i] = max(alignment[i], bar_size);
            let mem_info = (*mem_bar).set_address(start);
            membars[i].push(mem_info);
        }

        let address = self.pci_address.unwrap();
        let mut ranges: Vec<BarRange> = Vec::new();
        for (index, bars) in membars.iter().enumerate() {
            if bars.is_empty() {
                continue;
            }

            let i = if index == 1 {
                PREFETCHABLE
            } else {
                NON_PREFETCHABLE
            };
            let mut window_addr: u64 = 0;
            // Don't allocate mmio for hotplug device, OS will allocate it from
            // its parent's bridge window.
            if !self.hotplug {
                window_sz[i] = (window_sz[i] + 0xfffff) & !0xfffff;
                let alloc = if i == NON_PREFETCHABLE {
                    Alloc::PciBridgeWindow {
                        bus: address.bus,
                        dev: address.dev,
                        func: address.func,
                    }
                } else {
                    Alloc::PciBridgePrefetchWindow {
                        bus: address.bus,
                        dev: address.dev,
                        func: address.func,
                    }
                };
                window_addr = resources
                    .mmio_allocator(memtype[i])
                    .allocate_with_align(
                        window_sz[i],
                        alloc,
                        "vfio_bar_window".to_string(),
                        alignment[i],
                    )
                    .map_err(|e| PciDeviceError::IoAllocationFailed(window_sz[i], e))?;
                for mem_info in bars {
                    let bar_addr = window_addr + mem_info.address();
                    ranges.push(BarRange {
                        addr: bar_addr,
                        size: mem_info.size(),
                        prefetchable: mem_info.is_prefetchable(),
                    });
                }
            }

            for mem_info in bars {
                let bar_addr = window_addr + mem_info.address();
                self.configure_barmem(mem_info, bar_addr);
            }
        }
        Ok(ranges)
    }

    /// Return the supported iova max address of the Vfio Pci device
    pub fn get_max_iova(&self) -> u64 {
        self.device.get_max_addr()
    }

    fn get_ext_cap_by_reg(&self, reg: u32) -> Option<ExtCap> {
        self.ext_caps
            .iter()
            .find(|ext_cap| reg >= ext_cap.offset && reg < ext_cap.offset + ext_cap.size)
            .cloned()
    }

    fn is_skipped_reg(&self, reg: u32) -> bool {
        // fast handle for pci config space
        if reg < PCI_CONFIG_SPACE_SIZE {
            return false;
        }

        self.get_ext_cap_by_reg(reg)
            .is_some_and(|cap| cap.is_skipped)
    }
}

impl PciDevice for VfioPciDevice {
    fn debug_label(&self) -> String {
        format!("vfio {} device", self.device.device_name())
    }

    fn preferred_address(&self) -> Option<PciAddress> {
        Some(self.preferred_address)
    }

    fn allocate_address(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> Result<PciAddress, PciDeviceError> {
        if self.pci_address.is_none() {
            let mut address = self.preferred_address;
            while address.func < 8 {
                if resources.reserve_pci(address, self.debug_label()) {
                    self.pci_address = Some(address);
                    break;
                } else if self.hotplug_bus_number.is_none() {
                    break;
                } else {
                    address.func += 1;
                }
            }
            if let Some(msi_cap) = &mut self.msi_cap {
                msi_cap.config.set_pci_address(self.pci_address.unwrap());
            }
            if let Some(msix_cap) = &mut self.msix_cap {
                msix_cap
                    .lock()
                    .config
                    .set_pci_address(self.pci_address.unwrap());
            }
        }
        self.pci_address.ok_or(PciDeviceError::PciAllocationFailed)
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = self.device.keep_rds();
        if let Some(ref interrupt_evt) = self.interrupt_evt {
            rds.extend(interrupt_evt.as_raw_descriptors());
        }
        rds.push(self.vm_memory_client.as_raw_descriptor());
        if let Some(vm_socket_vm) = &self.vm_socket_vm {
            rds.push(vm_socket_vm.as_raw_descriptor());
        }
        if let Some(msi_cap) = &self.msi_cap {
            rds.push(msi_cap.config.get_msi_socket());
        }
        if let Some(msix_cap) = &self.msix_cap {
            rds.extend(msix_cap.lock().as_raw_descriptors());
        }
        rds
    }

    fn preferred_irq(&self) -> PreferredIrq {
        // Is INTx configured?
        let pin = match self.config.read_config::<u8>(PCI_INTERRUPT_PIN) {
            1 => PciInterruptPin::IntA,
            2 => PciInterruptPin::IntB,
            3 => PciInterruptPin::IntC,
            4 => PciInterruptPin::IntD,
            _ => return PreferredIrq::None,
        };

        // TODO: replace sysfs/irq value parsing with vfio interface
        //       reporting host allocated interrupt number and type.
        let path = self.sysfs_path.join("irq");
        let gsi = fs::read_to_string(path)
            .map(|v| v.trim().parse::<u32>().unwrap_or(0))
            .unwrap_or(0);

        PreferredIrq::Fixed { pin, gsi }
    }

    fn assign_irq(&mut self, irq_evt: IrqLevelEvent, pin: PciInterruptPin, irq_num: u32) {
        // Keep event/resample event references.
        self.interrupt_evt = Some(irq_evt);

        // enable INTX
        self.enable_intx();

        self.config
            .write_config(pin.to_mask() as u8, PCI_INTERRUPT_PIN);
        self.config.write_config(irq_num as u8, PCI_INTERRUPT_NUM);
    }

    fn allocate_io_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> Result<Vec<BarRange>, PciDeviceError> {
        let address = self
            .pci_address
            .expect("allocate_address must be called prior to allocate_device_bars");

        let mut mem_bars = self.collect_bars();

        let ranges = if address.bus == 0 {
            self.allocate_root_barmem(&mem_bars, resources)?
        } else {
            self.allocate_nonroot_barmem(&mut mem_bars, resources)?
        };

        // Quirk, enable igd memory for guest vga arbitrate, otherwise kernel vga arbitrate
        // driver doesn't claim this vga device, then xorg couldn't boot up.
        if self.is_intel_gfx() {
            let mut cmd = self.config.read_config::<u8>(PCI_COMMAND);
            cmd |= PCI_COMMAND_MEMORY;
            self.config.write_config(cmd, PCI_COMMAND);
        }
        Ok(ranges)
    }

    fn allocate_device_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> Result<Vec<BarRange>, PciDeviceError> {
        let mut ranges: Vec<BarRange> = Vec::new();

        if !self.is_intel_gfx() {
            return Ok(ranges);
        }

        // Make intel gfx's opregion as mmio bar, and allocate a gpa for it
        // then write this gpa into pci cfg register
        if let Some((index, size)) = self.device.get_cap_type_info(
            VFIO_REGION_TYPE_PCI_VENDOR_TYPE | (PCI_VENDOR_ID_INTEL as u32),
            VFIO_REGION_SUBTYPE_INTEL_IGD_OPREGION,
        ) {
            let address = self
                .pci_address
                .expect("allocate_address must be called prior to allocate_device_bars");
            let bar_addr = resources
                .allocate_mmio(
                    size,
                    Alloc::PciBar {
                        bus: address.bus,
                        dev: address.dev,
                        func: address.func,
                        bar: (index * 4) as u8,
                    },
                    "vfio_bar".to_string(),
                    AllocOptions::new().max_address(u32::MAX.into()),
                )
                .map_err(|e| PciDeviceError::IoAllocationFailed(size, e))?;
            ranges.push(BarRange {
                addr: bar_addr,
                size,
                prefetchable: false,
            });
            self.device_data = Some(DeviceData::IntelGfxData {
                opregion_index: index,
            });

            self.mmio_regions.push(
                PciBarConfiguration::new(
                    index as usize,
                    size,
                    PciBarRegionType::Memory32BitRegion,
                    PciBarPrefetchable::NotPrefetchable,
                )
                .set_address(bar_addr),
            );
            self.config.write_config(bar_addr as u32, 0xFC);
        }

        Ok(ranges)
    }

    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        for region in self.mmio_regions.iter().chain(self.io_regions.iter()) {
            if region.bar_index() == bar_num {
                let command: u8 = self.config.read_config(PCI_COMMAND);
                if (region.is_memory() && (command & PCI_COMMAND_MEMORY == 0)) || region.is_io() {
                    return None;
                } else {
                    return Some(*region);
                }
            }
        }

        None
    }

    fn register_device_capabilities(&mut self) -> Result<(), PciDeviceError> {
        Ok(())
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        let reg: u32 = (reg_idx * 4) as u32;
        let mut config: u32 = self.config.read_config(reg);

        // See VfioPciDevice::new for details how extended caps are managed
        if reg >= PCI_CONFIG_SPACE_SIZE {
            let ext_cap = self.get_ext_cap_by_reg(reg);
            if let Some(ext_cap) = ext_cap {
                if ext_cap.offset == reg {
                    config = (config & !(0xffc << 20)) | (((ext_cap.next & 0xffc) as u32) << 20);
                }

                if ext_cap.is_skipped {
                    if reg == PCI_CONFIG_SPACE_SIZE {
                        config = (config & (0xffc << 20)) | (PCI_EXT_CAP_ID_CAC as u32);
                    } else {
                        config = 0;
                    }
                }
            }
        }

        // Ignore IO bar
        if (0x10..=0x24).contains(&reg) {
            let bar_idx = (reg as usize - 0x10) / 4;
            if let Some(bar) = self.get_bar_configuration(bar_idx) {
                if bar.is_io() {
                    config = 0;
                }
            }
        } else if let Some(msix_cap) = &self.msix_cap {
            let msix_cap = msix_cap.lock();
            if msix_cap.is_msix_control_reg(reg, 4) {
                msix_cap.read_msix_control(&mut config);
            }
        } else if let Some(pm_cap) = &self.pm_cap {
            let pm_cap = pm_cap.lock();
            if pm_cap.is_pm_reg(reg) {
                config = pm_cap.read(reg);
            }
        }

        // Quirk for intel graphic, set stolen memory size to 0 in pci_cfg[0x51]
        if self.is_intel_gfx() && reg == 0x50 {
            config &= 0xffff00ff;
        }

        config
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        // When guest write config register at the first time, start worker thread
        if self.worker_thread.is_none() && self.vm_socket_vm.is_some() {
            self.start_work_thread();
        };

        let start = (reg_idx * 4) as u64 + offset;

        if let Some(pm_cap) = self.pm_cap.as_mut() {
            let mut pm_cap = pm_cap.lock();
            if pm_cap.is_pm_reg(start as u32) {
                pm_cap.write(start, data);
            }
        }

        let mut msi_change: Option<VfioMsiChange> = None;
        if let Some(msi_cap) = self.msi_cap.as_mut() {
            if msi_cap.is_msi_reg(start, data.len()) {
                msi_change = msi_cap.write_msi_reg(start, data);
            }
        }

        match msi_change {
            Some(VfioMsiChange::Enable) => self.enable_msi(),
            Some(VfioMsiChange::Disable) => self.disable_msi(),
            _ => (),
        }

        msi_change = None;
        if let Some(msix_cap) = &self.msix_cap {
            let mut msix_cap = msix_cap.lock();
            if msix_cap.is_msix_control_reg(start as u32, data.len() as u32) {
                msi_change = msix_cap.write_msix_control(data);
            }
        }

        match msi_change {
            Some(VfioMsiChange::Enable) => self.enable_msix(),
            Some(VfioMsiChange::Disable) => self.disable_msix(),
            Some(VfioMsiChange::FunctionChanged) => {
                if let Err(e) = self.msix_vectors_update() {
                    error!("update msix vectors failed: {}", e);
                }
            }
            _ => (),
        }

        if !self.is_skipped_reg(start as u32) {
            self.device
                .region_write(VFIO_PCI_CONFIG_REGION_INDEX as usize, data, start);
        }

        // if guest enable memory access, then enable bar mappable once
        if start == PCI_COMMAND as u64
            && data.len() == 2
            && data[0] & PCI_COMMAND_MEMORY == PCI_COMMAND_MEMORY
        {
            self.commit_bars_mmap();
        } else if (0x10..=0x24).contains(&start) && data.len() == 4 {
            let bar_idx = (start as u32 - 0x10) / 4;
            let value: [u8; 4] = [data[0], data[1], data[2], data[3]];
            let val = u32::from_le_bytes(value);
            let mut modify = false;
            for region in self.mmio_regions.iter_mut() {
                if region.bar_index() == bar_idx as usize {
                    let old_addr = region.address();
                    let new_addr = val & 0xFFFFFFF0;
                    if !region.is_64bit_memory() && (old_addr as u32) != new_addr {
                        // Change 32bit bar address
                        *region = region.set_address(u64::from(new_addr));
                        modify = true;
                    } else if region.is_64bit_memory() && (old_addr as u32) != new_addr {
                        // Change 64bit bar low address
                        *region =
                            region.set_address(u64::from(new_addr) | ((old_addr >> 32) << 32));
                        modify = true;
                    }
                    break;
                } else if region.is_64bit_memory()
                    && ((bar_idx % 2) == 1)
                    && (region.bar_index() + 1 == bar_idx as usize)
                {
                    // Change 64bit bar high address
                    let old_addr = region.address();
                    if val != (old_addr >> 32) as u32 {
                        let mut new_addr = (u64::from(val)) << 32;
                        new_addr |= old_addr & 0xFFFFFFFF;
                        *region = region.set_address(new_addr);
                        modify = true;
                    }
                    break;
                }
            }
            if modify {
                // if bar is changed under memory enabled, mmap the
                // new bar immediately.
                let cmd = self.config.read_config::<u8>(PCI_COMMAND);
                if cmd & PCI_COMMAND_MEMORY == PCI_COMMAND_MEMORY {
                    self.commit_bars_mmap();
                }
            }
        }
    }

    fn read_virtual_config_register(&self, reg_idx: usize) -> u32 {
        if reg_idx == PCI_VCFG_NOTY {
            let mut q = self.acpi_notifier_val.lock();
            let mut val = 0;
            if !q.is_empty() {
                val = q.remove(0);
            }
            drop(q);
            return val;
        }

        warn!(
            "{} read unsupported vcfg register {}",
            self.debug_label(),
            reg_idx
        );
        0xFFFF_FFFF
    }

    fn write_virtual_config_register(&mut self, reg_idx: usize, value: u32) {
        match reg_idx {
            PCI_VCFG_PM => {
                match value {
                    0 => {
                        if let Some(pm_evt) =
                            self.pm_evt.as_ref().map(|evt| evt.try_clone().unwrap())
                        {
                            *self.is_in_low_power.lock() = true;
                            let _ = self.device.pm_low_power_enter_with_wakeup(pm_evt);
                        } else {
                            let _ = self.device.pm_low_power_enter();
                        }
                    }
                    _ => {
                        *self.is_in_low_power.lock() = false;
                        let _ = self.device.pm_low_power_exit();
                    }
                };
            }
            PCI_VCFG_DSM => {
                if let Some(shm) = &self.vcfg_shm_mmap {
                    let mut args = [0u8; 4096];
                    if let Err(e) = shm.read_slice(&mut args, 0) {
                        error!("failed to read DSM Args: {}", e);
                        return;
                    }
                    let res = match self.device.acpi_dsm(&args) {
                        Ok(r) => r,
                        Err(e) => {
                            error!("failed to call DSM: {}", e);
                            return;
                        }
                    };
                    if let Err(e) = shm.write_slice(&res, 0) {
                        error!("failed to write DSM result: {}", e);
                        return;
                    }
                    if let Err(e) = shm.msync() {
                        error!("failed to msync: {}", e)
                    }
                }
            }
            _ => warn!(
                "{} write unsupported vcfg register {}",
                self.debug_label(),
                reg_idx
            ),
        };
    }

    fn read_bar(&mut self, bar_index: PciBarIndex, offset: u64, data: &mut [u8]) {
        if let Some(msix_cap) = &self.msix_cap {
            let msix_cap = msix_cap.lock();
            if msix_cap.is_msix_table(bar_index, offset) {
                msix_cap.read_table(offset, data);
                return;
            } else if msix_cap.is_msix_pba(bar_index, offset) {
                msix_cap.read_pba(offset, data);
                return;
            }
        }
        self.device.region_read(bar_index, data, offset);
    }

    fn write_bar(&mut self, bar_index: PciBarIndex, offset: u64, data: &[u8]) {
        // Ignore igd opregion's write
        if let Some(device_data) = &self.device_data {
            match *device_data {
                DeviceData::IntelGfxData { opregion_index } => {
                    if opregion_index == bar_index as u32 {
                        return;
                    }
                }
            }
        }

        if let Some(msix_cap) = &self.msix_cap {
            let mut msix_cap = msix_cap.lock();
            if msix_cap.is_msix_table(bar_index, offset) {
                let behavior = msix_cap.write_table(offset, data);
                if let MsixStatus::EntryChanged(index) = behavior {
                    let irqfd = msix_cap.get_msix_irqfd(index);
                    self.msix_vector_update(index, irqfd);
                }
                return;
            } else if msix_cap.is_msix_pba(bar_index, offset) {
                msix_cap.write_pba(offset, data);
                return;
            }
        }

        self.device.region_write(bar_index, data, offset);
    }

    fn destroy_device(&mut self) {
        self.close();
    }

    fn generate_acpi_methods(&mut self) -> (Vec<u8>, Option<(u32, MemoryMapping)>) {
        let mut amls = Vec::new();
        let mut shm = None;
        if let Some(pci_address) = self.pci_address {
            let vcfg_offset = pci_address.to_config_address(0, 13);
            if let Ok(vcfg_register) = DeviceVcfgRegister::new(vcfg_offset) {
                vcfg_register.to_aml_bytes(&mut amls);
                shm = vcfg_register
                    .create_shm_mmap()
                    .map(|shm| (vcfg_offset + SHM_OFFSET, shm));
                self.vcfg_shm_mmap = vcfg_register.create_shm_mmap();
                // All vfio-pci devices should have virtual _PRx method, otherwise
                // host couldn't know whether device has enter into suspend state,
                // host would always think it is in active state, so its parent PCIe
                // switch couldn't enter into suspend state.
                PowerResourceMethod {}.to_aml_bytes(&mut amls);
                // TODO: WIP: Ideally, we should generate DSM only if the physical
                // device has a _DSM; however, such information is not provided by
                // Linux. As a temporary workaround, we chech whether there is an
                // associated ACPI companion device node and skip generating guest
                // _DSM if there is none.
                let acpi_path = self.sysfs_path.join("firmware_node/path");
                if acpi_path.exists() {
                    DsmMethod {}.to_aml_bytes(&mut amls);
                }
            }
        }

        (amls, shm)
    }

    fn set_gpe(&mut self, resources: &mut SystemAllocator) -> Option<u32> {
        if let Some(gpe_nr) = resources.allocate_gpe() {
            base::debug!("set_gpe: gpe-nr {} addr {:?}", gpe_nr, self.pci_address);
            self.gpe = Some(gpe_nr);
        }
        self.gpe
    }
}

impl Suspendable for VfioPciDevice {
    fn sleep(&mut self) -> anyhow::Result<()> {
        if let Some(worker_thread) = self.worker_thread.take() {
            let res = worker_thread.stop();
            self.pci_address = Some(res.address);
            self.sysfs_path = res.sysfs_path;
            self.pm_cap = res.pm_cap;
            self.msix_cap = res.msix_cap;
            self.vm_socket_vm = Some(res.vm_socket);
        }
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        if self.activated {
            self.start_work_thread();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use resources::AddressRange;

    use super::VfioResourceAllocator;

    #[test]
    fn no_overlap() {
        // regions [32, 95]
        let mut memory =
            VfioResourceAllocator::new(AddressRange::from_start_and_end(32, 95)).unwrap();
        memory
            .allocate_at_can_overlap(AddressRange::from_start_and_end(0, 15))
            .unwrap();
        memory
            .allocate_at_can_overlap(AddressRange::from_start_and_end(100, 115))
            .unwrap();

        let mut iter = memory.regions.iter();
        assert_eq!(iter.next(), Some(&AddressRange::from_start_and_end(32, 95)));
    }

    #[test]
    fn complete_overlap() {
        // regions [32, 95]
        let mut memory =
            VfioResourceAllocator::new(AddressRange::from_start_and_end(32, 95)).unwrap();
        // regions [32, 47], [64, 95]
        memory
            .allocate_at_can_overlap(AddressRange::from_start_and_end(48, 63))
            .unwrap();
        // regions [64, 95]
        memory
            .allocate_at_can_overlap(AddressRange::from_start_and_end(32, 47))
            .unwrap();

        let mut iter = memory.regions.iter();
        assert_eq!(iter.next(), Some(&AddressRange::from_start_and_end(64, 95)));
    }

    #[test]
    fn partial_overlap_one() {
        // regions [32, 95]
        let mut memory =
            VfioResourceAllocator::new(AddressRange::from_start_and_end(32, 95)).unwrap();
        // regions [32, 47], [64, 95]
        memory
            .allocate_at_can_overlap(AddressRange::from_start_and_end(48, 63))
            .unwrap();
        // regions [32, 39], [64, 95]
        memory
            .allocate_at_can_overlap(AddressRange::from_start_and_end(40, 55))
            .unwrap();

        let mut iter = memory.regions.iter();
        assert_eq!(iter.next(), Some(&AddressRange::from_start_and_end(32, 39)));
        assert_eq!(iter.next(), Some(&AddressRange::from_start_and_end(64, 95)));
    }

    #[test]
    fn partial_overlap_two() {
        // regions [32, 95]
        let mut memory =
            VfioResourceAllocator::new(AddressRange::from_start_and_end(32, 95)).unwrap();
        // regions [32, 47], [64, 95]
        memory
            .allocate_at_can_overlap(AddressRange::from_start_and_end(48, 63))
            .unwrap();
        // regions [32, 39], [72, 95]
        memory
            .allocate_at_can_overlap(AddressRange::from_start_and_end(40, 71))
            .unwrap();

        let mut iter = memory.regions.iter();
        assert_eq!(iter.next(), Some(&AddressRange::from_start_and_end(32, 39)));
        assert_eq!(iter.next(), Some(&AddressRange::from_start_and_end(72, 95)));
    }

    #[test]
    fn partial_overlap_three() {
        // regions [32, 95]
        let mut memory =
            VfioResourceAllocator::new(AddressRange::from_start_and_end(32, 95)).unwrap();
        // regions [32, 39], [48, 95]
        memory
            .allocate_at_can_overlap(AddressRange::from_start_and_end(40, 47))
            .unwrap();
        // regions [32, 39], [48, 63], [72, 95]
        memory
            .allocate_at_can_overlap(AddressRange::from_start_and_end(64, 71))
            .unwrap();
        // regions [32, 35], [76, 95]
        memory
            .allocate_at_can_overlap(AddressRange::from_start_and_end(36, 75))
            .unwrap();

        let mut iter = memory.regions.iter();
        assert_eq!(iter.next(), Some(&AddressRange::from_start_and_end(32, 35)));
        assert_eq!(iter.next(), Some(&AddressRange::from_start_and_end(76, 95)));
    }
}
