// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::btree_map::Entry as BTreeMapEntry;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::ops::Bound::Included;
use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::Weak;

use anyhow::Context;
use base::error;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::Protection;
use base::RawDescriptor;
use base::SendTube;
use base::SharedMemory;
use base::VmEventType;
use hypervisor::MemCacheType;
use hypervisor::Vm;
use resources::SystemAllocator;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
use sync::Mutex;
use vm_memory::GuestAddress;

use crate::pci::pci_configuration::PciBarConfiguration;
use crate::pci::pci_configuration::PciBridgeSubclass;
use crate::pci::pci_configuration::PciClassCode;
use crate::pci::pci_configuration::PciConfiguration;
use crate::pci::pci_configuration::PciHeaderType;
use crate::pci::pci_configuration::HEADER_TYPE_MULTIFUNCTION_MASK;
use crate::pci::pci_configuration::HEADER_TYPE_REG;
use crate::pci::pci_configuration::HEADER_TYPE_REG_OFFSET;
use crate::pci::pci_device::Error;
use crate::pci::pci_device::PciBus;
use crate::pci::pci_device::PciDevice;
use crate::pci::PciAddress;
use crate::pci::PciBarIndex;
use crate::pci::PciId;
use crate::pci::PCI_VENDOR_ID_INTEL;
use crate::Bus;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::BusType;
use crate::DeviceId;
use crate::Suspendable;

// A PciDevice that holds the root hub's configuration.
struct PciRootConfiguration {
    config: PciConfiguration,
}

impl PciDevice for PciRootConfiguration {
    fn debug_label(&self) -> String {
        "pci root device".to_owned()
    }
    fn allocate_address(&mut self, _resources: &mut SystemAllocator) -> Result<PciAddress, Error> {
        // PCI root fixed address.
        Ok(PciAddress {
            bus: 0,
            dev: 0,
            func: 0,
        })
    }
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }
    fn read_config_register(&self, reg_idx: usize) -> u32 {
        self.config.read_reg(reg_idx)
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        self.config.write_reg(reg_idx, offset, data);
    }

    fn setup_pci_config_mapping(
        &mut self,
        shmem: &SharedMemory,
        base: usize,
        len: usize,
    ) -> Result<bool, Error> {
        self.config
            .setup_mapping(shmem, base, len)
            .map(|_| true)
            .map_err(Error::MmioSetup)
    }

    fn read_bar(&mut self, _bar_index: PciBarIndex, _offset: u64, _data: &mut [u8]) {}

    fn write_bar(&mut self, _bar_index: PciBarIndex, _offset: u64, _data: &[u8]) {}

    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        self.config.get_bar_configuration(bar_num)
    }
}

impl Suspendable for PciRootConfiguration {
    // no thread to sleep, no change required.
    fn sleep(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        self.config
            .snapshot()
            .with_context(|| format!("failed to serialize {}", PciDevice::debug_label(self)))
    }

    fn restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        self.config
            .restore(data)
            .context("failed to deserialize PciRootConfiguration")
    }
}

// Command send to pci root worker thread to add/remove device from pci root
pub enum PciRootCommand {
    Add(PciAddress, Arc<Mutex<dyn BusDevice>>),
    AddBridge(Arc<Mutex<PciBus>>),
    Remove(PciAddress),
    Kill,
}

#[derive(Serialize)]
struct PciRootMmioState {
    /// Contains pages mapped read-only into the guest's MMIO space corresponding to
    /// the PCI configuration space. Keys are the offset in number of pages from the
    /// start of MMIO space. If a particular value is None, then at least one
    /// attached device on that page does not support read-only mapped MMIO.
    #[serde(skip_serializing)]
    mappings: BTreeMap<u32, Option<(SharedMemory, MemoryMapping)>>,
    /// Base address of the PCI configuration space's MMIO region.
    base: GuestAddress,
    /// Number of bits in the address space of a particular function's MMIO space.
    register_bit_num: usize,
}

/// Emulates the PCI Root bridge.
#[allow(dead_code)] // TODO(b/174705596): remove once mmio_bus and io_bus are used
pub struct PciRoot {
    /// Memory (MMIO) bus.
    mmio_bus: Weak<Bus>,
    /// IO bus (x86 only - for non-x86 platforms, this is just an empty Bus).
    io_bus: Weak<Bus>,
    /// Root pci bus (bus 0)
    root_bus: Arc<Mutex<PciBus>>,
    /// Bus configuration for the root device.
    root_configuration: PciRootConfiguration,
    /// Devices attached to this bridge.
    devices: BTreeMap<PciAddress, Arc<Mutex<dyn BusDevice>>>,
    /// pcie enhanced configuration access mmio base
    pcie_cfg_mmio: Option<u64>,
    pci_mmio_state: PciRootMmioState,
}

const PCI_DEVICE_ID_INTEL_82441: u16 = 0x1237;
const PCIE_XBAR_BASE_ADDR: usize = 24;

/// Used to serialize relevant information to PciRoot
#[derive(Serialize, Deserialize)]
struct PciRootSerializable {
    root_configuration: AnySnapshot,
    pcie_cfg_mmio: Option<u64>,
}

impl PciRoot {
    /// Create an empty PCI root bus.
    pub fn new(
        vm: &mut impl Vm,
        mmio_bus: Weak<Bus>,
        mmio_base: GuestAddress,
        mmio_register_bit_num: usize,
        io_bus: Weak<Bus>,
        root_bus: Arc<Mutex<PciBus>>,
    ) -> anyhow::Result<Self> {
        // mmio_mappings's implementation assumes each device's mmio registers
        // can fit on a single page. Always true given existing specs.
        assert!(base::pagesize() >= (1 << mmio_register_bit_num));
        let mut root =
            Self::create_for_test(mmio_bus, mmio_base, mmio_register_bit_num, io_bus, root_bus);
        root.pci_mmio_state
            .setup_mapping(
                &PciAddress::new(0, 0, 0, 0).unwrap(),
                &mut root.root_configuration,
                vm,
            )
            .context("failed to set up root configuration mapping")?;
        Ok(root)
    }

    fn create_for_test(
        mmio_bus: Weak<Bus>,
        mmio_base: GuestAddress,
        mmio_register_bit_num: usize,
        io_bus: Weak<Bus>,
        root_bus: Arc<Mutex<PciBus>>,
    ) -> Self {
        PciRoot {
            mmio_bus,
            io_bus,
            root_bus,
            root_configuration: PciRootConfiguration {
                config: PciConfiguration::new(
                    PCI_VENDOR_ID_INTEL,
                    PCI_DEVICE_ID_INTEL_82441,
                    PciClassCode::BridgeDevice,
                    &PciBridgeSubclass::HostBridge,
                    None,
                    PciHeaderType::Device,
                    0,
                    0,
                    0,
                ),
            },
            devices: BTreeMap::new(),
            pcie_cfg_mmio: None,
            pci_mmio_state: PciRootMmioState {
                mappings: BTreeMap::new(),
                base: mmio_base,
                register_bit_num: mmio_register_bit_num,
            },
        }
    }

    /// Get the root pci bus
    pub fn get_root_bus(&self) -> Arc<Mutex<PciBus>> {
        self.root_bus.clone()
    }

    /// Get the ACPI path to a PCI device
    pub fn acpi_path(&self, address: &PciAddress) -> Option<String> {
        if let Some(device) = self.devices.get(address) {
            let path = self.root_bus.lock().path_to(address.bus);
            if path.is_empty() {
                None
            } else {
                Some(format!(
                    "_SB_.{}.{}",
                    path.iter()
                        .map(|x| format!("PC{:02X}", x))
                        .collect::<Vec<String>>()
                        .join("."),
                    match device.lock().is_bridge() {
                        Some(bus_no) => format!("PC{:02X}", bus_no),
                        None => format!("PE{:02X}", address.devfn()),
                    }
                ))
            }
        } else {
            None
        }
    }

    /// enable pcie enhanced configuration access and set base mmio
    pub fn enable_pcie_cfg_mmio(&mut self, pcie_cfg_mmio: u64) {
        self.pcie_cfg_mmio = Some(pcie_cfg_mmio);
        // Update the config space registers that depend on pcie_cfg_mmio.
        self.root_configuration.config.set_reg(
            PCIE_XBAR_BASE_ADDR,
            self.pcie_cfg_mmio.unwrap() as u32 | 0x1,
            0xffff_ffff,
        );
        self.root_configuration.config.set_reg(
            PCIE_XBAR_BASE_ADDR + 1,
            (self.pcie_cfg_mmio.unwrap() >> 32) as u32,
            0xffff_ffff,
        );
    }

    /// Add a `device` to this root PCI bus.
    pub fn add_device<T>(
        &mut self,
        address: PciAddress,
        device: Arc<Mutex<dyn BusDevice>>,
        mapper: &mut T,
    ) -> Result<(), Error>
    where
        T: PciMmioMapper,
    {
        // Ignore attempt to replace PCI Root host bridge.
        if !address.is_root() {
            self.pci_mmio_state
                .setup_mapping(&address, device.lock().deref_mut(), mapper)
                .map_err(Error::MmioSetup)?;
            self.devices.insert(address, device);
            self.sync_multifunction_bit_to_mmio_mappings(&address, true);
        }

        self.root_bus.lock().add_child_device(address)
    }

    fn sync_multifunction_bit_to_mmio_mappings(&mut self, address: &PciAddress, on_add: bool) {
        let num_mfd = self.num_multifunction_device(address);
        let target_range = if (num_mfd == 1 && on_add) || (num_mfd == 0 && !on_add) {
            // If we added the first mfd or removed the last mfd, update all functions' bits
            0..8
        } else if on_add && num_mfd > 0 {
            // If we added a new function, set its bit if necessary
            address.func..(address.func + 1)
        } else {
            return;
        };
        for i in target_range {
            self.pci_mmio_state.set_mfd_bit(
                &PciAddress {
                    func: i,
                    ..*address
                },
                num_mfd > 0,
            );
        }
    }

    pub fn add_bridge(&mut self, bridge_bus: Arc<Mutex<PciBus>>) -> Result<(), Error> {
        self.root_bus.lock().add_child_bus(bridge_bus)
    }

    pub fn remove_device(&mut self, address: PciAddress) {
        if let Some(d) = self.devices.remove(&address) {
            for (range, bus_type) in d.lock().get_ranges() {
                let bus_ptr = if bus_type == BusType::Mmio {
                    match self.mmio_bus.upgrade() {
                        Some(m) => m,
                        None => continue,
                    }
                } else {
                    match self.io_bus.upgrade() {
                        Some(i) => i,
                        None => continue,
                    }
                };
                let _ = bus_ptr.remove(range.base, range.len);
            }
            // Remove the pci bus if this device is a pci bridge.
            if let Some(bus_no) = d.lock().is_bridge() {
                let _ = self.root_bus.lock().remove_child_bus(bus_no);
            }
            d.lock().destroy_device();
            let _ = self.root_bus.lock().remove_child_device(address);
        }
        self.sync_multifunction_bit_to_mmio_mappings(&address, false);
    }

    pub fn config_space_read(&self, address: PciAddress, register: usize) -> u32 {
        if address.is_root() {
            if register == PCIE_XBAR_BASE_ADDR && self.pcie_cfg_mmio.is_some() {
                let pcie_mmio = self.pcie_cfg_mmio.unwrap() as u32;
                pcie_mmio | 0x1
            } else if register == (PCIE_XBAR_BASE_ADDR + 1) && self.pcie_cfg_mmio.is_some() {
                (self.pcie_cfg_mmio.unwrap() >> 32) as u32
            } else {
                self.root_configuration.config_register_read(register)
            }
        } else {
            let mut data = self
                .devices
                .get(&address)
                .map_or(0xffff_ffff, |d| d.lock().config_register_read(register));

            if register == HEADER_TYPE_REG {
                // Set multifunction bit in header type if there are devices at non-zero functions
                // in this slot.
                if self.num_multifunction_device(&address) != 0 {
                    data |= (HEADER_TYPE_MULTIFUNCTION_MASK as u32) << (HEADER_TYPE_REG_OFFSET * 8);
                }
            }

            data
        }
    }

    pub fn config_space_write(
        &mut self,
        address: PciAddress,
        register: usize,
        offset: u64,
        data: &[u8],
    ) {
        if offset as usize + data.len() > 4 {
            return;
        }
        if address.is_root() {
            self.root_configuration
                .config_register_write(register, offset, data);
        } else if let Some(d) = self.devices.get(&address) {
            let res = d.lock().config_register_write(register, offset, data);

            if !res.mmio_add.is_empty() || !res.mmio_remove.is_empty() {
                let mmio_bus = match self.mmio_bus.upgrade() {
                    Some(m) => m,
                    None => return,
                };
                for range in &res.mmio_remove {
                    let _ = mmio_bus.remove(range.base, range.len);
                }
                for range in &res.mmio_add {
                    let _ = mmio_bus.insert(d.clone(), range.base, range.len);
                }
            }

            if !res.io_add.is_empty() || !res.io_remove.is_empty() {
                let io_bus = match self.io_bus.upgrade() {
                    Some(i) => i,
                    None => return,
                };
                for range in &res.io_remove {
                    let _ = io_bus.remove(range.base, range.len);
                }
                for range in &res.io_add {
                    let _ = io_bus.insert(d.clone(), range.base, range.len);
                }
            }

            for remove_pci_device in res.removed_pci_devices.iter() {
                self.remove_device(*remove_pci_device);
            }
        }
    }

    pub fn virtual_config_space_read(&self, address: PciAddress, register: usize) -> u32 {
        if address.is_root() {
            0u32
        } else {
            self.devices
                .get(&address)
                .map_or(0u32, |d| d.lock().virtual_config_register_read(register))
        }
    }

    pub fn virtual_config_space_write(&mut self, address: PciAddress, register: usize, value: u32) {
        if !address.is_root() {
            if let Some(d) = self.devices.get(&address) {
                d.lock().virtual_config_register_write(register, value);
            }
        }
    }

    pub fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        AnySnapshot::to_any(PciRootSerializable {
            root_configuration: self
                .root_configuration
                .snapshot()
                .context("failed to serialize PciRoot.root_configuration")?,
            pcie_cfg_mmio: self.pcie_cfg_mmio,
        })
        .context("failed to serialize PciRoot")
    }

    pub fn restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        let deser: PciRootSerializable =
            AnySnapshot::from_any(data).context("failed to deserialize PciRoot")?;
        self.root_configuration.restore(deser.root_configuration)?;
        self.pcie_cfg_mmio = deser.pcie_cfg_mmio;
        Ok(())
    }

    fn num_multifunction_device(&self, address: &PciAddress) -> usize {
        self.devices
            .range((
                Included(&PciAddress {
                    func: 1,
                    ..*address
                }),
                Included(&PciAddress {
                    func: 7,
                    ..*address
                }),
            ))
            .count()
    }
}

impl PciRootMmioState {
    fn setup_mapping<T>(
        &mut self,
        address: &PciAddress,
        device: &mut dyn BusDevice,
        mapper: &mut T,
    ) -> anyhow::Result<()>
    where
        T: PciMmioMapper,
    {
        // The PCI spec requires that config writes are non-posted. This requires
        // uncached mappings in the guest. 32-bit ARM does not support flushing to
        // PoC from userspace. The cache maintance story for riscv is unclear, so
        // that is also not implemmented.
        if cfg!(not(any(target_arch = "x86_64", target_arch = "aarch64"))) {
            return Ok(());
        }

        // The optional optimizations below require the hypervisor to support read-only memory
        // regions.
        if !mapper.supports_readonly_mapping() {
            return Ok(());
        }

        let pagesize = base::pagesize();
        let offset = address.to_config_address(0, self.register_bit_num);
        let mmio_mapping_num = offset / pagesize as u32;
        let (shmem, new_entry) = match self.mappings.entry(mmio_mapping_num) {
            BTreeMapEntry::Vacant(e) => {
                let shmem = SharedMemory::new(
                    format!("{:04x}_pci_cfg_mapping", mmio_mapping_num),
                    pagesize as u64,
                )
                .context("failed to create shmem")?;
                let mapping = MemoryMappingBuilder::new(pagesize)
                    .from_shared_memory(&shmem)
                    .protection(Protection::read_write())
                    .build()
                    .context("failed to map shmem")?;
                let (shmem, _) = e.insert(Some((shmem, mapping))).as_ref().unwrap();
                (shmem, true)
            }
            BTreeMapEntry::Occupied(e) => {
                let Some((shmem, _)) = e.into_mut() else {
                    // Another device sharing the page didn't support mapped mmio. Oh
                    // well, we'll just have to fall back to vm-exit handling.
                    return Ok(());
                };
                (&*shmem, false)
            }
        };

        if device.init_pci_config_mapping(
            shmem,
            offset as usize % pagesize,
            1 << self.register_bit_num,
        ) {
            if new_entry {
                let mmio_address = self
                    .base
                    .unchecked_add(mmio_mapping_num as u64 * pagesize as u64);
                match mapper.add_mapping(mmio_address, shmem) {
                    // We never unmap the mapping, so we don't need the id
                    Ok(_) => (),
                    // If this fails, mmio handling via vm-exit will work fine. Devices
                    // will be doing some pointless work keeping the unused mapping up
                    // to date, but addressing that isn't worth the implementation cost.
                    Err(e) => error!("Failed to map mmio page; {:?}", e),
                }
            }
        } else {
            self.mappings.insert(mmio_mapping_num, None);
        }
        Ok(())
    }

    fn set_mfd_bit(&mut self, address: &PciAddress, is_mfd: bool) {
        let pagesize = base::pagesize();
        let offset = address.to_config_address(0, self.register_bit_num);
        let mapping_num = offset / pagesize as u32;
        if let Some(Some((_, mapping))) = self.mappings.get_mut(&mapping_num) {
            let mapping_base = offset as usize % pagesize;
            let reg_offset = mapping_base + (HEADER_TYPE_REG * 4) + HEADER_TYPE_REG_OFFSET;

            let mut val = mapping.read_obj::<u8>(reg_offset).expect("memcpy failed");
            val = if is_mfd {
                val | HEADER_TYPE_MULTIFUNCTION_MASK
            } else {
                val & !HEADER_TYPE_MULTIFUNCTION_MASK
            };
            mapping
                .write_obj_volatile(val, reg_offset)
                .expect("memcpy failed");
            if let Err(err) = mapping.flush_region(reg_offset, 4) {
                error!("failed to flush write to mfd bit: {}", err);
            }
        }
    }
}

pub trait PciMmioMapper {
    fn supports_readonly_mapping(&self) -> bool;
    fn add_mapping(&mut self, addr: GuestAddress, shmem: &SharedMemory) -> anyhow::Result<u32>;
}

impl<T: Vm> PciMmioMapper for T {
    fn supports_readonly_mapping(&self) -> bool {
        self.check_capability(hypervisor::VmCap::ReadOnlyMemoryRegion)
    }

    fn add_mapping(&mut self, addr: GuestAddress, shmem: &SharedMemory) -> anyhow::Result<u32> {
        let mapping = MemoryMappingBuilder::new(base::pagesize())
            .from_shared_memory(shmem)
            .protection(Protection::read())
            .build()
            .context("failed to map shmem")?;
        self.add_memory_region(
            addr,
            Box::new(mapping),
            true,
            false,
            MemCacheType::CacheCoherent,
        )
        .context("failed to create vm mapping")
    }
}

/// Emulates PCI configuration access mechanism #1 (I/O ports 0xcf8 and 0xcfc).
pub struct PciConfigIo {
    /// PCI root bridge.
    pci_root: Arc<Mutex<PciRoot>>,
    /// Current address to read/write from (0xcf8 register, litte endian).
    config_address: u32,
    /// Whether or not to actually function.
    break_linux_pci_config_io: bool,
    /// Tube to signal that the guest requested reset via writing to 0xcf9 register.
    reset_evt_wrtube: SendTube,
}

#[derive(Serialize, Deserialize)]
struct PciConfigIoSerializable {
    pci_root: AnySnapshot,
    config_address: u32,
}

impl PciConfigIo {
    const REGISTER_BITS_NUM: usize = 8;

    pub fn new(
        pci_root: Arc<Mutex<PciRoot>>,
        break_linux_pci_config_io: bool,
        reset_evt_wrtube: SendTube,
    ) -> Self {
        PciConfigIo {
            pci_root,
            config_address: 0,
            break_linux_pci_config_io,
            reset_evt_wrtube,
        }
    }

    fn config_space_read(&self) -> u32 {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return 0xffff_ffff;
        }

        let (address, register) =
            PciAddress::from_config_address(self.config_address, Self::REGISTER_BITS_NUM);
        self.pci_root.lock().config_space_read(address, register)
    }

    fn config_space_write(&mut self, offset: u64, data: &[u8]) {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return;
        }

        let (address, register) =
            PciAddress::from_config_address(self.config_address, Self::REGISTER_BITS_NUM);
        self.pci_root
            .lock()
            .config_space_write(address, register, offset, data)
    }

    fn set_config_address(&mut self, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }
        let (mask, value): (u32, u32) = match data.len() {
            1 => (
                0x0000_00ff << (offset * 8),
                (data[0] as u32) << (offset * 8),
            ),
            2 => (
                0x0000_ffff << (offset * 8),
                u32::from(u16::from_le_bytes(data.try_into().unwrap())) << (offset * 8),
            ),
            4 => (0xffff_ffff, u32::from_le_bytes(data.try_into().unwrap())),
            _ => return,
        };
        self.config_address = (self.config_address & !mask) | value;
    }
}

const PCI_RESET_CPU_BIT: u8 = 1 << 2;

impl BusDevice for PciConfigIo {
    fn debug_label(&self) -> String {
        "pci config io-port".to_string()
    }

    fn device_id(&self) -> DeviceId {
        PciId::new(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82441).into()
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        if self.break_linux_pci_config_io {
            for d in data {
                *d = 0xff;
            }
            return;
        }
        // `offset` is relative to 0xcf8
        let value = match info.offset {
            0..=3 => self.config_address,
            4..=7 => self.config_space_read(),
            _ => 0xffff_ffff,
        };

        // Only allow reads to the register boundary.
        let start = info.offset as usize % 4;
        let end = start + data.len();
        if end <= 4 {
            for i in start..end {
                data[i - start] = (value >> (i * 8)) as u8;
            }
        } else {
            for d in data {
                *d = 0xff;
            }
        }
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        // `offset` is relative to 0xcf8
        match info.offset {
            _o @ 1 if data.len() == 1 && data[0] & PCI_RESET_CPU_BIT != 0 => {
                if let Err(e) = self
                    .reset_evt_wrtube
                    .send::<VmEventType>(&VmEventType::Reset)
                {
                    error!("failed to trigger PCI 0xcf9 reset event: {}", e);
                }
            }
            o @ 0..=3 => self.set_config_address(o, data),
            o @ 4..=7 => self.config_space_write(o - 4, data),
            _ => (),
        };
    }
}

impl Suspendable for PciConfigIo {
    // no thread to sleep, no change required.
    fn sleep(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        AnySnapshot::to_any(PciConfigIoSerializable {
            pci_root: self
                .pci_root
                .lock()
                .snapshot()
                .context("failed to snapshot root")?,
            config_address: self.config_address,
        })
        .with_context(|| format!("failed to serialize {}", self.debug_label()))
    }

    fn restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        let mut root = self.pci_root.lock();
        let deser: PciConfigIoSerializable = AnySnapshot::from_any(data)
            .with_context(|| format!("failed to deserialize {}", self.debug_label()))?;
        root.restore(deser.pci_root)?;
        self.config_address = deser.config_address;
        Ok(())
    }
}

/// Emulates PCI memory-mapped configuration access mechanism.
pub struct PciConfigMmio {
    /// PCI root bridge.
    pci_root: Arc<Mutex<PciRoot>>,
    /// Register bit number in config address.
    register_bit_num: usize,
}

#[derive(Serialize, Deserialize)]
struct PciConfigMmioSerializable {
    pci_root: AnySnapshot,
    register_bit_num: usize,
}

impl PciConfigMmio {
    pub fn new(pci_root: Arc<Mutex<PciRoot>>, register_bit_num: usize) -> Self {
        PciConfigMmio {
            pci_root,
            register_bit_num,
        }
    }

    fn config_space_read(&self, config_address: u32) -> u32 {
        let (address, register) =
            PciAddress::from_config_address(config_address, self.register_bit_num);
        self.pci_root.lock().config_space_read(address, register)
    }

    fn config_space_write(&mut self, config_address: u32, offset: u64, data: &[u8]) {
        let (address, register) =
            PciAddress::from_config_address(config_address, self.register_bit_num);
        self.pci_root
            .lock()
            .config_space_write(address, register, offset, data)
    }
}

impl BusDevice for PciConfigMmio {
    fn debug_label(&self) -> String {
        "pci config mmio".to_owned()
    }

    fn device_id(&self) -> DeviceId {
        PciId::new(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82441).into()
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        // Only allow reads to the register boundary.
        let start = info.offset as usize % 4;
        let end = start + data.len();
        if end > 4 || info.offset > u32::MAX as u64 {
            for d in data {
                *d = 0xff;
            }
            return;
        }

        let value = self.config_space_read(info.offset as u32);
        for i in start..end {
            data[i - start] = (value >> (i * 8)) as u8;
        }
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        if info.offset > u32::MAX as u64 {
            return;
        }
        self.config_space_write(info.offset as u32, info.offset % 4, data)
    }
}

impl Suspendable for PciConfigMmio {
    // no thread to sleep, no change required.
    fn sleep(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        AnySnapshot::to_any(PciConfigMmioSerializable {
            pci_root: self
                .pci_root
                .lock()
                .snapshot()
                .context("failed to snapshot root")?,
            register_bit_num: self.register_bit_num,
        })
        .with_context(|| format!("failed to serialize {}", self.debug_label()))
    }

    fn restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        let mut root = self.pci_root.lock();
        let deser: PciConfigMmioSerializable = AnySnapshot::from_any(data)
            .with_context(|| format!("failed to deserialize {}", self.debug_label()))?;
        root.restore(deser.pci_root)?;
        self.register_bit_num = deser.register_bit_num;
        Ok(())
    }
}

/// Inspired by PCI configuration space, CrosVM provides 2048 dword virtual registers (8KiB in
/// total) for each PCI device. The guest can use these registers to exchange device-specific
/// information with crosvm. The first 4kB is trapped by crosvm and crosvm supplies these
/// register's emulation. The second 4KB is mapped into guest directly as shared memory, so
/// when guest access this 4KB, vm exit doesn't happen.
/// All these virtual registers from all PCI devices locate in a contiguous memory region.
/// The base address of this memory region is provided by an IntObj named VCFG in the ACPI DSDT.
/// Bit 12 is used to select the first trapped page or the second directly mapped page
/// The offset of each register is calculated in the same way as PCIe ECAM;
/// i.e. offset = (bus << 21) | (device << 16) | (function << 13) | (page_select << 12) |
/// (register_index << 2)
pub struct PciVirtualConfigMmio {
    /// PCI root bridge.
    pci_root: Arc<Mutex<PciRoot>>,
    /// Register bit number in config address.
    register_bit_num: usize,
}

#[derive(Serialize, Deserialize)]
struct PciVirtualConfigMmioSerializable {
    pci_root: AnySnapshot,
    register_bit_num: usize,
}

impl PciVirtualConfigMmio {
    pub fn new(pci_root: Arc<Mutex<PciRoot>>, register_bit_num: usize) -> Self {
        PciVirtualConfigMmio {
            pci_root,
            register_bit_num,
        }
    }
}

impl BusDevice for PciVirtualConfigMmio {
    fn debug_label(&self) -> String {
        "pci virtual config mmio".to_owned()
    }

    fn device_id(&self) -> DeviceId {
        PciId::new(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82441).into()
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        let value = if info.offset % 4 != 0 || data.len() != 4 {
            error!(
                "{} unexpected read at offset = {}, len = {}",
                self.debug_label(),
                info.offset,
                data.len()
            );
            0u32
        } else {
            let (address, register) =
                PciAddress::from_config_address(info.offset as u32, self.register_bit_num);
            self.pci_root
                .lock()
                .virtual_config_space_read(address, register)
        };
        data[0..4].copy_from_slice(&value.to_le_bytes()[..]);
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        if info.offset % 4 != 0 || data.len() != 4 {
            error!(
                "{} unexpected write at offset = {}, len = {}",
                self.debug_label(),
                info.offset,
                data.len()
            );
            return;
        }
        // Unwrap is safe as we verified length above
        let value = u32::from_le_bytes(data.try_into().unwrap());
        let (address, register) =
            PciAddress::from_config_address(info.offset as u32, self.register_bit_num);
        self.pci_root
            .lock()
            .virtual_config_space_write(address, register, value)
    }
}

impl Suspendable for PciVirtualConfigMmio {
    // no thread to sleep, no change required.
    fn sleep(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        AnySnapshot::to_any(PciVirtualConfigMmioSerializable {
            pci_root: self
                .pci_root
                .lock()
                .snapshot()
                .context("failed to snapshot root")?,
            register_bit_num: self.register_bit_num,
        })
        .with_context(|| format!("failed to serialize {}", self.debug_label()))
    }

    fn restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        let mut root = self.pci_root.lock();
        let deser: PciVirtualConfigMmioSerializable = AnySnapshot::from_any(data)
            .with_context(|| format!("failed to deserialize {}", self.debug_label()))?;
        root.restore(deser.pci_root)?;
        self.register_bit_num = deser.register_bit_num;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use base::Tube;

    use super::*;
    use crate::suspendable_tests;

    fn create_pci_root() -> Arc<Mutex<PciRoot>> {
        let io_bus = Arc::new(Bus::new(BusType::Io));
        let mmio_bus = Arc::new(Bus::new(BusType::Mmio));
        let root_bus = Arc::new(Mutex::new(PciBus::new(0, 0, false)));

        Arc::new(Mutex::new(PciRoot::create_for_test(
            Arc::downgrade(&mmio_bus),
            GuestAddress(0),
            0,
            Arc::downgrade(&io_bus),
            root_bus,
        )))
    }

    fn create_pci_io_config(pci_root: Arc<Mutex<PciRoot>>) -> PciConfigIo {
        let (reset_evt_wrtube, _) = Tube::directional_pair().unwrap();
        PciConfigIo::new(pci_root, false, reset_evt_wrtube)
    }

    fn modify_pci_io_config(pci_config: &mut PciConfigIo) {
        pci_config.config_address += 1;
    }
    fn create_pci_mmio_config(pci_root: Arc<Mutex<PciRoot>>) -> PciConfigMmio {
        PciConfigMmio::new(pci_root, 0)
    }

    fn modify_pci_mmio_config(pci_config: &mut PciConfigMmio) {
        pci_config.register_bit_num += 1;
    }

    fn create_pci_virtual_config_mmio(pci_root: Arc<Mutex<PciRoot>>) -> PciVirtualConfigMmio {
        PciVirtualConfigMmio::new(pci_root, 0)
    }

    fn modify_pci_virtual_config_mmio(pci_config: &mut PciVirtualConfigMmio) {
        pci_config.register_bit_num += 1;
    }

    suspendable_tests!(
        pci_io_config,
        create_pci_io_config(create_pci_root()),
        modify_pci_io_config
    );
    suspendable_tests!(
        pcie_mmio_config,
        create_pci_mmio_config(create_pci_root()),
        modify_pci_mmio_config
    );
    suspendable_tests!(
        pci_virtual_config_mmio,
        create_pci_virtual_config_mmio(create_pci_root()),
        modify_pci_virtual_config_mmio
    );

    #[test]
    fn pci_set_config_address_word() {
        let mut pci_io_config = create_pci_io_config(create_pci_root());

        // Set the full 32-bit config_address to a known value (0x11223344).
        pci_io_config.write(
            BusAccessInfo {
                offset: 0,
                address: 0xCF8,
                id: 0,
            },
            &[0x44, 0x33, 0x22, 0x11],
        );

        // Overwrite the high 16 bits of config_address with 0x55AA (test for b/274366589).
        pci_io_config.write(
            BusAccessInfo {
                offset: 2,
                address: 0xCFA,
                id: 0,
            },
            &[0xAA, 0x55],
        );

        // Verify config_address has the expected value (0x55AA3344).
        let mut config_address = [0u8; 4];
        pci_io_config.read(
            BusAccessInfo {
                offset: 0,
                address: 0xCF8,
                id: 0,
            },
            &mut config_address,
        );
        assert_eq!(config_address, [0x44, 0x33, 0xAA, 0x55]);
    }
}
