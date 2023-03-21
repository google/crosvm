// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::sync::Arc;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use acpi_tables::sdt::SDT;
use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::Event;
use base::Protection;
use base::RawDescriptor;
use base::Result;
use base::Tube;
use data_model::DataInit;
use data_model::Le32;
use hypervisor::Datamatch;
use libc::ERANGE;
use resources::Alloc;
use resources::AllocOptions;
use resources::SystemAllocator;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_ACKNOWLEDGE;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_DRIVER;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_DRIVER_OK;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_FAILED;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_FEATURES_OK;
use virtio_sys::virtio_config::VIRTIO_CONFIG_S_NEEDS_RESET;
use vm_control::MemSlot;
use vm_control::VmMemoryDestination;
use vm_control::VmMemoryRequest;
use vm_control::VmMemoryResponse;
use vm_control::VmMemorySource;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::FromBytes;

use self::virtio_pci_common_config::VirtioPciCommonConfig;
use super::*;
use crate::pci::BarRange;
use crate::pci::MsixCap;
use crate::pci::MsixConfig;
use crate::pci::PciAddress;
use crate::pci::PciBarConfiguration;
use crate::pci::PciBarIndex;
use crate::pci::PciBarPrefetchable;
use crate::pci::PciBarRegionType;
use crate::pci::PciCapability;
use crate::pci::PciCapabilityID;
use crate::pci::PciClassCode;
use crate::pci::PciConfiguration;
use crate::pci::PciDevice;
use crate::pci::PciDeviceError;
use crate::pci::PciDisplaySubclass;
use crate::pci::PciHeaderType;
use crate::pci::PciId;
use crate::pci::PciInterruptPin;
use crate::pci::PciSubclass;
use crate::virtio::ipc_memory_mapper::IpcMemoryMapper;
use crate::IrqLevelEvent;
use crate::Suspendable;

#[repr(u8)]
#[derive(Debug, Copy, Clone, enumn::N)]
pub enum PciCapabilityType {
    CommonConfig = 1,
    NotifyConfig = 2,
    IsrConfig = 3,
    DeviceConfig = 4,
    PciConfig = 5,
    // Doorbell, Notification and SharedMemory are Virtio Vhost User related PCI
    // capabilities. Specified in 5.7.7.4 here
    // https://stefanha.github.io/virtio/vhost-user-slave.html#x1-2830007.
    DoorbellConfig = 6,
    NotificationConfig = 7,
    SharedMemoryConfig = 8,
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy, FromBytes)]
pub struct VirtioPciCap {
    // cap_vndr and cap_next are autofilled based on id() in pci configuration
    pub cap_vndr: u8, // Generic PCI field: PCI_CAP_ID_VNDR
    pub cap_next: u8, // Generic PCI field: next ptr
    pub cap_len: u8,  // Generic PCI field: capability length
    pub cfg_type: u8, // Identifies the structure.
    pub bar: u8,      // Where to find it.
    id: u8,           // Multiple capabilities of the same type
    padding: [u8; 2], // Pad to full dword.
    pub offset: Le32, // Offset within bar.
    pub length: Le32, // Length of the structure, in bytes.
}
// It is safe to implement DataInit; all members are simple numbers and any value is valid.
unsafe impl DataInit for VirtioPciCap {}

impl PciCapability for VirtioPciCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::VendorSpecific
    }

    fn writable_bits(&self) -> Vec<u32> {
        vec![0u32; 4]
    }
}

impl VirtioPciCap {
    pub fn new(cfg_type: PciCapabilityType, bar: u8, offset: u32, length: u32) -> Self {
        VirtioPciCap {
            cap_vndr: 0,
            cap_next: 0,
            cap_len: std::mem::size_of::<VirtioPciCap>() as u8,
            cfg_type: cfg_type as u8,
            bar,
            id: 0,
            padding: [0; 2],
            offset: Le32::from(offset),
            length: Le32::from(length),
        }
    }

    pub fn set_cap_len(&mut self, cap_len: u8) {
        self.cap_len = cap_len;
    }
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtioPciNotifyCap {
    cap: VirtioPciCap,
    notify_off_multiplier: Le32,
}
// It is safe to implement DataInit; all members are simple numbers and any value is valid.
unsafe impl DataInit for VirtioPciNotifyCap {}

impl PciCapability for VirtioPciNotifyCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::VendorSpecific
    }

    fn writable_bits(&self) -> Vec<u32> {
        vec![0u32; 5]
    }
}

impl VirtioPciNotifyCap {
    pub fn new(
        cfg_type: PciCapabilityType,
        bar: u8,
        offset: u32,
        length: u32,
        multiplier: Le32,
    ) -> Self {
        VirtioPciNotifyCap {
            cap: VirtioPciCap {
                cap_vndr: 0,
                cap_next: 0,
                cap_len: std::mem::size_of::<VirtioPciNotifyCap>() as u8,
                cfg_type: cfg_type as u8,
                bar,
                id: 0,
                padding: [0; 2],
                offset: Le32::from(offset),
                length: Le32::from(length),
            },
            notify_off_multiplier: multiplier,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtioPciShmCap {
    cap: VirtioPciCap,
    offset_hi: Le32, // Most sig 32 bits of offset
    length_hi: Le32, // Most sig 32 bits of length
}
// It is safe to implement DataInit; all members are simple numbers and any value is valid.
unsafe impl DataInit for VirtioPciShmCap {}

impl PciCapability for VirtioPciShmCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::VendorSpecific
    }

    fn writable_bits(&self) -> Vec<u32> {
        vec![0u32; 6]
    }
}

impl VirtioPciShmCap {
    pub fn new(cfg_type: PciCapabilityType, bar: u8, offset: u64, length: u64, shmid: u8) -> Self {
        VirtioPciShmCap {
            cap: VirtioPciCap {
                cap_vndr: 0,
                cap_next: 0,
                cap_len: std::mem::size_of::<VirtioPciShmCap>() as u8,
                cfg_type: cfg_type as u8,
                bar,
                id: shmid,
                padding: [0; 2],
                offset: Le32::from(offset as u32),
                length: Le32::from(length as u32),
            },
            offset_hi: Le32::from((offset >> 32) as u32),
            length_hi: Le32::from((length >> 32) as u32),
        }
    }
}

/// Subclasses for virtio.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciVirtioSubclass {
    NonTransitionalBase = 0xff,
}

impl PciSubclass for PciVirtioSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

// Allocate one bar for the structs pointed to by the capability structures.
const COMMON_CONFIG_BAR_OFFSET: u64 = 0x0000;
const COMMON_CONFIG_SIZE: u64 = 56;
const COMMON_CONFIG_LAST: u64 = COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE - 1;
const ISR_CONFIG_BAR_OFFSET: u64 = 0x1000;
const ISR_CONFIG_SIZE: u64 = 1;
const ISR_CONFIG_LAST: u64 = ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE - 1;
const DEVICE_CONFIG_BAR_OFFSET: u64 = 0x2000;
const DEVICE_CONFIG_SIZE: u64 = 0x1000;
const DEVICE_CONFIG_LAST: u64 = DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE - 1;
const NOTIFICATION_BAR_OFFSET: u64 = 0x3000;
const NOTIFICATION_SIZE: u64 = 0x1000;
const NOTIFICATION_LAST: u64 = NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE - 1;
const MSIX_TABLE_BAR_OFFSET: u64 = 0x6000;
const MSIX_TABLE_SIZE: u64 = 0x1000;
const MSIX_TABLE_LAST: u64 = MSIX_TABLE_BAR_OFFSET + MSIX_TABLE_SIZE - 1;
const MSIX_PBA_BAR_OFFSET: u64 = 0x7000;
const MSIX_PBA_SIZE: u64 = 0x1000;
const MSIX_PBA_LAST: u64 = MSIX_PBA_BAR_OFFSET + MSIX_PBA_SIZE - 1;
const CAPABILITY_BAR_SIZE: u64 = 0x8000;

const NOTIFY_OFF_MULTIPLIER: u32 = 4; // A dword per notification address.

const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040; // Add to device type to get device ID.
const VIRTIO_PCI_REVISION_ID: u8 = 1;

const CAPABILITIES_BAR_NUM: usize = 0;
const SHMEM_BAR_NUM: usize = 2;

/// Implements the
/// [PCI](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-650001)
/// transport for virtio devices.
pub struct VirtioPciDevice {
    config_regs: PciConfiguration,
    preferred_address: Option<PciAddress>,
    pci_address: Option<PciAddress>,

    device: Box<dyn VirtioDevice>,
    device_activated: bool,
    disable_intx: bool,

    interrupt: Option<Interrupt>,
    interrupt_evt: Option<IrqLevelEvent>,
    queues: Vec<Queue>,
    queue_evts: Vec<Event>,
    mem: GuestMemory,
    settings_bar: u8,
    msix_config: Arc<Mutex<MsixConfig>>,
    msix_cap_reg_idx: Option<usize>,
    common_config: VirtioPciCommonConfig,

    iommu: Option<Arc<Mutex<IpcMemoryMapper>>>,

    // A tube that is present if the device has shared memory regions, and
    // is used to map/unmap files into the shared memory region.
    shared_memory_tube: Option<Tube>,
}

impl VirtioPciDevice {
    /// Constructs a new PCI transport for the given virtio device.
    pub fn new(
        mem: GuestMemory,
        device: Box<dyn VirtioDevice>,
        msi_device_tube: Tube,
        disable_intx: bool,
        shared_memory_tube: Option<Tube>,
    ) -> Result<Self> {
        // shared_memory_tube is required if there are shared memory regions.
        assert_eq!(
            device.get_shared_memory_region().is_none(),
            shared_memory_tube.is_none()
        );

        let mut queue_evts = Vec::new();
        for _ in device.queue_max_sizes() {
            queue_evts.push(Event::new()?)
        }
        let queues: Vec<Queue> = device
            .queue_max_sizes()
            .iter()
            .map(|&s| Queue::new(s))
            .collect();

        let pci_device_id = VIRTIO_PCI_DEVICE_ID_BASE + device.device_type() as u16;

        let (pci_device_class, pci_device_subclass) = match device.device_type() {
            DeviceType::Gpu => (
                PciClassCode::DisplayController,
                &PciDisplaySubclass::Other as &dyn PciSubclass,
            ),
            _ => (
                PciClassCode::TooOld,
                &PciVirtioSubclass::NonTransitionalBase as &dyn PciSubclass,
            ),
        };

        let num_interrupts = device.num_interrupts();

        // One MSI-X vector per queue plus one for configuration changes.
        let msix_num = u16::try_from(num_interrupts + 1).map_err(|_| base::Error::new(ERANGE))?;
        let msix_config = Arc::new(Mutex::new(MsixConfig::new(
            msix_num,
            msi_device_tube,
            PciId::new(VIRTIO_PCI_VENDOR_ID, pci_device_id).into(),
            device.debug_label(),
        )));

        let config_regs = PciConfiguration::new(
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
            pci_device_class,
            pci_device_subclass,
            None,
            PciHeaderType::Device,
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
            VIRTIO_PCI_REVISION_ID,
        );

        Ok(VirtioPciDevice {
            config_regs,
            preferred_address: device.pci_address(),
            pci_address: None,
            device,
            device_activated: false,
            disable_intx,
            interrupt: None,
            interrupt_evt: None,
            queues,
            queue_evts,
            mem,
            settings_bar: 0,
            msix_config,
            msix_cap_reg_idx: None,
            common_config: VirtioPciCommonConfig {
                driver_status: 0,
                config_generation: 0,
                device_feature_select: 0,
                driver_feature_select: 0,
                queue_select: 0,
                msix_config: VIRTIO_MSI_NO_VECTOR,
            },
            iommu: None,
            shared_memory_tube,
        })
    }

    fn is_driver_ready(&self) -> bool {
        let ready_bits = (VIRTIO_CONFIG_S_ACKNOWLEDGE
            | VIRTIO_CONFIG_S_DRIVER
            | VIRTIO_CONFIG_S_DRIVER_OK
            | VIRTIO_CONFIG_S_FEATURES_OK) as u8;
        (self.common_config.driver_status & ready_bits) == ready_bits
            && self.common_config.driver_status & VIRTIO_CONFIG_S_FAILED as u8 == 0
    }

    /// Determines if the driver has requested the device reset itself
    fn is_reset_requested(&self) -> bool {
        self.common_config.driver_status == DEVICE_RESET as u8
    }

    fn add_settings_pci_capabilities(
        &mut self,
        settings_bar: u8,
    ) -> std::result::Result<(), PciDeviceError> {
        // Add pointers to the different configuration structures from the PCI capabilities.
        let common_cap = VirtioPciCap::new(
            PciCapabilityType::CommonConfig,
            settings_bar,
            COMMON_CONFIG_BAR_OFFSET as u32,
            COMMON_CONFIG_SIZE as u32,
        );
        self.config_regs
            .add_capability(&common_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        let isr_cap = VirtioPciCap::new(
            PciCapabilityType::IsrConfig,
            settings_bar,
            ISR_CONFIG_BAR_OFFSET as u32,
            ISR_CONFIG_SIZE as u32,
        );
        self.config_regs
            .add_capability(&isr_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        // TODO(dgreid) - set based on device's configuration size?
        let device_cap = VirtioPciCap::new(
            PciCapabilityType::DeviceConfig,
            settings_bar,
            DEVICE_CONFIG_BAR_OFFSET as u32,
            DEVICE_CONFIG_SIZE as u32,
        );
        self.config_regs
            .add_capability(&device_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        let notify_cap = VirtioPciNotifyCap::new(
            PciCapabilityType::NotifyConfig,
            settings_bar,
            NOTIFICATION_BAR_OFFSET as u32,
            NOTIFICATION_SIZE as u32,
            Le32::from(NOTIFY_OFF_MULTIPLIER),
        );
        self.config_regs
            .add_capability(&notify_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        //TODO(dgreid) - How will the configuration_cap work?
        let configuration_cap = VirtioPciCap::new(PciCapabilityType::PciConfig, 0, 0, 0);
        self.config_regs
            .add_capability(&configuration_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;

        let msix_cap = MsixCap::new(
            settings_bar,
            self.msix_config.lock().num_vectors(),
            MSIX_TABLE_BAR_OFFSET as u32,
            settings_bar,
            MSIX_PBA_BAR_OFFSET as u32,
        );
        let msix_offset = self
            .config_regs
            .add_capability(&msix_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;
        self.msix_cap_reg_idx = Some(msix_offset / 4);

        self.settings_bar = settings_bar;
        Ok(())
    }

    /// Activates the underlying `VirtioDevice`. `assign_irq` has to be called first.
    fn activate(&mut self) -> anyhow::Result<()> {
        let interrupt_evt = if let Some(ref evt) = self.interrupt_evt {
            evt.try_clone()
                .with_context(|| format!("{} failed to clone interrupt_evt", self.debug_label()))?
        } else {
            return Err(anyhow!("{} interrupt_evt is none", self.debug_label()));
        };

        let mem = self.mem.clone();

        let interrupt = Interrupt::new(
            interrupt_evt,
            Some(self.msix_config.clone()),
            self.common_config.msix_config,
        );
        self.interrupt = Some(interrupt.clone());

        // Use ready queues and their events.
        let queues = self
            .queues
            .iter_mut()
            .zip(self.queue_evts.iter())
            .filter(|(q, _)| q.ready())
            .map(|(queue, evt)| {
                Ok((
                    queue.activate().context("failed to activate queue")?,
                    evt.try_clone().context("failed to clone queue_evt")?,
                ))
            })
            .collect::<anyhow::Result<Vec<(Queue, Event)>>>()?;

        if let Some(iommu) = &self.iommu {
            self.device.set_iommu(iommu);
        }

        if let Err(e) = self.device.activate(mem, interrupt, queues) {
            error!("{} activate failed: {:#}", self.debug_label(), e);
            self.common_config.driver_status |= VIRTIO_CONFIG_S_NEEDS_RESET as u8;
        } else {
            self.device_activated = true;
        }

        Ok(())
    }
}

impl PciDevice for VirtioPciDevice {
    fn supports_iommu(&self) -> bool {
        self.device.supports_iommu()
    }

    fn debug_label(&self) -> String {
        format!("pci{}", self.device.debug_label())
    }

    fn preferred_address(&self) -> Option<PciAddress> {
        self.preferred_address
    }

    fn allocate_address(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<PciAddress, PciDeviceError> {
        if self.pci_address.is_none() {
            if let Some(address) = self.preferred_address {
                if !resources.reserve_pci(
                    Alloc::PciBar {
                        bus: address.bus,
                        dev: address.dev,
                        func: address.func,
                        bar: 0,
                    },
                    self.debug_label(),
                ) {
                    return Err(PciDeviceError::PciAllocationFailed);
                }
                self.pci_address = Some(address);
            } else {
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
        }
        self.pci_address.ok_or(PciDeviceError::PciAllocationFailed)
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = self.device.keep_rds();
        if let Some(interrupt_evt) = &self.interrupt_evt {
            rds.extend(interrupt_evt.as_raw_descriptors());
        }
        let descriptor = self.msix_config.lock().get_msi_socket();
        rds.push(descriptor);
        if let Some(iommu) = &self.iommu {
            rds.append(&mut iommu.lock().as_raw_descriptors());
        }
        rds
    }

    fn assign_irq(&mut self, irq_evt: IrqLevelEvent, pin: PciInterruptPin, irq_num: u32) {
        self.interrupt_evt = Some(irq_evt);
        if !self.disable_intx {
            self.config_regs.set_irq(irq_num as u8, pin);
        }
    }

    fn allocate_io_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<Vec<BarRange>, PciDeviceError> {
        let address = self
            .pci_address
            .expect("allocaten_address must be called prior to allocate_io_bars");
        // Allocate one bar for the structures pointed to by the capability structures.
        let mut ranges: Vec<BarRange> = Vec::new();
        let settings_config_addr = resources
            .allocate_mmio(
                CAPABILITY_BAR_SIZE,
                Alloc::PciBar {
                    bus: address.bus,
                    dev: address.dev,
                    func: address.func,
                    bar: 0,
                },
                format!("virtio-{}-cap_bar", self.device.device_type()),
                AllocOptions::new()
                    .max_address(u32::MAX.into())
                    .align(CAPABILITY_BAR_SIZE),
            )
            .map_err(|e| PciDeviceError::IoAllocationFailed(CAPABILITY_BAR_SIZE, e))?;
        let config = PciBarConfiguration::new(
            CAPABILITIES_BAR_NUM,
            CAPABILITY_BAR_SIZE,
            PciBarRegionType::Memory32BitRegion,
            PciBarPrefetchable::NotPrefetchable,
        )
        .set_address(settings_config_addr);
        let settings_bar = self
            .config_regs
            .add_pci_bar(config)
            .map_err(|e| PciDeviceError::IoRegistrationFailed(settings_config_addr, e))?
            as u8;
        ranges.push(BarRange {
            addr: settings_config_addr,
            size: CAPABILITY_BAR_SIZE,
            prefetchable: false,
        });

        // Once the BARs are allocated, the capabilities can be added to the PCI configuration.
        self.add_settings_pci_capabilities(settings_bar)?;

        Ok(ranges)
    }

    fn allocate_device_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<Vec<BarRange>, PciDeviceError> {
        let address = self
            .pci_address
            .expect("allocaten_address must be called prior to allocate_device_bars");
        let mut ranges: Vec<BarRange> = Vec::new();

        let configs = self.device.get_device_bars(address);
        let configs = if !configs.is_empty() {
            configs
        } else {
            let region = match self.device.get_shared_memory_region() {
                None => return Ok(Vec::new()),
                Some(r) => r,
            };
            let config = PciBarConfiguration::new(
                SHMEM_BAR_NUM,
                region
                    .length
                    .checked_next_power_of_two()
                    .expect("bar too large"),
                PciBarRegionType::Memory64BitRegion,
                PciBarPrefetchable::Prefetchable,
            );

            let alloc = Alloc::PciBar {
                bus: address.bus,
                dev: address.dev,
                func: address.func,
                bar: config.bar_index() as u8,
            };

            self.device
                .set_shared_memory_mapper(Box::new(VmRequester::new(
                    self.shared_memory_tube
                        .take()
                        .expect("missing shared_memory_tube"),
                    alloc,
                )));

            vec![config]
        };

        for config in configs {
            let device_addr = resources
                .allocate_mmio(
                    config.size(),
                    Alloc::PciBar {
                        bus: address.bus,
                        dev: address.dev,
                        func: address.func,
                        bar: config.bar_index() as u8,
                    },
                    format!("virtio-{}-custom_bar", self.device.device_type()),
                    AllocOptions::new()
                        .prefetchable(config.is_prefetchable())
                        .align(config.size()),
                )
                .map_err(|e| PciDeviceError::IoAllocationFailed(config.size(), e))?;
            let config = config.set_address(device_addr);
            let _device_bar = self
                .config_regs
                .add_pci_bar(config)
                .map_err(|e| PciDeviceError::IoRegistrationFailed(device_addr, e))?;
            ranges.push(BarRange {
                addr: device_addr,
                size: config.size(),
                prefetchable: false,
            });
        }

        if self.device.get_shared_memory_region().is_some() {
            self.device
                .set_shared_memory_region_base(GuestAddress(ranges[0].addr));
        }

        Ok(ranges)
    }

    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        self.config_regs.get_bar_configuration(bar_num)
    }

    fn register_device_capabilities(&mut self) -> std::result::Result<(), PciDeviceError> {
        let mut caps = self.device.get_device_caps();
        if let Some(region) = self.device.get_shared_memory_region() {
            caps.push(Box::new(VirtioPciShmCap::new(
                PciCapabilityType::SharedMemoryConfig,
                SHMEM_BAR_NUM as u8,
                0,
                region.length,
                region.id,
            )));
        }

        for cap in caps {
            self.config_regs
                .add_capability(&*cap)
                .map_err(PciDeviceError::CapabilitiesSetup)?;
        }

        Ok(())
    }

    fn ioevents(&self) -> Vec<(&Event, u64, Datamatch)> {
        let bar0 = self.config_regs.get_bar_addr(self.settings_bar as usize);
        let notify_base = bar0 + NOTIFICATION_BAR_OFFSET;
        self.queue_evts
            .iter()
            .enumerate()
            .map(|(i, event)| {
                (
                    event,
                    notify_base + i as u64 * NOTIFY_OFF_MULTIPLIER as u64,
                    Datamatch::AnyLength,
                )
            })
            .collect()
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        let mut data: u32 = self.config_regs.read_reg(reg_idx);
        if let Some(msix_cap_reg_idx) = self.msix_cap_reg_idx {
            if msix_cap_reg_idx == reg_idx {
                data = self.msix_config.lock().read_msix_capability(data);
            }
        }

        data
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        if let Some(msix_cap_reg_idx) = self.msix_cap_reg_idx {
            if msix_cap_reg_idx == reg_idx {
                let behavior = self.msix_config.lock().write_msix_capability(offset, data);
                self.device.control_notify(behavior);
            }
        }

        self.config_regs.write_reg(reg_idx, offset, data)
    }

    fn read_bar(&mut self, addr: u64, data: &mut [u8]) {
        let bar = match self
            .config_regs
            .get_bars()
            .find(|bar| bar.address_range().contains(&addr))
        {
            Some(bar) => bar,
            None => return,
        };

        if bar.bar_index() == self.settings_bar as PciBarIndex {
            let offset = addr - bar.address();
            match offset {
                COMMON_CONFIG_BAR_OFFSET..=COMMON_CONFIG_LAST => self.common_config.read(
                    offset - COMMON_CONFIG_BAR_OFFSET,
                    data,
                    &mut self.queues,
                    self.device.as_mut(),
                ),
                ISR_CONFIG_BAR_OFFSET..=ISR_CONFIG_LAST => {
                    if let Some(v) = data.get_mut(0) {
                        // Reading this register resets it to 0.
                        *v = if let Some(interrupt) = &self.interrupt {
                            interrupt.read_and_reset_interrupt_status()
                        } else {
                            0
                        };
                    }
                }
                DEVICE_CONFIG_BAR_OFFSET..=DEVICE_CONFIG_LAST => {
                    self.device
                        .read_config(offset - DEVICE_CONFIG_BAR_OFFSET, data);
                }
                NOTIFICATION_BAR_OFFSET..=NOTIFICATION_LAST => {
                    // Handled with ioevents.
                }
                MSIX_TABLE_BAR_OFFSET..=MSIX_TABLE_LAST => {
                    self.msix_config
                        .lock()
                        .read_msix_table(offset - MSIX_TABLE_BAR_OFFSET, data);
                }
                MSIX_PBA_BAR_OFFSET..=MSIX_PBA_LAST => {
                    self.msix_config
                        .lock()
                        .read_pba_entries(offset - MSIX_PBA_BAR_OFFSET, data);
                }
                _ => (),
            }
        } else {
            self.device
                .read_bar(bar.bar_index(), addr - bar.address(), data);
        }
    }

    fn write_bar(&mut self, addr: u64, data: &[u8]) {
        let bar = match self
            .config_regs
            .get_bars()
            .find(|bar| bar.address_range().contains(&addr))
        {
            Some(bar) => bar,
            None => return,
        };

        if bar.bar_index() == self.settings_bar as PciBarIndex {
            let offset = addr - bar.address();
            match offset {
                COMMON_CONFIG_BAR_OFFSET..=COMMON_CONFIG_LAST => self.common_config.write(
                    offset - COMMON_CONFIG_BAR_OFFSET,
                    data,
                    &mut self.queues,
                    self.device.as_mut(),
                ),
                ISR_CONFIG_BAR_OFFSET..=ISR_CONFIG_LAST => {
                    if let Some(v) = data.first() {
                        if let Some(interrupt) = &self.interrupt {
                            interrupt.clear_interrupt_status_bits(*v);
                        }
                    }
                }
                DEVICE_CONFIG_BAR_OFFSET..=DEVICE_CONFIG_LAST => {
                    self.device
                        .write_config(offset - DEVICE_CONFIG_BAR_OFFSET, data);
                }
                NOTIFICATION_BAR_OFFSET..=NOTIFICATION_LAST => {
                    // Handled with ioevents.
                }
                MSIX_TABLE_BAR_OFFSET..=MSIX_TABLE_LAST => {
                    let behavior = self
                        .msix_config
                        .lock()
                        .write_msix_table(offset - MSIX_TABLE_BAR_OFFSET, data);
                    self.device.control_notify(behavior);
                }
                MSIX_PBA_BAR_OFFSET..=MSIX_PBA_LAST => {
                    self.msix_config
                        .lock()
                        .write_pba_entries(offset - MSIX_PBA_BAR_OFFSET, data);
                }
                _ => (),
            }
        } else {
            self.device
                .write_bar(bar.bar_index(), addr - bar.address(), data);
        }

        if !self.device_activated && self.is_driver_ready() {
            if let Some(iommu) = &self.iommu {
                for q in &mut self.queues {
                    q.set_iommu(Arc::clone(iommu));
                }
            }

            if let Err(e) = self.activate() {
                error!("failed to activate device: {:#}", e);
            }
        }

        // Device has been reset by the driver
        if self.device_activated && self.is_reset_requested() && self.device.reset() {
            self.device_activated = false;
            // reset queues
            self.queues.iter_mut().for_each(Queue::reset);
            // select queue 0 by default
            self.common_config.queue_select = 0;
        }
    }

    fn on_device_sandboxed(&mut self) {
        self.device.on_device_sandboxed();
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn generate_acpi(&mut self, sdts: Vec<SDT>) -> Option<Vec<SDT>> {
        self.device.generate_acpi(&self.pci_address, sdts)
    }

    fn set_iommu(&mut self, iommu: IpcMemoryMapper) -> anyhow::Result<()> {
        assert!(self.supports_iommu());
        self.iommu = Some(Arc::new(Mutex::new(iommu)));
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct VirtioPciDeviceSnapshot {
    inner_device: serde_json::Value,
    msix_config: serde_json::Value,
}

impl Suspendable for VirtioPciDevice {
    fn sleep(&mut self) -> anyhow::Result<()> {
        if let Some(state) = self.device.stop()? {
            self.queues = state.queues;
        }
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        if self.device_activated {
            self.activate()?;
        }
        Ok(())
    }

    fn snapshot(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(VirtioPciDeviceSnapshot {
            inner_device: self.device.snapshot()?,
            msix_config: self.msix_config.lock().snapshot()?,
        })
        .context("failed to serialize VirtioPciDeviceSnapshot")
    }

    fn restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let deser: VirtioPciDeviceSnapshot = serde_json::from_value(data)?;
        self.msix_config.lock().restore(deser.msix_config)?;
        self.device.restore(deser.inner_device)
    }
}

struct VmRequester {
    tube: Tube,
    alloc: Alloc,
    mappings: BTreeMap<u64, MemSlot>,
}

impl VmRequester {
    fn new(tube: Tube, alloc: Alloc) -> Self {
        Self {
            tube,
            alloc,
            mappings: BTreeMap::new(),
        }
    }
}

impl SharedMemoryMapper for VmRequester {
    fn add_mapping(
        &mut self,
        source: VmMemorySource,
        offset: u64,
        prot: Protection,
    ) -> anyhow::Result<()> {
        let request = VmMemoryRequest::RegisterMemory {
            source,
            dest: VmMemoryDestination::ExistingAllocation {
                allocation: self.alloc,
                offset,
            },
            prot,
        };
        self.tube.send(&request).context("failed to send request")?;
        match self
            .tube
            .recv()
            .context("failed to recieve request response")?
        {
            VmMemoryResponse::RegisterMemory { pfn: _, slot } => {
                self.mappings.insert(offset, slot);
                Ok(())
            }
            e => Err(anyhow!("unexpected response {:?}", e)),
        }
    }

    fn remove_mapping(&mut self, offset: u64) -> anyhow::Result<()> {
        let slot = self.mappings.remove(&offset).context("invalid offset")?;
        self.tube
            .send(&VmMemoryRequest::UnregisterMemory(slot))
            .context("failed to send request")?;
        match self
            .tube
            .recv()
            .context("failed to recieve request response")?
        {
            VmMemoryResponse::Ok => Ok(()),
            e => Err(anyhow!(format!("unexpected response {:?}", e))),
        }
    }

    fn as_raw_descriptor(&self) -> Option<RawDescriptor> {
        Some(self.tube.as_raw_descriptor())
    }
}
