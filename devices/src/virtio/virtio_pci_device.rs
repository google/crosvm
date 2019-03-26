// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use data_model::{DataInit, Le32};
use kvm::Datamatch;
use resources::{Alloc, SystemAllocator};
use sys_util::{EventFd, GuestMemory, Result};

use super::*;
use crate::pci::{
    PciBarConfiguration, PciCapability, PciCapabilityID, PciClassCode, PciConfiguration, PciDevice,
    PciDeviceError, PciHeaderType, PciInterruptPin, PciSubclass,
};

use self::virtio_pci_common_config::VirtioPciCommonConfig;

pub enum PciCapabilityType {
    CommonConfig = 1,
    NotifyConfig = 2,
    IsrConfig = 3,
    DeviceConfig = 4,
    PciConfig = 5,
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioPciCap {
    // _cap_vndr and _cap_next are autofilled based on id() in pci configuration
    _cap_vndr: u8,    // Generic PCI field: PCI_CAP_ID_VNDR
    _cap_next: u8,    // Generic PCI field: next ptr
    cap_len: u8,      // Generic PCI field: capability length
    cfg_type: u8,     // Identifies the structure.
    bar: u8,          // Where to find it.
    padding: [u8; 3], // Pad to full dword.
    offset: Le32,     // Offset within bar.
    length: Le32,     // Length of the structure, in bytes.
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
}

impl VirtioPciCap {
    pub fn new(cfg_type: PciCapabilityType, bar: u8, offset: u32, length: u32) -> Self {
        VirtioPciCap {
            _cap_vndr: 0,
            _cap_next: 0,
            cap_len: std::mem::size_of::<VirtioPciCap>() as u8,
            cfg_type: cfg_type as u8,
            bar,
            padding: [0; 3],
            offset: Le32::from(offset),
            length: Le32::from(length),
        }
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
                _cap_vndr: 0,
                _cap_next: 0,
                cap_len: std::mem::size_of::<VirtioPciNotifyCap>() as u8,
                cfg_type: cfg_type as u8,
                bar,
                padding: [0; 3],
                offset: Le32::from(offset),
                length: Le32::from(length),
            },
            notify_off_multiplier: multiplier,
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
const ISR_CONFIG_BAR_OFFSET: u64 = 0x1000;
const ISR_CONFIG_SIZE: u64 = 1;
const DEVICE_CONFIG_BAR_OFFSET: u64 = 0x2000;
const DEVICE_CONFIG_SIZE: u64 = 0x1000;
const NOTIFICATION_BAR_OFFSET: u64 = 0x3000;
const NOTIFICATION_SIZE: u64 = 0x1000;
const CAPABILITY_BAR_SIZE: u64 = 0x4000;

const NOTIFY_OFF_MULTIPLIER: u32 = 4; // A dword per notification address.

const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040; // Add to device type to get device ID.

/// Implements the
/// [PCI](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-650001)
/// transport for virtio devices.
pub struct VirtioPciDevice {
    config_regs: PciConfiguration,
    pci_bus_dev: Option<(u8, u8)>,

    device: Box<dyn VirtioDevice>,
    device_activated: bool,

    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: Option<EventFd>,
    interrupt_resample_evt: Option<EventFd>,
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    mem: Option<GuestMemory>,
    settings_bar: u8,

    common_config: VirtioPciCommonConfig,
}

impl VirtioPciDevice {
    /// Constructs a new PCI transport for the given virtio device.
    pub fn new(mem: GuestMemory, device: Box<dyn VirtioDevice>) -> Result<Self> {
        let mut queue_evts = Vec::new();
        for _ in device.queue_max_sizes() {
            queue_evts.push(EventFd::new()?)
        }
        let queues = device
            .queue_max_sizes()
            .iter()
            .map(|&s| Queue::new(s))
            .collect();

        let pci_device_id = VIRTIO_PCI_DEVICE_ID_BASE + device.device_type() as u16;

        let config_regs = PciConfiguration::new(
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
            PciClassCode::Other,
            &PciVirtioSubclass::NonTransitionalBase,
            None,
            PciHeaderType::Device,
            VIRTIO_PCI_VENDOR_ID,
            pci_device_id,
        );

        Ok(VirtioPciDevice {
            config_regs,
            pci_bus_dev: None,
            device,
            device_activated: false,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: None,
            interrupt_resample_evt: None,
            queues,
            queue_evts,
            mem: Some(mem),
            settings_bar: 0,
            common_config: VirtioPciCommonConfig {
                driver_status: 0,
                config_generation: 0,
                device_feature_select: 0,
                driver_feature_select: 0,
                queue_select: 0,
            },
        })
    }

    /// Gets the list of queue events that must be triggered whenever the VM writes to
    /// `virtio::NOTIFY_REG_OFFSET` past the MMIO base. Each event must be triggered when the
    /// value being written equals the index of the event in this list.
    pub fn queue_evts(&self) -> &[EventFd] {
        self.queue_evts.as_slice()
    }

    /// Gets the event this device uses to interrupt the VM when the used queue is changed.
    pub fn interrupt_evt(&self) -> Option<&EventFd> {
        self.interrupt_evt.as_ref()
    }

    fn is_driver_ready(&self) -> bool {
        let ready_bits =
            (DEVICE_ACKNOWLEDGE | DEVICE_DRIVER | DEVICE_DRIVER_OK | DEVICE_FEATURES_OK) as u8;
        self.common_config.driver_status == ready_bits
            && self.common_config.driver_status & DEVICE_FAILED as u8 == 0
    }

    fn are_queues_valid(&self) -> bool {
        if let Some(mem) = self.mem.as_ref() {
            self.queues.iter().all(|q| q.is_valid(mem))
        } else {
            false
        }
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

        self.settings_bar = settings_bar;
        Ok(())
    }
}

impl PciDevice for VirtioPciDevice {
    fn debug_label(&self) -> String {
        format!("virtio-pci ({})", self.device.debug_label())
    }

    fn assign_bus_dev(&mut self, bus: u8, device: u8) {
        self.pci_bus_dev = Some((bus, device));
    }

    fn keep_fds(&self) -> Vec<RawFd> {
        let mut fds = self.device.keep_fds();
        if let Some(interrupt_evt) = &self.interrupt_evt {
            fds.push(interrupt_evt.as_raw_fd());
        }
        if let Some(interrupt_resample_evt) = &self.interrupt_resample_evt {
            fds.push(interrupt_resample_evt.as_raw_fd());
        }
        fds
    }

    fn assign_irq(
        &mut self,
        irq_evt: EventFd,
        irq_resample_evt: EventFd,
        irq_num: u32,
        irq_pin: PciInterruptPin,
    ) {
        self.config_regs.set_irq(irq_num as u8, irq_pin);
        self.interrupt_evt = Some(irq_evt);
        self.interrupt_resample_evt = Some(irq_resample_evt);
    }

    fn allocate_io_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<Vec<(u64, u64)>, PciDeviceError> {
        let (bus, dev) = self
            .pci_bus_dev
            .expect("assign_bus_dev must be called prior to allocate_io_bars");
        // Allocate one bar for the structures pointed to by the capability structures.
        let mut ranges = Vec::new();
        let settings_config_addr = resources
            .mmio_allocator()
            .allocate(
                CAPABILITY_BAR_SIZE,
                Alloc::PciBar { bus, dev, bar: 0 },
                format!(
                    "virtio-{}-cap_bar",
                    type_to_str(self.device.device_type()).unwrap_or("?")
                ),
            )
            .map_err(|e| PciDeviceError::IoAllocationFailed(CAPABILITY_BAR_SIZE, e))?;
        let config = PciBarConfiguration::default()
            .set_register_index(0)
            .set_address(settings_config_addr)
            .set_size(CAPABILITY_BAR_SIZE);
        let settings_bar = self
            .config_regs
            .add_pci_bar(&config)
            .map_err(|e| PciDeviceError::IoRegistrationFailed(settings_config_addr, e))?
            as u8;
        ranges.push((settings_config_addr, CAPABILITY_BAR_SIZE));

        // Once the BARs are allocated, the capabilities can be added to the PCI configuration.
        self.add_settings_pci_capabilities(settings_bar)?;

        Ok(ranges)
    }

    fn allocate_device_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<Vec<(u64, u64)>, PciDeviceError> {
        let (bus, dev) = self
            .pci_bus_dev
            .expect("assign_bus_dev must be called prior to allocate_device_bars");
        let mut ranges = Vec::new();
        for config in self.device.get_device_bars() {
            let device_addr = resources
                .device_allocator()
                .allocate(
                    config.get_size(),
                    Alloc::PciBar {
                        bus,
                        dev,
                        bar: config.get_register_index() as u8,
                    },
                    format!(
                        "virtio-{}-custom_bar",
                        type_to_str(self.device.device_type()).unwrap_or("?")
                    ),
                )
                .map_err(|e| PciDeviceError::IoAllocationFailed(config.get_size(), e))?;
            let config = config.set_address(device_addr);
            let _device_bar = self
                .config_regs
                .add_pci_bar(&config)
                .map_err(|e| PciDeviceError::IoRegistrationFailed(device_addr, e))?;
            ranges.push((device_addr, config.get_size()));
        }
        Ok(ranges)
    }

    fn register_device_capabilities(&mut self) -> std::result::Result<(), PciDeviceError> {
        for cap in self.device.get_device_caps() {
            self.config_regs
                .add_capability(&*cap)
                .map_err(PciDeviceError::CapabilitiesSetup)?;
        }

        Ok(())
    }

    fn ioeventfds(&self) -> Vec<(&EventFd, u64, Datamatch)> {
        let bar0 = self.config_regs.get_bar_addr(self.settings_bar as usize) as u64;
        let notify_base = bar0 + NOTIFICATION_BAR_OFFSET;
        self.queue_evts()
            .iter()
            .enumerate()
            .map(|(i, event)| {
                (
                    event,
                    notify_base + i as u64 * NOTIFY_OFF_MULTIPLIER as u64,
                    Datamatch::U16(Some(i as u16)),
                )
            })
            .collect()
    }

    fn config_registers(&self) -> &PciConfiguration {
        &self.config_regs
    }

    fn config_registers_mut(&mut self) -> &mut PciConfiguration {
        &mut self.config_regs
    }

    // Clippy: the value of COMMON_CONFIG_BAR_OFFSET happens to be zero so the
    // expression `COMMON_CONFIG_BAR_OFFSET <= o` is always true, but this code
    // is written such that the value of the const may be changed independently.
    #[allow(clippy::absurd_extreme_comparisons)]
    fn read_bar(&mut self, addr: u64, data: &mut [u8]) {
        // The driver is only allowed to do aligned, properly sized access.
        let bar0 = self.config_regs.get_bar_addr(self.settings_bar as usize) as u64;
        let offset = addr - bar0;
        match offset {
            o if COMMON_CONFIG_BAR_OFFSET <= o
                && o < COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE =>
            {
                self.common_config.read(
                    o - COMMON_CONFIG_BAR_OFFSET,
                    data,
                    &mut self.queues,
                    self.device.as_mut(),
                )
            }
            o if ISR_CONFIG_BAR_OFFSET <= o && o < ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE => {
                if let Some(v) = data.get_mut(0) {
                    // Reading this register resets it to 0.
                    *v = self.interrupt_status.swap(0, Ordering::SeqCst) as u8;
                }
            }
            o if DEVICE_CONFIG_BAR_OFFSET <= o
                && o < DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE =>
            {
                self.device.read_config(o - DEVICE_CONFIG_BAR_OFFSET, data);
            }
            o if NOTIFICATION_BAR_OFFSET <= o
                && o < NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE =>
            {
                // Handled with ioeventfds.
            }
            _ => (),
        }
    }

    #[allow(clippy::absurd_extreme_comparisons)]
    fn write_bar(&mut self, addr: u64, data: &[u8]) {
        let bar0 = self.config_regs.get_bar_addr(self.settings_bar as usize) as u64;
        let offset = addr - bar0;
        match offset {
            o if COMMON_CONFIG_BAR_OFFSET <= o
                && o < COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE =>
            {
                self.common_config.write(
                    o - COMMON_CONFIG_BAR_OFFSET,
                    data,
                    &mut self.queues,
                    self.device.as_mut(),
                )
            }
            o if ISR_CONFIG_BAR_OFFSET <= o && o < ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE => {
                if let Some(v) = data.get(0) {
                    self.interrupt_status
                        .fetch_and(!(*v as usize), Ordering::SeqCst);
                }
            }
            o if DEVICE_CONFIG_BAR_OFFSET <= o
                && o < DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE =>
            {
                self.device.write_config(o - DEVICE_CONFIG_BAR_OFFSET, data);
            }
            o if NOTIFICATION_BAR_OFFSET <= o
                && o < NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE =>
            {
                // Handled with ioeventfds.
            }
            _ => (),
        };

        if !self.device_activated && self.is_driver_ready() && self.are_queues_valid() {
            if let Some(interrupt_evt) = self.interrupt_evt.take() {
                if let Some(interrupt_resample_evt) = self.interrupt_resample_evt.take() {
                    if let Some(mem) = self.mem.take() {
                        self.device.activate(
                            mem,
                            interrupt_evt,
                            interrupt_resample_evt,
                            self.interrupt_status.clone(),
                            self.queues.clone(),
                            self.queue_evts.split_off(0),
                        );
                        self.device_activated = true;
                    }
                }
            }
        }
    }
}
