// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub(crate) mod sys;

use std::default::Default;
use std::str::FromStr;

use base::error;
use base::AsRawDescriptor;
use base::RawDescriptor;
#[cfg(windows)]
use base::Tube;
#[cfg(feature = "audio_cras")]
use libcras::CrasClientType;
#[cfg(feature = "audio_cras")]
use libcras::CrasSocketType;
#[cfg(feature = "audio_cras")]
use libcras::CrasSysError;
use remain::sorted;
use resources::Alloc;
use resources::AllocOptions;
use resources::SystemAllocator;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use vm_memory::GuestMemory;

use crate::pci::ac97_bus_master::Ac97BusMaster;
use crate::pci::ac97_mixer::Ac97Mixer;
use crate::pci::ac97_regs::*;
use crate::pci::pci_configuration::PciBarConfiguration;
use crate::pci::pci_configuration::PciBarPrefetchable;
use crate::pci::pci_configuration::PciBarRegionType;
use crate::pci::pci_configuration::PciClassCode;
use crate::pci::pci_configuration::PciConfiguration;
use crate::pci::pci_configuration::PciHeaderType;
use crate::pci::pci_configuration::PciMultimediaSubclass;
use crate::pci::pci_device;
use crate::pci::pci_device::BarRange;
use crate::pci::pci_device::PciDevice;
use crate::pci::pci_device::Result;
use crate::pci::PciAddress;
use crate::pci::PciDeviceError;
use crate::pci::PciInterruptPin;
use crate::pci::PCI_VENDOR_ID_INTEL;
use crate::IrqLevelEvent;
use crate::Suspendable;

// Use 82801AA because it's what qemu does.
const PCI_DEVICE_ID_INTEL_82801AA_5: u16 = 0x2415;

/// AC97 audio device emulation.
/// Provides the PCI interface for the internal Ac97 emulation.
/// Internally the `Ac97BusMaster` and `Ac97Mixer` structs are used to emulated the bus master and
/// mixer registers respectively. `Ac97BusMaster` handles moving smaples between guest memory and
/// the audio backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ac97Backend {
    NULL,
    System(sys::Ac97Backend),
}

impl Default for Ac97Backend {
    fn default() -> Self {
        Ac97Backend::NULL
    }
}

/// Errors that are possible from a `Ac97`.
#[sorted]
#[derive(Error, Debug)]
pub enum Ac97Error {
    #[cfg(unix)]
    #[error("Must be cras or null")]
    InvalidBackend,
    #[cfg(windows)]
    #[error("Must be win_audio or null")]
    InvalidBackend,
}

impl FromStr for Ac97Backend {
    type Err = Ac97Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "null" => Ok(Ac97Backend::NULL),
            _ => sys::ac97_backend_from_str(s),
        }
    }
}

/// Holds the parameters for a AC97 device
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Ac97Parameters {
    pub backend: Ac97Backend,
    pub capture: bool,
    #[cfg(feature = "audio_cras")]
    #[serde(skip)]
    client_type: Option<CrasClientType>,
    #[cfg(feature = "audio_cras")]
    #[serde(skip)]
    socket_type: Option<CrasSocketType>,
}

impl Ac97Parameters {
    /// Set CRAS client type by given client type string.
    ///
    /// `client_type` - The client type string.
    #[cfg(feature = "audio_cras")]
    pub fn set_client_type(&mut self, client_type: &str) -> std::result::Result<(), CrasSysError> {
        self.client_type = Some(client_type.parse()?);
        Ok(())
    }

    /// Set CRAS socket type by given socket type string.
    ///
    /// `socket_type` - The socket type string.
    #[cfg(feature = "audio_cras")]
    pub fn set_socket_type(
        &mut self,
        socket_type: &str,
    ) -> std::result::Result<(), libcras::Error> {
        self.socket_type = Some(socket_type.parse()?);
        Ok(())
    }
}

pub struct Ac97Dev {
    config_regs: PciConfiguration,
    pci_address: Option<PciAddress>,
    // The irq events are temporarily saved here. They need to be passed to the device after the
    // jail forks. This happens when the bus is first written.
    irq_evt: Option<IrqLevelEvent>,
    bus_master: Ac97BusMaster,
    mixer: Ac97Mixer,
    #[cfg_attr(windows, allow(dead_code))]
    backend: Ac97Backend,
}

impl Ac97Dev {
    /// Creates an 'Ac97Dev' that uses the given `GuestMemory` and starts with all registers at
    /// default values.
    pub fn new(
        mem: GuestMemory,
        backend: Ac97Backend,
        audio_server: sys::AudioStreamSource,
        #[cfg(windows)] ac97_device_tube: Option<Tube>,
    ) -> Self {
        let config_regs = PciConfiguration::new(
            PCI_VENDOR_ID_INTEL,
            PCI_DEVICE_ID_INTEL_82801AA_5,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioDevice,
            None, // No Programming interface.
            PciHeaderType::Device,
            PCI_VENDOR_ID_INTEL, // Subsystem Vendor ID
            0x1,                 // Subsystem ID.
            0,                   //  Revision ID.
        );

        Self {
            config_regs,
            pci_address: None,
            irq_evt: None,
            bus_master: Ac97BusMaster::new(
                mem,
                audio_server,
                #[cfg(windows)]
                ac97_device_tube,
            ),
            mixer: Ac97Mixer::new(),
            backend,
        }
    }

    /// Creates an `Ac97Dev` with suitable audio server inside based on Ac97Parameters. If it fails
    /// to create `Ac97Dev` with the given back-end, it'll fallback to the null audio device.
    pub fn try_new(
        mem: GuestMemory,
        param: Ac97Parameters,
        #[cfg(windows)] ac97_device_tube: Tube,
    ) -> Result<Self> {
        match &param.backend {
            Ac97Backend::System(ac97_backend) => Self::initialize_backend(
                ac97_backend,
                mem,
                &param,
                #[cfg(windows)]
                ac97_device_tube,
            ),
            Ac97Backend::NULL => Ok(Self::create_null_audio_device(mem)),
        }
    }

    fn create_null_audio_device(mem: GuestMemory) -> Self {
        let server = sys::create_null_server();
        Self::new(
            mem,
            Ac97Backend::NULL,
            server,
            #[cfg(windows)]
            None,
        )
    }

    fn read_mixer(&mut self, offset: u64, data: &mut [u8]) {
        match data.len() {
            // The mixer is only accessed with 16-bit words.
            2 => {
                let val: u16 = self.mixer.readw(offset);
                data[0] = val as u8;
                data[1] = (val >> 8) as u8;
            }
            l => error!("mixer read length of {}", l),
        }
    }

    fn write_mixer(&mut self, offset: u64, data: &[u8]) {
        match data.len() {
            // The mixer is only accessed with 16-bit words.
            2 => self
                .mixer
                .writew(offset, u16::from(data[0]) | u16::from(data[1]) << 8),
            l => error!("mixer write length of {}", l),
        }
        // Apply the new mixer settings to the bus master.
        self.bus_master.update_mixer_settings(&self.mixer);
    }

    fn read_bus_master(&mut self, offset: u64, data: &mut [u8]) {
        match data.len() {
            1 => data[0] = self.bus_master.readb(offset),
            2 => {
                let val: u16 = self.bus_master.readw(offset, &self.mixer);
                data[0] = val as u8;
                data[1] = (val >> 8) as u8;
            }
            4 => {
                let val: u32 = self.bus_master.readl(offset);
                data[0] = val as u8;
                data[1] = (val >> 8) as u8;
                data[2] = (val >> 16) as u8;
                data[3] = (val >> 24) as u8;
            }
            l => error!("read length of {}", l),
        }
    }

    fn write_bus_master(&mut self, offset: u64, data: &[u8]) {
        match data.len() {
            1 => self.bus_master.writeb(offset, data[0], &self.mixer),
            2 => self
                .bus_master
                .writew(offset, u16::from(data[0]) | u16::from(data[1]) << 8),
            4 => self.bus_master.writel(
                offset,
                (u32::from(data[0]))
                    | (u32::from(data[1]) << 8)
                    | (u32::from(data[2]) << 16)
                    | (u32::from(data[3]) << 24),
                &mut self.mixer,
            ),
            l => error!("write length of {}", l),
        }
    }
}

impl PciDevice for Ac97Dev {
    fn debug_label(&self) -> String {
        "AC97".to_owned()
    }

    fn allocate_address(&mut self, resources: &mut SystemAllocator) -> Result<PciAddress> {
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

    fn assign_irq(&mut self, irq_evt: IrqLevelEvent, pin: PciInterruptPin, irq_num: u32) {
        self.irq_evt = Some(irq_evt);
        self.config_regs.set_irq(irq_num as u8, pin);
    }

    fn allocate_io_bars(&mut self, resources: &mut SystemAllocator) -> Result<Vec<BarRange>> {
        let address = self
            .pci_address
            .expect("allocate_address must be called prior to allocate_io_bars");
        let mut ranges: Vec<BarRange> = Vec::new();
        let mixer_regs_addr = resources
            .allocate_mmio(
                MIXER_REGS_SIZE,
                Alloc::PciBar {
                    bus: address.bus,
                    dev: address.dev,
                    func: address.func,
                    bar: 0,
                },
                "ac97-mixer_regs".to_string(),
                AllocOptions::new()
                    .max_address(u32::MAX.into())
                    .align(MIXER_REGS_SIZE),
            )
            .map_err(|e| pci_device::Error::IoAllocationFailed(MIXER_REGS_SIZE, e))?;
        let mixer_config = PciBarConfiguration::new(
            0,
            MIXER_REGS_SIZE,
            PciBarRegionType::Memory32BitRegion,
            PciBarPrefetchable::NotPrefetchable,
        )
        .set_address(mixer_regs_addr);
        self.config_regs
            .add_pci_bar(mixer_config)
            .map_err(|e| pci_device::Error::IoRegistrationFailed(mixer_regs_addr, e))?;
        ranges.push(BarRange {
            addr: mixer_regs_addr,
            size: MIXER_REGS_SIZE,
            prefetchable: false,
        });

        let master_regs_addr = resources
            .allocate_mmio(
                MASTER_REGS_SIZE,
                Alloc::PciBar {
                    bus: address.bus,
                    dev: address.dev,
                    func: address.func,
                    bar: 1,
                },
                "ac97-master_regs".to_string(),
                AllocOptions::new()
                    .max_address(u32::MAX.into())
                    .align(MASTER_REGS_SIZE),
            )
            .map_err(|e| pci_device::Error::IoAllocationFailed(MASTER_REGS_SIZE, e))?;
        let master_config = PciBarConfiguration::new(
            1,
            MASTER_REGS_SIZE,
            PciBarRegionType::Memory32BitRegion,
            PciBarPrefetchable::NotPrefetchable,
        )
        .set_address(master_regs_addr);
        self.config_regs
            .add_pci_bar(master_config)
            .map_err(|e| pci_device::Error::IoRegistrationFailed(master_regs_addr, e))?;
        ranges.push(BarRange {
            addr: master_regs_addr,
            size: MASTER_REGS_SIZE,
            prefetchable: false,
        });
        Ok(ranges)
    }

    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        self.config_regs.get_bar_configuration(bar_num)
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        self.config_regs.read_reg(reg_idx)
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        self.config_regs.write_reg(reg_idx, offset, data)
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = Vec::new();
        if let Some(mut server_fds) = self.bus_master.keep_rds() {
            rds.append(&mut server_fds);
        }
        if let Some(irq_evt) = &self.irq_evt {
            rds.push(irq_evt.get_trigger().as_raw_descriptor());
            rds.push(irq_evt.get_resample().as_raw_descriptor());
        }
        rds
    }

    fn read_bar(&mut self, addr: u64, data: &mut [u8]) {
        let bar0 = self.config_regs.get_bar_addr(0);
        let bar1 = self.config_regs.get_bar_addr(1);
        match addr {
            a if a >= bar0 && a < bar0 + MIXER_REGS_SIZE => self.read_mixer(addr - bar0, data),
            a if a >= bar1 && a < bar1 + MASTER_REGS_SIZE => {
                self.read_bus_master(addr - bar1, data)
            }
            _ => (),
        }
    }

    fn write_bar(&mut self, addr: u64, data: &[u8]) {
        let bar0 = self.config_regs.get_bar_addr(0);
        let bar1 = self.config_regs.get_bar_addr(1);
        match addr {
            a if a >= bar0 && a < bar0 + MIXER_REGS_SIZE => self.write_mixer(addr - bar0, data),
            a if a >= bar1 && a < bar1 + MASTER_REGS_SIZE => {
                // Check if the irq needs to be passed to the device.
                if let Some(irq_evt) = self.irq_evt.take() {
                    self.bus_master.set_irq_event(irq_evt);
                }
                self.write_bus_master(addr - bar1, data)
            }
            _ => (),
        }
    }
}

impl Suspendable for Ac97Dev {}

#[cfg(test)]
mod tests {
    use resources::AddressRange;
    use resources::SystemAllocatorConfig;
    use vm_memory::GuestAddress;

    use super::*;

    #[test]
    fn create() {
        let mem = GuestMemory::new(&[(GuestAddress(0u64), 4 * 1024 * 1024)]).unwrap();
        let mut ac97_dev = sys::tests::create_ac97_device(mem, Ac97Backend::NULL);

        let mut allocator = SystemAllocator::new(
            SystemAllocatorConfig {
                io: Some(AddressRange {
                    start: 0xc000,
                    end: 0xffff,
                }),
                low_mmio: AddressRange {
                    start: 0x2000_0000,
                    end: 0x2fff_ffff,
                },
                high_mmio: AddressRange {
                    start: 0x3000_0000,
                    end: 0x3fff_ffff,
                },
                platform_mmio: None,
                first_irq: 5,
            },
            None,
            &[],
        )
        .unwrap();
        assert!(ac97_dev.allocate_address(&mut allocator).is_ok());
        assert!(ac97_dev.allocate_io_bars(&mut allocator).is_ok());
    }
}
