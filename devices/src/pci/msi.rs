// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg_attr(windows, allow(dead_code))]

use base::error;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use base::Tube;
use bit_field::*;
use vm_control::VmIrqRequest;
use vm_control::VmIrqResponse;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use crate::pci::pci_configuration::PciCapConfig;
use crate::pci::pci_configuration::PciCapConfigWriteResult;
use crate::pci::PciCapability;
use crate::pci::PciCapabilityID;

// MSI registers
pub const PCI_MSI_NEXT_POINTER: u32 = 0x1; // Next cap pointer
pub const PCI_MSI_FLAGS: u32 = 0x2; // Message Control
const PCI_MSI_FLAGS_ENABLE: u16 = 0x0001; // MSI feature enabled
pub const PCI_MSI_FLAGS_64BIT: u16 = 0x0080; // 64-bit addresses allowed
pub const PCI_MSI_FLAGS_MASKBIT: u16 = 0x0100; // Per-vector masking capable
const PCI_MSI_ADDRESS_LO: u32 = 0x4; // MSI address lower 32 bits
const PCI_MSI_ADDRESS_HI: u32 = 0x8; // MSI address upper 32 bits (if 64 bit allowed)
const PCI_MSI_DATA_32: u32 = 0x8; // 16 bits of data for 32-bit message address
const PCI_MSI_DATA_64: u32 = 0xC; // 16 bits of date for 64-bit message address

// MSI length
const MSI_LENGTH_32BIT_WITHOUT_MASK: u32 = 0xA;
const MSI_LENGTH_32BIT_WITH_MASK: u32 = 0x14;
const MSI_LENGTH_64BIT_WITHOUT_MASK: u32 = 0xE;
const MSI_LENGTH_64BIT_WITH_MASK: u32 = 0x18;

pub enum MsiStatus {
    Enabled,
    Disabled,
    NothingToDo,
}

/// Wrapper over MSI Capability Structure
pub struct MsiConfig {
    is_64bit: bool,
    mask_cap: bool,
    ctrl: u16,
    address: u64,
    data: u16,
    vm_socket_irq: Tube,
    irqfd: Option<Event>,
    gsi: Option<u32>,
    device_id: u32,
    device_name: String,
    pci_address: Option<resources::PciAddress>,
}

impl MsiConfig {
    pub fn new(
        is_64bit: bool,
        mask_cap: bool,
        vm_socket_irq: Tube,
        device_id: u32,
        device_name: String,
    ) -> Self {
        let mut ctrl: u16 = 0;
        if is_64bit {
            ctrl |= PCI_MSI_FLAGS_64BIT;
        }
        if mask_cap {
            ctrl |= PCI_MSI_FLAGS_MASKBIT;
        }
        MsiConfig {
            is_64bit,
            mask_cap,
            ctrl,
            address: 0,
            data: 0,
            vm_socket_irq,
            irqfd: None,
            gsi: None,
            device_id,
            device_name,
            pci_address: None,
        }
    }

    /// PCI address of the associated device.
    pub fn set_pci_address(&mut self, pci_address: resources::PciAddress) {
        self.pci_address = Some(pci_address);
    }

    fn len(&self) -> u32 {
        match (self.is_64bit, self.mask_cap) {
            (true, true) => MSI_LENGTH_64BIT_WITH_MASK,
            (true, false) => MSI_LENGTH_64BIT_WITHOUT_MASK,
            (false, true) => MSI_LENGTH_32BIT_WITH_MASK,
            (false, false) => MSI_LENGTH_32BIT_WITHOUT_MASK,
        }
    }

    pub fn is_msi_reg(&self, offset: u32, index: u64, len: usize) -> bool {
        let msi_len = self.len();
        index >= offset as u64
            && index + len as u64 <= (offset + msi_len) as u64
            && len as u32 <= msi_len
    }

    pub fn read_msi_capability(&self, offset: u32, data: u32) -> u32 {
        if offset == 0 {
            (self.ctrl as u32) << 16 | (data & u16::MAX as u32)
        } else {
            data
        }
    }

    pub fn write_msi_capability(&mut self, offset: u32, data: &[u8]) -> MsiStatus {
        let len = data.len();
        let mut ret = MsiStatus::NothingToDo;
        let old_address = self.address;
        let old_data = self.data;

        // write msi ctl
        if len == 2 && offset == PCI_MSI_FLAGS {
            let was_enabled = self.is_msi_enabled();
            let value: [u8; 2] = [data[0], data[1]];
            self.ctrl = u16::from_le_bytes(value);
            let is_enabled = self.is_msi_enabled();
            if !was_enabled && is_enabled {
                self.enable();
                ret = MsiStatus::Enabled;
            } else if was_enabled && !is_enabled {
                ret = MsiStatus::Disabled;
            }
        } else if len == 4 && offset == PCI_MSI_ADDRESS_LO && !self.is_64bit {
            //write 32 bit message address
            let value: [u8; 8] = [data[0], data[1], data[2], data[3], 0, 0, 0, 0];
            self.address = u64::from_le_bytes(value);
        } else if len == 4 && offset == PCI_MSI_ADDRESS_LO && self.is_64bit {
            // write 64 bit message address low part
            let value: [u8; 8] = [data[0], data[1], data[2], data[3], 0, 0, 0, 0];
            self.address &= !0xffffffff;
            self.address |= u64::from_le_bytes(value);
        } else if len == 4 && offset == PCI_MSI_ADDRESS_HI && self.is_64bit {
            //write 64 bit message address high part
            let value: [u8; 8] = [0, 0, 0, 0, data[0], data[1], data[2], data[3]];
            self.address &= 0xffffffff;
            self.address |= u64::from_le_bytes(value);
        } else if len == 8 && offset == PCI_MSI_ADDRESS_LO && self.is_64bit {
            // write 64 bit message address
            let value: [u8; 8] = [
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ];
            self.address = u64::from_le_bytes(value);
        } else if len == 2
            && ((offset == PCI_MSI_DATA_32 && !self.is_64bit)
                || (offset == PCI_MSI_DATA_64 && self.is_64bit))
        {
            // write message data
            let value: [u8; 2] = [data[0], data[1]];
            self.data = u16::from_le_bytes(value);
        }

        if self.is_msi_enabled() && (old_address != self.address || old_data != self.data) {
            self.add_msi_route();
        }

        ret
    }

    pub fn is_msi_enabled(&self) -> bool {
        self.ctrl & PCI_MSI_FLAGS_ENABLE == PCI_MSI_FLAGS_ENABLE
    }

    fn add_msi_route(&self) {
        let gsi = match self.gsi {
            Some(g) => g,
            None => {
                error!("Add msi route but gsi is none");
                return;
            }
        };
        // Only used on aarch64, but make sure it is initialized correctly on all archs for better
        // test coverage.
        #[allow(unused_variables)]
        let pci_address = self
            .pci_address
            .expect("MsixConfig: must call set_pci_address before config writes");
        if let Err(e) = self.vm_socket_irq.send(&VmIrqRequest::AddMsiRoute {
            gsi,
            msi_address: self.address,
            msi_data: self.data.into(),
            #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
            pci_address,
        }) {
            error!("failed to send AddMsiRoute request at {:?}", e);
            return;
        }
        match self.vm_socket_irq.recv() {
            Ok(VmIrqResponse::Err(e)) => error!("failed to call AddMsiRoute request {:?}", e),
            Ok(_) => {}
            Err(e) => error!("failed to receive AddMsiRoute response {:?}", e),
        }
    }

    fn allocate_one_msi(&mut self) {
        let irqfd = match self.irqfd.take() {
            Some(e) => e,
            None => match Event::new() {
                Ok(e) => e,
                Err(e) => {
                    error!("failed to create event: {:?}", e);
                    return;
                }
            },
        };

        let request = VmIrqRequest::AllocateOneMsi {
            irqfd,
            device_id: self.device_id,
            queue_id: 0,
            device_name: self.device_name.clone(),
        };
        let request_result = self.vm_socket_irq.send(&request);

        // Stash the irqfd in self immediately because we used take above.
        self.irqfd = match request {
            VmIrqRequest::AllocateOneMsi { irqfd, .. } => Some(irqfd),
            _ => unreachable!(),
        };

        if let Err(e) = request_result {
            error!("failed to send AllocateOneMsi request: {:?}", e);
            return;
        }

        match self.vm_socket_irq.recv() {
            Ok(VmIrqResponse::AllocateOneMsi { gsi }) => self.gsi = Some(gsi),
            _ => error!("failed to receive AllocateOneMsi Response"),
        }
    }

    fn enable(&mut self) {
        if self.gsi.is_none() || self.irqfd.is_none() {
            self.allocate_one_msi();
        }

        self.add_msi_route();
    }

    pub fn get_irqfd(&self) -> Option<&Event> {
        self.irqfd.as_ref()
    }

    pub fn destroy(&mut self) {
        if let Some(gsi) = self.gsi {
            if let Some(irqfd) = self.irqfd.take() {
                let request = VmIrqRequest::ReleaseOneIrq { gsi, irqfd };
                if self.vm_socket_irq.send(&request).is_ok() {
                    let _ = self.vm_socket_irq.recv::<VmIrqResponse>();
                }
            }
        }
    }

    /// Return the raw descriptor of the MSI device socket
    pub fn get_msi_socket(&self) -> RawDescriptor {
        self.vm_socket_irq.as_raw_descriptor()
    }

    pub fn trigger(&self) {
        if let Some(irqfd) = self.irqfd.as_ref() {
            irqfd.signal().unwrap();
        }
    }
}

#[bitfield]
#[derive(Copy, Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct MsiCtrl {
    enable: B1,
    multi_msg_capable: B3,
    multi_msg_enable: B3,
    is_64bit: B1,
    per_vector_masking: B1,
    extended_msg_data_capable: B1,
    extended_msg_data_enable: B1,
    reserved: B5,
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
/// MSI Capability Structure
pub struct MsiCap {
    // To make add_capability() happy
    _cap_vndr: u8,
    _cap_next: u8,
    // Message Control Register
    msg_ctl: MsiCtrl,
    // Message Address
    msg_addr: u32,
    // Msi Vary structure
    msi_vary: [u8; 16],
}

impl PciCapability for MsiCap {
    fn bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::MessageSignalledInterrupts
    }

    fn writable_bits(&self) -> Vec<u32> {
        // Check spec for detail
        match (
            self.msg_ctl.get_is_64bit(),
            self.msg_ctl.get_per_vector_masking(),
        ) {
            (0, 0) => vec![0x0471_0000, 0xffff_fffc, 0xffff_ffff],
            (0, 1) => vec![0x0471_0000, 0xffff_fffc, 0xffff_ffff, 0xffff_ffff],
            (1, 0) => vec![
                0x0471_0000,
                0xffff_fffc,
                0xffff_ffff,
                0xffff_ffff,
                0x0000_0000,
            ],
            (1, 1) => vec![
                0x0471_0000,
                0xffff_fffc,
                0xffff_ffff,
                0xffff_ffff,
                0xffff_ffff,
                0x0000_0000,
            ],
            (_, _) => Vec::new(),
        }
    }
}

impl MsiCap {
    pub fn new(is_64bit: bool, mask_cap: bool) -> Self {
        let mut msg_ctl = MsiCtrl::new();
        if is_64bit {
            msg_ctl.set_is_64bit(1);
        }
        if mask_cap {
            msg_ctl.set_per_vector_masking(1);
        }
        MsiCap {
            _cap_vndr: 0,
            _cap_next: 0,
            msg_ctl,
            msg_addr: 0,
            msi_vary: [0; 16],
        }
    }
}

const MSI_CONFIG_READ_MASK: [u32; MSI_LENGTH_64BIT_WITH_MASK as usize / 4] =
    [0xffff_0000, 0, 0, 0, 0, 0];

impl PciCapConfig for MsiConfig {
    fn read_mask(&self) -> &'static [u32] {
        let num_regs = (self.len() + 3) / 4;
        &MSI_CONFIG_READ_MASK[0..(num_regs as usize)]
    }

    fn read_reg(&self, reg_idx: usize) -> u32 {
        self.read_msi_capability(reg_idx as u32 * 4, 0)
    }

    fn write_reg(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> Option<Box<dyn PciCapConfigWriteResult>> {
        let offset = reg_idx as u32 * 4 + offset as u32;
        self.write_msi_capability(offset, data);
        None
    }
}
