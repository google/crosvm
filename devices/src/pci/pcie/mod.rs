// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod pci_bridge;
mod pcie_device;
mod pcie_host;
mod pcie_port;
mod pcie_rp;
mod pcie_switch;

pub use pci_bridge::PciBridge;
pub use pcie_host::PcieHostPort;
pub use pcie_rp::PcieRootPort;
pub use pcie_switch::PcieDownstreamPort;
pub use pcie_switch::PcieUpstreamPort;

#[allow(dead_code)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum PcieDevicePortType {
    PcieEndpoint = 0,
    PcieLegacyEndpoint = 1,
    RootPort = 4,
    UpstreamPort = 5,
    DownstreamPort = 6,
    Pcie2PciBridge = 7,
    Pci2PcieBridge = 8,
    RCIntegratedEndpoint = 9,
    RCEventCollector = 0xa,
}

const PCIE_CAP_LEN: usize = 0x3C;

const PCIE_CAP_VERSION: u16 = 0x2;
const PCIE_TYPE_SHIFT: u16 = 0x4;
const PCIE_CAP_SLOT_SHIFT: u16 = 0x8;
const PCIE_CAP_IRQ_NUM_SHIFT: u16 = 0x9;

const PCIE_DEVCAP_RBER: u32 = 0x0000_8000;
const PCIE_LINK_X1: u16 = 0x10;
const PCIE_LINK_2_5GT: u16 = 0x01;

const PCIE_SLTCAP_ABP: u32 = 0x01; // Attention Button Present
const PCIE_SLTCAP_AIP: u32 = 0x08; // Attention Indicator Present
const PCIE_SLTCAP_PIP: u32 = 0x10; // Power Indicator Present
const PCIE_SLTCAP_HPS: u32 = 0x20; // Hot-Plug Surprise
const PCIE_SLTCAP_HPC: u32 = 0x40; // Hot-Plug Capable

const PCIE_SLTCTL_OFFSET: usize = 0x18;
const PCIE_SLTCTL_PIC: u16 = 0x300; // Power indicator
const PCIE_SLTCTL_PIC_ON: u16 = 0x100; // Power indicator on
const PCIE_SLTCTL_PIC_BLINK: u16 = 0x200; // Power indicator blink
const PCIE_SLTCTL_PIC_OFF: u16 = 0x300; // Power indicator off
const PCIE_SLTCTL_AIC_OFF: u16 = 0xC0;
const PCIE_SLTCTL_ABPE: u16 = 0x01;
const PCIE_SLTCTL_PDCE: u16 = 0x08;
const PCIE_SLTCTL_CCIE: u16 = 0x10;
const PCIE_SLTCTL_HPIE: u16 = 0x20;

const PCIE_SLTSTA_OFFSET: usize = 0x1A;
const PCIE_SLTSTA_ABP: u16 = 0x0001;
const PCIE_SLTSTA_PFD: u16 = 0x0002;
const PCIE_SLTSTA_PDC: u16 = 0x0008;
const PCIE_SLTSTA_CC: u16 = 0x0010;
const PCIE_SLTSTA_PDS: u16 = 0x0040;
const PCIE_SLTSTA_DLLSC: u16 = 0x0100;

const PCIE_ROOTCTL_OFFSET: usize = 0x1C;
const PCIE_ROOTCTL_PME_ENABLE: u16 = 0x08;

const PCIE_ROOTSTA_OFFSET: usize = 0x20;
const PCIE_ROOTSTA_PME_REQ_ID_MASK: u32 = 0xFFFF;
const PCIE_ROOTSTA_PME_STATUS: u32 = 0x10000;
const PCIE_ROOTSTA_PME_PENDING: u32 = 0x20000;
