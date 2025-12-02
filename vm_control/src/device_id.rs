// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Device ID types.

#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PlatformDeviceId {
    Pit = 1,
    Pic = 2,
    Ioapic = 3,
    Serial = 4,
    Cmos = 5,
    I8042 = 6,
    Pl030 = 7,
    ACPIPMResource = 8,
    GoldfishBattery = 9,
    DebugConsole = 10,
    ProxyDevice = 11,
    VfioPlatformDevice = 12,
    DirectGsi = 13,
    DirectIo = 14,
    DirectMmio = 15,
    UserspaceIrqChip = 16,
    VmWatchdog = 17,
    Pflash = 18,
    VirtioMmio = 19,
    AcAdapter = 20,
    VirtualPmc = 21,
    VirtCpufreq = 22,
    FwCfg = 23,
}

/// A wrapper structure for pci device and vendor id.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PciId {
    vendor_id: u16,
    device_id: u16,
}

impl PciId {
    pub fn new(vendor_id: u16, device_id: u16) -> Self {
        Self {
            vendor_id,
            device_id,
        }
    }
}

impl From<PciId> for u32 {
    fn from(pci_id: PciId) -> Self {
        // vendor ID is the lower 16 bits and device id is the upper 16 bits
        pci_id.vendor_id as u32 | (pci_id.device_id as u32) << 16
    }
}

impl From<u32> for PciId {
    fn from(value: u32) -> Self {
        let vendor_id = (value & 0xFFFF) as u16;
        let device_id = (value >> 16) as u16;
        Self::new(vendor_id, device_id)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeviceId {
    /// PCI Device, use its PciId directly.
    PciDeviceId(PciId),
    /// Platform device, use a unique Id.
    PlatformDeviceId(PlatformDeviceId),
}

impl From<PciId> for DeviceId {
    fn from(v: PciId) -> Self {
        Self::PciDeviceId(v)
    }
}

impl From<PlatformDeviceId> for DeviceId {
    fn from(v: PlatformDeviceId) -> Self {
        Self::PlatformDeviceId(v)
    }
}

impl DeviceId {
    pub fn metrics_id(self) -> u32 {
        match self {
            DeviceId::PciDeviceId(pci_id) => pci_id.into(),
            DeviceId::PlatformDeviceId(id) => {
                static_assertions::const_assert!(std::mem::size_of::<PlatformDeviceId>() <= 2);
                0xFFFF0000 | id as u32
            }
        }
    }
}
