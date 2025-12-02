// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Device ID types.

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CrosvmDeviceId {
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

impl TryFrom<u16> for CrosvmDeviceId {
    type Error = base::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CrosvmDeviceId::Pit),
            2 => Ok(CrosvmDeviceId::Pic),
            3 => Ok(CrosvmDeviceId::Ioapic),
            4 => Ok(CrosvmDeviceId::Serial),
            5 => Ok(CrosvmDeviceId::Cmos),
            6 => Ok(CrosvmDeviceId::I8042),
            7 => Ok(CrosvmDeviceId::Pl030),
            8 => Ok(CrosvmDeviceId::ACPIPMResource),
            9 => Ok(CrosvmDeviceId::GoldfishBattery),
            10 => Ok(CrosvmDeviceId::DebugConsole),
            11 => Ok(CrosvmDeviceId::ProxyDevice),
            12 => Ok(CrosvmDeviceId::VfioPlatformDevice),
            13 => Ok(CrosvmDeviceId::DirectGsi),
            14 => Ok(CrosvmDeviceId::DirectMmio),
            15 => Ok(CrosvmDeviceId::DirectIo),
            16 => Ok(CrosvmDeviceId::UserspaceIrqChip),
            17 => Ok(CrosvmDeviceId::VmWatchdog),
            18 => Ok(CrosvmDeviceId::Pflash),
            19 => Ok(CrosvmDeviceId::VirtioMmio),
            20 => Ok(CrosvmDeviceId::AcAdapter),
            21 => Ok(CrosvmDeviceId::VirtualPmc),
            22 => Ok(CrosvmDeviceId::VirtCpufreq),
            23 => Ok(CrosvmDeviceId::FwCfg),
            _ => Err(base::Error::new(libc::EINVAL)),
        }
    }
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
    PlatformDeviceId(CrosvmDeviceId),
}

impl From<PciId> for DeviceId {
    fn from(v: PciId) -> Self {
        Self::PciDeviceId(v)
    }
}

impl From<CrosvmDeviceId> for DeviceId {
    fn from(v: CrosvmDeviceId) -> Self {
        Self::PlatformDeviceId(v)
    }
}

impl TryFrom<u32> for DeviceId {
    type Error = base::Error;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        let device_id = (value & 0xFFFF) as u16;
        let vendor_id = ((value & 0xFFFF_0000) >> 16) as u16;
        if vendor_id == 0xFFFF {
            Ok(DeviceId::PlatformDeviceId(CrosvmDeviceId::try_from(
                device_id,
            )?))
        } else {
            Ok(DeviceId::PciDeviceId(PciId::new(vendor_id, device_id)))
        }
    }
}

impl From<DeviceId> for u32 {
    fn from(id: DeviceId) -> Self {
        match id {
            DeviceId::PciDeviceId(pci_id) => pci_id.into(),
            DeviceId::PlatformDeviceId(id) => 0xFFFF0000 | id as u32,
        }
    }
}
