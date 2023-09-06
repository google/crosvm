// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use acpi_tables::aml;
use acpi_tables::aml::Aml;
use base::warn;
use sync::Condvar;
use sync::Mutex;

use crate::pci::CrosvmDeviceId;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;
use crate::Suspendable;

/// PMC Virt MMIO offset
const PMC_RESERVED1: u32 = 0;
const _PMC_RESERVED2: u32 = 0x4;
const _PMC_RESERVED3: u32 = 0x8;
const _PMC_RESERVED4: u32 = 0xc;

pub const VPMC_VIRT_MMIO_SIZE: u64 = 0x10;

pub struct VirtualPmc {
    mmio_base: u64,
    guest_suspended_cvar: Arc<(Mutex<bool>, Condvar)>,
}

impl VirtualPmc {
    pub fn new(mmio_base: u64, guest_suspended_cvar: Arc<(Mutex<bool>, Condvar)>) -> Self {
        VirtualPmc {
            mmio_base,
            guest_suspended_cvar,
        }
    }
}

fn handle_s2idle_request(guest_suspended_cvar: &Arc<(Mutex<bool>, Condvar)>) {
    // Wake up blocked thread on condvar, which is awaiting non-privileged guest suspension to
    // finish.
    let (lock, cvar) = &**guest_suspended_cvar;
    let mut guest_suspended = lock.lock();
    *guest_suspended = true;

    cvar.notify_one();
}

impl BusDevice for VirtualPmc {
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::VirtualPmc.into()
    }
    fn debug_label(&self) -> String {
        "PmcVirt".to_owned()
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        if data.len() != std::mem::size_of::<u32>() {
            warn!(
                "{}: unsupported read length {}, only support 4bytes read",
                self.debug_label(),
                data.len()
            );
            return;
        }

        warn!("{}: unsupported read address {}", self.debug_label(), info);
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        if data.len() != std::mem::size_of::<u32>() {
            warn!(
                "{}: unsupported write length {}, only support 4bytes write",
                self.debug_label(),
                data.len()
            );
            return;
        }

        match info.offset as u32 {
            PMC_RESERVED1 => {
                handle_s2idle_request(&self.guest_suspended_cvar);
            }
            _ => {
                warn!("{}: Bad write to address {}", self.debug_label(), info);
            }
        };
    }
}

impl Aml for VirtualPmc {
    fn to_aml_bytes(&self, bytes: &mut Vec<u8>) {
        let vpmc_uuid = "9ea49ba3-434a-49a6-be30-37cc55c4d397";
        aml::Device::new(
            "VPMC".into(),
            vec![
                &aml::Name::new("_CID".into(), &aml::EISAName::new("PNP0D80")),
                &aml::Name::new("_HID".into(), &"HYPE0001"),
                &aml::Name::new("UUID".into(), &aml::Uuid::new(vpmc_uuid)),
                &aml::OpRegion::new(
                    "VREG".into(),
                    aml::OpRegionSpace::SystemMemory,
                    &self.mmio_base,
                    &(16_u32),
                ),
                &aml::Field::new(
                    "VREG".into(),
                    aml::FieldAccessType::DWord,
                    aml::FieldLockRule::Lock,
                    aml::FieldUpdateRule::Preserve,
                    vec![aml::FieldEntry::Named(*b"RSV1", 32)],
                ),
                &aml::Method::new(
                    "_DSM".into(),
                    4,
                    true,
                    vec![
                        &aml::If::new(
                            &aml::Equal::new(&aml::Arg(0), &aml::Name::new_field_name("UUID")),
                            vec![
                                &aml::If::new(
                                    &aml::Equal::new(&aml::Arg(2), &aml::ZERO),
                                    vec![&aml::Return::new(&aml::BufferData::new(vec![3]))],
                                ),
                                &aml::If::new(
                                    &aml::Equal::new(&aml::Arg(2), &aml::ONE),
                                    vec![&aml::Store::new(
                                        &aml::Name::new_field_name("RSV1"),
                                        &0x3_usize,
                                    )],
                                ),
                            ],
                        ),
                        &aml::Return::new(&aml::BufferData::new(vec![3])),
                    ],
                ),
            ],
        )
        .to_aml_bytes(bytes);
    }
}

impl Suspendable for VirtualPmc {}
