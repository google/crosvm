// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The ACPI AC adapter device (ACPI0003) description can be found in ACPI specification,
// section: 10.3. The AC adapter status change is signalized by generating associated GPE, which
// Notify()'s AC adapter device in the ACPI name space.

use crate::Suspendable;
use crate::{pci::CrosvmDeviceId, BusAccessInfo, BusDevice, DeviceId};
use acpi_tables::aml;
use acpi_tables::aml::Aml;
use anyhow::Context;
use base::warn;
use std::fs::read_to_string;
use std::path::PathBuf;

pub const ACDC_VIRT_MMIO_SIZE: u64 = 0x10;

/// ACDC Virt MMIO offset
const ACDC_ACEX: u32 = 0;
const _ACDC_RESERVED2: u32 = 0x4;
const _ACDC_RESERVED3: u32 = 0x8;
const _ACDC_RESERVED4: u32 = 0xc;

const ACDC_ACEX_UNINIT: u32 = 0xff;

pub struct AcAdapter {
    pub acex: u32,
    mmio_base: u64,
    pub gpe_nr: u32,
}

impl AcAdapter {
    pub fn new(mmio_base: u64, gpe_nr: u32) -> Self {
        AcAdapter {
            acex: ACDC_ACEX_UNINIT,
            mmio_base,
            gpe_nr,
        }
    }

    // The AC adapter state update is triggered upon handling "ac_adapter" acpi event, nevertheless
    // the init value is retrieved from host's sysfs. Determining it from AcAdapter::new would be
    // racy since after AcAdapter creation but before acpi listener is activated any status change
    // will be lost. Determining init state in such way will be triggered only once during guest
    // driver probe.
    fn get_init_state(&mut self) {
        // Find host AC adapter (ACPI0003 HID) and read its state.
        // e.g. hid     /sys/class/power_supply/ADP1/device/hid
        //      state   /sys/class/power_supply/ADP1/online
        let mut ac_status = None;
        let mut host_sysfs = PathBuf::new();
        host_sysfs.push("/sys/class/power_supply/");
        for entry in host_sysfs
            .read_dir()
            .expect("read_dir call failed")
            .flatten()
        {
            let hid_path = entry.path().join("device/hid");
            if hid_path.exists() {
                if read_to_string(hid_path.as_path())
                    .with_context(|| format!("failed to read {}", hid_path.display()))
                    .unwrap()
                    .contains("ACPI0003")
                {
                    ac_status = Some(
                        read_to_string(entry.path().join("online"))
                            .unwrap()
                            .trim()
                            .parse::<u32>()
                            .unwrap(),
                    );
                }
            }
        }

        if ac_status.is_none() {
            warn!("Couldn't get ACPI0003 AC adapter state");
        }
        self.acex = ac_status.unwrap_or(0);
    }
}

impl BusDevice for AcAdapter {
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::AcAdapter.into()
    }
    fn debug_label(&self) -> String {
        "AcAdapter".to_owned()
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

        let val = match info.offset as u32 {
            ACDC_ACEX => {
                if self.acex == ACDC_ACEX_UNINIT {
                    self.get_init_state();
                }
                self.acex
            }
            _ => {
                warn!("{}: unsupported read address {}", self.debug_label(), info);
                return;
            }
        };

        let val_arr = val.to_le_bytes();
        data.copy_from_slice(&val_arr);
    }
}

impl Aml for AcAdapter {
    fn to_aml_bytes(&self, bytes: &mut Vec<u8>) {
        aml::Device::new(
            "ACDC".into(),
            vec![
                &aml::Name::new("_HID".into(), &"ACPI0003"),
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
                    vec![aml::FieldEntry::Named(*b"ACEX", 32)],
                ),
                &aml::Method::new(
                    "_PSR".into(),
                    0,
                    false,
                    vec![&aml::Return::new(&aml::Name::new_field_name("ACEX"))],
                ),
                &aml::Method::new("_STA".into(), 0, false, vec![&aml::Return::new(&0xfu8)]),
            ],
        )
        .to_aml_bytes(bytes);
        aml::Scope::new(
            "_GPE".into(),
            vec![&aml::Method::new(
                format!("_E{:02X}", self.gpe_nr).as_str().into(),
                0,
                false,
                vec![&aml::Notify::new(&aml::Path::new("ACDC"), &0x80u8)],
            )],
        )
        .to_aml_bytes(bytes);
    }
}

impl Suspendable for AcAdapter {}
