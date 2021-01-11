// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{BusAccessInfo, BusDevice, BusResumeDevice};
use acpi_tables::{aml, aml::Aml};
use base::{error, warn, Event};

/// ACPI PM resource for handling OS suspend/resume request
pub struct ACPIPMResource {
    suspend_evt: Event,
    exit_evt: Event,
    pm1_status: u16,
    pm1_enable: u16,
    pm1_control: u16,
    sleep_control: u8,
    sleep_status: u8,
}

impl ACPIPMResource {
    /// Constructs ACPI Power Management Resouce.
    pub fn new(suspend_evt: Event, exit_evt: Event) -> ACPIPMResource {
        ACPIPMResource {
            suspend_evt,
            exit_evt,
            pm1_status: 0,
            pm1_enable: 0,
            pm1_control: 0,
            sleep_control: 0,
            sleep_status: 0,
        }
    }
}

/// the ACPI PM register length.
pub const ACPIPM_RESOURCE_LEN: u8 = 8;
pub const ACPIPM_RESOURCE_EVENTBLK_LEN: u8 = 4;
pub const ACPIPM_RESOURCE_CONTROLBLK_LEN: u8 = 2;

/// ACPI PM register value definations
const PM1_STATUS: u16 = 0;
const PM1_ENABLE: u16 = 2;
const PM1_CONTROL: u16 = 4;
const SLEEP_CONTROL: u16 = 6;
const SLEEP_STATUS: u16 = 7;
const BITMASK_PM1CNT_SLEEP_ENABLE: u16 = 0x2000;
const BITMASK_SLEEPCNT_SLEEP_ENABLE: u8 = 0x20;
const BITMASK_PM1CNT_WAKE_STATUS: u16 = 0x8000;
const BITMASK_SLEEPCNT_WAKE_STATUS: u8 = 0x80;

const BITMASK_PM1CNT_SLEEP_TYPE: u16 = 0x1C00;
const SLEEP_TYPE_S5: u16 = 0;

impl BusDevice for ACPIPMResource {
    fn debug_label(&self) -> String {
        "ACPIPMResource".to_owned()
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        let val = match info.offset as u16 {
            PM1_STATUS => self.pm1_status,
            PM1_ENABLE => self.pm1_enable,
            PM1_CONTROL => self.pm1_control,
            SLEEP_CONTROL => self.sleep_control as u16,
            SLEEP_STATUS => self.sleep_status as u16,
            _ => {
                warn!("ACPIPM: Bad read from {}", info);
                return;
            }
        };

        let val_arr = val.to_ne_bytes();
        for i in 0..std::mem::size_of::<u16>() {
            if i < data.len() {
                data[i] = val_arr[i];
            }
        }
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        let max_bytes = std::mem::size_of::<u16>();

        // only allow maximum max_bytes to write
        if data.len() > max_bytes {
            warn!("ACPIPM: bad write size: {}", data.len());
            return;
        }

        let mut val_arr = u16::to_ne_bytes(0u16);
        for i in 0..std::mem::size_of::<u16>() {
            if i < data.len() {
                val_arr[i] = data[i];
            }
        }
        let val = u16::from_ne_bytes(val_arr);

        match info.offset as u16 {
            PM1_STATUS => self.pm1_status &= !val,
            PM1_ENABLE => self.pm1_enable = val,
            PM1_CONTROL => {
                if (val & BITMASK_PM1CNT_SLEEP_ENABLE) == BITMASK_PM1CNT_SLEEP_ENABLE {
                    if val & BITMASK_PM1CNT_SLEEP_TYPE == SLEEP_TYPE_S5 {
                        if let Err(e) = self.exit_evt.write(1) {
                            error!("ACPIPM: failed to trigger exit event: {}", e);
                        }
                    } else {
                        if let Err(e) = self.suspend_evt.write(1) {
                            error!("ACPIPM: failed to trigger suspend event: {}", e);
                        }
                    }
                }
                self.pm1_control = val & !BITMASK_PM1CNT_SLEEP_ENABLE;
            }
            SLEEP_CONTROL => {
                let sleep_control = val as u8;
                if (sleep_control & BITMASK_SLEEPCNT_SLEEP_ENABLE) == BITMASK_SLEEPCNT_SLEEP_ENABLE
                {
                    if let Err(e) = self.suspend_evt.write(1) {
                        error!("ACPIPM: failed to trigger suspend event: {}", e);
                    }
                }
                self.sleep_control = sleep_control as u8 & !BITMASK_SLEEPCNT_SLEEP_ENABLE;
            }
            SLEEP_STATUS => self.sleep_status &= !val as u8,
            _ => {
                warn!("ACPIPM: Bad write to {}", info);
            }
        };
    }
}

impl BusResumeDevice for ACPIPMResource {
    fn resume_imminent(&mut self) {
        let val = self.pm1_status;
        self.pm1_status = val | BITMASK_PM1CNT_WAKE_STATUS;

        let val = self.sleep_status;
        self.sleep_status = val | BITMASK_SLEEPCNT_WAKE_STATUS;
    }
}

impl Aml for ACPIPMResource {
    fn to_aml_bytes(&self, bytes: &mut Vec<u8>) {
        // S1
        aml::Name::new(
            "_S1_".into(),
            &aml::Package::new(vec![&aml::ONE, &aml::ONE, &aml::ZERO, &aml::ZERO]),
        )
        .to_aml_bytes(bytes);

        // S5
        aml::Name::new(
            "_S5_".into(),
            &aml::Package::new(vec![&aml::ZERO, &aml::ZERO, &aml::ZERO, &aml::ZERO]),
        )
        .to_aml_bytes(bytes);
    }
}
