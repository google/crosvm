// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::BusDevice;
use acpi_tables::{aml, aml::Aml};
use base::{warn, Event};
use std::fmt::{self, Display};

/// Errors for battery devices.
#[derive(Debug)]
pub enum BatteryError {
    Non32BitMmioAddress,
}

impl Display for BatteryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::BatteryError::*;

        match self {
            Non32BitMmioAddress => write!(f, "Non 32-bit mmio address space"),
        }
    }
}

type Result<T> = std::result::Result<T, BatteryError>;

/// the GoldFish Battery MMIO length.
pub const GOLDFISHBAT_MMIO_LEN: u64 = 0x1000;

struct GoldfishBatteryState {
    // interrupt state
    int_status: u32,
    int_enable: u32,
    // AC state
    ac_online: u32,
    // Battery state
    status: u32,
    health: u32,
    present: u32,
    capacity: u32,
}

/// GoldFish Battery state
pub struct GoldfishBattery {
    state: GoldfishBatteryState,
    mmio_base: u32,
    irq_num: u32,
    _irq_evt: Event,
    _irq_resample_evt: Event,
}

/// Goldfish Battery MMIO offset
const BATTERY_INT_STATUS: u32 = 0;
const BATTERY_INT_ENABLE: u32 = 0x4;
const BATTERY_AC_ONLINE: u32 = 0x8;
const BATTERY_STATUS: u32 = 0xC;
const BATTERY_HEALTH: u32 = 0x10;
const BATTERY_PRESENT: u32 = 0x14;
const BATTERY_CAPACITY: u32 = 0x18;
const BATTERY_VOLTAGE: u32 = 0x1C;
const BATTERY_TEMP: u32 = 0x20;
const BATTERY_CHARGE_COUNTER: u32 = 0x24;
const BATTERY_VOLTAGE_MAX: u32 = 0x28;
const BATTERY_CURRENT_MAX: u32 = 0x2C;
const BATTERY_CURRENT_NOW: u32 = 0x30;
const BATTERY_CURRENT_AVG: u32 = 0x34;
const BATTERY_CHARGE_FULL_UAH: u32 = 0x38;
const BATTERY_CYCLE_COUNT: u32 = 0x40;

impl GoldfishBattery {
    /// Create GoldfishBattery device model
    ///
    /// * `mmio_base` - The 32-bit mmio base address.
    /// * `irq_num` - The corresponding interrupt number of the irq_evt
    ///               which will be put into the ACPI DSDT.
    /// * `irq_evt` - The interrupt event used to notify driver about
    ///               the battery properties changing.
    /// * `irq_resample_evt` - Resample interrupt event notified at EOI.
    pub fn new(
        mmio_base: u64,
        irq_num: u32,
        _irq_evt: Event,
        _irq_resample_evt: Event,
    ) -> Result<Self> {
        if mmio_base + GOLDFISHBAT_MMIO_LEN - 1 > u32::MAX as u64 {
            return Err(BatteryError::Non32BitMmioAddress);
        }

        let state = GoldfishBatteryState {
            capacity: 50,
            health: 1,
            present: 1,
            status: 1,
            ac_online: 1,
            int_enable: 0,
            int_status: 0,
        };

        Ok(GoldfishBattery {
            state,
            mmio_base: mmio_base as u32,
            irq_num,
            _irq_evt,
            _irq_resample_evt,
        })
    }
}

impl BusDevice for GoldfishBattery {
    fn debug_label(&self) -> String {
        "GoldfishBattery".to_owned()
    }

    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() != std::mem::size_of::<u32>() {
            warn!(
                "{}: unsupported read length {}, only support 4bytes read",
                self.debug_label(),
                data.len()
            );
            return;
        }

        let val = match offset as u32 {
            BATTERY_INT_STATUS => {
                // read to clear the interrupt status
                std::mem::replace(&mut self.state.int_status, 0)
            }
            BATTERY_INT_ENABLE => self.state.int_enable,
            BATTERY_AC_ONLINE => self.state.ac_online,
            BATTERY_STATUS => self.state.status,
            BATTERY_HEALTH => self.state.health,
            BATTERY_PRESENT => self.state.present,
            BATTERY_CAPACITY => self.state.capacity,
            BATTERY_VOLTAGE => 0,
            BATTERY_TEMP => 0,
            BATTERY_CHARGE_COUNTER => 0,
            BATTERY_VOLTAGE_MAX => 0,
            BATTERY_CURRENT_MAX => 0,
            BATTERY_CURRENT_NOW => 0,
            BATTERY_CURRENT_AVG => 0,
            BATTERY_CHARGE_FULL_UAH => 0,
            BATTERY_CYCLE_COUNT => 0,
            _ => {
                warn!("{}: unsupported read offset {}", self.debug_label(), offset);
                return;
            }
        };

        let val_arr = val.to_ne_bytes();
        data.copy_from_slice(&val_arr);
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() != std::mem::size_of::<u32>() {
            warn!(
                "{}: unsupported write length {}, only support 4bytes write",
                self.debug_label(),
                data.len()
            );
            return;
        }

        let mut val_arr = u32::to_ne_bytes(0 as u32);
        val_arr.copy_from_slice(data);
        let val = u32::from_ne_bytes(val_arr);

        match offset as u32 {
            BATTERY_INT_ENABLE => self.state.int_enable = val,
            _ => {
                warn!("{}: Bad write to offset {}", self.debug_label(), offset);
            }
        };
    }
}

impl Aml for GoldfishBattery {
    fn to_aml_bytes(&self, bytes: &mut Vec<u8>) {
        aml::Device::new(
            "GFBY".into(),
            vec![
                &aml::Name::new("_HID".into(), &"GFSH0001"),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![
                        &aml::Memory32Fixed::new(true, self.mmio_base, GOLDFISHBAT_MMIO_LEN as u32),
                        &aml::Interrupt::new(true, false, false, true, self.irq_num),
                    ]),
                ),
            ],
        )
        .to_aml_bytes(bytes);
    }
}
