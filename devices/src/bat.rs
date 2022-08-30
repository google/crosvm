// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;
use std::thread;

use acpi_tables::aml;
use acpi_tables::aml::Aml;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::Tube;
use base::WaitContext;
#[cfg(unix)]
use power_monitor::CreatePowerMonitorFn;
use remain::sorted;
use sync::Mutex;
use thiserror::Error;
use vm_control::BatControlCommand;
use vm_control::BatControlResult;

use crate::pci::CrosvmDeviceId;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;
use crate::IrqLevelEvent;

/// Errors for battery devices.
#[sorted]
#[derive(Error, Debug)]
pub enum BatteryError {
    #[error("Non 32-bit mmio address space")]
    Non32BitMmioAddress,
}

type Result<T> = std::result::Result<T, BatteryError>;

/// the GoldFish Battery MMIO length.
pub const GOLDFISHBAT_MMIO_LEN: u64 = 0x1000;

pub(crate) struct GoldfishBatteryState {
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
    voltage: u32,
    current: u32,
    charge_counter: u32,
    charge_full: u32,
}

macro_rules! create_battery_func {
    // $property: the battery property which is going to be modified.
    // $int: the interrupt status which is going to be set to notify the guest.
    ($fn:ident, $property:ident, $int:ident) => {
        pub(crate) fn $fn(&mut self, value: u32) -> bool {
            let old = std::mem::replace(&mut self.$property, value);
            old != self.$property && self.set_int_status($int)
        }
    };
}

impl GoldfishBatteryState {
    fn set_int_status(&mut self, mask: u32) -> bool {
        if ((self.int_enable & mask) != 0) && ((self.int_status & mask) == 0) {
            self.int_status |= mask;
            return true;
        }
        false
    }

    fn int_status(&self) -> u32 {
        self.int_status
    }

    create_battery_func!(set_ac_online, ac_online, AC_STATUS_CHANGED);

    create_battery_func!(set_status, status, BATTERY_STATUS_CHANGED);

    create_battery_func!(set_health, health, BATTERY_STATUS_CHANGED);

    create_battery_func!(set_present, present, BATTERY_STATUS_CHANGED);

    create_battery_func!(set_capacity, capacity, BATTERY_STATUS_CHANGED);

    #[cfg(unix)]
    create_battery_func!(set_voltage, voltage, BATTERY_STATUS_CHANGED);

    #[cfg(unix)]
    create_battery_func!(set_current, current, BATTERY_STATUS_CHANGED);

    #[cfg(unix)]
    create_battery_func!(set_charge_counter, charge_counter, BATTERY_STATUS_CHANGED);

    #[cfg(unix)]
    create_battery_func!(set_charge_full, charge_full, BATTERY_STATUS_CHANGED);
}

/// GoldFish Battery state
pub struct GoldfishBattery {
    state: Arc<Mutex<GoldfishBatteryState>>,
    mmio_base: u32,
    irq_num: u32,
    irq_evt: IrqLevelEvent,
    activated: bool,
    monitor_thread: Option<thread::JoinHandle<()>>,
    kill_evt: Option<Event>,
    tube: Option<Tube>,
    #[cfg(unix)]
    create_power_monitor: Option<Box<dyn CreatePowerMonitorFn>>,
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

/// Goldfish Battery interrupt bits
const BATTERY_STATUS_CHANGED: u32 = 1 << 0;
const AC_STATUS_CHANGED: u32 = 1 << 1;
const BATTERY_INT_MASK: u32 = BATTERY_STATUS_CHANGED | AC_STATUS_CHANGED;

/// Goldfish Battery status
pub(crate) const BATTERY_STATUS_VAL_UNKNOWN: u32 = 0;

/// Goldfish Battery health
const BATTERY_HEALTH_VAL_UNKNOWN: u32 = 0;

#[derive(EventToken)]
pub(crate) enum Token {
    Commands,
    Resample,
    Kill,
    #[cfg(unix)]
    Monitor,
}

fn command_monitor(
    tube: Tube,
    irq_evt: IrqLevelEvent,
    kill_evt: Event,
    state: Arc<Mutex<GoldfishBatteryState>>,
    #[cfg(unix)] create_power_monitor: Option<Box<dyn CreatePowerMonitorFn>>,
) {
    let wait_ctx: WaitContext<Token> = match WaitContext::build_with(&[
        (&tube, Token::Commands),
        (irq_evt.get_resample(), Token::Resample),
        (&kill_evt, Token::Kill),
    ]) {
        Ok(pc) => pc,
        Err(e) => {
            error!("failed to build WaitContext: {}", e);
            return;
        }
    };

    #[cfg(unix)]
    let mut power_monitor =
        crate::sys::unix::bat::create_power_monitor(create_power_monitor, &wait_ctx);

    'poll: loop {
        let events = match wait_ctx.wait() {
            Ok(v) => v,
            Err(e) => {
                error!("error while polling for events: {}", e);
                break;
            }
        };

        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::Commands => {
                    let req = match tube.recv() {
                        Ok(req) => req,
                        Err(e) => {
                            error!("failed to receive request: {}", e);
                            continue;
                        }
                    };

                    let mut bat_state = state.lock();
                    let inject_irq = match req {
                        BatControlCommand::SetStatus(status) => bat_state.set_status(status.into()),
                        BatControlCommand::SetHealth(health) => bat_state.set_health(health.into()),
                        BatControlCommand::SetPresent(present) => {
                            let v = if present != 0 { 1 } else { 0 };
                            bat_state.set_present(v)
                        }
                        BatControlCommand::SetCapacity(capacity) => {
                            let v = std::cmp::min(capacity, 100);
                            bat_state.set_capacity(v)
                        }
                        BatControlCommand::SetACOnline(ac_online) => {
                            let v = if ac_online != 0 { 1 } else { 0 };
                            bat_state.set_ac_online(v)
                        }
                    };

                    if inject_irq {
                        let _ = irq_evt.trigger();
                    }

                    if let Err(e) = tube.send(&BatControlResult::Ok) {
                        error!("failed to send response: {}", e);
                    }
                }

                #[cfg(unix)]
                Token::Monitor => {
                    crate::sys::bat::handle_token_monitor(
                        power_monitor.as_mut().unwrap(),
                        state.clone(),
                        &irq_evt,
                    );
                }

                Token::Resample => {
                    irq_evt.clear_resample();
                    if state.lock().int_status() != 0 {
                        let _ = irq_evt.trigger();
                    }
                }

                Token::Kill => break 'poll,
            }
        }
    }
}

impl GoldfishBattery {
    /// Create GoldfishBattery device model
    ///
    /// * `mmio_base` - The 32-bit mmio base address.
    /// * `irq_num` - The corresponding interrupt number of the irq_evt
    ///               which will be put into the ACPI DSDT.
    /// * `irq_evt` - The interrupt event used to notify driver about
    ///               the battery properties changing.
    /// * `socket` - Battery control socket
    pub fn new(
        mmio_base: u64,
        irq_num: u32,
        irq_evt: IrqLevelEvent,
        tube: Tube,
        #[cfg(unix)] create_power_monitor: Option<Box<dyn CreatePowerMonitorFn>>,
    ) -> Result<Self> {
        if mmio_base + GOLDFISHBAT_MMIO_LEN - 1 > u32::MAX as u64 {
            return Err(BatteryError::Non32BitMmioAddress);
        }
        let state = Arc::new(Mutex::new(GoldfishBatteryState {
            capacity: 50,
            health: BATTERY_HEALTH_VAL_UNKNOWN,
            present: 1,
            status: BATTERY_STATUS_VAL_UNKNOWN,
            ac_online: 1,
            int_enable: 0,
            int_status: 0,
            voltage: 0,
            current: 0,
            charge_counter: 0,
            charge_full: 0,
        }));

        Ok(GoldfishBattery {
            state,
            mmio_base: mmio_base as u32,
            irq_num,
            irq_evt,
            activated: false,
            monitor_thread: None,
            kill_evt: None,
            tube: Some(tube),
            #[cfg(unix)]
            create_power_monitor,
        })
    }

    /// return the descriptors used by this device
    pub fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = vec![
            self.irq_evt.get_trigger().as_raw_descriptor(),
            self.irq_evt.get_resample().as_raw_descriptor(),
        ];

        if let Some(tube) = &self.tube {
            rds.push(tube.as_raw_descriptor());
        }

        rds
    }

    /// start a monitor thread to monitor the events from host
    fn start_monitor(&mut self) {
        if self.activated {
            return;
        }

        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "{}: failed to create kill Event pair: {}",
                    self.debug_label(),
                    e
                );
                return;
            }
        };

        if let Some(tube) = self.tube.take() {
            let irq_evt = self.irq_evt.try_clone().unwrap();
            let bat_state = self.state.clone();

            #[cfg(unix)]
            let create_monitor_fn = self.create_power_monitor.take();
            let monitor_result = thread::Builder::new()
                .name(self.debug_label())
                .spawn(move || {
                    command_monitor(
                        tube,
                        irq_evt,
                        kill_evt,
                        bat_state,
                        #[cfg(unix)]
                        create_monitor_fn,
                    );
                });

            self.monitor_thread = match monitor_result {
                Err(e) => {
                    error!(
                        "{}: failed to spawn PowerIO monitor: {}",
                        self.debug_label(),
                        e
                    );
                    return;
                }
                Ok(join_handle) => Some(join_handle),
            };
            self.kill_evt = Some(self_kill_evt);
            self.activated = true;
        }
    }
}

impl Drop for GoldfishBattery {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do with a failure.
            let _ = kill_evt.signal();
        }
        if let Some(thread) = self.monitor_thread.take() {
            let _ = thread.join();
        }
    }
}

impl BusDevice for GoldfishBattery {
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::GoldfishBattery.into()
    }

    fn debug_label(&self) -> String {
        "GoldfishBattery".to_owned()
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
            BATTERY_INT_STATUS => {
                // read to clear the interrupt status
                std::mem::replace(&mut self.state.lock().int_status, 0)
            }
            BATTERY_INT_ENABLE => self.state.lock().int_enable,
            BATTERY_AC_ONLINE => self.state.lock().ac_online,
            BATTERY_STATUS => self.state.lock().status,
            BATTERY_HEALTH => self.state.lock().health,
            BATTERY_PRESENT => self.state.lock().present,
            BATTERY_CAPACITY => self.state.lock().capacity,
            BATTERY_VOLTAGE => self.state.lock().voltage,
            BATTERY_TEMP => 0,
            BATTERY_CHARGE_COUNTER => self.state.lock().charge_counter,
            BATTERY_VOLTAGE_MAX => 0,
            BATTERY_CURRENT_MAX => 0,
            BATTERY_CURRENT_NOW => self.state.lock().current,
            BATTERY_CURRENT_AVG => 0,
            BATTERY_CHARGE_FULL_UAH => self.state.lock().charge_full,
            BATTERY_CYCLE_COUNT => 0,
            _ => {
                warn!("{}: unsupported read address {}", self.debug_label(), info);
                return;
            }
        };

        let val_arr = val.to_ne_bytes();
        data.copy_from_slice(&val_arr);
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

        let mut val_arr = u32::to_ne_bytes(0u32);
        val_arr.copy_from_slice(data);
        let val = u32::from_ne_bytes(val_arr);

        match info.offset as u32 {
            BATTERY_INT_ENABLE => {
                self.state.lock().int_enable = val;
                if (val & BATTERY_INT_MASK) != 0 && !self.activated {
                    self.start_monitor();
                }
            }
            _ => {
                warn!("{}: Bad write to address {}", self.debug_label(), info);
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
