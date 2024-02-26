// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

#[cfg(feature = "seccomp_trace")]
use base::debug;
use base::Event;
use devices::serial_device::SerialHardware;
use devices::serial_device::SerialParameters;
use devices::serial_device::SerialType;
use devices::Bus;
use devices::Serial;
use hypervisor::ProtectionType;
#[cfg(feature = "seccomp_trace")]
use jail::read_jail_addr;
#[cfg(windows)]
use jail::FakeMinijailStub as Minijail;
#[cfg(any(target_os = "android", target_os = "linux"))]
use minijail::Minijail;
use remain::sorted;
use thiserror::Error as ThisError;

use crate::DeviceRegistrationError;

mod sys;

/// Add the default serial parameters for serial ports that have not already been specified.
///
/// This ensures that `serial_parameters` will contain parameters for each of the four PC-style
/// serial ports (COM1-COM4).
///
/// It also sets the first `SerialHardware::Serial` to be the default console device if no other
/// serial parameters exist with console=true and the first serial device has not already been
/// configured explicitly.
pub fn set_default_serial_parameters(
    serial_parameters: &mut BTreeMap<(SerialHardware, u8), SerialParameters>,
    is_vhost_user_console_enabled: bool,
) {
    // If no console device exists and the first serial port has not been specified,
    // set the first serial port as a stdout+stdin console.
    let default_console = (SerialHardware::Serial, 1);
    if !serial_parameters.iter().any(|(_, p)| p.console) && !is_vhost_user_console_enabled {
        serial_parameters
            .entry(default_console)
            .or_insert(SerialParameters {
                type_: SerialType::Stdout,
                hardware: SerialHardware::Serial,
                name: None,
                path: None,
                input: None,
                num: 1,
                console: true,
                earlycon: false,
                stdin: true,
                out_timestamp: false,
                ..Default::default()
            });
    }

    // Ensure all four of the COM ports exist.
    // If one of these four SerialHardware::Serial port was not configured by the user,
    // set it up as a sink.
    for num in 1..=4 {
        let key = (SerialHardware::Serial, num);
        serial_parameters.entry(key).or_insert(SerialParameters {
            type_: SerialType::Sink,
            hardware: SerialHardware::Serial,
            name: None,
            path: None,
            input: None,
            num,
            console: false,
            earlycon: false,
            stdin: false,
            out_timestamp: false,
            ..Default::default()
        });
    }
}

/// Address for Serial ports in x86
pub const SERIAL_ADDR: [u64; 4] = [0x3f8, 0x2f8, 0x3e8, 0x2e8];

/// Adds serial devices to the provided bus based on the serial parameters given.
///
/// Only devices with hardware type `SerialHardware::Serial` are added by this function.
///
/// # Arguments
///
/// * `protection_type` - VM protection mode.
/// * `io_bus` - Bus to add the devices to
/// * `com_evt_1_3` - event for com1 and com3
/// * `com_evt_1_4` - event for com2 and com4
/// * `serial_parameters` - definitions of serial parameter configurations.
/// * `serial_jail` - minijail object cloned for use with each serial device. All four of the
///   traditional PC-style serial ports (COM1-COM4) must be specified.
pub fn add_serial_devices(
    protection_type: ProtectionType,
    io_bus: &Bus,
    com_evt_1_3: &Event,
    com_evt_2_4: &Event,
    serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
    #[cfg_attr(windows, allow(unused_variables))] serial_jail: Option<Minijail>,
    #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
) -> std::result::Result<(), DeviceRegistrationError> {
    for com_num in 0..=3 {
        let com_evt = match com_num {
            0 => &com_evt_1_3,
            1 => &com_evt_2_4,
            2 => &com_evt_1_3,
            3 => &com_evt_2_4,
            _ => &com_evt_1_3,
        };

        let param = serial_parameters
            .get(&(SerialHardware::Serial, com_num + 1))
            .ok_or(DeviceRegistrationError::MissingRequiredSerialDevice(
                com_num + 1,
            ))?;

        let mut preserved_descriptors = Vec::new();
        let com = param
            .create_serial_device::<Serial>(protection_type, com_evt, &mut preserved_descriptors)
            .map_err(DeviceRegistrationError::CreateSerialDevice)?;

        #[cfg(any(target_os = "android", target_os = "linux"))]
        let serial_jail = if let Some(serial_jail) = serial_jail.as_ref() {
            let jail_clone = serial_jail
                .try_clone()
                .map_err(DeviceRegistrationError::CloneJail)?;
            #[cfg(feature = "seccomp_trace")]
            debug!(
                    "seccomp_trace {{\"event\": \"minijail_clone\", \"src_jail_addr\": \"0x{:x}\", \"dst_jail_addr\": \"0x{:x}\"}}",
                    read_jail_addr(serial_jail),
                    read_jail_addr(&jail_clone)
                );
            Some(jail_clone)
        } else {
            None
        };
        #[cfg(windows)]
        let serial_jail = None;

        sys::add_serial_device(
            com_num as usize,
            com,
            param,
            serial_jail,
            preserved_descriptors,
            io_bus,
            #[cfg(feature = "swap")]
            swap_controller,
        )?;
    }

    Ok(())
}

#[sorted]
#[derive(ThisError, Debug)]
pub enum GetSerialCmdlineError {
    #[error("Error appending to cmdline: {0}")]
    KernelCmdline(kernel_cmdline::Error),
    #[error("Hardware {0} not supported as earlycon")]
    UnsupportedEarlyconHardware(SerialHardware),
}

pub type GetSerialCmdlineResult<T> = std::result::Result<T, GetSerialCmdlineError>;

/// Add serial options to the provided `cmdline` based on `serial_parameters`.
/// `serial_io_type` should be "io" if the platform uses x86-style I/O ports for serial devices
/// or "mmio" if the serial ports are memory mapped.
// TODO(b/227407433): Support cases where vhost-user console is specified.
pub fn get_serial_cmdline(
    cmdline: &mut kernel_cmdline::Cmdline,
    serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
    serial_io_type: &str,
) -> GetSerialCmdlineResult<()> {
    for serial_parameter in serial_parameters
        .iter()
        .filter(|(_, p)| p.console)
        .map(|(k, _)| k)
    {
        match serial_parameter {
            (SerialHardware::Serial, num) => {
                cmdline
                    .insert("console", &format!("ttyS{}", num - 1))
                    .map_err(GetSerialCmdlineError::KernelCmdline)?;
            }
            (SerialHardware::VirtioConsole, num) | (SerialHardware::LegacyVirtioConsole, num) => {
                cmdline
                    .insert("console", &format!("hvc{}", num - 1))
                    .map_err(GetSerialCmdlineError::KernelCmdline)?;
            }
            (SerialHardware::Debugcon, _) => {}
        }
    }

    match serial_parameters
        .iter()
        .filter(|(_, p)| p.earlycon)
        .map(|(k, _)| k)
        .next()
    {
        Some((SerialHardware::Serial, num)) => {
            if let Some(addr) = SERIAL_ADDR.get(*num as usize - 1) {
                cmdline
                    .insert(
                        "earlycon",
                        &format!("uart8250,{},0x{:x}", serial_io_type, addr),
                    )
                    .map_err(GetSerialCmdlineError::KernelCmdline)?;
            }
        }
        Some((hw, _num)) => {
            return Err(GetSerialCmdlineError::UnsupportedEarlyconHardware(*hw));
        }
        None => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use kernel_cmdline::Cmdline;

    use super::*;

    #[test]
    fn get_serial_cmdline_default() {
        let mut cmdline = Cmdline::new(4096);
        let mut serial_parameters = BTreeMap::new();

        set_default_serial_parameters(&mut serial_parameters, false);
        get_serial_cmdline(&mut cmdline, &serial_parameters, "io")
            .expect("get_serial_cmdline failed");

        let cmdline_str = cmdline.as_str();
        assert!(cmdline_str.contains("console=ttyS0"));
    }

    #[test]
    fn get_serial_cmdline_virtio_console() {
        let mut cmdline = Cmdline::new(4096);
        let mut serial_parameters = BTreeMap::new();

        // Add a virtio-console device with console=true.
        serial_parameters.insert(
            (SerialHardware::VirtioConsole, 1),
            SerialParameters {
                type_: SerialType::Stdout,
                hardware: SerialHardware::VirtioConsole,
                name: None,
                path: None,
                input: None,
                num: 1,
                console: true,
                earlycon: false,
                stdin: true,
                out_timestamp: false,
                debugcon_port: 0,
                pci_address: None,
            },
        );

        set_default_serial_parameters(&mut serial_parameters, false);
        get_serial_cmdline(&mut cmdline, &serial_parameters, "io")
            .expect("get_serial_cmdline failed");

        let cmdline_str = cmdline.as_str();
        assert!(cmdline_str.contains("console=hvc0"));
    }

    #[test]
    fn get_serial_cmdline_virtio_console_serial_earlycon() {
        let mut cmdline = Cmdline::new(4096);
        let mut serial_parameters = BTreeMap::new();

        // Add a virtio-console device with console=true.
        serial_parameters.insert(
            (SerialHardware::VirtioConsole, 1),
            SerialParameters {
                type_: SerialType::Stdout,
                hardware: SerialHardware::VirtioConsole,
                name: None,
                path: None,
                input: None,
                num: 1,
                console: true,
                earlycon: false,
                stdin: true,
                out_timestamp: false,
                debugcon_port: 0,
                pci_address: None,
            },
        );

        // Override the default COM1 with an earlycon device.
        serial_parameters.insert(
            (SerialHardware::Serial, 1),
            SerialParameters {
                type_: SerialType::Stdout,
                hardware: SerialHardware::Serial,
                name: None,
                path: None,
                input: None,
                num: 1,
                console: false,
                earlycon: true,
                stdin: false,
                out_timestamp: false,
                debugcon_port: 0,
                pci_address: None,
            },
        );

        set_default_serial_parameters(&mut serial_parameters, false);
        get_serial_cmdline(&mut cmdline, &serial_parameters, "io")
            .expect("get_serial_cmdline failed");

        let cmdline_str = cmdline.as_str();
        assert!(cmdline_str.contains("console=hvc0"));
        assert!(cmdline_str.contains("earlycon=uart8250,io,0x3f8"));
    }

    #[test]
    fn get_serial_cmdline_virtio_console_invalid_earlycon() {
        let mut cmdline = Cmdline::new(4096);
        let mut serial_parameters = BTreeMap::new();

        // Try to add a virtio-console device with earlycon=true (unsupported).
        serial_parameters.insert(
            (SerialHardware::VirtioConsole, 1),
            SerialParameters {
                type_: SerialType::Stdout,
                hardware: SerialHardware::VirtioConsole,
                name: None,
                path: None,
                input: None,
                num: 1,
                console: false,
                earlycon: true,
                stdin: true,
                out_timestamp: false,
                debugcon_port: 0,
                pci_address: None,
            },
        );

        set_default_serial_parameters(&mut serial_parameters, false);
        get_serial_cmdline(&mut cmdline, &serial_parameters, "io")
            .expect_err("get_serial_cmdline succeeded");
    }
}
