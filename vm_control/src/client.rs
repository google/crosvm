// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;
use std::num::ParseIntError;
use std::path::{Path, PathBuf};

use base::info;
use remain::sorted;
use thiserror::Error;

pub use crate::{sys::handle_request, *};

#[sorted]
#[derive(Error, Debug)]
enum ModifyBatError {
    #[error("{0}")]
    BatControlErr(BatControlResult),
}

#[sorted]
#[derive(Error, Debug)]
pub enum ModifyUsbError {
    #[error("argument missing: {0}")]
    ArgMissing(&'static str),
    #[error("failed to parse argument {0} value `{1}`")]
    ArgParse(&'static str, String),
    #[error("failed to parse integer argument {0} value `{1}`: {2}")]
    ArgParseInt(&'static str, String, ParseIntError),
    #[error("failed to validate file descriptor: {0}")]
    FailedDescriptorValidate(base::Error),
    #[error("path `{0}` does not exist")]
    PathDoesNotExist(PathBuf),
    #[error("socket failed")]
    SocketFailed,
    #[error("unexpected response: {0}")]
    UnexpectedResponse(VmResponse),
    #[error("unknown command: `{0}`")]
    UnknownCommand(String),
    #[error("{0}")]
    UsbControl(UsbControlResult),
}

pub type ModifyUsbResult<T> = std::result::Result<T, ModifyUsbError>;

pub type VmsRequestResult = std::result::Result<(), ()>;

pub fn vms_request<T: AsRef<Path> + std::fmt::Debug>(
    request: &VmRequest,
    socket_path: T,
) -> VmsRequestResult {
    let response = handle_request(request, socket_path)?;
    info!("request response was {}", response);
    Ok(())
}

pub fn do_usb_attach<T: AsRef<Path> + std::fmt::Debug>(
    socket_path: T,
    bus: u8,
    addr: u8,
    vid: u16,
    pid: u16,
    dev_path: &Path,
) -> ModifyUsbResult<UsbControlResult> {
    let usb_file: File = if dev_path.parent() == Some(Path::new("/proc/self/fd")) {
        // Special case '/proc/self/fd/*' paths. The FD is already open, just use it.
        // Safe because we will validate |raw_fd|.
        unsafe { File::from_raw_descriptor(sys::raw_descriptor_from_path(dev_path)?) }
    } else {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(dev_path)
            .map_err(|_| ModifyUsbError::UsbControl(UsbControlResult::FailedToOpenDevice))?
    };

    let request = VmRequest::UsbCommand(UsbControlCommand::AttachDevice {
        bus,
        addr,
        vid,
        pid,
        file: usb_file,
    });
    let response =
        handle_request(&request, socket_path).map_err(|_| ModifyUsbError::SocketFailed)?;
    match response {
        VmResponse::UsbResponse(usb_resp) => Ok(usb_resp),
        r => Err(ModifyUsbError::UnexpectedResponse(r)),
    }
}

pub fn do_usb_detach<T: AsRef<Path> + std::fmt::Debug>(
    socket_path: T,
    port: u8,
) -> ModifyUsbResult<UsbControlResult> {
    let request = VmRequest::UsbCommand(UsbControlCommand::DetachDevice { port });
    let response =
        handle_request(&request, socket_path).map_err(|_| ModifyUsbError::SocketFailed)?;
    match response {
        VmResponse::UsbResponse(usb_resp) => Ok(usb_resp),
        r => Err(ModifyUsbError::UnexpectedResponse(r)),
    }
}

pub fn do_usb_list<T: AsRef<Path> + std::fmt::Debug>(
    socket_path: T,
) -> ModifyUsbResult<UsbControlResult> {
    let mut ports: [u8; USB_CONTROL_MAX_PORTS] = Default::default();
    for (index, port) in ports.iter_mut().enumerate() {
        *port = index as u8
    }
    let request = VmRequest::UsbCommand(UsbControlCommand::ListDevice { ports });
    let response =
        handle_request(&request, socket_path).map_err(|_| ModifyUsbError::SocketFailed)?;
    match response {
        VmResponse::UsbResponse(usb_resp) => Ok(usb_resp),
        r => Err(ModifyUsbError::UnexpectedResponse(r)),
    }
}

pub type DoModifyBatteryResult = std::result::Result<(), ()>;

pub fn do_modify_battery<T: AsRef<Path> + std::fmt::Debug>(
    socket_path: T,
    battery_type: &str,
    property: &str,
    target: &str,
) -> DoModifyBatteryResult {
    let response = match battery_type.parse::<BatteryType>() {
        Ok(type_) => match BatControlCommand::new(property.to_string(), target.to_string()) {
            Ok(cmd) => {
                let request = VmRequest::BatCommand(type_, cmd);
                Ok(handle_request(&request, socket_path)?)
            }
            Err(e) => Err(ModifyBatError::BatControlErr(e)),
        },
        Err(e) => Err(ModifyBatError::BatControlErr(e)),
    };

    match response {
        Ok(response) => {
            println!("{}", response);
            Ok(())
        }
        Err(e) => {
            println!("error {}", e);
            Err(())
        }
    }
}

pub type HandleRequestResult = std::result::Result<VmResponse, ()>;
