// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;
use std::path::Path;
use std::path::PathBuf;

use base::open_file;
use remain::sorted;
use thiserror::Error;

#[cfg(feature = "gpu")]
pub use crate::gpu::*;
pub use crate::sys::handle_request;
pub use crate::*;

#[sorted]
#[derive(Error, Debug)]
enum ModifyBatError {
    #[error("{0}")]
    BatControlErr(BatControlResult),
}

#[sorted]
#[derive(Error, Debug)]
pub enum ModifyUsbError {
    #[error("failed to open device {0}: {1}")]
    FailedToOpenDevice(PathBuf, base::Error),
    #[error("socket failed")]
    SocketFailed,
    #[error("unexpected response: {0}")]
    UnexpectedResponse(VmResponse),
    #[error("{0}")]
    UsbControl(UsbControlResult),
}

pub type ModifyUsbResult<T> = std::result::Result<T, ModifyUsbError>;

pub type VmsRequestResult = std::result::Result<(), ()>;

/// Send a `VmRequest` that expects a `VmResponse::Ok` reply.
pub fn vms_request<T: AsRef<Path> + std::fmt::Debug>(
    request: &VmRequest,
    socket_path: T,
) -> VmsRequestResult {
    match handle_request(request, socket_path)? {
        VmResponse::Ok => Ok(()),
        r => {
            println!("unexpected response: {r}");
            Err(())
        }
    }
}

pub fn do_usb_attach<T: AsRef<Path> + std::fmt::Debug>(
    socket_path: T,
    dev_path: &Path,
) -> ModifyUsbResult<UsbControlResult> {
    let usb_file = open_file(dev_path, OpenOptions::new().read(true).write(true))
        .map_err(|e| ModifyUsbError::FailedToOpenDevice(dev_path.into(), e))?;

    let request = VmRequest::UsbCommand(UsbControlCommand::AttachDevice { file: usb_file });
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

pub fn do_swap_status<T: AsRef<Path> + std::fmt::Debug>(socket_path: T) -> VmsRequestResult {
    let response = handle_request(&VmRequest::Swap(SwapCommand::Status), socket_path)?;
    match &response {
        VmResponse::SwapStatus(_) => {
            println!("{}", response);
            Ok(())
        }
        r => {
            println!("unexpected response: {r:?}");
            Err(())
        }
    }
}

pub type HandleRequestResult = std::result::Result<VmResponse, ()>;
