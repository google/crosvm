// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::usb::xhci::scatter_gather_buffer::Error as BufferError;
use crate::usb::xhci::xhci_transfer::Error as XhciTransferError;
use crate::utils::Error as UtilsError;
use msg_socket::MsgError;
use std::fmt::{self, Display};
use usb_util::error::Error as UsbUtilError;

#[derive(Debug)]
pub enum Error {
    AddToEventLoop(UtilsError),
    StartAsyncJobQueue(UtilsError),
    QueueAsyncJob(UtilsError),
    CreateLibUsbContext(UsbUtilError),
    GetActiveConfig(UsbUtilError),
    SetActiveConfig(UsbUtilError),
    SetInterfaceAltSetting(UsbUtilError),
    ClearHalt(UsbUtilError),
    GetEndpointType,
    CreateControlSock(std::io::Error),
    SetupControlSock(std::io::Error),
    ReadControlSock(MsgError),
    WriteControlSock(MsgError),
    GetXhciTransferType(XhciTransferError),
    TransferComplete(XhciTransferError),
    ReadBuffer(BufferError),
    WriteBuffer(BufferError),
    BufferLen(BufferError),
    /// Cannot get interface descriptor for (interface, altsetting).
    GetInterfaceDescriptor((i32, u16)),
    GetEndpointDescriptor(u8),
    BadXhciTransferState,
    BadBackendProviderState,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            AddToEventLoop(e) => write!(f, "failed to add to event loop: {}", e),
            StartAsyncJobQueue(e) => write!(f, "failed to start async job queue: {}", e),
            QueueAsyncJob(e) => write!(f, "failed to queue async job: {}", e),
            CreateLibUsbContext(e) => write!(f, "failed to create libusb context: {:?}", e),
            GetActiveConfig(e) => write!(f, "failed to get active config: {:?}", e),
            SetActiveConfig(e) => write!(f, "failed to set active config: {:?}", e),
            SetInterfaceAltSetting(e) => write!(f, "failed to set interface alt setting: {:?}", e),
            ClearHalt(e) => write!(f, "failed to clear halt: {:?}", e),
            GetEndpointType => write!(f, "failed to get endpoint type"),
            CreateControlSock(e) => write!(f, "failed to create contro sock: {}", e),
            SetupControlSock(e) => write!(f, "failed to setup control sock: {}", e),
            ReadControlSock(e) => write!(f, "failed to read control sock: {}", e),
            WriteControlSock(e) => write!(f, "failed to write control sock: {}", e),
            GetXhciTransferType(e) => write!(f, "failed to get xhci transfer type: {}", e),
            TransferComplete(e) => write!(f, "xhci transfer completed: {}", e),
            ReadBuffer(e) => write!(f, "failed to read buffer: {}", e),
            WriteBuffer(e) => write!(f, "failed to write buffer: {}", e),
            BufferLen(e) => write!(f, "failed to get buffer length: {}", e),
            GetInterfaceDescriptor((i, alt_setting)) => write!(
                f,
                "failed to get interface descriptor for interface {}, alt setting {}",
                i, alt_setting
            ),
            GetEndpointDescriptor(ep_idx) => {
                write!(f, "failed to get endpoint descriptor for ep: {}", ep_idx)
            }
            BadXhciTransferState => write!(f, "xhci transfer is in a bad state"),
            BadBackendProviderState => write!(f, "backend provider is in a bad state"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
