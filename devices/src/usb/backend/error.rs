// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::TubeError;
use remain::sorted;
use thiserror::Error;
use usb_util::Error as UsbUtilError;

use crate::usb::xhci::scatter_gather_buffer::Error as BufferError;
use crate::usb::xhci::xhci_transfer::Error as XhciTransferError;
use crate::utils::Error as UtilsError;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to add to event loop: {0}")]
    AddToEventLoop(UtilsError),
    #[error("failed to alloc streams: {0}")]
    AllocStreams(UsbUtilError),
    #[error("backend provider is in a bad state")]
    BadBackendProviderState,
    #[error("xhci transfer is in a bad state")]
    BadXhciTransferState,
    #[error("failed to get buffer length: {0}")]
    BufferLen(BufferError),
    #[error("failed to clear halt: {0}")]
    ClearHalt(UsbUtilError),
    #[error("failed to create scatter gather buffer: {0}")]
    CreateBuffer(XhciTransferError),
    #[error("failed to create control tube: {0}")]
    CreateControlTube(TubeError),
    #[error("failed to create host backend usb device: {0}")]
    CreateHostUsbDevice(UsbUtilError),
    #[error("failed to create libusb context: {0}")]
    CreateLibUsbContext(UsbUtilError),
    #[error("failed to create transfer: {0}")]
    CreateTransfer(UsbUtilError),
    #[error("failed to create USB request setup: {0}")]
    CreateUsbRequestSetup(XhciTransferError),
    #[error("failed to free streams: {0}")]
    FreeStreams(UsbUtilError),
    #[error("failed to get active config: {0}")]
    GetActiveConfig(UsbUtilError),
    #[error("failed to get config descriptor: {0}")]
    GetConfigDescriptor(UsbUtilError),
    #[error("failed to get device descriptor: {0}")]
    GetDeviceDescriptor(UsbUtilError),
    #[error("failed to get endpoint descriptor for ep: {0}")]
    GetEndpointDescriptor(u8),
    #[error("failed to get endpoint type")]
    GetEndpointType,
    /// Cannot get interface descriptor for (interface, altsetting).
    #[error("failed to get interface descriptor for interface {0}, alt setting {1}")]
    GetInterfaceDescriptor(u8, u8),
    #[error("failed to get xhci transfer type: {0}")]
    GetXhciTransferType(XhciTransferError),
    #[error("request missing required data buffer")]
    MissingRequiredBuffer,
    #[error("failed to queue async job: {0}")]
    QueueAsyncJob(UtilsError),
    #[error("failed to read buffer: {0}")]
    ReadBuffer(BufferError),
    #[error("failed to read control tube: {0}")]
    ReadControlTube(TubeError),
    #[error("failed to remove device from event loop: {0}")]
    RemoveFromEventLoop(UtilsError),
    #[error("failed to reset: {0}")]
    Reset(UsbUtilError),
    #[error("failed to set active config: {0}")]
    SetActiveConfig(UsbUtilError),
    #[error("failed to set interface alt setting: {0}")]
    SetInterfaceAltSetting(UsbUtilError),
    #[error("failed to setup control tube: {0}")]
    SetupControlTube(TubeError),
    #[error("failed to start async job queue: {0}")]
    StartAsyncJobQueue(UtilsError),
    #[error("xhci transfer completed: {0}")]
    TransferComplete(XhciTransferError),
    #[error("failed to cancel transfer: {0}")]
    TransferHandle(UsbUtilError),
    #[error("failed to write buffer: {0}")]
    WriteBuffer(BufferError),
    #[error("failed to write control tube: {0}")]
    WriteControlTube(TubeError),
}

pub type Result<T> = std::result::Result<T, Error>;
