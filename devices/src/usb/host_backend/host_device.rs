// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::drop;
use std::sync::Arc;
use sync::Mutex;

use super::error::*;
use super::usb_endpoint::UsbEndpoint;
use super::utils::{submit_transfer, update_transfer_state};
use crate::usb::xhci::scatter_gather_buffer::ScatterGatherBuffer;
use crate::usb::xhci::xhci_backend_device::{BackendType, UsbDeviceAddress, XhciBackendDevice};
use crate::usb::xhci::xhci_transfer::{XhciTransfer, XhciTransferState, XhciTransferType};
use crate::utils::AsyncJobQueue;
use crate::utils::FailHandle;
use std::collections::HashMap;
use sys_util::{error, warn};
use usb_util::device_handle::DeviceHandle;
use usb_util::error::Error as LibUsbError;
use usb_util::libusb_device::LibUsbDevice;
use usb_util::types::{
    ControlRequestDataPhaseTransferDirection, ControlRequestRecipient, StandardControlRequest,
    UsbRequestSetup,
};
use usb_util::usb_transfer::{
    control_transfer, ControlTransferBuffer, TransferStatus, UsbTransfer,
};

#[derive(PartialEq)]
pub enum ControlEndpointState {
    /// Control endpoint should receive setup stage next.
    SetupStage,
    /// Control endpoint should receive data stage next.
    DataStage,
    /// Control endpoint should receive status stage next.
    StatusStage,
}

/// Host device is a device connected to host.
pub struct HostDevice {
    fail_handle: Arc<dyn FailHandle>,
    // Endpoints only contains data endpoints (1 to 30). Control transfers are handled at device
    // level.
    endpoints: Vec<UsbEndpoint>,
    device: LibUsbDevice,
    device_handle: Arc<Mutex<DeviceHandle>>,
    ctl_ep_state: ControlEndpointState,
    alt_settings: HashMap<u16, u16>,
    claimed_interfaces: Vec<i32>,
    control_request_setup: UsbRequestSetup,
    executed: bool,
    job_queue: Arc<AsyncJobQueue>,
}

impl Drop for HostDevice {
    fn drop(&mut self) {
        self.release_interfaces();
    }
}

impl HostDevice {
    /// Create a new host device.
    pub fn new(
        fail_handle: Arc<dyn FailHandle>,
        job_queue: Arc<AsyncJobQueue>,
        device: LibUsbDevice,
        device_handle: DeviceHandle,
    ) -> HostDevice {
        HostDevice {
            fail_handle,
            endpoints: vec![],
            device,
            device_handle: Arc::new(Mutex::new(device_handle)),
            ctl_ep_state: ControlEndpointState::SetupStage,
            alt_settings: HashMap::new(),
            claimed_interfaces: vec![],
            control_request_setup: UsbRequestSetup::new(0, 0, 0, 0, 0),
            executed: false,
            job_queue,
        }
    }

    fn get_interface_number_of_active_config(&self) -> i32 {
        match self.device.get_active_config_descriptor() {
            Err(LibUsbError::NotFound) => {
                usb_debug!("device is in unconfigured state");
                0
            }
            Err(e) => {
                // device might be disconnected now.
                error!("unexpected error: {:?}", e);
                0
            }
            Ok(descriptor) => descriptor.bNumInterfaces as i32,
        }
    }

    fn release_interfaces(&mut self) {
        for i in &self.claimed_interfaces {
            if let Err(e) = self.device_handle.lock().release_interface(*i) {
                error!("could not release interface: {:?}", e);
            }
        }
        self.claimed_interfaces = Vec::new();
    }

    // Check for requests that should be intercepted and emulated using libusb
    // functions rather than passed directly to the device.
    // Returns true if the request has been intercepted or false if the request
    // should be passed through to the device.
    fn intercepted_control_transfer(&mut self, xhci_transfer: &XhciTransfer) -> Result<bool> {
        let direction = self.control_request_setup.get_direction();
        let recipient = self.control_request_setup.get_recipient();
        let standard_request = self.control_request_setup.get_standard_request();

        if direction != ControlRequestDataPhaseTransferDirection::HostToDevice {
            // Only host to device requests are intercepted currently.
            return Ok(false);
        }

        let status = match standard_request {
            Some(StandardControlRequest::SetAddress) => {
                if recipient != ControlRequestRecipient::Device {
                    return Ok(false);
                }
                usb_debug!("host device handling set address");
                let addr = self.control_request_setup.value as u32;
                self.set_address(addr);
                TransferStatus::Completed
            }
            Some(StandardControlRequest::SetConfiguration) => {
                if recipient != ControlRequestRecipient::Device {
                    return Ok(false);
                }
                usb_debug!("host device handling set config");
                self.set_config()?
            }
            Some(StandardControlRequest::SetInterface) => {
                if recipient != ControlRequestRecipient::Interface {
                    return Ok(false);
                }
                usb_debug!("host device handling set interface");
                self.set_interface()?
            }
            Some(StandardControlRequest::ClearFeature) => {
                if recipient != ControlRequestRecipient::Endpoint {
                    return Ok(false);
                }
                usb_debug!("host device handling clear feature");
                self.clear_feature()?
            }
            _ => {
                // Other requests will be passed through to the device.
                return Ok(false);
            }
        };

        xhci_transfer
            .on_transfer_complete(&status, 0)
            .map_err(Error::TransferComplete)?;
        Ok(true)
    }

    fn execute_control_transfer(
        &mut self,
        xhci_transfer: Arc<XhciTransfer>,
        buffer: Option<ScatterGatherBuffer>,
    ) -> Result<()> {
        let mut control_transfer = control_transfer(0);
        control_transfer
            .buffer_mut()
            .set_request_setup(&self.control_request_setup);

        if self.intercepted_control_transfer(&xhci_transfer)? {
            return Ok(());
        }

        let direction = self.control_request_setup.get_direction();
        let buffer = if direction == ControlRequestDataPhaseTransferDirection::HostToDevice {
            if let Some(buffer) = buffer {
                buffer
                    .read(&mut control_transfer.buffer_mut().data_buffer)
                    .map_err(Error::ReadBuffer)?;
            }
            // buffer is consumed here for HostToDevice transfers.
            None
        } else {
            // buffer will be used later in the callback for DeviceToHost transfers.
            buffer
        };

        let tmp_transfer = xhci_transfer.clone();
        let callback = move |t: UsbTransfer<ControlTransferBuffer>| {
            usb_debug!("setup token control transfer callback invoked");
            update_transfer_state(&xhci_transfer, &t)?;
            let state = xhci_transfer.state().lock();
            match *state {
                XhciTransferState::Cancelled => {
                    usb_debug!("transfer cancelled");
                    drop(state);
                    xhci_transfer
                        .on_transfer_complete(&TransferStatus::Cancelled, 0)
                        .map_err(Error::TransferComplete)?;
                }
                XhciTransferState::Completed => {
                    let status = t.status();
                    let actual_length = t.actual_length();
                    if direction == ControlRequestDataPhaseTransferDirection::DeviceToHost {
                        if let Some(buffer) = &buffer {
                            buffer
                                .write(&t.buffer().data_buffer)
                                .map_err(Error::WriteBuffer)?;
                        }
                    }
                    drop(state);
                    usb_debug!("transfer completed with actual length {}", actual_length);
                    xhci_transfer
                        .on_transfer_complete(&status, actual_length as u32)
                        .map_err(Error::TransferComplete)?;
                }
                _ => {
                    // update_transfer_state is already invoked before match.
                    // This transfer could only be `Cancelled` or `Completed`.
                    // Any other state means there is a bug in crosvm implementation.
                    error!("should not take this branch");
                    return Err(Error::BadXhciTransferState);
                }
            }
            Ok(())
        };

        let fail_handle = self.fail_handle.clone();
        control_transfer.set_callback(
            move |t: UsbTransfer<ControlTransferBuffer>| match callback(t) {
                Ok(_) => {}
                Err(e) => {
                    error!("control transfer callback failed {:?}", e);
                    fail_handle.fail();
                }
            },
        );
        submit_transfer(
            self.fail_handle.clone(),
            &self.job_queue,
            tmp_transfer,
            &self.device_handle,
            control_transfer,
        )
    }

    fn handle_control_transfer(&mut self, transfer: XhciTransfer) -> Result<()> {
        let xhci_transfer = Arc::new(transfer);
        match xhci_transfer
            .get_transfer_type()
            .map_err(Error::GetXhciTransferType)?
        {
            XhciTransferType::SetupStage(setup) => {
                if self.ctl_ep_state != ControlEndpointState::SetupStage {
                    error!("Control endpoint is in an inconsistant state");
                    return Ok(());
                }
                usb_debug!("setup stage setup buffer: {:?}", setup);
                self.control_request_setup = setup;
                xhci_transfer
                    .on_transfer_complete(&TransferStatus::Completed, 0)
                    .map_err(Error::TransferComplete)?;
                self.ctl_ep_state = ControlEndpointState::DataStage;
            }
            XhciTransferType::DataStage(buffer) => {
                if self.ctl_ep_state != ControlEndpointState::DataStage {
                    error!("Control endpoint is in an inconsistant state");
                    return Ok(());
                }
                // Requests with a DataStage will be executed here.
                // Requests without a DataStage will be executed in StatusStage.
                self.execute_control_transfer(xhci_transfer, Some(buffer))?;
                self.executed = true;
                self.ctl_ep_state = ControlEndpointState::StatusStage;
            }
            XhciTransferType::StatusStage => {
                if self.ctl_ep_state == ControlEndpointState::SetupStage {
                    error!("Control endpoint is in an inconsistant state");
                    return Ok(());
                }
                if self.executed {
                    // Request was already executed during DataStage.
                    // Just complete the StatusStage transfer.
                    xhci_transfer
                        .on_transfer_complete(&TransferStatus::Completed, 0)
                        .map_err(Error::TransferComplete)?;
                } else {
                    // Execute the request now since there was no DataStage.
                    self.execute_control_transfer(xhci_transfer, None)?;
                }
                self.executed = false;
                self.ctl_ep_state = ControlEndpointState::SetupStage;
            }
            _ => {
                // Non control transfer should not be handled in this function.
                error!("Non control (could be noop) transfer sent to control endpoint.");
                xhci_transfer
                    .on_transfer_complete(&TransferStatus::Completed, 0)
                    .map_err(Error::TransferComplete)?;
            }
        }
        Ok(())
    }

    fn set_config(&mut self) -> Result<TransferStatus> {
        // It's a standard, set_config, device request.
        let config = (self.control_request_setup.value & 0xff) as i32;
        usb_debug!(
            "Set config control transfer is received with config: {}",
            config
        );
        self.release_interfaces();
        let cur_config = self
            .device_handle
            .lock()
            .get_active_configuration()
            .map_err(Error::GetActiveConfig)?;
        usb_debug!("current config is: {}", cur_config);
        if config != cur_config {
            self.device_handle
                .lock()
                .set_active_configuration(config)
                .map_err(Error::SetActiveConfig)?;
        }
        self.claim_interfaces();
        self.create_endpoints()?;
        Ok(TransferStatus::Completed)
    }

    fn set_interface(&mut self) -> Result<TransferStatus> {
        usb_debug!("set interface");
        // It's a standard, set_interface, interface request.
        let interface = self.control_request_setup.index;
        let alt_setting = self.control_request_setup.value;
        self.device_handle
            .lock()
            .set_interface_alt_setting(interface as i32, alt_setting as i32)
            .map_err(Error::SetInterfaceAltSetting)?;
        self.alt_settings.insert(interface, alt_setting);
        self.create_endpoints()?;
        Ok(TransferStatus::Completed)
    }

    fn clear_feature(&mut self) -> Result<TransferStatus> {
        usb_debug!("clear feature");
        let request_setup = &self.control_request_setup;
        // It's a standard, clear_feature, endpoint request.
        const STD_FEATURE_ENDPOINT_HALT: u16 = 0;
        if request_setup.value == STD_FEATURE_ENDPOINT_HALT {
            self.device_handle
                .lock()
                .clear_halt(request_setup.index as u8)
                .map_err(Error::ClearHalt)?;
        }
        Ok(TransferStatus::Completed)
    }

    fn claim_interfaces(&mut self) {
        for i in 0..self.get_interface_number_of_active_config() {
            match self.device_handle.lock().claim_interface(i) {
                Ok(()) => {
                    usb_debug!("claimed interface {}", i);
                    self.claimed_interfaces.push(i);
                }
                Err(e) => {
                    error!("unable to claim interface {}: {:?}", i, e);
                }
            }
        }
    }

    fn create_endpoints(&mut self) -> Result<()> {
        self.endpoints = Vec::new();
        let config_descriptor = match self.device.get_active_config_descriptor() {
            Err(e) => {
                error!("device might be disconnected: {:?}", e);
                return Ok(());
            }
            Ok(descriptor) => descriptor,
        };
        for i in &self.claimed_interfaces {
            let alt_setting = self.alt_settings.get(&(*i as u16)).unwrap_or(&0);
            let interface = config_descriptor
                .get_interface_descriptor(*i as u8, *alt_setting as i32)
                .ok_or(Error::GetInterfaceDescriptor((*i, *alt_setting)))?;
            for ep_idx in 0..interface.bNumEndpoints {
                let ep_dp = interface
                    .endpoint_descriptor(ep_idx)
                    .ok_or(Error::GetEndpointDescriptor(ep_idx))?;
                let ep_num = ep_dp.get_endpoint_number();
                if ep_num == 0 {
                    usb_debug!("endpoint 0 in endpoint descriptors");
                    continue;
                }
                let direction = ep_dp.get_direction();
                let ty = ep_dp.get_endpoint_type().ok_or(Error::GetEndpointType)?;
                self.endpoints.push(UsbEndpoint::new(
                    self.fail_handle.clone(),
                    self.job_queue.clone(),
                    self.device_handle.clone(),
                    ep_num,
                    direction,
                    ty,
                ));
            }
        }
        Ok(())
    }

    fn submit_transfer_helper(&mut self, transfer: XhciTransfer) -> Result<()> {
        if transfer.get_endpoint_number() == 0 {
            return self.handle_control_transfer(transfer);
        }
        for ep in &self.endpoints {
            if ep.match_ep(transfer.get_endpoint_number(), transfer.get_transfer_dir()) {
                return ep.handle_transfer(transfer);
            }
        }
        warn!("Could not find endpoint for transfer");
        transfer
            .on_transfer_complete(&TransferStatus::Error, 0)
            .map_err(Error::TransferComplete)
    }
}

impl XhciBackendDevice for HostDevice {
    fn get_backend_type(&self) -> BackendType {
        let d = match self.device.get_device_descriptor() {
            Ok(d) => d,
            Err(_) => return BackendType::Usb2,
        };

        // See definition of bcdUsb.
        const USB3_MASK: u16 = 0x0300;
        match d.bcdUSB & USB3_MASK {
            USB3_MASK => BackendType::Usb3,
            _ => BackendType::Usb2,
        }
    }

    fn host_bus(&self) -> u8 {
        self.device.get_bus_number()
    }

    fn host_address(&self) -> u8 {
        self.device.get_address()
    }

    fn get_vid(&self) -> u16 {
        match self.device.get_device_descriptor() {
            Ok(d) => d.idVendor,
            Err(e) => {
                error!("cannot get device descriptor: {:?}", e);
                0
            }
        }
    }

    fn get_pid(&self) -> u16 {
        match self.device.get_device_descriptor() {
            Ok(d) => d.idProduct,
            Err(e) => {
                error!("cannot get device descriptor: {:?}", e);
                0
            }
        }
    }

    fn submit_transfer(&mut self, transfer: XhciTransfer) -> std::result::Result<(), ()> {
        self.submit_transfer_helper(transfer).map_err(|e| {
            error!("failed to submit transfer: {}", e);
        })
    }

    fn set_address(&mut self, _address: UsbDeviceAddress) {
        // It's a standard, set_address, device request. We do nothing here. As described in XHCI
        // spec. See set address command ring trb.
        usb_debug!(
            "Set address control transfer is received with address: {}",
            _address
        );
    }

    fn reset(&mut self) -> std::result::Result<(), ()> {
        usb_debug!("resetting host device");
        let result = self.device_handle.lock().reset();
        match result {
            Err(LibUsbError::NotFound) => {
                // libusb will return NotFound if it fails to re-claim
                // the interface after the reset.
                Ok(())
            }
            _ => result.map_err(|e| {
                error!("failed to reset device: {:?}", e);
            }),
        }
    }
}
