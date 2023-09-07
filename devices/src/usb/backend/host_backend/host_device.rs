// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::mem;
use std::mem::drop;
use std::sync::Arc;

use base::debug;
use base::error;
use base::warn;
use sync::Mutex;
use usb_util::ConfigDescriptorTree;
use usb_util::ControlRequestDataPhaseTransferDirection;
use usb_util::ControlRequestRecipient;
use usb_util::DescriptorHeader;
use usb_util::DescriptorType;
use usb_util::Device;
use usb_util::DeviceSpeed;
use usb_util::InterfaceDescriptor;
use usb_util::StandardControlRequest;
use usb_util::Transfer;
use usb_util::TransferHandle;
use usb_util::TransferStatus;
use usb_util::UsbRequestSetup;
use zerocopy::AsBytes;

use crate::usb::backend::device::BackendDevice;
use crate::usb::backend::endpoint::UsbEndpoint;
use crate::usb::backend::error::*;
use crate::usb::backend::transfer::BackendTransferHandle;
use crate::usb::backend::transfer::GenericTransferHandle;
use crate::usb::backend::utils::submit_transfer;
use crate::usb::backend::utils::update_transfer_state;
use crate::usb::xhci::scatter_gather_buffer::ScatterGatherBuffer;
use crate::usb::xhci::xhci_backend_device::BackendType;
use crate::usb::xhci::xhci_backend_device::UsbDeviceAddress;
use crate::usb::xhci::xhci_backend_device::XhciBackendDevice;
use crate::usb::xhci::xhci_transfer::XhciTransfer;
use crate::usb::xhci::xhci_transfer::XhciTransferState;
use crate::usb::xhci::xhci_transfer::XhciTransferType;
use crate::utils::AsyncJobQueue;
use crate::utils::FailHandle;

#[derive(PartialEq, Eq)]
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
    device: Arc<Mutex<Device>>,
    ctl_ep_state: ControlEndpointState,
    alt_settings: HashMap<u8, u8>,
    claimed_interfaces: Vec<u8>,
    control_request_setup: UsbRequestSetup,
    executed: bool,
    initialized: bool,
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
        device: Arc<Mutex<Device>>,
    ) -> Result<HostDevice> {
        let mut host_device = HostDevice {
            fail_handle,
            endpoints: vec![],
            device,
            ctl_ep_state: ControlEndpointState::SetupStage,
            alt_settings: HashMap::new(),
            claimed_interfaces: vec![],
            control_request_setup: UsbRequestSetup::new(0, 0, 0, 0, 0),
            executed: false,
            initialized: false,
            job_queue,
        };

        let cur_config = host_device
            .device
            .lock()
            .get_active_configuration()
            .map_err(Error::GetActiveConfig)?;
        let config_descriptor = host_device
            .device
            .lock()
            .get_config_descriptor(cur_config)
            .map_err(Error::GetActiveConfig)?;
        host_device.claim_interfaces(&config_descriptor);

        Ok(host_device)
    }

    // Check for requests that should be intercepted and emulated using libusb
    // functions rather than passed directly to the device.
    // Returns true if the request has been intercepted or false if the request
    // should be passed through to the device.
    fn intercepted_control_transfer(
        &mut self,
        xhci_transfer: &XhciTransfer,
        buffer: &Option<ScatterGatherBuffer>,
    ) -> Result<bool> {
        let direction = self.control_request_setup.get_direction();
        let recipient = self.control_request_setup.get_recipient();
        let standard_request = if let Some(req) = self.control_request_setup.get_standard_request()
        {
            req
        } else {
            // Unknown control requests will be passed through to the device.
            return Ok(false);
        };

        let (status, bytes_transferred) = match (standard_request, recipient, direction) {
            (
                StandardControlRequest::SetAddress,
                ControlRequestRecipient::Device,
                ControlRequestDataPhaseTransferDirection::HostToDevice,
            ) => {
                usb_trace!("handling set address");
                let addr = self.control_request_setup.value as u32;
                self.set_address(addr);
                (TransferStatus::Completed, 0)
            }
            (
                StandardControlRequest::SetConfiguration,
                ControlRequestRecipient::Device,
                ControlRequestDataPhaseTransferDirection::HostToDevice,
            ) => {
                usb_trace!("handling set config");
                (self.set_config()?, 0)
            }
            (
                StandardControlRequest::SetInterface,
                ControlRequestRecipient::Interface,
                ControlRequestDataPhaseTransferDirection::HostToDevice,
            ) => {
                usb_trace!("handling set interface");
                (self.set_interface()?, 0)
            }
            (
                StandardControlRequest::ClearFeature,
                ControlRequestRecipient::Endpoint,
                ControlRequestDataPhaseTransferDirection::HostToDevice,
            ) => {
                usb_trace!("handling clear feature");
                (self.clear_feature()?, 0)
            }
            (
                StandardControlRequest::GetDescriptor,
                ControlRequestRecipient::Device,
                ControlRequestDataPhaseTransferDirection::DeviceToHost,
            ) => {
                let descriptor_type = (self.control_request_setup.value >> 8) as u8;
                if descriptor_type == DescriptorType::Configuration as u8 {
                    let buffer = if let Some(buffer) = buffer {
                        buffer
                    } else {
                        return Err(Error::MissingRequiredBuffer);
                    };

                    self.get_config_descriptor_filtered(buffer)?
                } else {
                    return Ok(false);
                }
            }
            _ => {
                // Other requests will be passed through to the device.
                return Ok(false);
            }
        };

        xhci_transfer
            .on_transfer_complete(&status, bytes_transferred)
            .map_err(Error::TransferComplete)?;
        Ok(true)
    }

    fn execute_control_transfer(
        &mut self,
        xhci_transfer: Arc<XhciTransfer>,
        buffer: Option<ScatterGatherBuffer>,
    ) -> Result<()> {
        if self.intercepted_control_transfer(&xhci_transfer, &buffer)? {
            return Ok(());
        }

        // Allocate a buffer for the control transfer.
        // This buffer will hold a UsbRequestSetup struct followed by the data.
        let control_buffer_len =
            mem::size_of::<UsbRequestSetup>() + self.control_request_setup.length as usize;
        let mut control_buffer = vec![0u8; control_buffer_len];

        // Copy the control request header.
        control_buffer[..mem::size_of::<UsbRequestSetup>()]
            .copy_from_slice(self.control_request_setup.as_bytes());

        let direction = self.control_request_setup.get_direction();
        let buffer = if direction == ControlRequestDataPhaseTransferDirection::HostToDevice {
            if let Some(buffer) = buffer {
                buffer
                    .read(&mut control_buffer[mem::size_of::<UsbRequestSetup>()..])
                    .map_err(Error::ReadBuffer)?;
            }
            // buffer is consumed here for HostToDevice transfers.
            None
        } else {
            // buffer will be used later in the callback for DeviceToHost transfers.
            buffer
        };

        let mut control_transfer =
            Transfer::new_control(control_buffer).map_err(Error::CreateTransfer)?;

        let tmp_transfer = xhci_transfer.clone();
        let callback = move |t: Transfer| {
            usb_trace!("setup token control transfer callback");
            update_transfer_state(&xhci_transfer, &t)?;
            let state = xhci_transfer.state().lock();
            match *state {
                XhciTransferState::Cancelled => {
                    drop(state);
                    xhci_transfer
                        .on_transfer_complete(&TransferStatus::Cancelled, 0)
                        .map_err(Error::TransferComplete)?;
                }
                XhciTransferState::Completed => {
                    let status = t.status();
                    let actual_length = t.actual_length();
                    if direction == ControlRequestDataPhaseTransferDirection::DeviceToHost {
                        if let Some(control_request_data) =
                            t.buffer.get(mem::size_of::<UsbRequestSetup>()..)
                        {
                            if let Some(buffer) = &buffer {
                                buffer
                                    .write(control_request_data)
                                    .map_err(Error::WriteBuffer)?;
                            }
                        }
                    }
                    drop(state);
                    debug!(
                        "xhci transfer completed with actual length {}",
                        actual_length
                    );
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
        control_transfer.set_callback(move |t: Transfer| match callback(t) {
            Ok(_) => {}
            Err(e) => {
                error!("control transfer callback failed {:?}", e);
                fail_handle.fail();
            }
        });
        submit_transfer(
            self.fail_handle.clone(),
            &self.job_queue,
            tmp_transfer,
            &mut *self.device.lock(),
            control_transfer,
        )
    }

    fn handle_control_transfer(&mut self, transfer: XhciTransfer) -> Result<()> {
        let xhci_transfer = Arc::new(transfer);
        let transfer_type = xhci_transfer
            .get_transfer_type()
            .map_err(Error::GetXhciTransferType)?;
        match transfer_type {
            XhciTransferType::SetupStage => {
                let setup = xhci_transfer
                    .create_usb_request_setup()
                    .map_err(Error::CreateUsbRequestSetup)?;
                if self.ctl_ep_state != ControlEndpointState::SetupStage {
                    error!("Control endpoint is in an inconsistant state");
                    return Ok(());
                }
                usb_trace!("setup stage: setup buffer: {:?}", setup);
                self.control_request_setup = setup;
                xhci_transfer
                    .on_transfer_complete(&TransferStatus::Completed, 0)
                    .map_err(Error::TransferComplete)?;
                self.ctl_ep_state = ControlEndpointState::DataStage;
            }
            XhciTransferType::DataStage => {
                if self.ctl_ep_state != ControlEndpointState::DataStage {
                    error!("Control endpoint is in an inconsistant state");
                    return Ok(());
                }
                // Requests with a DataStage will be executed here.
                // Requests without a DataStage will be executed in StatusStage.
                let buffer = xhci_transfer.create_buffer().map_err(Error::CreateBuffer)?;
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
                error!(
                    "Non control {} transfer sent to control endpoint.",
                    transfer_type,
                );
                xhci_transfer
                    .on_transfer_complete(&TransferStatus::Completed, 0)
                    .map_err(Error::TransferComplete)?;
            }
        }
        Ok(())
    }

    fn set_config(&mut self) -> Result<TransferStatus> {
        // It's a standard, set_config, device request.
        let config = (self.control_request_setup.value & 0xff) as u8;
        usb_trace!("set_config: {}", config);
        self.release_interfaces();

        let cur_config = match self.device.lock().get_active_configuration() {
            Ok(c) => Some(c),
            Err(e) => {
                // The device may be in the default state, in which case
                // GET_CONFIGURATION may fail.  Assume the device needs to be
                // reconfigured.
                error!("Failed to get active configuration: {}", e);
                None
            }
        };

        let mut need_set_config = true;
        if !self.initialized {
            need_set_config = Some(config) != cur_config;
            self.initialized = true;
        }

        if need_set_config {
            self.device
                .lock()
                .set_active_configuration(config)
                .map_err(Error::SetActiveConfig)?;
        }

        let config_descriptor = self
            .device
            .lock()
            .get_config_descriptor(config)
            .map_err(Error::GetActiveConfig)?;
        self.claim_interfaces(&config_descriptor);
        self.create_endpoints(&config_descriptor)?;
        Ok(TransferStatus::Completed)
    }

    fn set_interface(&mut self) -> Result<TransferStatus> {
        let _trace = cros_tracing::trace_event!(USB, "host_device set_interface");
        // It's a standard, set_interface, interface request.
        let interface = self.control_request_setup.index as u8;
        let alt_setting = self.control_request_setup.value as u8;
        self.device
            .lock()
            .set_interface_alt_setting(interface, alt_setting)
            .map_err(Error::SetInterfaceAltSetting)?;
        self.alt_settings.insert(interface, alt_setting);
        let config = self
            .device
            .lock()
            .get_active_configuration()
            .map_err(Error::GetActiveConfig)?;
        let config_descriptor = self
            .device
            .lock()
            .get_config_descriptor(config)
            .map_err(Error::GetActiveConfig)?;
        self.create_endpoints(&config_descriptor)?;
        Ok(TransferStatus::Completed)
    }

    fn clear_feature(&mut self) -> Result<TransferStatus> {
        let _trace = cros_tracing::trace_event!(USB, "host_device clear_feature");
        let request_setup = &self.control_request_setup;
        // It's a standard, clear_feature, endpoint request.
        const STD_FEATURE_ENDPOINT_HALT: u16 = 0;
        if request_setup.value == STD_FEATURE_ENDPOINT_HALT {
            self.device
                .lock()
                .clear_halt(request_setup.index as u8)
                .map_err(Error::ClearHalt)?;
        }
        Ok(TransferStatus::Completed)
    }

    // Execute a Get Descriptor control request with type Configuration.
    // This function is used to return a filtered version of the host device's configuration
    // descriptor that only includes the interfaces in `self.claimed_interfaces`.
    fn get_config_descriptor_filtered(
        &mut self,
        buffer: &ScatterGatherBuffer,
    ) -> Result<(TransferStatus, u32)> {
        let descriptor_index = self.control_request_setup.value as u8;
        let _trace = cros_tracing::trace_event!(
            USB,
            "host_device get_config_descriptor_filtered",
            descriptor_index
        );

        let config_descriptor = self
            .device
            .lock()
            .get_config_descriptor_by_index(descriptor_index)
            .map_err(Error::GetConfigDescriptor)?;

        let device = self.device.lock();
        let device_descriptor = device.get_device_descriptor_tree();

        let config_start = config_descriptor.offset();
        let config_end = config_start + config_descriptor.wTotalLength as usize;
        let mut descriptor_data = device_descriptor.raw()[config_start..config_end].to_vec();

        if config_descriptor.bConfigurationValue
            == device
                .get_active_configuration()
                .map_err(Error::GetActiveConfig)?
        {
            for i in 0..config_descriptor.bNumInterfaces {
                if !self.claimed_interfaces.contains(&i) {
                    // Rewrite descriptors for unclaimed interfaces to vendor-specific class.
                    // This prevents them from being recognized by the guest drivers.
                    let alt_setting = self.alt_settings.get(&i).unwrap_or(&0);
                    let interface = config_descriptor
                        .get_interface_descriptor(i, *alt_setting)
                        .ok_or(Error::GetInterfaceDescriptor(i, *alt_setting))?;
                    let mut interface_data: InterfaceDescriptor = **interface;
                    interface_data.bInterfaceClass = 0xFF;
                    interface_data.bInterfaceSubClass = 0xFF;
                    interface_data.bInterfaceProtocol = 0xFF;

                    let interface_start =
                        interface.offset() + mem::size_of::<DescriptorHeader>() - config_start;
                    let interface_end = interface_start + mem::size_of::<InterfaceDescriptor>();
                    descriptor_data[interface_start..interface_end]
                        .copy_from_slice(interface_data.as_bytes());
                }
            }
        }

        let bytes_transferred = buffer.write(&descriptor_data).map_err(Error::WriteBuffer)?;
        Ok((TransferStatus::Completed, bytes_transferred as u32))
    }

    fn claim_interfaces(&mut self, config_descriptor: &ConfigDescriptorTree) {
        for i in 0..config_descriptor.num_interfaces() {
            match self.device.lock().claim_interface(i) {
                Ok(()) => {
                    debug!("usb: claimed interface {}", i);
                    self.claimed_interfaces.push(i);
                }
                Err(e) => {
                    error!("unable to claim interface {}: {:?}", i, e);
                }
            }
        }
    }

    fn create_endpoints(&mut self, config_descriptor: &ConfigDescriptorTree) -> Result<()> {
        self.endpoints = Vec::new();
        for i in &self.claimed_interfaces {
            let alt_setting = self.alt_settings.get(i).unwrap_or(&0);
            let interface = config_descriptor
                .get_interface_descriptor(*i, *alt_setting)
                .ok_or(Error::GetInterfaceDescriptor(*i, *alt_setting))?;
            for ep_idx in 0..interface.bNumEndpoints {
                let ep_dp = interface
                    .get_endpoint_descriptor(ep_idx)
                    .ok_or(Error::GetEndpointDescriptor(ep_idx))?;
                let ep_num = ep_dp.get_endpoint_number();
                if ep_num == 0 {
                    continue;
                }
                let direction = ep_dp.get_direction();
                let ty = ep_dp.get_endpoint_type().ok_or(Error::GetEndpointType)?;
                self.endpoints.push(UsbEndpoint::new(
                    self.fail_handle.clone(),
                    self.job_queue.clone(),
                    ep_num,
                    direction,
                    ty,
                ));
            }
        }
        Ok(())
    }

    fn release_interfaces(&mut self) {
        for i in &self.claimed_interfaces {
            if let Err(e) = self.device.lock().release_interface(*i) {
                error!("could not release interface: {:?}", e);
            }
        }
        self.claimed_interfaces = Vec::new();
    }

    fn submit_transfer_helper(&mut self, transfer: XhciTransfer) -> Result<()> {
        if transfer.get_endpoint_number() == 0 {
            return self.handle_control_transfer(transfer);
        }
        for ep in &self.endpoints {
            if ep.match_ep(transfer.get_endpoint_number(), transfer.get_transfer_dir()) {
                return ep.handle_transfer(&mut *self.device.lock(), transfer);
            }
        }
        warn!("Could not find endpoint for transfer");
        transfer
            .on_transfer_complete(&TransferStatus::Error, 0)
            .map_err(Error::TransferComplete)
    }
}

impl GenericTransferHandle for TransferHandle {
    fn cancel(&self) -> Result<()> {
        TransferHandle::cancel(self).map_err(Error::TransferHandle)
    }
}

impl BackendDevice for Device {
    fn submit_backend_transfer(&mut self, transfer: Transfer) -> Result<BackendTransferHandle> {
        match Device::submit_transfer(self, transfer).map_err(Error::CreateTransfer) {
            Ok(handle) => Ok(BackendTransferHandle::new(handle)),
            Err(e) => Err(e),
        }
    }
}

impl XhciBackendDevice for HostDevice {
    fn get_backend_type(&self) -> BackendType {
        let d = match self.device.lock().get_device_descriptor() {
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

    fn get_vid(&self) -> u16 {
        match self.device.lock().get_device_descriptor() {
            Ok(d) => d.idVendor,
            Err(e) => {
                error!("cannot get device descriptor: {:?}", e);
                0
            }
        }
    }

    fn get_pid(&self) -> u16 {
        match self.device.lock().get_device_descriptor() {
            Ok(d) => d.idProduct,
            Err(e) => {
                error!("cannot get device descriptor: {:?}", e);
                0
            }
        }
    }

    fn submit_transfer(&mut self, transfer: XhciTransfer) -> Result<()> {
        self.submit_transfer_helper(transfer)
    }

    fn set_address(&mut self, _address: UsbDeviceAddress) {
        // It's a standard, set_address, device request. We do nothing here. As described in XHCI
        // spec. See set address command ring trb.
        debug!(
            "usb set address control transfer is received with address: {}",
            _address
        );
    }

    fn reset(&mut self) -> Result<()> {
        self.device.lock().reset().map_err(Error::Reset)
    }

    fn get_speed(&self) -> Option<DeviceSpeed> {
        let speed = self.device.lock().get_speed();
        if let Ok(speed) = speed {
            speed
        } else {
            None
        }
    }

    fn alloc_streams(&self, ep: u8, num_streams: u16) -> Result<()> {
        self.device
            .lock()
            .alloc_streams(ep, num_streams)
            .map_err(Error::AllocStreams)
    }

    fn free_streams(&self, ep: u8) -> Result<()> {
        self.device
            .lock()
            .free_streams(ep)
            .map_err(Error::FreeStreams)
    }
}
