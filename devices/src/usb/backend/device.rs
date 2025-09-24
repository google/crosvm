// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::mem::drop;
use std::sync::Arc;
use std::sync::RwLock;

use base::debug;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::RawDescriptor;
use usb_util::ConfigDescriptorTree;
use usb_util::ControlRequestDataPhaseTransferDirection;
use usb_util::ControlRequestRecipient;
use usb_util::DescriptorType;
use usb_util::DeviceDescriptorTree;
use usb_util::DeviceSpeed;
use usb_util::StandardControlRequest;
use usb_util::Transfer;
use usb_util::TransferBuffer;
use usb_util::TransferStatus;
use usb_util::UsbRequestSetup;
use zerocopy::IntoBytes;

use crate::usb::backend::endpoint::ControlEndpointState;
use crate::usb::backend::endpoint::UsbEndpoint;
use crate::usb::backend::error::Error;
use crate::usb::backend::error::Result;
use crate::usb::backend::fido_backend::fido_passthrough::FidoPassthroughDevice;
use crate::usb::backend::fido_backend::transfer::FidoTransfer;
use crate::usb::backend::host_backend::host_device::HostDevice;
use crate::usb::backend::transfer::BackendTransfer;
use crate::usb::backend::transfer::BackendTransferHandle;
use crate::usb::backend::transfer::BackendTransferType;
use crate::usb::backend::transfer::ControlTransferState;
use crate::usb::backend::utils::multi_dispatch;
use crate::usb::backend::utils::update_transfer_state;
use crate::usb::xhci::scatter_gather_buffer::ScatterGatherBuffer;
use crate::usb::xhci::xhci_backend_device::BackendType;
use crate::usb::xhci::xhci_backend_device::UsbDeviceAddress;
use crate::usb::xhci::xhci_backend_device::XhciBackendDevice;
use crate::usb::xhci::xhci_transfer::XhciTransfer;
use crate::usb::xhci::xhci_transfer::XhciTransferState;
use crate::usb::xhci::xhci_transfer::XhciTransferType;
use crate::utils::AsyncJobQueue;
use crate::utils::EventLoop;
use crate::utils::FailHandle;

/// This enum defines different USB backend implementations that we support. Each implementation
/// needs to implement the `BackendDevice` trait as we dispatch on the enum based on the type.
/// Each concrete implementation can take care of setting up the device-specific configurations.
pub enum BackendDeviceType {
    // Real device on the host, backed by usbdevfs
    HostDevice(HostDevice),
    // Virtual security key implementation
    FidoDevice(FidoPassthroughDevice),
}

impl AsRawDescriptor for BackendDeviceType {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        multi_dispatch!(self, BackendDeviceType, HostDevice FidoDevice, as_raw_descriptor)
    }
}

impl BackendDevice for BackendDeviceType {
    fn submit_backend_transfer(
        &mut self,
        transfer: BackendTransferType,
    ) -> Result<BackendTransferHandle> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            submit_backend_transfer,
            transfer
        )
    }

    fn detach_event_handler(&self, event_loop: &Arc<EventLoop>) -> Result<()> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            detach_event_handler,
            event_loop
        )
    }

    fn request_transfer_buffer(&mut self, size: usize) -> TransferBuffer {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            request_transfer_buffer,
            size
        )
    }

    fn build_bulk_transfer(
        &mut self,
        ep_addr: u8,
        transfer_buffer: TransferBuffer,
        stream_id: Option<u16>,
    ) -> Result<BackendTransferType> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            build_bulk_transfer,
            ep_addr,
            transfer_buffer,
            stream_id
        )
    }

    fn build_interrupt_transfer(
        &mut self,
        ep_addr: u8,
        transfer_buffer: TransferBuffer,
    ) -> Result<BackendTransferType> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            build_interrupt_transfer,
            ep_addr,
            transfer_buffer
        )
    }

    fn get_control_transfer_state(&mut self) -> Arc<RwLock<ControlTransferState>> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            get_control_transfer_state
        )
    }

    fn get_device_state(&mut self) -> Arc<RwLock<DeviceState>> {
        multi_dispatch!(self, BackendDeviceType, HostDevice FidoDevice, get_device_state)
    }

    fn get_active_config_descriptor(&mut self) -> Result<ConfigDescriptorTree> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            get_active_config_descriptor
        )
    }

    fn get_config_descriptor(&mut self, config: u8) -> Result<ConfigDescriptorTree> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            get_config_descriptor,
            config
        )
    }

    fn get_config_descriptor_by_index(&mut self, config_index: u8) -> Result<ConfigDescriptorTree> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            get_config_descriptor_by_index,
            config_index
        )
    }

    fn get_device_descriptor_tree(&mut self) -> Result<DeviceDescriptorTree> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            get_device_descriptor_tree
        )
    }

    fn get_active_configuration(&mut self) -> Result<u8> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            get_active_configuration
        )
    }

    fn set_active_configuration(&mut self, config: u8) -> Result<()> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            set_active_configuration,
            config
        )
    }

    fn clear_feature(&mut self, value: u16, index: u16) -> Result<TransferStatus> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            clear_feature,
            value,
            index
        )
    }

    fn create_endpoints(&mut self, config_descriptor: &ConfigDescriptorTree) -> Result<()> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            create_endpoints,
            config_descriptor
        )
    }
}

impl XhciBackendDevice for BackendDeviceType {
    fn get_backend_type(&self) -> BackendType {
        multi_dispatch!(self, BackendDeviceType, HostDevice FidoDevice, get_backend_type)
    }

    fn get_vid(&self) -> u16 {
        multi_dispatch!(self, BackendDeviceType, HostDevice FidoDevice, get_vid)
    }

    fn get_pid(&self) -> u16 {
        multi_dispatch!(self, BackendDeviceType, HostDevice FidoDevice, get_pid)
    }

    fn set_address(&mut self, address: UsbDeviceAddress) {
        multi_dispatch!(self, BackendDeviceType, HostDevice FidoDevice, set_address, address)
    }

    fn reset(&mut self) -> Result<()> {
        multi_dispatch!(self, BackendDeviceType, HostDevice FidoDevice, reset)
    }

    fn get_speed(&self) -> Option<DeviceSpeed> {
        multi_dispatch!(self, BackendDeviceType, HostDevice FidoDevice, get_speed)
    }

    fn alloc_streams(&self, ep: u8, num_streams: u16) -> Result<()> {
        multi_dispatch!(
            self,
            BackendDeviceType,
            HostDevice FidoDevice,
            alloc_streams,
            ep,
            num_streams
        )
    }

    fn free_streams(&self, ep: u8) -> Result<()> {
        multi_dispatch!(self, BackendDeviceType, HostDevice FidoDevice, free_streams, ep)
    }

    fn stop(&mut self) {
        multi_dispatch!(self, BackendDeviceType, HostDevice FidoDevice, stop)
    }
}

pub struct DeviceState {
    pub fail_handle: Arc<dyn FailHandle>,
    // Endpoints only contains data endpoints (1 to 30). Control transfers are handled at device
    // level.
    pub endpoints: Vec<UsbEndpoint>,
    pub initialized: bool,
    pub job_queue: Arc<AsyncJobQueue>,
}

impl DeviceState {
    pub fn new(fail_handle: Arc<dyn FailHandle>, job_queue: Arc<AsyncJobQueue>) -> Self {
        DeviceState {
            fail_handle,
            endpoints: vec![],
            initialized: false,
            job_queue,
        }
    }
}

impl BackendDeviceType {
    // Check for requests that should be intercepted and handled in a generic way
    // rather than passed directly to the backend device for device-specific implementations.
    // Returns true if the request has been intercepted or false if the request
    // should be passed through.
    fn intercepted_control_transfer(
        &mut self,
        xhci_transfer: &XhciTransfer,
        buffer: &Option<ScatterGatherBuffer>,
        control_request_setup: &UsbRequestSetup,
    ) -> Result<bool> {
        let direction = control_request_setup.get_direction();
        let recipient = control_request_setup.get_recipient();
        let standard_request = if let Some(req) = control_request_setup.get_standard_request() {
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
                let addr = control_request_setup.value as u32;
                self.set_address(addr);
                (TransferStatus::Completed, 0)
            }
            (
                StandardControlRequest::SetConfiguration,
                ControlRequestRecipient::Device,
                ControlRequestDataPhaseTransferDirection::HostToDevice,
            ) => {
                usb_trace!("handling set config");
                let config = (control_request_setup.value & 0xff) as u8;
                match self.set_config(config) {
                    Ok(status) => (status, 0),
                    Err(e) => {
                        error!("set config error: {}", e);
                        (TransferStatus::Stalled, 0)
                    }
                }
            }
            (
                StandardControlRequest::SetInterface,
                ControlRequestRecipient::Interface,
                ControlRequestDataPhaseTransferDirection::HostToDevice,
            ) => {
                usb_trace!("handling set interface");
                match self {
                    BackendDeviceType::HostDevice(host_device) => match host_device.set_interface(
                        control_request_setup.index as u8,
                        control_request_setup.value as u8,
                    ) {
                        Ok(status) => (status, 0),
                        Err(e) => {
                            error!("set interface error: {}", e);
                            (TransferStatus::Stalled, 0)
                        }
                    },
                    _ => {
                        // Nothing to do for non-host devices
                        (TransferStatus::Completed, 0)
                    }
                }
            }
            (
                StandardControlRequest::ClearFeature,
                ControlRequestRecipient::Endpoint,
                ControlRequestDataPhaseTransferDirection::HostToDevice,
            ) => {
                usb_trace!("handling clear feature");
                match self.clear_feature(control_request_setup.value, control_request_setup.index) {
                    Ok(status) => (status, 0),
                    Err(e) => {
                        error!("clear feature error: {}", e);
                        (TransferStatus::Stalled, 0)
                    }
                }
            }
            (
                StandardControlRequest::GetDescriptor,
                ControlRequestRecipient::Device,
                ControlRequestDataPhaseTransferDirection::DeviceToHost,
            ) => {
                let descriptor_type = (control_request_setup.value >> 8) as u8;
                if descriptor_type == DescriptorType::Configuration as u8 {
                    let buffer = if let Some(buffer) = buffer {
                        buffer
                    } else {
                        return Err(Error::MissingRequiredBuffer);
                    };

                    match self {
                        // If it's a host device we filter the descriptor tree
                        BackendDeviceType::HostDevice(host_device) => {
                            match host_device.get_config_descriptor_filtered(
                                buffer,
                                control_request_setup.value as u8,
                            ) {
                                Ok((status, b)) => (status, b),
                                Err(e) => {
                                    error!("get descriptor error: {}", e);
                                    (TransferStatus::Stalled, 0)
                                }
                            }
                        }
                        BackendDeviceType::FidoDevice(fido_passthrough) => {
                            match fido_passthrough
                                .get_config_descriptor_by_index(control_request_setup.value as u8)
                            {
                                Ok(descriptor_tree) => {
                                    let device_descriptor =
                                        fido_passthrough.get_device_descriptor_tree()?;
                                    let offset = descriptor_tree.offset();
                                    let data = device_descriptor.raw()
                                        [offset..offset + descriptor_tree.wTotalLength as usize]
                                        .to_vec();
                                    let bytes = buffer.write(&data).map_err(Error::WriteBuffer)?;
                                    (TransferStatus::Completed, bytes as u32)
                                }
                                Err(e) => {
                                    error!("get fido descriptor error: {}", e);
                                    (TransferStatus::Stalled, 0)
                                }
                            }
                        }
                    }
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
        transfer: XhciTransfer,
        control_request_setup: &UsbRequestSetup,
        buffer: Option<ScatterGatherBuffer>,
    ) -> Result<()> {
        let xhci_transfer = Arc::new(transfer);
        if self.intercepted_control_transfer(&xhci_transfer, &buffer, control_request_setup)? {
            return Ok(());
        }

        // Allocate a buffer for the control transfer.
        // This buffer will hold a UsbRequestSetup struct followed by the data.
        let control_buffer_len =
            mem::size_of::<UsbRequestSetup>() + control_request_setup.length as usize;
        let mut control_buffer = vec![0u8; control_buffer_len];

        // Copy the control request header.
        control_buffer[..mem::size_of::<UsbRequestSetup>()]
            .copy_from_slice(control_request_setup.as_bytes());

        let direction = control_request_setup.get_direction();
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

        // TODO(morg): Refactor this code so it doesn't need to match on each implementation type
        let mut control_transfer = match self {
            BackendDeviceType::HostDevice(_) => BackendTransferType::HostDevice(
                Transfer::new_control(TransferBuffer::Vector(control_buffer))
                    .map_err(Error::CreateTransfer)?,
            ),
            BackendDeviceType::FidoDevice(_) => BackendTransferType::FidoDevice(FidoTransfer::new(
                0,
                TransferBuffer::Vector(control_buffer),
            )),
        };

        let tmp_transfer = xhci_transfer.clone();
        let callback = move |t: BackendTransferType| {
            usb_trace!("setup token control transfer callback");
            update_transfer_state(&xhci_transfer, t.status())?;
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
                        match t.buffer() {
                            TransferBuffer::Vector(v) => {
                                if let Some(control_request_data) =
                                    v.get(mem::size_of::<UsbRequestSetup>()..)
                                {
                                    if let Some(buffer) = &buffer {
                                        buffer
                                            .write(control_request_data)
                                            .map_err(Error::WriteBuffer)?;
                                    }
                                }
                            }
                            // control buffer must use a vector for buffer
                            TransferBuffer::Dma(_) => unreachable!(),
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

        let fail_handle = self.get_device_state().write().unwrap().fail_handle.clone();
        control_transfer.set_callback(move |t: BackendTransferType| match callback(t) {
            Ok(_) => {}
            Err(e) => {
                error!("control transfer callback failed {:?}", e);
                fail_handle.fail();
            }
        });
        // Create a temporary binding for the rwlock
        let device_state_binding = self.get_device_state();
        // Acquire the lock as a reader
        let device_state_lock = device_state_binding.read().unwrap();
        self.submit_transfer(
            device_state_lock.fail_handle.clone(),
            &device_state_lock.job_queue,
            tmp_transfer,
            control_transfer,
        )
    }

    fn handle_control_transfer(&mut self, transfer: XhciTransfer) -> Result<()> {
        let transfer_type = transfer
            .get_transfer_type()
            .map_err(Error::GetXhciTransferType)?;
        let control_transfer_state_binding = self.get_control_transfer_state();
        let mut control_transfer_state = control_transfer_state_binding.write().unwrap();
        match transfer_type {
            XhciTransferType::SetupStage => {
                let setup = transfer
                    .create_usb_request_setup()
                    .map_err(Error::CreateUsbRequestSetup)?;
                if control_transfer_state.ctl_ep_state != ControlEndpointState::SetupStage {
                    error!("Control endpoint is in an inconsistant state");
                    return Ok(());
                }
                usb_trace!("setup stage: setup buffer: {:?}", setup);
                control_transfer_state.control_request_setup = setup;
                transfer
                    .on_transfer_complete(&TransferStatus::Completed, 0)
                    .map_err(Error::TransferComplete)?;
                control_transfer_state.ctl_ep_state = ControlEndpointState::DataStage;
            }
            XhciTransferType::DataStage => {
                if control_transfer_state.ctl_ep_state != ControlEndpointState::DataStage {
                    error!("Control endpoint is in an inconsistant state");
                    return Ok(());
                }
                // Postpone the execution of this stage until the status stage.
                transfer.proceed().map_err(Error::Proceed)?;
                control_transfer_state.data_stage_transfer = Some(transfer);
                control_transfer_state.ctl_ep_state = ControlEndpointState::StatusStage;
            }
            XhciTransferType::StatusStage => {
                if control_transfer_state.ctl_ep_state == ControlEndpointState::SetupStage {
                    error!("Control endpoint is in an inconsistant state");
                    return Ok(());
                }

                // If there's a data stage, merge the status stage onto it, so the completion of
                // status stage can wait for the data stage and the event TRBs are submitted in the
                // correct order.
                if let Some(mut data_stage_transfer) =
                    control_transfer_state.data_stage_transfer.take()
                {
                    let buffer = data_stage_transfer
                        .create_buffer()
                        .map_err(Error::CreateBuffer)?;
                    data_stage_transfer.append_trbs(transfer);
                    self.execute_control_transfer(
                        data_stage_transfer,
                        &control_transfer_state.control_request_setup,
                        Some(buffer),
                    )?;
                } else {
                    self.execute_control_transfer(
                        transfer,
                        &control_transfer_state.control_request_setup,
                        None,
                    )?;
                };
                control_transfer_state.ctl_ep_state = ControlEndpointState::SetupStage;
            }
            _ => {
                // Non control transfer should not be handled in this function.
                error!(
                    "Non control {} transfer sent to control endpoint.",
                    transfer_type,
                );
                transfer
                    .on_transfer_complete(&TransferStatus::Completed, 0)
                    .map_err(Error::TransferComplete)?;
            }
        }
        Ok(())
    }

    fn set_config(&mut self, config: u8) -> Result<TransferStatus> {
        // It's a standard, set_config, device request.
        usb_trace!("set_config: {}", config);

        if let BackendDeviceType::HostDevice(host_device) = self {
            host_device.release_interfaces();
        }

        let cur_config = match self.get_active_configuration() {
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
        let device_state_binding = self.get_device_state();
        let mut device_state = device_state_binding.write().unwrap();
        if !device_state.initialized {
            need_set_config = Some(config) != cur_config;
            device_state.initialized = true;
        }
        // Drop the lock on the device state writer
        drop(device_state);

        if need_set_config {
            self.set_active_configuration(config)?;
        }

        let config_descriptor = self.get_config_descriptor(config)?;

        if let BackendDeviceType::HostDevice(host_device) = self {
            host_device.claim_interfaces(&config_descriptor);
        }

        self.create_endpoints(&config_descriptor)?;
        Ok(TransferStatus::Completed)
    }

    pub fn submit_transfer(
        &mut self,
        fail_handle: Arc<dyn FailHandle>,
        job_queue: &Arc<AsyncJobQueue>,
        xhci_transfer: Arc<XhciTransfer>,
        usb_transfer: BackendTransferType,
    ) -> Result<()> {
        let transfer_status = {
            // We need to hold the lock to avoid race condition.
            // While we are trying to submit the transfer, another thread might want to cancel the
            // same transfer. Holding the lock here makes sure one of them is cancelled.
            let mut state = xhci_transfer.state().lock();
            match mem::replace(&mut *state, XhciTransferState::Cancelled) {
                XhciTransferState::Created => {
                    match self.submit_backend_transfer(usb_transfer) {
                        Err(e) => {
                            error!("fail to submit transfer {:?}", e);
                            *state = XhciTransferState::Completed;
                            TransferStatus::NoDevice
                        }
                        Ok(canceller) => {
                            let cancel_callback = Box::new(move || match canceller.cancel() {
                                Ok(()) => {
                                    debug!("cancel issued to kernel");
                                }
                                Err(e) => {
                                    error!("failed to cancel XhciTransfer: {}", e);
                                }
                            });
                            *state = XhciTransferState::Submitted { cancel_callback };
                            // If it's submitted, we don't need to send on_transfer_complete now.
                            return Ok(());
                        }
                    }
                }
                XhciTransferState::Cancelled => {
                    warn!("Transfer is already cancelled");
                    TransferStatus::Cancelled
                }
                _ => {
                    // The transfer could not be in the following states:
                    // Submitted: A transfer should only be submitted once.
                    // Cancelling: Transfer is cancelling only when it's submitted and someone is
                    // trying to cancel it.
                    // Completed: A completed transfer should not be submitted again.
                    error!("xhci trasfer state is invalid");
                    return Err(Error::BadXhciTransferState);
                }
            }
        };
        // We are holding locks to of backends, we want to call on_transfer_complete
        // without any lock.
        job_queue
            .queue_job(move || {
                if let Err(e) = xhci_transfer.on_transfer_complete(&transfer_status, 0) {
                    error!("transfer complete failed: {:?}", e);
                    fail_handle.fail();
                }
            })
            .map_err(Error::QueueAsyncJob)
    }

    pub fn submit_xhci_transfer(&mut self, transfer: XhciTransfer) -> Result<()> {
        // We catch the submit_xhci_transfer call at the top BackendDeviceType level because
        // the implementation is generic for all backend types. If it's a control
        // transfer we handle it accordingly, before dispatching into each specific
        // endpoint logic.
        if transfer.get_endpoint_number() == 0 {
            return self.handle_control_transfer(transfer);
        }

        for ep in &self.get_device_state().write().unwrap().endpoints {
            if ep.match_ep(transfer.get_endpoint_number(), transfer.get_transfer_dir()) {
                return ep.handle_transfer(self, transfer);
            }
        }

        warn!("Could not find endpoint for transfer");
        transfer
            .on_transfer_complete(&TransferStatus::Error, 0)
            .map_err(Error::TransferComplete)
    }
}

/// Backend device trait implementation is the interface of a generic backend device
/// to interact with concrete implementations
pub trait BackendDevice: Sync + Send {
    /// Submits a transfer to the specific backend implementation.
    fn submit_backend_transfer(
        &mut self,
        transfer: BackendTransferType,
    ) -> Result<BackendTransferHandle>;
    /// This is called by a generic backend provider when a USB detach message is received from the
    /// vm control socket. It detaches the backend device from the backend provider event loop.
    fn detach_event_handler(&self, event_loop: &Arc<EventLoop>) -> Result<()>;
    /// Gets a buffer used for data transfer between the host and this device. The buffer returned
    /// by this function must be consumed by `submit_backend_transfer()`.
    fn request_transfer_buffer(&mut self, size: usize) -> TransferBuffer;

    /// Requests the backend to build a backend-specific bulk transfer request
    fn build_bulk_transfer(
        &mut self,
        ep_addr: u8,
        transfer_buffer: TransferBuffer,
        stream_id: Option<u16>,
    ) -> Result<BackendTransferType>;
    /// Requests the backend to build a backend-specific interrupt transfer request
    fn build_interrupt_transfer(
        &mut self,
        ep_addr: u8,
        transfer_buffer: TransferBuffer,
    ) -> Result<BackendTransferType>;

    /// Returns the `ControlTransferState` for the given backend device.
    fn get_control_transfer_state(&mut self) -> Arc<RwLock<ControlTransferState>>;
    /// Returns the `DeviceState` for the given backend device. This state contains all the
    /// backend-agnostic state for all generic USB backends.
    fn get_device_state(&mut self) -> Arc<RwLock<DeviceState>>;

    /// Gets the device active config descriptor tree.
    fn get_active_config_descriptor(&mut self) -> Result<ConfigDescriptorTree>;
    /// Gets a specific device config descriptor tree.
    fn get_config_descriptor(&mut self, config: u8) -> Result<ConfigDescriptorTree>;
    /// Gets a specific device config descriptor tree by index.
    fn get_config_descriptor_by_index(&mut self, config_index: u8) -> Result<ConfigDescriptorTree>;
    /// Gets the device descriptor tree.
    fn get_device_descriptor_tree(&mut self) -> Result<DeviceDescriptorTree>;
    /// Gets the device current active configuration.
    fn get_active_configuration(&mut self) -> Result<u8>;
    /// Sets the device active configuration.
    fn set_active_configuration(&mut self, config: u8) -> Result<()>;
    /// Handles a clear feature endpoint request for the given device.
    fn clear_feature(&mut self, value: u16, index: u16) -> Result<TransferStatus>;
    /// Creates endpoints for the device with the given config descriptor tree.
    fn create_endpoints(&mut self, config_descriptor: &ConfigDescriptorTree) -> Result<()>;
}
