// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;
use std::sync::RwLock;

use base::error;
use base::AsRawDescriptor;
use base::RawDescriptor;
use sync::Mutex;
use usb_util::ConfigDescriptorTree;
use usb_util::DeviceDescriptorTree;
use usb_util::DeviceSpeed;
use usb_util::EndpointDirection;
use usb_util::EndpointType;
use usb_util::TransferBuffer;
use usb_util::TransferStatus;
use usb_util::UsbRequestSetup;

use crate::usb::backend::device::BackendDevice;
use crate::usb::backend::device::DeviceState;
use crate::usb::backend::endpoint::ControlEndpointState;
use crate::usb::backend::endpoint::UsbEndpoint;
use crate::usb::backend::error::Error as BackendError;
use crate::usb::backend::error::Result as BackendResult;
use crate::usb::backend::fido_backend::constants;
use crate::usb::backend::fido_backend::transfer::FidoTransfer;
use crate::usb::backend::fido_backend::transfer::FidoTransferHandle;
use crate::usb::backend::transfer::BackendTransferHandle;
use crate::usb::backend::transfer::BackendTransferType;
use crate::usb::backend::transfer::ControlTransferState;
use crate::usb::xhci::xhci_backend_device::BackendType;
use crate::usb::xhci::xhci_backend_device::UsbDeviceAddress;
use crate::usb::xhci::xhci_backend_device::XhciBackendDevice;
use crate::utils::EventLoop;

/// Host-level fido passthrough device that handles USB operations and relays them to the
/// appropriate virtual fido device.
pub struct FidoPassthroughDevice {
    /// The state of the device as seen by the backend provider.
    state: Arc<RwLock<DeviceState>>,
    /// The state of the control transfer exchange with the xhci layer.
    control_transfer_state: Arc<RwLock<ControlTransferState>>,
}

impl FidoPassthroughDevice {
    pub fn new(state: DeviceState, _event_loop: Arc<EventLoop>) -> Self {
        let control_transfer_state = ControlTransferState {
            ctl_ep_state: ControlEndpointState::SetupStage,
            control_request_setup: UsbRequestSetup::new(0, 0, 0, 0, 0),
            executed: false,
        };
        FidoPassthroughDevice {
            state: Arc::new(RwLock::new(state)),
            control_transfer_state: Arc::new(RwLock::new(control_transfer_state)),
        }
    }

    /// This function is called from the low-level event handler when the monitored `fd` is ready
    /// to transmit data from the host to the guest.
    pub fn read_hidraw_file(&mut self) {
        // TODO: Implement reading hidraw file for virtual security key
        unimplemented!();
    }
}

impl Drop for FidoPassthroughDevice {
    fn drop(&mut self) {
        // Nothing to do
    }
}

impl AsRawDescriptor for FidoPassthroughDevice {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        // TODO: Return host security key fd once FidoDevice is implemented
        unimplemented!();
    }
}

impl BackendDevice for FidoPassthroughDevice {
    fn submit_backend_transfer(
        &mut self,
        transfer: BackendTransferType,
    ) -> BackendResult<BackendTransferHandle> {
        let transfer = match transfer {
            BackendTransferType::FidoDevice(transfer) => transfer,
            _ => return Err(BackendError::MalformedBackendTransfer),
        };

        let endpoint = transfer.endpoint;
        let arc_transfer = Arc::new(Mutex::new(Some(transfer)));
        let _cancel_handle = FidoTransferHandle {
            weak_transfer: Arc::downgrade(&arc_transfer),
        };

        // TODO: Implement endpoint/transfer logic
        match endpoint {
            constants::U2FHID_CONTROL_ENDPOINT => {
                unimplemented!();
            }
            constants::U2FHID_OUT_ENDPOINT => {
                unimplemented!();
            }
            constants::U2FHID_IN_ENDPOINT => {
                unimplemented!();
            }
            _ => {
                error!("Wrong endpoint requested: {}", endpoint);
                Err(BackendError::MalformedBackendTransfer)
            }
        }
    }

    fn detach_event_handler(&self, _event_loop: &Arc<EventLoop>) -> BackendResult<()> {
        // TODO: Detach fd poll once it's implemented
        Ok(())
    }

    fn request_transfer_buffer(&mut self, size: usize) -> TransferBuffer {
        TransferBuffer::Vector(vec![0u8; size])
    }

    fn build_bulk_transfer(
        &mut self,
        _ep_addr: u8,
        _transfer_buffer: TransferBuffer,
        _stream_id: Option<u16>,
    ) -> BackendResult<BackendTransferType> {
        // Fido devices don't support bulk transfer requests
        Err(BackendError::MalformedBackendTransfer)
    }

    fn build_interrupt_transfer(
        &mut self,
        ep_addr: u8,
        transfer_buffer: TransferBuffer,
    ) -> BackendResult<BackendTransferType> {
        Ok(BackendTransferType::FidoDevice(FidoTransfer::new(
            ep_addr,
            transfer_buffer,
        )))
    }

    fn get_control_transfer_state(&mut self) -> Arc<RwLock<ControlTransferState>> {
        self.control_transfer_state.clone()
    }

    fn get_device_state(&mut self) -> Arc<RwLock<DeviceState>> {
        self.state.clone()
    }

    // TODO: Implement config descriptor code
    fn get_active_config_descriptor(&mut self) -> BackendResult<ConfigDescriptorTree> {
        unimplemented!();
    }

    fn get_config_descriptor(&mut self, _config: u8) -> BackendResult<ConfigDescriptorTree> {
        unimplemented!();
    }

    fn get_config_descriptor_by_index(
        &mut self,
        _config_index: u8,
    ) -> BackendResult<ConfigDescriptorTree> {
        unimplemented!();
    }

    fn get_device_descriptor_tree(&mut self) -> BackendResult<DeviceDescriptorTree> {
        unimplemented!();
    }

    fn get_active_configuration(&mut self) -> BackendResult<u8> {
        unimplemented!();
    }

    fn set_active_configuration(&mut self, _config: u8) -> BackendResult<()> {
        unimplemented!();
    }

    fn clear_feature(&mut self, _value: u16, _index: u16) -> BackendResult<TransferStatus> {
        // Nothing to do here, just return.
        Ok(TransferStatus::Completed)
    }

    fn create_endpoints(&mut self, _config_descriptor: &ConfigDescriptorTree) -> BackendResult<()> {
        let mut endpoints = Vec::new();
        let device_state = self.get_device_state();
        // We ignore the config descriptor because u2f-hid endpoints are already defined by the
        // protocol and are unchanging.
        // Endpoint 1 (OUT)
        endpoints.push(UsbEndpoint::new(
            device_state.read().unwrap().fail_handle.clone(),
            device_state.read().unwrap().job_queue.clone(),
            1,
            EndpointDirection::HostToDevice,
            EndpointType::Interrupt,
        ));
        // Endpoint 1 (IN)
        endpoints.push(UsbEndpoint::new(
            device_state.read().unwrap().fail_handle.clone(),
            device_state.read().unwrap().job_queue.clone(),
            1,
            EndpointDirection::DeviceToHost,
            EndpointType::Interrupt,
        ));
        device_state.write().unwrap().endpoints = endpoints;
        Ok(())
    }
}

impl XhciBackendDevice for FidoPassthroughDevice {
    fn get_backend_type(&self) -> BackendType {
        BackendType::Usb2
    }

    fn get_vid(&self) -> u16 {
        // Google vendor ID
        0x18d1
    }

    fn get_pid(&self) -> u16 {
        // Unique Product ID
        0xf1d0
    }

    fn set_address(&mut self, _address: UsbDeviceAddress) {
        // Nothing to do here
    }

    fn reset(&mut self) -> BackendResult<()> {
        // TODO: Implement logic to reset fido device state
        Ok(())
    }

    fn get_speed(&self) -> Option<DeviceSpeed> {
        Some(DeviceSpeed::Full)
    }

    fn alloc_streams(&self, _ep: u8, _num_streams: u16) -> BackendResult<()> {
        // FIDO devices don't support bulk/streams so we ignore this request.
        Ok(())
    }

    fn free_streams(&self, _ep: u8) -> BackendResult<()> {
        // FIDO devices don't support bulk/streams so we ignore this request.
        Ok(())
    }

    fn stop(&mut self) {
        // Transition the FIDO device into inactive mode and mark device as lost.
        // The FIDO device cannot error on reset so we can unwrap safely.
        self.reset().unwrap();
        // TODO: Implement logic to mark fido device state as stopped
    }
}
