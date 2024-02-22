// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::mem;
use std::sync::Arc;
use std::sync::RwLock;

use base::debug;
use base::error;
use base::AsRawDescriptor;
use base::RawDescriptor;
use sync::Mutex;
use usb_util::ConfigDescriptorTree;
use usb_util::DescriptorHeader;
use usb_util::Device;
use usb_util::DeviceDescriptorTree;
use usb_util::DeviceSpeed;
use usb_util::InterfaceDescriptor;
use usb_util::Transfer;
use usb_util::TransferBuffer;
use usb_util::TransferHandle;
use usb_util::TransferStatus;
use usb_util::UsbRequestSetup;
use zerocopy::AsBytes;

use crate::usb::backend::device::BackendDevice;
use crate::usb::backend::device::DeviceState;
use crate::usb::backend::endpoint::ControlEndpointState;
use crate::usb::backend::endpoint::UsbEndpoint;
use crate::usb::backend::error::Error;
use crate::usb::backend::error::Result;
use crate::usb::backend::transfer::BackendTransfer;
use crate::usb::backend::transfer::BackendTransferHandle;
use crate::usb::backend::transfer::BackendTransferType;
use crate::usb::backend::transfer::ControlTransferState;
use crate::usb::backend::transfer::GenericTransferHandle;
use crate::usb::xhci::scatter_gather_buffer::ScatterGatherBuffer;
use crate::usb::xhci::xhci_backend_device::BackendType;
use crate::usb::xhci::xhci_backend_device::UsbDeviceAddress;
use crate::usb::xhci::xhci_backend_device::XhciBackendDevice;
use crate::utils::EventLoop;

/// Host device is a device connected to host.
pub struct HostDevice {
    pub device: Arc<Mutex<Device>>,
    alt_settings: HashMap<u8, u8>,
    claimed_interfaces: Vec<u8>,
    state: Arc<RwLock<DeviceState>>,
    control_transfer_state: Arc<RwLock<ControlTransferState>>,
}

impl HostDevice {
    /// Create a new host device.
    pub fn new(device: Arc<Mutex<Device>>, state: DeviceState) -> Result<HostDevice> {
        let control_transfer_state = ControlTransferState {
            ctl_ep_state: ControlEndpointState::SetupStage,
            control_request_setup: UsbRequestSetup::new(0, 0, 0, 0, 0),
            executed: false,
        };
        let mut host_device = HostDevice {
            device,
            alt_settings: HashMap::new(),
            claimed_interfaces: vec![],
            state: Arc::new(RwLock::new(state)),
            control_transfer_state: Arc::new(RwLock::new(control_transfer_state)),
        };

        let config_descriptor = host_device.get_active_config_descriptor()?;
        host_device.claim_interfaces(&config_descriptor);

        Ok(host_device)
    }

    // Execute a Get Descriptor control request with type Configuration.
    // This function is used to return a filtered version of the host device's configuration
    // descriptor that only includes the interfaces in `self.claimed_interfaces`.
    pub fn get_config_descriptor_filtered(
        &mut self,
        buffer: &ScatterGatherBuffer,
        descriptor_index: u8,
    ) -> Result<(TransferStatus, u32)> {
        let _trace = cros_tracing::trace_event!(
            USB,
            "host_device get_config_descriptor_filtered",
            descriptor_index
        );

        let config_descriptor = self.get_config_descriptor_by_index(descriptor_index)?;

        let device_descriptor = self.get_device_descriptor_tree();
        let config_start = config_descriptor.offset();
        let config_end = config_start + config_descriptor.wTotalLength as usize;
        let mut descriptor_data = device_descriptor.raw()[config_start..config_end].to_vec();

        if config_descriptor.bConfigurationValue == self.get_active_configuration()? {
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

    pub fn set_interface(&mut self, interface: u8, alt_setting: u8) -> Result<TransferStatus> {
        let _trace = cros_tracing::trace_event!(USB, "host_device set_interface");
        // It's a standard, set_interface, interface request.
        self.device
            .lock()
            .set_interface_alt_setting(interface, alt_setting)
            .map_err(Error::SetInterfaceAltSetting)?;
        self.alt_settings.insert(interface, alt_setting);
        let config = self.get_active_configuration()?;
        let config_descriptor = self.get_config_descriptor(config)?;
        self.create_endpoints(&config_descriptor)?;
        Ok(TransferStatus::Completed)
    }

    pub fn claim_interfaces(&mut self, config_descriptor: &ConfigDescriptorTree) {
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

    pub fn release_interfaces(&mut self) {
        let device_locked = self.device.lock();
        for i in &self.claimed_interfaces {
            if let Err(e) = device_locked.release_interface(*i) {
                error!("could not release interface: {:?}", e);
            }
        }
        self.claimed_interfaces = Vec::new();
    }
}

impl AsRawDescriptor for HostDevice {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.device.lock().as_raw_descriptor()
    }
}

impl GenericTransferHandle for TransferHandle {
    fn cancel(&self) -> Result<()> {
        TransferHandle::cancel(self).map_err(Error::TransferHandle)
    }
}

impl BackendDevice for HostDevice {
    fn submit_backend_transfer(
        &mut self,
        transfer: BackendTransferType,
    ) -> Result<BackendTransferHandle> {
        match transfer {
            BackendTransferType::HostDevice(transfer) => self
                .device
                .lock()
                .submit_transfer(transfer)
                .map_err(Error::CreateTransfer)
                .map(BackendTransferHandle::new),
        }
    }

    fn detach_event_handler(&self, event_loop: &Arc<EventLoop>) -> Result<()> {
        event_loop
            .remove_event_for_descriptor(self)
            .map_err(Error::RemoveFromEventLoop)
    }

    fn request_transfer_buffer(&mut self, size: usize) -> TransferBuffer {
        match self.device.lock().reserve_dma_buffer(size) {
            Ok(dmabuf) => TransferBuffer::Dma(dmabuf),
            Err(_) => TransferBuffer::Vector(vec![0u8; size]),
        }
    }

    fn build_bulk_transfer(
        &mut self,
        ep_addr: u8,
        transfer_buffer: TransferBuffer,
        stream_id: Option<u16>,
    ) -> Result<BackendTransferType> {
        Ok(BackendTransferType::HostDevice(
            Transfer::new_bulk(ep_addr, transfer_buffer, stream_id)
                .map_err(Error::CreateTransfer)?,
        ))
    }

    fn build_interrupt_transfer(
        &mut self,
        ep_addr: u8,
        transfer_buffer: TransferBuffer,
    ) -> Result<BackendTransferType> {
        Ok(BackendTransferType::HostDevice(
            Transfer::new_interrupt(ep_addr, transfer_buffer).map_err(Error::CreateTransfer)?,
        ))
    }

    fn get_control_transfer_state(&mut self) -> Arc<RwLock<ControlTransferState>> {
        self.control_transfer_state.clone()
    }

    fn get_device_state(&mut self) -> Arc<RwLock<DeviceState>> {
        self.state.clone()
    }

    fn get_active_config_descriptor(&mut self) -> Result<ConfigDescriptorTree> {
        let cur_config = self.get_active_configuration()?;
        self.get_config_descriptor(cur_config)
    }

    fn get_config_descriptor(&mut self, config: u8) -> Result<ConfigDescriptorTree> {
        self.device
            .lock()
            .get_config_descriptor(config)
            .map_err(Error::GetActiveConfig)
    }

    fn get_config_descriptor_by_index(&mut self, config_index: u8) -> Result<ConfigDescriptorTree> {
        self.device
            .lock()
            .get_config_descriptor_by_index(config_index)
            .map_err(Error::GetConfigDescriptor)
    }

    fn get_device_descriptor_tree(&mut self) -> DeviceDescriptorTree {
        self.device.lock().get_device_descriptor_tree().clone()
    }

    fn get_active_configuration(&mut self) -> Result<u8> {
        self.device
            .lock()
            .get_active_configuration()
            .map_err(Error::GetActiveConfig)
    }

    fn set_active_configuration(&mut self, config: u8) -> Result<()> {
        self.device
            .lock()
            .set_active_configuration(config)
            .map_err(Error::SetActiveConfig)
    }

    fn clear_feature(&mut self, value: u16, index: u16) -> Result<TransferStatus> {
        // It's a standard, clear_feature, endpoint request.
        const STD_FEATURE_ENDPOINT_HALT: u16 = 0;
        if value == STD_FEATURE_ENDPOINT_HALT {
            self.device
                .lock()
                .clear_halt(index as u8)
                .map_err(Error::ClearHalt)?;
        }
        Ok(TransferStatus::Completed)
    }

    fn create_endpoints(&mut self, config_descriptor: &ConfigDescriptorTree) -> Result<()> {
        let mut endpoints = Vec::new();
        let device_state = self.get_device_state();
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
                endpoints.push(UsbEndpoint::new(
                    device_state.read().unwrap().fail_handle.clone(),
                    device_state.read().unwrap().job_queue.clone(),
                    ep_num,
                    direction,
                    ty,
                ));
            }
        }
        device_state.write().unwrap().endpoints = endpoints;
        Ok(())
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

    fn stop(&mut self) {
        // NOOP, nothing to do
    }
}

impl BackendTransfer for Transfer {
    fn status(&self) -> TransferStatus {
        Transfer::status(self)
    }

    fn actual_length(&self) -> usize {
        Transfer::actual_length(self)
    }

    fn buffer(&self) -> &TransferBuffer {
        &self.buffer
    }

    fn set_callback<C: 'static + Fn(BackendTransferType) + Send + Sync>(&mut self, cb: C) {
        Transfer::set_callback(self, move |t| cb(BackendTransferType::HostDevice(t)));
    }
}
