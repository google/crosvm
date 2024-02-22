// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::io::Error as IOError;
use std::io::ErrorKind;
use std::io::Read;
use std::sync::Arc;
use std::sync::RwLock;

use base::debug;
use base::error;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use base::WorkerThread;
use sync::Mutex;
use usb_util::parse_usbfs_descriptors;
use usb_util::ConfigDescriptorTree;
use usb_util::ControlRequestDataPhaseTransferDirection;
use usb_util::ControlRequestRecipient;
use usb_util::ControlRequestType;
use usb_util::DescriptorType;
use usb_util::DeviceDescriptorTree;
use usb_util::DeviceSpeed;
use usb_util::EndpointDirection;
use usb_util::EndpointType;
use usb_util::Error as UsbUtilError;
use usb_util::TransferBuffer;
use usb_util::TransferStatus;
use usb_util::UsbRequestSetup;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::usb::backend::device::BackendDevice;
use crate::usb::backend::device::DeviceState;
use crate::usb::backend::endpoint::ControlEndpointState;
use crate::usb::backend::endpoint::UsbEndpoint;
use crate::usb::backend::error::Error as BackendError;
use crate::usb::backend::error::Result as BackendResult;
use crate::usb::backend::fido_backend::constants;
use crate::usb::backend::fido_backend::error::Error;
use crate::usb::backend::fido_backend::error::Result;
use crate::usb::backend::fido_backend::fido_device::FidoDevice;
use crate::usb::backend::fido_backend::poll_thread::poll_for_pending_packets;
use crate::usb::backend::fido_backend::transfer::FidoTransfer;
use crate::usb::backend::fido_backend::transfer::FidoTransferHandle;
use crate::usb::backend::transfer::BackendTransferHandle;
use crate::usb::backend::transfer::BackendTransferType;
use crate::usb::backend::transfer::ControlTransferState;
use crate::usb::backend::transfer::GenericTransferHandle;
use crate::usb::xhci::xhci_backend_device::BackendType;
use crate::usb::xhci::xhci_backend_device::UsbDeviceAddress;
use crate::usb::xhci::xhci_backend_device::XhciBackendDevice;
use crate::utils::AsyncJobQueue;
use crate::utils::EventLoop;

/// Host-level fido passthrough device that handles USB operations and relays them to the
/// appropriate virtual fido device.
pub struct FidoPassthroughDevice {
    /// The virtual FIDO device implementation.
    device: Arc<Mutex<FidoDevice>>,
    /// The state of the device as seen by the backend provider.
    state: Arc<RwLock<DeviceState>>,
    /// The state of the control transfer exchange with the xhci layer.
    control_transfer_state: Arc<RwLock<ControlTransferState>>,
    transfer_job_queue: Arc<AsyncJobQueue>,
    kill_evt: Event,
    worker_thread: Option<WorkerThread<()>>,
    pending_in_transfers:
        Arc<Mutex<VecDeque<(FidoTransferHandle, Arc<Mutex<Option<FidoTransfer>>>)>>>,
}

impl FidoPassthroughDevice {
    pub fn new(
        device: Arc<Mutex<FidoDevice>>,
        state: DeviceState,
        event_loop: Arc<EventLoop>,
    ) -> Result<Self> {
        let control_transfer_state = ControlTransferState {
            ctl_ep_state: ControlEndpointState::SetupStage,
            control_request_setup: UsbRequestSetup::new(0, 0, 0, 0, 0),
            executed: false,
        };
        let job_queue = AsyncJobQueue::init(&event_loop).map_err(Error::StartAsyncFidoQueue)?;
        Ok(FidoPassthroughDevice {
            device,
            state: Arc::new(RwLock::new(state)),
            control_transfer_state: Arc::new(RwLock::new(control_transfer_state)),
            transfer_job_queue: job_queue,
            kill_evt: Event::new().unwrap(),
            worker_thread: None,
            pending_in_transfers: Arc::new(Mutex::new(VecDeque::new())),
        })
    }

    /// This function is called from the low-level event handler when the monitored `fd` is ready
    /// to transmit data from the host to the guest.
    pub fn read_hidraw_file(&mut self) -> Result<()> {
        let mut device = self.device.lock();
        // Device has already stopped working, just return early.
        if device.is_device_lost {
            return Ok(());
        }
        if !device.is_active {
            // We should NEVER be polling on the fd and wake up if no transactions have been
            // initiated from the guest first.
            error!("Fido device received fd poll event from inactive device. This is a bug.");
            return Err(Error::InconsistentFidoDeviceState);
        }

        let mut packet = vec![0; constants::U2FHID_PACKET_SIZE * 2];

        if device.guest_key.lock().pending_in_packets.len() >= constants::U2FHID_MAX_IN_PENDING {
            return Err(Error::PendingInQueueFull);
        }

        let read_result = device.fd.lock().read(&mut packet);
        match read_result {
            Ok(n) => {
                // We read too much, the device is misbehaving
                if n != constants::U2FHID_PACKET_SIZE {
                    return Err(Error::ReadHidrawDevice(IOError::new(
                        ErrorKind::Other,
                        format!("Read too many bytes ({n}), the hidraw device is misbehaving."),
                    )));
                }
                // This is safe because we just checked the size of n is exactly U2FHID_PACKET_SIZE
                device
                    .recv_from_host(packet[..constants::U2FHID_PACKET_SIZE].try_into().unwrap())?;
            }
            Err(e) => {
                error!("U2F hidraw read error: {e:#}, resetting and detaching device",);
                device.set_active(false);
                device.is_device_lost = true;
                return Err(Error::ReadHidrawDevice(e));
            }
        }
        Ok(())
    }

    /// This function is called by a queued job to handle all communication related to USB control
    /// transfer packets between the guest and the virtual security key.
    pub fn handle_control(
        transfer: &mut FidoTransfer,
        device: &Arc<Mutex<FidoDevice>>,
    ) -> Result<()> {
        transfer.actual_length = 0;
        let request_setup = match &transfer.buffer {
            TransferBuffer::Vector(v) => {
                UsbRequestSetup::read_from_prefix(v).ok_or_else(|| Error::InvalidDataBufferSize)?
            }
            _ => {
                return Err(Error::UnsupportedTransferBufferType);
            }
        };

        let mut request_setup_out = request_setup.as_bytes().to_vec();
        let is_device_to_host =
            request_setup.get_direction() == ControlRequestDataPhaseTransferDirection::DeviceToHost;
        let descriptor_type = (request_setup.value >> 8) as u8;

        // Get Device Descriptor request
        if descriptor_type == (DescriptorType::Device as u8) && is_device_to_host {
            // If the descriptor is larger than the actual requested data, we only allocate space
            // for the request size. This is common for USB3 control setup to request only the
            // initial 8 bytes instead of the full descriptor.
            let buf_size = std::cmp::min(
                request_setup.length.into(),
                constants::U2FHID_DEVICE_DESC.len(),
            );
            let mut buffer: Vec<u8> = constants::U2FHID_DEVICE_DESC[..buf_size].to_vec();
            transfer.actual_length = buffer.len();
            request_setup_out.append(&mut buffer);
        }

        if request_setup.get_recipient() == ControlRequestRecipient::Interface {
            // It's a request for the HID report descriptor
            if is_device_to_host && descriptor_type == constants::HID_GET_REPORT_DESC {
                let mut buffer: Vec<u8> = constants::HID_REPORT_DESC.to_vec();
                transfer.actual_length = buffer.len();
                request_setup_out.append(&mut buffer);
            }
        }

        if request_setup.get_type() == ControlRequestType::Class {
            match request_setup.request {
                constants::HID_GET_IDLE => {
                    let mut buffer: Vec<u8> = vec![0u8, 1];
                    buffer[0] = device.lock().guest_key.lock().idle;
                    transfer.actual_length = 1;
                    request_setup_out.append(&mut buffer);
                }
                constants::HID_SET_IDLE => {
                    device.lock().guest_key.lock().idle = (request_setup.value >> 8) as u8;
                }
                _ => {
                    debug!(
                        "Received unsupported setup request code of Class type: {}",
                        request_setup.request
                    );
                }
            }
        }

        // Store the response
        transfer.buffer = TransferBuffer::Vector(request_setup_out);
        Ok(())
    }

    /// This function is called by a queued job to handle all USB OUT requests from the guest down
    /// to the host by writing the given `FidoTransfer` data into the hidraw file.
    pub fn handle_interrupt_out(
        transfer: &mut FidoTransfer,
        device: &Arc<Mutex<FidoDevice>>,
    ) -> Result<()> {
        let mut packet = [0u8; constants::U2FHID_PACKET_SIZE];
        let buffer = match &transfer.buffer {
            TransferBuffer::Vector(v) => v,
            _ => {
                return Err(Error::UnsupportedTransferBufferType);
            }
        };
        if buffer.len() > constants::U2FHID_PACKET_SIZE {
            error!(
                "Buffer size is bigger than u2f-hid packet size: {}",
                buffer.len()
            );
            return Err(Error::InvalidDataBufferSize);
        }
        packet.copy_from_slice(buffer);
        let written = device.lock().recv_from_guest(packet)?;
        transfer.actual_length = written;
        Ok(())
    }
}

impl Drop for FidoPassthroughDevice {
    fn drop(&mut self) {
        self.device.lock().is_device_lost = true;
        if let Err(e) = self.kill_evt.signal() {
            error!(
                "Failed to send signal to stop poll worker thread, \
                it might have already stopped. {e:#}"
            );
        }
    }
}

impl AsRawDescriptor for FidoPassthroughDevice {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.device.lock().as_raw_descriptor()
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
        let cancel_handle = FidoTransferHandle {
            weak_transfer: Arc::downgrade(&arc_transfer),
        };

        match endpoint {
            constants::U2FHID_CONTROL_ENDPOINT => {
                let arc_transfer_local = arc_transfer.clone();
                let fido_device = self.device.clone();
                self.transfer_job_queue
                    .queue_job(move || {
                        let mut lock = arc_transfer_local.lock();
                        match lock.take() {
                            Some(mut transfer) => {
                                if let Err(e) = FidoPassthroughDevice::handle_control(
                                    &mut transfer,
                                    &fido_device,
                                ) {
                                    error!(
                                        "Fido device handle control failed, cancelling transfer:\
                                        {e:#}"
                                    );
                                    drop(lock);
                                    if let Err(e) = cancel_handle.cancel() {
                                        error!(
                                            "Failed to cancel transfer, dropping request: {e:#}"
                                        );
                                        return;
                                    }
                                }
                                transfer.complete_transfer();
                            }
                            None => {
                                error!(
                                    "USB transfer disappeared in handle_control. Dropping request."
                                );
                            }
                        }
                    })
                    .map_err(BackendError::QueueAsyncJob)?;
            }
            constants::U2FHID_OUT_ENDPOINT => {
                let arc_transfer_local = arc_transfer.clone();
                let fido_device = self.device.clone();
                self.transfer_job_queue
                    .queue_job(move || {
                        let mut lock = arc_transfer_local.lock();
                        match lock.take() {
                            Some(mut transfer) => {
                                if let Err(e) = FidoPassthroughDevice::handle_interrupt_out(
                                    &mut transfer,
                                    &fido_device,
                                ) {
                                    error!(
                                        "Fido device handle interrupt out failed,\
                                        cancelling transfer: {e:#}"
                                    );
                                    drop(lock);
                                    if let Err(e) = cancel_handle.cancel() {
                                        error!(
                                            "Failed to cancel transfer, dropping request: {e:#}"
                                        );
                                        return;
                                    }
                                }
                                transfer.complete_transfer();
                            }
                            None => {
                                error!("Interrupt out transfer disappeared. Dropping request.");
                            }
                        }
                    })
                    .map_err(BackendError::QueueAsyncJob)?;
            }
            constants::U2FHID_IN_ENDPOINT => {
                let handle = FidoTransferHandle {
                    weak_transfer: Arc::downgrade(&arc_transfer.clone()),
                };
                self.pending_in_transfers
                    .lock()
                    .push_back((handle, arc_transfer.clone()));

                // Make sure to arm the timer for both transfer and host packet polling as we wait
                // for transaction requests to be fulfilled by the host or xhci transfer to time
                // out.
                if let Err(e) = self.device.lock().guest_key.lock().timer.arm() {
                    error!("Unable to start U2F guest key timer. U2F packets may be lost. {e:#}");
                }
                if let Err(e) = self.device.lock().transfer_timer.arm() {
                    error!("Unable to start transfer poll timer. Transfers might stall. {e:#}");
                }
            }
            _ => {
                error!("Wrong endpoint requested: {endpoint}");
                return Err(BackendError::MalformedBackendTransfer);
            }
        }

        // Start the worker thread if it hasn't been created yet
        if self.worker_thread.is_none()
            && (endpoint == constants::U2FHID_IN_ENDPOINT
                || endpoint == constants::U2FHID_OUT_ENDPOINT)
        {
            let device = self.device.clone();
            let pending_in_transfers = self.pending_in_transfers.clone();
            self.worker_thread = Some(WorkerThread::start("fido poll thread", move |kill_evt| {
                if let Err(e) = poll_for_pending_packets(device, pending_in_transfers, kill_evt) {
                    error!("Poll worker thread errored: {e:#}");
                }
            }));
        }

        let cancel_handle = FidoTransferHandle {
            weak_transfer: Arc::downgrade(&arc_transfer),
        };
        Ok(BackendTransferHandle::new(cancel_handle))
    }

    fn detach_event_handler(&self, _event_loop: &Arc<EventLoop>) -> BackendResult<()> {
        self.device.lock().set_active(false);
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

    fn get_active_config_descriptor(&mut self) -> BackendResult<ConfigDescriptorTree> {
        // There is only a config descriptor for u2f virtual keys.
        self.get_config_descriptor_by_index(0)
    }

    fn get_config_descriptor(&mut self, config: u8) -> BackendResult<ConfigDescriptorTree> {
        let device_descriptor = self.get_device_descriptor_tree()?;
        if let Some(config_descriptor) = device_descriptor.get_config_descriptor(config) {
            return Ok(config_descriptor.clone());
        }
        Err(BackendError::GetConfigDescriptor(
            UsbUtilError::DescriptorParse,
        ))
    }

    fn get_config_descriptor_by_index(
        &mut self,
        config_index: u8,
    ) -> BackendResult<ConfigDescriptorTree> {
        let device_descriptor = self.get_device_descriptor_tree()?;
        if let Some(config_descriptor) =
            device_descriptor.get_config_descriptor_by_index(config_index)
        {
            return Ok(config_descriptor.clone());
        }
        Err(BackendError::GetConfigDescriptor(
            UsbUtilError::DescriptorParse,
        ))
    }

    fn get_device_descriptor_tree(&mut self) -> BackendResult<DeviceDescriptorTree> {
        // Skip the first two fields of length and descriptor type as we don't need them in our
        // DeviceDescriptor structure.
        let mut descbuf: Vec<u8> = constants::U2FHID_DEVICE_DESC.to_vec();
        let mut configbuf: Vec<u8> = constants::U2FHID_CONFIG_DESC.to_vec();
        descbuf.append(&mut configbuf);
        parse_usbfs_descriptors(&descbuf).map_err(BackendError::GetDeviceDescriptor)
    }

    fn get_active_configuration(&mut self) -> BackendResult<u8> {
        let descriptor_tree = self.get_device_descriptor_tree()?;
        if descriptor_tree.bNumConfigurations != 1 {
            error!(
                "Fido devices should only have one configuration, found {}",
                descriptor_tree.bNumConfigurations
            );
        } else if let Some(config_descriptor) = descriptor_tree.get_config_descriptor_by_index(0) {
            return Ok(config_descriptor.bConfigurationValue);
        }
        Err(BackendError::GetActiveConfig(UsbUtilError::DescriptorParse))
    }

    fn set_active_configuration(&mut self, config: u8) -> BackendResult<()> {
        // Fido devices only have one configuration so we should do nothing here.
        // Return an error if the configuration number is unexpected.
        if config != 0 {
            error!(
                "Requested to set fido active configuration of {config}, but only 0 is allowed."
            );
            return Err(BackendError::BadBackendProviderState);
        }
        Ok(())
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
        let mut device_lock = self.device.lock();
        device_lock.set_active(false);
        device_lock.guest_key.lock().reset();
        device_lock.transaction_manager.lock().reset();
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
        self.device.lock().is_device_lost = true;
    }
}
