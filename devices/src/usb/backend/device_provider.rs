// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::fs::File;
use std::mem;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use base::error;
use base::AsRawDescriptor;
use base::EventType;
use base::RawDescriptor;
use base::Tube;
use sync::Mutex;
use vm_control::UsbControlAttachedDevice;
use vm_control::UsbControlCommand;
use vm_control::UsbControlResult;
use vm_control::USB_CONTROL_MAX_PORTS;

use crate::usb::backend::device::BackendDevice;
use crate::usb::backend::error::*;
use crate::usb::backend::host_backend::host_backend_device_provider::attach_host_backend_device;
use crate::usb::backend::host_backend::host_device::HostDevice;
use crate::usb::xhci::usb_hub::UsbHub;
use crate::usb::xhci::xhci_backend_device_provider::XhciBackendDeviceProvider;
use crate::utils::AsyncJobQueue;
use crate::utils::EventHandler;
use crate::utils::EventLoop;
use crate::utils::FailHandle;

const SOCKET_TIMEOUT_MS: u64 = 2000;

/// Device provider is an xhci backend device provider that provides generic semantics to handle
/// various types of backend devices and connects them to the xhci layer.
pub enum DeviceProvider {
    // The provider is created but not yet started.
    Created { control_tube: Mutex<Tube> },
    // The provider is started on an event loop.
    Started { inner: Arc<ProviderInner> },
    // The provider has failed.
    Failed,
}

impl DeviceProvider {
    pub fn new() -> Result<(Tube, DeviceProvider)> {
        let (child_tube, control_tube) = Tube::pair().map_err(Error::CreateControlTube)?;
        control_tube
            .set_send_timeout(Some(Duration::from_millis(SOCKET_TIMEOUT_MS)))
            .map_err(Error::SetupControlTube)?;
        control_tube
            .set_recv_timeout(Some(Duration::from_millis(SOCKET_TIMEOUT_MS)))
            .map_err(Error::SetupControlTube)?;

        let provider = DeviceProvider::Created {
            control_tube: Mutex::new(child_tube),
        };
        Ok((control_tube, provider))
    }

    fn start_helper(
        &mut self,
        fail_handle: Arc<dyn FailHandle>,
        event_loop: Arc<EventLoop>,
        hub: Arc<UsbHub>,
    ) -> Result<()> {
        match mem::replace(self, DeviceProvider::Failed) {
            DeviceProvider::Created { control_tube } => {
                let job_queue =
                    AsyncJobQueue::init(&event_loop).map_err(Error::StartAsyncJobQueue)?;
                let inner = Arc::new(ProviderInner::new(
                    fail_handle,
                    job_queue,
                    event_loop.clone(),
                    control_tube,
                    hub,
                ));
                let handler: Arc<dyn EventHandler> = inner.clone();
                event_loop
                    .add_event(
                        &*inner.control_tube.lock(),
                        EventType::Read,
                        Arc::downgrade(&handler),
                    )
                    .map_err(Error::AddToEventLoop)?;
                *self = DeviceProvider::Started { inner };
                Ok(())
            }
            DeviceProvider::Started { .. } => {
                error!("Usb device provider has already started");
                Err(Error::BadBackendProviderState)
            }
            DeviceProvider::Failed => {
                error!("Usb device provider has already failed");
                Err(Error::BadBackendProviderState)
            }
        }
    }
}

impl XhciBackendDeviceProvider for DeviceProvider {
    fn start(
        &mut self,
        fail_handle: Arc<dyn FailHandle>,
        event_loop: Arc<EventLoop>,
        hub: Arc<UsbHub>,
    ) -> Result<()> {
        self.start_helper(fail_handle, event_loop, hub)
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        match self {
            DeviceProvider::Created { control_tube } => {
                vec![control_tube.lock().as_raw_descriptor()]
            }
            _ => {
                error!("Trying to get keepfds when DeviceProvider is not in created state");
                vec![]
            }
        }
    }
}

/// ProviderInner listens to control socket.
pub struct ProviderInner {
    fail_handle: Arc<dyn FailHandle>,
    job_queue: Arc<AsyncJobQueue>,
    event_loop: Arc<EventLoop>,
    control_tube: Mutex<Tube>,
    usb_hub: Arc<UsbHub>,

    // Map of USB hub port number to per-device context.
    devices: Mutex<HashMap<u8, DeviceContext>>,
}

struct DeviceContext {
    event_handler: Arc<dyn EventHandler>,
    device: Arc<Mutex<dyn BackendDevice>>,
}

impl ProviderInner {
    fn new(
        fail_handle: Arc<dyn FailHandle>,
        job_queue: Arc<AsyncJobQueue>,
        event_loop: Arc<EventLoop>,
        control_tube: Mutex<Tube>,
        usb_hub: Arc<UsbHub>,
    ) -> ProviderInner {
        ProviderInner {
            fail_handle,
            job_queue,
            event_loop,
            control_tube,
            usb_hub,
            devices: Mutex::new(HashMap::new()),
        }
    }

    fn handle_attach_device(&self, usb_file: File) -> UsbControlResult {
        let (device, event_handler) = match attach_host_backend_device(usb_file) {
            Ok((device, event_handler)) => (device, event_handler),
            Err(e) => {
                error!("could not construct USB device from the given file: {}", e);
                return UsbControlResult::NoSuchDevice;
            }
        };

        if let Err(e) = self.event_loop.add_event(
            &*device.lock(),
            EventType::ReadWrite,
            Arc::downgrade(&event_handler),
        ) {
            error!("failed to add USB device to event handler: {}", e);
            return UsbControlResult::FailedToOpenDevice;
        }

        let device_ctx = DeviceContext {
            event_handler,
            device: device.clone(),
        };

        // Resetting the device is used to make sure it is in a known state, but it may
        // still function if the reset fails.
        if let Err(e) = device.lock().reset() {
            error!("failed to reset device after attach: {:?}", e);
        }

        let host_device =
            match HostDevice::new(self.fail_handle.clone(), self.job_queue.clone(), device) {
                Ok(host_device) => Box::new(host_device),
                Err(e) => {
                    error!("failed to initialize HostDevice: {}", e);
                    return UsbControlResult::FailedToInitHostDevice;
                }
            };

        let port = self.usb_hub.connect_backend(host_device);
        match port {
            Ok(port) => {
                self.devices.lock().insert(port, device_ctx);
                UsbControlResult::Ok { port }
            }
            Err(e) => {
                error!("failed to connect device to hub: {}", e);
                UsbControlResult::NoAvailablePort
            }
        }
    }

    fn handle_detach_device(&self, port: u8) -> UsbControlResult {
        match self.usb_hub.disconnect_port(port) {
            Ok(()) => {
                if let Some(device_ctx) = self.devices.lock().remove(&port) {
                    let _ = device_ctx.event_handler.on_event();
                    let device = device_ctx.device.lock();

                    if let Err(e) = device.detach_event_handler(&self.event_loop) {
                        error!(
                            "failed to remove poll change handler from event loop: {}",
                            e
                        );
                    }
                }
                UsbControlResult::Ok { port }
            }
            Err(e) => {
                error!("failed to disconnect device from port {}: {}", port, e);
                UsbControlResult::NoSuchDevice
            }
        }
    }

    fn handle_list_devices(&self, ports: [u8; USB_CONTROL_MAX_PORTS]) -> UsbControlResult {
        let mut devices: [UsbControlAttachedDevice; USB_CONTROL_MAX_PORTS] = Default::default();
        for (result_index, &port_id) in ports.iter().enumerate() {
            match self.usb_hub.get_port(port_id).and_then(|p| {
                p.backend_device()
                    .as_ref()
                    .map(|d| (d.get_vid(), d.get_pid()))
            }) {
                Some((vendor_id, product_id)) => {
                    devices[result_index] = UsbControlAttachedDevice {
                        port: port_id,
                        vendor_id,
                        product_id,
                    }
                }
                None => continue,
            }
        }
        UsbControlResult::Devices(devices)
    }

    fn on_event_helper(&self) -> Result<()> {
        let tube = self.control_tube.lock();
        let cmd = tube.recv().map_err(Error::ReadControlTube)?;
        let result = match cmd {
            UsbControlCommand::AttachDevice { file } => self.handle_attach_device(file),
            UsbControlCommand::DetachDevice { port } => self.handle_detach_device(port),
            UsbControlCommand::ListDevice { ports } => self.handle_list_devices(ports),
        };
        tube.send(&result).map_err(Error::WriteControlTube)?;
        Ok(())
    }
}

impl EventHandler for ProviderInner {
    fn on_event(&self) -> anyhow::Result<()> {
        self.on_event_helper()
            .context("host backend device provider failed")
    }
}
