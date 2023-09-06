// Copyright 2019 The ChromiumOS Authors
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
use usb_util::Device;
use vm_control::UsbControlAttachedDevice;
use vm_control::UsbControlCommand;
use vm_control::UsbControlResult;
use vm_control::USB_CONTROL_MAX_PORTS;

use super::host_device::HostDevice;
use crate::usb::backend::error::*;
use crate::usb::xhci::usb_hub::UsbHub;
use crate::usb::xhci::xhci_backend_device_provider::XhciBackendDeviceProvider;
use crate::utils::AsyncJobQueue;
use crate::utils::EventHandler;
use crate::utils::EventLoop;
use crate::utils::FailHandle;

const SOCKET_TIMEOUT_MS: u64 = 2000;

/// Host backend device provider is a xhci backend device provider that would provide pass through
/// devices.
pub enum HostBackendDeviceProvider {
    // The provider is created but not yet started.
    Created { control_tube: Mutex<Tube> },
    // The provider is started on an event loop.
    Started { inner: Arc<ProviderInner> },
    // The provider has failed.
    Failed,
}

impl HostBackendDeviceProvider {
    pub fn new() -> Result<(Tube, HostBackendDeviceProvider)> {
        let (child_tube, control_tube) = Tube::pair().map_err(Error::CreateControlTube)?;
        control_tube
            .set_send_timeout(Some(Duration::from_millis(SOCKET_TIMEOUT_MS)))
            .map_err(Error::SetupControlTube)?;
        control_tube
            .set_recv_timeout(Some(Duration::from_millis(SOCKET_TIMEOUT_MS)))
            .map_err(Error::SetupControlTube)?;

        let provider = HostBackendDeviceProvider::Created {
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
        match mem::replace(self, HostBackendDeviceProvider::Failed) {
            HostBackendDeviceProvider::Created { control_tube } => {
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
                *self = HostBackendDeviceProvider::Started { inner };
                Ok(())
            }
            HostBackendDeviceProvider::Started { .. } => {
                error!("Host backend provider has already started");
                Err(Error::BadBackendProviderState)
            }
            HostBackendDeviceProvider::Failed => {
                error!("Host backend provider has already failed");
                Err(Error::BadBackendProviderState)
            }
        }
    }
}

impl XhciBackendDeviceProvider for HostBackendDeviceProvider {
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
            HostBackendDeviceProvider::Created { control_tube } => {
                vec![control_tube.lock().as_raw_descriptor()]
            }
            _ => {
                error!(
                    "Trying to get keepfds when HostBackendDeviceProvider is not in created state"
                );
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
    devices: Mutex<HashMap<u8, HostDeviceContext>>,
}

struct HostDeviceContext {
    event_handler: Arc<dyn EventHandler>,
    device: Arc<Mutex<Device>>,
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

    /// Open a usbdevfs file to create a host USB device object.
    /// `fd` should be an open file descriptor for a file in `/dev/bus/usb`.
    fn handle_attach_device(&self, usb_file: File) -> UsbControlResult {
        let device = match Device::new(usb_file) {
            Ok(d) => d,
            Err(e) => {
                error!("could not construct USB device from fd: {}", e);
                return UsbControlResult::NoSuchDevice;
            }
        };

        let arc_mutex_device = Arc::new(Mutex::new(device));

        let event_handler: Arc<dyn EventHandler> = Arc::new(UsbUtilEventHandler {
            device: arc_mutex_device.clone(),
        });

        if let Err(e) = self.event_loop.add_event(
            &*arc_mutex_device.lock(),
            EventType::ReadWrite,
            Arc::downgrade(&event_handler),
        ) {
            error!("failed to add USB device fd to event handler: {}", e);
            return UsbControlResult::FailedToOpenDevice;
        }

        let device_ctx = HostDeviceContext {
            event_handler,
            device: arc_mutex_device.clone(),
        };

        // Resetting the device is used to make sure it is in a known state, but it may
        // still function if the reset fails.
        if let Err(e) = arc_mutex_device.lock().reset() {
            error!("failed to reset device after attach: {:?}", e);
        }

        let host_device = match HostDevice::new(
            self.fail_handle.clone(),
            self.job_queue.clone(),
            arc_mutex_device,
        ) {
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
                    let descriptor = device.fd();

                    if let Err(e) = self.event_loop.remove_event_for_descriptor(&*descriptor) {
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
                p.get_backend_device()
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

struct UsbUtilEventHandler {
    device: Arc<Mutex<Device>>,
}

impl EventHandler for UsbUtilEventHandler {
    fn on_event(&self) -> anyhow::Result<()> {
        self.device
            .lock()
            .poll_transfers()
            .context("UsbUtilEventHandler poll_transfers failed")
    }
}
