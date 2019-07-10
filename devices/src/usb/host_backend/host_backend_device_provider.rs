// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use super::error::*;
use super::host_device::HostDevice;
use crate::usb::xhci::usb_hub::UsbHub;
use crate::usb::xhci::xhci_backend_device_provider::XhciBackendDeviceProvider;
use crate::utils::AsyncJobQueue;
use crate::utils::{EventHandler, EventLoop, FailHandle};
use msg_socket::{MsgReceiver, MsgSender, MsgSocket};
use std::collections::HashMap;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use sync::Mutex;
use sys_util::net::UnixSeqpacket;
use sys_util::{error, WatchingEvents};
use usb_util::Device;
use vm_control::{
    MaybeOwnedFd, UsbControlAttachedDevice, UsbControlCommand, UsbControlResult, UsbControlSocket,
    USB_CONTROL_MAX_PORTS,
};

const SOCKET_TIMEOUT_MS: u64 = 2000;

/// Host backend device provider is a xhci backend device provider that would provide pass through
/// devices.
pub enum HostBackendDeviceProvider {
    // The provider is created but not yet started.
    Created {
        sock: MsgSocket<UsbControlResult, UsbControlCommand>,
    },
    // The provider is started on an event loop.
    Started {
        inner: Arc<ProviderInner>,
    },
    // The provider has failed.
    Failed,
}

impl HostBackendDeviceProvider {
    pub fn new() -> Result<(UsbControlSocket, HostBackendDeviceProvider)> {
        let (child_sock, control_sock) = UnixSeqpacket::pair().map_err(Error::CreateControlSock)?;
        control_sock
            .set_write_timeout(Some(Duration::from_millis(SOCKET_TIMEOUT_MS)))
            .map_err(Error::SetupControlSock)?;
        control_sock
            .set_read_timeout(Some(Duration::from_millis(SOCKET_TIMEOUT_MS)))
            .map_err(Error::SetupControlSock)?;

        let provider = HostBackendDeviceProvider::Created {
            sock: MsgSocket::new(child_sock),
        };
        Ok((MsgSocket::new(control_sock), provider))
    }

    fn start_helper(
        &mut self,
        fail_handle: Arc<dyn FailHandle>,
        event_loop: Arc<EventLoop>,
        hub: Arc<UsbHub>,
    ) -> Result<()> {
        match mem::replace(self, HostBackendDeviceProvider::Failed) {
            HostBackendDeviceProvider::Created { sock } => {
                let job_queue =
                    AsyncJobQueue::init(&event_loop).map_err(Error::StartAsyncJobQueue)?;
                let inner = Arc::new(ProviderInner::new(
                    fail_handle,
                    job_queue,
                    event_loop.clone(),
                    sock,
                    hub,
                ));
                let handler: Arc<dyn EventHandler> = inner.clone();
                event_loop
                    .add_event(
                        &inner.sock,
                        WatchingEvents::empty().set_read(),
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
    ) -> std::result::Result<(), ()> {
        self.start_helper(fail_handle, event_loop, hub)
            .map_err(|e| {
                error!("failed to start host backend device provider: {}", e);
            })
    }

    fn keep_fds(&self) -> Vec<RawFd> {
        match self {
            HostBackendDeviceProvider::Created { sock } => vec![sock.as_raw_fd()],
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
    sock: MsgSocket<UsbControlResult, UsbControlCommand>,
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
        sock: MsgSocket<UsbControlResult, UsbControlCommand>,
        usb_hub: Arc<UsbHub>,
    ) -> ProviderInner {
        ProviderInner {
            fail_handle,
            job_queue,
            event_loop,
            sock,
            usb_hub,
            devices: Mutex::new(HashMap::new()),
        }
    }

    /// Open a usbdevfs file to create a host USB device object.
    /// `fd` should be an open file descriptor for a file in `/dev/bus/usb`.
    fn handle_attach_device(&self, fd: Option<MaybeOwnedFd>) -> UsbControlResult {
        let usb_file = match fd {
            Some(MaybeOwnedFd::Owned(file)) => file,
            _ => {
                error!("missing fd in UsbControlCommand::AttachDevice message");
                return UsbControlResult::FailedToOpenDevice;
            }
        };

        let raw_fd = usb_file.as_raw_fd();
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
            &MaybeOwnedFd::Borrowed(raw_fd),
            WatchingEvents::empty().set_read().set_write(),
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

        let host_device = Box::new(HostDevice::new(
            self.fail_handle.clone(),
            self.job_queue.clone(),
            arc_mutex_device,
        ));
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
                    let fd = device.fd();

                    if let Err(e) = self
                        .event_loop
                        .remove_event_for_fd(&MaybeOwnedFd::Borrowed(fd.as_raw_fd()))
                    {
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
        let cmd = self.sock.recv().map_err(Error::ReadControlSock)?;
        let result = match cmd {
            UsbControlCommand::AttachDevice { fd, .. } => self.handle_attach_device(fd),
            UsbControlCommand::DetachDevice { port } => self.handle_detach_device(port),
            UsbControlCommand::ListDevice { ports } => self.handle_list_devices(ports),
        };
        self.sock.send(&result).map_err(Error::WriteControlSock)?;
        Ok(())
    }
}

impl EventHandler for ProviderInner {
    fn on_event(&self) -> std::result::Result<(), ()> {
        self.on_event_helper().map_err(|e| {
            error!("host backend device provider failed: {}", e);
        })
    }
}

struct UsbUtilEventHandler {
    device: Arc<Mutex<Device>>,
}

impl EventHandler for UsbUtilEventHandler {
    fn on_event(&self) -> std::result::Result<(), ()> {
        self.device.lock().poll_transfers().map_err(|_e| ())
    }
}
