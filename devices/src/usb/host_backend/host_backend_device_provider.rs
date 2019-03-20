// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use super::context::Context;
use super::error::*;
use super::host_device::HostDevice;
use super::hotplug::HotplugHandler;
use crate::usb::xhci::usb_hub::UsbHub;
use crate::usb::xhci::xhci_backend_device_provider::XhciBackendDeviceProvider;
use crate::utils::AsyncJobQueue;
use crate::utils::{EventHandler, EventLoop, FailHandle};
use msg_socket::{MsgReceiver, MsgSender, MsgSocket};
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use sys_util::net::UnixSeqpacket;
use sys_util::{error, WatchingEvents};
use vm_control::{
    UsbControlAttachedDevice, UsbControlCommand, UsbControlResult, UsbControlSocket,
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
                let ctx = Context::new(event_loop.clone())?;
                let hotplug_handler = HotplugHandler::new(hub.clone());
                ctx.set_hotplug_handler(hotplug_handler);
                let job_queue =
                    AsyncJobQueue::init(&event_loop).map_err(Error::StartAsyncJobQueue)?;
                let inner = Arc::new(ProviderInner::new(fail_handle, job_queue, ctx, sock, hub));
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
    ctx: Context,
    sock: MsgSocket<UsbControlResult, UsbControlCommand>,
    usb_hub: Arc<UsbHub>,
}

impl ProviderInner {
    fn new(
        fail_handle: Arc<dyn FailHandle>,
        job_queue: Arc<AsyncJobQueue>,
        ctx: Context,
        sock: MsgSocket<UsbControlResult, UsbControlCommand>,
        usb_hub: Arc<UsbHub>,
    ) -> ProviderInner {
        ProviderInner {
            fail_handle,
            job_queue,
            ctx,
            sock,
            usb_hub,
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
        match cmd {
            UsbControlCommand::AttachDevice {
                bus,
                addr,
                vid,
                pid,
                fd: usb_fd,
            } => {
                let _ = usb_fd;
                #[cfg(not(feature = "sandboxed-libusb"))]
                let device = match self.ctx.get_device(bus, addr, vid, pid) {
                    Some(d) => d,
                    None => {
                        error!(
                            "cannot get device bus: {}, addr: {}, vid: {}, pid: {}",
                            bus, addr, vid, pid
                        );
                        // The send failure will be logged, but event loop still think the event is
                        // handled.
                        let _ = self
                            .sock
                            .send(&UsbControlResult::NoSuchDevice)
                            .map_err(Error::WriteControlSock)?;
                        return Ok(());
                    }
                };
                #[cfg(feature = "sandboxed-libusb")]
                let (device, device_handle) = {
                    use vm_control::MaybeOwnedFd;

                    let usb_file = match usb_fd {
                        Some(MaybeOwnedFd::Owned(file)) => file,
                        _ => {
                            let _ = self
                                .sock
                                .send(&UsbControlResult::FailedToOpenDevice)
                                .map_err(Error::WriteControlSock);
                            return Ok(());
                        }
                    };

                    let device_fd = usb_file.as_raw_fd();

                    let device = match self.ctx.get_device(usb_file) {
                        Some(d) => d,
                        None => {
                            error!(
                                "cannot get device bus: {}, addr: {}, vid: {}, pid: {}",
                                bus, addr, vid, pid
                            );
                            // The send failure will be logged, but event loop still think the event
                            // is handled.
                            let _ = self
                                .sock
                                .send(&UsbControlResult::NoSuchDevice)
                                .map_err(Error::WriteControlSock);
                            return Ok(());
                        }
                    };

                    let device_handle = {
                        // This is safe only when fd is an fd of the current device.
                        match unsafe { device.open_fd(device_fd) } {
                            Ok(handle) => handle,
                            Err(e) => {
                                error!("fail to open device: {:?}", e);
                                // The send failure will be logged, but event loop still think
                                // the event is handled.
                                let _ = self
                                    .sock
                                    .send(&UsbControlResult::FailedToOpenDevice)
                                    .map_err(Error::WriteControlSock);
                                return Ok(());
                            }
                        }
                    };

                    // Resetting the device is used to make sure it is in a known state, but it may
                    // still function if the reset fails.
                    if let Err(e) = device_handle.reset() {
                        error!("failed to reset device after attach: {:?}", e);
                    }
                    (device, device_handle)
                };

                #[cfg(not(feature = "sandboxed-libusb"))]
                let device_handle = match device.open() {
                    Ok(handle) => handle,
                    Err(e) => {
                        error!("fail to open device: {:?}", e);
                        // The send failure will be logged, but event loop still think the event is
                        // handled.
                        let _ = self
                            .sock
                            .send(&UsbControlResult::FailedToOpenDevice)
                            .map_err(Error::WriteControlSock);
                        return Ok(());
                    }
                };
                let device = Box::new(HostDevice::new(
                    self.fail_handle.clone(),
                    self.job_queue.clone(),
                    device,
                    device_handle,
                ));
                let port = self.usb_hub.connect_backend(device);
                match port {
                    Ok(port) => {
                        // The send failure will be logged, but event loop still think the event is
                        // handled.
                        let _ = self
                            .sock
                            .send(&UsbControlResult::Ok { port })
                            .map_err(Error::WriteControlSock);
                    }
                    Err(e) => {
                        error!("failed to connect device to hub: {}", e);
                        // The send failure will be logged, but event loop still think the event is
                        // handled.
                        let _ = self
                            .sock
                            .send(&UsbControlResult::NoAvailablePort)
                            .map_err(Error::WriteControlSock);
                    }
                }
                Ok(())
            }
            UsbControlCommand::DetachDevice { port } => {
                match self.usb_hub.disconnect_port(port) {
                    Ok(()) => {
                        // The send failure will be logged, but event loop still think the event is
                        // handled.
                        let _ = self
                            .sock
                            .send(&UsbControlResult::Ok { port })
                            .map_err(Error::WriteControlSock);
                    }
                    Err(e) => {
                        error!("failed to disconnect device from port {}: {}", port, e);
                        // The send failure will be logged, but event loop still think the event is
                        // handled.
                        let _ = self
                            .sock
                            .send(&UsbControlResult::NoSuchDevice)
                            .map_err(Error::WriteControlSock);
                    }
                }
                Ok(())
            }
            UsbControlCommand::ListDevice { ports } => {
                let result = self.handle_list_devices(ports);
                // The send failure will be logged, but event loop still think the event is
                // handled.
                let _ = self.sock.send(&result).map_err(Error::WriteControlSock);
                Ok(())
            }
        }
    }
}

impl EventHandler for ProviderInner {
    fn on_event(&self) -> std::result::Result<(), ()> {
        self.on_event_helper().map_err(|e| {
            error!("host backend device provider failed: {}", e);
        })
    }
}
