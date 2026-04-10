// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;
use std::sync::Weak;

use anyhow::Context;
use base::error;
use base::EventType;
use sync::Mutex;
use usb_util::TransferStatus;

use crate::usb::backend::device::BackendDevice;
use crate::usb::backend::device::BackendDeviceType;
use crate::usb::backend::error::Error;
use crate::usb::backend::error::Result;
use crate::usb::xhci::usb_hub::UsbPort;
use crate::usb::xhci::xhci_transfer::XhciTransferState;
use crate::utils::EventHandler;
use crate::utils::EventLoop;

#[macro_export]
/// Allows dispatching a function call to all its enum value implementations.
/// See `BackendDeviceType` in usb/backend/device.rs for an example usage of it.
///
/// # Arguments
///
/// * `self` - Replacement for the local `self` reference in the function call.
/// * `enum` - Enum name that the macro is matching on.
/// * `types` - Space-separated list of value types of the given enum.
/// * `func` - Function name that will be called by each match arm.
/// * `param` - Optional parameters needed for the given function call.
macro_rules! multi_dispatch {
    ($self:ident, $enum:ident, $($types:ident )+, $func:ident) => {
        match $self {
            $(
                $enum::$types(device) => device.$func(),
            )+
        }
    };
    ($self:ident, $enum:ident, $($types:ident )+, $func:ident, $param:expr) => {
        match $self {
            $(
                $enum::$types(device) => device.$func($param),
            )+
        }
    };
    ($self:ident, $enum:ident, $($types:ident )+, $func:ident, $param1:expr, $param2: expr) => {
        match $self {
            $(
                $enum::$types(device) => device.$func($param1, $param2),
            )+
        }
    };
    ($self:ident, $enum:ident, $($types:ident )+, $func:ident, $param1:expr, $param2: expr, $param3: expr) => {
        match $self {
            $(
                $enum::$types(device) => device.$func($param1, $param2, $param3),
            )+
        }
    };
}

pub(crate) use multi_dispatch;

pub(crate) struct UsbUtilEventHandler {
    pub device: Arc<Mutex<BackendDeviceType>>,
    pub event_loop: Arc<EventLoop>,
    pub port: Mutex<Weak<UsbPort>>,
    pub self_ref: Mutex<Option<Arc<UsbUtilEventHandler>>>,
}

impl EventHandler for UsbUtilEventHandler {
    fn on_event(&self) -> anyhow::Result<()> {
        let (backend_result, is_lost) = {
            let mut device_locked = self.device.lock();
            let res = match &mut *device_locked {
                BackendDeviceType::HostDevice(host_device) => host_device
                    .device
                    .lock()
                    .poll_transfers()
                    .context("UsbUtilEventHandler poll_transfers failed"),
                BackendDeviceType::FidoDevice(fido_device) => fido_device
                    .read_hidraw_file()
                    .context("FidoDeviceEventHandler failed to read hidraw device"),
            };
            (res, device_locked.is_lost())
        };

        let is_detached = self.port.lock().upgrade().is_none_or(|port| {
            if is_lost || backend_result.is_err() {
                let _ = port.detach();
            }
            // It might already be manually detached.
            !port.is_attached()
        });

        if is_detached {
            self.signal_detach();
        }

        if let Err(e) = backend_result {
            error!("usb: backend event failure: {:#}", e);
        }
        Ok(())
    }
}

impl UsbUtilEventHandler {
    pub(crate) fn new(
        device: Arc<Mutex<BackendDeviceType>>,
        event_loop: Arc<EventLoop>,
    ) -> Arc<Self> {
        Arc::new(Self {
            device,
            event_loop,
            port: Mutex::new(Weak::new()),
            self_ref: Mutex::new(None),
        })
    }

    /// Register this handler with the event loop. After a successful return, call
    /// finalize_detach() for cleanup.
    pub fn activate(self: &Arc<Self>, event_type: EventType, port: Weak<UsbPort>) -> Result<()> {
        *self.port.lock() = port;

        self.event_loop
            .add_event(
                &*self.device.lock(),
                event_type,
                Arc::downgrade(self) as Weak<dyn EventHandler>,
            )
            .map_err(Error::AddToEventLoop)?;

        *self.self_ref.lock() = Some(self.clone());
        Ok(())
    }

    /// Signal this handler to perform the host resource cleanup.
    pub fn signal_detach(&self) {
        // self_ref acts as our atomic flag. Only the first caller (i.e., manual detach vs unplug)
        // will succeed.
        let self_arc = match self.self_ref.lock().take() {
            Some(arc) => arc,
            None => return, // Detach process is already running.
        };

        std::thread::spawn(move || {
            let mut retries = 0;
            loop {
                let can_finalize = {
                    let mut device = self_arc.device.lock();
                    if let BackendDeviceType::HostDevice(host_device) = &mut *device {
                        let _ = host_device.device.lock().poll_transfers();
                    }
                    device.can_finalize()
                };

                if can_finalize {
                    break;
                }

                // When a device is unplugged from the host, the in-flight URBs will be aborted and
                // queued back to the completion list. However, there's a small window where the
                // completion list is empty because the actual hardware has not responded to the
                // host kernel. Since there's no way for the user space to wait for the host kernel
                // to queue them back, we keep polling here.
                std::thread::sleep(std::time::Duration::from_millis(100));
                retries += 1;

                // Use a generous 30-second timeout. The guest's StopEndpointCommand typically
                // times out in 5 seconds. We want to wait much longer to guarantee the host kernel
                // has time to finish aborting the URBs. In theory, we shouldn't hit this timeout,
                // because the host driver would also time out around the same time and reset the
                // HC, making all the in-flight URBs reap-able.
                if retries > 300 {
                    error!("Timeout waiting for host device to release all URBs.");
                    break;
                }
            }

            if let Err(e) = self_arc.finalize_detach() {
                error!("failed to finalize USB detachment: {}", e);
            }
        });
    }

    /// Clean up the resources and remove itself from the event loop.
    pub(crate) fn finalize_detach(&self) -> Result<()> {
        let mut device = self.device.lock();
        if let BackendDeviceType::HostDevice(host_device) = &mut *device {
            host_device.device.lock().drop_dma_buffer();
        }

        // Ignore the error, because the event handler might already be detached in the event loop.
        let _ = device.detach_event_handler(&self.event_loop);
        Ok(())
    }
}

/// Helper function to update xhci_transfer state.
pub fn update_transfer_state(state: &mut XhciTransferState, status: TransferStatus) -> Result<()> {
    if status == TransferStatus::Cancelled {
        *state = XhciTransferState::Cancelled;
        return Ok(());
    }

    match *state {
        XhciTransferState::Cancelling => {
            *state = XhciTransferState::Cancelled;
        }
        XhciTransferState::Submitted { .. } => {
            *state = XhciTransferState::Completed;
        }
        _ => {
            error!("xhci trasfer state is invalid");
            *state = XhciTransferState::Completed;
            return Err(Error::BadXhciTransferState);
        }
    }
    Ok(())
}
