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
use crate::utils::AsyncJobQueue;
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
    pub job_queue: Arc<AsyncJobQueue>,
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

        if is_detached && self.device.lock().can_finalize() {
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
        job_queue: Arc<AsyncJobQueue>,
    ) -> Arc<Self> {
        Arc::new(Self {
            device,
            event_loop,
            job_queue,
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
        let self_ref = self.self_ref.lock();
        if let Some(self_arc) = &*self_ref {
            let self_clone = self_arc.clone();
            if let Err(e) = self.job_queue.queue_job(move || {
                if self_clone.device.lock().can_finalize() {
                    if let Err(e) = self_clone.finalize_detach() {
                        error!("failed to finalize USB detachment: {}", e);
                    }
                }
            }) {
                error!("failed to queue USB detach job: {}", e);
            }
        }
    }

    /// Clean up the resources and remove itself from the event loop.
    pub(crate) fn finalize_detach(&self) -> Result<()> {
        if self.self_ref.lock().take().is_none() {
            return Ok(());
        }

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
