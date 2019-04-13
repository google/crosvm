// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::error::*;
use crate::utils::{EventHandler, EventLoop};
use std::os::raw::c_short;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Weak};
use sys_util::{error, WatchingEvents};
use usb_util::hotplug::UsbHotplugHandler;
use usb_util::libusb_context::{LibUsbContext, LibUsbPollfdChangeHandler};
use usb_util::libusb_device::LibUsbDevice;
use vm_control::MaybeOwnedFd;

/// Context wraps libusb context with libusb event handling.
pub struct Context {
    context: LibUsbContext,
    event_loop: Arc<EventLoop>,
    event_handler: Arc<dyn EventHandler>,
}

impl Context {
    /// Create a new context.
    #[cfg(not(feature = "sandboxed-libusb"))]
    pub fn new(event_loop: Arc<EventLoop>) -> Result<Context> {
        let context = LibUsbContext::new().map_err(Error::CreateLibUsbContext)?;
        let ctx = Context {
            context: context.clone(),
            event_loop,
            event_handler: Arc::new(LibUsbEventHandler {
                context: context.clone(),
            }),
        };
        ctx.init_event_handler()?;
        Ok(ctx)
    }

    #[cfg(feature = "sandboxed-libusb")]
    pub fn new(event_loop: Arc<EventLoop>) -> Result<Context> {
        let context = LibUsbContext::new_jailed().map_err(Error::CreateLibUsbContext)?;
        let ctx = Context {
            context: context.clone(),
            event_loop,
            event_handler: Arc::new(LibUsbEventHandler {
                context: context.clone(),
            }),
        };
        ctx.init_event_handler()?;
        Ok(ctx)
    }

    pub fn set_hotplug_handler<H: UsbHotplugHandler + Sized>(&self, handler: H) {
        if let Err(e) = self.context.set_hotplug_cb(handler) {
            error!("cannot set hotplug handler: {:?}", e);
        }
    }

    fn init_event_handler(&self) -> Result<()> {
        for pollfd in self.context.get_pollfd_iter() {
            usb_debug!("event loop add event {} events handler", pollfd.fd);
            self.event_loop
                .add_event(
                    &MaybeOwnedFd::Borrowed(pollfd.fd),
                    WatchingEvents::new(pollfd.events as u32),
                    Arc::downgrade(&self.event_handler),
                )
                .map_err(Error::AddToEventLoop)?;
        }

        self.context
            .set_pollfd_notifiers(Box::new(PollfdChangeHandler {
                event_loop: self.event_loop.clone(),
                event_handler: Arc::downgrade(&self.event_handler),
            }));
        Ok(())
    }

    /// Get libusb device with matching bus, addr, vid and pid.
    #[cfg(not(feature = "sandboxed-libusb"))]
    pub fn get_device(&self, bus: u8, addr: u8, vid: u16, pid: u16) -> Option<LibUsbDevice> {
        let device_iter = match self.context.get_device_iter() {
            Ok(iter) => iter,
            Err(e) => {
                error!("could not get libusb device iterator: {:?}", e);
                return None;
            }
        };
        for device in device_iter {
            if device.get_bus_number() == bus && device.get_address() == addr {
                if let Ok(descriptor) = device.get_device_descriptor() {
                    if descriptor.idProduct == pid && descriptor.idVendor == vid {
                        return Some(device);
                    }
                }
            }
        }
        error!("device not found bus {}, addr {}", bus, addr);
        None
    }

    #[cfg(feature = "sandboxed-libusb")]
    pub fn get_device(&self, fd: std::fs::File) -> Option<LibUsbDevice> {
        match self.context.get_device_from_fd(fd) {
            Ok(dev) => Some(dev),
            Err(e) => {
                error!("could not build device from fd: {:?}", e);
                None
            }
        }
    }
}

struct LibUsbEventHandler {
    context: LibUsbContext,
}

impl EventHandler for LibUsbEventHandler {
    fn on_event(&self) -> std::result::Result<(), ()> {
        self.context.handle_events_nonblock();
        Ok(())
    }
}

struct PollfdChangeHandler {
    event_loop: Arc<EventLoop>,
    event_handler: Weak<dyn EventHandler>,
}

impl LibUsbPollfdChangeHandler for PollfdChangeHandler {
    fn add_poll_fd(&self, fd: RawFd, events: c_short) {
        if let Err(e) = self.event_loop.add_event(
            &MaybeOwnedFd::Borrowed(fd),
            WatchingEvents::new(events as u32),
            self.event_handler.clone(),
        ) {
            error!("cannot add event to event loop: {}", e);
        }
    }

    fn remove_poll_fd(&self, fd: RawFd) {
        if let Some(h) = self.event_handler.upgrade() {
            if let Err(e) = h.on_event() {
                error!("cannot handle event: {:?}", e);
            }
        }
        if let Err(e) = self
            .event_loop
            .remove_event_for_fd(&MaybeOwnedFd::Borrowed(fd))
        {
            error!(
                "failed to remove poll change handler from event loop: {}",
                e
            );
        }
    }
}
