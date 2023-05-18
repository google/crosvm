// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::marker::PhantomPinned;
use std::os::raw::c_void;
use std::pin::Pin;
use std::ptr::null_mut;
use std::rc::Rc;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::debug;
use base::error;
use base::info;
use linux_input_sys::virtio_input_event;
#[cfg(feature = "kiwi")]
use vm_control::ServiceSendToGpu;
use winapi::shared::minwindef::LRESULT;
use winapi::shared::windef::HWND;
use winapi::um::winuser::*;

use super::window::MessagePacket;
use super::window::Window;
use super::window_message_processor::*;
use super::ObjectId;
use crate::EventDevice;
use crate::EventDeviceKind;

/// The pointer to dispatcher will be stored with HWND using `SetPropW()` with the following name.
pub(crate) const DISPATCHER_PROPERTY_NAME: &str = "PROP_WND_MSG_DISPATCHER";

/// This class is used to dispatch display events to the guest device.
#[derive(Clone)]
pub struct DisplayEventDispatcher {
    event_devices: Rc<RefCell<BTreeMap<ObjectId, EventDevice>>>,
}

impl DisplayEventDispatcher {
    pub fn new() -> Self {
        Self {
            event_devices: Default::default(),
        }
    }

    pub fn dispatch(&self, events: &[virtio_input_event], device_type: EventDeviceKind) {
        for event_device in self
            .event_devices
            .borrow_mut()
            .values_mut()
            .filter(|event_device| event_device.kind() == device_type)
        {
            if let Err(e) = event_device.send_report(events.iter().cloned()) {
                error!("Failed to send events to event device: {}", e);
            }
        }
    }

    fn import_event_device(&mut self, event_device_id: ObjectId, event_device: EventDevice) {
        info!("Importing {:?} (ID: {:?})", event_device, event_device_id);
        self.event_devices
            .borrow_mut()
            .insert(event_device_id, event_device);
    }
}

impl Default for DisplayEventDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// This class is used for dispatching thread and window messages. It should be created before any
/// other threads start to post messages to the WndProc thread, and before the WndProc thread enters
/// the window message loop. Once all windows tracked by it are destroyed, it will signal exiting
/// the message loop and then it can be dropped.
pub(crate) struct WindowMessageDispatcher<T: HandleWindowMessage> {
    message_processor: Option<WindowMessageProcessor<T>>,
    display_event_dispatcher: DisplayEventDispatcher,
    // The dispatcher is pinned so that its address in the memory won't change, and it is always
    // safe to use the pointer to it stored in the window.
    _pinned_marker: PhantomPinned,
}

impl<T: HandleWindowMessage> WindowMessageDispatcher<T> {
    /// This function should only be called once from the WndProc thread. It will take the ownership
    /// of the `Window` object, and drop it before the underlying window is completely gone.
    /// TODO(b/238680252): This should be good enough for supporting multi-windowing, but we should
    /// revisit it if we also want to manage some child windows of the crosvm window.
    pub fn create(window: Window) -> Result<Pin<Box<Self>>> {
        let mut dispatcher = Box::pin(Self {
            message_processor: Default::default(),
            display_event_dispatcher: DisplayEventDispatcher::new(),
            _pinned_marker: PhantomPinned,
        });
        dispatcher
            .as_mut()
            .create_message_processor(window)
            .context("When creating WindowMessageDispatcher")?;
        Ok(dispatcher)
    }

    pub fn process_thread_message(self: Pin<&mut Self>, packet: &MessagePacket) {
        // Safe because we won't move the dispatcher out of it.
        unsafe {
            self.get_unchecked_mut()
                .process_thread_message_internal(packet);
        }
    }

    /// Returns `Some` if the message is processed by the targeted window.
    pub fn dispatch_window_message(
        &mut self,
        hwnd: HWND,
        packet: &MessagePacket,
    ) -> Option<LRESULT> {
        if let Some(processor) = &mut self.message_processor {
            if processor.window().is_same_window(hwnd) {
                let ret = processor.process_message(packet);
                // `WM_NCDESTROY` is sent at the end of the window destruction, and is the last
                // message the window will receive. Drop the message processor so that associated
                // resources can be cleaned up before the window is completely gone.
                if packet.msg == WM_NCDESTROY {
                    if let Err(e) = Self::remove_pointer_from_window(processor.window()) {
                        error!("{:?}", e);
                    }
                    self.message_processor = None;
                    Self::request_exit_message_loop();
                }
                return Some(ret);
            }
        }
        None
    }

    fn create_message_processor(self: Pin<&mut Self>, window: Window) -> Result<()> {
        if !window.is_valid() {
            bail!("Window handle is invalid!");
        }
        Self::store_pointer_in_window(&*self, &window)?;
        // Safe because we won't move the dispatcher out of it, and the dispatcher is aware of the
        // lifecycle of the window.
        unsafe {
            self.get_unchecked_mut()
                .message_processor
                .replace(WindowMessageProcessor::<T>::new(window));
        }
        Ok(())
    }

    fn process_thread_message_internal(&mut self, packet: &MessagePacket) {
        let MessagePacket {
            msg,
            w_param,
            l_param,
        } = *packet;
        match msg {
            #[cfg(feature = "kiwi")]
            WM_USER_HANDLE_SERVICE_MESSAGE_INTERNAL => {
                // Safe because the sender gives up the ownership and expects the receiver to
                // destruct the message.
                let message = unsafe { Box::from_raw(l_param as *mut ServiceSendToGpu) };
                match &mut self.message_processor {
                    Some(processor) => processor.handle_service_message(&*message),
                    None => error!(
                        "Cannot handle service message because there is no message processor!"
                    ),
                }
            }
            WM_USER_HANDLE_DISPLAY_MESSAGE_INTERNAL => {
                // Safe because the sender gives up the ownership and expects the receiver to
                // destruct the message.
                let message = unsafe { Box::from_raw(l_param as *mut DisplaySendToWndProc<T>) };
                self.handle_display_message(*message);
            }
            WM_USER_WNDPROC_THREAD_DROP_KILL_WINDOW_INTERNAL => match &self.message_processor {
                Some(processor) => {
                    debug!("Destroying window on WndProc thread drop");
                    if let Err(e) = processor.window().destroy() {
                        error!(
                            "Failed to destroy window when dropping WndProc thread: {:?}",
                            e
                        );
                    }
                }
                None => debug!("No window to destroy on WndProc thread drop"),
            },
            // Safe because we are processing a message targeting this thread.
            _ => unsafe {
                DefWindowProcW(null_mut(), msg, w_param, l_param);
            },
        }
    }

    fn handle_display_message(&mut self, message: DisplaySendToWndProc<T>) {
        match message {
            DisplaySendToWndProc::CreateSurface { function, callback } => {
                callback(self.create_message_handler(function));
            }
            DisplaySendToWndProc::ImportEventDevice {
                event_device_id,
                event_device,
            } => {
                self.display_event_dispatcher
                    .import_event_device(event_device_id, event_device);
            }
        }
    }

    /// Returns true if the window message handler is created successfully.
    fn create_message_handler(
        &mut self,
        create_handler_func: CreateMessageHandlerFunction<T>,
    ) -> bool {
        match &mut self.message_processor {
            Some(processor) => match processor
                .create_message_handler(create_handler_func, self.display_event_dispatcher.clone())
            {
                Ok(_) => return true,
                Err(e) => error!("Failed to create message handler: {:?}", e),
            },
            None => {
                error!("Cannot create message handler because there is no message processor!")
            }
        }
        false
    }

    fn store_pointer_in_window(pointer: *const Self, window: &Window) -> Result<()> {
        window
            .set_property(DISPATCHER_PROPERTY_NAME, pointer as *mut c_void)
            .context("When storing message dispatcher pointer")
    }

    /// When the window is being destroyed, we must remove all entries added to the property list
    /// before `WM_NCDESTROY` returns.
    fn remove_pointer_from_window(window: &Window) -> Result<()> {
        window
            .remove_property(DISPATCHER_PROPERTY_NAME)
            .context("When removing message dispatcher pointer")
    }

    fn request_exit_message_loop() {
        info!("Posting WM_QUIT");
        // Safe because it will always succeed.
        unsafe {
            PostQuitMessage(0);
        }
    }
}
