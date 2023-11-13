// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::marker::PhantomPinned;
use std::os::raw::c_void;
use std::pin::Pin;
use std::rc::Rc;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
use base::Tube;
use cros_tracing::trace_event;
use linux_input_sys::virtio_input_event;
#[cfg(feature = "kiwi")]
use vm_control::ServiceSendToGpu;
use winapi::shared::minwindef::LRESULT;
use winapi::shared::windef::HWND;
use winapi::um::winuser::*;

use super::keyboard_input_manager::KeyboardInputManager;
use super::window::BasicWindow;
use super::window::GuiWindow;
use super::window::MessageOnlyWindow;
use super::window::MessagePacket;
use super::window_message_processor::*;
use super::ObjectId;
use crate::EventDevice;
use crate::EventDeviceKind;

/// The pointer to dispatcher will be stored with HWND using `SetPropW()` with the following name.
pub(crate) const DISPATCHER_PROPERTY_NAME: &str = "PROP_WND_MSG_DISPATCHER";

/// This class is used to dispatch input events from the display to the guest input device. It is
/// also used to receive events from the input device (e.g. guest) on behalf of the window so they
/// can be routed back to the window for processing.
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

    pub fn read_from_device(
        &self,
        event_device_id: ObjectId,
    ) -> Option<(EventDeviceKind, virtio_input_event)> {
        if let Some(device) = self.event_devices.borrow_mut().get(&event_device_id) {
            match device.recv_event_encoded() {
                Ok(event) => return Some((device.kind(), event)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => return None,
                Err(e) => error!("failed to read from event device: {:?}", e),
            }
        } else {
            error!(
                "notified to read from event device {:?} but do not have a device with that ID",
                event_device_id
            );
        }
        None
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

/// This struct is used for dispatching window messages. Note that messages targeting the WndProc
/// thread itself shouldn't be posted using `PostThreadMessageW()`, but posted as window messages to
/// `message_router_window`, so that they won't get lost when the modal loop is running.
///
/// This struct should be created before the WndProc thread enters the message loop. Once all
/// windows tracked by it are destroyed, it will signal exiting the message loop, and then it can be
/// dropped.
pub(crate) struct WindowMessageDispatcher {
    message_router_window: Option<MessageOnlyWindow>,
    message_processor: Option<WindowMessageProcessor>,
    keyboard_input_manager: KeyboardInputManager,
    display_event_dispatcher: DisplayEventDispatcher,
    gpu_main_display_tube: Option<Rc<Tube>>,
    // The dispatcher is pinned so that its address in the memory won't change, and it is always
    // safe to use the pointer to it stored in the window.
    _pinned_marker: PhantomPinned,
}

impl WindowMessageDispatcher {
    /// This function should only be called once from the WndProc thread. It will take the ownership
    /// of the `GuiWindow` object, and drop it before the underlying window is completely gone.
    /// TODO(b/238680252): This should be good enough for supporting multi-windowing, but we should
    /// revisit it if we also want to manage some child windows of the crosvm window.
    pub fn create(
        message_router_window: MessageOnlyWindow,
        gui_window: GuiWindow,
        gpu_main_display_tube: Option<Rc<Tube>>,
    ) -> Result<Pin<Box<Self>>> {
        static CONTEXT_MESSAGE: &str = "When creating WindowMessageDispatcher";
        let display_event_dispatcher = DisplayEventDispatcher::new();
        let mut dispatcher = Box::pin(Self {
            message_router_window: Some(message_router_window),
            message_processor: Default::default(),
            keyboard_input_manager: KeyboardInputManager::new(display_event_dispatcher.clone()),
            display_event_dispatcher,
            gpu_main_display_tube,
            _pinned_marker: PhantomPinned,
        });
        dispatcher
            .as_mut()
            .attach_thread_message_router()
            .context(CONTEXT_MESSAGE)?;
        dispatcher
            .as_mut()
            .create_message_processor(gui_window)
            .context(CONTEXT_MESSAGE)?;
        Ok(dispatcher)
    }

    /// # Safety
    /// The caller must not use the handle after the message loop terminates.
    pub unsafe fn message_router_handle(&self) -> Option<HWND> {
        self.message_router_window
            .as_ref()
            .map(|router| router.handle())
    }

    #[cfg(feature = "kiwi")]
    pub fn process_service_message(self: Pin<&mut Self>, message: &ServiceSendToGpu) {
        // Safe because we won't move the dispatcher out of the returned mutable reference.
        match unsafe { self.get_unchecked_mut().message_processor.as_mut() } {
            Some(processor) => processor.handle_service_message(message),
            None => error!("Cannot handle service message because there is no message processor!"),
        }
    }

    /// Returns `Some` if the message is processed by the targeted window.
    pub fn dispatch_window_message(
        &mut self,
        hwnd: HWND,
        packet: &MessagePacket,
    ) -> Option<LRESULT> {
        // `WM_NCDESTROY` is sent at the end of the window destruction, and is the last message the
        // window will receive before its handle becomes invalid. So, we will perform final cleanups
        // when this message is received.
        //
        // First, check if the message is targeting the wndproc thread itself.
        if let Some(router) = &self.message_router_window {
            if router.is_same_window(hwnd) {
                let ret = self.process_simulated_thread_message(hwnd, packet);
                // If the destruction of thread message router completes, exit the message loop and
                // terminate the wndproc thread.
                if packet.msg == WM_NCDESTROY {
                    if let Some(router_window) = &self.message_router_window {
                        Self::remove_pointer_from_window(router_window);
                    }
                    self.message_router_window = None;
                    Self::request_exit_message_loop();
                }
                return Some(ret);
            }
        }

        // Second, check if the message is targeting our GUI window.
        if let Some(processor) = &mut self.message_processor {
            if processor.window().is_same_window(hwnd) {
                let ret = processor.process_message(packet, &self.keyboard_input_manager);
                // If the destruction of window completes, drop the message processor so that
                // associated resources can be cleaned up before the window is completely gone.
                if packet.msg == WM_NCDESTROY {
                    Self::remove_pointer_from_window(processor.window());
                    self.message_processor = None;
                    self.request_destroy_message_router_window();
                }
                return Some(ret);
            }
        }
        None
    }

    fn attach_thread_message_router(self: Pin<&mut Self>) -> Result<()> {
        let dispatcher_ptr = &*self as *const Self;
        // Safe because we won't move the dispatcher out of it.
        match unsafe { &self.get_unchecked_mut().message_router_window } {
            // Safe because we guarantee the dispatcher outlives the thread message router.
            Some(router) => unsafe { Self::store_pointer_in_window(dispatcher_ptr, router) },
            None => bail!("Thread message router not found, cannot associate with dispatcher!"),
        }
    }

    fn create_message_processor(self: Pin<&mut Self>, window: GuiWindow) -> Result<()> {
        if !window.is_valid() {
            bail!("Window handle is invalid!");
        }
        // Safe because we guarantee the dispatcher outlives our GUI windows.
        unsafe { Self::store_pointer_in_window(&*self, &window)? };
        // Safe because we won't move the dispatcher out of it, and the dispatcher is aware of the
        // lifecycle of the window.
        unsafe {
            self.get_unchecked_mut()
                .message_processor
                .replace(WindowMessageProcessor::new(window));
        }
        Ok(())
    }

    /// Processes messages targeting the WndProc thread itself. Note that these messages are not
    /// posted using `PostThreadMessageW()`, but posted to `message_router_window` as window
    /// messages (hence "simulated"), so they won't get lost if the modal loop is running.
    fn process_simulated_thread_message(
        &mut self,
        message_router_hwnd: HWND,
        packet: &MessagePacket,
    ) -> LRESULT {
        let MessagePacket {
            msg,
            w_param,
            l_param,
        } = *packet;
        match msg {
            WM_USER_HANDLE_DISPLAY_MESSAGE_INTERNAL => {
                let _trace_event =
                    trace_event!(gpu_display, "WM_USER_HANDLE_DISPLAY_MESSAGE_INTERNAL");
                // Safe because the sender gives up the ownership and expects the receiver to
                // destruct the message.
                let message = unsafe { Box::from_raw(l_param as *mut DisplaySendToWndProc) };
                self.handle_display_message(*message);
            }
            WM_USER_WNDPROC_THREAD_DROP_KILL_WINDOW_INTERNAL => {
                let _trace_event = trace_event!(
                    gpu_display,
                    "WM_USER_WNDPROC_THREAD_DROP_KILL_WINDOW_INTERNAL"
                );
                self.request_destory_gui_window();
            }
            _ => {
                let _trace_event =
                    trace_event!(gpu_display, "WM_OTHER_MESSAGE_ROUTER_WINDOW_MESSAGE");
                // Safe because we are processing a message targeting the message router window.
                return unsafe { DefWindowProcW(message_router_hwnd, msg, w_param, l_param) };
            }
        }
        0
    }

    fn handle_display_message(&mut self, message: DisplaySendToWndProc) {
        match message {
            DisplaySendToWndProc::CreateSurface { function, callback } => {
                callback(self.create_surface(function));
            }
            DisplaySendToWndProc::ImportEventDevice {
                event_device_id,
                event_device,
            } => {
                self.display_event_dispatcher
                    .import_event_device(event_device_id, event_device);
            }
            DisplaySendToWndProc::HandleEventDevice(event_device_id) => {
                self.handle_event_device(event_device_id)
            }
        }
    }

    fn handle_event_device(&mut self, event_device_id: ObjectId) {
        match &mut self.message_processor {
            Some(processor) => {
                if let Some((kind, event)) = self
                    .display_event_dispatcher
                    .read_from_device(event_device_id)
                {
                    processor.handle_event_device(kind, event, &self.keyboard_input_manager);
                }
            }
            None => {
                error!("Cannot handle event device because there is no message processor!")
            }
        }
    }

    /// Returns true if the surface is created successfully.
    fn create_surface(&mut self, create_surface_func: CreateSurfaceFunction) -> bool {
        match &mut self.message_processor {
            Some(processor) => {
                let resources = SurfaceResources {
                    display_event_dispatcher: self.display_event_dispatcher.clone(),
                    gpu_main_display_tube: self.gpu_main_display_tube.clone(),
                };
                match processor.create_surface(create_surface_func, resources) {
                    Ok(_) => return true,
                    Err(e) => error!("Failed to create surface: {:?}", e),
                }
            }
            None => {
                error!("Cannot create surface because there is no message processor!")
            }
        }
        false
    }

    /// # Safety
    /// The caller is responsible for keeping the pointer valid until `remove_pointer_from_window()`
    /// is called.
    unsafe fn store_pointer_in_window(
        pointer: *const Self,
        window: &dyn BasicWindow,
    ) -> Result<()> {
        window
            .set_property(DISPATCHER_PROPERTY_NAME, pointer as *mut c_void)
            .context("When storing message dispatcher pointer")
    }

    /// When the window is being destroyed, we must remove all entries added to the property list
    /// before `WM_NCDESTROY` returns.
    fn remove_pointer_from_window(window: &dyn BasicWindow) {
        if let Err(e) = window.remove_property(DISPATCHER_PROPERTY_NAME) {
            error!("Failed to remove message dispatcher pointer: {:?}", e);
        }
    }

    fn request_destory_gui_window(&self) {
        info!("Destroying GUI window on WndProc thread drop");
        match &self.message_processor {
            Some(processor) => {
                if let Err(e) = processor.window().destroy() {
                    error!("Failed to destroy GUI window: {:?}", e);
                }
            }
            None => error!("No GUI window to destroy!"),
        }
    }

    fn request_destroy_message_router_window(&self) {
        info!("Destroying thread message router on WndProc thread drop");
        match &self.message_router_window {
            Some(router) => {
                if let Err(e) = router.destroy() {
                    error!("Failed to destroy thread message router: {:?}", e);
                }
            }
            None => error!("No thread message router to destroy!"),
        }
    }

    fn request_exit_message_loop() {
        info!("Posting WM_QUIT");
        // Safe because it will always succeed.
        unsafe {
            PostQuitMessage(0);
        }
    }
}
