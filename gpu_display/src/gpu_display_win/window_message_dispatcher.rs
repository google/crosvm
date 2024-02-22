// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::HashMap;
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
use base::Event;
use base::Tube;
use cros_tracing::trace_event;
use linux_input_sys::virtio_input_event;
#[cfg(feature = "kiwi")]
use vm_control::ServiceSendToGpu;
use win_util::win32_wide_string;
use winapi::shared::minwindef::LRESULT;
use winapi::shared::windef::HWND;
use winapi::um::winuser::DefWindowProcW;
use winapi::um::winuser::PostQuitMessage;
use winapi::um::winuser::RemovePropW;
use winapi::um::winuser::WM_CLOSE;
use winapi::um::winuser::WM_NCDESTROY;

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

/// Tracks the ids of all event devices in one kind. For each kind, we either have one event device
/// shared by all scanouts (guest displays), or one per scanout.
enum EventDeviceIds {
    GlobalDevice(ObjectId),
    PerScanoutDevices(Vec<ObjectId>),
}

/// This class is used to dispatch input events from the display to the guest input device. It is
/// also used to receive events from the input device (e.g. guest) on behalf of the window so they
/// can be routed back to the window for processing.
#[derive(Clone)]
pub struct DisplayEventDispatcher {
    event_devices: Rc<RefCell<HashMap<ObjectId, EventDevice>>>,
    event_device_ids: Rc<RefCell<HashMap<EventDeviceKind, EventDeviceIds>>>,
}

impl DisplayEventDispatcher {
    pub fn new() -> Self {
        Self {
            event_devices: Default::default(),
            event_device_ids: Default::default(),
        }
    }

    pub fn dispatch(
        &self,
        window: &GuiWindow,
        events: &[virtio_input_event],
        device_kind: EventDeviceKind,
    ) {
        if let Some(event_device_id) = self.find_event_device_id(device_kind, window.scanout_id()) {
            if let Some(event_device) = self.event_devices.borrow_mut().get_mut(&event_device_id) {
                if let Err(e) = event_device.send_report(events.iter().cloned()) {
                    error!("Failed to send events to event device: {}", e);
                }
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
                Err(e) => error!(
                    "failed to read from event device {}: {:?}",
                    event_device_id, e
                ),
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
        let device_kind = event_device.kind();
        let same_kind_device_ids = match device_kind {
            EventDeviceKind::Touchscreen => {
                // Temporarily removing from `self.event_device_ids`. Will be reinserted after
                // adding `event_device_id`.
                let mut per_scanout_device_ids = self
                    .event_device_ids
                    .borrow_mut()
                    .remove(&device_kind)
                    .and_then(|imported_device_ids| match imported_device_ids {
                        EventDeviceIds::PerScanoutDevices(ids) => Some(ids),
                        _ => unreachable!(),
                    })
                    .unwrap_or_default();
                per_scanout_device_ids.push(event_device_id);
                EventDeviceIds::PerScanoutDevices(per_scanout_device_ids)
            }
            _ => EventDeviceIds::GlobalDevice(event_device_id),
        };
        self.event_device_ids
            .borrow_mut()
            .insert(device_kind, same_kind_device_ids);
        self.event_devices
            .borrow_mut()
            .insert(event_device_id, event_device);
    }

    fn find_event_device_id(
        &self,
        device_kind: EventDeviceKind,
        scanout_id: u32,
    ) -> Option<ObjectId> {
        self.event_device_ids
            .borrow()
            .get(&device_kind)
            .and_then(|same_kind_device_ids| match same_kind_device_ids {
                EventDeviceIds::GlobalDevice(event_device_id) => Some(*event_device_id),
                EventDeviceIds::PerScanoutDevices(event_device_ids) => {
                    event_device_ids.get(scanout_id as usize).cloned()
                }
            })
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
    vacant_gui_windows: HashMap<HWND, WindowResources>,
    in_use_gui_windows: HashMap<HWND, WindowMessageProcessor>,
    // We have a one-to-one mapping between virtio-gpu scanouts and GUI window surfaces. The index
    // of the GUI window in this Vec will be the same as the associated scanout's id.
    // These handles are only used for hashmap queries. Do not directly call Windows APIs on them.
    gui_window_handles: Vec<HWND>,
    keyboard_input_manager: KeyboardInputManager,
    display_event_dispatcher: DisplayEventDispatcher,
    gpu_main_display_tube: Option<Rc<Tube>>,
    close_requested_event: Event,
    // The dispatcher is pinned so that its address in the memory won't change, and it is always
    // safe to use the pointer to it stored in the window.
    _pinned_marker: PhantomPinned,
}

impl WindowMessageDispatcher {
    /// This function should only be called once from the WndProc thread. It will take the ownership
    /// of the `GuiWindow` objects, and drop them before the underlying windows are completely gone.
    /// TODO(b/238680252): This should be good enough for supporting multi-windowing, but we should
    /// revisit it if we also want to manage some child windows of the crosvm window.
    pub fn new(
        message_router_window: MessageOnlyWindow,
        gui_windows: Vec<GuiWindow>,
        gpu_main_display_tube: Option<Rc<Tube>>,
        close_requested_event: Event,
    ) -> Result<Pin<Box<Self>>> {
        static CONTEXT_MESSAGE: &str = "When creating WindowMessageDispatcher";
        let display_event_dispatcher = DisplayEventDispatcher::new();
        let gui_window_handles = gui_windows
            .iter()
            .map(|window| {
                // SAFETY:
                // Safe because we will only use these handles to query hashmaps.
                unsafe { window.handle() }
            })
            .collect();
        let mut dispatcher = Box::pin(Self {
            message_router_window: Some(message_router_window),
            vacant_gui_windows: Default::default(), // To be updated.
            in_use_gui_windows: Default::default(),
            gui_window_handles,
            keyboard_input_manager: KeyboardInputManager::new(display_event_dispatcher.clone()),
            display_event_dispatcher,
            gpu_main_display_tube,
            close_requested_event,
            _pinned_marker: PhantomPinned,
        });
        dispatcher
            .as_mut()
            .attach_thread_message_router()
            .context(CONTEXT_MESSAGE)?;
        dispatcher
            .as_mut()
            .create_window_resources(gui_windows)
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
        if matches!(message, ServiceSendToGpu::Shutdown) {
            info!("Processing ShutdownRequest from service");
            // Safe because we won't move the dispatcher out of the returned mutable reference.
            unsafe { self.get_unchecked_mut().request_shutdown_gpu_display() };
            return;
        }

        // TODO(b/306024335): `ServiceSendToGpu` should specify the targeted display id.
        // Safe because we won't move the dispatcher out of the returned mutable reference.
        let primary_window_handle = self.primary_window_handle();
        match unsafe {
            self.get_unchecked_mut()
                .in_use_gui_windows
                .get_mut(&primary_window_handle)
        } {
            Some(processor) => processor.handle_service_message(message),
            None => error!("Cannot handle service message because primary window is not in-use!"),
        }
    }

    /// Returns `Some` if the message is processed by the targeted window.
    pub fn dispatch_window_message(
        &mut self,
        hwnd: HWND,
        packet: &MessagePacket,
    ) -> Option<LRESULT> {
        // First, check if the message is targeting the wndproc thread itself.
        if let Some(router) = &self.message_router_window {
            if router.is_same_window(hwnd) {
                return Some(self.process_simulated_thread_message(hwnd, packet));
            }
        }

        // Second, check if this message indicates any lifetime events of GUI windows.
        if let Some(ret) = self.handle_gui_window_lifetime_message(hwnd, packet) {
            return Some(ret);
        }

        // Third, check if the message is targeting an in-use GUI window.
        self.in_use_gui_windows
            .get_mut(&hwnd)
            .map(|processor| processor.process_message(packet, &self.keyboard_input_manager))
    }

    // TODO(b/306407787): We won't need this once we have full support for multi-window.
    fn primary_window_handle(&self) -> HWND {
        self.gui_window_handles[0]
    }

    fn attach_thread_message_router(self: Pin<&mut Self>) -> Result<()> {
        let dispatcher_ptr = &*self as *const Self;
        // SAFETY:
        // Safe because we won't move the dispatcher out of it.
        match unsafe { &self.get_unchecked_mut().message_router_window } {
            // SAFETY:
            // Safe because we guarantee the dispatcher outlives the thread message router.
            Some(router) => unsafe { Self::store_pointer_in_window(dispatcher_ptr, router) },
            None => bail!("Thread message router not found, cannot associate with dispatcher!"),
        }
    }

    fn create_window_resources(self: Pin<&mut Self>, windows: Vec<GuiWindow>) -> Result<()> {
        // SAFETY:
        // because we won't move the dispatcher out of it.
        let pinned_dispatcher = unsafe { self.get_unchecked_mut() };
        for window in windows.into_iter() {
            if !window.is_valid() {
                // SAFETY:
                // Safe because we are just logging the handle value.
                bail!("Window {:p} is invalid!", unsafe { window.handle() });
            }

            // SAFETY:
            // because we guarantee the dispatcher outlives our GUI windows.
            unsafe { Self::store_pointer_in_window(&*pinned_dispatcher, &window)? };

            pinned_dispatcher.vacant_gui_windows.insert(
                // SAFETY:
                // Safe because this handle is only used as the hashmap kay.
                unsafe { window.handle() },
                // SAFETY:
                // Safe the dispatcher will take care of the lifetime of the window.
                unsafe { WindowResources::new(window) },
            );
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
                // SAFETY:
                // Safe because the sender gives up the ownership and expects the receiver to
                // destruct the message.
                let message = unsafe { Box::from_raw(l_param as *mut DisplaySendToWndProc) };
                self.handle_display_message(*message);
            }
            WM_USER_SHUTDOWN_WNDPROC_THREAD_INTERNAL => {
                let _trace_event =
                    trace_event!(gpu_display, "WM_USER_SHUTDOWN_WNDPROC_THREAD_INTERNAL");
                self.shutdown();
            }
            _ => {
                let _trace_event =
                    trace_event!(gpu_display, "WM_OTHER_MESSAGE_ROUTER_WINDOW_MESSAGE");
                // SAFETY:
                // Safe because we are processing a message targeting the message router window.
                return unsafe { DefWindowProcW(message_router_hwnd, msg, w_param, l_param) };
            }
        }
        0
    }

    fn handle_display_message(&mut self, message: DisplaySendToWndProc) {
        match message {
            DisplaySendToWndProc::CreateSurface {
                scanout_id,
                function,
                callback,
            } => {
                callback(self.create_surface(scanout_id, function));
            }
            DisplaySendToWndProc::ReleaseSurface { surface_id } => self.release_surface(surface_id),
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
        // TODO(b/306407787): Events should be routed to the correct window.
        match self
            .in_use_gui_windows
            .get_mut(&self.primary_window_handle())
        {
            Some(processor) => {
                if let Some((kind, event)) = self
                    .display_event_dispatcher
                    .read_from_device(event_device_id)
                {
                    processor.handle_event_device(kind, event, &self.keyboard_input_manager);
                }
            }
            None => {
                error!("Cannot handle event device because primary window is not in-use!")
            }
        }
    }

    /// Returns true if the surface is created successfully.
    fn create_surface(
        &mut self,
        scanout_id: u32,
        create_surface_func: CreateSurfaceFunction,
    ) -> bool {
        // virtio-gpu prefers to use the lowest available scanout id when creating a new surface, so
        // here we implictly prefer the primary window (associated with scanout 0).
        let hwnd = match self.gui_window_handles.get(scanout_id as usize) {
            Some(hwnd) => *hwnd,
            None => {
                error!("Invalid scanout id {}!", scanout_id);
                return false;
            }
        };
        let window_resources = match self.vacant_gui_windows.remove(&hwnd) {
            Some(resources) => resources,
            None => {
                error!(
                    "GUI window associated with scanout {} is not vacant!",
                    scanout_id
                );
                return false;
            }
        };
        let surface_resources = SurfaceResources {
            display_event_dispatcher: self.display_event_dispatcher.clone(),
            gpu_main_display_tube: self.gpu_main_display_tube.clone(),
        };
        // SAFETY:
        // Safe because the dispatcher will take care of the lifetime of the window.
        match unsafe {
            WindowMessageProcessor::new(create_surface_func, surface_resources, window_resources)
        } {
            Ok(processor) => {
                self.in_use_gui_windows.insert(hwnd, processor);
                self.in_use_gui_windows
                    .get_mut(&hwnd)
                    .expect("It is just inserted")
                    .on_message_dispatcher_attached();
                true
            }
            Err(e) => {
                error!("Failed to create surface: {:?}", e);
                false
            }
        }
    }

    fn release_surface(&mut self, surface_id: u32) {
        match self
            .in_use_gui_windows
            .iter()
            .find(|(_, processor)| processor.surface_id() == surface_id)
        {
            Some(iter) => {
                self.try_release_surface_and_dissociate_gui_window(*iter.0);
            }
            None => error!(
                "Can't release surface {} because there is no window associated with it!",
                surface_id
            ),
        }
    }

    /// Returns true if `hwnd` points to an in-use GUI window.
    fn try_release_surface_and_dissociate_gui_window(&mut self, hwnd: HWND) -> bool {
        if let Some(processor) = self.in_use_gui_windows.remove(&hwnd) {
            // SAFETY:
            // Safe because the dispatcher will take care of the lifetime of the window.
            self.vacant_gui_windows.insert(hwnd, unsafe {
                processor.release_surface_and_take_window_resources()
            });
            return true;
        }
        false
    }

    /// # Safety
    /// The caller is responsible for keeping the pointer valid until it is removed from the window.
    unsafe fn store_pointer_in_window(
        pointer: *const Self,
        window: &dyn BasicWindow,
    ) -> Result<()> {
        window
            .set_property(DISPATCHER_PROPERTY_NAME, pointer as *mut c_void)
            .context("When storing message dispatcher pointer")
    }

    /// Returns Some if this is a GUI window lifetime related message and if we have handled it.
    fn handle_gui_window_lifetime_message(
        &mut self,
        hwnd: HWND,
        packet: &MessagePacket,
    ) -> Option<LRESULT> {
        // Windows calls WndProc as a subroutine when we call `DestroyWindow()`. So, when handling
        // WM_DESTROY/WM_NCDESTROY for one window, we would avoid calling `DestroyWindow()` on
        // another window to avoid recursively mutably borrowing self. Instead, we do
        // `DestroyWindow()` and clean up all associated resources on WM_CLOSE. The long-term fix is
        // tracked by b/314379499.
        match packet.msg {
            WM_CLOSE => {
                // If the window is in-use, return it to the vacant window pool.
                // TODO(b/314309389): This only frees the `Surface` in WndProc thread, while the
                // corresponding guest display isn't unplugged. We might need to figure out a way to
                // inform `gpu_control_tube` to remove that display.
                if self.try_release_surface_and_dissociate_gui_window(hwnd) {
                    // If the service isn't connnected (e.g. when debugging the emulator alone), we
                    // would request shutdown if no window is in-use anymore.
                    if self.gpu_main_display_tube.is_none() && self.in_use_gui_windows.is_empty() {
                        self.request_shutdown_gpu_display();
                    }
                    return Some(0);
                }
            }
            // Don't use any reference to `self` when handling WM_DESTROY/WM_NCDESTROY, since it is
            // likely already mutably borrowed when handling WM_CLOSE on the same stack.
            WM_NCDESTROY => {
                info!("Window {:p} destroyed", hwnd);
                // We don't care if removing the dispatcher pointer succeeds, since this window will
                // be completely gone right after this function returns.
                let property = win32_wide_string(DISPATCHER_PROPERTY_NAME);
                // SAFETY:
                // Safe because `hwnd` is valid, and `property` lives longer than the function call.
                unsafe { RemovePropW(hwnd, property.as_ptr()) };
                return Some(0);
            }
            _ => (),
        }
        None
    }

    /// Signals GpuDisplay to close. This is not going to release any resources right away, but the
    /// closure of GpuDisplay will trigger shutting down the entire VM, and all resources will be
    /// released by then.
    fn request_shutdown_gpu_display(&self) {
        if let Err(e) = self.close_requested_event.signal() {
            error!("Failed to signal close requested event: {}", e);
        }
    }

    /// Destroys all GUI windows and the message router window, and requests exiting message loop.
    fn shutdown(&mut self) {
        info!("Shutting down all windows and message loop");

        // Destroy all GUI windows.
        // Note that Windows calls WndProc as a subroutine when we call `DestroyWindow()`, we have
        // to store window handles in a Vec and query the hashmaps every time rather than simply
        // iterating through the hashmaps.
        let in_use_handles: Vec<HWND> = self.in_use_gui_windows.keys().cloned().collect();
        for hwnd in in_use_handles.iter() {
            if let Some(processor) = self.in_use_gui_windows.remove(hwnd) {
                // SAFETY:
                // Safe because we are dropping the `WindowResources` before the window is gone.
                let resources = unsafe { processor.release_surface_and_take_window_resources() };
                if let Err(e) = resources.window().destroy() {
                    error!("Failed to destroy in-use GUI window: {:?}", e);
                }
            }
        }

        let vacant_handles: Vec<HWND> = self.vacant_gui_windows.keys().cloned().collect();
        for hwnd in vacant_handles.iter() {
            if let Some(resources) = self.vacant_gui_windows.remove(hwnd) {
                if let Err(e) = resources.window().destroy() {
                    error!("Failed to destroy vacant GUI window: {:?}", e);
                }
            }
        }

        // Destroy the message router window.
        if let Some(window) = self.message_router_window.take() {
            if let Err(e) = window.destroy() {
                error!("Failed to destroy thread message router: {:?}", e);
            }
        }

        // Exit the message loop.
        //
        // SAFETY:
        // Safe because this function takes in no memory managed by us, and it always succeeds.
        unsafe {
            PostQuitMessage(0);
        }
    }
}
