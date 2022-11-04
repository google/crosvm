// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::rc::Rc;

use anyhow::Context;
use anyhow::Result;
use base::error;
use base::warn;
use base::Tube;
#[cfg(feature = "kiwi")]
use vm_control::ServiceSendToGpu;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::minwindef::LRESULT;
use winapi::shared::minwindef::TRUE;
use winapi::shared::minwindef::UINT;
use winapi::shared::minwindef::WPARAM;
use winapi::um::winuser::*;

use super::window::MessagePacket;
use super::window::Window;
use super::window_message_dispatcher::DisplayEventDispatcher;
use super::ObjectId;
use crate::EventDevice;

/// Thread message for killing the window during a `WndProcThread` drop. This indicates an error
/// within crosvm that internally causes the WndProc thread to be dropped, rather than when the
/// user/service initiates the window to be killed.
/// TODO(b/238678893): During such an abnormal event, window messages might not be reliable anymore.
/// Relying on destructors might be a safer choice.
pub(crate) const WM_USER_WNDPROC_THREAD_DROP_KILL_WINDOW_INTERNAL: UINT = WM_USER;

// Message for handling the change in host viewport. This is sent when the host window size changes
// and we need to render to a different part of the window. The new width and height are sent as the
// low/high word of lParam.
pub(crate) const WM_USER_HOST_VIEWPORT_CHANGE_INTERNAL: UINT = WM_USER + 1;

/// Thread message for handling the message sent from the GPU worker thread. A pointer to enum
/// `DisplaySendToWndProc` is sent as the lParam. Note that the receiver is responsible for
/// destructing the message.
pub(crate) const WM_USER_HANDLE_DISPLAY_MESSAGE_INTERNAL: UINT = WM_USER + 2;

/// Struct for resources used for window message handler creation.
pub struct MessageHandlerResources {
    pub display_event_dispatcher: DisplayEventDispatcher,
    pub gpu_main_display_tube: Option<Rc<Tube>>,
}

pub type CreateMessageHandlerFunction<T> =
    Box<dyn FnOnce(&Window, MessageHandlerResources) -> Result<T>>;

/// Called after the handler creation finishes. The argument indicates whether that was successful.
pub type CreateMessageHandlerCallback = Box<dyn FnOnce(bool)>;

/// Messages sent from the GPU worker thread to the WndProc thread.
pub enum DisplaySendToWndProc<T: HandleWindowMessage> {
    CreateSurface {
        function: CreateMessageHandlerFunction<T>,
        callback: CreateMessageHandlerCallback,
    },
    ImportEventDevice {
        event_device_id: ObjectId,
        event_device: EventDevice,
    },
}

/// A trait for processing messages retrieved from the window message queue. All messages routed to
/// a trait object would target the same window.
pub trait HandleWindowMessage {
    /// Called once when it is safe to assume all future messages targeting this window will be
    /// dispatched to this handler.
    fn on_message_dispatcher_attached(&mut self, _window: &Window) {}

    /// Called when processing `WM_ACTIVATE`.
    fn on_activate(&mut self, _window: &Window, _w_param: WPARAM) {}

    /// Called when processing `WM_MOUSEACTIVATE`. See possible return values:
    /// https://docs.microsoft.com/en-us/windows/win32/inputdev/wm-mouseactivate#return-value
    fn on_mouse_activate(&self, _l_param: LPARAM) -> i32 {
        MA_NOACTIVATE as i32
    }

    /// Called when processing `WM_SETFOCUS`.
    fn on_set_focus(&mut self) {}

    /// Called when processing `WM_INPUT`.
    fn on_raw_input(&mut self, _window: &Window, _l_param: LPARAM) {}

    /// Called when processing `WM_MOUSEMOVE`.
    fn on_mouse_move(&mut self, _w_param: WPARAM, _l_param: LPARAM) {}

    /// Called when processing `WM_LBUTTONDOWN` and `WM_LBUTTONUP`.
    fn on_mouse_button_left(&mut self, _window: &Window, _is_down: bool, _l_param: LPARAM) {}

    /// Called when processing `WM_RBUTTONDOWN` and `WM_RBUTTONUP`.
    fn on_mouse_button_right(&mut self, _is_down: bool) {}

    /// Called when processing `WM_MOUSEWHEEL`.
    fn on_mouse_wheel(&mut self, _w_param: WPARAM) {}

    /// Called when processing `WM_SETCURSOR`. It should return true if the cursor has been handled
    /// and the default processing should be skipped.
    fn on_set_cursor(&mut self, _window: &Window) -> bool {
        false
    }

    /// Called when processing `WM_KEYDOWN`, `WM_KEYUP`, `WM_SYSKEYDOWN` and `WM_SYSKEYUP`.
    fn on_key(&mut self, _window: &Window, _key_down: bool, _w_param: WPARAM, _l_param: LPARAM) {}

    /// Called when processing `WM_WINDOWPOSCHANGING`.
    fn on_window_pos_changing(&mut self, _window: &Window, _l_param: LPARAM) {}

    /// Called when processing `WM_SIZING`.
    fn on_window_size_changing(&mut self, _window: &Window, _w_param: WPARAM, _l_param: LPARAM) {}

    /// Called when processing `WM_WINDOWPOSCHANGED`. It should return true if it is intended to
    /// skip default processing, in which case `WM_SIZE` and `WM_MOVE` won't be sent to the window.
    fn on_window_pos_changed(&mut self, _window: &Window, _l_param: LPARAM) -> bool {
        false
    }

    /// Called when processing `WM_SIZE`.
    fn on_window_size_changed(&mut self, _window: &Window, _w_param: WPARAM, _l_param: LPARAM) {}

    /// Called when processing `WM_ENTERSIZEMOVE`.
    fn on_enter_size_move(&mut self) {}

    /// Called when processing `WM_EXITSIZEMOVE`.
    fn on_exit_size_move(&mut self, _window: &Window) {}

    /// Called when processing `WM_DISPLAYCHANGE`.
    fn on_display_change(&mut self, _window: &Window) {}

    /// Called when processing requests from the service.
    #[cfg(feature = "kiwi")]
    fn on_handle_service_message(&mut self, _window: &Window, _message: &ServiceSendToGpu) {}

    /// Called when processing `WM_USER_HOST_VIEWPORT_CHANGE_INTERNAL`.
    fn on_host_viewport_change(&mut self, _window: &Window, _l_param: LPARAM) {}

    /// Called when processing `WM_CLOSE`. It should return true if the window should be destroyed
    /// immediately.
    fn on_close(&mut self) -> bool {
        true
    }

    /// Called when processing `WM_DESTROY`.
    fn on_destroy(&mut self) {}
}

/// This class drives the underlying `HandleWindowMessage` trait object to process window messages
/// retrieved from the message pump. Note that we rely on the owner of `WindowMessageProcessor`
/// object to drop it before the underlying window is completely gone.
pub(crate) struct WindowMessageProcessor<T: HandleWindowMessage> {
    window: Window,
    message_handler: Option<T>,
}

impl<T: HandleWindowMessage> WindowMessageProcessor<T> {
    /// # Safety
    /// The owner of `WindowMessageProcessor` object is responsible for dropping it before we finish
    /// processing `WM_NCDESTROY`, because the window handle will become invalid afterwards.
    pub unsafe fn new(window: Window) -> Self {
        Self {
            window,
            message_handler: None,
        }
    }

    pub fn create_message_handler(
        &mut self,
        create_handler_func: CreateMessageHandlerFunction<T>,
        handler_resources: MessageHandlerResources,
    ) -> Result<()> {
        create_handler_func(&self.window, handler_resources)
            .map(|handler| {
                self.message_handler.replace(handler);
                if let Some(handler) = &mut self.message_handler {
                    handler.on_message_dispatcher_attached(&self.window);
                }
            })
            .context("When creating window message handler")
    }

    #[cfg(feature = "kiwi")]
    pub fn handle_service_message(&mut self, message: &ServiceSendToGpu) {
        match &mut self.message_handler {
            Some(handler) => handler.on_handle_service_message(&self.window, message),
            None => error!(
                "Cannot handle {:?} because window message handler has not been created!",
                message
            ),
        }
    }

    pub fn process_message(&mut self, packet: &MessagePacket) -> LRESULT {
        let MessagePacket {
            msg,
            w_param,
            l_param,
        } = *packet;

        // The handler may read window states so we should update them first.
        self.window.update_states(msg, w_param);

        let handler = match &mut self.message_handler {
            Some(handler) => handler,
            None => {
                warn!(
                    "Skipping processing {:?} because message handler has not been created!",
                    packet
                );
                return self.window.default_process_message(packet);
            }
        };
        match msg {
            WM_ACTIVATE => {
                handler.on_activate(&self.window, w_param);
                0
            }
            WM_MOUSEACTIVATE => handler.on_mouse_activate(l_param) as LRESULT,
            WM_SETFOCUS => {
                handler.on_set_focus();
                0
            }
            WM_INPUT => {
                handler.on_raw_input(&self.window, l_param);
                self.window.default_process_message(packet)
            }
            WM_MOUSEMOVE => {
                handler.on_mouse_move(w_param, l_param);
                0
            }
            WM_LBUTTONDOWN | WM_LBUTTONUP => {
                let is_down = msg == WM_LBUTTONDOWN;
                handler.on_mouse_button_left(&self.window, is_down, l_param);
                0
            }
            WM_RBUTTONDOWN | WM_RBUTTONUP => {
                handler.on_mouse_button_right(/* is_down= */ msg == WM_RBUTTONDOWN);
                0
            }
            WM_MOUSEWHEEL => {
                handler.on_mouse_wheel(w_param);
                0
            }
            WM_SETCURSOR => {
                if handler.on_set_cursor(&self.window) {
                    return 0;
                }
                self.window.default_process_message(packet)
            }
            WM_KEYDOWN | WM_KEYUP | WM_SYSKEYDOWN | WM_SYSKEYUP => {
                let key_down = msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN;
                handler.on_key(&self.window, key_down, w_param, l_param);
                0
            }
            WM_WINDOWPOSCHANGING => {
                handler.on_window_pos_changing(&self.window, l_param);
                0
            }
            WM_SIZING => {
                handler.on_window_size_changing(&self.window, w_param, l_param);
                TRUE as LRESULT
            }
            WM_WINDOWPOSCHANGED => {
                if handler.on_window_pos_changed(&self.window, l_param) {
                    return 0;
                }
                self.window.default_process_message(packet)
            }
            WM_SIZE => {
                handler.on_window_size_changed(&self.window, w_param, l_param);
                0
            }
            WM_ENTERSIZEMOVE => {
                handler.on_enter_size_move();
                0
            }
            WM_EXITSIZEMOVE => {
                handler.on_exit_size_move(&self.window);
                0
            }
            WM_DISPLAYCHANGE => {
                handler.on_display_change(&self.window);
                0
            }
            WM_USER_HOST_VIEWPORT_CHANGE_INTERNAL => {
                handler.on_host_viewport_change(&self.window, l_param);
                0
            }
            WM_CLOSE => {
                if handler.on_close() {
                    if let Err(e) = self.window.destroy() {
                        error!("Failed to destroy window on WM_CLOSE: {:?}", e);
                    }
                }
                0
            }
            WM_DESTROY => {
                handler.on_destroy();
                0
            }
            _ => self.window.default_process_message(packet),
        }
    }

    pub fn window(&self) -> &Window {
        &self.window
    }
}
