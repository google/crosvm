// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::rc::Rc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
#[cfg(feature = "kiwi")]
use base::error;
use base::warn;
use base::Tube;
use cros_tracing::trace_event;
use euclid::point2;
use euclid::size2;
use euclid::Rect;
use linux_input_sys::virtio_input_event;
#[cfg(feature = "kiwi")]
use vm_control::ServiceSendToGpu;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::minwindef::LRESULT;
use winapi::shared::minwindef::UINT;
use winapi::shared::minwindef::WPARAM;
use winapi::um::winuser::*;

use super::keyboard_input_manager::KeyboardInputManager;
use super::window::GuiWindow;
use super::window::MessagePacket;
use super::window_message_dispatcher::DisplayEventDispatcher;
use super::HostWindowSpace;
use super::ObjectId;
use super::Surface;
use crate::EventDevice;
use crate::EventDeviceKind;

// Once a window message is added to the message queue, if it is not retrieved within 5 seconds,
// Windows will mark the application as "Not Responding", so we'd better finish processing any
// message within this timeout and retrieve the next one.
// https://docs.microsoft.com/en-us/windows/win32/win7appqual/preventing-hangs-in-windows-applications
pub(crate) const HANDLE_WINDOW_MESSAGE_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Struct for resources used for Surface creation.
pub struct SurfaceResources {
    pub display_event_dispatcher: DisplayEventDispatcher,
    pub gpu_main_display_tube: Option<Rc<Tube>>,
}

pub type CreateSurfaceFunction = Box<dyn FnOnce(&GuiWindow, SurfaceResources) -> Result<Surface>>;

/// Called after the surface creation finishes. The argument indicates whether that was successful.
pub type CreateSurfaceCallback = Box<dyn FnOnce(bool)>;

/// Messages sent from the GPU worker thread to the WndProc thread.
pub enum DisplaySendToWndProc {
    CreateSurface {
        function: CreateSurfaceFunction,
        callback: CreateSurfaceCallback,
    },
    ImportEventDevice {
        event_device_id: ObjectId,
        event_device: EventDevice,
    },
    /// Handle a guest -> host input_event.
    HandleEventDevice(ObjectId),
}

/// This class drives the underlying `Surface` object to process window messages retrieved from the
/// message pump. Note that we rely on the owner of `WindowMessageProcessor` object to drop it
/// before the underlying window is completely gone.
pub(crate) struct WindowMessageProcessor {
    window: GuiWindow,
    surface: Option<Surface>,
}

impl WindowMessageProcessor {
    /// # Safety
    /// The owner of `WindowMessageProcessor` object is responsible for dropping it before we finish
    /// processing `WM_NCDESTROY`, because the window handle will become invalid afterwards.
    pub unsafe fn new(window: GuiWindow) -> Self {
        Self {
            window,
            surface: None,
        }
    }

    pub fn create_surface(
        &mut self,
        create_surface_func: CreateSurfaceFunction,
        surface_resources: SurfaceResources,
    ) -> Result<()> {
        create_surface_func(&self.window, surface_resources)
            .map(|surface| {
                self.surface.replace(surface);
                if let Some(surface) = &mut self.surface {
                    surface.on_message_dispatcher_attached(&self.window);
                }
            })
            .context("When creating surface")
    }

    pub fn handle_event_device(
        &mut self,
        event_device_kind: EventDeviceKind,
        event: virtio_input_event,
        keyboard_input_manager: &KeyboardInputManager,
    ) {
        if event_device_kind == EventDeviceKind::Keyboard {
            keyboard_input_manager.handle_guest_event(event);
        }
    }

    #[cfg(feature = "kiwi")]
    pub fn handle_service_message(&mut self, message: &ServiceSendToGpu) {
        match &mut self.surface {
            Some(surface) => surface.handle_service_message(&self.window, message),
            None => error!(
                "Cannot handle {:?} because surface has not been created!",
                message
            ),
        }
    }

    pub fn process_message(
        &mut self,
        packet: &MessagePacket,
        keyboard_input_manager: &KeyboardInputManager,
    ) -> LRESULT {
        // Surface may read window states so we should update them first.
        self.window.update_states(packet.msg, packet.w_param);

        let surface = match &mut self.surface {
            Some(surface) => surface,
            None => {
                warn!(
                    "Skipping processing {:?} because surface has not been created!",
                    packet
                );
                return self.window.default_process_message(packet);
            }
        };

        let _trace_event = Self::new_trace_event(packet.msg);

        let window_message: WindowMessage = packet.into();
        keyboard_input_manager.handle_window_message(&window_message);
        surface
            .handle_window_message(&self.window, window_message)
            .unwrap_or_else(|| self.window.default_process_message(packet))
    }

    pub fn window(&self) -> &GuiWindow {
        &self.window
    }

    #[allow(clippy::if_same_then_else)]
    fn new_trace_event(msg: UINT) -> impl std::any::Any {
        if msg == WM_USER_HOST_VIEWPORT_CHANGE_INTERNAL {
            trace_event!(gpu_display, "WM_USER_HOST_VIEWPORT_CHANGE_INTERNAL")
        } else {
            trace_event!(gpu_display, "WM_OTHER_GUI_WINDOW_MESSAGE")
        }
    }
}

/// Indicates whether the window is getting shown or hidden when receiving `WM_WINDOWPOSCHANGED`.
#[derive(PartialEq, Debug)]
pub enum WindowVisibilityChange {
    Unchanged,
    Shown,
    Hidden,
}

impl From<UINT> for WindowVisibilityChange {
    fn from(flags: UINT) -> Self {
        if flags & SWP_SHOWWINDOW != 0 {
            Self::Shown
        } else if flags & SWP_HIDEWINDOW != 0 {
            Self::Hidden
        } else {
            Self::Unchanged
        }
    }
}

/// General window messages that multiple modules may want to process, such as the window manager,
/// input manager, IME handler, etc.
pub enum WindowMessage {
    /// `WM_ACTIVATE`, "sent to both the window being activated and the window being deactivated."
    WindowActivate { is_activated: bool },
    /// Window location and size related messages.
    WindowPos(WindowPosMessage),
    /// Mouse related messages.
    Mouse(MouseMessage),
    /// `WM_SETFOCUS`, "sent to a window after it has gained the keyboard focus."
    KeyboardFocus,
    /// `WM_KEYDOWN`, `WM_KEYUP`, `WM_SYSKEYDOWN` or `WM_SYSKEYUP`, "posted to the window with the
    /// keyboard focus when a nonsystem/system key is pressed/released."
    Key {
        is_sys_key: bool,
        is_down: bool,
        w_param: WPARAM,
        l_param: LPARAM,
    },
    /// `WM_DISPLAYCHANGE`, "sent to all windows when the display resolution has changed."
    DisplayChange,
    /// `WM_USER_HOST_VIEWPORT_CHANGE_INTERNAL`.
    HostViewportChange { l_param: LPARAM },
    /// `WM_CLOSE`, "sent as a signal that a window or an application should terminate."
    WindowClose,
    /// Not one of the general window messages we care about.
    Other(MessagePacket),
}

/// Window location and size related window messages.
pub enum WindowPosMessage {
    /// `WM_WINDOWPOSCHANGING`, "sent to a window whose size, position, or place in the Z order is
    /// about to change."
    WindowPosChanging { l_param: LPARAM },
    /// `WM_WINDOWPOSCHANGED`, "sent to a window whose size, position, or place in the Z order has
    /// changed."
    WindowPosChanged {
        visibility_change: WindowVisibilityChange,
        window_rect: Rect<i32, HostWindowSpace>,
    },
    /// `WM_SIZING`, "sent to a window that the user is resizing."
    WindowSizeChanging { w_param: WPARAM, l_param: LPARAM },
    /// `WM_SIZE`, "sent to a window after its size has changed."
    WindowSizeChanged { w_param: WPARAM, l_param: LPARAM },
    /// `WM_ENTERSIZEMOVE`, "sent one time to a window after it enters the moving or sizing modal
    /// loop."
    EnterSizeMove,
    /// `WM_EXITSIZEMOVE`, "sent one time to a window, after it has exited the moving or sizing
    /// modal loop."
    ExitSizeMove,
}

impl std::fmt::Display for WindowPosMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::WindowPosChanging { .. } => write!(f, "WindowPosChanging"),
            Self::WindowPosChanged { .. } => write!(f, "WindowPosChanged"),
            Self::WindowSizeChanging { .. } => write!(f, "WindowSizeChanging"),
            Self::WindowSizeChanged { .. } => write!(f, "WindowSizeChanged"),
            Self::EnterSizeMove => write!(f, "EnterSizeMove"),
            Self::ExitSizeMove => write!(f, "ExitSizeMove"),
        }
    }
}

/// Mouse related window messages.
pub enum MouseMessage {
    /// `WM_MOUSEACTIVATE`, "sent when the cursor is in an inactive window and the user presses a
    /// mouse button."
    MouseActivate { l_param: LPARAM },
    /// `WM_INPUT`, "sent to the window that is getting raw input."
    RawInput { l_param: LPARAM },
    /// `WM_MOUSEMOVE`, "posted to a window when the cursor moves."
    MouseMove { w_param: WPARAM, l_param: LPARAM },
    /// `WM_LBUTTONDOWN` or `WM_LBUTTONUP`, "posted when the user presses/releases the left mouse
    /// button while the cursor is in the client area of a window."
    LeftMouseButton { is_down: bool, l_param: LPARAM },
    /// `WM_RBUTTONDOWN` or `WM_RBUTTONUP`, "posted when the user presses/releases the right mouse
    /// button while the cursor is in the client area of a window."
    RightMouseButton { is_down: bool },
    /// `WM_MBUTTONDOWN` or `WM_MBUTTONUP`, "posted when the user presses/releases the middle mouse
    /// button while the cursor is in the client area of a window."
    MiddleMouseButton { is_down: bool },
    /// `WM_MOUSEWHEEL`, "sent to the focus window when the mouse wheel is rotated."
    MouseWheel { w_param: WPARAM, l_param: LPARAM },
    /// `WM_SETCURSOR`, "sent to a window if the mouse causes the cursor to move within a window and
    /// mouse input is not captured."
    SetCursor,
}

impl From<&MessagePacket> for WindowMessage {
    fn from(packet: &MessagePacket) -> Self {
        let MessagePacket {
            msg,
            w_param,
            l_param,
        } = *packet;

        match msg {
            WM_ACTIVATE => Self::WindowActivate {
                is_activated: w_param != 0,
            },
            WM_WINDOWPOSCHANGING => {
                Self::WindowPos(WindowPosMessage::WindowPosChanging { l_param })
            }
            WM_WINDOWPOSCHANGED => {
                // SAFETY:
                // Safe because it will live at least until we finish handling
                // `WM_WINDOWPOSCHANGED`.
                let window_pos: WINDOWPOS = unsafe { *(l_param as *mut WINDOWPOS) };
                Self::WindowPos(WindowPosMessage::WindowPosChanged {
                    visibility_change: window_pos.flags.into(),
                    window_rect: Rect::new(
                        point2(window_pos.x, window_pos.y),
                        size2(window_pos.cx, window_pos.cy),
                    ),
                })
            }
            WM_SIZING => Self::WindowPos(WindowPosMessage::WindowSizeChanging { w_param, l_param }),
            WM_SIZE => Self::WindowPos(WindowPosMessage::WindowSizeChanged { w_param, l_param }),
            WM_ENTERSIZEMOVE => Self::WindowPos(WindowPosMessage::EnterSizeMove),
            WM_EXITSIZEMOVE => Self::WindowPos(WindowPosMessage::ExitSizeMove),
            WM_MOUSEACTIVATE => Self::Mouse(MouseMessage::MouseActivate { l_param }),
            WM_INPUT => Self::Mouse(MouseMessage::RawInput { l_param }),
            WM_MOUSEMOVE => Self::Mouse(MouseMessage::MouseMove { w_param, l_param }),
            WM_LBUTTONDOWN | WM_LBUTTONUP => Self::Mouse(MouseMessage::LeftMouseButton {
                is_down: msg == WM_LBUTTONDOWN,
                l_param,
            }),
            WM_RBUTTONDOWN | WM_RBUTTONUP => Self::Mouse(MouseMessage::RightMouseButton {
                is_down: msg == WM_RBUTTONDOWN,
            }),
            WM_MBUTTONDOWN | WM_MBUTTONUP => Self::Mouse(MouseMessage::MiddleMouseButton {
                is_down: msg == WM_MBUTTONDOWN,
            }),
            WM_MOUSEWHEEL => Self::Mouse(MouseMessage::MouseWheel { w_param, l_param }),
            WM_SETCURSOR => Self::Mouse(MouseMessage::SetCursor),
            WM_SETFOCUS => Self::KeyboardFocus,
            WM_KEYDOWN | WM_KEYUP | WM_SYSKEYDOWN | WM_SYSKEYUP => Self::Key {
                is_sys_key: msg == WM_SYSKEYDOWN || msg == WM_SYSKEYUP,
                is_down: msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN,
                w_param,
                l_param,
            },
            WM_DISPLAYCHANGE => Self::DisplayChange,
            WM_USER_HOST_VIEWPORT_CHANGE_INTERNAL => Self::HostViewportChange { l_param },
            WM_CLOSE => Self::WindowClose,
            _ => Self::Other(*packet),
        }
    }
}
