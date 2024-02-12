// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::rc::Rc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
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
use winapi::um::winuser::SWP_HIDEWINDOW;
use winapi::um::winuser::SWP_SHOWWINDOW;
use winapi::um::winuser::WINDOWPOS;
use winapi::um::winuser::WM_ACTIVATE;
use winapi::um::winuser::WM_DISPLAYCHANGE;
use winapi::um::winuser::WM_ENTERSIZEMOVE;
use winapi::um::winuser::WM_EXITSIZEMOVE;
use winapi::um::winuser::WM_INPUT;
use winapi::um::winuser::WM_KEYDOWN;
use winapi::um::winuser::WM_KEYUP;
use winapi::um::winuser::WM_LBUTTONDOWN;
use winapi::um::winuser::WM_LBUTTONUP;
use winapi::um::winuser::WM_MBUTTONDOWN;
use winapi::um::winuser::WM_MBUTTONUP;
use winapi::um::winuser::WM_MOUSEACTIVATE;
use winapi::um::winuser::WM_MOUSEMOVE;
use winapi::um::winuser::WM_MOUSEWHEEL;
use winapi::um::winuser::WM_RBUTTONDOWN;
use winapi::um::winuser::WM_RBUTTONUP;
use winapi::um::winuser::WM_SETCURSOR;
use winapi::um::winuser::WM_SETFOCUS;
use winapi::um::winuser::WM_SIZE;
use winapi::um::winuser::WM_SIZING;
use winapi::um::winuser::WM_SYSKEYDOWN;
use winapi::um::winuser::WM_SYSKEYUP;
use winapi::um::winuser::WM_USER;
use winapi::um::winuser::WM_WINDOWPOSCHANGED;
use winapi::um::winuser::WM_WINDOWPOSCHANGING;

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

/// Thread message for destroying all windows and releasing all resources during a
/// `WindowProcedureThread` drop. This may be triggered if crosvm has encountered errors and has to
/// shut down, or if the user/service initiates the shutdown.
pub(crate) const WM_USER_SHUTDOWN_WNDPROC_THREAD_INTERNAL: UINT = WM_USER;

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
        scanout_id: u32,
        function: CreateSurfaceFunction,
        callback: CreateSurfaceCallback,
    },
    ReleaseSurface {
        surface_id: u32,
    },
    ImportEventDevice {
        event_device_id: ObjectId,
        event_device: EventDevice,
    },
    /// Handle a guest -> host input_event.
    HandleEventDevice(ObjectId),
}

/// This struct wraps a `GuiWindow` that is currently not associated with any `Surface`.
pub(crate) struct WindowResources {
    window: GuiWindow,
}

impl WindowResources {
    /// # Safety
    /// The owner of `WindowResource` object is responsible for dropping it before we finish
    /// processing `WM_NCDESTROY` for this window, because the window handle will become invalid
    /// afterwards.
    pub unsafe fn new(window: GuiWindow) -> Self {
        Self { window }
    }

    pub fn window(&self) -> &GuiWindow {
        &self.window
    }
}

/// This struct drives the underlying `Surface` object to process window messages retrieved from the
/// message pump.
pub(crate) struct WindowMessageProcessor {
    window_resources: WindowResources,
    surface: Surface,
}

impl WindowMessageProcessor {
    /// Creates a `Surface` and associates it with the window. To dissociate them, call
    /// `release_surface_and_take_window_resources()` below.
    /// # Safety
    /// The owner of `WindowMessageProcessor` object is responsible for dropping it before we finish
    /// processing `WM_NCDESTROY` for this window, because the window handle will become invalid
    /// afterwards.
    pub unsafe fn new(
        create_surface_func: CreateSurfaceFunction,
        surface_resources: SurfaceResources,
        window_resources: WindowResources,
    ) -> Result<Self> {
        create_surface_func(&window_resources.window, surface_resources)
            .map(|surface| Self {
                window_resources,
                surface,
            })
            .context("When creating Surface")
    }

    pub fn surface_id(&self) -> u32 {
        self.surface.surface_id()
    }

    /// Drops the associated `Surface` and turns `self` back into `WindowResources`. This also hides
    /// the window if it hasn't been hidden.
    /// # Safety
    /// The owner of `WindowResources` object is responsible for dropping it before we finish
    /// processing `WM_NCDESTROY` for this window, because the window handle will become invalid
    /// afterwards.
    pub unsafe fn release_surface_and_take_window_resources(self) -> WindowResources {
        let surface_id = self.surface_id();
        let resources = self.window_resources;
        info!(
            "Releasing surface {} associated with scanout {}",
            surface_id,
            resources.window().scanout_id(),
        );
        if let Err(e) = resources.window().hide_if_visible() {
            error!("Failed to hide window before releasing surface: {:?}", e);
        }
        resources
    }

    /// This should be called once when it is safe to assume all future messages targeting the GUI
    /// window will be dispatched to this `WindowMessageProcessor`.
    pub fn on_message_dispatcher_attached(&mut self) {
        let window = &self.window_resources.window;
        self.surface.on_message_dispatcher_attached(window);
        #[cfg(feature = "kiwi")]
        if let Some(ime_handler) = self.window_resources.ime_handler.as_mut() {
            ime_handler.on_message_dispatcher_attached(window);
        }
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
        self.surface
            .handle_service_message(&self.window_resources.window, message);
    }

    pub fn process_message(
        &mut self,
        packet: &MessagePacket,
        keyboard_input_manager: &KeyboardInputManager,
    ) -> LRESULT {
        // Message handlers may read window states so we should update those states first.
        let window = &mut self.window_resources.window;
        window.update_states(packet.msg, packet.w_param);

        let _trace_event = Self::new_trace_event(packet.msg);

        let window_message: WindowMessage = packet.into();
        keyboard_input_manager.handle_window_message(&window_message);
        self.surface
            .handle_window_message(window, window_message)
            .unwrap_or_else(|| window.default_process_message(packet))
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
    /// `WM_SETCURSOR`, "sent to a window if the mouse causes the cursor to move within a window
    /// and mouse input is not captured."
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
            _ => Self::Other(*packet),
        }
    }
}
