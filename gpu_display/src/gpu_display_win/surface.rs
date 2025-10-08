// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::ControlFlow;
use std::ops::Deref;
#[cfg(feature = "gfxstream_display")]
use std::os::raw::c_int;
#[cfg(feature = "gfxstream_display")]
use std::os::raw::c_void;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Weak;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
use base::warn;
use base::Tube;
use euclid::size2;
use euclid::Box2D;
use euclid::Size2D;
use metrics::sys::windows::Metrics;
use sync::Mutex;
use vm_control::gpu::DisplayMode;
use vm_control::gpu::DisplayParameters;
use win_util::keys_down;
use winapi::shared::minwindef::HIWORD;
use winapi::shared::minwindef::LOWORD;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::minwindef::LRESULT;
use winapi::shared::minwindef::TRUE;
use winapi::shared::minwindef::WPARAM;
use winapi::um::winuser::VK_F4;
use winapi::um::winuser::VK_MENU;
use winapi::um::winuser::WM_CLOSE;

use super::keyboard_input_manager::KeyboardInputManager;
use super::math_util::Size2DCheckedCast;
use super::mouse_input_manager::MouseInputManager;
use super::virtual_display_manager::NoopVirtualDisplayManager as VirtualDisplayManager;
#[cfg(feature = "gfxstream_display")]
use super::window::BasicWindow;
use super::window::GuiWindow;
use super::window_manager::NoopWindowManager as WindowManager;
use super::window_message_processor::GeneralMessage;
use super::window_message_processor::SurfaceResources;
use super::window_message_processor::WindowMessage;
use super::window_message_processor::WindowPosMessage;
use super::window_message_processor::HANDLE_WINDOW_MESSAGE_TIMEOUT;
use super::HostDisplayWrapper;
use super::HostWindowSpace;
use super::MouseMode;
use crate::EventDeviceKind;

#[cfg(feature = "gfxstream_display")]
#[link(name = "gfxstream_backend")]
extern "C" {
    fn gfxstream_backend_setup_window(
        hwnd: *const c_void,
        window_x: c_int,
        window_y: c_int,
        window_width: c_int,
        window_height: c_int,
        fb_width: c_int,
        fb_height: c_int,
    );
}

// Updates the rectangle in the window's client area to which gfxstream renders.
fn update_virtual_display_projection(
    #[allow(unused)] host_display: impl Deref<Target = HostDisplayWrapper>,
    #[allow(unused)] window: &GuiWindow,
    #[allow(unused)] projection_box: &Box2D<i32, HostWindowSpace>,
) {
    #[cfg(feature = "vulkan_display")]
    if let HostDisplayWrapper::Initialized(ref host_display) = *host_display {
        if let Err(err) = host_display
            .move_window(&projection_box.cast_unit())
            .with_context(|| "move the subwindow")
        {
            error!("{:?}", err);
        }
        #[cfg(feature = "gfxstream_display")]
        return;
    }

    // Safe because `Window` object won't outlive the HWND.
    #[cfg(feature = "gfxstream_display")]
    unsafe {
        gfxstream_backend_setup_window(
            window.handle() as *const c_void,
            projection_box.min.x,
            projection_box.min.y,
            projection_box.width(),
            projection_box.height(),
            projection_box.width(),
            projection_box.height(),
        );
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct DisplayProperties {
    pub start_hidden: bool,
    pub is_fullscreen: bool,
    pub window_width: u32,
    pub window_height: u32,
}

impl From<&DisplayParameters> for DisplayProperties {
    fn from(params: &DisplayParameters) -> Self {
        let is_fullscreen = matches!(params.mode, DisplayMode::BorderlessFullScreen(_));
        let (window_width, window_height) = params.get_window_size();

        Self {
            start_hidden: params.hidden,
            is_fullscreen,
            window_width,
            window_height,
        }
    }
}

pub struct Surface {
    surface_id: u32,
    mouse_input: MouseInputManager,
    window_manager: WindowManager,
    virtual_display_manager: VirtualDisplayManager,
    #[allow(dead_code)]
    gpu_main_display_tube: Option<Rc<Tube>>,
    host_display: Arc<Mutex<HostDisplayWrapper>>,
}

impl Surface {
    pub fn new(
        surface_id: u32,
        window: &GuiWindow,
        _metrics: Option<Weak<Metrics>>,
        display_params: &DisplayParameters,
        resources: SurfaceResources,
        host_display: Arc<Mutex<HostDisplayWrapper>>,
    ) -> Result<Self> {
        static CONTEXT_MESSAGE: &str = "When creating Surface";
        info!(
            "Creating surface {} to associate with scanout {}",
            surface_id,
            window.scanout_id()
        );

        let initial_host_viewport_size = window.get_client_rect().context(CONTEXT_MESSAGE)?.size;
        let virtual_display_size = {
            let (width, height) = display_params.get_virtual_display_size();
            size2(width, height).checked_cast()
        };
        let virtual_display_manager =
            VirtualDisplayManager::new(&initial_host_viewport_size, &virtual_display_size);
        // This will make gfxstream initialize the child window to which it will render.
        update_virtual_display_projection(
            host_display.lock(),
            window,
            &virtual_display_manager.get_virtual_display_projection_box(),
        );

        let SurfaceResources {
            display_event_dispatcher,
            gpu_main_display_tube,
        } = resources;

        let mouse_input = MouseInputManager::new(
            window,
            *virtual_display_manager.get_host_to_guest_transform(),
            virtual_display_size.checked_cast(),
            display_event_dispatcher,
        );

        Ok(Surface {
            surface_id,
            mouse_input,
            window_manager: WindowManager::new(
                window,
                &display_params.into(),
                initial_host_viewport_size,
                gpu_main_display_tube.clone(),
            )
            .context(CONTEXT_MESSAGE)?,
            virtual_display_manager,
            gpu_main_display_tube,
            host_display,
        })
    }

    pub fn surface_id(&self) -> u32 {
        self.surface_id
    }

    fn handle_key_event(
        &mut self,
        window: &GuiWindow,
        _key_down: bool,
        w_param: WPARAM,
        _l_param: LPARAM,
    ) {
        // Since we handle WM_SYSKEYDOWN we have to handle Alt-F4 ourselves.
        if (w_param == VK_MENU as usize || w_param == VK_F4 as usize)
            && keys_down(&[VK_MENU, VK_F4])
        {
            info!("Got alt-F4 w_param={}, posting WM_CLOSE", w_param);
            if let Err(e) =
                window.post_message(WM_CLOSE, /* w_param */ 0, /* l_param */ 0)
            {
                error!("Failed to post WM_CLOSE: {:?}", e);
            }
        }
    }

    fn set_mouse_mode(&mut self, window: &GuiWindow, mouse_mode: MouseMode) {
        self.mouse_input
            .handle_change_mouse_mode_request(window, mouse_mode);
    }

    fn update_host_viewport_size(
        &mut self,
        window: &GuiWindow,
        host_viewport_size: &Size2D<i32, HostWindowSpace>,
    ) {
        info!("Updating host viewport size to {:?}", host_viewport_size);
        let start = Instant::now();

        self.virtual_display_manager
            .update_host_guest_transforms(host_viewport_size);
        let virtual_display_projection_box = self
            .virtual_display_manager
            .get_virtual_display_projection_box();
        update_virtual_display_projection(
            self.host_display.lock(),
            window,
            &virtual_display_projection_box,
        );
        self.mouse_input.update_host_to_guest_transform(
            *self.virtual_display_manager.get_host_to_guest_transform(),
        );

        let elapsed = start.elapsed();
        let elapsed_millis = elapsed.as_millis();
        if elapsed < HANDLE_WINDOW_MESSAGE_TIMEOUT {
            info!(
                "Finished updating host viewport size in {}ms",
                elapsed_millis
            );
        } else {
            warn!(
                "Window might have been hung since updating host viewport size took \
                        too long ({}ms)!",
                elapsed_millis
            );
        }
    }

    /// Called once when it is safe to assume all future messages targeting `window` will be
    /// dispatched to this `Surface`.
    fn on_message_dispatcher_attached(&mut self, window: &GuiWindow) {
        // `WindowManager` relies on window messages to properly set initial window pos.
        // We might see a suboptimal UI if any error occurs here, such as having black bars. Instead
        // of crashing the emulator, we would just log the error and still allow the user to
        // experience the app.
        if let Err(e) = self.window_manager.set_initial_window_pos(window) {
            error!("Failed to set initial window pos: {:#?}", e);
        }
    }

    /// Called whenever any window message is retrieved. Returns None if `DefWindowProcW()` should
    /// be called after our processing.
    #[inline]
    pub fn handle_window_message(
        &mut self,
        window: &GuiWindow,
        message: WindowMessage,
    ) -> Option<LRESULT> {
        if let ControlFlow::Break(ret) = self.mouse_input.handle_window_message(window, &message) {
            return ret;
        }

        // Just return 0 for most of the messages we processed.
        let mut ret: Option<LRESULT> = Some(0);
        match message {
            WindowMessage::Key {
                is_sys_key: _,
                is_down,
                w_param,
                l_param,
            } => self.handle_key_event(window, is_down, w_param, l_param),
            WindowMessage::WindowPos(window_pos_msg) => {
                ret = self.handle_window_pos_message(window, window_pos_msg)
            }
            WindowMessage::DisplayChange => self.window_manager.handle_display_change(window),
            WindowMessage::HostViewportChange { l_param } => {
                self.on_host_viewport_change(window, l_param)
            }
            // The following messages are handled by other modules.
            WindowMessage::WindowActivate { .. }
            | WindowMessage::Mouse(_)
            | WindowMessage::KeyboardFocus => (),
            WindowMessage::Other(..) => {
                // Request default processing for messages that we don't explicitly handle.
                ret = None;
            }
        }
        ret
    }

    #[inline]
    pub fn handle_general_message(
        &mut self,
        window: &GuiWindow,
        message: &GeneralMessage,
        keyboard_input_manager: &KeyboardInputManager,
    ) {
        match message {
            GeneralMessage::MessageDispatcherAttached => {
                self.on_message_dispatcher_attached(window)
            }
            GeneralMessage::RawInputEvent(raw_input) => {
                self.mouse_input.handle_raw_input_event(window, *raw_input)
            }
            GeneralMessage::GuestEvent {
                event_device_kind,
                event,
            } => {
                if let EventDeviceKind::Keyboard = event_device_kind {
                    keyboard_input_manager.handle_guest_event(window, *event);
                }
            }
            GeneralMessage::SetMouseMode(mode) => self.set_mouse_mode(window, *mode),
        }
    }

    /// Returns None if `DefWindowProcW()` should be called after our processing.
    #[inline]
    fn handle_window_pos_message(
        &mut self,
        window: &GuiWindow,
        message: WindowPosMessage,
    ) -> Option<LRESULT> {
        self.window_manager
            .handle_window_pos_message(window, &message);
        match message {
            WindowPosMessage::WindowPosChanged { .. } => {
                // Request default processing, otherwise `WM_SIZE` and `WM_MOVE` won't be sent.
                // https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-windowposchanged#remarks
                return None;
            }
            // "An application should return TRUE if it processes this message."
            WindowPosMessage::WindowSizeChanging { .. } => return Some(TRUE as LRESULT),
            _ => (),
        }
        Some(0)
    }

    #[inline]
    fn on_host_viewport_change(&mut self, window: &GuiWindow, l_param: LPARAM) {
        let new_size = size2(LOWORD(l_param as u32) as i32, HIWORD(l_param as u32) as i32);
        self.update_host_viewport_size(window, &new_size);
    }
}
