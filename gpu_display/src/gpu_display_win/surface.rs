// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::ControlFlow;
use std::rc::Rc;
use std::sync::Weak;
use std::time::Instant;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
use base::warn;
use base::Tube;
use euclid::size2;
use euclid::Size2D;
use metrics::sys::windows::Metrics;
use win_util::keys_down;
use winapi::shared::minwindef::HIWORD;
use winapi::shared::minwindef::LOWORD;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::minwindef::LRESULT;
use winapi::shared::minwindef::TRUE;
use winapi::shared::minwindef::WPARAM;
use winapi::um::winuser::*;

use super::math_util::Size2DCheckedCast;
use super::mouse_input_manager::NoopMouseInputManager as MouseInputManager;
use super::virtual_display_manager::NoopVirtualDisplayManager as VirtualDisplayManager;
use super::window::BasicWindow;
use super::window::GuiWindow;
use super::window_manager::NoopWindowManager as WindowManager;
use super::window_message_processor::SurfaceResources;
use super::window_message_processor::WindowMessage;
use super::window_message_processor::WindowPosMessage;
use super::window_message_processor::HANDLE_WINDOW_MESSAGE_TIMEOUT;
use super::DisplayProperties;
use super::HostWindowSpace;
use super::VirtualDisplaySpace;

pub struct Surface {
    mouse_input: MouseInputManager,
    window_manager: WindowManager,
    virtual_display_manager: VirtualDisplayManager,
    #[allow(dead_code)]
    gpu_main_display_tube: Option<Rc<Tube>>,
}

impl Surface {
    pub fn create(
        window: &GuiWindow,
        virtual_display_size: &Size2D<i32, VirtualDisplaySpace>,
        _metrics: Option<Weak<Metrics>>,
        display_properties: &DisplayProperties,
        resources: SurfaceResources,
    ) -> Result<Self> {
        static CONTEXT_MESSAGE: &str = "When creating Surface";
        info!("Creating Surface");

        let initial_host_viewport_size = window.get_client_rect().context(CONTEXT_MESSAGE)?.size;
        let virtual_display_manager =
            VirtualDisplayManager::new(&initial_host_viewport_size, virtual_display_size);
        // This will make gfxstream initialize the child window to which it will render.
        window.update_virtual_display_projection(
            &virtual_display_manager.get_virtual_display_projection_box(),
        );

        let SurfaceResources {
            display_event_dispatcher,
            gpu_main_display_tube,
        } = resources;

        let mouse_input = match MouseInputManager::new(
            window,
            *virtual_display_manager.get_host_to_guest_transform(),
            virtual_display_size.checked_cast(),
            display_event_dispatcher,
        ) {
            Ok(mouse_input) => mouse_input,
            Err(e) => bail!(
                "Failed to create MouseInputManager during Surface creation: {:?}",
                e
            ),
        };

        Ok(Surface {
            mouse_input,
            window_manager: WindowManager::new(
                window,
                display_properties,
                initial_host_viewport_size,
                gpu_main_display_tube.clone(),
            )
            .context(CONTEXT_MESSAGE)?,
            virtual_display_manager,
            gpu_main_display_tube,
        })
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
        window.update_virtual_display_projection(&virtual_display_projection_box);
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
    pub fn on_message_dispatcher_attached(&mut self, window: &GuiWindow) {
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
            WindowMessage::WindowClose => self.on_close(window),
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

    #[inline]
    fn on_close(&mut self, window: &GuiWindow) {
        if let Err(e) = window.destroy() {
            error!("Failed to destroy window on WM_CLOSE: {:?}", e);
        }
    }
}
