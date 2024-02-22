// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::c_void;
use std::mem;
use std::ops::ControlFlow;
use std::ptr::null;
use std::ptr::null_mut;

use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
use base::warn;
use euclid::point2;
use euclid::size2;
use euclid::Box2D;
use euclid::Point2D;
use euclid::Size2D;
use euclid::Transform2D;
use euclid::Vector2D;
use linux_input_sys::virtio_input_event;
use smallvec::smallvec;
use smallvec::SmallVec;
use win_util::syscall_bail;
use winapi::shared::minwindef::LOWORD;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::minwindef::LRESULT;
use winapi::shared::minwindef::UINT;
use winapi::shared::windef::RECT;
use winapi::shared::windowsx::GET_X_LPARAM;
use winapi::shared::windowsx::GET_Y_LPARAM;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winuser::ClipCursor;
use winapi::um::winuser::GetRawInputData;
use winapi::um::winuser::GetSystemMetrics;
use winapi::um::winuser::IntersectRect;
use winapi::um::winuser::ReleaseCapture;
use winapi::um::winuser::SetCapture;
use winapi::um::winuser::SetCursor;
use winapi::um::winuser::SetRect;
use winapi::um::winuser::GET_WHEEL_DELTA_WPARAM;
use winapi::um::winuser::HRAWINPUT;
use winapi::um::winuser::HTCLIENT;
use winapi::um::winuser::MA_ACTIVATE;
use winapi::um::winuser::MA_NOACTIVATE;
use winapi::um::winuser::MK_LBUTTON;
use winapi::um::winuser::MOUSE_MOVE_ABSOLUTE;
use winapi::um::winuser::MOUSE_MOVE_RELATIVE;
use winapi::um::winuser::MOUSE_VIRTUAL_DESKTOP;
use winapi::um::winuser::RAWINPUT;
use winapi::um::winuser::RAWINPUTHEADER;
use winapi::um::winuser::RID_INPUT;
use winapi::um::winuser::RIM_TYPEMOUSE;
use winapi::um::winuser::SM_CXSCREEN;
use winapi::um::winuser::SM_CXVIRTUALSCREEN;
use winapi::um::winuser::SM_CYSCREEN;
use winapi::um::winuser::SM_CYVIRTUALSCREEN;
use winapi::um::winuser::SM_XVIRTUALSCREEN;
use winapi::um::winuser::SM_YVIRTUALSCREEN;
use winapi::um::winuser::WHEEL_DELTA;

use super::math_util::Rect;
use super::math_util::RectExtension;
use super::window::BasicWindow;
use super::window::GuiWindow;
use super::window_message_dispatcher::DisplayEventDispatcher;
use super::window_message_processor::MouseMessage;
use super::window_message_processor::WindowMessage;
use super::window_message_processor::WindowPosMessage;
use super::HostWindowSpace;
use super::MouseMode;
use super::VirtualDisplaySpace;
use crate::EventDeviceKind;

// Used as the multi-touch slot & tracking IDs.
// See https://www.kernel.org/doc/html/latest/input/multi-touch-protocol.html for further details.
const PRIMARY_FINGER_ID: i32 = 0;

// The fixed amount of pixels to remove in each side of the client window when confining the cursor
// in relative mouse mode
const BORDER_OFFSET: i32 = 10;

/// Responsible for capturing input from a HWND and forwarding it to the guest.
pub(crate) struct MouseInputManager {
    display_event_dispatcher: DisplayEventDispatcher,
    mouse_pos: Option<Point2D<f64, HostWindowSpace>>,
    /// Accumulates the delta value for mouse/touchpad scrolling. The doc for `WHEEL_DELTA` says it
    /// "... is the threshold for action to be taken, and one such action (for example, scrolling
    /// one increment) should occur for each delta". While the mouse wheel produces exactly
    /// `WHEEL_DELTA` every time it is scrolled, a touchpad may produce much smaller amounts, so we
    /// would want to accumulate it until `WHEEL_DELTA` is reached.
    accumulated_wheel_delta: i16,
    mouse_mode: MouseMode,
    /// Used to transform coordinates from the host window space to the virtual device space
    transform: Transform2D<f64, HostWindowSpace, VirtualDisplaySpace>,
    /// A 2D box in virtual device coordinate space. If a touch event happens outside the box, the
    /// event won't be processed.
    virtual_display_box: Box2D<f64, VirtualDisplaySpace>,
}

impl MouseInputManager {
    pub fn new(
        _window: &GuiWindow,
        transform: Transform2D<f64, HostWindowSpace, VirtualDisplaySpace>,
        virtual_display_size: Size2D<u32, VirtualDisplaySpace>,
        display_event_dispatcher: DisplayEventDispatcher,
    ) -> Self {
        let virtual_display_box = Box2D::new(
            Point2D::zero(),
            Point2D::zero().add_size(&virtual_display_size),
        )
        .to_f64();
        Self {
            display_event_dispatcher,
            mouse_pos: None,
            accumulated_wheel_delta: 0,
            mouse_mode: MouseMode::Touchscreen,
            transform,
            virtual_display_box,
        }
    }

    /// Processes raw input events for the mouse.
    ///
    /// Raw input is required to properly create relative motion events. A previous version used
    /// simulated relative motion based on WM_MOUSEMOVE events (which provide absolute position).
    /// That version worked surprisingly well, except it had one fatal flaw: the guest & host
    /// pointer are not necessarily in sync. This means the host's pointer can hit the edge of the
    /// VM's display window, but the guest's pointer is still in the middle of the screen; for
    /// example, the host pointer hits the left edge and stops generating position change events,
    /// but the guest pointer is still in the middle of the screen. Because of that desync, the left
    /// half of the guest's screen is inaccessible. To avoid that flaw, we use raw input to get
    /// the actual relative input events directly from Windows.
    #[inline]
    pub fn handle_raw_input_event(&mut self, window: &GuiWindow, input_lparam: HRAWINPUT) {
        if !self.should_capture_cursor(window) {
            return;
        }

        let mut promised_size: UINT = 0;
        // SAFETY:
        // Safe because promised_size is guaranteed to exist.
        let ret = unsafe {
            GetRawInputData(
                input_lparam,
                RID_INPUT,
                null_mut(),
                &mut promised_size as *mut UINT,
                mem::size_of::<RAWINPUTHEADER>() as u32,
            )
        };
        if ret == UINT::MAX {
            error!(
                "Relative mouse error: GetRawInputData failed to get size of events: {}",
                // SAFETY: trivially safe
                unsafe { GetLastError() }
            );
            return;
        }
        if promised_size == 0 {
            // No actual raw input to process
            return;
        }

        // buf should be 8 byte aligned because it is used as a RAWINPUT struct. Note that this
        // buffer could be slightly larger, but that's necessary for safety.
        let mut buf: Vec<u64> = Vec::with_capacity(
            promised_size as usize / mem::size_of::<u64>()
                + promised_size as usize % mem::size_of::<u64>(),
        );
        let mut buf_size: UINT = promised_size as UINT;

        // SAFETY:
        // Safe because buf is guaranteed to exist, and be of sufficient size because we checked the
        // required size previously.
        let input_size = unsafe {
            GetRawInputData(
                input_lparam,
                RID_INPUT,
                buf.as_mut_ptr() as *mut c_void,
                &mut buf_size as *mut UINT,
                mem::size_of::<RAWINPUTHEADER>() as u32,
            )
        };
        if input_size == UINT::MAX {
            error!(
                "Relative mouse error: GetRawInputData failed to get events: {}",
                // SAFETY: trivially safe
                unsafe { GetLastError() }
            );
            return;
        }
        if input_size != promised_size {
            error!(
                "GetRawInputData returned {}, but was expected to return {}.",
                input_size, promised_size
            );
            return;
        }

        // SAFETY:
        // Safe because buf is guaranteed to exist, and it was correctly populated by the previous
        // call to GetRawInputData.
        let raw_input = unsafe { (buf.as_ptr() as *const RAWINPUT).as_ref().unwrap() };

        self.process_valid_raw_input_mouse(window, raw_input)
    }

    /// Processes a RAWINPUT event for a mouse and dispatches the appropriate virtio_input_events
    /// to the guest.
    #[inline]
    fn process_valid_raw_input_mouse(&mut self, window: &GuiWindow, raw_input: &RAWINPUT) {
        if raw_input.header.dwType != RIM_TYPEMOUSE {
            error!("Receiving non-mouse RAWINPUT.");
            return;
        }

        // SAFETY:
        // Safe because we checked that raw_input.data is a mouse event.
        let mouse = unsafe { raw_input.data.mouse() };

        // MOUSE_MOVE_RELATIVE is a bitwise flag value that is zero; in other words, it is
        // considered "set" if the 0th bit is zero. For that reason, we mask off the relevant
        // bit, and assert it is equal to the flag value (which is zero).
        let mouse_motion = if mouse.usFlags & 0x1 == MOUSE_MOVE_RELATIVE {
            // Most mice will report as relative, which makes this simple.
            Some(Vector2D::<f64, HostWindowSpace>::new(
                mouse.lLastX as f64,
                mouse.lLastY as f64,
            ))
        } else if mouse.usFlags & MOUSE_MOVE_ABSOLUTE == MOUSE_MOVE_ABSOLUTE {
            // Trackpads may present as "absolute" devices, but we want to show a relative
            // device to the guest. We simulate relative motion in that case by figuring out
            // how much the mouse has moved relative to its last known position.
            // `lLastX` and `lLastY` contain normalized absolute coordinates, and they should be
            // mapped to the primary monitor coordinate space first:
            // https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-rawmouse#remarks
            let primary_monitor_rect = get_primary_monitor_rect(
                /* is_virtual_desktop= */
                mouse.usFlags & MOUSE_VIRTUAL_DESKTOP == MOUSE_VIRTUAL_DESKTOP,
            )
            .to_f64();
            let new_mouse_pos = point2(
                mouse.lLastX as f64 * primary_monitor_rect.width() / 65535.0
                    + primary_monitor_rect.min_x(),
                mouse.lLastY as f64 * primary_monitor_rect.height() / 65535.0
                    + primary_monitor_rect.min_y(),
            );
            let motion = self.mouse_pos.as_ref().map(|pos| new_mouse_pos - *pos);
            self.mouse_pos = Some(new_mouse_pos);
            motion
        } else {
            // Other non-motion events we don't care about.
            None
        };

        if let Some(mouse_motion) = mouse_motion {
            let events = self.create_relative_mouse_events(mouse_motion);
            self.display_event_dispatcher.dispatch(
                window,
                events.as_slice(),
                EventDeviceKind::Mouse,
            );
        }
    }

    #[inline]
    fn create_relative_mouse_events(
        &self,
        mouse_motion: Vector2D<f64, HostWindowSpace>,
    ) -> SmallVec<[virtio_input_event; 2]> {
        smallvec![
            virtio_input_event::relative_x(mouse_motion.x as i32),
            virtio_input_event::relative_y(mouse_motion.y as i32),
        ]
    }

    /// Converts the given host point to a guest point, clipping it to the host window viewport.
    #[inline]
    fn to_guest_point(
        &self,
        pos: Point2D<i32, HostWindowSpace>,
    ) -> Option<Point2D<i32, VirtualDisplaySpace>> {
        let pos = self.transform.transform_point(pos.to_f64());
        let pos = pos.clamp(self.virtual_display_box.min, self.virtual_display_box.max);
        Some(pos.round().to_i32())
    }

    /// Takes a down or up event and converts it into suitable multi touch events. Those events are
    /// then dispatched to the guest. Note that a "click" and movement of the cursor with a button
    /// down are represented as the same event.
    fn handle_multi_touch_finger(
        &mut self,
        window: &GuiWindow,
        pos: Point2D<i32, HostWindowSpace>,
        pressed: bool,
        finger_id: i32,
    ) {
        let pos = match self.to_guest_point(pos) {
            Some(pos) => pos,
            None => return,
        };
        if pressed {
            self.display_event_dispatcher.dispatch(
                window,
                &[
                    virtio_input_event::multitouch_slot(finger_id),
                    virtio_input_event::multitouch_tracking_id(finger_id),
                    virtio_input_event::multitouch_absolute_x(pos.x),
                    virtio_input_event::multitouch_absolute_y(pos.y),
                    virtio_input_event::touch(pressed),
                ],
                EventDeviceKind::Touchscreen,
            );
        } else {
            self.display_event_dispatcher.dispatch(
                window,
                &[
                    virtio_input_event::multitouch_slot(finger_id),
                    virtio_input_event::multitouch_tracking_id(-1),
                    virtio_input_event::touch(false),
                ],
                EventDeviceKind::Touchscreen,
            );
        }
    }

    /// Handles WM_MOUSEMOVE events. Note that these events are NOT used for the relative mouse
    /// (we use raw input instead).
    #[inline]
    fn handle_mouse_move(
        &mut self,
        window: &GuiWindow,
        pos: Point2D<i32, HostWindowSpace>,
        left_down: bool,
    ) {
        if let MouseMode::Touchscreen { .. } = self.mouse_mode {
            if left_down {
                self.handle_multi_touch_finger(window, pos, left_down, PRIMARY_FINGER_ID);
            }
        }
    }

    /// Sets or releases mouse "capture" when a mouse button is pressed or released. This lets us
    /// track motion beyond the window bounds, which is useful for drag gestures in the guest.
    fn adjust_capture_on_mouse_button(&self, down: bool, window: &GuiWindow) {
        if let MouseMode::Touchscreen = self.mouse_mode {
            if down {
                // SAFETY: safe because window is alive during the call, and we don't care if the
                // function fails to capture the mouse because there's nothing we can do about that
                // anyway.
                unsafe { SetCapture(window.handle()) };
            }
        }

        if !down {
            // SAFETY: safe because no memory is involved.
            if unsafe { ReleaseCapture() } == 0 {
                // SAFETY: trivially safe
                warn!("failed to release capture: {}", unsafe { GetLastError() });
            }
        }
    }

    fn handle_mouse_button_left(
        &mut self,
        pos: Point2D<i32, HostWindowSpace>,
        down: bool,
        window: &GuiWindow,
    ) {
        self.adjust_capture_on_mouse_button(down, window);
        match self.mouse_mode {
            MouseMode::Touchscreen { .. } => {
                self.handle_multi_touch_finger(window, pos, down, PRIMARY_FINGER_ID);
            }
            MouseMode::Relative => {
                self.display_event_dispatcher.dispatch(
                    window,
                    &[virtio_input_event::left_click(down)],
                    EventDeviceKind::Mouse,
                );
            }
        }
    }

    fn handle_mouse_button_right(&mut self, window: &GuiWindow, down: bool) {
        if let MouseMode::Relative = self.mouse_mode {
            self.display_event_dispatcher.dispatch(
                window,
                &[virtio_input_event::right_click(down)],
                EventDeviceKind::Mouse,
            );
        }
    }

    fn handle_mouse_button_middle(&mut self, window: &GuiWindow, down: bool) {
        if let MouseMode::Relative = self.mouse_mode {
            self.display_event_dispatcher.dispatch(
                window,
                &[virtio_input_event::middle_click(down)],
                EventDeviceKind::Mouse,
            );
        }
    }

    fn handle_mouse_button_forward(&mut self, window: &GuiWindow, down: bool) {
        if let MouseMode::Relative = self.mouse_mode {
            self.display_event_dispatcher.dispatch(
                window,
                &[virtio_input_event::forward_click(down)],
                EventDeviceKind::Mouse,
            );
        }
    }

    fn handle_mouse_button_back(&mut self, window: &GuiWindow, down: bool) {
        if let MouseMode::Relative = self.mouse_mode {
            self.display_event_dispatcher.dispatch(
                window,
                &[virtio_input_event::back_click(down)],
                EventDeviceKind::Mouse,
            );
        }
    }

    fn set_mouse_mode(&mut self, window: &GuiWindow, mode: MouseMode) {
        info!(
            "requested mouse mode switch to {:?} (current mode is: {:?})",
            mode, self.mouse_mode
        );
        if mode == self.mouse_mode {
            return;
        }

        self.mouse_mode = mode;
        self.mouse_pos = None;
        if let Err(e) = self.adjust_cursor_capture(window) {
            error!(
                "Failed to adjust cursor capture on mouse mode change: {:?}",
                e
            )
        }
    }

    fn handle_mouse_wheel(
        &mut self,
        window: &GuiWindow,
        z_delta: i16,
        _cursor_pos: Option<Point2D<i32, HostWindowSpace>>,
    ) {
        let accumulated_delta = self.accumulated_wheel_delta + z_delta;
        self.accumulated_wheel_delta = accumulated_delta % WHEEL_DELTA;
        let scaled_delta = accumulated_delta / WHEEL_DELTA;
        if scaled_delta == 0 {
            return;
        }
        let deivce_kind = match self.mouse_mode {
            MouseMode::Relative => EventDeviceKind::Mouse,
            MouseMode::Touchscreen => return,
        };
        self.display_event_dispatcher.dispatch(
            window,
            &[virtio_input_event::wheel(scaled_delta as i32)],
            deivce_kind,
        );
    }

    pub fn update_host_to_guest_transform(
        &mut self,
        transform: Transform2D<f64, HostWindowSpace, VirtualDisplaySpace>,
    ) {
        self.transform = transform;
    }

    /// Possible return values:
    /// 1. `ControlFlow::Continue`, should continue invoking other modules, such as the window
    ///    manager, to perform more processing.
    /// 2. `ControlFlow::Break(Some)`, should skip any other processing and return the value.
    /// 3. `ControlFlow::Break(None)`, should immediately perform default processing.
    #[inline]
    pub fn handle_window_message(
        &mut self,
        window: &GuiWindow,
        message: &WindowMessage,
    ) -> ControlFlow<Option<LRESULT>> {
        match message {
            WindowMessage::WindowActivate { .. }
            | WindowMessage::WindowPos(WindowPosMessage::EnterSizeMove)
            | WindowMessage::WindowPos(WindowPosMessage::ExitSizeMove)
            | WindowMessage::WindowPos(WindowPosMessage::WindowPosChanged { .. }) => {
                if let Err(e) = self.adjust_cursor_capture(window) {
                    error!("Failed to adjust cursor capture on {:?}: {:?}", message, e)
                }
            }
            WindowMessage::Mouse(mouse_message) => {
                return self.handle_mouse_message(window, mouse_message);
            }
            _ => (),
        }
        ControlFlow::Continue(())
    }

    /// Possible return values are documented at `handle_window_message()`.
    #[inline]
    fn handle_mouse_message(
        &mut self,
        window: &GuiWindow,
        message: &MouseMessage,
    ) -> ControlFlow<Option<LRESULT>> {
        match message {
            MouseMessage::MouseMove { w_param, l_param } => {
                // Safe because `l_param` comes from the window message and should contain valid
                // numbers.
                let (x, y) = get_x_y_from_lparam(*l_param);
                self.handle_mouse_move(
                    window,
                    Point2D::<_, HostWindowSpace>::new(x, y),
                    w_param & MK_LBUTTON != 0,
                );
            }
            MouseMessage::LeftMouseButton { is_down, l_param } => {
                // Safe because `l_param` comes from the window message and should contain valid
                // numbers.
                let (x, y) = get_x_y_from_lparam(*l_param);
                self.handle_mouse_button_left(
                    Point2D::<_, HostWindowSpace>::new(x, y),
                    *is_down,
                    window,
                );
            }
            MouseMessage::RightMouseButton { is_down } => {
                self.handle_mouse_button_right(window, *is_down)
            }
            MouseMessage::MiddleMouseButton { is_down } => {
                self.handle_mouse_button_middle(window, *is_down)
            }
            MouseMessage::ForwardMouseButton { is_down } => {
                self.handle_mouse_button_forward(window, *is_down)
            }
            MouseMessage::BackMouseButton { is_down } => {
                self.handle_mouse_button_back(window, *is_down)
            }
            MouseMessage::MouseWheel { w_param, l_param } => {
                // Safe because `l_param` comes from the window message and should contain valid
                // numbers.
                let (x, y) = get_x_y_from_lparam(*l_param);
                let cursor_pos = window.screen_to_client(Point2D::new(x, y));
                if let Err(ref e) = cursor_pos {
                    error!(
                        "Failed to convert cursor position to client coordinates: {}",
                        e
                    );
                }

                let z_delta = GET_WHEEL_DELTA_WPARAM(*w_param);
                self.handle_mouse_wheel(window, z_delta, cursor_pos.ok());
            }
            MouseMessage::SetCursor => {
                return if self.should_capture_cursor(window) {
                    // Hide the cursor and skip default processing.
                    // SAFETY: trivially safe
                    unsafe { SetCursor(null_mut()) };
                    ControlFlow::Continue(())
                } else {
                    // Request default processing, i.e. showing the cursor.
                    ControlFlow::Break(None)
                };
            }
            MouseMessage::MouseActivate { l_param } => {
                let hit_test = LOWORD(*l_param as u32) as isize;
                // Only activate if we hit the client area.
                let activate = if hit_test == HTCLIENT {
                    MA_ACTIVATE
                } else {
                    MA_NOACTIVATE
                };
                return ControlFlow::Break(Some(activate as LRESULT));
            }
        }
        ControlFlow::Continue(())
    }

    pub fn handle_change_mouse_mode_request(&mut self, window: &GuiWindow, mouse_mode: MouseMode) {
        self.set_mouse_mode(window, mouse_mode);
    }

    /// Confines/releases the cursor to/from `window`, depending on the current mouse mode and
    /// window states.
    fn adjust_cursor_capture(&mut self, window: &GuiWindow) -> Result<()> {
        let should_capture = self.should_capture_cursor(window);
        if should_capture {
            self.confine_cursor_to_window_internal(window)
                .context("When confining cursor to window")?;
        } else {
            // SAFETY: trivially safe
            unsafe {
                clip_cursor(null()).context("When releasing cursor from window")?;
            }
        }
        Ok(())
    }

    /// Confines the host cursor to a new window area.
    fn confine_cursor_to_window_internal(&mut self, window: &GuiWindow) -> Result<()> {
        let work_rect = window.get_monitor_info()?.work_rect.to_sys_rect();
        let client_rect = window.get_client_rect()?;

        // Translate client rect to screen coordinates.
        let client_ul = window.client_to_screen(&client_rect.min())?;
        let client_br = window.client_to_screen(&client_rect.max())?;
        let mut client_rect = client_rect.to_sys_rect();

        // SAFETY:
        // Safe because hwnd and all RECT are valid objects
        unsafe {
            SetRect(
                &mut client_rect,
                client_ul.x + BORDER_OFFSET,
                client_ul.y + BORDER_OFFSET,
                client_br.x - BORDER_OFFSET,
                client_br.y - BORDER_OFFSET,
            );
            let mut clip_rect = RECT::default();

            // If client_rect intersects with the taskbar then remove that area.
            if IntersectRect(&mut clip_rect, &client_rect, &work_rect) != 0 {
                clip_cursor(&clip_rect)?;
            } else {
                clip_cursor(&client_rect)?;
            }
        }
        Ok(())
    }

    /// Returns whether we intend the mouse cursor to be captured based on the mouse mode.
    ///
    /// Note that we also need to check the window state to see if we actually want to capture the
    /// cursor at this moment. See `should_capture_cursor()`.
    fn is_capture_mode(&self) -> bool {
        self.mouse_mode == MouseMode::Relative
    }

    /// Returns true if the mouse cursor should be captured and hidden.
    ///
    /// We don't always want mouse capture in relative mouse mode. When we are dragging the title
    /// bar to move the window around, or dragging window borders/corners for resizing, we'd still
    /// want to show the cursor until the dragging ends.
    fn should_capture_cursor(&self, window: &GuiWindow) -> bool {
        self.is_capture_mode()
            && window.is_global_foreground_window()
            && !window.is_sizing_or_moving()
    }
}

/// Given an l_param from a mouse event, extracts the (x, y) coordinates. Note that these
/// coordinates should be positive provided the mouse is not captured. (They can be negative when
/// the mouse is captured and it moves outside the bounds of the hwnd.)
fn get_x_y_from_lparam(l_param: LPARAM) -> (i32, i32) {
    (GET_X_LPARAM(l_param), GET_Y_LPARAM(l_param))
}

unsafe fn clip_cursor(rect: *const RECT) -> Result<()> {
    if ClipCursor(rect) == 0 {
        syscall_bail!("Failed to call ClipCursor()");
    }
    Ok(())
}

fn get_primary_monitor_rect(is_virtual_desktop: bool) -> Rect {
    // SAFETY: trivially-safe
    let (origin, size) = unsafe {
        if is_virtual_desktop {
            (
                point2(
                    GetSystemMetrics(SM_XVIRTUALSCREEN),
                    GetSystemMetrics(SM_YVIRTUALSCREEN),
                ),
                size2(
                    GetSystemMetrics(SM_CXVIRTUALSCREEN),
                    GetSystemMetrics(SM_CYVIRTUALSCREEN),
                ),
            )
        } else {
            (
                Point2D::zero(),
                size2(GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)),
            )
        }
    };
    Rect::new(origin, size)
}
