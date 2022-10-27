// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::From;
use std::fmt;
use std::mem;
#[cfg(feature = "gfxstream")]
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::ptr::null_mut;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
use base::warn;
use euclid::point2;
use euclid::size2;
use euclid::Box2D;
use euclid::Size2D;
use vm_control::display::WindowVisibility;
use win_util::syscall_bail;
use win_util::win32_wide_string;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::HINSTANCE;
use winapi::shared::minwindef::HMODULE;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::minwindef::LRESULT;
use winapi::shared::minwindef::TRUE;
use winapi::shared::minwindef::UINT;
use winapi::shared::minwindef::WORD;
use winapi::shared::minwindef::WPARAM;
use winapi::shared::windef::HBRUSH;
use winapi::shared::windef::HCURSOR;
use winapi::shared::windef::HICON;
use winapi::shared::windef::HMONITOR;
use winapi::shared::windef::HWND;
use winapi::shared::windef::RECT;
use winapi::shared::winerror::S_OK;
use winapi::um::dwmapi::DwmEnableBlurBehindWindow;
use winapi::um::dwmapi::DWM_BB_ENABLE;
use winapi::um::dwmapi::DWM_BLURBEHIND;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::errhandlingapi::SetLastError;
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::shellscalingapi::GetDpiForMonitor;
use winapi::um::shellscalingapi::MDT_DEFAULT;
use winapi::um::shellscalingapi::MDT_RAW_DPI;
use winapi::um::wingdi::GetStockObject;
use winapi::um::wingdi::BLACK_BRUSH;
use winapi::um::winnt::LPCWSTR;
use winapi::um::winuser::*;

use super::math_util::*;
use super::HostWindowSpace;

#[cfg(feature = "gfxstream")]
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

// Windows desktop's default DPI at default scaling settings is 96.
// (https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mpc/pixel-density-and-usability)
pub(crate) const DEFAULT_HOST_DPI: i32 = 96;

/// Stores a message retrieved from the message pump. We don't include the HWND since it is only
/// used for determining the recipient.
#[derive(Copy, Clone, Debug)]
pub struct MessagePacket {
    pub msg: UINT,
    pub w_param: WPARAM,
    pub l_param: LPARAM,
}

impl MessagePacket {
    pub fn new(msg: UINT, w_param: WPARAM, l_param: LPARAM) -> Self {
        Self {
            msg,
            w_param,
            l_param,
        }
    }
}

impl From<MSG> for MessagePacket {
    fn from(message: MSG) -> Self {
        Self::new(message.message, message.wParam, message.lParam)
    }
}

/// The state of window moving or sizing modal loop.
///
/// We do receive `WM_ENTERSIZEMOVE` when the window is about to be resized or moved, but it doesn't
/// tell us whether resizing or moving should be expected. We won't know that until later we receive
/// `WM_SIZING` or `WM_MOVING`. Corner cases are:
/// (1) If the user long presses the title bar, window borders or corners, and then releases without
///     moving the mouse, we would receive both `WM_ENTERSIZEMOVE` and `WM_EXITSIZEMOVE`, but
///     without any `WM_SIZING` or `WM_MOVING` in between.
/// (2) When the window is maximized, if we drag the title bar of it, it will be restored to the
///     normal size and then move along with the cursor. In this case, we would expect
///     `WM_ENTERSIZEMOVE` to be followed by one `WM_SIZING`, and then multiple `WM_MOVING`.
///
/// This enum tracks the modal loop state. Possible state transition:
/// (1) NotInLoop -> WillResizeOrMove -> IsResizing -> NotInLoop. This is for sizing modal loops.
/// (2) NotInLoop -> WillResizeOrMove -> IsMoving -> NotInLoop. This is for moving modal loops.
/// (3) NotInLoop -> WillResizeOrMove -> NotInLoop. This may occur if the user long presses the
///     window title bar, window borders or corners, but doesn't actually resize or move the window.
#[derive(Copy, Clone, Debug, PartialEq)]
enum SizeMoveLoopState {
    /// The window is not in the moving or sizing modal loop.
    NotInLoop,
    /// We have received `WM_ENTERSIZEMOVE` but haven't received either `WM_SIZING` or `WM_MOVING`,
    /// so we don't know if the window is going to be resized or moved at this point.
    WillResizeOrMove,
    /// We have received `WM_SIZING` after `WM_ENTERSIZEMOVE`. `is_first` indicates whether this is
    /// the first `WM_SIZING`.
    IsResizing { is_first: bool },
    /// We have received `WM_MOVING` after `WM_ENTERSIZEMOVE`. `is_first` indicates whether this is
    /// the first `WM_MOVING`.
    IsMoving { is_first: bool },
}

impl SizeMoveLoopState {
    pub fn new() -> Self {
        Self::NotInLoop
    }

    pub fn update(&mut self, msg: UINT, w_param: WPARAM) {
        match msg {
            WM_ENTERSIZEMOVE => self.on_entering_loop(),
            WM_EXITSIZEMOVE => self.on_exiting_loop(),
            WM_SIZING => self.on_resizing_window(w_param),
            WM_MOVING => self.on_moving_window(),
            _ => (),
        };
    }

    pub fn is_in_loop(&self) -> bool {
        *self != Self::NotInLoop
    }

    pub fn is_resizing_starting(&self) -> bool {
        *self == Self::IsResizing { is_first: true }
    }

    fn on_entering_loop(&mut self) {
        info!("Entering window sizing/moving modal loop");
        *self = Self::WillResizeOrMove;
    }

    fn on_exiting_loop(&mut self) {
        info!("Exiting window sizing/moving modal loop");
        *self = Self::NotInLoop;
    }

    fn on_resizing_window(&mut self, w_param: WPARAM) {
        match *self {
            Self::NotInLoop => (),
            Self::WillResizeOrMove => match w_param as u32 {
                // In these cases, the user is dragging window borders or corners for resizing.
                WMSZ_LEFT | WMSZ_RIGHT | WMSZ_TOP | WMSZ_BOTTOM | WMSZ_TOPLEFT | WMSZ_TOPRIGHT
                | WMSZ_BOTTOMLEFT | WMSZ_BOTTOMRIGHT => {
                    info!("Window is being resized");
                    *self = Self::IsResizing { is_first: true };
                }
                // In this case, the user is dragging the title bar of the maximized window. The
                // window will be restored to the normal size and then move along with the cursor,
                // so we can expect `WM_MOVING` coming and entering the moving modal loop.
                _ => info!("Window is being restored"),
            },
            Self::IsResizing { .. } => *self = Self::IsResizing { is_first: false },
            Self::IsMoving { .. } => warn!("WM_SIZING is unexpected in moving modal loops!"),
        }
    }

    fn on_moving_window(&mut self) {
        match *self {
            Self::NotInLoop => (),
            Self::WillResizeOrMove => {
                info!("Window is being moved");
                *self = Self::IsMoving { is_first: true };
            }
            Self::IsMoving { .. } => *self = Self::IsMoving { is_first: false },
            Self::IsResizing { .. } => warn!("WM_MOVING is unexpected in sizing modal loops!"),
        }
    }
}

/// This class helps create and operate on a window using Windows APIs. The owner of `Window` object
/// is responsible for:
/// (1) Calling `update_states()` when a new window message arrives.
/// (2) Dropping the `Window` object before the underlying window is completely gone.
pub struct Window {
    hwnd: HWND,
    size_move_loop_state: SizeMoveLoopState,
}

impl Window {
    /// # Safety
    /// The owner of `Window` object is responsible for dropping it before we finish processing
    /// `WM_NCDESTROY`, because the window handle will become invalid afterwards.
    pub unsafe fn new(
        wnd_proc: WNDPROC,
        class_name: &str,
        title: &str,
        icon_resource_id: WORD,
        dw_style: DWORD,
        initial_window_size: &Size2D<i32, HostWindowSpace>,
    ) -> Result<Self> {
        info!("Creating window");
        static CONTEXT_MESSAGE: &str = "When creating Window";

        let hinstance = Self::get_current_module_handle();
        // If we fail to load any UI element below, use NULL to let the system use the default UI
        // rather than crash.
        let hicon = Self::load_custom_icon(hinstance, icon_resource_id).unwrap_or(null_mut());
        let hcursor = Self::load_system_cursor(IDC_ARROW).unwrap_or(null_mut());
        let hbrush_background = Self::create_opaque_black_brush().unwrap_or(null_mut());

        Self::register_window_class(
            wnd_proc,
            hinstance,
            class_name,
            hicon,
            hcursor,
            hbrush_background,
        )
        .context(CONTEXT_MESSAGE)?;

        let hwnd =
            Self::create_sys_window(hinstance, class_name, title, dw_style, initial_window_size)
                .context(CONTEXT_MESSAGE)?;

        Ok(Self {
            hwnd,
            size_move_loop_state: SizeMoveLoopState::new(),
        })
    }

    /// # Safety
    /// The returned handle should be used carefully, since it may have become invalid if it
    /// outlives the `Window` object.
    pub unsafe fn handle(&self) -> HWND {
        self.hwnd
    }

    pub fn is_same_window(&self, hwnd: HWND) -> bool {
        hwnd == self.hwnd
    }

    pub fn update_states(&mut self, msg: UINT, w_param: WPARAM) {
        self.size_move_loop_state.update(msg, w_param);
    }

    pub fn is_sizing_or_moving(&self) -> bool {
        self.size_move_loop_state.is_in_loop()
    }

    pub fn is_resizing_loop_starting(&self) -> bool {
        self.size_move_loop_state.is_resizing_starting()
    }

    /// Calls `IsWindow()` internally. Returns true if the HWND identifies an existing window.
    pub fn is_valid(&self) -> bool {
        // Safe because it is called from the same thread the created the window.
        unsafe { IsWindow(self.hwnd) != 0 }
    }

    /// Calls `SetPropW()` internally.
    pub fn set_property(&self, property: &str, data: *mut c_void) -> Result<()> {
        // Safe because `Window` object won't outlive the HWND, and failures are handled below.
        unsafe {
            if SetPropW(self.hwnd, win32_wide_string(property).as_ptr(), data) == 0 {
                syscall_bail!("Failed to call SetPropW()");
            }
        }
        Ok(())
    }

    /// Calls `RemovePropW()` internally.
    pub fn remove_property(&self, property: &str) -> Result<()> {
        // Safe because `Window` object won't outlive the HWND, and failures are handled below.
        unsafe {
            SetLastError(0);
            RemovePropW(self.hwnd, win32_wide_string(property).as_ptr());
            if GetLastError() != 0 {
                syscall_bail!("Failed to call RemovePropW()");
            }
        }
        Ok(())
    }

    /// Updates the rectangle in the window's client area to which gfxstream renders.
    pub fn update_virtual_display_projection(
        &self,
        #[allow(unsed)] projection_box: &Box2D<i32, HostWindowSpace>,
    ) {
        // Safe because `Window` object won't outlive the HWND.
        #[cfg(feature = "gfxstream")]
        unsafe {
            gfxstream_backend_setup_window(
                self.hwnd as *const c_void,
                projection_box.min.x,
                projection_box.min.y,
                projection_box.width(),
                projection_box.height(),
                projection_box.width(),
                projection_box.height(),
            );
        }
    }

    /// Calls `GetWindowLongPtrW()` internally.
    pub fn get_attribute(&self, index: i32) -> Result<isize> {
        // Safe because `Window` object won't outlive the HWND, and failures are handled below.
        unsafe {
            // GetWindowLongPtrW() may return zero if we haven't set that attribute before, so we
            // need to check if the error code is non-zero.
            SetLastError(0);
            let value = GetWindowLongPtrW(self.hwnd, index);
            if value == 0 && GetLastError() != 0 {
                syscall_bail!("Failed to call GetWindowLongPtrW()");
            }
            Ok(value)
        }
    }

    /// Calls `SetWindowLongPtrW()` internally.
    pub fn set_attribute(&self, index: i32, value: isize) -> Result<()> {
        // Safe because `Window` object won't outlive the HWND, and failures are handled below.
        unsafe {
            // SetWindowLongPtrW() may return zero if the previous value of that attribute was zero,
            // so we need to check if the error code is non-zero.
            SetLastError(0);
            let prev_value = SetWindowLongPtrW(self.hwnd, index, value);
            if prev_value == 0 && GetLastError() != 0 {
                syscall_bail!("Failed to call SetWindowLongPtrW()");
            }
            Ok(())
        }
    }

    /// Calls `GetWindowRect()` internally.
    pub fn get_window_rect(&self) -> Result<Rect> {
        let mut rect: RECT = Default::default();
        // Safe because `Window` object won't outlive the HWND, we know `rect` is valid, and
        // failures are handled below.
        unsafe {
            if GetWindowRect(self.hwnd, &mut rect) == 0 {
                syscall_bail!("Failed to call GetWindowRect()");
            }
        }
        Ok(rect.to_rect())
    }

    /// Calls `GetWindowRect()` internally.
    pub fn get_window_origin(&self) -> Result<Point> {
        Ok(self.get_window_rect()?.origin)
    }

    /// Calls `GetClientRect()` internally.
    pub fn get_client_rect(&self) -> Result<Rect> {
        let mut rect: RECT = Default::default();
        // Safe because `Window` object won't outlive the HWND, we know `rect` is valid, and
        // failures are handled below.
        unsafe {
            if GetClientRect(self.hwnd, &mut rect) == 0 {
                syscall_bail!("Failed to call GetClientRect()");
            }
        }
        Ok(rect.to_rect())
    }

    /// The system may add adornments around the client area of the window, such as the title bar
    /// and borders. This function returns the size of all those paddings. It can be assumed that:
    /// window_size = client_size + window_padding_size
    pub fn get_window_padding_size(&self, dw_style: u32) -> Result<Size> {
        static CONTEXT_MESSAGE: &str = "When calculating window padding";
        // The padding is always the same in windowed mode, hence we can use an arbitrary rect.
        let client_rect = Rect::new(point2(0, 0), size2(500, 500));
        let dw_ex_style = self.get_attribute(GWL_EXSTYLE).context(CONTEXT_MESSAGE)?;
        let window_rect: Rect = self
            .get_adjusted_window_rect(&client_rect, dw_style, dw_ex_style as u32)
            .context(CONTEXT_MESSAGE)?;
        Ok(window_rect.size - client_rect.size)
    }

    /// Calls `ClientToScreen()` internally. Converts the window client area coordinates of a
    /// specified point to screen coordinates.
    pub fn client_to_screen(&self, point: &Point) -> Result<Point> {
        let mut point = point.to_sys_point();
        // Safe because `Window` object won't outlive the HWND, we know `point` is valid, and
        // failures are handled below.
        unsafe {
            if ClientToScreen(self.hwnd, &mut point) == 0 {
                syscall_bail!("Failed to call ClientToScreen()");
            }
        }
        Ok(point.to_point())
    }

    /// Calls `MonitorFromWindow()` internally. If the window is not on any active display monitor,
    /// returns the handle to the closest one.
    pub fn get_nearest_monitor_handle(&self) -> HMONITOR {
        // Safe because `Window` object won't outlive the HWND.
        unsafe { MonitorFromWindow(self.hwnd, MONITOR_DEFAULTTONEAREST) }
    }

    /// Calls `MonitorFromWindow()` internally. If the window is not on any active display monitor,
    /// returns the info of the closest one.
    pub fn get_monitor_info(&self) -> Result<MonitorInfo> {
        // Safe because `get_nearest_monitor_handle()` always returns a valid monitor handle.
        unsafe { MonitorInfo::new(self.get_nearest_monitor_handle()) }
    }

    /// Calls `MonitorFromWindow()` internally.
    pub fn is_on_active_display(&self) -> bool {
        // Safe because `Window` object won't outlive the HWND.
        unsafe { !MonitorFromWindow(self.hwnd, MONITOR_DEFAULTTONULL).is_null() }
    }

    /// Calls `SetWindowPos()` internally.
    pub fn set_pos(&self, window_rect: &Rect, flags: u32) -> Result<()> {
        // Safe because `Window` object won't outlive the HWND, and failures are handled below.
        unsafe {
            if SetWindowPos(
                self.hwnd,
                null_mut(),
                window_rect.origin.x,
                window_rect.origin.y,
                window_rect.size.width,
                window_rect.size.height,
                flags,
            ) == 0
            {
                syscall_bail!("Failed to call SetWindowPos()");
            }
            Ok(())
        }
    }

    /// Calls `SetWindowPos()` internally. If window size and position need to be changed as well,
    /// prefer to call `set_pos()` with the `SWP_FRAMECHANGED` flag instead.
    pub fn flush_window_style_change(&self) -> Result<()> {
        // Because of `SWP_NOMOVE` and `SWP_NOSIZE` flags, we can pass in arbitrary window size and
        // position as they will be ignored.
        self.set_pos(
            &Rect::zero(),
            SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
        )
    }

    /// Calls `ShowWindow()` internally. Note that it is more preferable to call `set_pos()` with
    /// `SWP_SHOWWINDOW` since that would set the error code on failure.
    pub fn show(&self) {
        // Safe because `Window` object won't outlive the HWND.
        unsafe {
            ShowWindow(self.hwnd, SW_SHOW);
        }
    }

    /// Calls `IsZoomed()` internally. Note that the window may carry the WS_MAXIMIZE flag until it
    /// is restored. For example, if we have switched from maximized to fullscreen, this function
    /// would still return true.
    pub fn was_maximized(&self) -> bool {
        // Safe because `Window` object won't outlive the HWND.
        unsafe { IsZoomed(self.hwnd) != 0 }
    }

    /// Calls `IsWindowVisible()` internally. We also require that the window size is nonzero to be
    /// considered visible.
    pub fn is_visible(&self) -> Result<bool> {
        // Safe because `Window` object won't outlive the HWND.
        if unsafe { IsWindowVisible(self.hwnd) } != 0 {
            let window_rect = self
                .get_window_rect()
                .context("When querying window visibility")?;
            if window_rect.size != Size::zero() {
                return Ok(true);
            } else {
                info!("Window has WS_VISIBLE flag but its size is zero");
            }
        }
        Ok(false)
    }

    pub fn get_visibility(&self) -> Result<WindowVisibility> {
        Ok(if !self.is_visible()? {
            WindowVisibility::Hidden
        } else if self.is_minimized() {
            WindowVisibility::Minimized
        } else {
            WindowVisibility::Normal
        })
    }

    /// Calls `GetForegroundWindow()` internally. A foreground window is the window with which the
    /// user is currently working. It might belong to a different thread/process than the calling
    /// thread.
    pub fn is_global_foreground_window(&self) -> bool {
        // Safe because there is no argument.
        unsafe { GetForegroundWindow() == self.hwnd }
    }

    /// Calls `GetActiveWindow()` internally. An active window is the window with which the user is
    /// currently working and is attached to the calling thread's message queue. It is possible that
    /// there is no active window if the foreground focus is on another thread/process.
    pub fn is_thread_foreground_window(&self) -> bool {
        // Safe because there is no argument.
        unsafe { GetActiveWindow() == self.hwnd }
    }

    /// Calls `IsIconic()` internally.
    pub fn is_minimized(&self) -> bool {
        // Safe because `Window` object won't outlive the HWND.
        unsafe { IsIconic(self.hwnd) != 0 }
    }

    /// Calls `SetForegroundWindow()` internally. `SetForegroundWindow()` may fail, for example,
    /// when the taskbar is in the foreground, hence this is a best-effort call.
    pub fn bring_to_foreground(&self) {
        // Safe because `Window` object won't outlive the HWND.
        if unsafe { SetForegroundWindow(self.hwnd) } == 0 {
            info!("Cannot bring the window to foreground.");
        }
    }

    /// Calls `DwmEnableBlurBehindWindow()` internally. This is only used for a top-level window.
    /// Even though the name of Windows API suggests that it blurs the background, beginning with
    /// Windows 8, it does not blur it, but only makes the window semi-transparent.
    pub fn set_transparency(&self, is_transparent: bool) -> Result<()> {
        let blur_behind = DWM_BLURBEHIND {
            dwFlags: DWM_BB_ENABLE,
            fEnable: if is_transparent { TRUE } else { FALSE },
            hRgnBlur: null_mut(),
            fTransitionOnMaximized: FALSE,
        };
        // Safe because `Window` object won't outlive the HWND, we know `blur_behind` is valid,
        // and failures are handled below.
        let errno = unsafe { DwmEnableBlurBehindWindow(self.hwnd, &blur_behind) };
        match errno {
            0 => Ok(()),
            _ => bail!(
                "Failed to call DwmEnableBlurBehindWindow() when setting \
                window transparency to {} (Error code {})",
                is_transparent,
                errno
            ),
        }
    }

    /// Calls `AdjustWindowRectExForDpi()` internally.
    pub fn get_adjusted_window_rect(
        &self,
        client_rect: &Rect,
        dw_style: u32,
        dw_ex_style: u32,
    ) -> Result<Rect> {
        let mut window_rect: RECT = client_rect.to_sys_rect();
        // Safe because `Window` object won't outlive the HWND, we know `window_rect` is valid,
        // and failures are handled below.
        unsafe {
            if AdjustWindowRectExForDpi(
                &mut window_rect,
                dw_style,
                FALSE,
                dw_ex_style,
                GetDpiForSystem(),
            ) == 0
            {
                syscall_bail!("Failed to call AdjustWindowRectExForDpi()");
            }
        }
        Ok(window_rect.to_rect())
    }

    /// Calls `GetWindowPlacement()` and `SetWindowPlacement()` internally.
    pub fn set_restored_pos(&self, window_rect: &Rect) -> Result<()> {
        let mut window_placement = WINDOWPLACEMENT {
            length: mem::size_of::<WINDOWPLACEMENT>().try_into().unwrap(),
            ..Default::default()
        };
        // Safe because `Window` object won't outlive the HWND, we know `window_placement` is valid,
        // and failures are handled below.
        unsafe {
            if GetWindowPlacement(self.hwnd, &mut window_placement) == 0 {
                syscall_bail!("Failed to call GetWindowPlacement()");
            }
            window_placement.rcNormalPosition = window_rect.to_sys_rect();
            if SetWindowPlacement(self.hwnd, &window_placement) == 0 {
                syscall_bail!("Failed to call SetWindowPlacement()");
            }
        }
        Ok(())
    }

    /// Calls `PostMessageW()` internally.
    pub fn post_message(&self, msg: UINT, w_param: WPARAM, l_param: LPARAM) -> Result<()> {
        // Safe because `Window` object won't outlive the HWND.
        unsafe {
            if PostMessageW(self.hwnd, msg, w_param, l_param) == 0 {
                syscall_bail!("Failed to call PostMessageW()");
            }
        }
        Ok(())
    }

    /// Calls `DestroyWindow()` internally.
    pub fn destroy(&self) -> Result<()> {
        // Safe because `Window` object won't outlive the HWND.
        unsafe {
            if DestroyWindow(self.hwnd) == 0 {
                syscall_bail!("Failed to call DestroyWindow()");
            }
        }
        Ok(())
    }

    /// Calls `DefWindowProcW()` internally.
    pub fn default_process_message(&self, packet: &MessagePacket) -> LRESULT {
        // Safe because `Window` object won't outlive the HWND.
        unsafe { DefWindowProcW(self.hwnd, packet.msg, packet.w_param, packet.l_param) }
    }

    /// Calls `GetModuleHandleW()` internally.
    fn get_current_module_handle() -> HMODULE {
        // Safe because we handle failures below.
        let hmodule = unsafe { GetModuleHandleW(null_mut()) };
        if hmodule.is_null() {
            // If it fails, we are in a very broken state and it doesn't make sense to keep running.
            panic!(
                "Failed to call GetModuleHandleW() for the current module (Error code {})",
                unsafe { GetLastError() }
            );
        }
        hmodule
    }

    /// Calls `LoadIconW()` internally.
    fn load_custom_icon(hinstance: HINSTANCE, resource_id: WORD) -> Result<HICON> {
        // Safe because we handle failures below.
        unsafe {
            let hicon = LoadIconW(hinstance, MAKEINTRESOURCEW(resource_id));
            if hicon.is_null() {
                syscall_bail!("Failed to call LoadIconW()");
            }
            Ok(hicon)
        }
    }

    /// Calls `LoadCursorW()` internally.
    fn load_system_cursor(cursor_id: LPCWSTR) -> Result<HCURSOR> {
        // Safe because we handle failures below.
        unsafe {
            let hcursor = LoadCursorW(null_mut(), cursor_id);
            if hcursor.is_null() {
                syscall_bail!("Failed to call LoadCursorW()");
            }
            Ok(hcursor)
        }
    }

    /// Calls `GetStockObject()` internally.
    fn create_opaque_black_brush() -> Result<HBRUSH> {
        // Safe because we handle failures below.
        unsafe {
            let hobject = GetStockObject(BLACK_BRUSH as i32);
            if hobject.is_null() {
                syscall_bail!("Failed to call GetStockObject()");
            }
            Ok(hobject as HBRUSH)
        }
    }

    fn register_window_class(
        wnd_proc: WNDPROC,
        hinstance: HINSTANCE,
        class_name: &str,
        hicon: HICON,
        hcursor: HCURSOR,
        hbrush_background: HBRUSH,
    ) -> Result<()> {
        let class_name = win32_wide_string(class_name);
        let window_class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_OWNDC | CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: wnd_proc,
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: hicon,
            hCursor: hcursor,
            hbrBackground: hbrush_background,
            lpszMenuName: null_mut(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: hicon,
        };

        // Safe because we know the lifetime of `window_class`, and we handle failures below.
        unsafe {
            if RegisterClassExW(&window_class) == 0 {
                syscall_bail!("Failed to call RegisterClassExW()");
            }
            Ok(())
        }
    }

    fn create_sys_window(
        hinstance: HINSTANCE,
        class_name: &str,
        title: &str,
        dw_style: DWORD,
        initial_window_size: &Size2D<i32, HostWindowSpace>,
    ) -> Result<HWND> {
        // Safe because we handle failures below.
        unsafe {
            let hwnd = CreateWindowExW(
                0,
                win32_wide_string(class_name).as_ptr(),
                win32_wide_string(title).as_ptr(),
                dw_style,
                0,
                0,
                initial_window_size.width,
                initial_window_size.height,
                null_mut(),
                null_mut(),
                hinstance,
                null_mut(),
            );
            if hwnd.is_null() {
                syscall_bail!("Failed to call CreateWindowExW()");
            }
            Ok(hwnd)
        }
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        // Safe because it is called from the same thread the created the window.
        if unsafe { IsWindow(self.hwnd) } == 0 {
            error!("The underlying HWND is invalid when Window is being dropped!")
        }
    }
}

/// If the resolution/orientation of the monitor changes, or if the monitor is unplugged, this must
/// be recreated with a valid HMONITOR.
pub struct MonitorInfo {
    pub hmonitor: HMONITOR,
    pub display_rect: Rect,
    pub work_rect: Rect,
    pub dpi: i32,
}

impl MonitorInfo {
    /// # Safety
    /// Caller is responsible for ensuring that `hmonitor` is a valid handle.
    pub unsafe fn new(hmonitor: HMONITOR) -> Result<Self> {
        let monitor_info: MONITORINFO =
            Self::get_monitor_info(hmonitor).context("When creating MonitorInfo")?;
        Ok(Self {
            hmonitor,
            display_rect: monitor_info.rcMonitor.to_rect(),
            work_rect: monitor_info.rcWork.to_rect(),
            dpi: Self::get_dpi(hmonitor),
        })
    }

    /// Calls `GetMonitorInfoW()` internally.
    /// # Safety
    /// Caller is responsible for ensuring that `hmonitor` is a valid handle.
    unsafe fn get_monitor_info(hmonitor: HMONITOR) -> Result<MONITORINFO> {
        let mut monitor_info = MONITORINFO {
            cbSize: mem::size_of::<MONITORINFO>().try_into().unwrap(),
            ..Default::default()
        };
        if GetMonitorInfoW(hmonitor, &mut monitor_info) == 0 {
            syscall_bail!("Failed to call GetMonitorInfoW()");
        }
        Ok(monitor_info)
    }

    /// Calls `GetDpiForMonitor()` internally.
    fn get_dpi(hmonitor: HMONITOR) -> i32 {
        let mut dpi_x = 0;
        let mut dpi_y = 0;
        // This is always safe since `GetDpiForMonitor` won't crash if HMONITOR is invalid, but
        // return E_INVALIDARG.
        unsafe {
            if GetDpiForMonitor(hmonitor, MDT_RAW_DPI, &mut dpi_x, &mut dpi_y) == S_OK
                || GetDpiForMonitor(hmonitor, MDT_DEFAULT, &mut dpi_x, &mut dpi_y) == S_OK
            {
                // We assume screen pixels are square and DPI in different directions are the same.
                dpi_x as i32
            } else {
                error!("Failed to retrieve DPI with HMONITOR {:p}", hmonitor);
                DEFAULT_HOST_DPI
            }
        }
    }
}

impl fmt::Debug for MonitorInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{hmonitor: {:p}, display_rect: {:?}, work_rect: {:?}, DPI: {}}}",
            self.hmonitor, self.display_rect, self.work_rect, self.dpi,
        )
    }
}
