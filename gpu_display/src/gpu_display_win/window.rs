// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::From;
use std::fmt;
use std::mem;
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
use euclid::Point2D;
use euclid::Size2D;
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
use winapi::um::winuser::AdjustWindowRectExForDpi;
use winapi::um::winuser::ClientToScreen;
use winapi::um::winuser::CreateWindowExW;
use winapi::um::winuser::DefWindowProcW;
use winapi::um::winuser::DestroyWindow;
use winapi::um::winuser::GetActiveWindow;
use winapi::um::winuser::GetClientRect;
use winapi::um::winuser::GetDpiForSystem;
use winapi::um::winuser::GetForegroundWindow;
use winapi::um::winuser::GetMonitorInfoW;
use winapi::um::winuser::GetSystemMetrics;
use winapi::um::winuser::GetWindowLongPtrW;
use winapi::um::winuser::GetWindowPlacement;
use winapi::um::winuser::GetWindowRect;
use winapi::um::winuser::IsIconic;
use winapi::um::winuser::IsWindow;
use winapi::um::winuser::IsWindowVisible;
use winapi::um::winuser::IsZoomed;
use winapi::um::winuser::LoadCursorW;
use winapi::um::winuser::LoadIconW;
use winapi::um::winuser::MonitorFromWindow;
use winapi::um::winuser::PostMessageW;
use winapi::um::winuser::RegisterRawInputDevices;
use winapi::um::winuser::RegisterTouchWindow;
use winapi::um::winuser::RemovePropW;
use winapi::um::winuser::ScreenToClient;
use winapi::um::winuser::SetForegroundWindow;
use winapi::um::winuser::SetPropW;
use winapi::um::winuser::SetWindowLongPtrW;
use winapi::um::winuser::SetWindowPlacement;
use winapi::um::winuser::SetWindowPos;
use winapi::um::winuser::ShowWindow;
use winapi::um::winuser::GWL_EXSTYLE;
use winapi::um::winuser::HWND_MESSAGE;
use winapi::um::winuser::MAKEINTRESOURCEW;
use winapi::um::winuser::MONITORINFO;
use winapi::um::winuser::MONITOR_DEFAULTTONEAREST;
use winapi::um::winuser::MONITOR_DEFAULTTONULL;
use winapi::um::winuser::MSG;
use winapi::um::winuser::PCRAWINPUTDEVICE;
use winapi::um::winuser::RAWINPUTDEVICE;
use winapi::um::winuser::SM_REMOTESESSION;
use winapi::um::winuser::SWP_FRAMECHANGED;
use winapi::um::winuser::SWP_HIDEWINDOW;
use winapi::um::winuser::SWP_NOACTIVATE;
use winapi::um::winuser::SWP_NOMOVE;
use winapi::um::winuser::SWP_NOSIZE;
use winapi::um::winuser::SWP_NOZORDER;
use winapi::um::winuser::SW_RESTORE;
use winapi::um::winuser::SW_SHOW;
use winapi::um::winuser::WINDOWPLACEMENT;
use winapi::um::winuser::WMSZ_BOTTOM;
use winapi::um::winuser::WMSZ_BOTTOMLEFT;
use winapi::um::winuser::WMSZ_BOTTOMRIGHT;
use winapi::um::winuser::WMSZ_LEFT;
use winapi::um::winuser::WMSZ_RIGHT;
use winapi::um::winuser::WMSZ_TOP;
use winapi::um::winuser::WMSZ_TOPLEFT;
use winapi::um::winuser::WMSZ_TOPRIGHT;
use winapi::um::winuser::WM_ENTERSIZEMOVE;
use winapi::um::winuser::WM_EXITSIZEMOVE;
use winapi::um::winuser::WM_MOVING;
use winapi::um::winuser::WM_SIZING;

use super::math_util::*;
use super::HostWindowSpace;

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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

/// A trait for basic functionalities that are common to both message-only windows and GUI windows.
/// Implementers must guarantee that when these functions are called, the underlying window object
/// is still alive.
pub(crate) trait BasicWindow {
    /// # Safety
    /// The returned handle should be used carefully, since it may have become invalid if it
    /// outlives the window object.
    unsafe fn handle(&self) -> HWND;

    fn is_same_window(&self, hwnd: HWND) -> bool {
        // SAFETY:
        // Safe because we are just comparing handle values.
        hwnd == unsafe { self.handle() }
    }

    /// Calls `DefWindowProcW()` internally.
    fn default_process_message(&self, packet: &MessagePacket) -> LRESULT {
        // SAFETY:
        // Safe because the window object won't outlive the HWND.
        unsafe { DefWindowProcW(self.handle(), packet.msg, packet.w_param, packet.l_param) }
    }

    /// Calls `SetPropW()` internally.
    /// # Safety
    /// The caller is responsible for keeping the data pointer valid until `remove_property()` is
    /// called.
    unsafe fn set_property(&self, property: &str, data: *mut c_void) -> Result<()> {
        // Partially safe because the window object won't outlive the HWND, and failures are handled
        // below. The caller is responsible for the rest of safety.
        if SetPropW(self.handle(), win32_wide_string(property).as_ptr(), data) == 0 {
            syscall_bail!("Failed to call SetPropW()");
        }
        Ok(())
    }

    /// Calls `RemovePropW()` internally.
    fn remove_property(&self, property: &str) -> Result<()> {
        // SAFETY:
        // Safe because the window object won't outlive the HWND, and failures are handled below.
        unsafe {
            SetLastError(0);
            RemovePropW(self.handle(), win32_wide_string(property).as_ptr());
            if GetLastError() != 0 {
                syscall_bail!("Failed to call RemovePropW()");
            }
        }
        Ok(())
    }

    /// Calls `DestroyWindow()` internally.
    fn destroy(&self) -> Result<()> {
        // SAFETY:
        // Safe because the window object won't outlive the HWND.
        if unsafe { DestroyWindow(self.handle()) } == 0 {
            syscall_bail!("Failed to call DestroyWindow()");
        }
        Ok(())
    }
}

/// This class helps create and operate on a GUI window using Windows APIs. The owner of `GuiWindow`
/// object is responsible for:
/// (1) Calling `update_states()` when a new window message arrives.
/// (2) Dropping the `GuiWindow` object before the underlying window is completely gone.
pub struct GuiWindow {
    hwnd: HWND,
    scanout_id: u32,
    size_move_loop_state: SizeMoveLoopState,
}

impl GuiWindow {
    /// # Safety
    /// The owner of `GuiWindow` object is responsible for dropping it before we finish processing
    /// `WM_NCDESTROY`, because the window handle will become invalid afterwards.
    pub unsafe fn new(
        scanout_id: u32,
        class_name: &str,
        title: &str,
        dw_style: DWORD,
        initial_window_size: &Size2D<i32, HostWindowSpace>,
    ) -> Result<Self> {
        info!("Creating GUI window for scanout {}", scanout_id);

        let hwnd = create_sys_window(
            get_current_module_handle(),
            class_name,
            title,
            dw_style,
            /* hwnd_parent */ null_mut(),
            initial_window_size,
        )
        .context("When creating GuiWindow")?;
        let window = Self {
            hwnd,
            scanout_id,
            size_move_loop_state: SizeMoveLoopState::new(),
        };
        window.register_touch();
        Ok(window)
    }

    pub fn scanout_id(&self) -> u32 {
        self.scanout_id
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
        // SAFETY:
        // Safe because it is called from the same thread the created the window.
        unsafe { IsWindow(self.hwnd) != 0 }
    }

    /// Calls `GetWindowLongPtrW()` internally.
    pub fn get_attribute(&self, index: i32) -> Result<isize> {
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND, and failures are handled below.
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
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND, and failures are handled below.
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
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND, we know `rect` is valid, and
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
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND, we know `rect` is valid, and
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
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND, we know `point` is valid, and
        // failures are handled below.
        unsafe {
            if ClientToScreen(self.hwnd, &mut point) == 0 {
                syscall_bail!("Failed to call ClientToScreen()");
            }
        }
        Ok(point.to_point())
    }

    /// Calls `ScreenToClient()` internally. Converts the screen coordinates to window client area
    /// coordinates.
    pub fn screen_to_client(&self, point: Point) -> Result<Point> {
        let mut point = point.to_sys_point();

        // SAFETY:
        // Safe because:
        // 1. point is stack allocated & lives as long as the function call.
        // 2. the window handle is guaranteed valid by self.
        // 3. we check the error before using the output data.
        unsafe {
            let res = ScreenToClient(self.hwnd, point.as_mut_ptr());
            if res == 0 {
                syscall_bail!("failed to convert cursor position to client coordinates");
            }
        }
        Ok(Point2D::new(point.x, point.y))
    }

    /// Calls `MonitorFromWindow()` internally. If the window is not on any active display monitor,
    /// returns the handle to the closest one.
    pub fn get_nearest_monitor_handle(&self) -> HMONITOR {
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND.
        unsafe { MonitorFromWindow(self.hwnd, MONITOR_DEFAULTTONEAREST) }
    }

    /// Calls `MonitorFromWindow()` internally. If the window is not on any active display monitor,
    /// returns the info of the closest one.
    pub fn get_monitor_info(&self) -> Result<MonitorInfo> {
        // SAFETY:
        // Safe because `get_nearest_monitor_handle()` always returns a valid monitor handle.
        unsafe { MonitorInfo::new(self.get_nearest_monitor_handle()) }
    }

    /// Calls `MonitorFromWindow()` internally.
    pub fn is_on_active_display(&self) -> bool {
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND.
        unsafe { !MonitorFromWindow(self.hwnd, MONITOR_DEFAULTTONULL).is_null() }
    }

    /// Calls `SetWindowPos()` internally.
    pub fn set_pos(&self, window_rect: &Rect, flags: u32) -> Result<()> {
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND, and failures are handled below.
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
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND.
        unsafe {
            ShowWindow(self.hwnd, SW_SHOW);
        }
    }

    /// Calls `SetWindowPos()` internally. Returns false if the window is already hidden and thus
    /// this operation is skipped.
    pub fn hide_if_visible(&self) -> Result<bool> {
        Ok(if self.is_visible()? {
            self.set_pos(
                &Rect::zero(),
                SWP_HIDEWINDOW | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER,
            )?;
            true
        } else {
            false
        })
    }

    /// Calls `ShowWindow()` internally to restore a minimized window.
    pub fn restore(&self) {
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND.
        unsafe {
            ShowWindow(self.hwnd, SW_RESTORE);
        }
    }

    /// Calls `IsZoomed()` internally. Note that the window may carry the WS_MAXIMIZE flag until it
    /// is restored. For example, if we have switched from maximized to fullscreen, this function
    /// would still return true.
    pub fn was_maximized(&self) -> bool {
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND.
        unsafe { IsZoomed(self.hwnd) != 0 }
    }

    /// Calls `IsWindowVisible()` internally. We also require that the window size is nonzero to be
    /// considered visible.
    pub fn is_visible(&self) -> Result<bool> {
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND.
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

    /// Calls `GetForegroundWindow()` internally. A foreground window is the window with which the
    /// user is currently working. It might belong to a different thread/process than the calling
    /// thread.
    pub fn is_global_foreground_window(&self) -> bool {
        // SAFETY:
        // Safe because there is no argument.
        unsafe { GetForegroundWindow() == self.hwnd }
    }

    /// Calls `GetActiveWindow()` internally. An active window is the window with which the user is
    /// currently working and is attached to the calling thread's message queue. It is possible that
    /// there is no active window if the foreground focus is on another thread/process.
    pub fn is_thread_foreground_window(&self) -> bool {
        // SAFETY:
        // Safe because there is no argument.
        unsafe { GetActiveWindow() == self.hwnd }
    }

    /// Calls `IsIconic()` internally.
    pub fn is_minimized(&self) -> bool {
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND.
        unsafe { IsIconic(self.hwnd) != 0 }
    }

    /// Calls `SetForegroundWindow()` internally. `SetForegroundWindow()` may fail, for example,
    /// when the taskbar is in the foreground, hence this is a best-effort call.
    pub fn bring_to_foreground(&self) {
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND.
        if unsafe { SetForegroundWindow(self.hwnd) } == 0 {
            info!("Cannot bring the window to foreground.");
        }
    }

    /// Calls `DwmEnableBlurBehindWindow()` internally. This is only used for a top-level window.
    /// Even though the name of Windows API suggests that it blurs the background, beginning with
    /// Windows 8, it does not blur it, but only makes the window semi-transparent.
    pub fn set_backgound_transparency(&self, semi_transparent: bool) -> Result<()> {
        let blur_behind = DWM_BLURBEHIND {
            dwFlags: DWM_BB_ENABLE,
            fEnable: if semi_transparent { TRUE } else { FALSE },
            hRgnBlur: null_mut(),
            fTransitionOnMaximized: FALSE,
        };
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND, we know `blur_behind` is valid,
        // and failures are handled below.
        let errno = unsafe { DwmEnableBlurBehindWindow(self.hwnd, &blur_behind) };
        match errno {
            0 => Ok(()),
            _ => bail!(
                "Failed to call DwmEnableBlurBehindWindow() when setting \
                window background transparency to {} (Error code {})",
                semi_transparent,
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
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND, we know `window_rect` is valid,
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
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND, we know `window_placement` is
        // valid, and failures are handled below.
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
        // SAFETY:
        // Safe because `GuiWindow` object won't outlive the HWND.
        unsafe {
            if PostMessageW(self.hwnd, msg, w_param, l_param) == 0 {
                syscall_bail!("Failed to call PostMessageW()");
            }
        }
        Ok(())
    }

    /// Calls `LoadIconW()` internally.
    pub(crate) fn load_custom_icon(hinstance: HINSTANCE, resource_id: WORD) -> Result<HICON> {
        // SAFETY:
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
    pub(crate) fn load_system_cursor(cursor_id: LPCWSTR) -> Result<HCURSOR> {
        // SAFETY:
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
    pub(crate) fn create_opaque_black_brush() -> Result<HBRUSH> {
        // SAFETY:
        // Safe because we handle failures below.
        unsafe {
            let hobject = GetStockObject(BLACK_BRUSH as i32);
            if hobject.is_null() {
                syscall_bail!("Failed to call GetStockObject()");
            }
            Ok(hobject as HBRUSH)
        }
    }

    /// Calls `RegisterTouchWindow()` internally.
    fn register_touch(&self) {
        // SAFETY: Safe because `GuiWindow` object won't outlive the HWND.
        if unsafe { RegisterTouchWindow(self.handle(), 0) } == 0 {
            // For now, we register touch only to get stats. It is ok if the registration fails.
            // SAFETY: trivially-safe
            warn!("failed to register touch: {}", unsafe { GetLastError() });
        }
    }
}

impl BasicWindow for GuiWindow {
    /// # Safety
    /// The returned handle should be used carefully, since it may have become invalid if it
    /// outlives the `GuiWindow` object.
    unsafe fn handle(&self) -> HWND {
        self.hwnd
    }
}

/// A message-only window is always invisible, and is only responsible for sending and receiving
/// messages. The owner of `MessageOnlyWindow` object is responsible for dropping it before the
/// underlying window is completely gone.
pub(crate) struct MessageOnlyWindow {
    hwnd: HWND,
}

impl MessageOnlyWindow {
    /// # Safety
    /// The owner of `MessageOnlyWindow` object is responsible for dropping it before we finish
    /// processing `WM_NCDESTROY`, because the window handle will become invalid afterwards.
    pub unsafe fn new(class_name: &str, title: &str) -> Result<Self> {
        info!("Creating message-only window");
        static CONTEXT_MESSAGE: &str = "When creating MessageOnlyWindow";

        let window = Self {
            hwnd: create_sys_window(
                get_current_module_handle(),
                class_name,
                title,
                /* dw_style */ 0,
                HWND_MESSAGE,
                /* initial_window_size */ &size2(0, 0),
            )
            .context(CONTEXT_MESSAGE)?,
        };
        window.register_raw_input_mouse().context(CONTEXT_MESSAGE)?;
        Ok(window)
    }

    /// Registers this window as the receiver of raw mouse input events.
    ///
    /// On Windows, an application can only have one window that receives raw input events, so we
    /// make `MessageOnlyWindow` take on this role and reroute events to the foreground `GuiWindow`.
    fn register_raw_input_mouse(&self) -> Result<()> {
        let mouse_device = RAWINPUTDEVICE {
            usUsagePage: 1, // Generic
            usUsage: 2,     // Mouse
            dwFlags: 0,
            // SAFETY: Safe because `self` won't outlive the HWND.
            hwndTarget: unsafe { self.handle() },
        };
        // SAFETY: Safe because `mouse_device` lives longer than this function call.
        if unsafe {
            RegisterRawInputDevices(
                &mouse_device as PCRAWINPUTDEVICE,
                1,
                mem::size_of::<RAWINPUTDEVICE>() as u32,
            )
        } == 0
        {
            syscall_bail!("Relative mouse is broken. Failed to call RegisterRawInputDevices()");
        }
        Ok(())
    }
}

impl BasicWindow for MessageOnlyWindow {
    /// # Safety
    /// The returned handle should be used carefully, since it may have become invalid if it
    /// outlives the `MessageOnlyWindow` object.
    unsafe fn handle(&self) -> HWND {
        self.hwnd
    }
}

/// Calls `CreateWindowExW()` internally.
fn create_sys_window(
    hinstance: HINSTANCE,
    class_name: &str,
    title: &str,
    dw_style: DWORD,
    hwnd_parent: HWND,
    initial_window_size: &Size2D<i32, HostWindowSpace>,
) -> Result<HWND> {
    // SAFETY:
    // Safe because we handle failures below.
    let hwnd = unsafe {
        CreateWindowExW(
            /* dwExStyle */ 0,
            win32_wide_string(class_name).as_ptr(),
            win32_wide_string(title).as_ptr(),
            dw_style,
            /* x */ 0,
            /* y */ 0,
            initial_window_size.width,
            initial_window_size.height,
            hwnd_parent,
            /* hMenu */ null_mut(),
            hinstance,
            /* lpParam */ null_mut(),
        )
    };
    if hwnd.is_null() {
        syscall_bail!("Failed to call CreateWindowExW()");
    }
    info!("Created window {:p}", hwnd);
    Ok(hwnd)
}

/// Calls `GetModuleHandleW()` internally.
pub(crate) fn get_current_module_handle() -> HMODULE {
    // SAFETY:
    // Safe because we handle failures below.
    let hmodule = unsafe { GetModuleHandleW(null_mut()) };
    if hmodule.is_null() {
        // If it fails, we are in a very broken state and it doesn't make sense to keep running.
        panic!(
            "Failed to call GetModuleHandleW() for the current module (Error code {})",
            // SAFETY: trivially safe
            unsafe { GetLastError() }
        );
    }
    hmodule
}

/// If the resolution/orientation of the monitor changes, or if the monitor is unplugged, this must
/// be recreated with a valid HMONITOR.
pub struct MonitorInfo {
    pub hmonitor: HMONITOR,
    pub display_rect: Rect,
    pub work_rect: Rect,
    raw_dpi: i32,
    // Whether we are running in a Remote Desktop Protocol (RDP) session. The monitor DPI returned
    // by `GetDpiForMonitor()` may not make sense in that case. For example, the DPI is always 25
    // under Chrome Remote Desktop, which is way lower than the standard DPI 96. This might be a
    // flaw in RDP itself. We have to override the DPI in that case, otherwise the guest DPI
    // calculated based on it would be too low as well.
    // https://learn.microsoft.com/en-us/troubleshoot/windows-server/shell-experience/dpi-adjustment-unavailable-in-rdp
    is_rdp_session: bool,
}

impl MonitorInfo {
    /// # Safety
    /// Caller is responsible for ensuring that `hmonitor` is a valid handle.
    pub unsafe fn new(hmonitor: HMONITOR) -> Result<Self> {
        let monitor_info: MONITORINFO =
            Self::get_monitor_info(hmonitor).context("When creating MonitorInfo")?;
        // Docs state that apart from `GetSystemMetrics(SM_REMOTESESSION)`, we also need to check
        // registry entries to see if we are running in a remote session that uses RemoteFX vGPU:
        // https://learn.microsoft.com/en-us/windows/win32/termserv/detecting-the-terminal-services-environment
        // However, RemoteFX vGPU was then removed because of security vulnerabilities:
        // https://support.microsoft.com/en-us/topic/kb4570006-update-to-disable-and-remove-the-remotefx-vgpu-component-in-windows-bbdf1531-7188-2bf4-0de6-641de79f09d2
        // So, we are only calling `GetSystemMetrics(SM_REMOTESESSION)` here until this changes in
        // the future.
        // SAFETY:
        // Safe because no memory management is needed for arguments.
        let is_rdp_session = unsafe { GetSystemMetrics(SM_REMOTESESSION) != 0 };
        Ok(Self {
            hmonitor,
            display_rect: monitor_info.rcMonitor.to_rect(),
            work_rect: monitor_info.rcWork.to_rect(),
            raw_dpi: Self::get_monitor_dpi(hmonitor),
            is_rdp_session,
        })
    }

    pub fn get_dpi(&self) -> i32 {
        if self.is_rdp_session {
            // Override the DPI since the system may not tell us the correct value in RDP sessions.
            DEFAULT_HOST_DPI
        } else {
            self.raw_dpi
        }
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
    fn get_monitor_dpi(hmonitor: HMONITOR) -> i32 {
        let mut dpi_x = 0;
        let mut dpi_y = 0;
        // SAFETY:
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
            "{{hmonitor: {:p}, display_rect: {:?}, work_rect: {:?}, DPI: {}{}}}",
            self.hmonitor,
            self.display_rect,
            self.work_rect,
            self.get_dpi(),
            if self.is_rdp_session {
                format!(" (raw value: {}, overriden due to RDP)", self.raw_dpi)
            } else {
                String::new()
            }
        )
    }
}
