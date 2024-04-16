// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap as Map;
use std::fmt;
use std::fmt::Display;
use std::path::Path;

use serde::Deserialize;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;

pub use crate::sys::handle_request;
pub use crate::sys::DisplayMode;
pub use crate::sys::MouseMode;
pub use crate::*;

pub const DEFAULT_DISPLAY_WIDTH: u32 = 1280;
pub const DEFAULT_DISPLAY_HEIGHT: u32 = 1024;
pub const DEFAULT_DPI: u32 = 320;
pub const DEFAULT_REFRESH_RATE: u32 = 60;

fn default_refresh_rate() -> u32 {
    DEFAULT_REFRESH_RATE
}

/// Trait that the platform-specific type `DisplayMode` needs to implement.
pub(crate) trait DisplayModeTrait {
    /// Returns the initial host window size.
    fn get_window_size(&self) -> (u32, u32);

    /// Returns the virtual display size used for creating the display device.
    ///
    /// We need to query the phenotype flags to see if resolutions higher than 1080p should be
    /// enabled. This functions assumes process invariants have been set up and phenotype flags are
    /// available. If not, use `get_virtual_display_size_4k_uhd()` instead.
    ///
    /// This may be different from the initial host window size since different display backends may
    /// have different alignment requirements on it.
    fn get_virtual_display_size(&self) -> (u32, u32);

    /// Returns the virtual display size used for creating the display device.
    ///
    /// While `get_virtual_display_size()` reads phenotype flags internally, this function does not,
    /// so it can be used when process invariants and phenotype flags are not yet ready.
    fn get_virtual_display_size_4k_uhd(&self, is_4k_uhd_enabled: bool) -> (u32, u32);
}

impl Default for DisplayMode {
    fn default() -> Self {
        Self::Windowed(DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DisplayParameters {
    #[serde(default)]
    pub mode: DisplayMode,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default = "default_refresh_rate")]
    pub refresh_rate: u32,
    // TODO(b/260101753): `dpi` has to be an `Option` for supporting CLI backward compatibility.
    // That should be changed once compat fields below are deprecated.
    pub dpi: Option<(u32, u32)>,
    // `horizontal-dpi` and `vertical-dpi` are supported for CLI backward compatibility.
    #[serde(rename = "horizontal-dpi")]
    pub __horizontal_dpi_compat: Option<u32>,
    #[serde(rename = "vertical-dpi")]
    pub __vertical_dpi_compat: Option<u32>,
}

impl DisplayParameters {
    pub fn new(
        mode: DisplayMode,
        hidden: bool,
        refresh_rate: u32,
        horizontal_dpi: u32,
        vertical_dpi: u32,
    ) -> Self {
        Self {
            mode,
            hidden,
            refresh_rate,
            dpi: Some((horizontal_dpi, vertical_dpi)),
            __horizontal_dpi_compat: None,
            __vertical_dpi_compat: None,
        }
    }

    pub fn default_with_mode(mode: DisplayMode) -> Self {
        Self::new(mode, false, DEFAULT_REFRESH_RATE, DEFAULT_DPI, DEFAULT_DPI)
    }

    pub fn get_window_size(&self) -> (u32, u32) {
        self.mode.get_window_size()
    }

    pub fn get_virtual_display_size(&self) -> (u32, u32) {
        self.mode.get_virtual_display_size()
    }

    pub fn get_virtual_display_size_4k_uhd(&self, is_4k_uhd_enabled: bool) -> (u32, u32) {
        self.mode.get_virtual_display_size_4k_uhd(is_4k_uhd_enabled)
    }

    pub fn horizontal_dpi(&self) -> u32 {
        self.dpi.expect("'dpi' is None").0
    }

    pub fn vertical_dpi(&self) -> u32 {
        self.dpi.expect("'dpi' is None").1
    }
}

impl Default for DisplayParameters {
    fn default() -> Self {
        Self::default_with_mode(Default::default())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum GpuControlCommand {
    AddDisplays {
        displays: Vec<DisplayParameters>,
    },
    ListDisplays,
    RemoveDisplays {
        display_ids: Vec<u32>,
    },
    SetDisplayMouseMode {
        display_id: u32,
        mouse_mode: MouseMode,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum GpuControlResult {
    DisplaysUpdated,
    DisplayList {
        displays: Map<u32, DisplayParameters>,
    },
    TooManyDisplays {
        allowed: usize,
        requested: usize,
    },
    NoSuchDisplay {
        display_id: u32,
    },
    DisplayMouseModeSet,
    ErrString(String),
}

impl Display for GpuControlResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::GpuControlResult::*;

        match self {
            DisplaysUpdated => write!(f, "displays updated"),
            DisplayList { displays } => {
                let json: serde_json::Value = serde_json::json!({
                    "displays": displays,
                });
                let json_pretty =
                    serde_json::to_string_pretty(&json).map_err(|_| std::fmt::Error)?;
                write!(f, "{}", json_pretty)
            }
            TooManyDisplays { allowed, requested } => write!(
                f,
                "too_many_displays: allowed {}, requested {}",
                allowed, requested
            ),
            NoSuchDisplay { display_id } => write!(f, "no_such_display {}", display_id),
            DisplayMouseModeSet => write!(f, "display_mouse_mode_set"),
            ErrString(reason) => write!(f, "err_string {}", reason),
        }
    }
}

pub enum ModifyGpuError {
    SocketFailed,
    UnexpectedResponse(VmResponse),
    UnknownCommand(String),
    GpuControl(GpuControlResult),
}

impl fmt::Display for ModifyGpuError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ModifyGpuError::*;

        match self {
            SocketFailed => write!(f, "socket failed"),
            UnexpectedResponse(r) => write!(f, "unexpected response: {}", r),
            UnknownCommand(c) => write!(f, "unknown display command: `{}`", c),
            GpuControl(e) => write!(f, "{}", e),
        }
    }
}

pub type ModifyGpuResult = std::result::Result<GpuControlResult, ModifyGpuError>;

impl From<VmResponse> for ModifyGpuResult {
    fn from(response: VmResponse) -> Self {
        match response {
            VmResponse::GpuResponse(gpu_response) => Ok(gpu_response),
            r => Err(ModifyGpuError::UnexpectedResponse(r)),
        }
    }
}

pub fn do_gpu_display_add<T: AsRef<Path> + std::fmt::Debug>(
    control_socket_path: T,
    displays: Vec<DisplayParameters>,
) -> ModifyGpuResult {
    let request = VmRequest::GpuCommand(GpuControlCommand::AddDisplays { displays });
    handle_request(&request, control_socket_path)
        .map_err(|_| ModifyGpuError::SocketFailed)?
        .into()
}

pub fn do_gpu_display_list<T: AsRef<Path> + std::fmt::Debug>(
    control_socket_path: T,
) -> ModifyGpuResult {
    let request = VmRequest::GpuCommand(GpuControlCommand::ListDisplays);
    handle_request(&request, control_socket_path)
        .map_err(|_| ModifyGpuError::SocketFailed)?
        .into()
}

pub fn do_gpu_display_remove<T: AsRef<Path> + std::fmt::Debug>(
    control_socket_path: T,
    display_ids: Vec<u32>,
) -> ModifyGpuResult {
    let request = VmRequest::GpuCommand(GpuControlCommand::RemoveDisplays { display_ids });
    handle_request(&request, control_socket_path)
        .map_err(|_| ModifyGpuError::SocketFailed)?
        .into()
}

pub fn do_gpu_set_display_mouse_mode<T: AsRef<Path> + std::fmt::Debug>(
    control_socket_path: T,
    display_id: u32,
    mouse_mode: MouseMode,
) -> ModifyGpuResult {
    let request = VmRequest::GpuCommand(GpuControlCommand::SetDisplayMouseMode {
        display_id,
        mouse_mode,
    });
    handle_request(&request, control_socket_path)
        .map_err(|_| ModifyGpuError::SocketFailed)?
        .into()
}
