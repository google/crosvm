// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::marker::PhantomData;

use base::info;
use serde::Deserialize;
use serde::Serialize;
use winapi::um::winuser::GetSystemMetrics;
use winapi::um::winuser::SM_CXSCREEN;
use winapi::um::winuser::SM_CYSCREEN;

use crate::gpu::DisplayModeTrait;

const DISPLAY_WIDTH_SOFT_MAX: u32 = 1920;
const DISPLAY_HEIGHT_SOFT_MAX: u32 = 1080;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WinDisplayMode<T> {
    Windowed(u32, u32),
    BorderlessFullScreen(PhantomData<T>),
}

impl<T> DisplayModeTrait for WinDisplayMode<T> {
    fn get_virtual_display_size(&self) -> (u32, u32) {
        let (width, height) = match self {
            Self::Windowed(width, height) => (*width, *height),
            Self::BorderlessFullScreen(_) => {
                let (width, height) = DisplayDataProvider::get_host_display_size();
                adjust_virtual_display_size(width, height)
            }
        };
        info!("Guest display size: {}x{}", width, height);
        (width, height)
    }
}

impl<T> From<WinDisplayMode<T>> for WinDisplayModeArg {
    fn from(mode: WinDisplayMode<T>) -> WinDisplayModeArg {
        match mode {
            WinDisplayMode::Windowed { .. } => WinDisplayModeArg::Windowed,
            WinDisplayMode::BorderlessFullScreen(_) => WinDisplayModeArg::BorderlessFullScreen,
        }
    }
}

/// Trait for returning host display data such as resolution. Tests may overwrite this to specify
/// display data rather than rely on properties of the actual display device.
trait ProvideDisplayData {
    fn get_host_display_size() -> (u32, u32);
}

#[derive(Clone, Copy, Debug)]
pub struct DisplayDataProvider;

impl ProvideDisplayData for DisplayDataProvider {
    fn get_host_display_size() -> (u32, u32) {
        // Safe because we're passing valid values and screen size won't exceed u32 range.
        let (width, height) = unsafe {
            (
                GetSystemMetrics(SM_CXSCREEN) as u32,
                GetSystemMetrics(SM_CYSCREEN) as u32,
            )
        };
        // Note: This is the size of the host's display. The guest display size given by
        // (width, height) may be smaller if we are letterboxing.
        info!("Host display size: {}x{}", width, height);
        (width, height)
    }
}

fn adjust_virtual_display_size(width: u32, height: u32) -> (u32, u32) {
    let width = std::cmp::min(width, DISPLAY_WIDTH_SOFT_MAX);
    let height = std::cmp::min(height, DISPLAY_HEIGHT_SOFT_MAX);
    // Widths that aren't a multiple of 8 break gfxstream: b/156110663.
    let width = width - (width % 8);
    (width, height)
}
