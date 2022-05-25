// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Definitions and utilities for GPU related parameters.

use super::GpuMode;
use rutabaga_gfx::RutabagaWsi;

use serde::{Deserialize, Serialize};

pub const DEFAULT_DISPLAY_WIDTH: u32 = 1280;
pub const DEFAULT_DISPLAY_HEIGHT: u32 = 1024;

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct DisplayParameters {
    pub width: u32,
    pub height: u32,
}

impl Default for DisplayParameters {
    fn default() -> Self {
        DisplayParameters {
            width: DEFAULT_DISPLAY_WIDTH,
            height: DEFAULT_DISPLAY_HEIGHT,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct GpuParameters {
    pub displays: Vec<DisplayParameters>,
    pub renderer_use_egl: bool,
    pub renderer_use_gles: bool,
    pub renderer_use_glx: bool,
    pub renderer_use_surfaceless: bool,
    pub gfxstream_use_guest_angle: bool,
    pub gfxstream_use_syncfd: bool,
    pub use_vulkan: bool,
    pub gfxstream_support_gles31: bool,
    pub wsi: Option<RutabagaWsi>,
    pub udmabuf: bool,
    pub mode: GpuMode,
    pub cache_path: Option<String>,
    pub cache_size: Option<String>,
    pub context_mask: u64,
}

impl Default for GpuParameters {
    fn default() -> Self {
        GpuParameters {
            displays: vec![],
            renderer_use_egl: true,
            renderer_use_gles: true,
            renderer_use_glx: false,
            renderer_use_surfaceless: true,
            gfxstream_use_guest_angle: false,
            gfxstream_use_syncfd: true,
            use_vulkan: false,
            mode: if cfg!(feature = "virgl_renderer") {
                GpuMode::ModeVirglRenderer
            } else {
                GpuMode::Mode2D
            },
            gfxstream_support_gles31: true,
            wsi: None,
            cache_path: None,
            cache_size: None,
            udmabuf: false,
            context_mask: 0,
        }
    }
}
