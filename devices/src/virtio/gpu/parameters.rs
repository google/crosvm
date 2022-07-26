// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Definitions and utilities for GPU related parameters.

use rutabaga_gfx::RutabagaWsi;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;

use super::GpuMode;

pub const DEFAULT_DISPLAY_WIDTH: u32 = 1280;
pub const DEFAULT_DISPLAY_HEIGHT: u32 = 1024;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
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

fn deserialize_wsi<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<RutabagaWsi>, D::Error> {
    let s = String::deserialize(deserializer)?;

    match s.as_str() {
        "vk" => Ok(Some(RutabagaWsi::Vulkan)),
        _ => Err(serde::de::Error::custom(
            "gpu parameter 'wsi' should be vk".to_string(),
        )),
    }
}

fn deserialize_context_mask<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let s = String::deserialize(deserializer)?;
    let context_types: Vec<String> = s.split(':').map(|s| s.to_string()).collect();

    Ok(rutabaga_gfx::calculate_context_mask(context_types))
}

#[derive(Debug, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct GpuParameters {
    #[serde(rename = "backend")]
    pub mode: GpuMode,
    #[serde(skip)]
    pub display_params: Vec<DisplayParameters>,
    #[serde(rename = "egl")]
    pub renderer_use_egl: bool,
    #[serde(rename = "gles")]
    pub renderer_use_gles: bool,
    #[serde(rename = "glx")]
    pub renderer_use_glx: bool,
    #[serde(rename = "surfaceless")]
    pub renderer_use_surfaceless: bool,
    #[serde(rename = "angle")]
    pub gfxstream_use_guest_angle: Option<bool>,
    #[serde(rename = "vulkan")]
    pub use_vulkan: Option<bool>,
    #[serde(skip)]
    pub gfxstream_support_gles31: bool,
    #[serde(deserialize_with = "deserialize_wsi")]
    pub wsi: Option<RutabagaWsi>,
    pub udmabuf: bool,
    pub cache_path: Option<String>,
    pub cache_size: Option<String>,
    pub pci_bar_size: u64,
    #[serde(
        rename = "context-types",
        deserialize_with = "deserialize_context_mask"
    )]
    pub context_mask: u64,
}

impl Default for GpuParameters {
    fn default() -> Self {
        GpuParameters {
            display_params: vec![],
            renderer_use_egl: true,
            renderer_use_gles: true,
            renderer_use_glx: false,
            renderer_use_surfaceless: true,
            gfxstream_use_guest_angle: None,
            use_vulkan: None,
            mode: if cfg!(feature = "virgl_renderer") {
                GpuMode::ModeVirglRenderer
            } else {
                GpuMode::Mode2D
            },
            gfxstream_support_gles31: true,
            wsi: None,
            cache_path: None,
            cache_size: None,
            pci_bar_size: (1 << 33),
            udmabuf: false,
            context_mask: 0,
        }
    }
}
