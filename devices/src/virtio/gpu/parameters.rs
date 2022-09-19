// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Definitions and utilities for GPU related parameters.

#[cfg(windows)]
use std::marker::PhantomData;

use rutabaga_gfx::RutabagaWsi;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde_keyvalue::FromKeyValues;

pub use super::sys::DisplayMode;
use super::sys::DisplayModeArg;
use super::GpuMode;

pub const DEFAULT_DISPLAY_WIDTH: u32 = 1280;
pub const DEFAULT_DISPLAY_HEIGHT: u32 = 1024;
pub const DEFAULT_REFRESH_RATE: u32 = 60;

/// Trait that the platform-specific type `DisplayMode` needs to implement.
pub trait DisplayModeTrait {
    fn get_virtual_display_size(&self) -> (u32, u32);
}

// This struct is only used for argument parsing. It will be converted to platform-specific
// `DisplayParameters` implementation.
#[derive(Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct DisplayParametersArgs {
    pub mode: Option<DisplayModeArg>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default = "default_refresh_rate")]
    pub refresh_rate: u32,
}

#[derive(Clone, Debug, Deserialize, FromKeyValues)]
#[serde(try_from = "DisplayParametersArgs")]
pub struct DisplayParameters {
    pub mode: DisplayMode,
    pub hidden: bool,
    pub refresh_rate: u32,
}

impl DisplayParameters {
    pub fn new(mode: DisplayMode, hidden: bool, refresh_rate: u32) -> Self {
        Self {
            mode,
            hidden,
            refresh_rate,
        }
    }

    pub fn default_with_mode(mode: DisplayMode) -> Self {
        Self::new(mode, false, DEFAULT_REFRESH_RATE)
    }

    pub fn get_virtual_display_size(&self) -> (u32, u32) {
        self.mode.get_virtual_display_size()
    }
}

impl Default for DisplayParameters {
    fn default() -> Self {
        Self::default_with_mode(default_windowed_mode())
    }
}

impl TryFrom<DisplayParametersArgs> for DisplayParameters {
    type Error = String;

    fn try_from(args: DisplayParametersArgs) -> Result<Self, Self::Error> {
        let mode = match args.mode.unwrap_or(DisplayModeArg::Windowed) {
            DisplayModeArg::Windowed => match (args.width, args.height) {
                (Some(width), Some(height)) => DisplayMode::Windowed { width, height },
                (None, None) => default_windowed_mode(),
                _ => {
                    return Err(
                        "must include both 'width' and 'height' if either is supplied".to_string(),
                    )
                }
            },

            #[cfg(windows)]
            DisplayModeArg::BorderlessFullScreen => match (args.width, args.height) {
                (None, None) => DisplayMode::BorderlessFullScreen(PhantomData),
                _ => return Err("'width' and 'height' are invalid with borderless_full_screen"),
            },
        };

        Ok(DisplayParameters::new(mode, args.hidden, args.refresh_rate))
    }
}

fn default_windowed_mode() -> DisplayMode {
    DisplayMode::Windowed {
        width: DEFAULT_DISPLAY_WIDTH,
        height: DEFAULT_DISPLAY_HEIGHT,
    }
}

fn default_refresh_rate() -> u32 {
    DEFAULT_REFRESH_RATE
}

mod serde_context_mask {
    use super::*;

    pub fn serialize<S>(context_mask: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let context_types = rutabaga_gfx::calculate_context_types(*context_mask).join(":");

        serializer.serialize_str(context_types.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let s = String::deserialize(deserializer)?;
        let context_types: Vec<String> = s.split(':').map(|s| s.to_string()).collect();

        Ok(rutabaga_gfx::calculate_context_mask(context_types))
    }
}

#[derive(Debug, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct GpuParameters {
    #[serde(rename = "backend")]
    pub mode: GpuMode,
    #[serde(skip)]
    pub display_params: Vec<DisplayParameters>,
    // `width` and `height` are supported for CLI backwards compatibility.
    #[serde(rename = "width")]
    pub __width_compat: Option<u32>,
    #[serde(rename = "height")]
    pub __height_compat: Option<u32>,
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
    pub wsi: Option<RutabagaWsi>,
    pub udmabuf: bool,
    pub cache_path: Option<String>,
    pub cache_size: Option<String>,
    pub pci_bar_size: u64,
    #[serde(rename = "context-types", with = "serde_context_mask")]
    pub context_mask: u64,
}

impl Default for GpuParameters {
    fn default() -> Self {
        GpuParameters {
            display_params: vec![],
            __width_compat: None,
            __height_compat: None,
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

#[cfg(test)]
mod tests {
    use serde_json::*;

    use super::*;

    #[test]
    fn context_mask_serialize_deserialize() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct ContextMask {
            #[serde(rename = "context-types", with = "serde_context_mask")]
            pub value: u64,
        }

        // Capset "virgl", id: 1, context_mask: 0b0010
        // Capset "gfxstream", id: 3, context_mask: 0b1000
        const CONTEXT_MASK: u64 = 0b1010;
        const SERIALIZED_CONTEXT_MASK: &str = "{\"context-types\":\"virgl:gfxstream\"}";

        let context_mask = ContextMask {
            value: CONTEXT_MASK,
        };

        assert_eq!(to_string(&context_mask).unwrap(), SERIALIZED_CONTEXT_MASK);
        assert_eq!(
            from_str::<ContextMask>(SERIALIZED_CONTEXT_MASK).unwrap(),
            context_mask
        );
    }
}
