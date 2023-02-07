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
use vm_control::gpu::DisplayParameters;

use super::GpuMode;

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

#[derive(Clone, Debug, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct GpuParameters {
    #[serde(rename = "backend")]
    pub mode: GpuMode,
    #[serde(rename = "displays")]
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
    #[cfg(feature = "gfxstream")]
    #[serde(rename = "angle")]
    pub gfxstream_use_guest_angle: Option<bool>,
    #[serde(rename = "vulkan")]
    pub use_vulkan: Option<bool>,
    // It is possible that we compile with the gfxstream feature but don't use the gfxstream
    // backend, in which case we want to ensure this option is not touched accidentally, so we make
    // it an `Option` with default value `None`.
    #[cfg(feature = "gfxstream")]
    #[serde(rename = "gles31")]
    pub gfxstream_support_gles31: Option<bool>,
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
            #[cfg(feature = "gfxstream")]
            gfxstream_use_guest_angle: None,
            use_vulkan: None,
            mode: Default::default(),
            #[cfg(feature = "gfxstream")]
            gfxstream_support_gles31: None,
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
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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
