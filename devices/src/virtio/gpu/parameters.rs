// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Definitions and utilities for GPU related parameters.

#[cfg(windows)]
use std::marker::PhantomData;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde_keyvalue::FromKeyValues;
use vm_control::gpu::DisplayParameters;

use super::GpuMode;
use super::GpuWsi;
use crate::virtio::gpu::VIRTIO_GPU_MAX_SCANOUTS;
use crate::PciAddress;

mod serde_capset_mask {
    use super::*;

    pub fn serialize<S>(capset_mask: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let context_types = rutabaga_gfx::calculate_capset_names(*capset_mask).join(":");

        serializer.serialize_str(context_types.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(rutabaga_gfx::calculate_capset_mask(s.split(':')))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, default, rename_all = "kebab-case")]
pub struct GpuParameters {
    #[serde(rename = "backend")]
    pub mode: GpuMode,
    #[serde(default = "default_max_num_displays")]
    pub max_num_displays: u32,
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
    #[serde(rename = "vulkan")]
    pub use_vulkan: Option<bool>,
    pub wsi: Option<GpuWsi>,
    pub udmabuf: bool,
    pub cache_path: Option<String>,
    pub cache_size: Option<String>,
    pub pci_address: Option<PciAddress>,
    pub pci_bar_size: u64,
    #[serde(rename = "context-types", with = "serde_capset_mask")]
    pub capset_mask: u64,
    // enforce that blob resources MUST be exportable as file descriptors
    pub external_blob: bool,
    pub system_blob: bool,
    // enable use of descriptor mapping to fixed host VA within a prepared vMMU mapping (e.g. kvm
    // user memslot)
    pub fixed_blob_mapping: bool,
    #[serde(rename = "implicit-render-server")]
    pub allow_implicit_render_server_exec: bool,
    // Passthrough parameters sent to the underlying renderer in a renderer-specific format.
    pub renderer_features: Option<String>,
}

impl Default for GpuParameters {
    fn default() -> Self {
        GpuParameters {
            max_num_displays: default_max_num_displays(),
            display_params: vec![],
            __width_compat: None,
            __height_compat: None,
            renderer_use_egl: true,
            renderer_use_gles: true,
            renderer_use_glx: false,
            renderer_use_surfaceless: true,
            use_vulkan: None,
            mode: Default::default(),
            wsi: None,
            cache_path: None,
            cache_size: None,
            pci_address: None,
            pci_bar_size: (1 << 33),
            udmabuf: false,
            capset_mask: 0,
            external_blob: false,
            system_blob: false,
            // TODO(b/324649619): not yet fully compatible with other platforms (windows)
            // TODO(b/246334944): gfxstream may map vulkan opaque blobs directly (without vulkano),
            // so set the default to disabled when built with the gfxstream feature.
            fixed_blob_mapping: cfg!(target_os = "linux") && !cfg!(feature = "gfxstream"),
            allow_implicit_render_server_exec: false,
            renderer_features: None,
        }
    }
}

fn default_max_num_displays() -> u32 {
    VIRTIO_GPU_MAX_SCANOUTS as u32
}

#[cfg(test)]
mod tests {
    use serde_json::*;

    use super::*;

    #[test]
    fn capset_mask_serialize_deserialize() {
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        struct CapsetMask {
            #[serde(rename = "context-types", with = "serde_capset_mask")]
            pub value: u64,
        }

        // Capset "virgl", id: 1, capset_mask: 0b0010
        // Capset "gfxstream", id: 3, capset_mask: 0b1000
        const CAPSET_MASK: u64 = 0b1010;
        const SERIALIZED_CAPSET_MASK: &str = "{\"context-types\":\"virgl:gfxstream-vulkan\"}";

        let capset_mask = CapsetMask { value: CAPSET_MASK };

        assert_eq!(to_string(&capset_mask).unwrap(), SERIALIZED_CAPSET_MASK);
        assert_eq!(
            from_str::<CapsetMask>(SERIALIZED_CAPSET_MASK).unwrap(),
            capset_mask
        );
    }
}
