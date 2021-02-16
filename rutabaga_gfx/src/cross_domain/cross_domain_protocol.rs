// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Hand-written protocol for the cross-domain context type.  Intended to be shared with C/C++
//! components.

#![allow(dead_code)]

use data_model::DataInit;

/// Cross-domain commands (only a maximum of 255 supported)
pub const CROSS_DOMAIN_CMD_INIT: u8 = 1;
pub const CROSS_DOMAIN_CMD_GET_IMAGE_REQUIREMENTS: u8 = 2;

/// Channel types (must match rutabaga channel types)
pub const CROSS_DOMAIN_CHANNEL_TYPE_WAYLAND: u32 = 0x0001;
pub const CROSS_DOMAIN_CHANNEL_TYPE_CAMERA: u32 = 0x0002;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CrossDomainCapabilities {
    pub version: u32,
    pub supported_channels: u32,
    pub supports_dmabuf: u32,
    pub supports_external_gpu_memory: u32,
}

unsafe impl DataInit for CrossDomainCapabilities {}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CrossDomainImageRequirements {
    pub strides: [u32; 4],
    pub offsets: [u32; 4],
    pub modifier: u64,
    pub size: u64,
    pub blob_id: u64,
    pub map_info: u32,
    pub pad: u32,
    pub memory_idx: i32,
    pub physical_device_idx: i32,
}

unsafe impl DataInit for CrossDomainImageRequirements {}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CrossDomainHeader {
    pub cmd: u8,
    pub fence_ctx_idx: u8,
    pub cmd_size: u16,
    pub pad: u32,
}

unsafe impl DataInit for CrossDomainHeader {}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CrossDomainInit {
    pub hdr: CrossDomainHeader,
    pub ring_id: u32,
    pub channel_type: u32,
}

unsafe impl DataInit for CrossDomainInit {}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CrossDomainGetImageRequirements {
    pub hdr: CrossDomainHeader,
    pub width: u32,
    pub height: u32,
    pub drm_format: u32,
    pub flags: u32,
}

unsafe impl DataInit for CrossDomainGetImageRequirements {}
