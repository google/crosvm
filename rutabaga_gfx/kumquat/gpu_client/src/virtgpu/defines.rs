// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::raw::c_void;

pub const VIRTGPU_KUMQUAT_PARAM_3D_FEATURES: u64 = 1;
pub const VIRTGPU_KUMQUAT_PARAM_CAPSET_QUERY_FIX: u64 = 2;
#[allow(unused)]
pub const VIRTGPU_KUMQUAT_PARAM_RESOURCE_BLOB: u64 = 3;
#[allow(unused)]
pub const VIRTGPU_KUMQUAT_PARAM_HOST_VISIBLE: u64 = 4;
#[allow(unused)]
pub const VIRTGPU_KUMQUAT_PARAM_CROSS_DEVICE: u64 = 5;
pub const VIRTGPU_KUMQUAT_PARAM_CONTEXT_INIT: u64 = 6;
pub const VIRTGPU_KUMQUAT_PARAM_SUPPORTED_CAPSET_IDS: u64 = 7;

#[allow(unused)]
pub const VIRTGPU_KUMQUAT_EXECBUF_FENCE_FD_IN: u32 = 0x01;
#[allow(unused)]
pub const VIRTGPU_KUMQUAT_EXECBUF_FENCE_FD_OUT: u32 = 0x02;
#[allow(unused)]
pub const VIRTGPU_KUMQUAT_EXECBUF_RING_IDX: u32 = 0x04;

#[allow(unused)]
pub const VIRTGPU_KUMQUAT_CONTEXT_PARAM_CAPSET_ID: u64 = 0x01;
#[allow(unused)]
pub const VIRTGPU_KUMQUAT_CONTEXT_PARAM_NUM_RINGS: u64 = 0x02;
#[allow(unused)]
pub const VIRTGPU_KUMQUAT_CONTEXT_PARAM_POLL_RING_MASK: u64 = 0x03;

pub const VIRTGPU_KUMQUAT_EMULATED_EXPORT: u32 = 0x01;
pub const VIRTGPU_KUMQUAT_PAGE_SIZE: usize = 4096;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuParam {
    pub param: u64,
    pub value: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuGetCaps {
    pub cap_set_id: u32,
    pub cap_set_ver: u32,
    pub addr: u64,
    pub size: u32,
    pub pad: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuContextInit {
    pub num_params: u32,
    pub pad: u32,
    pub ctx_set_params: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuResourceCreate3D {
    pub target: u32,
    pub format: u32,
    pub bind: u32,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub array_size: u32,
    pub last_level: u32,
    pub nr_samples: u32,
    pub bo_handle: u32,
    pub res_handle: u32,
    pub flags: u32,
    pub size: u32,
    pub stride: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuBox {
    pub x: u32,
    pub y: u32,
    pub z: u32,
    pub w: u32,
    pub h: u32,
    pub d: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuTransfer {
    pub bo_handle: u32,
    pub _box: VirtGpuBox,
    pub level: u32,
    pub offset: u64,
    pub stride: u32,
    pub layer_stride: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuResourceCreateBlob {
    pub blob_mem: u32,
    pub blob_flags: u32,
    pub bo_handle: u32,
    pub res_handle: u32,
    pub size: u64,
    pub pad: u32,
    pub cmd_size: u32,
    pub cmd: u64,
    pub blob_id: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuResourceUnref {
    pub bo_handle: u32,
    pub pad: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuExecBuffer {
    pub flags: u32,
    pub size: u32,
    pub command: u64,
    pub bo_handles: u64,
    pub num_bo_handles: u32,
    pub fence_fd: i32,
    pub ring_idx: u32,
    pub syncobj_stride: u32,
    pub num_in_syncobjs: u32,
    pub num_out_syncobjs: u32,
    pub in_syncobjs: u64,
    pub out_syncobjs: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuWait {
    pub bo_handle: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuResourceMap {
    pub bo_handle: u32,
    pub ptr: *mut c_void,
    pub size: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuResourceExport {
    pub bo_handle: u32,
    pub flags: u32,
    pub os_handle: i64,
    pub handle_type: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VirtGpuResourceImport {
    pub os_handle: i64,
    pub handle_type: u32,
    pub bo_handle: u32,
    pub res_handle: u32,
    pub size: u64,
}
