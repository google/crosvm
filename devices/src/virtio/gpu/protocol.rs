// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::cmp::min;
use std::fmt::{self, Display};
use std::marker::PhantomData;
use std::mem::{size_of, size_of_val};
use std::str::from_utf8;

use data_model::{DataInit, Le32, Le64, VolatileMemory, VolatileMemoryError, VolatileSlice};

pub const VIRTIO_GPU_F_VIRGL: u32 = 0;

pub const VIRTIO_GPU_UNDEFINED: u32 = 0x0;

/* 2d commands */
pub const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x100;
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x101;
pub const VIRTIO_GPU_CMD_RESOURCE_UNREF: u32 = 0x102;
pub const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x103;
pub const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x104;
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x105;
pub const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x106;
pub const VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING: u32 = 0x107;
pub const VIRTIO_GPU_CMD_GET_CAPSET_INFO: u32 = 0x108;
pub const VIRTIO_GPU_CMD_GET_CAPSET: u32 = 0x109;

/* 3d commands */
pub const VIRTIO_GPU_CMD_CTX_CREATE: u32 = 0x200;
pub const VIRTIO_GPU_CMD_CTX_DESTROY: u32 = 0x201;
pub const VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE: u32 = 0x202;
pub const VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE: u32 = 0x203;
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_3D: u32 = 0x204;
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D: u32 = 0x205;
pub const VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D: u32 = 0x206;
pub const VIRTIO_GPU_CMD_SUBMIT_3D: u32 = 0x207;

/* cursor commands */
pub const VIRTIO_GPU_CMD_UPDATE_CURSOR: u32 = 0x300;
pub const VIRTIO_GPU_CMD_MOVE_CURSOR: u32 = 0x301;

/* success responses */
pub const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
pub const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;
pub const VIRTIO_GPU_RESP_OK_CAPSET_INFO: u32 = 0x1102;
pub const VIRTIO_GPU_RESP_OK_CAPSET: u32 = 0x1103;
pub const VIRTIO_GPU_RESP_OK_RESOURCE_PLANE_INFO: u32 = 0x1104;

/* error responses */
pub const VIRTIO_GPU_RESP_ERR_UNSPEC: u32 = 0x1200;
pub const VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
pub const VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
pub const VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
pub const VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID: u32 = 0x1204;
pub const VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

pub fn virtio_gpu_cmd_str(cmd: u32) -> &'static str {
    match cmd {
        VIRTIO_GPU_CMD_GET_DISPLAY_INFO => "VIRTIO_GPU_CMD_GET_DISPLAY_INFO",
        VIRTIO_GPU_CMD_RESOURCE_CREATE_2D => "VIRTIO_GPU_CMD_RESOURCE_CREATE_2D",
        VIRTIO_GPU_CMD_RESOURCE_UNREF => "VIRTIO_GPU_CMD_RESOURCE_UNREF",
        VIRTIO_GPU_CMD_SET_SCANOUT => "VIRTIO_GPU_CMD_SET_SCANOUT",
        VIRTIO_GPU_CMD_RESOURCE_FLUSH => "VIRTIO_GPU_CMD_RESOURCE_FLUSH",
        VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D => "VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D",
        VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING => "VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING",
        VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING => "VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING",
        VIRTIO_GPU_CMD_GET_CAPSET_INFO => "VIRTIO_GPU_CMD_GET_CAPSET_INFO",
        VIRTIO_GPU_CMD_GET_CAPSET => "VIRTIO_GPU_CMD_GET_CAPSET",
        VIRTIO_GPU_CMD_CTX_CREATE => "VIRTIO_GPU_CMD_CTX_CREATE",
        VIRTIO_GPU_CMD_CTX_DESTROY => "VIRTIO_GPU_CMD_CTX_DESTROY",
        VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE => "VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE",
        VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE => "VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE",
        VIRTIO_GPU_CMD_RESOURCE_CREATE_3D => "VIRTIO_GPU_CMD_RESOURCE_CREATE_3D",
        VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D => "VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D",
        VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D => "VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D",
        VIRTIO_GPU_CMD_SUBMIT_3D => "VIRTIO_GPU_CMD_SUBMIT_3D",
        VIRTIO_GPU_CMD_UPDATE_CURSOR => "VIRTIO_GPU_CMD_UPDATE_CURSOR",
        VIRTIO_GPU_CMD_MOVE_CURSOR => "VIRTIO_GPU_CMD_MOVE_CURSOR",
        VIRTIO_GPU_RESP_OK_NODATA => "VIRTIO_GPU_RESP_OK_NODATA",
        VIRTIO_GPU_RESP_OK_DISPLAY_INFO => "VIRTIO_GPU_RESP_OK_DISPLAY_INFO",
        VIRTIO_GPU_RESP_OK_CAPSET_INFO => "VIRTIO_GPU_RESP_OK_CAPSET_INFO",
        VIRTIO_GPU_RESP_OK_CAPSET => "VIRTIO_GPU_RESP_OK_CAPSET",
        VIRTIO_GPU_RESP_OK_RESOURCE_PLANE_INFO => "VIRTIO_GPU_RESP_OK_RESOURCE_PLANE_INFO",
        VIRTIO_GPU_RESP_ERR_UNSPEC => "VIRTIO_GPU_RESP_ERR_UNSPEC",
        VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY => "VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY",
        VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID => "VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID",
        VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID => "VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID",
        VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID => "VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID",
        VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER => "VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER",
        _ => "UNKNOWN",
    }
}

pub const VIRTIO_GPU_FLAG_FENCE: u32 = (1 << 0);

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_ctrl_hdr {
    pub type_: Le32,
    pub flags: Le32,
    pub fence_id: Le64,
    pub ctx_id: Le32,
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_ctrl_hdr {}

/* data passed in the cursor vq */

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_cursor_pos {
    pub scanout_id: Le32,
    pub x: Le32,
    pub y: Le32,
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_cursor_pos {}

/* VIRTIO_GPU_CMD_UPDATE_CURSOR, VIRTIO_GPU_CMD_MOVE_CURSOR */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_update_cursor {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub pos: virtio_gpu_cursor_pos, /* update & move */
    pub resource_id: Le32,          /* update only */
    pub hot_x: Le32,                /* update only */
    pub hot_y: Le32,                /* update only */
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_update_cursor {}

/* data passed in the control vq, 2d related */

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct virtio_gpu_rect {
    pub x: Le32,
    pub y: Le32,
    pub width: Le32,
    pub height: Le32,
}

unsafe impl DataInit for virtio_gpu_rect {}

/* VIRTIO_GPU_CMD_RESOURCE_UNREF */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_resource_unref {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub resource_id: Le32,
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_resource_unref {}

/* VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: create a 2d resource with a format */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_resource_create_2d {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub resource_id: Le32,
    pub format: Le32,
    pub width: Le32,
    pub height: Le32,
}

unsafe impl DataInit for virtio_gpu_resource_create_2d {}

/* VIRTIO_GPU_CMD_SET_SCANOUT */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_set_scanout {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub r: virtio_gpu_rect,
    pub scanout_id: Le32,
    pub resource_id: Le32,
}

unsafe impl DataInit for virtio_gpu_set_scanout {}

/* VIRTIO_GPU_CMD_RESOURCE_FLUSH */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_resource_flush {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub r: virtio_gpu_rect,
    pub resource_id: Le32,
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_resource_flush {}

/* VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: simple transfer to_host */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_transfer_to_host_2d {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub r: virtio_gpu_rect,
    pub offset: Le64,
    pub resource_id: Le32,
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_transfer_to_host_2d {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_mem_entry {
    pub addr: Le64,
    pub length: Le32,
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_mem_entry {}

/* VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_resource_attach_backing {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub resource_id: Le32,
    pub nr_entries: Le32,
}

unsafe impl DataInit for virtio_gpu_resource_attach_backing {}

/* VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_resource_detach_backing {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub resource_id: Le32,
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_resource_detach_backing {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct virtio_gpu_display_one {
    pub r: virtio_gpu_rect,
    pub enabled: Le32,
    pub flags: Le32,
}

unsafe impl DataInit for virtio_gpu_display_one {}

/* VIRTIO_GPU_RESP_OK_DISPLAY_INFO */
const VIRTIO_GPU_MAX_SCANOUTS: usize = 16;
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_resp_display_info {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub pmodes: [virtio_gpu_display_one; VIRTIO_GPU_MAX_SCANOUTS],
}

unsafe impl DataInit for virtio_gpu_resp_display_info {}

/* data passed in the control vq, 3d related */

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_box {
    pub x: Le32,
    pub y: Le32,
    pub z: Le32,
    pub w: Le32,
    pub h: Le32,
    pub d: Le32,
}

unsafe impl DataInit for virtio_gpu_box {}

/* VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D, VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_transfer_host_3d {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub box_: virtio_gpu_box,
    pub offset: Le64,
    pub resource_id: Le32,
    pub level: Le32,
    pub stride: Le32,
    pub layer_stride: Le32,
}

unsafe impl DataInit for virtio_gpu_transfer_host_3d {}

/* VIRTIO_GPU_CMD_RESOURCE_CREATE_3D */
pub const VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP: u32 = (1 << 0);
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_resource_create_3d {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub resource_id: Le32,
    pub target: Le32,
    pub format: Le32,
    pub bind: Le32,
    pub width: Le32,
    pub height: Le32,
    pub depth: Le32,
    pub array_size: Le32,
    pub last_level: Le32,
    pub nr_samples: Le32,
    pub flags: Le32,
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_resource_create_3d {}

/* VIRTIO_GPU_CMD_CTX_CREATE */
#[derive(Copy)]
#[repr(C)]
pub struct virtio_gpu_ctx_create {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub nlen: Le32,
    pub padding: Le32,
    pub debug_name: [u8; 64],
}

unsafe impl DataInit for virtio_gpu_ctx_create {}

impl Clone for virtio_gpu_ctx_create {
    fn clone(&self) -> virtio_gpu_ctx_create {
        *self
    }
}

impl fmt::Debug for virtio_gpu_ctx_create {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let debug_name = from_utf8(&self.debug_name[..min(64, self.nlen.to_native() as usize)])
            .unwrap_or("<invalid>");
        f.debug_struct("virtio_gpu_ctx_create")
            .field("hdr", &self.hdr)
            .field("debug_name", &debug_name)
            .finish()
    }
}

/* VIRTIO_GPU_CMD_CTX_DESTROY */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_ctx_destroy {
    pub hdr: virtio_gpu_ctrl_hdr,
}

unsafe impl DataInit for virtio_gpu_ctx_destroy {}

/* VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE, VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_ctx_resource {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub resource_id: Le32,
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_ctx_resource {}

/* VIRTIO_GPU_CMD_SUBMIT_3D */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_cmd_submit {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub size: Le32,
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_cmd_submit {}

pub const VIRTIO_GPU_CAPSET_VIRGL: u32 = 1;
pub const VIRTIO_GPU_CAPSET_VIRGL2: u32 = 2;

/* VIRTIO_GPU_CMD_GET_CAPSET_INFO */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_get_capset_info {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub capset_index: Le32,
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_get_capset_info {}

/* VIRTIO_GPU_RESP_OK_CAPSET_INFO */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_resp_capset_info {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub capset_id: Le32,
    pub capset_max_version: Le32,
    pub capset_max_size: Le32,
    pub padding: Le32,
}

unsafe impl DataInit for virtio_gpu_resp_capset_info {}

/* VIRTIO_GPU_CMD_GET_CAPSET */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_get_capset {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub capset_id: Le32,
    pub capset_version: Le32,
}

unsafe impl DataInit for virtio_gpu_get_capset {}

/* VIRTIO_GPU_RESP_OK_CAPSET */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_resp_capset {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub capset_data: PhantomData<[u8]>,
}

unsafe impl DataInit for virtio_gpu_resp_capset {}

/* VIRTIO_GPU_RESP_OK_RESOURCE_PLANE_INFO */
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_resp_resource_plane_info {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub count: Le32,
    pub padding: Le32,
    pub format_modifier: Le64,
    pub strides: [Le32; 4],
    pub offsets: [Le32; 4],
}

unsafe impl DataInit for virtio_gpu_resp_resource_plane_info {}

const PLANE_INFO_MAX_COUNT: usize = 4;

pub const VIRTIO_GPU_EVENT_DISPLAY: u32 = 1 << 0;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct virtio_gpu_config {
    pub events_read: Le32,
    pub events_clear: Le32,
    pub num_scanouts: Le32,
    pub num_capsets: Le32,
}

unsafe impl DataInit for virtio_gpu_config {}

/* simple formats for fbcon/X use */
pub const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
pub const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 2;
pub const VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM: u32 = 3;
pub const VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM: u32 = 4;
pub const VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM: u32 = 67;
pub const VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM: u32 = 68;
pub const VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM: u32 = 121;
pub const VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM: u32 = 134;

/// A virtio gpu command and associated metadata specific to each command.
#[derive(Copy, Clone)]
pub enum GpuCommand {
    GetDisplayInfo(virtio_gpu_ctrl_hdr),
    ResourceCreate2d(virtio_gpu_resource_create_2d),
    ResourceUnref(virtio_gpu_resource_unref),
    SetScanout(virtio_gpu_set_scanout),
    ResourceFlush(virtio_gpu_resource_flush),
    TransferToHost2d(virtio_gpu_transfer_to_host_2d),
    ResourceAttachBacking(virtio_gpu_resource_attach_backing),
    ResourceDetachBacking(virtio_gpu_resource_detach_backing),
    GetCapsetInfo(virtio_gpu_get_capset_info),
    GetCapset(virtio_gpu_get_capset),
    CtxCreate(virtio_gpu_ctx_create),
    CtxDestroy(virtio_gpu_ctx_destroy),
    CtxAttachResource(virtio_gpu_ctx_resource),
    CtxDetachResource(virtio_gpu_ctx_resource),
    ResourceCreate3d(virtio_gpu_resource_create_3d),
    TransferToHost3d(virtio_gpu_transfer_host_3d),
    TransferFromHost3d(virtio_gpu_transfer_host_3d),
    CmdSubmit3d(virtio_gpu_cmd_submit),
    UpdateCursor(virtio_gpu_update_cursor),
    MoveCursor(virtio_gpu_update_cursor),
}

/// An error indicating something went wrong decoding a `GpuCommand`. These correspond to
/// `VIRTIO_GPU_CMD_*`.
#[derive(Debug)]
pub enum GpuCommandDecodeError {
    /// The command referenced an inaccessible area of memory.
    Memory(VolatileMemoryError),
    /// The type of the command was invalid.
    InvalidType(u32),
}

impl Display for GpuCommandDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::GpuCommandDecodeError::*;

        match self {
            Memory(e) => write!(
                f,
                "command referenced an inaccessible area of memory: {}",
                e,
            ),
            InvalidType(n) => write!(f, "invalid command type ({})", n),
        }
    }
}

impl From<VolatileMemoryError> for GpuCommandDecodeError {
    fn from(e: VolatileMemoryError) -> GpuCommandDecodeError {
        GpuCommandDecodeError::Memory(e)
    }
}

impl fmt::Debug for GpuCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::GpuCommand::*;
        match self {
            GetDisplayInfo(_info) => f.debug_struct("GetDisplayInfo").finish(),
            ResourceCreate2d(_info) => f.debug_struct("ResourceCreate2d").finish(),
            ResourceUnref(_info) => f.debug_struct("ResourceUnref").finish(),
            SetScanout(_info) => f.debug_struct("SetScanout").finish(),
            ResourceFlush(_info) => f.debug_struct("ResourceFlush").finish(),
            TransferToHost2d(_info) => f.debug_struct("TransferToHost2d").finish(),
            ResourceAttachBacking(_info) => f.debug_struct("ResourceAttachBacking").finish(),
            ResourceDetachBacking(_info) => f.debug_struct("ResourceDetachBacking").finish(),
            GetCapsetInfo(_info) => f.debug_struct("GetCapsetInfo").finish(),
            GetCapset(_info) => f.debug_struct("GetCapset").finish(),
            CtxCreate(_info) => f.debug_struct("CtxCreate").finish(),
            CtxDestroy(_info) => f.debug_struct("CtxDestroy").finish(),
            CtxAttachResource(_info) => f.debug_struct("CtxAttachResource").finish(),
            CtxDetachResource(_info) => f.debug_struct("CtxDetachResource").finish(),
            ResourceCreate3d(_info) => f.debug_struct("ResourceCreate3d").finish(),
            TransferToHost3d(_info) => f.debug_struct("TransferToHost3d").finish(),
            TransferFromHost3d(_info) => f.debug_struct("TransferFromHost3d").finish(),
            CmdSubmit3d(_info) => f.debug_struct("CmdSubmit3d").finish(),
            UpdateCursor(_info) => f.debug_struct("UpdateCursor").finish(),
            MoveCursor(_info) => f.debug_struct("MoveCursor").finish(),
        }
    }
}

impl GpuCommand {
    /// Decodes a command from the given chunk of memory.
    pub fn decode(cmd: VolatileSlice) -> Result<GpuCommand, GpuCommandDecodeError> {
        use self::GpuCommand::*;
        let hdr: virtio_gpu_ctrl_hdr = cmd.get_ref(0)?.load();
        Ok(match hdr.type_.into() {
            VIRTIO_GPU_CMD_GET_DISPLAY_INFO => GetDisplayInfo(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_RESOURCE_CREATE_2D => ResourceCreate2d(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_RESOURCE_UNREF => ResourceUnref(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_SET_SCANOUT => SetScanout(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_RESOURCE_FLUSH => ResourceFlush(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D => TransferToHost2d(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING => ResourceAttachBacking(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING => ResourceDetachBacking(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_GET_CAPSET_INFO => GetCapsetInfo(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_GET_CAPSET => GetCapset(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_CTX_CREATE => CtxCreate(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_CTX_DESTROY => CtxDestroy(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE => CtxAttachResource(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE => CtxDetachResource(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_RESOURCE_CREATE_3D => ResourceCreate3d(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D => TransferToHost3d(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D => TransferFromHost3d(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_SUBMIT_3D => CmdSubmit3d(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_UPDATE_CURSOR => UpdateCursor(cmd.get_ref(0)?.load()),
            VIRTIO_GPU_CMD_MOVE_CURSOR => MoveCursor(cmd.get_ref(0)?.load()),
            _ => return Err(GpuCommandDecodeError::InvalidType(hdr.type_.into())),
        })
    }

    /// Gets the generic `virtio_gpu_ctrl_hdr` from this command.
    pub fn ctrl_hdr(&self) -> &virtio_gpu_ctrl_hdr {
        use self::GpuCommand::*;
        match self {
            GetDisplayInfo(info) => info,
            ResourceCreate2d(info) => &info.hdr,
            ResourceUnref(info) => &info.hdr,
            SetScanout(info) => &info.hdr,
            ResourceFlush(info) => &info.hdr,
            TransferToHost2d(info) => &info.hdr,
            ResourceAttachBacking(info) => &info.hdr,
            ResourceDetachBacking(info) => &info.hdr,
            GetCapsetInfo(info) => &info.hdr,
            GetCapset(info) => &info.hdr,
            CtxCreate(info) => &info.hdr,
            CtxDestroy(info) => &info.hdr,
            CtxAttachResource(info) => &info.hdr,
            CtxDetachResource(info) => &info.hdr,
            ResourceCreate3d(info) => &info.hdr,
            TransferToHost3d(info) => &info.hdr,
            TransferFromHost3d(info) => &info.hdr,
            CmdSubmit3d(info) => &info.hdr,
            UpdateCursor(info) => &info.hdr,
            MoveCursor(info) => &info.hdr,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct GpuResponsePlaneInfo {
    pub stride: u32,
    pub offset: u32,
}

/// A response to a `GpuCommand`. These correspond to `VIRTIO_GPU_RESP_*`.
#[derive(Debug, PartialEq)]
pub enum GpuResponse {
    OkNoData,
    OkDisplayInfo(Vec<(u32, u32)>),
    OkCapsetInfo {
        id: u32,
        version: u32,
        size: u32,
    },
    OkCapset(Vec<u8>),
    OkResourcePlaneInfo {
        format_modifier: u64,
        plane_info: Vec<GpuResponsePlaneInfo>,
    },
    ErrUnspec,
    ErrOutOfMemory,
    ErrInvalidScanoutId,
    ErrInvalidResourceId,
    ErrInvalidContextId,
    ErrInvalidParameter,
}

/// An error indicating something went wrong decoding a `GpuCommand`.
#[derive(Debug)]
pub enum GpuResponseEncodeError {
    /// The response was encoded to an inaccessible area of memory.
    Memory(VolatileMemoryError),
    /// More displays than are valid were in a `OkDisplayInfo`.
    TooManyDisplays(usize),
    /// More planes than are valid were in a `OkResourcePlaneInfo`.
    TooManyPlanes(usize),
}

impl Display for GpuResponseEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::GpuResponseEncodeError::*;

        match self {
            Memory(e) => write!(
                f,
                "response was encoded to an inaccessible area of memory: {}",
                e,
            ),
            TooManyDisplays(n) => write!(f, "{} is more displays than are valid", n),
            TooManyPlanes(n) => write!(f, "{} is more planes than are valid", n),
        }
    }
}

impl From<VolatileMemoryError> for GpuResponseEncodeError {
    fn from(e: VolatileMemoryError) -> GpuResponseEncodeError {
        GpuResponseEncodeError::Memory(e)
    }
}

impl GpuResponse {
    /// Encodes a this `GpuResponse` into `resp` and the given set of metadata.
    pub fn encode(
        &self,
        flags: u32,
        fence_id: u64,
        ctx_id: u32,
        resp: VolatileSlice,
    ) -> Result<u32, GpuResponseEncodeError> {
        let hdr = virtio_gpu_ctrl_hdr {
            type_: Le32::from(self.get_type()),
            flags: Le32::from(flags),
            fence_id: Le64::from(fence_id),
            ctx_id: Le32::from(ctx_id),
            padding: Le32::from(0),
        };
        let len = match *self {
            GpuResponse::OkDisplayInfo(ref info) => {
                if info.len() > VIRTIO_GPU_MAX_SCANOUTS {
                    return Err(GpuResponseEncodeError::TooManyDisplays(info.len()));
                }
                let mut disp_info = virtio_gpu_resp_display_info {
                    hdr,
                    pmodes: Default::default(),
                };
                for (disp_mode, &(width, height)) in disp_info.pmodes.iter_mut().zip(info) {
                    disp_mode.r.width = Le32::from(width);
                    disp_mode.r.height = Le32::from(height);
                    disp_mode.enabled = Le32::from(1);
                }
                resp.get_ref(0)?.store(disp_info);
                size_of_val(&disp_info)
            }
            GpuResponse::OkCapsetInfo { id, version, size } => {
                resp.get_ref(0)?.store(virtio_gpu_resp_capset_info {
                    hdr,
                    capset_id: Le32::from(id),
                    capset_max_version: Le32::from(version),
                    capset_max_size: Le32::from(size),
                    padding: Le32::from(0),
                });
                size_of::<virtio_gpu_resp_capset_info>()
            }
            GpuResponse::OkCapset(ref data) => {
                resp.get_ref(0)?.store(hdr);
                let resp_data_slice =
                    resp.get_slice(size_of_val(&hdr) as u64, data.len() as u64)?;
                resp_data_slice.copy_from(data);
                size_of_val(&hdr) + data.len()
            }
            GpuResponse::OkResourcePlaneInfo {
                format_modifier,
                ref plane_info,
            } => {
                if plane_info.len() > PLANE_INFO_MAX_COUNT {
                    return Err(GpuResponseEncodeError::TooManyPlanes(plane_info.len()));
                }
                let mut strides = [Le32::default(); PLANE_INFO_MAX_COUNT];
                let mut offsets = [Le32::default(); PLANE_INFO_MAX_COUNT];
                for (plane_index, plane) in plane_info.iter().enumerate() {
                    strides[plane_index] = plane.stride.into();
                    offsets[plane_index] = plane.offset.into();
                }
                let plane_info = virtio_gpu_resp_resource_plane_info {
                    hdr,
                    count: Le32::from(plane_info.len() as u32),
                    padding: 0.into(),
                    format_modifier: format_modifier.into(),
                    strides,
                    offsets,
                };
                match resp.get_ref(0) {
                    Ok(resp_ref) => {
                        resp_ref.store(plane_info);
                        size_of_val(&plane_info)
                    }
                    _ => {
                        // In case there is too little room in the response slice to store the
                        // entire virtio_gpu_resp_resource_plane_info, convert response to a regular
                        // VIRTIO_GPU_RESP_OK_NODATA and attempt to return that.
                        resp.get_ref(0)?.store(virtio_gpu_ctrl_hdr {
                            type_: Le32::from(VIRTIO_GPU_RESP_OK_NODATA),
                            ..hdr
                        });
                        size_of_val(&hdr)
                    }
                }
            }
            _ => {
                resp.get_ref(0)?.store(hdr);
                size_of_val(&hdr)
            }
        };
        Ok(len as u32)
    }

    /// Gets the `VIRTIO_GPU_*` enum value that corresponds to this variant.
    pub fn get_type(&self) -> u32 {
        match self {
            GpuResponse::OkNoData => VIRTIO_GPU_RESP_OK_NODATA,
            GpuResponse::OkDisplayInfo(_) => VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
            GpuResponse::OkCapsetInfo { .. } => VIRTIO_GPU_RESP_OK_CAPSET_INFO,
            GpuResponse::OkCapset(_) => VIRTIO_GPU_RESP_OK_CAPSET,
            GpuResponse::OkResourcePlaneInfo { .. } => VIRTIO_GPU_RESP_OK_RESOURCE_PLANE_INFO,
            GpuResponse::ErrUnspec => VIRTIO_GPU_RESP_ERR_UNSPEC,
            GpuResponse::ErrOutOfMemory => VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
            GpuResponse::ErrInvalidScanoutId => VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID,
            GpuResponse::ErrInvalidResourceId => VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
            GpuResponse::ErrInvalidContextId => VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID,
            GpuResponse::ErrInvalidParameter => VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
        }
    }

    /// Returns true if this response indicates success.
    pub fn is_ok(&self) -> bool {
        match self {
            GpuResponse::OkNoData => true,
            GpuResponse::OkDisplayInfo(_) => true,
            GpuResponse::OkCapsetInfo { .. } => true,
            GpuResponse::OkCapset(_) => true,
            GpuResponse::OkResourcePlaneInfo { .. } => true,
            _ => false,
        }
    }

    /// Returns true if this response indicates an error.
    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }
}
