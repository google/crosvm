// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Generated with bindgen --whitelist-function='gbm_.*' --whitelist-type='gbm_.*' minigbm/gbm.h
// Hand-modified by zachr

#![allow(dead_code)]

use std::os::raw::{c_char, c_int, c_void};

/// \file gbm.h
/// \brief Generic Buffer Manager
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct gbm_device {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct gbm_bo {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct gbm_surface {
    _unused: [u8; 0],
}
/// Abstraction representing the handle to a buffer allocated by the
/// manager
#[repr(C)]
#[derive(Copy, Clone)]
pub union gbm_bo_handle {
    pub ptr: *mut c_void,
    pub s32: i32,
    pub u32: u32,
    pub s64: i64,
    pub u64: u64,
    _bindgen_union_align: u64,
}

/// Buffer is going to be presented to the screen using an API such as KMS
pub const GBM_BO_USE_SCANOUT: gbm_bo_flags = 1;
/// Buffer is going to be used as cursor
pub const GBM_BO_USE_CURSOR: gbm_bo_flags = 2;
/// Deprecated
pub const GBM_BO_USE_CURSOR_64X64: gbm_bo_flags = 2;
/// Buffer is to be used for rendering - for example it is going to be used
/// as the storage for a color buffer
pub const GBM_BO_USE_RENDERING: gbm_bo_flags = 4;
/// Deprecated
pub const GBM_BO_USE_WRITE: gbm_bo_flags = 8;
/// Buffer is guaranteed to be laid out linearly in memory. That is, the
/// buffer is laid out as an array with 'height' blocks, each block with
/// length 'stride'. Each stride is in the same order as the rows of the
/// buffer. This is intended to be used with buffers that will be accessed
/// via dma-buf mmap().
pub const GBM_BO_USE_LINEAR: gbm_bo_flags = 16;
/// The buffer will be used as a texture that will be sampled from.
pub const GBM_BO_USE_TEXTURING: gbm_bo_flags = 32;
/// The buffer will be written to by a camera subsystem.
pub const GBM_BO_USE_CAMERA_WRITE: gbm_bo_flags = 64;
/// The buffer will be read from by a camera subsystem.
pub const GBM_BO_USE_CAMERA_READ: gbm_bo_flags = 128;
/// Buffer inaccessible to unprivileged users.
pub const GBM_BO_USE_PROTECTED: gbm_bo_flags = 256;
/// These flags specify the frequency of software access. These flags do not
/// guarantee the buffer is linear, but do guarantee gbm_bo_map(..) will
/// present a linear view.
pub const GBM_BO_USE_SW_READ_OFTEN: gbm_bo_flags = 512;
/// These flags specify the frequency of software access. These flags do not
/// guarantee the buffer is linear, but do guarantee gbm_bo_map(..) will
/// present a linear view.
pub const GBM_BO_USE_SW_READ_RARELY: gbm_bo_flags = 1024;
/// These flags specify the frequency of software access. These flags do not
/// guarantee the buffer is linear, but do guarantee gbm_bo_map(..) will
/// present a linear view.
pub const GBM_BO_USE_SW_WRITE_OFTEN: gbm_bo_flags = 2048;
/// These flags specify the frequency of software access. These flags do not
/// guarantee the buffer is linear, but do guarantee gbm_bo_map(..) will
/// present a linear view.
pub const GBM_BO_USE_SW_WRITE_RARELY: gbm_bo_flags = 4096;
/// Flags to indicate the intended use for the buffer - these are passed into
/// gbm_bo_create(). The caller must set the union of all the flags that are
/// appropriate
///
/// \sa Use gbm_device_is_format_supported() to check if the combination of format
/// and use flags are supported
#[allow(non_camel_case_types)]
pub type gbm_bo_flags = u32;

#[link(name = "gbm")]
extern "C" {
    pub fn gbm_device_get_fd(gbm: *mut gbm_device) -> c_int;
    pub fn gbm_device_get_backend_name(gbm: *mut gbm_device) -> *const c_char;
    pub fn gbm_device_is_format_supported(gbm: *mut gbm_device, format: u32, usage: u32) -> c_int;
    pub fn gbm_device_destroy(gbm: *mut gbm_device);
    pub fn gbm_create_device(fd: c_int) -> *mut gbm_device;
    pub fn gbm_bo_create(
        gbm: *mut gbm_device,
        width: u32,
        height: u32,
        format: u32,
        flags: u32,
    ) -> *mut gbm_bo;
    pub fn gbm_bo_create_with_modifiers(
        gbm: *mut gbm_device,
        width: u32,
        height: u32,
        format: u32,
        modifiers: *const u64,
        count: u32,
    ) -> *mut gbm_bo;
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct gbm_import_fd_data {
    pub fd: c_int,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct gbm_import_fd_planar_data {
    pub fds: [c_int; 4usize],
    pub width: u32,
    pub height: u32,
    pub format: u32,
    pub strides: [u32; 4usize],
    pub offsets: [u32; 4usize],
    pub format_modifiers: [u64; 4usize],
}

extern "C" {
    pub fn gbm_bo_import(
        gbm: *mut gbm_device,
        type_: u32,
        buffer: *mut c_void,
        usage: u32,
    ) -> *mut gbm_bo;
}

/// Buffer contents read back (or accessed directly) at transfer
/// create time.
pub const GBM_BO_TRANSFER_READ: gbm_bo_transfer_flags = 1;
/// Buffer contents will be written back at unmap time
/// (or modified as a result of being accessed directly).
pub const GBM_BO_TRANSFER_WRITE: gbm_bo_transfer_flags = 2;
/// Read/modify/write
pub const GBM_BO_TRANSFER_READ_WRITE: gbm_bo_transfer_flags = 3;

/// Flags to indicate the type of mapping for the buffer - these are
/// passed into gbm_bo_map(). The caller must set the union of all the
/// flags that are appropriate.
///
/// These flags are independent of the GBM_BO_USE_* creation flags. However,
/// mapping the buffer may require copying to/from a staging buffer.
///
/// See also: pipe_transfer_usage
#[allow(non_camel_case_types)]
pub type gbm_bo_transfer_flags = u32;

extern "C" {
    pub fn gbm_bo_map(
        bo: *mut gbm_bo,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        flags: u32,
        stride: *mut u32,
        map_data: *mut *mut c_void,
        plane: usize,
    ) -> *mut c_void;
    pub fn gbm_bo_unmap(bo: *mut gbm_bo, map_data: *mut c_void);
    pub fn gbm_bo_get_width(bo: *mut gbm_bo) -> u32;
    pub fn gbm_bo_get_height(bo: *mut gbm_bo) -> u32;
    pub fn gbm_bo_get_stride(bo: *mut gbm_bo) -> u32;
    pub fn gbm_bo_get_stride_or_tiling(bo: *mut gbm_bo) -> u32;
    pub fn gbm_bo_get_format(bo: *mut gbm_bo) -> u32;
    pub fn gbm_bo_get_modifier(bo: *mut gbm_bo) -> u64;
    pub fn gbm_bo_get_device(bo: *mut gbm_bo) -> *mut gbm_device;
    pub fn gbm_bo_get_handle(bo: *mut gbm_bo) -> gbm_bo_handle;
    pub fn gbm_bo_get_fd(bo: *mut gbm_bo) -> c_int;
    pub fn gbm_bo_get_plane_count(bo: *mut gbm_bo) -> usize;
    pub fn gbm_bo_get_handle_for_plane(bo: *mut gbm_bo, plane: usize) -> gbm_bo_handle;
    pub fn gbm_bo_get_plane_fd(bo: *mut gbm_bo, plane: usize) -> c_int;
    pub fn gbm_bo_get_offset(bo: *mut gbm_bo, plane: usize) -> u32;
    pub fn gbm_bo_get_plane_size(bo: *mut gbm_bo, plane: usize) -> u32;
    pub fn gbm_bo_get_stride_for_plane(bo: *mut gbm_bo, plane: usize) -> u32;
    pub fn gbm_bo_get_plane_format_modifier(bo: *mut gbm_bo, plane: usize) -> u64;
    // Did not generate cleanly by bindgen. Redone manually by zachr.
    pub fn gbm_bo_set_user_data(
        bo: *mut gbm_bo,
        data: *mut c_void,
        destroy_user_data: extern "C" fn(bo: *mut gbm_bo, data: *mut c_void),
    );
    pub fn gbm_bo_get_user_data(bo: *mut gbm_bo) -> *mut c_void;
    pub fn gbm_bo_destroy(bo: *mut gbm_bo);
    pub fn gbm_surface_create(
        gbm: *mut gbm_device,
        width: u32,
        height: u32,
        format: u32,
        flags: u32,
    ) -> *mut gbm_surface;
    pub fn gbm_surface_lock_front_buffer(surface: *mut gbm_surface) -> *mut gbm_bo;
    pub fn gbm_surface_release_buffer(surface: *mut gbm_surface, bo: *mut gbm_bo);
    pub fn gbm_surface_has_free_buffers(surface: *mut gbm_surface) -> c_int;
    pub fn gbm_surface_destroy(surface: *mut gbm_surface);
}
