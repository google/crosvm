// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Stub implementation of the native interface of libcrosvm_android_display_client
//!
//! This implementation is used to enable the gpu display backend for Android to be compiled
//! without libcrosvm_android_display_client available. It is only used for testing purposes and
//! not functional at runtime.

use std::ffi::c_char;

use crate::gpu_display_android::ANativeWindow;
use crate::gpu_display_android::ANativeWindow_Buffer;
use crate::gpu_display_android::AndroidDisplayContext;
use crate::gpu_display_android::ErrorCallback;

#[no_mangle]
extern "C" fn create_android_display_context(
    _name: *const c_char,
    _error_callback: ErrorCallback,
) -> *mut AndroidDisplayContext {
    unimplemented!();
}

#[no_mangle]
extern "C" fn destroy_android_display_context(_ctx: *mut AndroidDisplayContext) {
    unimplemented!();
}

#[no_mangle]
extern "C" fn create_android_surface(
    _ctx: *mut AndroidDisplayContext,
    _width: u32,
    _height: u32,
    _for_cursor: bool,
) -> *mut ANativeWindow {
    unimplemented!();
}

#[no_mangle]
extern "C" fn destroy_android_surface(
    _ctx: *mut AndroidDisplayContext,
    _surface: *mut ANativeWindow,
) {
    unimplemented!();
}

#[no_mangle]
extern "C" fn set_android_surface_position(_ctx: *mut AndroidDisplayContext, _x: u32, _y: u32) {
    unimplemented!();
}

#[no_mangle]
extern "C" fn get_android_surface_buffer(
    _ctx: *mut AndroidDisplayContext,
    _surface: *mut ANativeWindow,
    _out_buffer: *mut ANativeWindow_Buffer,
) -> u32 {
    unimplemented!();
}

#[no_mangle]
extern "C" fn post_android_surface_buffer(
    _ctx: *mut AndroidDisplayContext,
    _surface: *mut ANativeWindow,
) {
    unimplemented!();
}
