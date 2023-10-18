// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Stub implementation of the native interface of libcrosvm_android_display_client
//!
//! This implementation is used to enable the gpu display backend for Android to be compiled
//! without libcrosvm_android_display_client available. It is only used for testing purposes and
//! not functional at runtime.

use crate::gpu_display_android::android_display_context;
use crate::gpu_display_android::android_display_error_callback_type;

#[no_mangle]
extern "C" fn create_android_display_context(
    _service_name: *const ::std::os::raw::c_char,
    _error_callback: android_display_error_callback_type,
) -> *mut android_display_context {
    unimplemented!();
}

#[no_mangle]
extern "C" fn destroy_android_display_context(
    _error_callback: android_display_error_callback_type,
    _self_: *mut *mut android_display_context,
) {
    unimplemented!();
}

#[no_mangle]
extern "C" fn get_android_display_width(
    _error_callback: android_display_error_callback_type,
    _self_: *mut android_display_context,
) -> u32 {
    unimplemented!();
}

#[no_mangle]
extern "C" fn get_android_display_height(
    _error_callback: android_display_error_callback_type,
    _self_: *mut android_display_context,
) -> u32 {
    unimplemented!();
}

#[no_mangle]
extern "C" fn blit_android_display(
    _error_callback: android_display_error_callback_type,
    _self_: *mut android_display_context,
    _width: u32,
    _height: u32,
    _bytes: *mut u8,
) {
    unimplemented!();
}
