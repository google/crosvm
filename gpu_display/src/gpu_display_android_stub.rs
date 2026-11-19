// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Stub implementation of the native interface of libcrosvm_android_display_client
//!
//! This implementation is used to enable the gpu display backend for Android to be compiled
//! without libcrosvm_android_display_client available. It is only used for testing purposes and
//! not functional at runtime. Buffer imports are emulated so that unit tests can check how the
//! backend manages imported buffers.

use std::cell::Cell;
use std::cell::RefCell;
use std::ffi::c_char;

use crate::gpu_display_android::AHardwareBuffer;
use crate::gpu_display_android::AHardwareBufferInfo;
use crate::gpu_display_android::ANativeWindow_Buffer;
use crate::gpu_display_android::AndroidDisplayContext;
use crate::gpu_display_android::AndroidDisplaySurface;
use crate::gpu_display_android::ErrorCallback;

thread_local! {
    static IMPORTED_BUFFERS: Cell<usize> = const { Cell::new(0) };
    static LIVE_IMPORTED_BUFFERS: Cell<usize> = const { Cell::new(0) };
    static FLIPPED_BUFFERS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// Returns how many buffers were imported on the current thread.
#[cfg(test)]
pub(crate) fn imported_buffer_count() -> usize {
    IMPORTED_BUFFERS.with(Cell::get)
}

/// Returns how many buffers imported on the current thread are not released yet.
#[cfg(test)]
pub(crate) fn live_imported_buffers() -> usize {
    LIVE_IMPORTED_BUFFERS.with(Cell::get)
}

/// Returns the addresses of the buffers flipped to on the current thread, in order.
#[cfg(test)]
pub(crate) fn flipped_buffers() -> Vec<usize> {
    FLIPPED_BUFFERS.with(|flipped| flipped.borrow().clone())
}

/// Resets the buffer tracking of the current thread, which tests may share (`--test-threads=1`).
#[cfg(test)]
pub(crate) fn reset_test_state() {
    IMPORTED_BUFFERS.with(|count| count.set(0));
    LIVE_IMPORTED_BUFFERS.with(|count| count.set(0));
    FLIPPED_BUFFERS.with(|flipped| flipped.borrow_mut().clear());
}

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
) -> *mut AndroidDisplaySurface {
    unimplemented!();
}

#[no_mangle]
extern "C" fn destroy_android_surface(
    _ctx: *mut AndroidDisplayContext,
    _surface: *mut AndroidDisplaySurface,
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
    _surface: *mut AndroidDisplaySurface,
    _out_buffer: *mut ANativeWindow_Buffer,
) -> u32 {
    unimplemented!();
}

#[no_mangle]
extern "C" fn post_android_surface_buffer(
    _ctx: *mut AndroidDisplayContext,
    _surface: *mut AndroidDisplaySurface,
) {
    unimplemented!();
}

#[no_mangle]
extern "C" fn android_display_flip_to(
    _ctx: *mut AndroidDisplayContext,
    _surface: *mut AndroidDisplaySurface,
    _ahb_info: *const AHardwareBufferInfo,
) {
    unimplemented!();
}

#[no_mangle]
extern "C" fn android_display_import_buffer(
    _ctx: *mut AndroidDisplayContext,
    _ahb_info: *const AHardwareBufferInfo,
) -> *mut AHardwareBuffer {
    IMPORTED_BUFFERS.with(|count| count.set(count.get() + 1));
    LIVE_IMPORTED_BUFFERS.with(|count| count.set(count.get() + 1));
    Box::into_raw(Box::new(0u8)).cast()
}

#[no_mangle]
extern "C" fn android_display_flip_to_imported(
    _ctx: *mut AndroidDisplayContext,
    _surface: *mut AndroidDisplaySurface,
    ahb: *mut AHardwareBuffer,
) {
    FLIPPED_BUFFERS.with(|flipped| flipped.borrow_mut().push(ahb as usize));
}

#[no_mangle]
extern "C" fn android_display_release_buffer(ahb: *mut AHardwareBuffer) {
    // SAFETY: `ahb` was allocated by `android_display_import_buffer` and is released once.
    drop(unsafe { Box::from_raw(ahb.cast::<u8>()) });
    LIVE_IMPORTED_BUFFERS.with(|count| count.set(count.get() - 1));
}
