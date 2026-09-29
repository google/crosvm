// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Stub implementation of Android AAudio NDK
//!
//! This implementation is used to enable the virtio-snd for Android to be compiled without
//! Andoird AAudio NDK available. It is only used for testing purposes and not functional at
//! runtime.

use std::os::raw::c_void;

use crate::AAudioStream;
use crate::AAudioStreamBuilder;
use crate::AaudioFormatT;
use crate::AaudioResultT;

#[no_mangle]
extern "C" fn AAudio_createStreamBuilder(builder: *mut *mut AAudioStreamBuilder) -> AaudioResultT {
    if !builder.is_null() {
        // SAFETY: `builder` is a valid out-pointer provided by the caller in tests.
        unsafe {
            *builder = std::ptr::NonNull::<AAudioStreamBuilder>::dangling().as_ptr();
        }
    }
    0
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_delete(_builder: *mut AAudioStreamBuilder) -> AaudioResultT {
    0
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_setBufferCapacityInFrames(
    _builder: *mut AAudioStreamBuilder,
    _num_frames: i32,
) {
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_setDirection(
    _builder: *mut AAudioStreamBuilder,
    _direction: u32,
) {
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_setFormat(
    _builder: *mut AAudioStreamBuilder,
    _format: AaudioFormatT,
) {
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_setSampleRate(
    _builder: *mut AAudioStreamBuilder,
    _sample_rate: i32,
) {
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_setChannelCount(
    _builder: *mut AAudioStreamBuilder,
    _channel_count: i32,
) {
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_openStream(
    _builder: *mut AAudioStreamBuilder,
    stream: *mut *mut AAudioStream,
) -> AaudioResultT {
    if !stream.is_null() {
        // SAFETY: `stream` is a valid out-pointer provided by the caller in tests.
        unsafe {
            *stream = std::ptr::NonNull::<AAudioStream>::dangling().as_ptr();
        }
    }
    0
}

#[no_mangle]
extern "C" fn AAudioStream_getBufferSizeInFrames(_stream: *mut AAudioStream) -> i32 {
    960
}

#[no_mangle]
extern "C" fn AAudioStream_requestStart(_stream: *mut AAudioStream) -> AaudioResultT {
    0
}

#[no_mangle]
extern "C" fn AAudioStream_read(
    _stream: *mut AAudioStream,
    _buffer: *mut c_void,
    num_frames: i32,
    _timeout_nanoseconds: i64,
) -> AaudioResultT {
    num_frames
}

#[no_mangle]
extern "C" fn AAudioStream_write(
    _stream: *mut AAudioStream,
    _buffer: *const c_void,
    num_frames: i32,
    _timeout_nanoseconds: i64,
) -> AaudioResultT {
    num_frames
}

#[no_mangle]
extern "C" fn AAudioStream_requestStop(_stream: *mut AAudioStream) -> AaudioResultT {
    0
}

#[no_mangle]
extern "C" fn AAudioStream_close(_stream: *mut AAudioStream) -> AaudioResultT {
    0
}
