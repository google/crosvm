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
extern "C" fn AAudio_createStreamBuilder(_builder: *mut *mut AAudioStreamBuilder) -> AaudioResultT {
    unimplemented!();
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_delete(_builder: *mut AAudioStreamBuilder) -> AaudioResultT {
    unimplemented!();
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_setBufferCapacityInFrames(
    _builder: *mut AAudioStreamBuilder,
    _num_frames: i32,
) {
    unimplemented!();
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_setFormat(
    _builder: *mut AAudioStreamBuilder,
    _format: AaudioFormatT,
) {
    unimplemented!();
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_setSampleRate(
    _builder: *mut AAudioStreamBuilder,
    _sample_rate: i32,
) {
    unimplemented!();
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_setChannelCount(
    _builder: *mut AAudioStreamBuilder,
    _channel_count: i32,
) {
    unimplemented!();
}

#[no_mangle]
extern "C" fn AAudioStreamBuilder_openStream(
    _builder: *mut AAudioStreamBuilder,
    _stream: *mut *mut AAudioStream,
) -> AaudioResultT {
    unimplemented!();
}

#[no_mangle]
extern "C" fn AAudioStream_requestStart(_stream: *mut AAudioStream) -> AaudioResultT {
    unimplemented!();
}

#[no_mangle]
extern "C" fn AAudioStream_write(
    _stream: *mut AAudioStream,
    _buffer: *const c_void,
    _num_frames: i32,
    _timeout_nanoseconds: i64,
) {
    unimplemented!();
}

#[no_mangle]
extern "C" fn AAudioStream_close(_stream: *mut AAudioStream) {
    unimplemented!();
}
