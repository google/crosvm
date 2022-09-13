// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::ffi;

pub const AV_NOPTS_VALUE: u64 = 0x8000000000000000;

/// Get the maximum data alignment that may be required by FFmpeg.
/// This could change depending on FFmpeg's build configuration (AVX etc.).
pub fn max_buffer_alignment() -> usize {
    // Safe because this function has no side effects and just returns an integer.
    unsafe { ffi::av_cpu_max_align() as usize }
}
