// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::generated::p_format;

macro_rules! fourcc {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        Some($a as u32 | ($b as u32) << 8 | ($c as u32) << 16 | ($d as u32) << 24)
    };
}

/// Gets the fourcc that corresponds to the given pipe format, or `None` if the format is
/// unrecognized.
pub fn pipe_format_fourcc(f: p_format::pipe_format) -> Option<u32> {
    match f {
        p_format::PIPE_FORMAT_B8G8R8A8_UNORM => fourcc!('A', 'R', '2', '4'),
        p_format::PIPE_FORMAT_B8G8R8X8_UNORM => fourcc!('X', 'R', '2', '4'),
        p_format::PIPE_FORMAT_R8G8B8A8_UNORM => fourcc!('A', 'B', '2', '4'),
        p_format::PIPE_FORMAT_R8G8B8X8_UNORM => fourcc!('X', 'B', '2', '4'),
        p_format::PIPE_FORMAT_B5G6R5_UNORM => fourcc!('R', 'G', '1', '6'),
        // p_format::PIPE_FORMAT_R8_UNORM => fourcc!('R', '8', ' ', ' '),
        // p_format::PIPE_FORMAT_G8R8_UNORM => fourcc!('R', 'G', '8', '8'),
        _ => None,
    }
}
