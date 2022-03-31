// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::iov_max;
use std::cmp::{max, min};

pub fn get_seg_max(queue_size: u16) -> u32 {
    let seg_max = min(max(iov_max(), 1), u32::max_value() as usize) as u32;

    // Since we do not currently support indirect descriptors, the maximum
    // number of segments must be smaller than the queue size.
    // In addition, the request header and status each consume a descriptor.
    min(seg_max, u32::from(queue_size) - 2)
}
