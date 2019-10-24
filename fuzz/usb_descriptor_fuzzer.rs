// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![no_main]

use cros_fuzz::fuzz_target;

use usb_util::parse_usbfs_descriptors;

fuzz_target!(|data| {
    let _ = parse_usbfs_descriptors(data);
});
