// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;

fn main() {
    env::set_var("PKG_CONFIG_ALLOW_CROSS", "1");
    pkg_config::probe_library("libusb-1.0").unwrap();
}
