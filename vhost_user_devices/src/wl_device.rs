// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use devices::virtio::vhost::user::device::run_wl_device;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args();
    let program_name = args.next().expect("empty args");
    run_wl_device(&program_name, args)
}
