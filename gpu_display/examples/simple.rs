// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use gpu_display::*;

fn main() {
    let mut disp = GpuDisplay::new("/run/wayland-0").unwrap();
    let surface_id = disp.create_surface(None, 1280, 1024).unwrap();
    while !disp.close_requested(surface_id) {
        disp.dispatch_events();
    }
}
