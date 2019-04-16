// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use gpu_display::*;

fn main() {
    let mut disp = GpuDisplay::open_wayland(None::<&str>).unwrap();
    let surface_id = disp.create_surface(None, 1280, 1024).unwrap();
    disp.flip(surface_id);
    disp.commit(surface_id);
    while !disp.close_requested(surface_id) {
        disp.dispatch_events();
    }
}
