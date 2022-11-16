// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::process::exit;

use anyhow::Context;
use anyhow::Result;
use gpu_display::GpuDisplay;
use gpu_display::SurfaceType;

fn run() -> Result<()> {
    let mut disp = GpuDisplay::open_x(None::<&str>).context("open_x")?;
    let surface_id = disp
        .create_surface(None, 1280, 1024, SurfaceType::Scanout)
        .context("create_surface")?;

    let mem = disp.framebuffer(surface_id).context("framebuffer")?;
    for y in 0..1024 {
        let mut row = [0u32; 1280];
        for (x, item) in row.iter_mut().enumerate() {
            let b = ((x as f32 / 1280.0) * 256.0) as u32;
            let g = ((y as f32 / 1024.0) * 256.0) as u32;
            *item = b | (g << 8);
        }
        mem.as_volatile_slice()
            .offset(1280 * 4 * y)
            .unwrap()
            .copy_from(&row);
    }
    disp.flip(surface_id);

    while !disp.close_requested(surface_id) {
        disp.dispatch_events().context("dispatch_events")?;
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {:#}", e);
        exit(1);
    }
}
