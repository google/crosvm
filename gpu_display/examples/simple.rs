// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::process::exit;

use anyhow::Context;
use anyhow::Result;
use gpu_display::*;

fn run() -> Result<()> {
    let mut disp = GpuDisplay::open_wayland(None::<&str>).context("open_wayland")?;
    let surface_id = disp
        .create_surface(None, 1280, 1024, SurfaceType::Scanout)
        .context("create_surface")?;
    disp.flip(surface_id);
    disp.commit(surface_id).context("commit")?;
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
