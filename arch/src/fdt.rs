// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Read;

use cros_fdt::apply_overlay;
use cros_fdt::Error;
use cros_fdt::Fdt;
use cros_fdt::Result;

/// Device tree overlay file
pub struct DtbOverlay(pub File);

/// Apply multiple device tree overlays to the base FDT.
pub fn apply_device_tree_overlays(fdt: &mut Fdt, overlays: Vec<DtbOverlay>) -> Result<()> {
    for DtbOverlay(mut overlay_file) in overlays {
        let mut buffer = Vec::new();
        overlay_file
            .read_to_end(&mut buffer)
            .map_err(Error::FdtIoError)?;
        let overlay = Fdt::from_blob(buffer.as_slice())?;
        apply_overlay::<&str>(fdt, overlay, [])?;
    }
    Ok(())
}
