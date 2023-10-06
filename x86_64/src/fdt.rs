// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::path::PathBuf;

use arch::android::create_android_fdt;
use arch::apply_device_tree_overlays;
use arch::DtbOverlay;
use cros_fdt::Error;
use cros_fdt::Fdt;

use crate::SetupData;
use crate::SetupDataType;

/// Creates a flattened device tree containing all of the parameters for the
/// kernel and returns it as `SetupData`.
///
/// # Arguments
///
/// * `android_fstab` - the File object for the android fstab
pub fn create_fdt(
    android_fstab: File,
    dump_device_tree_blob: Option<PathBuf>,
    device_tree_overlays: Vec<DtbOverlay>,
) -> Result<SetupData, Error> {
    let mut fdt = Fdt::new(&[]);
    // The whole thing is put into one giant node with some top level properties
    create_android_fdt(&mut fdt, android_fstab)?;

    // Done writing base FDT, now apply DT overlays
    apply_device_tree_overlays(
        &mut fdt,
        device_tree_overlays,
        #[cfg(any(target_os = "android", target_os = "linux"))]
        vec![],
    )?;

    let fdt_final = fdt.finish()?;

    if let Some(file_path) = dump_device_tree_blob {
        std::fs::write(&file_path, &fdt_final)
            .map_err(|e| Error::FdtDumpIoError(e, file_path.clone()))?;
    }

    Ok(SetupData {
        data: fdt_final,
        type_: SetupDataType::Dtb,
    })
}
