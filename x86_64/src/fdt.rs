// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(target_os = "android", target_os = "linux"))]
use std::collections::BTreeMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use arch::android::create_android_fdt;
use arch::apply_device_tree_overlays;
use arch::DtbOverlay;
use base::open_file_or_duplicate;
use cros_fdt::Error;
use cros_fdt::Fdt;
use vm_memory::GuestAddress;

fn create_config_node(fdt: &mut Fdt, (addr, size): (GuestAddress, usize)) -> cros_fdt::Result<()> {
    let addr: u32 = addr
        .offset()
        .try_into()
        .map_err(|_| Error::PropertyValueTooLarge)?;
    let size: u32 = size.try_into().map_err(|_| Error::PropertyValueTooLarge)?;

    let config_node = fdt.root_mut().subnode_mut("config")?;
    config_node.set_prop("kernel-address", addr)?;
    config_node.set_prop("kernel-size", size)?;
    Ok(())
}

/// Creates a flattened device tree containing all of the parameters for the
/// kernel and returns it as DTB.
///
/// # Arguments
///
/// * `android_fstab` - the File object for the android fstab
pub fn create_fdt(
    android_fstab: Option<File>,
    dump_device_tree_blob: Option<PathBuf>,
    device_tree_overlays: Vec<DtbOverlay>,
    image: (GuestAddress, usize),
) -> Result<Vec<u8>, Error> {
    let mut fdt = Fdt::new(&[]);
    // The whole thing is put into one giant node with some top level properties
    if let Some(android_fstab) = android_fstab {
        create_android_fdt(&mut fdt, android_fstab)?;
    }

    create_config_node(&mut fdt, image)?;

    // Done writing base FDT, now apply DT overlays
    apply_device_tree_overlays(
        &mut fdt,
        device_tree_overlays,
        #[cfg(any(target_os = "android", target_os = "linux"))]
        vec![],
        #[cfg(any(target_os = "android", target_os = "linux"))]
        &BTreeMap::new(),
    )?;

    let fdt_final = fdt.finish()?;

    if let Some(file_path) = dump_device_tree_blob {
        let mut fd = open_file_or_duplicate(
            &file_path,
            OpenOptions::new()
                .read(true)
                .create(true)
                .truncate(true)
                .write(true),
        )
        .map_err(|e| Error::FdtIoError(e.into()))?;
        fd.write_all(&fdt_final)
            .map_err(|e| Error::FdtDumpIoError(e, file_path.clone()))?;
    }

    Ok(fdt_final)
}
