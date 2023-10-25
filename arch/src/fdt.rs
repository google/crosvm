// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(target_os = "android", target_os = "linux"))]
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;

use cros_fdt::apply_overlay;
use cros_fdt::Error;
use cros_fdt::Fdt;
#[cfg(any(target_os = "android", target_os = "linux"))]
use cros_fdt::Path;
use cros_fdt::Result;
#[cfg(any(target_os = "android", target_os = "linux"))]
use devices::IommuDevType;

#[cfg(any(target_os = "android", target_os = "linux"))]
use crate::sys::linux::PlatformBusResources;

/// Device tree overlay file
pub struct DtbOverlay {
    /// Device tree overlay file to apply
    pub file: File,
    /// Whether to filter out nodes that do not belong to assigned VFIO devices.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub do_filter: bool,
}

/// Apply multiple device tree overlays to the base FDT.
#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub fn apply_device_tree_overlays(fdt: &mut Fdt, overlays: Vec<DtbOverlay>) -> Result<()> {
    for mut dtbo in overlays {
        let mut buffer = Vec::new();
        dtbo.file
            .read_to_end(&mut buffer)
            .map_err(Error::FdtIoError)?;
        let overlay = Fdt::from_blob(buffer.as_slice())?;
        apply_overlay::<&str>(fdt, overlay, [])?;
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn get_iommu_phandle(
    iommu_type: IommuDevType,
    id: Option<u32>,
    phandles: &BTreeMap<&str, u32>,
) -> Result<u32> {
    match iommu_type {
        IommuDevType::NoIommu | IommuDevType::VirtioIommu | IommuDevType::CoIommu => None,
        IommuDevType::PkvmPviommu => {
            if let Some(id) = id {
                phandles.get(format!("pviommu{id}").as_str()).copied()
            } else {
                None
            }
        }
    }
    .ok_or_else(|| Error::MissingIommuPhandle(format!("{iommu_type:?}"), id))
}

// Find the device node at given path and update its `reg` and `interrupts` properties using
// its platform resources.
#[cfg(any(target_os = "android", target_os = "linux"))]
fn update_device_nodes(
    node_path: Path,
    fdt: &mut Fdt,
    resources: &PlatformBusResources,
    phandles: &BTreeMap<&str, u32>,
) -> Result<()> {
    const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;

    let node = fdt.get_node_mut(node_path).ok_or_else(|| {
        Error::InvalidPath(format!(
            "cannot find FDT node for dt-symbol {}",
            &resources.dt_symbol
        ))
    })?;
    let reg_val: Vec<u64> = resources
        .regions
        .iter()
        .flat_map(|(a, s)| [*a, *s].into_iter())
        .collect();
    let irq_val: Vec<u32> = resources
        .irqs
        .iter()
        .flat_map(|(n, f)| [GIC_FDT_IRQ_TYPE_SPI, *n, *f].into_iter())
        .collect();
    if !reg_val.is_empty() {
        node.set_prop("reg", reg_val)?;
    }
    if !irq_val.is_empty() {
        node.set_prop("interrupts", irq_val)?;
    }

    if !resources.iommus.is_empty() {
        let mut iommus_val = Vec::new();
        for (t, id, vsids) in &resources.iommus {
            let phandle = get_iommu_phandle(*t, *id, phandles)?;
            iommus_val.push(phandle);
            iommus_val.extend_from_slice(vsids);
        }
        node.set_prop("iommus", iommus_val)?;
    }

    Ok(())
}

/// Apply multiple device tree overlays to the base FDT.
///
/// # Arguments
///
/// * `fdt` - The base FDT
/// * `overlays` - A vector of overlay files to apply
/// * `devices` - A vector of device resource descriptors to amend the overlay nodes with
#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn apply_device_tree_overlays(
    fdt: &mut Fdt,
    overlays: Vec<DtbOverlay>,
    mut devices: Vec<PlatformBusResources>,
    phandles: &BTreeMap<&str, u32>,
) -> Result<()> {
    for mut dtbo in overlays {
        let mut buffer = Vec::new();
        dtbo.file
            .read_to_end(&mut buffer)
            .map_err(Error::FdtIoError)?;
        let mut overlay = Fdt::from_blob(buffer.as_slice())?;

        // Find device node paths corresponding to the resources.
        let mut node_paths = vec![];
        let devs_in_overlay;
        (devs_in_overlay, devices) = devices.into_iter().partition(|r| {
            if let Ok(path) = overlay.symbol_to_path(&r.dt_symbol) {
                node_paths.push(path);
                true
            } else {
                false
            }
        });

        // Update device nodes found in this overlay, and then apply the overlay.
        for (path, res) in node_paths.into_iter().zip(&devs_in_overlay) {
            update_device_nodes(path, &mut overlay, res, phandles)?;
        }

        // Unfiltered DTBOs applied as whole.
        if !dtbo.do_filter {
            apply_overlay::<&str>(fdt, overlay, [])?;
        } else if !devs_in_overlay.is_empty() {
            apply_overlay(fdt, overlay, devs_in_overlay.iter().map(|r| &r.dt_symbol))?;
        }
    }

    if devices.is_empty() {
        Ok(())
    } else {
        Err(Error::ApplyOverlayError(format!(
            "labels {:#?} not found in overlay files",
            devices.iter().map(|r| &r.dt_symbol).collect::<Vec<_>>()
        )))
    }
}
