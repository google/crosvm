// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;

use cros_fdt::apply_overlay;
use cros_fdt::Error;
use cros_fdt::Fdt;
use cros_fdt::FdtNode;
use cros_fdt::Result;
use devices::IommuDevType;
use devices::PlatformBusResources;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::MemoryRegionInformation;
use vm_memory::MemoryRegionPurpose;

/// Device tree overlay file
pub struct DtbOverlay {
    /// Device tree overlay file to apply
    pub file: File,
    /// Labels of nodes to include in the final device tree.
    pub symbol_allowlist: Option<BTreeSet<String>>,
}

/// Apply multiple device tree overlays to the base FDT.
#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub fn apply_device_tree_overlays(
    fdt: &mut Fdt,
    overlays: &[DtbOverlay],
    _devices: &[PlatformBusResources],
    _phandles: &BTreeMap<&str, u32>,
) -> Result<()> {
    for dtbo in overlays {
        let mut buffer = Vec::new();
        (&dtbo.file)
            .read_to_end(&mut buffer)
            .map_err(Error::FdtIoError)?;
        let overlay = Fdt::from_blob(buffer.as_slice())?;
        if let Some(allowlist) = &dtbo.symbol_allowlist {
            if !allowlist.is_empty() {
                apply_overlay(fdt, overlay, allowlist)?;
            }
        } else {
            apply_overlay::<&str>(fdt, overlay, [])?;
        }
    }
    Ok(())
}

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(unused))]
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

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(unused))]
fn get_power_domain_phandle(offset: usize, phandles: &BTreeMap<&str, u32>) -> Result<u32> {
    phandles
        .get(format!("dev_pd{offset}").as_str())
        .copied()
        .ok_or(Error::MissingPowerDomain(offset))
}

// Find the device node at given path and update its `reg` and `interrupts` properties using
// its platform resources.
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(unused))]
fn patch_fdt_node(
    node: &mut FdtNode,
    resources: &PlatformBusResources,
    phandles: &BTreeMap<&str, u32>,
    power_domain_count: &mut usize,
) -> Result<()> {
    const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
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
            for vsid in vsids {
                iommus_val.push(phandle);
                iommus_val.push(*vsid);
            }
        }
        node.set_prop("iommus", iommus_val)?;
    }

    if resources.requires_power_domain {
        let phandle = get_power_domain_phandle(*power_domain_count, phandles)?;
        node.set_prop("power-domains", phandle)?;
        *power_domain_count += 1;
    }

    Ok(())
}

/// Apply multiple device tree overlays to the base FDT.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn apply_device_tree_overlays(
    fdt: &mut Fdt,
    overlays: &[DtbOverlay],
    devices: &[PlatformBusResources],
    phandles: &BTreeMap<&str, u32>,
) -> Result<()> {
    let mut power_domain_count = 0;
    let mut devices: Vec<&_> = devices.iter().collect();
    for dtbo in overlays {
        let mut buffer = Vec::new();
        (&dtbo.file)
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
            let node = overlay.get_node_mut(path).ok_or_else(|| {
                Error::InvalidPath(format!(
                    "cannot find FDT node for dt-symbol {}",
                    &res.dt_symbol
                ))
            })?;
            patch_fdt_node(node, res, phandles, &mut power_domain_count)?;
        }

        // Apply overlay, optionally filtered by label allowlist.
        if let Some(allowlist) = &dtbo.symbol_allowlist {
            if !allowlist.is_empty() {
                apply_overlay(fdt, overlay, allowlist)?;
            }
        } else {
            apply_overlay::<&str>(fdt, overlay, [])?;
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

/// Create a "/memory" node describing all guest memory regions.
pub fn create_memory_node(fdt: &mut Fdt, guest_mem: &GuestMemory) -> Result<()> {
    let mut mem_reg_prop = Vec::new();
    let mut previous_memory_region_end = None;
    let mut regions: Vec<MemoryRegionInformation> = guest_mem
        .regions()
        .filter(|region| match region.options.purpose {
            MemoryRegionPurpose::Bios => false,
            MemoryRegionPurpose::GuestMemoryRegion => true,
            MemoryRegionPurpose::ProtectedFirmwareRegion => true,
            MemoryRegionPurpose::ReservedMemory => true,
            #[cfg(target_arch = "aarch64")]
            MemoryRegionPurpose::StaticSwiotlbRegion => true,
        })
        .collect();
    regions.sort_by(|a, b| a.guest_addr.cmp(&b.guest_addr));
    for region in regions {
        // Merge with the previous region if possible.
        if let Some(previous_end) = previous_memory_region_end {
            if region.guest_addr == previous_end {
                *mem_reg_prop.last_mut().unwrap() += region.size as u64;
                previous_memory_region_end =
                    Some(previous_end.checked_add(region.size as u64).unwrap());
                continue;
            }
            assert!(region.guest_addr > previous_end, "Memory regions overlap");
        }

        mem_reg_prop.push(region.guest_addr.offset());
        mem_reg_prop.push(region.size as u64);
        previous_memory_region_end =
            Some(region.guest_addr.checked_add(region.size as u64).unwrap());
    }

    let memory_node = fdt.root_mut().subnode_mut("memory")?;
    memory_node.set_prop("device_type", "memory")?;
    memory_node.set_prop("reg", mem_reg_prop)?;
    Ok(())
}

pub struct ReservedMemoryRegion<'a> {
    pub name: &'a str,
    pub address: Option<GuestAddress>,
    pub size: u64,
    pub phandle: Option<u32>,
    pub compatible: Option<&'a str>,
    pub alignment: Option<u64>,
    pub no_map: bool,
}

/// Create a "/reserved-memory" node with child nodes for `reserved_regions`.
pub fn create_reserved_memory_node(
    fdt: &mut Fdt,
    reserved_regions: &[ReservedMemoryRegion],
) -> Result<()> {
    if reserved_regions.is_empty() {
        return Ok(());
    }

    let resv_memory_node = fdt.root_mut().subnode_mut("reserved-memory")?;
    resv_memory_node.set_prop("#address-cells", 0x2u32)?;
    resv_memory_node.set_prop("#size-cells", 0x2u32)?;
    resv_memory_node.set_prop("ranges", ())?;

    for region in reserved_regions {
        let child_node = if let Some(resv_addr) = region.address {
            let node =
                resv_memory_node.subnode_mut(&format!("{}@{:x}", region.name, resv_addr.0))?;
            node.set_prop("reg", &[resv_addr.0, region.size])?;
            node
        } else {
            let node = resv_memory_node.subnode_mut(region.name)?;
            node.set_prop("size", region.size)?;
            node
        };

        if let Some(phandle) = region.phandle {
            child_node.set_prop("phandle", phandle)?;
        }
        if let Some(compatible) = region.compatible {
            child_node.set_prop("compatible", compatible)?;
        }
        if let Some(alignment) = region.alignment {
            child_node.set_prop("alignment", alignment)?;
        }
        if region.no_map {
            child_node.set_prop("no-map", ())?;
        }
    }

    Ok(())
}

/// Collect a list of `ReservedMemoryRegion`s for any `MemoryRegionPurpose::ReservedMemory` regions
/// in `GuestMemory`.
pub fn reserved_memory_regions_from_guest_mem(
    guest_mem: &GuestMemory,
) -> Vec<ReservedMemoryRegion> {
    guest_mem
        .regions()
        .filter(|region| region.options.purpose == MemoryRegionPurpose::ReservedMemory)
        .map(|region| ReservedMemoryRegion {
            address: Some(region.guest_addr),
            size: region.size.try_into().unwrap(),
            name: "reserved",
            phandle: None,
            compatible: None,
            alignment: None,
            no_map: true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_fdt_node() {
        let mut fdt = Fdt::new(&[]);
        let root = fdt.root_mut();

        let resources = PlatformBusResources {
            dt_symbol: "test".to_string(),
            regions: vec![(0x1000, 0x100)],
            irqs: vec![(5, 1)],
            iommus: vec![(IommuDevType::PkvmPviommu, Some(1), vec![10])],
            requires_power_domain: true,
        };

        let mut phandles = BTreeMap::new();
        phandles.insert("dev_pd0", 42);
        phandles.insert("pviommu1", 43);

        let mut power_domain_count = 0;

        patch_fdt_node(root, &resources, &phandles, &mut power_domain_count).unwrap();

        assert_eq!(root.get_prop("reg"), Some(vec![0x1000u64, 0x100]));
        assert_eq!(root.get_prop("interrupts"), Some(vec![0u32, 5, 1]));
        assert_eq!(root.get_prop("power-domains"), Some(vec![42u32]));
        assert_eq!(root.get_prop("iommus"), Some(vec![43u32, 10]));
        assert_eq!(power_domain_count, 1);
    }

    #[test]
    fn test_patch_fdt_node_power_domain_offsets() {
        let mut fdt = Fdt::new(&[]);
        let root = fdt.root_mut();

        let resources = PlatformBusResources {
            dt_symbol: "test".to_string(),
            regions: vec![],
            irqs: vec![],
            iommus: vec![],
            requires_power_domain: true,
        };

        let mut phandles = BTreeMap::new();
        phandles.insert("dev_pd1", 42);

        let mut power_domain_count = 1;

        patch_fdt_node(root, &resources, &phandles, &mut power_domain_count).unwrap();

        assert_eq!(root.get_prop("power-domains"), Some(vec![42u32]));
        assert_eq!(power_domain_count, 2);
    }

    #[test]
    fn test_patch_fdt_node_multiple_properties() {
        let mut fdt = Fdt::new(&[]);
        let root = fdt.root_mut();

        let resources = PlatformBusResources {
            dt_symbol: "test".to_string(),
            regions: vec![(0x1000, 0x100), (0x2000, 0x200)],
            irqs: vec![(5, 1), (6, 2)],
            iommus: vec![
                (IommuDevType::PkvmPviommu, Some(1), vec![10]),
                (IommuDevType::PkvmPviommu, Some(2), vec![20]),
            ],
            requires_power_domain: false,
        };

        let mut phandles = BTreeMap::new();
        phandles.insert("pviommu1", 42);
        phandles.insert("pviommu2", 43);

        let mut power_domain_count = 0;

        patch_fdt_node(root, &resources, &phandles, &mut power_domain_count).unwrap();

        assert_eq!(
            root.get_prop("reg"),
            Some(vec![0x1000u64, 0x100, 0x2000, 0x200])
        );
        assert_eq!(root.get_prop("interrupts"), Some(vec![0u32, 5, 1, 0, 6, 2]));
        assert_eq!(root.get_prop("iommus"), Some(vec![42u32, 10, 43, 20]));
    }

    #[test]
    fn test_patch_fdt_node_non_root() {
        let mut fdt = Fdt::new(&[]);
        let root = fdt.root_mut();
        let subnode = root.subnode_mut("subnode").unwrap();

        let resources = PlatformBusResources {
            dt_symbol: "test".to_string(),
            regions: vec![(0x1000, 0x100)],
            irqs: vec![],
            iommus: vec![],
            requires_power_domain: false,
        };

        let phandles = BTreeMap::new();
        let mut power_domain_count = 0;

        patch_fdt_node(subnode, &resources, &phandles, &mut power_domain_count).unwrap();

        assert_eq!(subnode.get_prop("reg"), Some(vec![0x1000u64, 0x100]));
    }

    #[test]
    fn test_patch_fdt_node_non_pkvm_iommu() {
        let mut fdt = Fdt::new(&[]);
        let root = fdt.root_mut();

        let resources = PlatformBusResources {
            dt_symbol: "test".to_string(),
            regions: vec![],
            irqs: vec![],
            iommus: vec![(IommuDevType::VirtioIommu, Some(1), vec![10])],
            requires_power_domain: false,
        };

        let phandles = BTreeMap::new();
        let mut power_domain_count = 0;

        let result = patch_fdt_node(root, &resources, &phandles, &mut power_domain_count);
        assert!(matches!(
            result,
            Err(Error::MissingIommuPhandle(msg, id)) if msg == "VirtioIommu" && id == Some(1)
        ));
    }

    #[test]
    fn test_patch_fdt_node_missing_phandle() {
        let mut fdt = Fdt::new(&[]);
        let root = fdt.root_mut();

        let resources = PlatformBusResources {
            dt_symbol: "test".to_string(),
            regions: vec![],
            irqs: vec![],
            iommus: vec![(IommuDevType::PkvmPviommu, Some(1), vec![10])],
            requires_power_domain: false,
        };

        let phandles = BTreeMap::new();
        let mut power_domain_count = 0;

        let result = patch_fdt_node(root, &resources, &phandles, &mut power_domain_count);
        assert!(matches!(
            result,
            Err(Error::MissingIommuPhandle(msg, id)) if msg == "PkvmPviommu" && id == Some(1)
        ));
    }
}
