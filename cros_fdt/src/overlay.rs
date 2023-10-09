// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module applies binary flattened device tree overlays.

use std::collections::BTreeMap;
use std::collections::VecDeque;

use crate::fdt::Error;
use crate::fdt::Fdt;
use crate::fdt::FdtNode;
use crate::fdt::FdtReserveEntry;
use crate::fdt::Result;
use crate::path::parse_path_with_prop;
use crate::path::Path;
use crate::path::PhandlePin;
use crate::path::PATH_SEP;

const PHANDLE_PROP: &str = "phandle";
const LINUX_PHANDLE_PROP: &str = "linux,phandle";
const TARGET_PATH_PROP: &str = "target-path";
const TARGET_PROP: &str = "target";
const LOCAL_FIXUPS_NODE: &str = "__local_fixups__";
const OVERLAY_NODE: &str = "__overlay__";
const SYMBOLS_NODE: &str = "__symbols__";
const FIXUPS_NODE: &str = "__fixups__";
const ROOT_NODE: &str = "/";

// Read 'phandle' or 'linux,phandle' property of a node.
fn get_node_phandle(node: &FdtNode) -> Option<u32> {
    node.get_prop(PHANDLE_PROP)
        .or_else(|| node.get_prop(LINUX_PHANDLE_PROP))
}

// Return the largest phandle value in a node tree.
fn get_max_phandle(root_node: &FdtNode) -> u32 {
    let mut max_phandle = 0u32;
    let mut nodes_to_visit = VecDeque::new();
    nodes_to_visit.push_back(root_node);
    while let Some(node) = nodes_to_visit.pop_front() {
        max_phandle = max_phandle.max(get_node_phandle(node).unwrap_or(0u32));
        nodes_to_visit.extend(node.iter_subnodes());
    }
    max_phandle
}

// Add the given delta to the phandle property of the node.
fn offset_phandle_prop(node: &mut FdtNode, propname: &str, delta: u32) -> Result<()> {
    let mut val: u32 = node.get_prop(propname).ok_or_else(|| {
        Error::ApplyOverlayError(format!(
            "cannot offset {}:{} - invalid value",
            node.name, propname
        ))
    })?;
    val = val
        .checked_add(delta)
        .ok_or_else(|| Error::ApplyOverlayError("cannot offset phandle - value overflow".into()))?;
    node.set_prop(propname, val)
        .expect("phandle property name is valid");
    Ok(())
}

// Add the given delta to phandle properties of all nodes in the FDT.
fn offset_phandle_values(fdt: &mut Fdt, delta: u32) -> Result<()> {
    let mut stack = VecDeque::new();
    stack.push_back(&mut fdt.root);
    while let Some(node) = stack.pop_front() {
        if node.has_prop(PHANDLE_PROP) {
            offset_phandle_prop(node, PHANDLE_PROP, delta)?;
        }
        if node.has_prop(LINUX_PHANDLE_PROP) {
            offset_phandle_prop(node, LINUX_PHANDLE_PROP, delta)?;
        }
        stack.extend(node.iter_subnodes_mut());
    }
    Ok(())
}

// Returns a vector of paths which contain a local phandle value (reference)
fn collect_local_fixup_paths(fdt: &Fdt) -> Result<BTreeMap<Path, Vec<PhandlePin>>> {
    let mut local_phandles = BTreeMap::<Path, Vec<PhandlePin>>::new();
    let Some(local_fixups_node) = fdt.root.subnode(LOCAL_FIXUPS_NODE) else {
        return Ok(local_phandles);
    };
    let mut stack = VecDeque::<(Path, &FdtNode)>::new();
    stack.push_back((ROOT_NODE.parse().unwrap(), local_fixups_node));

    // Collect local phandle properties to fixup from __local_fixups__
    while let Some((path, node)) = stack.pop_front() {
        // Every property in __local_fixups__ contains a vector of offsets (u32)
        // where the phandles are located
        for propname in node.prop_names() {
            let offsets = node.get_prop::<Vec<u32>>(propname).ok_or_else(|| {
                Error::ApplyOverlayError(format!(
                    "fixup node {} contains invalid offset array",
                    node.name
                ))
            })?;
            // Add phandle pins
            if !local_phandles.contains_key(&path) {
                local_phandles.insert(path.clone(), vec![]);
            }
            let pins = local_phandles.get_mut(&path).unwrap();
            pins.extend(offsets.into_iter().map(|o| PhandlePin(propname.into(), o)));
        }
        // Traverse into this node's children
        for child in node.iter_subnodes() {
            stack.push_back((path.push(&child.name)?, child));
        }
    }
    Ok(local_phandles)
}

fn update_local_phandle_propvals(
    fdt: &mut Fdt,
    paths: BTreeMap<Path, Vec<PhandlePin>>,
    delta: u32,
) -> Result<()> {
    // Update phandles in collected locations
    for (path, pins) in &paths {
        let node = fdt
            .get_node_mut(path)
            .ok_or_else(|| Error::ApplyOverlayError("cannot find node for fixup".into()))?;
        for pin in pins {
            let phandle_val = node
                .phandle_at_offset(&pin.0, pin.1 as usize)
                .ok_or_else(|| Error::ApplyOverlayError(format!("missing property {}", &pin.0)))?;
            node.update_phandle_at_offset(&pin.0, pin.1 as usize, phandle_val + delta)?;
        }
    }
    Ok(())
}

fn update_local_refs(fdt: &mut Fdt, delta: u32) -> Result<()> {
    let phandle_locations = collect_local_fixup_paths(fdt)?;
    update_local_phandle_propvals(fdt, phandle_locations, delta)
}

// Given a DT symbol (label), find the path and phandle value of the node the symbol refers to.
fn get_symbol_path_and_phandle(symbol: &str, fdt: &Fdt) -> Option<(String, u32)> {
    let symbols_node = fdt.root.subnode(SYMBOLS_NODE)?;
    let symbol = symbols_node.get_prop::<String>(symbol)?;
    let target_node_path = Path::try_from(symbol.as_str()).ok()?;
    let target_node = fdt.get_node(&target_node_path)?;
    Some((symbol, get_node_phandle(target_node)?))
}

// For each symbol defined in base and referenced in overlay, set its references in overlay to
// correct phandle values.
fn apply_external_fixups(base: &Fdt, overlay: &mut Fdt) -> Result<()> {
    let Some(fixups_node) = overlay.root.subnode(FIXUPS_NODE) else {
        return Ok(()); // No references to base nodes
    };

    // Collect locations in overlay where external nodes are referenced
    let mut paths_to_update = BTreeMap::<(String, u32), Vec<String>>::new();
    for fixup_symbol in fixups_node.prop_names() {
        // Find phandle value and path of a labeled node in base DT
        let path_and_phandle =
            get_symbol_path_and_phandle(fixup_symbol, base).ok_or_else(|| {
                Error::ApplyOverlayError(format!("cannot find symbol {fixup_symbol} in base fdt"))
            })?;
        // Get target paths of this symbol in overlay
        let target_paths: Vec<String> = fixups_node.get_prop(fixup_symbol).ok_or_else(|| {
            Error::ApplyOverlayError(format!(
                "cannot parse target paths for fixup {fixup_symbol}"
            ))
        })?;
        paths_to_update.insert(path_and_phandle, target_paths);
    }

    // Update locations in overlay where external nodes are referenced
    for ((base_path, phandle), paths) in paths_to_update {
        for path in paths {
            let (path, pin) = parse_path_with_prop(&path)?;
            // Update phandle reference in target to new value
            let target_node = overlay.get_node_mut(&path).ok_or_else(|| {
                Error::ApplyOverlayError(format!("invalid fixup target path {path}"))
            })?;
            target_node.update_phandle_at_offset(&pin.0, pin.1 as usize, phandle)?;

            // If the property that is being updated here is actually a `target` property of
            // an overlay fragment, also add the `target-path` property to the fragment, containing
            // the full path to the target node in base FDT.
            // This covers the case where the target of an overlay fragment is a phandle reference
            // (of a node in base overlay), instead of absolute path in base.
            if pin.0 == TARGET_PROP && target_node.iter_subnodes().any(|n| n.name == OVERLAY_NODE) {
                target_node.set_prop(TARGET_PATH_PROP, base_path.as_str())?;
            }
        }
    }
    Ok(())
}

// Copy properties from overlay node to base node, then add subnodes and overlay them as well.
fn overlay_node_pair(base_node: &mut FdtNode, overlay_node: &FdtNode) -> Result<()> {
    base_node.props.extend(overlay_node.props.clone());
    for overlay_subnode in overlay_node.iter_subnodes() {
        overlay_node_pair(
            base_node.subnode_mut(&overlay_subnode.name)?,
            overlay_subnode,
        )?;
    }
    Ok(())
}

// Verify and apply an overlay fragment node to the base FDT.
fn overlay_fragment(fragment_node: &FdtNode, base: &mut Fdt) -> Result<()> {
    // Fragment must have an '__overlay__' subnode and `target-path` property.
    let Some(overlay_node) = fragment_node.subnode(OVERLAY_NODE) else {
        return Ok(()); // Skip invalid fragments.
    };
    let Some(target_path) = fragment_node.get_prop::<String>(TARGET_PATH_PROP) else {
        return Ok(()); // Skip invalid fragments.
    };
    // Apply overlay fragment to target node in base FDT.
    let target_node = base.get_node_mut(&target_path).ok_or_else(|| {
        Error::ApplyOverlayError(format!(
            "cannot find node in base FDT for target-path {target_path}",
        ))
    })?;
    overlay_node_pair(target_node, overlay_node)
}

// Parse the location of the symbol (property value), extract fragment name and the
// rest of the path after `__overlay__`, (expected structure:
// "/fragment@X/__overlay__/path/to/subnode").
fn extract_fragment_and_subpath(path: &Path) -> Result<(&str, String)> {
    let mut path_iter = path.iter();
    let fragment_name = path_iter
        .next()
        .ok_or_else(|| Error::ApplyOverlayError(format!("symbol path {path} too short")))?;
    path_iter.next(); // Skip "__overlay__" node
    let rest = path_iter.collect::<Vec<_>>();
    if rest.is_empty() {
        Err(Error::ApplyOverlayError(format!(
            "symbol path {path} too short"
        )))
    } else {
        Ok((fragment_name, rest.join(PATH_SEP)))
    }
}

fn update_base_symbols(base: &mut Fdt, overlay: &Fdt) -> Result<()> {
    let Some(overlay_symbols_node) = overlay.root.subnode(SYMBOLS_NODE) else {
        return Ok(()); // If there are no symbols in the overlay, just skip it.
    };
    let base_symbols_node = base.root.subnode_mut(SYMBOLS_NODE).unwrap();
    for symbol in overlay_symbols_node.prop_names() {
        let symbol_target: Path = overlay_symbols_node
            .get_prop::<String>(symbol)
            .unwrap()
            .parse()?;

        // Parse location
        let (fragment_name, rest) = extract_fragment_and_subpath(&symbol_target)?;

        // Find the overlay fragment
        let fragment_node = overlay.root.subnode(fragment_name).ok_or_else(|| {
            Error::ApplyOverlayError(format!("invalid symbol path {symbol_target}"))
        })?;

        // Construct the new symbol path from `target-path` property value and the remainder of
        // the symbol location. Eg, for target-path = "/node", and overlay symbol path
        // "/fragment@X/__overlay__/path/to/subnode", the result is "/node/path/to/subnode".
        let new_path: String = fragment_node
            .get_prop::<String>(TARGET_PATH_PROP)
            .unwrap_or_default()
            .parse::<Path>()?
            .push(&rest)?
            .into();
        // Update base with new symbol path. `symbol` is a valid property name.
        base_symbols_node.set_prop(symbol, new_path).unwrap();
    }
    Ok(())
}

// Merge new reserved memory entries from overlay into base.
fn merge_resvmem(base: &mut Vec<FdtReserveEntry>, new_entries: Vec<FdtReserveEntry>) {
    base.extend(new_entries);
    base.sort_by_key(|a| std::cmp::Reverse(a.address));
    if let Some(mut entry) = base.pop() {
        let mut result = Vec::new();
        while let Some(next_entry) = base.pop() {
            if next_entry.address <= entry.address + entry.size {
                entry.size = (entry.address + entry.size).max(next_entry.address + next_entry.size)
                    - entry.address;
            } else {
                result.push(entry);
                entry = next_entry;
            }
        }
        result.push(entry);
        base.extend(result);
    }
}

/// Apply an overlay to the base FDT.
///
/// # Arguments
///
/// `base` - base FDT that will be updated with new nodes and properties.
/// `overlay` - overlay FDT that will be applied to the base. Must contain symbols and fixups nodes.
pub fn apply_overlay(base: &mut Fdt, mut overlay: Fdt) -> Result<()> {
    // Offset phandle property values in overlay nodes
    let max_phandle = get_max_phandle(&base.root);
    offset_phandle_values(&mut overlay, max_phandle)?;

    // Offset local phandle references in overlay properties
    update_local_refs(&mut overlay, max_phandle)?;

    // Apply phandle values for external references
    apply_external_fixups(base, &mut overlay)?;

    // Merge nodes from overlay into base
    for fragment_node in overlay.root.iter_subnodes() {
        overlay_fragment(fragment_node, base)?;
    }

    // Apply __symbols__ to base
    update_base_symbols(base, &overlay)?;

    // Merge reserved regions
    merge_resvmem(&mut base.reserved_memory, overlay.reserved_memory);
    Ok(())
}
