// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module applies binary flattened device tree overlays.

use std::collections::BTreeMap;
use std::collections::HashSet;
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

// Ensure filtered symbols exist and contain a valid path. They will be the starting points
// for the filtering algorithm.
fn prepare_filtered_symbols<T: AsRef<str>>(
    start_symbols: impl std::iter::IntoIterator<Item = T>,
    fdt: &Fdt,
) -> Result<(HashSet<String>, Vec<Path>)> {
    let symbols = HashSet::from_iter(start_symbols.into_iter().map(|s| s.as_ref().to_owned()));
    let mut paths = vec![];
    for symbol in &symbols {
        paths.push(
            fdt.symbol_to_path(symbol)
                .map_err(|e| Error::FilterError(format!("{e}")))?,
        );
    }
    Ok((symbols, paths))
}

// Look for references (phandle values) defined by `fixup_node` in properties of `tree_node`.
fn collect_phandle_refs_from_props(fixup_node: &FdtNode, tree_node: &FdtNode) -> Result<Vec<u32>> {
    let mut phandles = vec![];
    for propname in fixup_node.prop_names() {
        for phandle_offset in fixup_node.get_prop::<Vec<u32>>(propname).unwrap() {
            phandles.push(
                tree_node
                    .phandle_at_offset(propname, phandle_offset as usize)
                    .ok_or(Error::PropertyValueInvalid)?,
            );
        }
    }
    Ok(phandles)
}

// Traverse all nodes along given node path, and collect phandle reference values from properties.
fn collect_all_references_by_path(
    path: &Path,
    root: &FdtNode,
    local_fixups_node: &FdtNode,
) -> Result<HashSet<u32>> {
    // Follow node names inside the local fixups node and in the tree root.
    let mut tree_node = root;
    let mut fixup_node = local_fixups_node;
    let mut phandle_refs = HashSet::<u32>::new();

    // Follow node names along path
    for node_name in path.iter() {
        tree_node = tree_node
            .subnode(node_name)
            .ok_or_else(|| Error::InvalidPath(format!("cannot find subnode {}", node_name)))?;
        if let Some(n) = fixup_node.subnode(node_name) {
            fixup_node = n
        } else {
            return Ok(phandle_refs); // No references left to collect in this subtree.
        }

        // Look for references (phandle values) in properties along path; add them to set.
        phandle_refs.extend(collect_phandle_refs_from_props(fixup_node, tree_node)?);
    }
    Ok(phandle_refs)
}

// Collect locations of all phandles in the FDT.
fn get_all_phandles(fdt: &Fdt) -> BTreeMap<u32, Path> {
    let mut phandles = BTreeMap::new();
    let mut nodes = VecDeque::<(&FdtNode, Path)>::new();
    nodes.push_back((&fdt.root, ROOT_NODE.parse().unwrap()));
    while let Some((node, path)) = nodes.pop_front() {
        for subnode in node.iter_subnodes() {
            nodes.push_back((subnode, path.push(&subnode.name).unwrap()));
        }
        if let Some(phandle) = get_node_phandle(node) {
            phandles.insert(phandle, path);
        }
    }
    phandles
}

// Minimize paths - if the vector contains two paths where one is the
// parent of the other, only include the parent path, and drop the child path.
fn minimize_paths(paths: &mut Vec<Path>) {
    paths.sort();
    paths.dedup_by(|a, b| a.is_child_of(b));
}

// Collect paths of all nodes that nodes in `start_paths` depend on. Path A depends on
// path B if any node along the path A references the node path B points to.
fn collect_all_filtered_paths(mut start_paths: Vec<Path>, fdt: &Fdt) -> Result<Vec<Path>> {
    if start_paths.is_empty() {
        return Ok(vec![]);
    }
    minimize_paths(&mut start_paths);
    let Some(local_fixups_node) = fdt.root.subnode(LOCAL_FIXUPS_NODE) else {
        return Ok(start_paths); // No fixups node -> no other references
    };

    let all_phandles = get_all_phandles(fdt); // All FDT phandles, mapped to their paths
    let mut result_paths = HashSet::<Path>::with_capacity(start_paths.len());
    let mut pending_paths: VecDeque<_> = start_paths.iter().collect(); // Paths to visit

    while let Some(path) = pending_paths.pop_front() {
        if result_paths.contains(path) {
            continue; // Already seen this path
        }
        // Collect all phandles that this path references
        let phandles = collect_all_references_by_path(path, &fdt.root, local_fixups_node)?;
        // Map the phandles to other locations
        for ph in phandles {
            pending_paths.push_back(all_phandles.get(&ph).ok_or(Error::PropertyValueInvalid)?);
        }
        // This path should remain in the final overlay.
        result_paths.insert(path.to_owned());
    }

    let mut result_paths = result_paths.into_iter().collect();
    minimize_paths(&mut result_paths);
    Ok(result_paths)
}

// Drop nodes which are not covered by the filtered paths.
fn do_overlay_filter(filtered_paths: Vec<Path>, overlay: &mut Fdt) {
    if filtered_paths.is_empty() {
        return;
    }
    let mut new_root = FdtNode::empty("").unwrap();
    for path in filtered_paths {
        let mut src_node = &overlay.root;
        let mut tgt_node = &mut new_root;
        for node_name in path.iter() {
            src_node = src_node
                .subnode(node_name)
                .expect("filtered paths reference valid nodes");
            tgt_node = tgt_node
                .subnode_mut(node_name)
                .expect("filtered paths reference valid nodes");
            tgt_node.props = src_node.props.clone();
        }
    }
    overlay.root = new_root;
}

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
    for (path, pins) in paths {
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
    let target_node = fdt.get_node(symbol.as_str())?;
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
            let target_node = overlay
                .get_node_mut(path)
                .ok_or_else(|| Error::ApplyOverlayError("invalid fixup target path".into()))?;
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
    let target_node = base.get_node_mut(target_path.as_str()).ok_or_else(|| {
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

fn update_base_symbols(
    base: &mut Fdt,
    overlay: &Fdt,
    filtered_symbols: HashSet<String>,
) -> Result<()> {
    let Some(overlay_symbols_node) = overlay.root.subnode(SYMBOLS_NODE) else {
        return Ok(()); // If there are no symbols in the overlay, just skip it.
    };
    let base_symbols_node = base.root.subnode_mut(SYMBOLS_NODE).unwrap();
    for symbol in overlay_symbols_node.prop_names() {
        if !filtered_symbols.is_empty() && !filtered_symbols.contains(symbol) {
            continue; // Skip this symbol, it is not in the set of symbols we want.
        }

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
/// `filtered_symbols` - A slice of node labels (symbols) listing nodes which will be applied to the
///     base. Values must correspond to the properties of overlay `__symbols__` node. If empty, the
///     entire overlay is applied to base.
pub fn apply_overlay<T: AsRef<str>>(
    base: &mut Fdt,
    mut overlay: Fdt,
    filter_symbols: impl std::iter::IntoIterator<Item = T>,
) -> Result<()> {
    // Analyze filtered symbols and find paths they point to.
    let (filter_symbols, filter_paths) = prepare_filtered_symbols(filter_symbols, &overlay)?;

    // Analyze the overlay tree and extract paths that have to be applied to base.
    let filtered_paths = collect_all_filtered_paths(filter_paths, &overlay)?;

    // Offset phandle property values in overlay nodes
    let max_phandle = get_max_phandle(&base.root);
    offset_phandle_values(&mut overlay, max_phandle)?;

    // Offset local phandle references in overlay properties
    update_local_refs(&mut overlay, max_phandle)?;

    // Apply phandle values for external references
    apply_external_fixups(base, &mut overlay)?;

    // Copy filtered overlay __symbols__ to base
    update_base_symbols(base, &overlay, filter_symbols)?;

    // Remove unneeded nodes
    do_overlay_filter(filtered_paths, &mut overlay);

    // Merge nodes from overlay into base
    for fragment_node in overlay.root.iter_subnodes() {
        overlay_fragment(fragment_node, base)?;
    }

    // Merge reserved regions
    merge_resvmem(&mut base.reserved_memory, overlay.reserved_memory);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_fdt(mut reader: impl std::io::Read) -> Result<Fdt> {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(Error::FdtIoError)?;
        Fdt::from_blob(&buffer[..])
    }

    #[test]
    fn fdt_merge_resvmem() {
        let mut base = vec![
            FdtReserveEntry::new(1000, 100),
            FdtReserveEntry::new(2000, 500),
            FdtReserveEntry::new(3000, 1000),
        ];
        let new_entries = vec![
            FdtReserveEntry::new(1010, 20),
            FdtReserveEntry::new(1050, 1000),
            FdtReserveEntry::new(2700, 500),
        ];
        merge_resvmem(&mut base, new_entries);
        assert_eq!(
            base,
            vec![
                FdtReserveEntry::new(1000, 1500),
                FdtReserveEntry::new(2700, 1300),
            ]
        );
    }

    #[test]
    fn fdt_find_phandle_single() {
        let mut root = FdtNode::empty("").unwrap();
        root.set_prop("a", 1u32).unwrap();
        root.set_prop("b", 2u32).unwrap();
        root.set_prop("phandle", 3u32).unwrap();
        assert_eq!(get_node_phandle(&root), Some(3));
    }

    #[test]
    fn fdt_find_phandle_none() {
        let mut root = FdtNode::empty("").unwrap();
        root.set_prop("a", 1u32).unwrap();
        root.set_prop("b", 2u32).unwrap();
        assert_eq!(get_node_phandle(&root), None);
    }

    #[test]
    fn fdt_find_phandle_deprecated() {
        let mut root = FdtNode::empty("").unwrap();
        root.set_prop("a", 1u32).unwrap();
        root.set_prop("linux,phandle", 2u32).unwrap();
        assert_eq!(get_node_phandle(&root), Some(2));
    }

    #[test]
    fn fdt_find_max_phandle() {
        let mut root = FdtNode::empty("").unwrap();
        root.set_prop("phandle", 2u32).unwrap();
        let node_a = root.subnode_mut("a").unwrap();
        node_a.set_prop("linux,phandle", 4u32).unwrap();
        let node_b = root.subnode_mut("b").unwrap();
        node_b.set_prop("phandle", 0xAu32).unwrap();
        node_b.set_prop("linux,phandle", 0xAAu32).unwrap();

        let node_c = node_b.subnode_mut("c").unwrap();
        node_c.set_prop("linux,phandle", 0x10u32).unwrap();
        node_c.set_prop("not-phandle", 0x11u32).unwrap();
        let node_d = node_b.subnode_mut("d").unwrap();
        node_d.set_prop("not-phandle", 0x20u32).unwrap();
        node_b.subnode_mut("").unwrap();

        assert_eq!(get_max_phandle(&root), 0x10);
    }

    #[test]
    fn fdt_offset_phandles() {
        let mut fdt = Fdt::new(&[]);
        fdt.root.set_prop("a", 1u32).unwrap();
        fdt.root.set_prop("b", 2u32).unwrap();
        fdt.root.set_prop("phandle", 3u32).unwrap();
        let node_a = fdt.root.subnode_mut("a").unwrap();
        node_a.set_prop("linux,phandle", 0x10u32).unwrap();
        fdt.root.subnode_mut("b").unwrap();

        offset_phandle_values(&mut fdt, 100).unwrap();
        for (prop, exp_val) in fdt.root.prop_names().zip([1u32, 2, 103].into_iter()) {
            assert_eq!(fdt.root.get_prop::<u32>(prop).unwrap(), exp_val);
        }
        let node = fdt.get_node("/a").unwrap();
        assert_eq!(node.get_prop::<u32>(LINUX_PHANDLE_PROP).unwrap(), 116);
        let node = fdt.get_node("/b").unwrap();
        assert!(node.prop_names().next().is_none());
    }

    #[test]
    fn fdt_collect_local_references() {
        let mut fdt = Fdt::new(&[]);
        let fixups_node = fdt.root.subnode_mut(LOCAL_FIXUPS_NODE).unwrap();
        fixups_node.set_prop("p1", vec![0u32, 4u32]).unwrap();
        let fixups_subnode = fixups_node.subnode_mut("subnode1").unwrap();
        fixups_subnode.set_prop("p2", vec![8u32]).unwrap();
        let fixups_subnode = fixups_node.subnode_mut("subnode2").unwrap();
        fixups_subnode.set_prop("p1", vec![16u32, 24u32]).unwrap();

        let paths = collect_local_fixup_paths(&fdt).unwrap();
        assert_eq!(paths.len(), 3);

        let expected_paths: BTreeMap<Path, Vec<PhandlePin>> = BTreeMap::from([
            (
                ROOT_NODE.parse().unwrap(),
                vec![PhandlePin("p1".into(), 0), PhandlePin("p1".into(), 4)],
            ),
            (
                "/subnode1".parse().unwrap(),
                vec![PhandlePin("p2".into(), 8)],
            ),
            (
                "/subnode2".parse().unwrap(),
                vec![PhandlePin("p1".into(), 16), PhandlePin("p1".into(), 24)],
            ),
        ]);

        for (key, value) in expected_paths {
            assert!(value.eq(paths.get(&key).unwrap()));
        }
    }

    fn make_fragment0() -> FdtNode {
        let mut fragment_node = FdtNode::empty("fragment@0").unwrap();
        fragment_node.set_prop("target-path", ROOT_NODE).unwrap();

        let overlay_node = fragment_node.subnode_mut(OVERLAY_NODE).unwrap();
        overlay_node.set_prop("root-prop1", 1u32).unwrap();
        overlay_node
            .set_prop("root-prop2", vec![1u32, 2u32, 3u32])
            .unwrap();
        let overlay_child_node = overlay_node.subnode_mut("child1").unwrap();
        overlay_child_node.set_prop("prop1", 10u32).unwrap();
        overlay_child_node
            .set_prop("prop2", vec![10u32, 20u32, 30u32])
            .unwrap();
        fragment_node
    }

    fn make_fragment1() -> FdtNode {
        let mut fragment_node = FdtNode::empty("fragment@1").unwrap();
        fragment_node.set_prop("target-path", ROOT_NODE).unwrap();

        let overlay_node = fragment_node.subnode_mut(OVERLAY_NODE).unwrap();
        overlay_node.set_prop("root-prop1", "abc").unwrap();
        overlay_node.set_prop("root-prop3", 100u64).unwrap();
        let overlay_child_node = overlay_node.subnode_mut("child1").unwrap();
        overlay_child_node.set_prop("prop1", 0u32).unwrap();
        let _ = overlay_node.subnode_mut("child2").unwrap();
        fragment_node
    }

    #[test]
    fn fdt_test_overlay_nodes() {
        let mut base = Fdt::new(&[]);

        let fragment_node = make_fragment0();
        overlay_fragment(&fragment_node, &mut base).unwrap();

        assert_eq!(base.root.get_prop::<u32>("root-prop1").unwrap(), 1u32);
        assert_eq!(
            base.root.get_prop::<Vec<u32>>("root-prop2").unwrap(),
            vec![1u32, 2u32, 3u32]
        );
        let child_node = base.get_node("/child1").unwrap();
        assert_eq!(child_node.get_prop::<u32>("prop1").unwrap(), 10u32);
        assert_eq!(
            child_node.get_prop::<Vec<u32>>("prop2").unwrap(),
            vec![10u32, 20u32, 30u32]
        );

        let fragment_node = make_fragment1();
        overlay_fragment(&fragment_node, &mut base).unwrap();
        assert_eq!(
            base.root.get_prop::<Vec<u8>>("root-prop1").unwrap(),
            vec![b'a', b'b', b'c', 0u8]
        );
        assert_eq!(base.root.get_prop::<u64>("root-prop3").unwrap(), 100u64);

        let child_node = base.get_node("/child1").unwrap();
        assert_eq!(child_node.get_prop::<u32>("prop1").unwrap(), 0u32);

        let child_node = base.get_node("/child2").unwrap();
        assert!(child_node.prop_names().next().is_none());
    }

    #[test]
    fn fdt_overlay_symbols() {
        let mut base = Fdt::new(&[]);
        let symbols = base.root.subnode_mut(SYMBOLS_NODE).unwrap();

        symbols.set_prop("n1", "/path/to/node1").unwrap();
        symbols.set_prop("n2", "/path/to/node2").unwrap();

        let mut overlay = Fdt::new(&[]);
        let symbols = overlay.root.subnode_mut(SYMBOLS_NODE).unwrap();
        symbols
            .set_prop("n1", "/fragment@0/__overlay__/node1")
            .unwrap();
        symbols
            .set_prop("n3", "/fragment@0/__overlay__/path/to/node3")
            .unwrap();
        let fragment = overlay.root.subnode_mut("fragment@0").unwrap();
        fragment.set_prop("target-path", ROOT_NODE).unwrap();

        update_base_symbols(&mut base, &overlay, [].into()).unwrap();

        let symbols = base.root.subnode_mut(SYMBOLS_NODE).unwrap();
        assert_eq!(symbols.get_prop::<String>("n1").unwrap(), "/node1");
        assert_eq!(symbols.get_prop::<String>("n2").unwrap(), "/path/to/node2");
        assert_eq!(symbols.get_prop::<String>("n3").unwrap(), "/path/to/node3");
    }

    #[test]
    fn fdt_overlay_filtered_symbols() {
        let mut base = Fdt::new(&[]);

        let symbols = base.root.subnode_mut(SYMBOLS_NODE).unwrap();
        symbols.set_prop("n1", "/path/to/node1").unwrap();
        symbols.set_prop("n2", "/path/to/node2").unwrap();

        let mut overlay = Fdt::new(&[]);
        let symbols = overlay.root.subnode_mut(SYMBOLS_NODE).unwrap();
        symbols
            .set_prop("n1", "/fragment@0/__overlay__/node1")
            .unwrap();
        symbols
            .set_prop("n3", "/fragment@0/__overlay__/path/to/node3")
            .unwrap();
        symbols
            .set_prop("not-this", "/fragment@0/__overlay__/path/to/not-this")
            .unwrap();
        symbols
            .set_prop(
                "not-this-either",
                "/fragment@0/__overlay__/path/to/not-this-either",
            )
            .unwrap();
        let fragment = overlay.root.subnode_mut("fragment@0").unwrap();
        fragment.set_prop("target-path", ROOT_NODE).unwrap();

        update_base_symbols(
            &mut base,
            &overlay,
            ["n1".to_string(), "n3".to_string()].into(),
        )
        .unwrap();
        let symbols = base.root.subnode(SYMBOLS_NODE).unwrap();
        assert_eq!(symbols.get_prop::<String>("n1").unwrap(), "/node1");
        assert_eq!(symbols.get_prop::<String>("n2").unwrap(), "/path/to/node2");
        assert_eq!(symbols.get_prop::<String>("n3").unwrap(), "/path/to/node3");
        assert!(symbols.get_prop::<String>("not-this").is_none());
        assert!(symbols.get_prop::<String>("not-this-either").is_none());

        update_base_symbols(&mut base, &overlay, [].into()).unwrap();
        let symbols = base.root.subnode(SYMBOLS_NODE).unwrap();
        assert_eq!(symbols.get_prop::<String>("n1").unwrap(), "/node1");
        assert_eq!(symbols.get_prop::<String>("n2").unwrap(), "/path/to/node2");
        assert_eq!(symbols.get_prop::<String>("n3").unwrap(), "/path/to/node3");
        assert_eq!(
            symbols.get_prop::<String>("not-this").unwrap(),
            "/path/to/not-this"
        );
        assert_eq!(
            symbols.get_prop::<String>("not-this-either").unwrap(),
            "/path/to/not-this-either"
        );
    }

    fn make_fdt_with_local_refs(references: &[(&str, u32)]) -> Result<Fdt> {
        /* Returns this structure:
           /
               node1 (phandle=1)
                   node1-1 (phandle=2)
                       node1-1-1 (phandle=3)
                       node1-1-2 (phandle=4)
                   node1-2 (phandle=5)
                       node1-2-1 (phandle=6)
               node2 (phandle=7)
                   node2-1 (phandle=8)
                   node2-2 (phandle=9)
                   node2-3 (phandle=10)
                       node2-3-1 (phandle=11)
               node3 (phandle=12)
                   node3-1 (phandle=13)
               __local_fixups__
                   <references>
               __symbols__
                   <symbols>
        */
        let mut fdt = Fdt::new(&[]);
        let root = fdt.root_mut();

        let node1 = root.subnode_mut("node1")?;
        node1.set_prop(PHANDLE_PROP, 1u32)?;
        let node11 = node1.subnode_mut("node1-1")?;
        node11.set_prop(PHANDLE_PROP, 2u32)?;
        let node111 = node11.subnode_mut("node1-1-1")?;
        node111.set_prop(PHANDLE_PROP, 3u32)?;
        let node112 = node11.subnode_mut("node1-1-2")?;
        node112.set_prop(PHANDLE_PROP, 4u32)?;
        let node12 = node1.subnode_mut("node1-2")?;
        node12.set_prop(PHANDLE_PROP, 5u32)?;
        let node121 = node12.subnode_mut("node1-2-1")?;
        node121.set_prop(PHANDLE_PROP, 6u32)?;
        let node2 = root.subnode_mut("node2")?;
        node2.set_prop(PHANDLE_PROP, 7u32)?;
        let node21 = node2.subnode_mut("node2-1")?;
        node21.set_prop(PHANDLE_PROP, 8u32)?;
        let node22 = node2.subnode_mut("node2-2")?;
        node22.set_prop(PHANDLE_PROP, 9u32)?;
        let node23 = node2.subnode_mut("node2-3")?;
        node23.set_prop(PHANDLE_PROP, 10u32)?;
        let node231 = node23.subnode_mut("node2-3-1")?;
        node231.set_prop(PHANDLE_PROP, 11u32)?;
        let node3 = root.subnode_mut("node3")?;
        node3.set_prop(PHANDLE_PROP, 12u32)?;
        let node31 = node3.subnode_mut("node3-1")?;
        node31.set_prop(PHANDLE_PROP, 13u32)?;

        let symbols = root.subnode_mut(SYMBOLS_NODE)?;
        symbols.set_prop("node1", "/node1")?;
        symbols.set_prop("node1-1", "/node1/node1-1")?;
        symbols.set_prop("node1-1-2", "/node1/node1-1/node1-1-2")?;
        symbols.set_prop("node2", "/node2")?;
        symbols.set_prop("node2-3-1", "/node2/node2-3/node2-3-1")?;

        for (loc, phandle_val) in references {
            let (path, pin) = parse_path_with_prop(loc)?;
            // Write reference value in the tree sutrcture
            let mut node = fdt
                .get_node_mut(path.clone())
                .ok_or_else(|| Error::InvalidPath(path.to_string()))?;
            node.set_prop(&pin.0, *phandle_val)?;

            // Write reference path to local fixups node
            node = fdt.root_mut().subnode_mut(LOCAL_FIXUPS_NODE)?;
            for nname in path.iter() {
                node = node.subnode_mut(nname)?;
            }
            node.set_prop(&pin.0, 0u32)?;
        }

        Ok(fdt)
    }

    #[test]
    fn fdt_collect_filter_roots() {
        let fdt = make_fdt_with_local_refs(&[]).unwrap();
        let (symbols, paths) = prepare_filtered_symbols::<&str>([], &fdt).unwrap();
        assert!(symbols.is_empty());
        assert!(paths.is_empty());

        let (symbols, paths) = prepare_filtered_symbols(["node1"], &fdt).unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(paths.len(), 1);
        assert!(symbols.contains("node1"));
        assert!(paths.contains(&"/node1".parse().unwrap()));

        let (symbols, paths) =
            prepare_filtered_symbols(["node1", "node1-1", "node1"], &fdt).unwrap();
        assert_eq!(symbols.len(), 2);
        assert!(symbols.contains("node1") && symbols.contains("node1-1"));
        assert!(
            paths.contains(&"/node1".parse().unwrap())
                && paths.contains(&"/node1/node1-1".parse().unwrap())
        );

        prepare_filtered_symbols(["node1", "node1-1", "node1", "nosuchnode"], &fdt)
            .expect_err("no symbol");
        prepare_filtered_symbols(["node1-1-1"], &fdt).expect_err("no symbol");
        prepare_filtered_symbols(["node1"], &Fdt::new(&[])).expect_err("no symbols node");
    }

    #[test]
    fn fdt_collect_filtered_paths() {
        // /node1/node1-2/node1-2-1:prop:0 => /node2/node2-3/node2-3-1 (phandle=11)
        // /node1:prop:0 => /node3 (phandle=12)
        let fdt = make_fdt_with_local_refs(&[
            ("/node1/node1-2/node1-2-1:prop:0", 11),
            ("/node1:prop:0", 12),
        ])
        .unwrap();
        let (_, paths) = prepare_filtered_symbols(["node1"], &fdt).unwrap();
        let filtered = collect_all_filtered_paths(paths, &fdt).unwrap();

        // This is referenced by the symbol that was given.
        assert!(filtered.contains(&"/node1".parse().unwrap()));
        // This is referenced by the phandle value stored in the property.
        assert!(filtered.contains(&"/node3".parse().unwrap()));
        // References that appeart in the subtree of the filtered node are not included.
        assert!(!filtered.contains(&"/node2/node2-3/node2-3-1".parse().unwrap()));
    }

    #[test]
    fn fdt_collect_filtered_paths_circular() {
        // /node1:prop:0 => /node2/node2-3/node2-3-1 (phandle=11)
        // /node2/node2-3:prop:0 => /node1/node1-1 (phandle=2)
        let fdt = make_fdt_with_local_refs(&[("/node1:prop:0", 11), ("/node2/node2-3:prop:0", 2)])
            .unwrap();
        let (_, paths) = prepare_filtered_symbols(["node1-1"], &fdt).unwrap();
        let filtered = collect_all_filtered_paths(paths, &fdt).unwrap();

        // This is referenced by the symbol that was given.
        assert!(filtered.contains(&"/node1/node1-1".parse().unwrap()));
        // This is referenced by a parent node of the given symbol.
        assert!(filtered.contains(&"/node2/node2-3/node2-3-1".parse().unwrap()));
        // Above two paths cover all references
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn fdt_collect_filtered_paths_dangling() {
        // /node1:prop:0 => /node2/node2-3/node2-3-1 (phandle=11)
        // /node2/node2-3:prop:0 => dangling phandle=200
        let fdt =
            make_fdt_with_local_refs(&[("/node1:prop:0", 11), ("/node2/node2-3:prop:0", 200)])
                .unwrap();
        let (_, paths) = prepare_filtered_symbols(["node1"], &fdt).unwrap();
        collect_all_filtered_paths(paths, &fdt).expect_err("dangling phandle");
    }

    #[test]
    fn fdt_collect_filtered_paths_minimal() {
        // /node1:prop:0 => /node3/node3-1 (phandle=13)
        // /node1/node1-1:prop:0 => /node1/node1-1/node1-1-2 (phandle=4)
        // /node1/node1-1/node1-1-2:prop:0 => /node1 (phandle=1)
        // /node3/node3-1:prop:0 => /node3 (phandle=12)
        let fdt = make_fdt_with_local_refs(&[
            ("/node1:prop:0", 13),
            ("/node1/node1-1:prop:0", 4),
            ("/node1/node1-1/node1-1-2:prop:0", 1),
            ("/node3/node3-1:prop:0", 12),
        ])
        .unwrap();
        let (_, paths) = prepare_filtered_symbols(["node1"], &fdt).unwrap();
        let filtered = collect_all_filtered_paths(paths, &fdt).unwrap();

        assert!(filtered.contains(&"/node1".parse().unwrap()));
        assert!(filtered.contains(&"/node3".parse().unwrap()));
        // Above two paths cover all references
        assert_eq!(filtered.len(), 2);
    }

    fn count_nodes(root: &FdtNode) -> usize {
        let mut count = 1;
        for s in root.iter_subnodes() {
            count += count_nodes(s);
        }
        count
    }

    #[test]
    fn fdt_do_filter_simple() {
        let l1 = "/node1";
        let l2 = "/node2";
        let l3 = "/node3";
        let fdt = &mut make_fdt_with_local_refs(&[]).unwrap();

        do_overlay_filter([].into(), fdt);
        assert!(fdt.get_node(l1).is_some());
        assert!(fdt.get_node(l2).is_some());
        assert!(fdt.get_node(l3).is_some());

        do_overlay_filter([l1.try_into().unwrap(), l2.try_into().unwrap()].into(), fdt);
        assert!(fdt.get_node(l1).is_some());
        assert!(fdt.get_node(l2).is_some());
        assert!(fdt.get_node(l3).is_none());
    }

    #[test]
    fn fdt_do_filter_subnodes() {
        let l1: Path = "/node1/node1-1".parse().unwrap();
        let fdt = &mut make_fdt_with_local_refs(&[]).unwrap();

        do_overlay_filter([l1.clone()].into(), fdt);
        assert!(fdt.get_node(l1).is_some());
        assert_eq!(count_nodes(&fdt.root), 3);
    }

    #[test]
    fn fdt_do_filter_deep() {
        let l1: Path = "/node1/node1-1/node1-1-1".parse().unwrap();
        let l2: Path = "/node2/node2-2".parse().unwrap();
        let l3: Path = "/node2/node2-3/node2-3-1".parse().unwrap();
        let fdt = &mut make_fdt_with_local_refs(&[]).unwrap();

        do_overlay_filter([l1.clone(), l2.clone(), l3.clone()].into(), fdt);
        assert!(fdt.get_node(l1).is_some());
        assert!(fdt.get_node(l2).is_some());
        assert!(fdt.get_node(l3).is_some());
        assert_eq!(count_nodes(&fdt.root), 8);
    }

    #[test]
    fn fdt_offset_local_references() {
        let file = include_bytes!("../test-files/local_refs.dtb").as_slice();
        let mut fdt = load_fdt(file).unwrap();

        let node = fdt.get_node("/fragment@0/__overlay__/node1").unwrap();
        assert_eq!(node.get_prop::<u32>("p2").unwrap(), 0x01);
        assert_eq!(node.get_prop::<u32>("p3").unwrap(), 0xaa);
        let node = fdt.get_node("/fragment@0/__overlay__/node1/node2").unwrap();
        assert_eq!(node.get_prop::<u32>("p1").unwrap(), 0xaa);
        assert_eq!(node.get_prop::<u32>("p2").unwrap(), 0x02);
        assert_eq!(node.get_prop::<u32>("p3").unwrap(), 0x03);
        let node = fdt.get_node("/fragment@0/__overlay__/node1/node3").unwrap();
        assert_eq!(node.get_prop::<u32>("p1").unwrap(), 0x01);

        update_local_refs(&mut fdt, 5).unwrap();
        let node = fdt.get_node("/fragment@0/__overlay__/node1").unwrap();
        assert_eq!(node.get_prop::<u32>("p2").unwrap(), 0x06);
        assert_eq!(node.get_prop::<u32>("p3").unwrap(), 0xaa);
        let node = fdt.get_node("/fragment@0/__overlay__/node1/node2").unwrap();
        assert_eq!(node.get_prop::<u32>("p1").unwrap(), 0xaa);
        assert_eq!(node.get_prop::<u32>("p2").unwrap(), 0x07);
        assert_eq!(node.get_prop::<u32>("p3").unwrap(), 0x08);
        let node = fdt.get_node("/fragment@0/__overlay__/node1/node3").unwrap();
        assert_eq!(node.get_prop::<u32>("p1").unwrap(), 0x06);
    }

    #[test]
    fn fdt_collect_symbols() {
        let base =
            load_fdt(include_bytes!("../test-files/external_refs_base.dtb").as_slice()).unwrap();
        let mut overlay =
            load_fdt(include_bytes!("../test-files/external_refs_overlay.dtb").as_slice()).unwrap();
        let paths = [
            "/fragment@0/__overlay__/node1:p2:0",
            "/fragment@0/__overlay__/node1/node2:p3:4",
            "/fragment@0/__overlay__/node1/node3:p1:0",
        ];
        for p in paths.iter() {
            let (path, pin) = parse_path_with_prop(p).unwrap();
            let node = overlay.get_node(path).unwrap();
            let ref_val = node.phandle_at_offset(&pin.0, pin.1 as usize).unwrap();
            assert_eq!(ref_val, 0xffffffff);
        }

        apply_external_fixups(&base, &mut overlay).unwrap();
        for (p, exp_val) in paths.iter().zip([1u32, 2u32, 2u32].into_iter()) {
            let (path, pin) = parse_path_with_prop(p).unwrap();
            let node = overlay.get_node(path).unwrap();
            let ref_val = node.phandle_at_offset(&pin.0, pin.1 as usize).unwrap();
            assert_eq!(ref_val, exp_val);
        }
    }

    #[test]
    fn fdt_apply_overlay_complete() {
        let mut base = load_fdt(include_bytes!("../test-files/base.dtb").as_slice()).unwrap();
        assert_eq!(count_nodes(&base.root), 7);

        let overlay = load_fdt(include_bytes!("../test-files/overlay.dtb").as_slice()).unwrap();
        apply_overlay(&mut base, overlay, ["mydev"]).unwrap();
        assert!(base.get_node("/mydev@8000000").is_some());
        assert!(base.get_node("/mydev@8000000/devnode1").is_none());
        assert!(base.get_node("/mydev@8001000").is_none());
        assert_eq!(count_nodes(&base.root), 8);

        let overlay = load_fdt(include_bytes!("../test-files/overlay.dtb").as_slice()).unwrap();
        apply_overlay(&mut base, overlay, ["mydev"]).unwrap();
        assert!(base.get_node("/mydev@8000000").is_some());
        assert!(base.get_node("/mydev@8001000").is_none());
        assert_eq!(count_nodes(&base.root), 8);

        let overlay = load_fdt(include_bytes!("../test-files/overlay.dtb").as_slice()).unwrap();
        apply_overlay(&mut base, overlay, ["mydev2"]).unwrap();
        assert!(base.get_node("/mydev@8000000").is_some());
        assert!(base.get_node("/mydev@8001000").is_some());
        assert!(base.get_node("/mydev@8000000/devnode1").is_none());
        assert!(base.get_node("/mydev@8001000/devnode1").is_none());
        assert_eq!(count_nodes(&base.root), 9);
    }

    #[test]
    fn fdt_overlay_filter_with_dependencies() {
        let mut base = Fdt::new(&[]);
        let overlay =
            load_fdt(include_bytes!("../test-files/overlay_deps.dtb").as_slice()).unwrap();
        apply_overlay(&mut base, overlay, ["dev2"]).unwrap();
        assert_eq!(count_nodes(&base.root), 6);

        let n = base.get_node("/n0-1").unwrap();
        assert_eq!(n.get_prop::<u32>("prop1"), Some(1));

        assert!(base.get_node("/no-1/n2").is_none());
        let n = base.get_node("/n0-1/n1").unwrap();
        assert_eq!(n.get_prop::<u32>("prop1"), Some(2));

        let n = base.get_node("/n0-2").unwrap();
        assert_eq!(n.get_prop::<u32>("prop1"), Some(4));

        assert!(base.get_node("/n0-2/n2").is_none());
        let n = base.get_node("/n0-2/n1").unwrap();
        assert_eq!(n.get_prop::<u32>("prop1"), Some(5));
    }

    #[test]
    fn fdt_overlay_skips_children() {
        let mut base =
            load_fdt(include_bytes!("../test-files/external_refs_base.dtb").as_slice()).unwrap();
        let overlay =
            load_fdt(include_bytes!("../test-files/external_refs_overlay.dtb").as_slice()).unwrap();
        apply_overlay(&mut base, overlay, ["n1"]).unwrap();
        assert_eq!(count_nodes(&base.root), 6);
        assert!(base.get_node("/node1").is_some());
        assert!(base.get_node("/node1/node2").is_none());
        assert!(base.get_node("/node1/node3").is_none());
    }
}
