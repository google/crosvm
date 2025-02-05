// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Utilities for working with directories for snapshots.

use std::collections::BTreeMap as Map;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use serde::Deserialize;
use serde::Serialize;

fn get_files_recursively(directory: &Path, paths: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    if directory.is_dir() {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                get_files_recursively(&entry_path, paths)?;
            } else {
                paths.push(entry_path.to_path_buf());
            }
        }
    }
    Ok(())
}

fn get_files_under(directory: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    get_files_recursively(directory, &mut paths)?;
    Ok(paths)
}

// TODO: use an actual archive/zip when a common crate is available in
// both Android and Chrome.
#[derive(Serialize, Deserialize)]
pub struct DirectorySnapshot {
    files: Map<PathBuf, Vec<u8>>,
}

pub fn pack_directory_to_snapshot(directory: &Path) -> anyhow::Result<DirectorySnapshot> {
    let directory_files = get_files_under(directory).with_context(|| {
        format!(
            "failed to list snapshot files under {}",
            directory.display()
        )
    })?;

    let mut snapshot = DirectorySnapshot { files: Map::new() };

    for path in directory_files.into_iter() {
        let contents: Vec<u8> = std::fs::read(&path)
            .with_context(|| format!("failed to read snapshot file {}", path.display()))?;

        let relative_path = path
            .strip_prefix(directory)
            .with_context(|| {
                format!(
                    "failed to strip {} from {}",
                    directory.display(),
                    path.display()
                )
            })?
            .to_path_buf();

        snapshot.files.insert(relative_path, contents);
    }

    Ok(snapshot)
}

pub fn unpack_snapshot_to_directory(
    directory: &Path,
    snapshot: DirectorySnapshot,
) -> anyhow::Result<()> {
    for (path, contents) in snapshot.files.into_iter() {
        let path = directory.join(path);
        let path_directory = path
            .parent()
            .with_context(|| format!("failed to get parent directory for {}", path.display()))?;
        std::fs::create_dir_all(path_directory)
            .with_context(|| format!("failed to create directories for {}", path.display()))?;
        std::fs::write(&path, contents)
            .with_context(|| format!("failed to unpack snapshot to {}", path.display()))?;
    }

    Ok(())
}
