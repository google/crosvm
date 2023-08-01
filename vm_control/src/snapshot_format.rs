// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;

/// Writer of serialized VM snapshots.
///
/// Each fragment is an opaque byte blob. Namespaces can be used to avoid fragment naming
/// collisions between devices.
///
/// In the current implementation, fragments are files and namespaces are directories, but the API
/// is kept abstract so that we can potentially support something like a single file archive
/// output.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SnapshotWriter {
    dir: PathBuf,
}

impl SnapshotWriter {
    /// Creates a new `SnapshotWriter` that will writes its data to a dir at `root`. The path must
    /// not exist yet.
    // TODO(b/268094487): If the snapshot fails, we leave incomplete snapshot files at the
    // requested path. Consider building up the snapshot dir somewhere else and moving it into
    // place at the end.
    pub fn new(root: PathBuf) -> Result<Self> {
        std::fs::create_dir(&root)
            .with_context(|| format!("failed to create snapshot root dir: {}", root.display()))?;
        Ok(Self { dir: root })
    }

    /// Creates a snapshot fragment and get access to the `File` representing it.
    pub fn raw_fragment(&self, name: &str) -> Result<File> {
        let path = self.dir.join(name);
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "failed to create snapshot fragment {name:?} at {}",
                    path.display()
                )
            })?;
        Ok(file)
    }

    /// Creates a snapshot fragment from a serialized representation of `v`.
    pub fn write_fragment<T: serde::Serialize>(&self, name: &str, v: &T) -> Result<()> {
        Ok(serde_json::to_writer(self.raw_fragment(name)?, v)?)
    }

    /// Creates new namespace and returns a `SnapshotWriter` that writes to it. Namespaces can be
    /// nested.
    pub fn add_namespace(&self, name: &str) -> Result<Self> {
        let dir = self.dir.join(name);
        std::fs::create_dir(&dir).with_context(|| {
            format!(
                "failed to create nested snapshot writer {name:?} at {}",
                dir.display()
            )
        })?;
        Ok(Self { dir })
    }
}

/// Reads snapshots created by `SnapshotWriter`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SnapshotReader {
    dir: PathBuf,
}

impl SnapshotReader {
    /// Reads a snapshot at `root`.
    pub fn new(root: PathBuf) -> Result<Self> {
        Ok(Self { dir: root })
    }

    /// Gets access to the `File` representing a fragment.
    pub fn raw_fragment(&self, name: &str) -> Result<File> {
        let path = self.dir.join(name);
        let file = File::open(&path).with_context(|| {
            format!(
                "failed to open snapshot fragment {name:?} at {}",
                path.display()
            )
        })?;
        Ok(file)
    }

    /// Reads a fragment.
    pub fn read_fragment<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<T> {
        Ok(serde_json::from_reader(self.raw_fragment(name)?)?)
    }

    /// Reads the names of all fragments in this namespace.
    pub fn list_fragments(&self) -> Result<Vec<String>> {
        let mut result = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            if entry.path().is_file() {
                if let Some(file_name) = entry.path().file_name() {
                    result.push(file_name.to_string_lossy().into_owned());
                }
            }
        }
        Ok(result)
    }

    /// Open a namespace.
    pub fn namespace(&self, name: &str) -> Result<Self> {
        let dir = self.dir.join(name);
        Ok(Self { dir })
    }

    /// Reads the names of all child namespaces
    pub fn list_namespaces(&self) -> Result<Vec<String>> {
        let mut result = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            if entry.path().is_dir() {
                if let Some(file_name) = entry.path().file_name() {
                    result.push(file_name.to_string_lossy().into_owned());
                }
            }
        }
        Ok(result)
    }
}
