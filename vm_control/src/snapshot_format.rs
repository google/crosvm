// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::Debug;
use std::fmt::Formatter;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use crypto::CryptKey;

// Use 4kB encrypted chunks by default (if encryption is used).
const DEFAULT_ENCRYPTED_CHUNK_SIZE_BYTES: usize = 1024 * 4;

/// Writer of serialized VM snapshots.
///
/// Each fragment is an opaque byte blob. Namespaces can be used to avoid fragment naming
/// collisions between devices.
///
/// In the current implementation, fragments are files and namespaces are directories, but the API
/// is kept abstract so that we can potentially support something like a single file archive
/// output.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotWriter {
    dir: PathBuf,
    /// If encryption is used, the plaintext key will be stored here.
    key: Option<CryptKey>,
}

impl Debug for SnapshotWriter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotWriter")
            .field("dir", &format!("{:?}", self.dir))
            .field("key", if self.key.is_some() { &"Some" } else { &"None" })
            .finish()
    }
}

impl SnapshotWriter {
    /// Creates a new `SnapshotWriter` that will writes its data to a dir at `root`. The path must
    /// not exist yet. If encryption is desired, set encrypt (Note: only supported downstream on
    /// Windows).
    // TODO(b/268094487): If the snapshot fails, we leave incomplete snapshot files at the
    // requested path. Consider building up the snapshot dir somewhere else and moving it into
    // place at the end.
    pub fn new(root: PathBuf, encrypt: bool) -> Result<Self> {
        std::fs::create_dir(&root)
            .with_context(|| format!("failed to create snapshot root dir: {}", root.display()))?;

        if encrypt {
            let key = crypto::generate_random_key();
            // Creating an empty CryptWriter will still write header information
            // to the file, and that header information is what we need. This
            // ensures we use a single key for *all* snapshot files.
            let mut writer = crypto::CryptWriter::new_from_key(
                File::create(root.join("enc_metadata")).context("failed to create enc_metadata")?,
                1024,
                &key,
            )
            .context("failed to create enc_metadata writer")?;
            writer.flush().context("flush of enc_metadata failed")?;
            return Ok(Self {
                dir: root,
                key: Some(key),
            });
        }

        Ok(Self {
            dir: root,
            key: None,
        })
    }

    /// Creates a snapshot fragment and get access to the `Write` impl representing it.
    pub fn raw_fragment(&self, name: &str) -> Result<Box<dyn Write>> {
        self.raw_fragment_with_chunk_size(name, DEFAULT_ENCRYPTED_CHUNK_SIZE_BYTES)
    }

    /// When encryption is used, allows direct control of the encrypted chunk size.
    pub fn raw_fragment_with_chunk_size(
        &self,
        name: &str,
        chunk_size_bytes: usize,
    ) -> Result<Box<dyn Write>> {
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

        if let Some(key) = self.key.as_ref() {
            return Ok(Box::new(crypto::CryptWriter::new_from_key(
                file,
                chunk_size_bytes,
                key,
            )?));
        }

        Ok(Box::new(file))
    }

    /// Creates a snapshot fragment from a serialized representation of `v`.
    pub fn write_fragment<T: serde::Serialize>(&self, name: &str, v: &T) -> Result<()> {
        let mut w = std::io::BufWriter::new(self.raw_fragment(name)?);
        serde_json::to_writer(&mut w, v)?;
        w.flush()?;
        Ok(())
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
        Ok(Self {
            dir,
            key: self.key.clone(),
        })
    }
}

/// Reads snapshots created by `SnapshotWriter`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotReader {
    dir: PathBuf,
    /// If encryption is used, the plaintext key will be stored here.
    key: Option<CryptKey>,
}

impl Debug for SnapshotReader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotReader")
            .field("dir", &format!("{:?}", self.dir))
            .field("key", if self.key.is_some() { &"Some" } else { &"None" })
            .finish()
    }
}

impl SnapshotReader {
    /// Reads a snapshot at `root`. Set require_encrypted to require an encrypted snapshot.
    pub fn new(root: &Path, require_encrypted: bool) -> Result<Self> {
        let enc_metadata_path = root.join("enc_metadata");
        if Path::exists(&enc_metadata_path) {
            let key = Some(
                crypto::CryptReader::extract_key(
                    File::open(&enc_metadata_path).context("failed to open encryption metadata")?,
                )
                .context("failed to load snapshot key")?,
            );
            return Ok(Self {
                dir: root.to_path_buf(),
                key,
            });
        } else if require_encrypted {
            return Err(anyhow::anyhow!("snapshot was not encrypted"));
        }

        Ok(Self {
            dir: root.to_path_buf(),
            key: None,
        })
    }

    /// Gets access to a `Read` impl that represents a fragment.
    pub fn raw_fragment(&self, name: &str) -> Result<Box<dyn Read>> {
        let path = self.dir.join(name);
        let file = File::open(&path).with_context(|| {
            format!(
                "failed to open snapshot fragment {name:?} at {}",
                path.display()
            )
        })?;
        if let Some(key) = self.key.as_ref() {
            return Ok(Box::new(crypto::CryptReader::from_file_and_key(file, key)?));
        }

        Ok(Box::new(file))
    }

    /// Reads a fragment.
    pub fn read_fragment<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<T> {
        Ok(serde_json::from_reader(std::io::BufReader::new(
            self.raw_fragment(name)?,
        ))?)
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
        Ok(Self {
            dir,
            key: self.key.clone(),
        })
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
