// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Simplified tempfile which doesn't depend on the `rand` crate.
//!
//! # Example
//!
//! ```
//! use std::io::Result;
//! use std::path::{Path, PathBuf};
//! use tempfile::TempDir;
//!
//! fn main() -> Result<()> {
//!     let t = TempDir::new()?;
//!     assert!(t.path().exists());
//!
//!     Ok(())
//! }
//! ```

use libc::{mkdtemp, mkstemp};
use std::env;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Error, ErrorKind, Result};
use std::mem::ManuallyDrop;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::ptr;

fn temp_path_template(prefix: &str) -> Result<CString> {
    // mkdtemp()/mkstemp() require the template to end in 6 X chars, which will be replaced
    // with random characters to make the path unique.
    let path_template = env::temp_dir().join(format!("{}.XXXXXX", prefix));
    match path_template.to_str() {
        Some(s) => Ok(CString::new(s)?),
        None => Err(Error::new(
            ErrorKind::InvalidData,
            "Path to string conversion failed",
        )),
    }
}

pub struct Builder {
    prefix: String,
}

// Note: we implement a builder because the protoc-rust crate uses this API from
// crates.io's tempfile. Our code mostly uses TempDir::new directly.
impl Builder {
    pub fn new() -> Self {
        Builder {
            prefix: ".tmp".to_owned(),
        }
    }

    /// Set a custom filename prefix.
    ///
    /// Default: `.tmp`
    pub fn prefix(&mut self, prefix: &str) -> &mut Self {
        self.prefix = prefix.to_owned();
        self
    }

    /// Creates a new temporary directory under libc's preferred system
    /// temporary directory. The new directory will be removed when the returned
    /// handle of type `TempDir` is dropped.
    pub fn tempdir(&self) -> Result<TempDir> {
        let template = temp_path_template(&self.prefix)?;
        let ptr = template.into_raw();
        // Safe because ownership of the buffer is handed off to mkdtemp() only
        // until it returns, and ownership is reclaimed by calling CString::from_raw()
        // on the same pointer returned by into_raw().
        let path = unsafe {
            let ret = mkdtemp(ptr);
            let path = CString::from_raw(ptr);
            if ret.is_null() {
                return Err(Error::last_os_error());
            }
            path
        };
        Ok(TempDir {
            path: PathBuf::from(path.to_str().map_err(|_| {
                Error::new(ErrorKind::InvalidData, "Path to string conversion failed")
            })?),
        })
    }

    /// Creates a new temporary file under libc's preferred system
    /// temporary directory. The new file will be removed when the returned
    /// handle of type `NamedTempFile` is dropped.
    pub fn tempfile(&self) -> Result<NamedTempFile> {
        let template = temp_path_template(&self.prefix)?;
        let ptr = template.into_raw();
        // Safe because ownership of the buffer is handed off to mkstemp() only
        // until it returns, and ownership is reclaimed by calling CString::from_raw()
        // on the same pointer returned by into_raw().
        let (file, path) = unsafe {
            let ret = mkstemp(ptr);
            let path = CString::from_raw(ptr);
            if ret < 0 {
                return Err(Error::last_os_error());
            }
            (File::from_raw_fd(ret), path)
        };

        Ok(NamedTempFile {
            path: TempPath {
                path: PathBuf::from(path.to_str().map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "Path to string conversion failed")
                })?),
            },
            file,
        })
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

/// Temporary directory. The directory will be removed when this object is
/// dropped.
pub struct TempDir {
    path: PathBuf,
    // When adding new fields to TempDir: note that anything with a Drop impl
    // will need to be dropped explicitly via ptr::read inside TempDir::remove
    // or else it gets leaked (memory safe but not ideal).
}

impl TempDir {
    pub fn new() -> Result<Self> {
        Builder::new().tempdir()
    }

    /// Accesses the tempdir's [`Path`].
    ///
    /// [`Path`]: http://doc.rust-lang.org/std/path/struct.Path.html
    pub fn path(&self) -> &Path {
        self.path.as_ref()
    }

    /// Removes the temporary directory.
    ///
    /// Calling this is optional as dropping a TempDir object will also remove
    /// the directory. Calling remove explicitly allows for any resulting error
    /// to be handled.
    pub fn remove(self) -> Result<()> {
        // Place self inside ManuallyDrop so its Drop impl doesn't run, but nor
        // does the path inside get dropped. Then use ptr::read to take out the
        // PathBuf so that it *does* get dropped correctly at the bottom of this
        // function.
        let dont_drop = ManuallyDrop::new(self);
        let path: PathBuf = unsafe { ptr::read(&dont_drop.path) };

        fs::remove_dir_all(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Temporary file with a known name.  The file will be removed when this object is dropped.
pub struct NamedTempFile {
    path: TempPath,
    file: File,
}

impl NamedTempFile {
    pub fn new() -> Result<Self> {
        Builder::new().tempfile()
    }

    /// Accesses the temporary file's `Path`.
    pub fn path(&self) -> &Path {
        self.path.path.as_ref()
    }

    /// Accesses the temporary file's `File` object.
    pub fn as_file(&self) -> &File {
        &self.file
    }

    /// Accesses the temporary file's `File` object mutably.
    pub fn as_file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Convert this `TempFile` into an open `File` and unlink it from the filesystem.
    pub fn into_file(self) -> File {
        self.file
    }
}

// Container for NamedTempFile's path so that it can be dropped separately from the File.
struct TempPath {
    path: PathBuf,
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Create a new anonymous temporary file under the preferred system
/// temporary directory. The new file will be removed when the returned
/// `File` is dropped.
pub fn tempfile() -> Result<File> {
    Ok(NamedTempFile::new()?.into_file())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};

    use crate::{tempfile, NamedTempFile, TempDir};

    #[test]
    fn create_dir() {
        let t = TempDir::new().unwrap();
        let path = t.path();
        assert!(path.exists());
        assert!(path.is_dir());
    }

    #[test]
    fn remove_dir() {
        let t = TempDir::new().unwrap();
        let path = t.path().to_owned();
        assert!(t.remove().is_ok());
        assert!(!path.exists());
    }

    #[test]
    fn create_file() {
        let mut f = tempfile().expect("tempfile() failed");
        f.write_all(&[0, 1, 2, 3]).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut data = vec![0u8; 4];
        f.read_exact(&mut data).unwrap();
        assert_eq!(data, [0, 1, 2, 3]);
    }

    #[test]
    fn create_named_file() {
        let named_temp = NamedTempFile::new().unwrap();
        let path = named_temp.path().to_owned();
        assert!(path.exists());

        // as_file() should not delete the file.
        let _f = named_temp.as_file();
        assert!(path.exists());

        // Dropping the NamedTempFile should delete the file.
        drop(named_temp);
        assert!(!path.exists());
    }
}
