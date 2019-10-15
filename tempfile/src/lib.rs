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

use libc::mkdtemp;
use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::ptr;

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
        // mkdtemp() requires the template to end in 6 X chars, which will be replaced
        // with random characters to make the path unique.
        let path_template = env::temp_dir().join(format!("{}.XXXXXX", self.prefix));
        let template = match path_template.to_str() {
            Some(s) => CString::new(s)?,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Path to string conversion failed",
                ))
            }
        };
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

#[cfg(test)]
mod tests {
    use crate::TempDir;

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
}
