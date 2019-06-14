// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Simplified tempfile which doesn't depend on the `rand` crate, instead using
//! /dev/urandom as a source of entropy

use libc::mkdtemp;
use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

pub struct Builder {
    prefix: String,
}

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

    /// Tries to make a tempdir inside of `env::temp_dir()` with a specified
    /// prefix. The directory and it's content is destroyed when TempDir is
    /// dropped.
    /// If the directory can not be created, `Err` is returned.
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

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Accesses the tempdir's [`Path`].
    ///
    /// [`Path`]: http://doc.rust-lang.org/std/path/struct.Path.html
    pub fn path(&self) -> &Path {
        self.path.as_ref()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
