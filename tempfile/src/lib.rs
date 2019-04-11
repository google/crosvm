// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Simplified tempfile which doesn't depend on the `rand` crate, instead using
//! /dev/urandom as a source of entropy

use rand_ish::urandom_str;
use std::env;
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
        for _ in 0..NUM_RETRIES {
            let suffix = urandom_str(12)?;
            let path = env::temp_dir().join(format!("{}.{}", self.prefix, suffix));

            match fs::create_dir(&path) {
                Ok(_) => return Ok(TempDir { path }),
                Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }

        Err(Error::new(
            ErrorKind::AlreadyExists,
            "too many tempdirs exist",
        ))
    }
}

pub struct TempDir {
    path: PathBuf,
}

const NUM_RETRIES: u32 = 4;

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
