// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Simplified tempdir which doesn't depend on the `rand` crate, instead using
//! /dev/urandom as a source of entropy

extern crate rand_ish;

use std::env;
use std::fs;
use std::io::{self, Error, ErrorKind};
use std::path::{Path, PathBuf};
use rand_ish::urandom_str;

pub struct TempDir {
    path: PathBuf,
}

const NUM_RETRIES: u32 = 4;

impl TempDir {
    /// Tries to make a tempdir inside of `env::temp_dir()` with a specified
    /// prefix. The directory and it's content is destroyed when TempDir is
    /// dropped.
    /// If the directory can not be created, `Err` is returned.
    pub fn new(prefix: &str) -> io::Result<TempDir> {
        for _ in 0..NUM_RETRIES {
            let suffix = urandom_str(12)?;
            let path = env::temp_dir().join(format!("{}.{}", prefix, suffix));

            match fs::create_dir(&path) {
                Ok(_) => return Ok(TempDir { path }),
                Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }

        Err(Error::new(ErrorKind::AlreadyExists, "too many tempdirs exist"))
    }

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
