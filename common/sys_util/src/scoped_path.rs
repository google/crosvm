// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env::{current_exe, temp_dir};
use std::fs::{create_dir_all, remove_dir_all};
use std::io::Result;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::thread::panicking;

use crate::{getpid, gettid};

/// Returns a stable path based on the label, pid, and tid. If the label isn't provided the
/// current_exe is used instead.
pub fn get_temp_path(label: Option<&str>) -> PathBuf {
    if let Some(label) = label {
        temp_dir().join(format!("{}-{}-{}", label, getpid(), gettid()))
    } else {
        get_temp_path(Some(
            current_exe()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
        ))
    }
}

/// Automatically deletes the path it contains when it goes out of scope unless it is a test and
/// drop is called after a panic!.
///
/// This is particularly useful for creating temporary directories for use with tests.
pub struct ScopedPath<P: AsRef<Path>>(P);

impl<P: AsRef<Path>> ScopedPath<P> {
    pub fn create(p: P) -> Result<Self> {
        create_dir_all(p.as_ref())?;
        Ok(ScopedPath(p))
    }
}

impl<P: AsRef<Path>> AsRef<Path> for ScopedPath<P> {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

impl<P: AsRef<Path>> Deref for ScopedPath<P> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<P: AsRef<Path>> Drop for ScopedPath<P> {
    fn drop(&mut self) {
        // Leave the files on a failed test run for debugging.
        if panicking() && cfg!(test) {
            eprintln!("NOTE: Not removing {}", self.display());
            return;
        }
        if let Err(e) = remove_dir_all(&**self) {
            eprintln!("Failed to remove {}: {}", self.display(), e);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::panic::catch_unwind;

    #[test]
    fn gettemppath() {
        assert_ne!("", get_temp_path(None).to_string_lossy());
        assert!(get_temp_path(None).starts_with(temp_dir()));
        assert_eq!(
            get_temp_path(None),
            get_temp_path(Some(
                current_exe()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            ))
        );
        assert_ne!(
            get_temp_path(Some("label")),
            get_temp_path(Some(
                current_exe()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            ))
        );
    }

    #[test]
    fn scopedpath_exists() {
        let tmp_path = get_temp_path(None);
        {
            let scoped_path = ScopedPath::create(&tmp_path).unwrap();
            assert!(scoped_path.exists());
        }
        assert!(!tmp_path.exists());
    }

    #[test]
    fn scopedpath_notexists() {
        let tmp_path = get_temp_path(None);
        {
            let _scoped_path = ScopedPath(&tmp_path);
        }
        assert!(!tmp_path.exists());
    }

    #[test]
    fn scopedpath_panic() {
        let tmp_path = get_temp_path(None);
        assert!(catch_unwind(|| {
            {
                let scoped_path = ScopedPath::create(&tmp_path).unwrap();
                assert!(scoped_path.exists());
                panic!()
            }
        })
        .is_err());
        assert!(tmp_path.exists());
        remove_dir_all(&tmp_path).unwrap();
    }
}
