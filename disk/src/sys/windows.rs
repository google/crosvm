// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;

use cros_async::sys::windows::HandleSource;
use cros_async::IoSourceExt;

use crate::Error;
use crate::Result;
use crate::SingleFileDisk;

impl SingleFileDisk {
    pub fn new_from_files(disk_files: Vec<File>) -> Result<Self> {
        HandleSource::new(disk_files.into_boxed_slice())
            .map_err(|e| Error::CreateSingleFileDisk(cros_async::AsyncError::HandleSource(e)))
            .map(|inner| SingleFileDisk {
                inner: Box::new(inner) as Box<dyn IoSourceExt<File>>,
            })
    }
}

/// On Windows, if the file is sparse, we set the option. On Linux this is not needed.
pub fn apply_raw_disk_file_options(raw_image: &File, is_sparse_file: bool) -> Result<()> {
    if is_sparse_file {
        base::set_sparse_file(raw_image).map_err(Error::SetSparseFailure)?;
    }
    Ok(())
}
