// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use base::read_overlapped_blocking;
use cros_async::Executor;

use crate::Error;
use crate::Result;
use crate::SingleFileDisk;

impl SingleFileDisk {
    pub fn new(disk: File, ex: &Executor) -> Result<Self> {
        ex.async_overlapped_from(disk)
            .map_err(Error::CreateSingleFileDisk)
            .map(|inner| SingleFileDisk { inner })
    }
}

/// On Windows, if the file is sparse, we set the option. On Linux this is not needed.
pub fn apply_raw_disk_file_options(raw_image: &File, is_sparse_file: bool) -> Result<()> {
    if is_sparse_file {
        base::set_sparse_file(raw_image).map_err(Error::SetSparseFailure)?;
    }
    Ok(())
}

pub fn read_from_disk(
    mut file: &File,
    offset: u64,
    buf: &mut [u8],
    overlapped_mode: bool,
) -> Result<()> {
    file.seek(SeekFrom::Start(offset))
        .map_err(Error::SeekingFile)?;
    if overlapped_mode {
        read_overlapped_blocking(file, offset, buf)
            .map(|_| ())
            .map_err(Error::ReadingHeader)
    } else {
        file.read_exact(buf).map_err(Error::ReadingHeader)
    }
}
