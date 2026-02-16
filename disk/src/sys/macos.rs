// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use cros_async::Executor;

use crate::DiskFileParams;
use crate::Error;
use crate::Result;
use crate::SingleFileDisk;

pub fn open_raw_disk_image(params: &DiskFileParams) -> Result<File> {
    let mut options = File::options();
    options.read(true).write(!params.is_read_only);

    let raw_image = base::open_file_or_duplicate(&params.path, &options)
        .map_err(|e| Error::OpenFile(params.path.display().to_string(), e))?;

    if params.lock {
        let lock_op = if params.is_read_only {
            base::FlockOperation::LockShared
        } else {
            base::FlockOperation::LockExclusive
        };
        base::flock(&raw_image, lock_op, true).map_err(Error::LockFileFailure)?;
    }

    // O_DIRECT is not supported on macOS; skip setting it.
    // macOS uses F_NOCACHE via fcntl for similar functionality, but it's
    // not critical for correctness, so we omit it here.

    Ok(raw_image)
}

pub fn apply_raw_disk_file_options(_raw_image: &File, _is_sparse_file: bool) -> Result<()> {
    // No-op on macOS.
    Ok(())
}

pub fn read_from_disk(
    mut file: &File,
    offset: u64,
    buf: &mut [u8],
    _overlapped_mode: bool,
) -> Result<()> {
    file.seek(SeekFrom::Start(offset))
        .map_err(Error::SeekingFile)?;
    file.read_exact(buf).map_err(Error::ReadingHeader)
}

impl SingleFileDisk {
    pub fn new(disk: File, ex: &Executor) -> Result<Self> {
        // macOS does not distinguish block device files for punch-hole operations
        // in the same way Linux does, so we don't need the is_block_device_file field.
        ex.async_from(disk)
            .map_err(Error::CreateSingleFileDisk)
            .map(|inner| SingleFileDisk { inner })
    }
}
