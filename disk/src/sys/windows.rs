// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::os::windows::fs::OpenOptionsExt;

use base::info;
use base::read_overlapped_blocking;
use cros_async::Executor;
use winapi::um::winbase::FILE_FLAG_NO_BUFFERING;
use winapi::um::winbase::FILE_FLAG_OVERLAPPED;
use winapi::um::winnt::FILE_SHARE_READ;
use winapi::um::winnt::FILE_SHARE_WRITE;

use crate::DiskFileParams;
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

pub fn open_raw_disk_image(params: &DiskFileParams) -> Result<File> {
    let mut options = File::options();
    options.read(true).write(!params.is_read_only);
    if params.lock {
        // We only prevent file deletion and renaming right now.
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }

    let mut flags = 0;
    if params.is_direct {
        info!("Opening disk file with no buffering");
        flags |= FILE_FLAG_NO_BUFFERING;
    }
    if params.is_overlapped {
        info!("Opening disk file for overlapped IO");
        flags |= FILE_FLAG_OVERLAPPED;
    }
    if flags != 0 {
        options.custom_flags(flags);
    }

    let raw_image = base::open_file_or_duplicate(&params.path, &options)
        .map_err(|e| Error::OpenFile(params.path.display().to_string(), e))?;

    Ok(raw_image)
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
