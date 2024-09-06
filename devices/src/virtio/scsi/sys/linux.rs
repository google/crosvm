// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Context;
use disk::DiskFile;

use crate::virtio::scsi::ScsiOption;

impl ScsiOption {
    pub fn open(&self) -> anyhow::Result<Box<dyn DiskFile>> {
        // We only support sparse disks for now.
        disk::open_disk_file(disk::DiskFileParams {
            path: self.path.clone(),
            is_read_only: self.read_only,
            is_sparse_file: true,
            is_overlapped: false,
            is_direct: false,
            depth: 0,
        })
        .context("open_disk_file failed")
    }
}
