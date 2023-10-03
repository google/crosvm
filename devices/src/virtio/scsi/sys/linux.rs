// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::fs::OpenOptions;

use anyhow::Context;
use base::flock;
use base::open_file_or_duplicate;
use base::FlockOperation;
use disk::DiskFile;

use crate::virtio::scsi::ScsiOption;

impl ScsiOption {
    pub fn open(&self) -> anyhow::Result<Box<dyn DiskFile>> {
        let mut options = OpenOptions::new();
        options.read(true).write(!self.read_only);

        let raw_image: File = open_file_or_duplicate(&self.path, &options)
            .with_context(|| format!("failed to load disk image {}", self.path.display()))?;
        // Lock the disk image to prevent other crosvm instances from using it.
        let lock_op = if self.read_only {
            FlockOperation::LockShared
        } else {
            FlockOperation::LockExclusive
        };
        flock(&raw_image, lock_op, true)
            .with_context(|| format!("failed to lock disk image {}", self.path.display()))?;

        // We only support sparse disks for now.
        disk::create_disk_file(raw_image, true, disk::MAX_NESTING_DEPTH, &self.path)
            .context("create_disk_file failed")
    }
}
