// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::max;
use std::cmp::min;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::prelude::OpenOptionsExt;

use anyhow::Context;
use base::flock;
use base::iov_max;
use base::open_file;
use base::FlockOperation;
use disk::DiskFile;

use crate::virtio::block::DiskOption;

pub fn get_seg_max(queue_size: u16) -> u32 {
    let seg_max = min(max(iov_max(), 1), u32::max_value() as usize) as u32;

    // Since we do not currently support indirect descriptors, the maximum
    // number of segments must be smaller than the queue size.
    // In addition, the request header and status each consume a descriptor.
    min(seg_max, u32::from(queue_size) - 2)
}

impl DiskOption {
    /// Open the specified disk file.
    pub fn open(&self) -> anyhow::Result<Box<dyn DiskFile>> {
        let mut options = OpenOptions::new();
        options.read(true).write(!self.read_only);

        if self.direct {
            options.custom_flags(libc::O_DIRECT);
        }

        let raw_image: File = open_file(&self.path, &options)
            .with_context(|| format!("failed to load disk image {}", self.path.display()))?;
        // Lock the disk image to prevent other crosvm instances from using it.
        let lock_op = if self.read_only {
            FlockOperation::LockShared
        } else {
            FlockOperation::LockExclusive
        };
        flock(&raw_image, lock_op, true)
            .with_context(|| format!("failed to lock disk image {}", self.path.display()))?;

        disk::create_disk_file(raw_image, self.sparse, disk::MAX_NESTING_DEPTH, &self.path)
            .context("create_disk_file failed")
    }
}
