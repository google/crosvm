// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::max;
use std::cmp::min;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;

use anyhow::Context;
use base::add_fd_flags;
use base::flock;
use base::open_file_or_duplicate;
use base::unix::iov_max;
use base::FlockOperation;
use cros_async::Executor;
use disk::DiskFile;

use crate::virtio::block::DiskOption;
use crate::virtio::BlockAsync;

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

        // If O_DIRECT is requested, set the flag via fcntl. It is not done at
        // open_file_or_reuse time because it will reuse existing fd and will
        // not actually use the given OpenOptions.
        if self.direct {
            add_fd_flags(raw_image.as_raw_fd(), libc::O_DIRECT)
                .with_context(|| format!("failed to set O_DIRECT to {}", &self.path.display()))?;
        }

        disk::create_disk_file(raw_image, self.sparse, disk::MAX_NESTING_DEPTH, &self.path)
            .context("create_disk_file failed")
    }
}

impl BlockAsync {
    pub fn create_executor(&self) -> Executor {
        Executor::with_executor_kind(self.executor_kind.into())
            .expect("Failed to create an executor")
    }
}
