// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::max;
use std::cmp::min;

use anyhow::Context;
use base::unix::iov_max;
use cros_async::Executor;
use disk::DiskFile;

use crate::virtio::block::DiskOption;
use crate::virtio::BlockAsync;

pub fn get_seg_max(queue_size: u16) -> u32 {
    let seg_max = min(max(iov_max(), 1), u32::MAX as usize) as u32;

    // Since we do not currently support indirect descriptors, the maximum
    // number of segments must be smaller than the queue size.
    // In addition, the request header and status each consume a descriptor.
    min(seg_max, u32::from(queue_size) - 2)
}

impl DiskOption {
    /// Open the specified disk file.
    pub fn open(&self) -> anyhow::Result<Box<dyn DiskFile>> {
        disk::open_disk_file(disk::DiskFileParams {
            path: self.path.clone(),
            is_read_only: self.read_only,
            is_sparse_file: self.sparse,
            is_overlapped: false,
            is_direct: self.direct,
            lock: self.lock,
            depth: 0,
        })
        .context("open_disk_file failed")
    }
}

impl BlockAsync {
    pub fn create_executor(&self) -> Executor {
        Executor::with_executor_kind(self.executor_kind).expect("Failed to create an executor")
    }
}
