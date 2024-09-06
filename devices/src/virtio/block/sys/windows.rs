// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Context;
use base::warn;
use cros_async::sys::windows::ExecutorKindSys;
use cros_async::Executor;
use cros_async::ExecutorKind;

use crate::virtio::block::DiskOption;
use crate::virtio::BlockAsync;

pub fn get_seg_max(_queue_size: u16) -> u32 {
    // Allow a single segment per request, since vectored I/O is not implemented for Windows yet.
    1
}

impl DiskOption {
    /// Open the specified disk file.
    pub fn open(&self) -> anyhow::Result<Box<dyn disk::DiskFile>> {
        Ok(disk::open_disk_file(disk::DiskFileParams {
            path: self.path.clone(),
            is_read_only: self.read_only,
            is_sparse_file: self.sparse,
            is_overlapped: matches!(
                self.async_executor.unwrap_or_default(),
                ExecutorKind::SysVariants(ExecutorKindSys::Overlapped { .. })
            ),
            is_direct: self.direct,
            depth: 0,
        })?)
    }
}

impl BlockAsync {
    pub fn create_executor(&self) -> Executor {
        let mut kind = self.executor_kind;
        if let ExecutorKind::SysVariants(ExecutorKindSys::Overlapped { concurrency }) = &mut kind {
            if concurrency.is_none() {
                *concurrency = Some(self.io_concurrency);
            }
        }
        Executor::with_executor_kind(kind).expect("Failed to create an executor")
    }
}
