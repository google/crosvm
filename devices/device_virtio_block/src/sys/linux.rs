// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::max;
use std::cmp::min;
use std::os::fd::BorrowedFd;

use anyhow::Context;
use base::linux::preadv2;
use base::linux::pwritev2;
use base::unix::iov_max;
use base::IoBufMut;
use base::RawDescriptor;
use cros_async::Executor;
use disk::DiskFile;

use crate::asynchronous::BlockAsync;
use crate::DiskOption;

pub fn get_seg_max(queue_size: u16) -> u32 {
    let seg_max = min(max(iov_max(), 1), u32::MAX as usize) as u32;

    // Since we do not currently support indirect descriptors, the maximum
    // number of segments must be smaller than the queue size.
    // In addition, the request header and status each consume a descriptor.
    min(seg_max, u32::from(queue_size) - 2)
}

pub fn check_dontcache_support(fd: RawDescriptor, write: bool) -> bool {
    let mut buf = [0u8; 1];
    let mut iovs = [IoBufMut::new(&mut buf)];
    // SAFETY: fd is an open file descriptor.
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let res = if write {
        pwritev2(
            borrowed_fd,
            IoBufMut::as_iobufs(&iovs),
            0,
            libc::RWF_DONTCACHE,
        )
    } else {
        preadv2(borrowed_fd, &mut iovs, 0, libc::RWF_DONTCACHE)
    };
    if res < 0 {
        let err = base::Error::last();
        match err.errno() {
            libc::EOPNOTSUPP | libc::EINVAL | libc::ENOSYS => false,
            _ => {
                base::warn!("Unexpected error checking for DONTCACHE support: {err}");
                false
            }
        }
    } else {
        true
    }
}

impl DiskOption {
    /// Open the specified disk file.
    pub fn open(&self) -> anyhow::Result<Box<dyn DiskFile>> {
        disk::open_disk_file(disk::DiskFileParams {
            path: self.path.clone(),
            is_read_only: self.read_only,
            is_sparse_file: self.sparse,
            is_direct: self.direct,
            lock: self.lock,
            ..Default::default()
        })
        .context("open_disk_file failed")
    }
}

impl BlockAsync {
    pub fn create_executor(&self) -> Executor {
        Executor::with_executor_kind(self.executor_kind).expect("Failed to create an executor")
    }
}
