// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::rc::Rc;
use std::task::{Context, Poll};

use crate::uring_executor::{PendingOperation, Result};
use crate::uring_mem::{BackingMemory, MemRegion};

/// A trait for supporting asynchronous reads and writes to `BackingMemory` implementations.
/// Users should use the interfaces provided by `IoSourceExt` to get Futures that can be `await`ed.
pub trait IoSource {
    /// Starts an operation to read from `self` at `file_offset` to `mem` at the addresses and
    /// lengths given in `mem_offsets`.
    fn read_to_mem(
        &self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &[MemRegion],
    ) -> Result<PendingOperation>;

    /// Starts an operation to write to `self` at `file_offset` from `mem` at the addresses and
    /// lengths given in `mem_offsets`.
    fn write_from_mem(
        &self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &[MemRegion],
    ) -> Result<PendingOperation>;

    /// Asynchronously `fallocate(2)`
    fn fallocate(&self, file_offset: u64, len: u64, mode: u32) -> Result<PendingOperation>;

    /// Starts the fsync operation that will sync all completed writes to the backing storage.
    fn fsync(&self) -> Result<PendingOperation>;

    /// Waits for the inner source to be readable. This is similar to calling `poll` with the FD of
    /// `self`. However, this returns a `PendingOperation` which can be polled asynchronously for
    /// completion.
    fn wait_readable(&self) -> Result<PendingOperation>;

    /// Checks if a `PendingOperation` returned from another trait method is complete.
    fn poll_complete(&self, cx: &mut Context, token: &mut PendingOperation) -> Poll<Result<u32>>;
}
