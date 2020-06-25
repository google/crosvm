// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! # `IoSourceExt`
//!
//! Extension functions to asynchronously access files.
//! `IoSourceExt` is the interface exposed to users for `IoSource` objects. Using `IoSource`
//! directly is inconvenient and requires dealing with state machines for the backing uring and
//! future libraries. `IoSourceExt` instead provides users with a future that can be `await`ed from
//! async context.
//!
//! Each member of `IoSourceExt` returns a future for the supported operation. One or more
//! operation can be pending at a time.
//!
//! Operations can only access memory in a `Vec` or an implementor of `BackingMemory`. See the
//! `URingExecutor` documentation for an explaination of why.

use std::rc::Rc;

use crate::io_source::IoSource;
use crate::uring_futures;
use crate::uring_mem::{BackingMemory, MemRegion};

/// Extends IoSource with ergonomic methods to perform asynchronous IO.
pub trait IoSourceExt: IoSource {
    /// Reads from the iosource at `file_offset` and fill the given `vec`.
    fn read_to_vec<'a>(&'a self, file_offset: u64, vec: Vec<u8>) -> uring_futures::ReadVec<'a, Self>
    where
        Self: Unpin,
    {
        uring_futures::ReadVec::new(self, file_offset, vec)
    }

    /// Writes from the given `vec` to the file starting at `file_offset`.
    fn write_from_vec<'a>(
        &'a self,
        file_offset: u64,
        vec: Vec<u8>,
    ) -> uring_futures::WriteVec<'a, Self>
    where
        Self: Unpin,
    {
        uring_futures::WriteVec::new(self, file_offset, vec)
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    fn read_to_mem<'a, 'b>(
        &'a self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &'b [MemRegion],
    ) -> uring_futures::ReadMem<'a, 'b, Self>
    where
        Self: Unpin,
    {
        uring_futures::ReadMem::new(self, file_offset, mem, mem_offsets)
    }

    /// Writes from the given `mem` from the given offsets to the file starting at `file_offset`.
    fn write_from_mem<'a, 'b>(
        &'a self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &'b [MemRegion],
    ) -> uring_futures::WriteMem<'a, 'b, Self>
    where
        Self: Unpin,
    {
        uring_futures::WriteMem::new(self, file_offset, mem, mem_offsets)
    }

    /// See `fallocate(2)` for details.
    fn fallocate(&self, file_offset: u64, len: u64, mode: u32) -> uring_futures::Fallocate<Self>
    where
        Self: Unpin,
    {
        uring_futures::Fallocate::new(self, file_offset, len, mode)
    }

    /// Sync all completed write operations to the backing storage.
    fn fsync(&self) -> uring_futures::Fsync<Self>
    where
        Self: Unpin,
    {
        uring_futures::Fsync::new(self)
    }

    /// Wait for the FD of `self` to be readable.
    fn wait_readable(&self) -> uring_futures::PollFd<'_, Self>
    where
        Self: Unpin,
    {
        uring_futures::PollFd::new(self)
    }
}

impl<T: IoSource + ?Sized> IoSourceExt for T {}
