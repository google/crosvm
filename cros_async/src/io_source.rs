// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::Deref;
use std::pin::Pin;
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
        self: Pin<&Self>,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &[MemRegion],
    ) -> Result<PendingOperation>;

    /// Starts an operation to write to `self` at `file_offset` from `mem` at the addresses and
    /// lengths given in `mem_offsets`.
    fn write_from_mem(
        self: Pin<&Self>,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &[MemRegion],
    ) -> Result<PendingOperation>;

    /// Asynchronously `fallocate(2)`
    fn fallocate(
        self: Pin<&Self>,
        file_offset: u64,
        len: u64,
        mode: u32,
    ) -> Result<PendingOperation>;

    /// Starts the fsync operation that will sync all completed writes to the backing storage.
    fn fsync(self: Pin<&Self>) -> Result<PendingOperation>;

    /// Waits for the inner source to be readable. This is similar to calling `poll` with the FD of
    /// `self`. However, this returns a `PendingOperation` which can be polled asynchronously for
    /// completion.
    fn wait_readable(self: Pin<&Self>) -> Result<PendingOperation>;

    /// Checks if a `PendingOperation` returned from another trait method is complete.
    fn poll_complete(
        self: Pin<&Self>,
        cx: &mut Context,
        token: &mut PendingOperation,
    ) -> Poll<Result<u32>>;
}

// Implement IoSource for types that can deref to IoSource.  Given a Pin<&Self> deref it and re-wrap
// it in a Pin. Re-wrapping is needed to avoid recursively calling the current funciton as the deref
// impl will be the first thing found again. These methods only work for types that are UnPin.
// For example: if Self is &T, self is Pin<&&T>, *self is &T (Deref on Pin derefs to the target of
// the wrapped types Deref implementaion), **self is T, which is used to created the new Pin type
// and run the underlying implementation of the function.
macro_rules! deref_io_source {
    () => {
        fn read_to_mem(
            self: Pin<&Self>,
            file_offset: u64,
            mem: Rc<dyn BackingMemory>,
            mem_offsets: &[MemRegion],
        ) -> Result<PendingOperation> {
            Pin::new(&**self).read_to_mem(file_offset, mem, mem_offsets)
        }

        fn write_from_mem(
            self: Pin<&Self>,
            file_offset: u64,
            mem: Rc<dyn BackingMemory>,
            mem_offsets: &[MemRegion],
        ) -> Result<PendingOperation> {
            Pin::new(&**self).write_from_mem(file_offset, mem, mem_offsets)
        }

        fn fallocate(
            self: Pin<&Self>,
            file_offset: u64,
            len: u64,
            mode: u32,
        ) -> Result<PendingOperation> {
            Pin::new(&**self).fallocate(file_offset, len, mode)
        }

        fn fsync(self: Pin<&Self>) -> Result<PendingOperation> {
            Pin::new(&**self).fsync()
        }

        fn wait_readable(self: Pin<&Self>) -> Result<PendingOperation> {
            Pin::new(&**self).wait_readable()
        }

        fn poll_complete(
            self: Pin<&Self>,
            cx: &mut Context,
            token: &mut PendingOperation,
        ) -> Poll<Result<u32>> {
            Pin::new(&**self).poll_complete(cx, token)
        }
    };
}

impl<T: ?Sized + IoSource + Unpin> IoSource for Box<T> {
    deref_io_source!();
}

impl<T: ?Sized + IoSource + Unpin> IoSource for &T {
    deref_io_source!();
}

impl<T: ?Sized + IoSource + Unpin> IoSource for &mut T {
    deref_io_source!();
}

impl<P> IoSource for Pin<P>
where
    P: Deref + Unpin,
    P::Target: IoSource,
{
    fn read_to_mem(
        self: Pin<&Self>,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &[MemRegion],
    ) -> Result<PendingOperation> {
        self.get_ref()
            .as_ref()
            .read_to_mem(file_offset, mem, mem_offsets)
    }

    fn write_from_mem(
        self: Pin<&Self>,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &[MemRegion],
    ) -> Result<PendingOperation> {
        self.get_ref()
            .as_ref()
            .write_from_mem(file_offset, mem, mem_offsets)
    }

    fn fallocate(
        self: Pin<&Self>,
        file_offset: u64,
        len: u64,
        mode: u32,
    ) -> Result<PendingOperation> {
        self.get_ref().as_ref().fallocate(file_offset, len, mode)
    }

    fn fsync(self: Pin<&Self>) -> Result<PendingOperation> {
        self.get_ref().as_ref().fsync()
    }

    fn wait_readable(self: Pin<&Self>) -> Result<PendingOperation> {
        self.get_ref().as_ref().wait_readable()
    }

    fn poll_complete(
        self: Pin<&Self>,
        cx: &mut Context,
        token: &mut PendingOperation,
    ) -> Poll<Result<u32>> {
        self.get_ref().as_ref().poll_complete(cx, token)
    }
}
