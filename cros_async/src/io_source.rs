// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use async_trait::async_trait;
use base::AsRawDescriptor;
use std::sync::Arc;

#[cfg(unix)]
use crate::sys::unix::PollSource;
#[cfg(unix)]
use crate::sys::unix::UringSource;
#[cfg(windows)]
use crate::sys::windows::HandleSource;
#[cfg(windows)]
use crate::sys::windows::OverlappedSource;
use crate::AllocateMode;
use crate::AsyncResult;
use crate::BackingMemory;
use crate::IoSourceExt;
use crate::MemRegion;
use crate::ReadAsync;
use crate::WriteAsync;

/// Associates an IO object `F` with cros_async's runtime and exposes an API to perform async IO on
/// that object's descriptor.
pub enum IoSource<F: base::AsRawDescriptor> {
    #[cfg(unix)]
    Uring(UringSource<F>),
    #[cfg(unix)]
    Epoll(PollSource<F>),
    #[cfg(windows)]
    Handle(HandleSource<F>),
    #[cfg(windows)]
    Overlapped(OverlappedSource<F>),
}

/// Invoke a method on the underlying source type and await the result.
///
/// `await_on_inner(io_source, method, ...)` => `inner_source.method(...).await`
macro_rules! await_on_inner {
    ($x:ident, $method:ident $(, $args:expr)*) => {
        match $x {
            #[cfg(unix)]
            IoSource::Uring(x) => UringSource::$method(x, $($args),*).await,
            #[cfg(unix)]
            IoSource::Epoll(x) => PollSource::$method(x, $($args),*).await,
            #[cfg(windows)]
            IoSource::Handle(x) => HandleSource::$method(x, $($args),*).await,
            #[cfg(windows)]
            IoSource::Overlapped(x) => OverlappedSource::$method(x, $($args),*).await,
        }
    };
}

/// Invoke a method on the underlying source type.
///
/// `on_inner(io_source, method, ...)` => `inner_source.method(...)`
macro_rules! on_inner {
    ($x:ident, $method:ident $(, $args:expr)*) => {
        match $x {
            #[cfg(unix)]
            IoSource::Uring(x) => UringSource::$method(x, $($args),*),
            #[cfg(unix)]
            IoSource::Epoll(x) => PollSource::$method(x, $($args),*),
            #[cfg(windows)]
            IoSource::Handle(x) => HandleSource::$method(x, $($args),*),
            #[cfg(windows)]
            IoSource::Overlapped(x) => OverlappedSource::$method(x, $($args),*),
        }
    };
}

impl<F: AsRawDescriptor> IoSource<F> {
    /// Reads at `file_offset` and fills the given `vec`.
    pub async fn read_to_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        await_on_inner!(self, read_to_vec, file_offset, vec)
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    pub async fn read_to_mem<'a>(
        &'a self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        await_on_inner!(self, read_to_mem, file_offset, mem, mem_offsets)
    }

    /// Reads a single u64 at the current offset.
    pub async fn read_u64(&self) -> AsyncResult<u64> {
        await_on_inner!(self, read_u64)
    }

    /// Waits for the object to be readable.
    pub async fn wait_readable(&self) -> AsyncResult<()> {
        await_on_inner!(self, wait_readable)
    }

    /// Writes from the given `vec` to the file starting at `file_offset`.
    pub async fn write_from_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        await_on_inner!(self, write_from_vec, file_offset, vec)
    }

    /// Writes from the given `mem` at the given offsets to the file starting at `file_offset`.
    pub async fn write_from_mem<'a>(
        &'a self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        await_on_inner!(self, write_from_mem, file_offset, mem, mem_offsets)
    }

    /// See `fallocate(2)`. Note this op is synchronous when using the Polled backend.
    pub async fn fallocate(
        &self,
        file_offset: u64,
        len: u64,
        mode: AllocateMode,
    ) -> AsyncResult<()> {
        await_on_inner!(self, fallocate, file_offset, len, mode)
    }

    /// Sync all completed write operations to the backing storage.
    pub async fn fsync(&self) -> AsyncResult<()> {
        await_on_inner!(self, fsync)
    }

    /// Yields the underlying IO source.
    pub fn into_source(self) -> F {
        on_inner!(self, into_source)
    }

    /// Provides a ref to the underlying IO source.
    pub fn as_source(&self) -> &F {
        on_inner!(self, as_source)
    }

    /// Provides a mutable ref to the underlying IO source.
    pub fn as_source_mut(&mut self) -> &mut F {
        on_inner!(self, as_source_mut)
    }

    /// Waits on a waitable handle.
    ///
    /// Needed for Windows currently, and subject to a potential future upstream.
    pub async fn wait_for_handle(&self) -> AsyncResult<u64> {
        await_on_inner!(self, wait_for_handle)
    }
}

#[async_trait(?Send)]
impl<F: AsRawDescriptor> ReadAsync for IoSource<F> {
    async fn read_to_vec<'a>(
        &'a self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        await_on_inner!(self, read_to_vec, file_offset, vec)
    }

    async fn wait_readable(&self) -> AsyncResult<()> {
        await_on_inner!(self, wait_readable)
    }

    async fn read_u64(&self) -> AsyncResult<u64> {
        await_on_inner!(self, read_u64)
    }

    async fn read_to_mem<'a>(
        &'a self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        await_on_inner!(self, read_to_mem, file_offset, mem, mem_offsets)
    }
}

#[async_trait(?Send)]
impl<F: AsRawDescriptor> WriteAsync for IoSource<F> {
    async fn write_from_vec<'a>(
        &'a self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        await_on_inner!(self, write_from_vec, file_offset, vec)
    }

    async fn write_from_mem<'a>(
        &'a self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        await_on_inner!(self, write_from_mem, file_offset, mem, mem_offsets)
    }

    async fn fallocate(&self, file_offset: u64, len: u64, mode: AllocateMode) -> AsyncResult<()> {
        await_on_inner!(self, fallocate, file_offset, len, mode)
    }

    async fn fsync(&self) -> AsyncResult<()> {
        await_on_inner!(self, fsync)
    }
}

#[async_trait(?Send)]
impl<F: base::AsRawDescriptor> IoSourceExt<F> for IoSource<F> {
    fn into_source(self) -> F {
        on_inner!(self, into_source)
    }

    fn as_source(&self) -> &F {
        on_inner!(self, as_source)
    }

    fn as_source_mut(&mut self) -> &mut F {
        on_inner!(self, as_source_mut)
    }

    async fn wait_for_handle(&self) -> AsyncResult<u64> {
        await_on_inner!(self, wait_for_handle)
    }
}
