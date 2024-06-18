// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Asynchronous disk image helpers.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base::AsRawDescriptors;
use base::FileAllocate;
use base::FileSetLen;
use base::FileSync;
use base::PunchHole;
use base::RawDescriptor;
use base::WriteZeroesAt;
use cros_async::BackingMemory;
use cros_async::BlockingPool;
use cros_async::Executor;

use crate::AsyncDisk;
use crate::DiskFile;
use crate::DiskGetLen;
use crate::Error;
use crate::Result;

/// Async wrapper around a non-async `DiskFile` using a `BlockingPool`.
///
/// This is meant to be a transitional type, not a long-term solution for async disk support. Disk
/// formats should be migrated to support async instead (b/219595052).
pub struct AsyncDiskFileWrapper<T: DiskFile + Send> {
    blocking_pool: BlockingPool,
    inner: Arc<T>,
}

impl<T: DiskFile + Send> AsyncDiskFileWrapper<T> {
    #[allow(dead_code)] // Only used if qcow or android-sparse features are enabled
    pub fn new(disk_file: T, _ex: &Executor) -> Self {
        Self {
            blocking_pool: BlockingPool::new(1, Duration::from_secs(10)),
            inner: Arc::new(disk_file),
        }
    }
}

impl<T: DiskFile + Send> DiskGetLen for AsyncDiskFileWrapper<T> {
    fn get_len(&self) -> io::Result<u64> {
        self.inner.get_len()
    }
}

impl<T: DiskFile + Send + FileSetLen> FileSetLen for AsyncDiskFileWrapper<T> {
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
}

impl<T: DiskFile + Send + FileAllocate> FileAllocate for AsyncDiskFileWrapper<T> {
    fn allocate(&self, offset: u64, len: u64) -> io::Result<()> {
        self.inner.allocate(offset, len)
    }
}

impl<T: DiskFile + Send> AsRawDescriptors for AsyncDiskFileWrapper<T> {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        self.inner.as_raw_descriptors()
    }
}

pub trait DiskFlush {
    /// Flush intermediary buffers and/or dirty state to file. fsync not required.
    fn flush(&self) -> io::Result<()>;
}

#[async_trait(?Send)]
impl<
        T: 'static
            + DiskFile
            + DiskFlush
            + Send
            + Sync
            + FileAllocate
            + FileSetLen
            + FileSync
            + PunchHole
            + WriteZeroesAt,
    > AsyncDisk for AsyncDiskFileWrapper<T>
{
    async fn flush(&self) -> Result<()> {
        let inner_clone = self.inner.clone();
        self.blocking_pool
            .spawn(move || inner_clone.flush().map_err(Error::IoFlush))
            .await
    }

    async fn fsync(&self) -> Result<()> {
        let inner_clone = self.inner.clone();
        self.blocking_pool
            .spawn(move || inner_clone.fsync().map_err(Error::IoFsync))
            .await
    }

    async fn fdatasync(&self) -> Result<()> {
        let inner_clone = self.inner.clone();
        self.blocking_pool
            .spawn(move || inner_clone.fdatasync().map_err(Error::IoFdatasync))
            .await
    }

    async fn read_to_mem<'a>(
        &'a self,
        mut file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: cros_async::MemRegionIter<'a>,
    ) -> Result<usize> {
        let inner_clone = self.inner.clone();
        let mem_offsets: Vec<cros_async::MemRegion> = mem_offsets.collect();
        self.blocking_pool
            .spawn(move || {
                let mut size = 0;
                for region in mem_offsets {
                    let mem_slice = mem.get_volatile_slice(region).unwrap();
                    let bytes_read = inner_clone
                        .read_at_volatile(mem_slice, file_offset)
                        .map_err(Error::ReadingData)?;
                    size += bytes_read;
                    if bytes_read < mem_slice.size() {
                        break;
                    }
                    file_offset += bytes_read as u64;
                }
                Ok(size)
            })
            .await
    }

    async fn write_from_mem<'a>(
        &'a self,
        mut file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: cros_async::MemRegionIter<'a>,
    ) -> Result<usize> {
        let inner_clone = self.inner.clone();
        let mem_offsets: Vec<cros_async::MemRegion> = mem_offsets.collect();
        self.blocking_pool
            .spawn(move || {
                let mut size = 0;
                for region in mem_offsets {
                    let mem_slice = mem.get_volatile_slice(region).unwrap();
                    let bytes_written = inner_clone
                        .write_at_volatile(mem_slice, file_offset)
                        .map_err(Error::ReadingData)?;
                    size += bytes_written;
                    if bytes_written < mem_slice.size() {
                        break;
                    }
                    file_offset += bytes_written as u64;
                }
                Ok(size)
            })
            .await
    }

    async fn punch_hole(&self, file_offset: u64, length: u64) -> Result<()> {
        let inner_clone = self.inner.clone();
        self.blocking_pool
            .spawn(move || {
                inner_clone
                    .punch_hole(file_offset, length)
                    .map_err(Error::IoPunchHole)
            })
            .await
    }

    async fn write_zeroes_at(&self, file_offset: u64, length: u64) -> Result<()> {
        let inner_clone = self.inner.clone();
        self.blocking_pool
            .spawn(move || {
                inner_clone
                    .write_zeroes_all_at(file_offset, length as usize)
                    .map_err(Error::WriteZeroes)
            })
            .await
    }
}
