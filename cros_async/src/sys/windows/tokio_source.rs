// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::mem::ManuallyDrop;
use std::sync::Arc;

use base::AsRawDescriptor;
use base::FileReadWriteAtVolatile;
use base::FileReadWriteVolatile;
use base::FromRawDescriptor;
use base::PunchHole;
use base::VolatileSlice;
use base::WriteZeroesAt;
use smallvec::SmallVec;
use sync::Mutex;

use crate::mem::MemRegion;
use crate::AsyncError;
use crate::AsyncResult;
use crate::BackingMemory;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("An error occurred trying to seek: {0}.")]
    IoSeekError(io::Error),
    #[error("An error occurred trying to read: {0}.")]
    IoReadError(io::Error),
    #[error("An error occurred trying to write: {0}.")]
    IoWriteError(io::Error),
    #[error("An error occurred trying to flush: {0}.")]
    IoFlushError(io::Error),
    #[error("An error occurred trying to punch hole: {0}.")]
    IoPunchHoleError(io::Error),
    #[error("An error occurred trying to write zeroes: {0}.")]
    IoWriteZeroesError(io::Error),
    #[error("Failed to join task: '{0}'")]
    Join(tokio::task::JoinError),
    #[error("An error occurred trying to duplicate source handles: {0}.")]
    HandleDuplicationFailed(io::Error),
    #[error("An error occurred trying to wait on source handles: {0}.")]
    HandleWaitFailed(base::Error),
    #[error("An error occurred trying to get a VolatileSlice into BackingMemory: {0}.")]
    BackingMemoryVolatileSliceFetchFailed(crate::mem::Error),
    #[error("TokioSource is gone, so no handles are available to fulfill the IO request.")]
    NoTokioSource,
    #[error("Operation on TokioSource is cancelled.")]
    OperationCancelled,
    #[error("Operation on TokioSource was aborted (unexpected).")]
    OperationAborted,
}

impl From<Error> for AsyncError {
    fn from(e: Error) -> AsyncError {
        AsyncError::SysVariants(e.into())
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            IoSeekError(e) => e,
            IoReadError(e) => e,
            IoWriteError(e) => e,
            IoFlushError(e) => e,
            IoPunchHoleError(e) => e,
            IoWriteZeroesError(e) => e,
            Join(e) => io::Error::new(io::ErrorKind::Other, e),
            HandleDuplicationFailed(e) => e,
            HandleWaitFailed(e) => e.into(),
            BackingMemoryVolatileSliceFetchFailed(e) => io::Error::new(io::ErrorKind::Other, e),
            NoTokioSource => io::Error::new(io::ErrorKind::Other, NoTokioSource),
            OperationCancelled => io::Error::new(io::ErrorKind::Interrupted, OperationCancelled),
            OperationAborted => io::Error::new(io::ErrorKind::Interrupted, OperationAborted),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct TokioSource<T: AsRawDescriptor> {
    source: Option<T>,
    source_file: Arc<Mutex<Option<ManuallyDrop<File>>>>,
    runtime: tokio::runtime::Handle,
}

impl<T: AsRawDescriptor> TokioSource<T> {
    pub(crate) fn new(source: T, runtime: tokio::runtime::Handle) -> Result<TokioSource<T>> {
        let descriptor = source.as_raw_descriptor();
        // SAFETY: The Drop implementation makes sure `source` outlives `source_file`.
        let source_file = unsafe { ManuallyDrop::new(File::from_raw_descriptor(descriptor)) };
        Ok(Self {
            source: Some(source),
            source_file: Arc::new(Mutex::new(Some(source_file))),
            runtime,
        })
    }
    #[inline]
    fn get_slices(
        mem: &Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: Vec<MemRegion>,
    ) -> Result<SmallVec<[VolatileSlice<'_>; 16]>> {
        mem_offsets
            .into_iter()
            .map(|region| {
                mem.get_volatile_slice(region)
                    .map_err(Error::BackingMemoryVolatileSliceFetchFailed)
            })
            .collect::<Result<SmallVec<[VolatileSlice; 16]>>>()
    }
    pub fn as_source(&self) -> &T {
        self.source.as_ref().unwrap()
    }
    pub fn as_source_mut(&mut self) -> &mut T {
        self.source.as_mut().unwrap()
    }
    pub async fn fdatasync(&self) -> AsyncResult<()> {
        // TODO(b/282003931): Fall back to regular fsync.
        self.fsync().await
    }
    pub async fn fsync(&self) -> AsyncResult<()> {
        let source_file = self.source_file.clone();
        Ok(self
            .runtime
            .spawn_blocking(move || {
                source_file
                    .lock()
                    .as_mut()
                    .ok_or(Error::OperationCancelled)?
                    .flush()
                    .map_err(Error::IoFlushError)
            })
            .await
            .map_err(Error::Join)??)
    }
    pub fn into_source(mut self) -> T {
        self.source_file.lock().take();
        self.source.take().unwrap()
    }
    pub async fn punch_hole(&self, file_offset: u64, len: u64) -> AsyncResult<()> {
        let source_file = self.source_file.clone();
        Ok(self
            .runtime
            .spawn_blocking(move || {
                source_file
                    .lock()
                    .as_mut()
                    .ok_or(Error::OperationCancelled)?
                    .punch_hole(file_offset, len)
                    .map_err(Error::IoPunchHoleError)
            })
            .await
            .map_err(Error::Join)??)
    }
    pub async fn read_to_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: impl IntoIterator<Item = MemRegion>,
    ) -> AsyncResult<usize> {
        let mem_offsets = mem_offsets.into_iter().collect();
        let source_file = self.source_file.clone();
        Ok(self
            .runtime
            .spawn_blocking(move || {
                let mut file_lock = source_file.lock();
                let file = file_lock.as_mut().ok_or(Error::OperationCancelled)?;
                let memory_slices = Self::get_slices(&mem, mem_offsets)?;
                match file_offset {
                    Some(file_offset) => file
                        .read_vectored_at_volatile(memory_slices.as_slice(), file_offset)
                        .map_err(Error::IoReadError),
                    None => file
                        .read_vectored_volatile(memory_slices.as_slice())
                        .map_err(Error::IoReadError),
                }
            })
            .await
            .map_err(Error::Join)??)
    }
    pub async fn read_to_vec(
        &self,
        file_offset: Option<u64>,
        mut vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        let source_file = self.source_file.clone();
        Ok(self
            .runtime
            .spawn_blocking(move || {
                let mut file_lock = source_file.lock();
                let file = file_lock.as_mut().ok_or(Error::OperationCancelled)?;
                if let Some(file_offset) = file_offset {
                    file.seek(SeekFrom::Start(file_offset))
                        .map_err(Error::IoSeekError)?;
                }
                Ok::<(usize, Vec<u8>), Error>((
                    file.read(vec.as_mut_slice()).map_err(Error::IoReadError)?,
                    vec,
                ))
            })
            .await
            .map_err(Error::Join)??)
    }
    pub async fn wait_readable(&self) -> AsyncResult<()> {
        unimplemented!();
    }
    pub async fn wait_for_handle(&self) -> AsyncResult<()> {
        base::sys::windows::async_wait_for_single_object(self.source.as_ref().unwrap()).await?;
        Ok(())
    }
    pub async fn write_from_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: impl IntoIterator<Item = MemRegion>,
    ) -> AsyncResult<usize> {
        let mem_offsets = mem_offsets.into_iter().collect();
        let source_file = self.source_file.clone();
        Ok(self
            .runtime
            .spawn_blocking(move || {
                let mut file_lock = source_file.lock();
                let file = file_lock.as_mut().ok_or(Error::OperationCancelled)?;
                let memory_slices = Self::get_slices(&mem, mem_offsets)?;
                match file_offset {
                    Some(file_offset) => file
                        .write_vectored_at_volatile(memory_slices.as_slice(), file_offset)
                        .map_err(Error::IoWriteError),
                    None => file
                        .write_vectored_volatile(memory_slices.as_slice())
                        .map_err(Error::IoWriteError),
                }
            })
            .await
            .map_err(Error::Join)??)
    }
    pub async fn write_from_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        let source_file = self.source_file.clone();
        Ok(self
            .runtime
            .spawn_blocking(move || {
                let mut file_lock = source_file.lock();
                let file = file_lock.as_mut().ok_or(Error::OperationCancelled)?;
                if let Some(file_offset) = file_offset {
                    file.seek(SeekFrom::Start(file_offset))
                        .map_err(Error::IoSeekError)?;
                }
                Ok::<(usize, Vec<u8>), Error>((
                    file.write(vec.as_slice()).map_err(Error::IoWriteError)?,
                    vec,
                ))
            })
            .await
            .map_err(Error::Join)??)
    }
    pub async fn write_zeroes_at(&self, file_offset: u64, len: u64) -> AsyncResult<()> {
        let source_file = self.source_file.clone();
        Ok(self
            .runtime
            .spawn_blocking(move || {
                // ZeroRange calls `punch_hole` which doesn't extend the File size if it needs to.
                // Will fix if it becomes a problem.
                source_file
                    .lock()
                    .as_mut()
                    .ok_or(Error::OperationCancelled)?
                    .write_zeroes_at(file_offset, len as usize)
                    .map_err(Error::IoWriteZeroesError)
                    .map(|_| ())
            })
            .await
            .map_err(Error::Join)??)
    }
}
impl<T: AsRawDescriptor> Drop for TokioSource<T> {
    fn drop(&mut self) {
        let mut source_file = self.source_file.lock();
        source_file.take();
    }
}
