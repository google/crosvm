// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::mem::ManuallyDrop;
use std::ptr::null_mut;
use std::sync::Arc;
use std::time::Duration;

use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Descriptor;
use base::Error as SysUtilError;
use base::FileReadWriteAtVolatile;
use base::FileReadWriteVolatile;
use base::FromRawDescriptor;
use base::PunchHole;
use base::VolatileSlice;
use base::WriteZeroesAt;
use smallvec::SmallVec;
use sync::Mutex;
use thiserror::Error as ThisError;
use winapi::um::ioapiset::CancelIoEx;

use crate::mem::BackingMemory;
use crate::mem::MemRegion;
use crate::AsyncError;
use crate::AsyncResult;
use crate::CancellableBlockingPool;

#[derive(ThisError, Debug)]
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
    #[error("An error occurred trying to duplicate source handles: {0}.")]
    HandleDuplicationFailed(io::Error),
    #[error("An error occurred trying to wait on source handles: {0}.")]
    HandleWaitFailed(io::Error),
    #[error("An error occurred trying to get a VolatileSlice into BackingMemory: {0}.")]
    BackingMemoryVolatileSliceFetchFailed(crate::mem::Error),
    #[error("HandleSource is gone, so no handles are available to fulfill the IO request.")]
    NoHandleSource,
    #[error("Operation on HandleSource is cancelled.")]
    OperationCancelled,
    #[error("Operation on HandleSource was aborted (unexpected).")]
    OperationAborted,
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
            HandleDuplicationFailed(e) => e,
            HandleWaitFailed(e) => e,
            BackingMemoryVolatileSliceFetchFailed(e) => io::Error::new(io::ErrorKind::Other, e),
            NoHandleSource => io::Error::new(io::ErrorKind::Other, NoHandleSource),
            OperationCancelled => io::Error::new(io::ErrorKind::Interrupted, OperationCancelled),
            OperationAborted => io::Error::new(io::ErrorKind::Interrupted, OperationAborted),
        }
    }
}

impl From<Error> for AsyncError {
    fn from(e: Error) -> AsyncError {
        AsyncError::SysVariants(e.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Used to shutdown IO running on a CancellableBlockingPool.
pub struct HandleWrapper {
    handle: Descriptor,
}

impl HandleWrapper {
    pub fn new(handle: Descriptor) -> Arc<Mutex<HandleWrapper>> {
        Arc::new(Mutex::new(Self { handle }))
    }

    pub fn cancel_sync_io<T>(&mut self, ret: T) -> T {
        // There isn't much we can do if cancel fails.
        // SAFETY: trivially safe
        if unsafe { CancelIoEx(self.handle.as_raw_descriptor(), null_mut()) } == 0 {
            warn!(
                "Cancel IO for handle:{:?} failed with {}",
                self.handle.as_raw_descriptor(),
                SysUtilError::last()
            );
        }
        ret
    }
}

/// Async IO source for Windows, such as a file.
pub struct HandleSource<F: AsRawDescriptor> {
    source: F,
    source_descriptor: Descriptor,
    blocking_pool: CancellableBlockingPool,
}

impl<F: AsRawDescriptor> HandleSource<F> {
    /// Create a new `HandleSource` from the given IO source.
    ///
    /// Each HandleSource uses its own thread pool, with one thread per source supplied. Since these
    /// threads are generally idle because they're waiting on blocking IO, so the cost is minimal.
    /// Long term, we may migrate away from this approach toward IOCP or overlapped IO.
    ///
    /// WARNING: `source` MUST be a unique file object (e.g. separate handles
    /// each created by CreateFile), and point at the same file on disk. This is because IO
    /// operations on the HandleSource are randomly distributed to each source.
    ///
    /// # Safety
    /// The caller must guarantee that `F`'s handle is compatible with the underlying functions
    /// exposed on `HandleSource`. The behavior when calling unsupported functions is not defined
    /// by this struct. Note that most winapis will fail with reasonable errors.
    pub fn new(source: F) -> Result<Self> {
        let source_descriptor = Descriptor(source.as_raw_descriptor());

        Ok(Self {
            source,
            source_descriptor,
            blocking_pool: CancellableBlockingPool::new(
                // WARNING: this is a safety requirement! Threads are 1:1 with sources.
                1,
                Duration::from_secs(10),
            ),
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
}

fn get_thread_file(descriptor: Descriptor) -> ManuallyDrop<File> {
    // SAFETY: trivially safe
    // Safe because all callers must exit *before* these handles will be closed (guaranteed by
    // HandleSource's Drop impl.).
    unsafe { ManuallyDrop::new(File::from_raw_descriptor(descriptor.0)) }
}

impl<F: AsRawDescriptor> HandleSource<F> {
    /// Reads from the iosource at `file_offset` and fill the given `vec`.
    pub async fn read_to_vec(
        &self,
        file_offset: Option<u64>,
        mut vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        let handles = HandleWrapper::new(self.source_descriptor);
        let descriptors = self.source_descriptor;

        Ok(self
            .blocking_pool
            .spawn(
                move || {
                    let mut file = get_thread_file(descriptors);
                    if let Some(file_offset) = file_offset {
                        file.seek(SeekFrom::Start(file_offset))
                            .map_err(Error::IoSeekError)?;
                    }
                    Ok((
                        file.read(vec.as_mut_slice()).map_err(Error::IoReadError)?,
                        vec,
                    ))
                },
                move || Err(handles.lock().cancel_sync_io(Error::OperationCancelled)),
            )
            .await?)
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    pub async fn read_to_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: impl IntoIterator<Item = MemRegion>,
    ) -> AsyncResult<usize> {
        let mem_offsets = mem_offsets.into_iter().collect();
        let handles = HandleWrapper::new(self.source_descriptor);
        let descriptors = self.source_descriptor;

        Ok(self
            .blocking_pool
            .spawn(
                move || {
                    let mut file = get_thread_file(descriptors);
                    let memory_slices = Self::get_slices(&mem, mem_offsets)?;

                    match file_offset {
                        Some(file_offset) => file
                            .read_vectored_at_volatile(memory_slices.as_slice(), file_offset)
                            .map_err(Error::IoReadError),
                        None => file
                            .read_vectored_volatile(memory_slices.as_slice())
                            .map_err(Error::IoReadError),
                    }
                },
                move || Err(handles.lock().cancel_sync_io(Error::OperationCancelled)),
            )
            .await?)
    }

    /// Wait for the handle of `self` to be readable.
    pub async fn wait_readable(&self) -> AsyncResult<()> {
        unimplemented!()
    }

    /// Reads a single u64 from the current offset.
    pub async fn read_u64(&self) -> AsyncResult<u64> {
        unimplemented!()
    }

    /// Writes from the given `vec` to the file starting at `file_offset`.
    pub async fn write_from_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        let handles = HandleWrapper::new(self.source_descriptor);
        let descriptors = self.source_descriptor;

        Ok(self
            .blocking_pool
            .spawn(
                move || {
                    let mut file = get_thread_file(descriptors);
                    if let Some(file_offset) = file_offset {
                        file.seek(SeekFrom::Start(file_offset))
                            .map_err(Error::IoSeekError)?;
                    }
                    Ok((
                        file.write(vec.as_slice()).map_err(Error::IoWriteError)?,
                        vec,
                    ))
                },
                move || Err(handles.lock().cancel_sync_io(Error::OperationCancelled)),
            )
            .await?)
    }

    /// Writes from the given `mem` from the given offsets to the file starting at `file_offset`.
    pub async fn write_from_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: impl IntoIterator<Item = MemRegion>,
    ) -> AsyncResult<usize> {
        let mem_offsets = mem_offsets.into_iter().collect();
        let handles = HandleWrapper::new(self.source_descriptor);
        let descriptors = self.source_descriptor;

        Ok(self
            .blocking_pool
            .spawn(
                move || {
                    let mut file = get_thread_file(descriptors);
                    let memory_slices = Self::get_slices(&mem, mem_offsets)?;

                    match file_offset {
                        Some(file_offset) => file
                            .write_vectored_at_volatile(memory_slices.as_slice(), file_offset)
                            .map_err(Error::IoWriteError),
                        None => file
                            .write_vectored_volatile(memory_slices.as_slice())
                            .map_err(Error::IoWriteError),
                    }
                },
                move || Err(handles.lock().cancel_sync_io(Error::OperationCancelled)),
            )
            .await?)
    }

    /// Deallocates the given range of a file.
    pub async fn punch_hole(&self, file_offset: u64, len: u64) -> AsyncResult<()> {
        let handles = HandleWrapper::new(self.source_descriptor);
        let descriptors = self.source_descriptor;
        Ok(self
            .blocking_pool
            .spawn(
                move || {
                    let file = get_thread_file(descriptors);
                    file.punch_hole(file_offset, len)
                        .map_err(Error::IoPunchHoleError)?;
                    Ok(())
                },
                move || Err(handles.lock().cancel_sync_io(Error::OperationCancelled)),
            )
            .await?)
    }

    /// Fills the given range with zeroes.
    pub async fn write_zeroes_at(&self, file_offset: u64, len: u64) -> AsyncResult<()> {
        let handles = HandleWrapper::new(self.source_descriptor);
        let descriptors = self.source_descriptor;
        Ok(self
            .blocking_pool
            .spawn(
                move || {
                    let file = get_thread_file(descriptors);
                    // ZeroRange calls `punch_hole` which doesn't extend the File size if it needs
                    // to. Will fix if it becomes a problem.
                    file.write_zeroes_at(file_offset, len as usize)
                        .map_err(Error::IoWriteZeroesError)?;
                    Ok(())
                },
                move || Err(handles.lock().cancel_sync_io(Error::OperationCancelled)),
            )
            .await?)
    }

    /// Sync all completed write operations to the backing storage.
    pub async fn fsync(&self) -> AsyncResult<()> {
        let handles = HandleWrapper::new(self.source_descriptor);
        let descriptors = self.source_descriptor;

        Ok(self
            .blocking_pool
            .spawn(
                move || {
                    let mut file = get_thread_file(descriptors);
                    file.flush().map_err(Error::IoFlushError)
                },
                move || Err(handles.lock().cancel_sync_io(Error::OperationCancelled)),
            )
            .await?)
    }

    /// Sync all data of completed write operations to the backing storage. Currently, the
    /// implementation is equivalent to fsync.
    pub async fn fdatasync(&self) -> AsyncResult<()> {
        // TODO(b/282003931): Fall back to regular fsync.
        self.fsync().await
    }

    /// Yields the underlying IO source.
    pub fn into_source(self) -> F {
        self.source
    }

    /// Provides a mutable ref to the underlying IO source.
    pub fn as_source_mut(&mut self) -> &mut F {
        &mut self.source
    }

    /// Provides a ref to the underlying IO source.
    ///
    /// If sources are not interchangeable, behavior is undefined.
    pub fn as_source(&self) -> &F {
        &self.source
    }

    /// If sources are not interchangeable, behavior is undefined.
    pub async fn wait_for_handle(&self) -> AsyncResult<()> {
        base::sys::windows::async_wait_for_single_object(&self.source)
            .await
            .map_err(Error::HandleWaitFailed)?;
        Ok(())
    }
}

// NOTE: Prefer adding tests to io_source.rs if not backend specific.
#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::NamedTempFile;

    use super::super::HandleReactor;
    use super::*;
    use crate::common_executor::RawExecutor;
    use crate::ExecutorTrait;

    #[cfg_attr(all(target_os = "windows", target_env = "gnu"), ignore)]
    #[test]
    fn test_punch_holes() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all("abcdefghijk".as_bytes()).unwrap();
        temp_file.flush().unwrap();
        temp_file.seek(SeekFrom::Start(0)).unwrap();

        async fn punch_hole(handle_src: &HandleSource<File>) {
            let offset = 1;
            let len = 3;
            handle_src.punch_hole(offset, len).await.unwrap();
        }

        let ex = RawExecutor::<HandleReactor>::new().unwrap();
        let f = fs::OpenOptions::new()
            .write(true)
            .open(temp_file.path())
            .unwrap();
        let handle_src = HandleSource::new(f).unwrap();
        ex.run_until(punch_hole(&handle_src)).unwrap();

        let mut buf = vec![0; 11];
        temp_file.read_exact(&mut buf).unwrap();
        assert_eq!(
            std::str::from_utf8(buf.as_slice()).unwrap(),
            "a\0\0\0efghijk"
        );
    }

    /// Test should fail because punch hole should not be allowed to allocate more memory
    #[cfg_attr(all(target_os = "windows", target_env = "gnu"), ignore)]
    #[test]
    fn test_punch_holes_fail_out_of_bounds() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all("abcdefghijk".as_bytes()).unwrap();
        temp_file.flush().unwrap();
        temp_file.seek(SeekFrom::Start(0)).unwrap();

        async fn punch_hole(handle_src: &HandleSource<File>) {
            let offset = 9;
            let len = 4;
            handle_src.punch_hole(offset, len).await.unwrap();
        }

        let ex = RawExecutor::<HandleReactor>::new().unwrap();
        let f = fs::OpenOptions::new()
            .write(true)
            .open(temp_file.path())
            .unwrap();
        let handle_src = HandleSource::new(f).unwrap();
        ex.run_until(punch_hole(&handle_src)).unwrap();

        let mut buf = vec![0; 13];
        assert!(temp_file.read_exact(&mut buf).is_err());
    }

    // TODO(b/194338842): "ZeroRange" is supposed to allocate more memory if it goes out of the
    // bounds of the file. Determine if we need to support this, since Windows doesn't do this yet.
    // #[test]
    // fn test_write_zeroes() {
    //     let mut temp_file = NamedTempFile::new().unwrap();
    //     temp_file.write("abcdefghijk".as_bytes()).unwrap();
    //     temp_file.flush().unwrap();
    //     temp_file.seek(SeekFrom::Start(0)).unwrap();

    //     async fn punch_hole(handle_src: &HandleSource<File>) {
    //         let offset = 9;
    //         let len = 4;
    //         handle_src
    //             .fallocate(offset, len, AllocateMode::ZeroRange)
    //             .await
    //             .unwrap();
    //     }

    //     let ex = RawExecutor::<HandleReactor>::new();
    //     let f = fs::OpenOptions::new()
    //         .write(true)
    //         .open(temp_file.path())
    //         .unwrap();
    //     let handle_src = HandleSource::new(f).unwrap();
    //     ex.run_until(punch_hole(&handle_src)).unwrap();

    //     let mut buf = vec![0; 13];
    //     temp_file.read_exact(&mut buf).unwrap();
    //     assert_eq!(
    //         std::str::from_utf8(buf.as_slice()).unwrap(),
    //         "abcdefghi\0\0\0\0"
    //     );
    // }
}
