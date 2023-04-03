// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use base::AsRawDescriptor;
use data_model::VolatileSlice;
use remain::sorted;
use thiserror::Error as ThisError;

use super::fd_executor;
use super::fd_executor::FdExecutor;
use super::fd_executor::RegisteredSource;
use crate::mem::BackingMemory;
use crate::mem::MemRegion;
use crate::AllocateMode;
use crate::AsyncError;
use crate::AsyncResult;

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    /// An error occurred attempting to register a waker with the executor.
    #[error("An error occurred attempting to register a waker with the executor: {0}.")]
    AddingWaker(fd_executor::Error),
    /// An executor error occurred.
    #[error("An executor error occurred: {0}")]
    Executor(fd_executor::Error),
    /// An error occurred when executing fallocate synchronously.
    #[error("An error occurred when executing fallocate synchronously: {0}")]
    Fallocate(base::Error),
    /// An error occurred when executing fsync synchronously.
    #[error("An error occurred when executing fsync synchronously: {0}")]
    Fsync(base::Error),
    /// An error occurred when reading the FD.
    #[error("An error occurred when reading the FD: {0}.")]
    Read(base::Error),
    /// Can't seek file.
    #[error("An error occurred when seeking the FD: {0}.")]
    Seeking(base::Error),
    /// An error occurred when writing the FD.
    #[error("An error occurred when writing the FD: {0}.")]
    Write(base::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            AddingWaker(e) => e.into(),
            Executor(e) => e.into(),
            Fallocate(e) => e.into(),
            Fsync(e) => e.into(),
            Read(e) => e.into(),
            Seeking(e) => e.into(),
            Write(e) => e.into(),
        }
    }
}

/// Async wrapper for an IO source that uses the FD executor to drive async operations.
pub struct PollSource<F>(RegisteredSource<F>);

impl<F: AsRawDescriptor> PollSource<F> {
    /// Create a new `PollSource` from the given IO source.
    pub fn new(f: F, ex: &FdExecutor) -> Result<Self> {
        ex.register_source(f)
            .map(PollSource)
            .map_err(Error::Executor)
    }
}

impl<F: AsRawDescriptor> Deref for PollSource<F> {
    type Target = F;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<F: AsRawDescriptor> DerefMut for PollSource<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut()
    }
}

impl<F: AsRawDescriptor> PollSource<F> {
    /// Reads from the iosource at `file_offset` and fill the given `vec`.
    pub async fn read_to_vec(
        &self,
        file_offset: Option<u64>,
        mut vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        loop {
            // Safe because this will only modify `vec` and we check the return value.
            let res = if let Some(offset) = file_offset {
                unsafe {
                    libc::pread64(
                        self.as_raw_descriptor(),
                        vec.as_mut_ptr() as *mut libc::c_void,
                        vec.len(),
                        offset as libc::off64_t,
                    )
                }
            } else {
                unsafe {
                    libc::read(
                        self.as_raw_descriptor(),
                        vec.as_mut_ptr() as *mut libc::c_void,
                        vec.len(),
                    )
                }
            };

            if res >= 0 {
                return Ok((res as usize, vec));
            }

            match base::Error::last() {
                e if e.errno() == libc::EWOULDBLOCK => {
                    let op = self.0.wait_readable().map_err(Error::AddingWaker)?;
                    op.await.map_err(Error::Executor)?;
                }
                e => return Err(Error::Read(e).into()),
            }
        }
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    pub async fn read_to_mem<'a>(
        &'a self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        let mut iovecs = mem_offsets
            .iter()
            .filter_map(|&mem_vec| mem.get_volatile_slice(mem_vec).ok())
            .collect::<Vec<VolatileSlice>>();

        loop {
            // Safe because we trust the kernel not to write path the length given and the length is
            // guaranteed to be valid from the pointer by io_slice_mut.
            let res = if let Some(offset) = file_offset {
                unsafe {
                    libc::preadv64(
                        self.as_raw_descriptor(),
                        iovecs.as_mut_ptr() as *mut _,
                        iovecs.len() as i32,
                        offset as libc::off64_t,
                    )
                }
            } else {
                unsafe {
                    libc::readv(
                        self.as_raw_descriptor(),
                        iovecs.as_mut_ptr() as *mut _,
                        iovecs.len() as i32,
                    )
                }
            };

            if res >= 0 {
                return Ok(res as usize);
            }

            match base::Error::last() {
                e if e.errno() == libc::EWOULDBLOCK => {
                    let op = self.0.wait_readable().map_err(Error::AddingWaker)?;
                    op.await.map_err(Error::Executor)?;
                }
                e => return Err(Error::Read(e).into()),
            }
        }
    }

    /// Wait for the FD of `self` to be readable.
    pub async fn wait_readable(&self) -> AsyncResult<()> {
        let op = self.0.wait_readable().map_err(Error::AddingWaker)?;
        op.await.map_err(Error::Executor)?;
        Ok(())
    }

    pub async fn read_u64(&self) -> AsyncResult<u64> {
        let mut buf = 0u64.to_ne_bytes();
        loop {
            // Safe because this will only modify `buf` and we check the return value.
            let res = unsafe {
                libc::read(
                    self.as_raw_descriptor(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };

            if res >= 0 {
                return Ok(u64::from_ne_bytes(buf));
            }

            match base::Error::last() {
                e if e.errno() == libc::EWOULDBLOCK => {
                    let op = self.0.wait_readable().map_err(Error::AddingWaker)?;
                    op.await.map_err(Error::Executor)?;
                }
                e => return Err(Error::Read(e).into()),
            }
        }
    }

    /// Writes from the given `vec` to the file starting at `file_offset`.
    pub async fn write_from_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        loop {
            // Safe because this will not modify any memory and we check the return value.
            let res = if let Some(offset) = file_offset {
                unsafe {
                    libc::pwrite64(
                        self.as_raw_descriptor(),
                        vec.as_ptr() as *const libc::c_void,
                        vec.len(),
                        offset as libc::off64_t,
                    )
                }
            } else {
                unsafe {
                    libc::write(
                        self.as_raw_descriptor(),
                        vec.as_ptr() as *const libc::c_void,
                        vec.len(),
                    )
                }
            };

            if res >= 0 {
                return Ok((res as usize, vec));
            }

            match base::Error::last() {
                e if e.errno() == libc::EWOULDBLOCK => {
                    let op = self.0.wait_writable().map_err(Error::AddingWaker)?;
                    op.await.map_err(Error::Executor)?;
                }
                e => return Err(Error::Write(e).into()),
            }
        }
    }

    /// Writes from the given `mem` from the given offsets to the file starting at `file_offset`.
    pub async fn write_from_mem<'a>(
        &'a self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        let iovecs = mem_offsets
            .iter()
            .map(|&mem_vec| mem.get_volatile_slice(mem_vec))
            .filter_map(|r| r.ok())
            .collect::<Vec<VolatileSlice>>();

        loop {
            // Safe because we trust the kernel not to write path the length given and the length is
            // guaranteed to be valid from the pointer by io_slice_mut.
            let res = if let Some(offset) = file_offset {
                unsafe {
                    libc::pwritev64(
                        self.as_raw_descriptor(),
                        iovecs.as_ptr() as *mut _,
                        iovecs.len() as i32,
                        offset as libc::off64_t,
                    )
                }
            } else {
                unsafe {
                    libc::writev(
                        self.as_raw_descriptor(),
                        iovecs.as_ptr() as *mut _,
                        iovecs.len() as i32,
                    )
                }
            };

            if res >= 0 {
                return Ok(res as usize);
            }

            match base::Error::last() {
                e if e.errno() == libc::EWOULDBLOCK => {
                    let op = self.0.wait_writable().map_err(Error::AddingWaker)?;
                    op.await.map_err(Error::Executor)?;
                }
                e => return Err(Error::Write(e).into()),
            }
        }
    }

    /// See `fallocate(2)` for details.
    pub async fn fallocate(
        &self,
        file_offset: u64,
        len: u64,
        mode: AllocateMode,
    ) -> AsyncResult<()> {
        let mode_u32: u32 = mode.into();
        let ret = unsafe {
            libc::fallocate64(
                self.as_raw_descriptor(),
                mode_u32 as libc::c_int,
                file_offset as libc::off64_t,
                len as libc::off64_t,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(AsyncError::Poll(Error::Fallocate(base::Error::last())))
        }
    }

    /// Sync all completed write operations to the backing storage.
    pub async fn fsync(&self) -> AsyncResult<()> {
        let ret = unsafe { libc::fsync(self.as_raw_descriptor()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(AsyncError::Poll(Error::Fsync(base::Error::last())))
        }
    }

    /// Yields the underlying IO source.
    pub fn into_source(self) -> F {
        self.0.into_source()
    }

    /// Provides a mutable ref to the underlying IO source.
    pub fn as_source_mut(&mut self) -> &mut F {
        self
    }

    /// Provides a ref to the underlying IO source.
    pub fn as_source(&self) -> &F {
        self
    }

    pub async fn wait_for_handle(&self) -> AsyncResult<u64> {
        self.read_u64().await
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn readvec() {
        async fn go(ex: &FdExecutor) {
            let f = File::open("/dev/zero").unwrap();
            let async_source = PollSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = async_source.read_to_vec(None, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
            assert!(ret_v.iter().all(|&b| b == 0));
        }

        let ex = FdExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn writevec() {
        async fn go(ex: &FdExecutor) {
            let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
            let async_source = PollSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = async_source.write_from_vec(None, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
        }

        let ex = FdExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn fallocate() {
        async fn go(ex: &FdExecutor) {
            let dir = tempfile::TempDir::new().unwrap();
            let mut file_path = PathBuf::from(dir.path());
            file_path.push("test");

            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&file_path)
                .unwrap();
            let source = PollSource::new(f, ex).unwrap();
            source
                .fallocate(0, 4096, AllocateMode::Allocate)
                .await
                .unwrap();

            let meta_data = std::fs::metadata(&file_path).unwrap();
            assert_eq!(meta_data.len(), 4096);
        }

        let ex = FdExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn memory_leak() {
        // This test needs to run under ASAN to detect memory leaks.

        async fn owns_poll_source(source: PollSource<File>) {
            let _ = source.wait_readable().await;
        }

        let (rx, _tx) = base::pipe(true).unwrap();
        let ex = FdExecutor::new().unwrap();
        let source = PollSource::new(rx, &ex).unwrap();
        ex.spawn_local(owns_poll_source(source)).detach();

        // Drop `ex` without running. This would cause a memory leak if PollSource owned a strong
        // reference to the executor because it owns a reference to the future that owns PollSource
        // (via its Runnable). The strong reference prevents the drop impl from running, which would
        // otherwise poll the future and have it return with an error.
    }
}
