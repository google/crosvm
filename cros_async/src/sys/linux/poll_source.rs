// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use base::sys::fallocate;
use base::sys::FallocateMode;
use base::AsRawDescriptor;
use data_model::VolatileSlice;
use remain::sorted;
use thiserror::Error as ThisError;

use super::fd_executor;
use super::fd_executor::EpollReactor;
use super::fd_executor::RegisteredSource;
use crate::common_executor::RawExecutor;
use crate::mem::BackingMemory;
use crate::AsyncError;
use crate::AsyncResult;
use crate::MemRegion;

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
    /// An error occurred when executing fdatasync synchronously.
    #[error("An error occurred when executing fdatasync synchronously: {0}")]
    Fdatasync(base::Error),
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
            Fdatasync(e) => e.into(),
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
    pub fn new(f: F, ex: &Arc<RawExecutor<EpollReactor>>) -> Result<Self> {
        RegisteredSource::new(ex, f)
            .map(PollSource)
            .map_err(Error::Executor)
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
                        self.0.duped_fd.as_raw_fd(),
                        vec.as_mut_ptr() as *mut libc::c_void,
                        vec.len(),
                        offset as libc::off64_t,
                    )
                }
            } else {
                unsafe {
                    libc::read(
                        self.0.duped_fd.as_raw_fd(),
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
    pub async fn read_to_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: impl IntoIterator<Item = MemRegion>,
    ) -> AsyncResult<usize> {
        let mut iovecs = mem_offsets
            .into_iter()
            .filter_map(|mem_range| mem.get_volatile_slice(mem_range).ok())
            .collect::<Vec<VolatileSlice>>();

        loop {
            // Safe because we trust the kernel not to write path the length given and the length is
            // guaranteed to be valid from the pointer by io_slice_mut.
            let res = if let Some(offset) = file_offset {
                unsafe {
                    libc::preadv64(
                        self.0.duped_fd.as_raw_fd(),
                        iovecs.as_mut_ptr() as *mut _,
                        iovecs.len() as i32,
                        offset as libc::off64_t,
                    )
                }
            } else {
                unsafe {
                    libc::readv(
                        self.0.duped_fd.as_raw_fd(),
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
                        self.0.duped_fd.as_raw_fd(),
                        vec.as_ptr() as *const libc::c_void,
                        vec.len(),
                        offset as libc::off64_t,
                    )
                }
            } else {
                unsafe {
                    libc::write(
                        self.0.duped_fd.as_raw_fd(),
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
    pub async fn write_from_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: impl IntoIterator<Item = MemRegion>,
    ) -> AsyncResult<usize> {
        let iovecs = mem_offsets
            .into_iter()
            .map(|mem_range| mem.get_volatile_slice(mem_range))
            .filter_map(|r| r.ok())
            .collect::<Vec<VolatileSlice>>();

        loop {
            // Safe because we trust the kernel not to write path the length given and the length is
            // guaranteed to be valid from the pointer by io_slice_mut.
            let res = if let Some(offset) = file_offset {
                unsafe {
                    libc::pwritev64(
                        self.0.duped_fd.as_raw_fd(),
                        iovecs.as_ptr() as *mut _,
                        iovecs.len() as i32,
                        offset as libc::off64_t,
                    )
                }
            } else {
                unsafe {
                    libc::writev(
                        self.0.duped_fd.as_raw_fd(),
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

    /// Sync all completed write operations to the backing storage.
    pub async fn fsync(&self) -> AsyncResult<()> {
        let ret = unsafe { libc::fsync(self.0.duped_fd.as_raw_fd()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(AsyncError::Poll(Error::Fsync(base::Error::last())))
        }
    }

    /// punch_hole
    pub async fn punch_hole(&self, file_offset: u64, len: u64) -> AsyncResult<()> {
        fallocate(
            &self.0.duped_fd.as_raw_fd(),
            FallocateMode::PunchHole,
            file_offset,
            len,
        )
        .map_err(|e| AsyncError::Poll(Error::Fallocate(e)))
    }

    /// write_zeroes_at
    pub async fn write_zeroes_at(&self, file_offset: u64, len: u64) -> AsyncResult<()> {
        fallocate(
            &self.0.duped_fd.as_raw_fd(),
            FallocateMode::ZeroRange,
            file_offset,
            len,
        )
        .map_err(|e| AsyncError::Poll(Error::Fallocate(e)))
    }

    /// Sync all data of completed write operations to the backing storage, avoiding updating extra
    /// metadata.
    pub async fn fdatasync(&self) -> AsyncResult<()> {
        let ret = unsafe { libc::fdatasync(self.0.duped_fd.as_raw_fd()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(AsyncError::Poll(Error::Fdatasync(base::Error::last())))
        }
    }

    /// Yields the underlying IO source.
    pub fn into_source(self) -> F {
        self.0.source
    }

    /// Provides a mutable ref to the underlying IO source.
    pub fn as_source_mut(&mut self) -> &mut F {
        &mut self.0.source
    }

    /// Provides a ref to the underlying IO source.
    pub fn as_source(&self) -> &F {
        &self.0.source
    }
}

// NOTE: Prefer adding tests to io_source.rs if not backend specific.
#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;

    #[test]
    fn memory_leak() {
        // This test needs to run under ASAN to detect memory leaks.

        async fn owns_poll_source(source: PollSource<File>) {
            let _ = source.wait_readable().await;
        }

        let (rx, _tx) = base::pipe(true).unwrap();
        let ex = RawExecutor::<EpollReactor>::new().unwrap();
        let source = PollSource::new(rx, &ex).unwrap();
        ex.spawn_local(owns_poll_source(source)).detach();

        // Drop `ex` without running. This would cause a memory leak if PollSource owned a strong
        // reference to the executor because it owns a reference to the future that owns PollSource
        // (via its Runnable). The strong reference prevents the drop impl from running, which would
        // otherwise poll the future and have it return with an error.
    }
}
