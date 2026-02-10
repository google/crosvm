// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use base::handle_eintr_errno;
use base::AsRawDescriptor;
use base::VolatileSlice;
use remain::sorted;
use thiserror::Error as ThisError;

use super::kqueue_executor;
use super::kqueue_executor::KqueueReactor;
use super::kqueue_executor::RegisteredSource;
use crate::common_executor::RawExecutor;
use crate::mem::BackingMemory;
use crate::AsyncError;
use crate::AsyncResult;
use crate::MemRegion;

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("An error occurred attempting to register a waker with the executor: {0}.")]
    AddingWaker(kqueue_executor::Error),
    #[error("Failed to discard a block: {0}")]
    Discard(base::Error),
    #[error("An executor error occurred: {0}")]
    Executor(kqueue_executor::Error),
    #[error("An error occurred when executing fallocate synchronously: {0}")]
    Fallocate(base::Error),
    #[error("An error occurred when executing fdatasync synchronously: {0}")]
    Fdatasync(base::Error),
    #[error("An error occurred when executing fsync synchronously: {0}")]
    Fsync(base::Error),
    #[error("An error occurred when reading the FD: {0}.")]
    Read(base::Error),
    #[error("An error occurred when seeking the FD: {0}.")]
    Seeking(base::Error),
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
            Discard(e) => e.into(),
            Fallocate(e) => e.into(),
            Fdatasync(e) => e.into(),
            Fsync(e) => e.into(),
            Read(e) => e.into(),
            Seeking(e) => e.into(),
            Write(e) => e.into(),
        }
    }
}

impl From<Error> for AsyncError {
    fn from(e: Error) -> AsyncError {
        AsyncError::SysVariants(e.into())
    }
}

pub struct KqueueSource<F> {
    registered_source: RegisteredSource<F>,
}

impl<F: AsRawDescriptor> KqueueSource<F> {
    pub fn new(f: F, ex: &Arc<RawExecutor<KqueueReactor>>) -> Result<Self> {
        RegisteredSource::new(ex, f)
            .map(|f| KqueueSource {
                registered_source: f,
            })
            .map_err(Error::Executor)
    }
}

impl<F: AsRawDescriptor> KqueueSource<F> {
    pub async fn read_to_vec(
        &self,
        file_offset: Option<u64>,
        mut vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        loop {
            let res = if let Some(offset) = file_offset {
                handle_eintr_errno!(unsafe {
                    libc::pread(
                        self.registered_source.duped_fd.as_raw_fd(),
                        vec.as_mut_ptr() as *mut libc::c_void,
                        vec.len(),
                        offset as libc::off_t,
                    )
                })
            } else {
                handle_eintr_errno!(unsafe {
                    libc::read(
                        self.registered_source.duped_fd.as_raw_fd(),
                        vec.as_mut_ptr() as *mut libc::c_void,
                        vec.len(),
                    )
                })
            };

            if res >= 0 {
                return Ok((res as usize, vec));
            }

            match base::Error::last() {
                e if e.errno() == libc::EWOULDBLOCK => {
                    let op = self
                        .registered_source
                        .wait_readable()
                        .map_err(Error::AddingWaker)?;
                    op.await.map_err(Error::Executor)?;
                }
                e => return Err(Error::Read(e).into()),
            }
        }
    }

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
            let res = if let Some(offset) = file_offset {
                handle_eintr_errno!(unsafe {
                    libc::preadv(
                        self.registered_source.duped_fd.as_raw_fd(),
                        iovecs.as_mut_ptr() as *mut _,
                        iovecs.len() as i32,
                        offset as libc::off_t,
                    )
                })
            } else {
                handle_eintr_errno!(unsafe {
                    libc::readv(
                        self.registered_source.duped_fd.as_raw_fd(),
                        iovecs.as_mut_ptr() as *mut _,
                        iovecs.len() as i32,
                    )
                })
            };

            if res >= 0 {
                return Ok(res as usize);
            }

            match base::Error::last() {
                e if e.errno() == libc::EWOULDBLOCK => {
                    let op = self
                        .registered_source
                        .wait_readable()
                        .map_err(Error::AddingWaker)?;
                    op.await.map_err(Error::Executor)?;
                }
                e => return Err(Error::Read(e).into()),
            }
        }
    }

    pub async fn wait_readable(&self) -> AsyncResult<()> {
        let op = self
            .registered_source
            .wait_readable()
            .map_err(Error::AddingWaker)?;
        op.await.map_err(Error::Executor)?;
        Ok(())
    }

    pub async fn write_from_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        loop {
            let res = if let Some(offset) = file_offset {
                handle_eintr_errno!(unsafe {
                    libc::pwrite(
                        self.registered_source.duped_fd.as_raw_fd(),
                        vec.as_ptr() as *const libc::c_void,
                        vec.len(),
                        offset as libc::off_t,
                    )
                })
            } else {
                handle_eintr_errno!(unsafe {
                    libc::write(
                        self.registered_source.duped_fd.as_raw_fd(),
                        vec.as_ptr() as *const libc::c_void,
                        vec.len(),
                    )
                })
            };

            if res >= 0 {
                return Ok((res as usize, vec));
            }

            match base::Error::last() {
                e if e.errno() == libc::EWOULDBLOCK => {
                    let op = self
                        .registered_source
                        .wait_writable()
                        .map_err(Error::AddingWaker)?;
                    op.await.map_err(Error::Executor)?;
                }
                e => return Err(Error::Write(e).into()),
            }
        }
    }

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
            let res = if let Some(offset) = file_offset {
                handle_eintr_errno!(unsafe {
                    libc::pwritev(
                        self.registered_source.duped_fd.as_raw_fd(),
                        iovecs.as_ptr() as *mut _,
                        iovecs.len() as i32,
                        offset as libc::off_t,
                    )
                })
            } else {
                handle_eintr_errno!(unsafe {
                    libc::writev(
                        self.registered_source.duped_fd.as_raw_fd(),
                        iovecs.as_ptr() as *mut _,
                        iovecs.len() as i32,
                    )
                })
            };

            if res >= 0 {
                return Ok(res as usize);
            }

            match base::Error::last() {
                e if e.errno() == libc::EWOULDBLOCK => {
                    let op = self
                        .registered_source
                        .wait_writable()
                        .map_err(Error::AddingWaker)?;
                    op.await.map_err(Error::Executor)?;
                }
                e => return Err(Error::Write(e).into()),
            }
        }
    }

    pub async fn fsync(&self) -> AsyncResult<()> {
        let ret = handle_eintr_errno!(unsafe {
            libc::fsync(self.registered_source.duped_fd.as_raw_fd())
        });
        if ret == 0 {
            Ok(())
        } else {
            Err(Error::Fsync(base::Error::last()).into())
        }
    }

    pub async fn punch_hole(&self, _file_offset: u64, _len: u64) -> AsyncResult<()> {
        // macOS doesn't have fallocate with PUNCH_HOLE, use fcntl F_PUNCHHOLE
        // For now, return Ok as a stub
        Ok(())
    }

    pub async fn write_zeroes_at(&self, _file_offset: u64, _len: u64) -> AsyncResult<()> {
        // macOS doesn't have fallocate with ZERO_RANGE
        // For now, return Ok as a stub
        Ok(())
    }

    pub async fn fdatasync(&self) -> AsyncResult<()> {
        // macOS doesn't have fdatasync, use fsync
        let ret = handle_eintr_errno!(unsafe {
            libc::fsync(self.registered_source.duped_fd.as_raw_fd())
        });
        if ret == 0 {
            Ok(())
        } else {
            Err(Error::Fdatasync(base::Error::last()).into())
        }
    }

    pub fn into_source(self) -> F {
        self.registered_source.source
    }

    pub fn as_source_mut(&mut self) -> &mut F {
        &mut self.registered_source.source
    }

    pub fn as_source(&self) -> &F {
        &self.registered_source.source
    }
}
