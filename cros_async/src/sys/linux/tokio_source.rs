// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::sync::Arc;

use base::add_fd_flags;
use base::clone_descriptor;
use base::linux::fallocate;
use base::linux::FallocateMode;
use base::AsRawDescriptor;
use base::VolatileSlice;
use tokio::io::unix::AsyncFd;

use crate::mem::MemRegion;
use crate::AsyncError;
use crate::AsyncResult;
use crate::BackingMemory;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to copy the FD for the polling context: '{0}'")]
    DuplicatingFd(base::Error),
    #[error("Failed to punch hole in file: '{0}'.")]
    Fallocate(base::Error),
    #[error("Failed to fdatasync: '{0}'")]
    Fdatasync(io::Error),
    #[error("Failed to fsync: '{0}'")]
    Fsync(io::Error),
    #[error("Failed to join task: '{0}'")]
    Join(tokio::task::JoinError),
    #[error("Cannot wait on file descriptor")]
    NonWaitable,
    #[error("Failed to read: '{0}'")]
    Read(io::Error),
    #[error("Failed to set nonblocking: '{0}'")]
    SettingNonBlocking(base::Error),
    #[error("Tokio Async FD error: '{0}'")]
    TokioAsyncFd(io::Error),
    #[error("Failed to write: '{0}'")]
    Write(io::Error),
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            DuplicatingFd(e) => e.into(),
            Fallocate(e) => e.into(),
            Fdatasync(e) => e,
            Fsync(e) => e,
            Join(e) => io::Error::new(io::ErrorKind::Other, e),
            NonWaitable => io::Error::new(io::ErrorKind::Other, e),
            Read(e) => e,
            SettingNonBlocking(e) => e.into(),
            TokioAsyncFd(e) => e,
            Write(e) => e,
        }
    }
}

enum FdType {
    Async(AsyncFd<Arc<OwnedFd>>),
    Blocking(Arc<OwnedFd>),
}

impl AsRawFd for FdType {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            FdType::Async(async_fd) => async_fd.as_raw_fd(),
            FdType::Blocking(blocking) => blocking.as_raw_fd(),
        }
    }
}

impl From<Error> for AsyncError {
    fn from(e: Error) -> AsyncError {
        AsyncError::SysVariants(e.into())
    }
}

fn do_fdatasync(raw: Arc<OwnedFd>) -> io::Result<()> {
    let fd = raw.as_raw_fd();
    // SAFETY: we partially own `raw`
    match unsafe { libc::fdatasync(fd) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

fn do_fsync(raw: Arc<OwnedFd>) -> io::Result<()> {
    let fd = raw.as_raw_fd();
    // SAFETY: we partially own `raw`
    match unsafe { libc::fsync(fd) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

fn do_read_vectored(
    raw: Arc<OwnedFd>,
    file_offset: Option<u64>,
    io_vecs: &[VolatileSlice],
) -> io::Result<usize> {
    let ptr = io_vecs.as_ptr() as *const libc::iovec;
    let len = io_vecs.len() as i32;
    let fd = raw.as_raw_fd();
    let res = match file_offset {
        // SAFETY: we partially own `raw`, `io_vecs` is validated
        Some(off) => unsafe { libc::preadv64(fd, ptr, len, off as libc::off64_t) },
        // SAFETY: we partially own `raw`, `io_vecs` is validated
        None => unsafe { libc::readv(fd, ptr, len) },
    };
    match res {
        r if r >= 0 => Ok(res as usize),
        _ => Err(io::Error::last_os_error()),
    }
}
fn do_read(raw: Arc<OwnedFd>, file_offset: Option<u64>, buf: &mut [u8]) -> io::Result<usize> {
    let fd = raw.as_raw_fd();
    let ptr = buf.as_mut_ptr() as *mut libc::c_void;
    let res = match file_offset {
        // SAFETY: we partially own `raw`, `ptr` has space up to vec.len()
        Some(off) => unsafe { libc::pread64(fd, ptr, buf.len(), off as libc::off64_t) },
        // SAFETY: we partially own `raw`, `ptr` has space up to vec.len()
        None => unsafe { libc::read(fd, ptr, buf.len()) },
    };
    match res {
        r if r >= 0 => Ok(res as usize),
        _ => Err(io::Error::last_os_error()),
    }
}

fn do_write(raw: Arc<OwnedFd>, file_offset: Option<u64>, buf: &[u8]) -> io::Result<usize> {
    let fd = raw.as_raw_fd();
    let ptr = buf.as_ptr() as *const libc::c_void;
    let res = match file_offset {
        // SAFETY: we partially own `raw`, `ptr` has data up to vec.len()
        Some(off) => unsafe { libc::pwrite64(fd, ptr, buf.len(), off as libc::off64_t) },
        // SAFETY: we partially own `raw`, `ptr` has data up to vec.len()
        None => unsafe { libc::write(fd, ptr, buf.len()) },
    };
    match res {
        r if r >= 0 => Ok(res as usize),
        _ => Err(io::Error::last_os_error()),
    }
}

fn do_write_vectored(
    raw: Arc<OwnedFd>,
    file_offset: Option<u64>,
    io_vecs: &[VolatileSlice],
) -> io::Result<usize> {
    let ptr = io_vecs.as_ptr() as *const libc::iovec;
    let len = io_vecs.len() as i32;
    let fd = raw.as_raw_fd();
    let res = match file_offset {
        // SAFETY: we partially own `raw`, `io_vecs` is validated
        Some(off) => unsafe { libc::pwritev64(fd, ptr, len, off as libc::off64_t) },
        // SAFETY: we partially own `raw`, `io_vecs` is validated
        None => unsafe { libc::writev(fd, ptr, len) },
    };
    match res {
        r if r >= 0 => Ok(res as usize),
        _ => Err(io::Error::last_os_error()),
    }
}

pub struct TokioSource<T> {
    fd: FdType,
    inner: T,
    runtime: tokio::runtime::Handle,
}
impl<T: AsRawDescriptor> TokioSource<T> {
    pub fn new(inner: T, runtime: tokio::runtime::Handle) -> Result<TokioSource<T>, Error> {
        let _guard = runtime.enter(); // Required for AsyncFd
        let safe_fd = clone_descriptor(&inner).map_err(Error::DuplicatingFd)?;
        let fd_arc: Arc<OwnedFd> = Arc::new(safe_fd.into());
        let fd = match AsyncFd::new(fd_arc.clone()) {
            Ok(async_fd) => {
                add_fd_flags(async_fd.get_ref().as_raw_descriptor(), libc::O_NONBLOCK)
                    .map_err(Error::SettingNonBlocking)?;
                FdType::Async(async_fd)
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => FdType::Blocking(fd_arc),
            Err(e) => return Err(Error::TokioAsyncFd(e)),
        };
        Ok(TokioSource { fd, inner, runtime })
    }

    pub fn as_source(&self) -> &T {
        &self.inner
    }

    pub fn as_source_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    fn clone_fd(&self) -> Arc<OwnedFd> {
        match &self.fd {
            FdType::Async(async_fd) => async_fd.get_ref().clone(),
            FdType::Blocking(blocking) => blocking.clone(),
        }
    }

    pub async fn fdatasync(&self) -> AsyncResult<()> {
        let fd = self.clone_fd();
        Ok(self
            .runtime
            .spawn_blocking(move || do_fdatasync(fd))
            .await
            .map_err(Error::Join)?
            .map_err(Error::Fdatasync)?)
    }

    pub async fn fsync(&self) -> AsyncResult<()> {
        let fd = self.clone_fd();
        Ok(self
            .runtime
            .spawn_blocking(move || do_fsync(fd))
            .await
            .map_err(Error::Join)?
            .map_err(Error::Fsync)?)
    }

    pub fn into_source(self) -> T {
        self.inner
    }

    pub async fn read_to_vec(
        &self,
        file_offset: Option<u64>,
        mut vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        Ok(match &self.fd {
            FdType::Async(async_fd) => {
                let res = async_fd
                    .async_io(tokio::io::Interest::READABLE, |fd| {
                        do_read(fd.clone(), file_offset, &mut vec)
                    })
                    .await
                    .map_err(AsyncError::Io)?;
                (res, vec)
            }
            FdType::Blocking(blocking) => {
                let fd = blocking.clone();
                self.runtime
                    .spawn_blocking(move || {
                        let size = do_read(fd, file_offset, &mut vec)?;
                        Ok((size, vec))
                    })
                    .await
                    .map_err(Error::Join)?
                    .map_err(Error::Read)?
            }
        })
    }

    pub async fn read_to_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: impl IntoIterator<Item = MemRegion>,
    ) -> AsyncResult<usize> {
        let mem_offsets_vec: Vec<MemRegion> = mem_offsets.into_iter().collect();
        Ok(match &self.fd {
            FdType::Async(async_fd) => {
                let iovecs = mem_offsets_vec
                    .into_iter()
                    .filter_map(|mem_range| mem.get_volatile_slice(mem_range).ok())
                    .collect::<Vec<VolatileSlice>>();
                async_fd
                    .async_io(tokio::io::Interest::READABLE, |fd| {
                        do_read_vectored(fd.clone(), file_offset, &iovecs)
                    })
                    .await
                    .map_err(AsyncError::Io)?
            }
            FdType::Blocking(blocking) => {
                let fd = blocking.clone();
                self.runtime
                    .spawn_blocking(move || {
                        let iovecs = mem_offsets_vec
                            .into_iter()
                            .filter_map(|mem_range| mem.get_volatile_slice(mem_range).ok())
                            .collect::<Vec<VolatileSlice>>();
                        do_read_vectored(fd, file_offset, &iovecs)
                    })
                    .await
                    .map_err(Error::Join)?
                    .map_err(Error::Read)?
            }
        })
    }

    pub async fn punch_hole(&self, file_offset: u64, len: u64) -> AsyncResult<()> {
        let fd = self.clone_fd();
        Ok(self
            .runtime
            .spawn_blocking(move || fallocate(&*fd, FallocateMode::PunchHole, file_offset, len))
            .await
            .map_err(Error::Join)?
            .map_err(Error::Fallocate)?)
    }

    pub async fn wait_readable(&self) -> AsyncResult<()> {
        match &self.fd {
            FdType::Async(async_fd) => async_fd
                .readable()
                .await
                .map_err(crate::AsyncError::Io)?
                .retain_ready(),
            FdType::Blocking(_) => return Err(Error::NonWaitable.into()),
        }
        Ok(())
    }

    pub async fn write_from_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: impl IntoIterator<Item = MemRegion>,
    ) -> AsyncResult<usize> {
        let mem_offsets_vec: Vec<MemRegion> = mem_offsets.into_iter().collect();
        Ok(match &self.fd {
            FdType::Async(async_fd) => {
                let iovecs = mem_offsets_vec
                    .into_iter()
                    .filter_map(|mem_range| mem.get_volatile_slice(mem_range).ok())
                    .collect::<Vec<VolatileSlice>>();
                async_fd
                    .async_io(tokio::io::Interest::WRITABLE, |fd| {
                        do_write_vectored(fd.clone(), file_offset, &iovecs)
                    })
                    .await
                    .map_err(AsyncError::Io)?
            }
            FdType::Blocking(blocking) => {
                let fd = blocking.clone();
                self.runtime
                    .spawn_blocking(move || {
                        let iovecs = mem_offsets_vec
                            .into_iter()
                            .filter_map(|mem_range| mem.get_volatile_slice(mem_range).ok())
                            .collect::<Vec<VolatileSlice>>();
                        do_write_vectored(fd, file_offset, &iovecs)
                    })
                    .await
                    .map_err(Error::Join)?
                    .map_err(Error::Read)?
            }
        })
    }

    pub async fn write_from_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        Ok(match &self.fd {
            FdType::Async(async_fd) => {
                let res = async_fd
                    .async_io(tokio::io::Interest::WRITABLE, |fd| {
                        do_write(fd.clone(), file_offset, &vec)
                    })
                    .await
                    .map_err(AsyncError::Io)?;
                (res, vec)
            }
            FdType::Blocking(blocking) => {
                let fd = blocking.clone();
                self.runtime
                    .spawn_blocking(move || {
                        let size = do_write(fd.clone(), file_offset, &vec)?;
                        Ok((size, vec))
                    })
                    .await
                    .map_err(Error::Join)?
                    .map_err(Error::Read)?
            }
        })
    }

    pub async fn write_zeroes_at(&self, file_offset: u64, len: u64) -> AsyncResult<()> {
        let fd = self.clone_fd();
        Ok(self
            .runtime
            .spawn_blocking(move || fallocate(&*fd, FallocateMode::ZeroRange, file_offset, len))
            .await
            .map_err(Error::Join)?
            .map_err(Error::Fallocate)?)
    }
}
