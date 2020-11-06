// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A wrapped IO source that uses FdExecutor to drive asynchronous completion. Used from
//! `IoSourceExt::new` when uring isn't available in the kernel.

use async_trait::async_trait;
use std::borrow::Borrow;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use libc::O_NONBLOCK;

use crate::fd_executor::{self, add_read_waker, add_write_waker, PendingWaker};
use crate::uring_mem::{BackingMemory, BorrowedIoVec, MemRegion};
use crate::AsyncError;
use crate::AsyncResult;
use crate::{IoSourceExt, ReadAsync, WriteAsync};
use sys_util::{self, add_fd_flags};
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
    /// An error occurred attempting to register a waker with the executor.
    #[error("An error occurred attempting to register a waker with the executor: {0}.")]
    AddingWaker(fd_executor::Error),
    /// An error occurred when executing fallocate synchronously.
    #[error("An error occurred when executing fallocate synchronously: {0}")]
    Fallocate(sys_util::Error),
    /// An error occurred when executing fsync synchronously.
    #[error("An error occurred when executing fsync synchronously: {0}")]
    Fsync(sys_util::Error),
    /// An error occurred when reading the FD.
    ///
    #[error("An error occurred when reading the FD: {0}.")]
    Read(sys_util::Error),
    /// Can't seek file.
    #[error("An error occurred when seeking the FD: {0}.")]
    Seeking(sys_util::Error),
    /// An error occurred when setting the FD non-blocking.
    #[error("An error occurred setting the FD non-blocking: {0}.")]
    SettingNonBlocking(sys_util::Error),
    /// An error occurred when writing the FD.
    #[error("An error occurred when writing the FD: {0}.")]
    Write(sys_util::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Async wrapper for an IO source that uses the FD executor to drive async operations.
/// Used by `IoSourceExt::new` when uring isn't available.
pub struct PollSource<F: AsRawFd> {
    source: F,
}

impl<F: AsRawFd> PollSource<F> {
    /// Create a new `PollSource` from the given IO source.
    pub fn new(f: F) -> Result<Self> {
        let fd = f.as_raw_fd();
        add_fd_flags(fd, O_NONBLOCK).map_err(Error::SettingNonBlocking)?;
        Ok(Self { source: f })
    }

    /// Read a u64 from the current offset. Avoid seeking Fds that don't support `pread`.
    pub fn read_u64(&self) -> PollReadU64<'_, F> {
        PollReadU64 {
            reader: self,
            pending_waker: None,
        }
    }

    /// Return the inner source.
    pub fn into_source(self) -> F {
        self.source
    }
}

impl<F: AsRawFd> Deref for PollSource<F> {
    type Target = F;

    fn deref(&self) -> &Self::Target {
        &self.source
    }
}

#[async_trait(?Send)]
impl<F: AsRawFd> ReadAsync for PollSource<F> {
    /// Reads from the iosource at `file_offset` and fill the given `vec`.
    async fn read_to_vec<'a>(
        &'a self,
        file_offset: u64,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        let fut = PollReadVec {
            reader: self,
            file_offset,
            vec: Some(vec),
            pending_waker: None,
        };
        fut.await
            .map(|(n, vec)| (n as usize, vec))
            .map_err(AsyncError::Poll)
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    async fn read_to_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        let fut = PollReadMem {
            reader: self,
            file_offset,
            mem,
            mem_offsets,
            pending_waker: None,
        };
        fut.await.map(|n| n as usize).map_err(AsyncError::Poll)
    }

    /// Wait for the FD of `self` to be readable.
    async fn wait_readable(&self) -> AsyncResult<()> {
        let fut = PollWaitReadable {
            pollee: self,
            pending_waker: None,
        };
        fut.await.map_err(AsyncError::Poll)
    }

    async fn read_u64(&self) -> AsyncResult<u64> {
        PollSource::read_u64(self).await.map_err(AsyncError::Poll)
    }
}

#[async_trait(?Send)]
impl<F: AsRawFd> WriteAsync for PollSource<F> {
    /// Writes from the given `vec` to the file starting at `file_offset`.
    async fn write_from_vec<'a>(
        &'a self,
        file_offset: u64,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        let fut = PollWriteVec {
            writer: self,
            file_offset,
            vec: Some(vec),
            pending_waker: None,
        };
        fut.await
            .map(|(n, vec)| (n as usize, vec))
            .map_err(AsyncError::Poll)
    }

    /// Writes from the given `mem` from the given offsets to the file starting at `file_offset`.
    async fn write_from_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        let fut = PollWriteMem {
            writer: self,
            file_offset,
            mem,
            mem_offsets,
            pending_waker: None,
        };
        fut.await.map(|n| n as usize).map_err(AsyncError::Poll)
    }

    /// See `fallocate(2)` for details.
    async fn fallocate(&self, file_offset: u64, len: u64, mode: u32) -> AsyncResult<()> {
        let ret = unsafe {
            libc::fallocate64(
                self.source.as_raw_fd(),
                mode as libc::c_int,
                file_offset as libc::off64_t,
                len as libc::off64_t,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(AsyncError::Poll(Error::Fallocate(sys_util::Error::last())))
        }
    }

    /// Sync all completed write operations to the backing storage.
    async fn fsync(&self) -> AsyncResult<()> {
        let ret = unsafe { libc::fsync(self.source.as_raw_fd()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(AsyncError::Poll(Error::Fsync(sys_util::Error::last())))
        }
    }
}

#[async_trait(?Send)]
impl<F: AsRawFd> IoSourceExt<F> for PollSource<F> {
    /// Yields the underlying IO source.
    fn into_source(self: Box<Self>) -> F {
        self.source
    }

    /// Provides a mutable ref to the underlying IO source.
    fn as_source_mut(&mut self) -> &mut F {
        &mut self.source
    }

    /// Provides a ref to the underlying IO source.
    fn as_source(&self) -> &F {
        &self.source
    }
}

impl<F: AsRawFd> DerefMut for PollSource<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.source
    }
}

pub struct PollReadVec<'a, F: AsRawFd> {
    reader: &'a PollSource<F>,
    file_offset: u64,
    vec: Option<Vec<u8>>,
    pending_waker: Option<PendingWaker>,
}

impl<'a, F: AsRawFd> Future for PollReadVec<'a, F> {
    type Output = Result<(usize, Vec<u8>)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        fn do_read(fd: RawFd, file_offset: u64, buf: &mut [u8]) -> sys_util::Result<usize> {
            // Safe because we trust the kernel not to write past the length given and the length is
            // guaranteed to be valid from the pointer by the mut slice.
            let ret = unsafe {
                libc::pread(
                    fd,
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    file_offset as libc::c_long,
                )
            };
            match ret {
                n if n >= 0 => Ok(n as usize),
                _ => sys_util::errno_result(),
            }
        }

        let file_offset = self.file_offset;
        // unwrap is allowed because Futures can panic if polled again after returning Ready, and
        // Ready is the only way for vec to be None.
        let mut vec = self.vec.take().unwrap();
        let source = &self.reader.source;
        match do_read(source.as_raw_fd(), file_offset, &mut vec) {
            Ok(v) => Poll::Ready(Ok((v as usize, vec))),
            Err(err) => {
                if err.errno() == libc::EWOULDBLOCK {
                    if self.pending_waker.is_some() {
                        // Already waiting.
                        self.vec = Some(vec);
                        Poll::Pending
                    } else {
                        match add_read_waker(source.as_raw_fd(), cx.waker().clone()) {
                            Ok(pending_waker) => {
                                self.pending_waker = Some(pending_waker);
                                self.vec = Some(vec);
                                Poll::Pending
                            }
                            Err(e) => Poll::Ready(Err(Error::AddingWaker(e))),
                        }
                    }
                } else {
                    Poll::Ready(Err(Error::Read(err)))
                }
            }
        }
    }
}

pub struct PollReadU64<'a, F: AsRawFd> {
    reader: &'a PollSource<F>,
    pending_waker: Option<PendingWaker>,
}

impl<'a, F: AsRawFd> Future for PollReadU64<'a, F> {
    type Output = Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        fn do_read(fd: RawFd, buf: &mut [u8]) -> sys_util::Result<usize> {
            // Safe because we trust the kernel not to write past the length given and the length is
            // guaranteed to be valid from the pointer by the mut slice.
            let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            match ret {
                n if n >= 0 => Ok(n as usize),
                _ => sys_util::errno_result(),
            }
        }

        let source = &self.reader.source;
        let mut bytes = 0u64.to_ne_bytes();
        match do_read(source.as_raw_fd(), &mut bytes) {
            Ok(_) => {
                let val = u64::from_ne_bytes(bytes);
                Poll::Ready(Ok(val))
            }
            Err(err) => {
                if err.errno() == libc::EWOULDBLOCK {
                    if self.pending_waker.is_some() {
                        Poll::Pending
                    } else {
                        match add_read_waker(source.as_raw_fd(), cx.waker().clone()) {
                            Ok(pending_waker) => {
                                self.pending_waker = Some(pending_waker);
                                Poll::Pending
                            }
                            Err(e) => Poll::Ready(Err(Error::AddingWaker(e))),
                        }
                    }
                } else {
                    Poll::Ready(Err(Error::Read(err)))
                }
            }
        }
    }
}

// Hack to tide over until io_uring is available everywhere. `PollWaitReadable` emulates requesting
// that uring notify when an FD is readable. This can also be removed if msg_on_socket is
// re-implemented in a way that doesn't depend on triggering when an FD is ready.
pub struct PollWaitReadable<'a, F: AsRawFd> {
    pollee: &'a PollSource<F>,
    pending_waker: Option<PendingWaker>,
}

impl<'a, F: AsRawFd> Future for PollWaitReadable<'a, F> {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        fn do_poll(fd: RawFd) -> sys_util::Result<usize> {
            let poll_arg = libc::pollfd {
                fd,
                events: sys_util::WatchingEvents::empty().set_read().get_raw() as i16,
                revents: 0,
            };

            // Safe because poll doesn't touch memory.
            let ret = unsafe { libc::poll(&poll_arg as *const _ as *mut _, 1, 0) };
            match ret {
                n if n >= 0 => Ok(n as usize),
                _ => sys_util::errno_result(),
            }
        }

        let source = &self.pollee.source;
        match do_poll(source.as_raw_fd()) {
            Ok(1) => Poll::Ready(Ok(())),
            Ok(_) => {
                if self.pending_waker.is_some() {
                    Poll::Pending
                } else {
                    match add_read_waker(source.as_raw_fd(), cx.waker().clone()) {
                        Ok(pending_waker) => {
                            self.pending_waker = Some(pending_waker);
                            Poll::Pending
                        }
                        Err(e) => Poll::Ready(Err(Error::AddingWaker(e))),
                    }
                }
            }
            Err(err) => Poll::Ready(Err(Error::Read(err))),
        }
    }
}

pub struct PollWriteVec<'a, F: AsRawFd> {
    writer: &'a PollSource<F>,
    file_offset: u64,
    vec: Option<Vec<u8>>,
    pending_waker: Option<PendingWaker>,
}

impl<'a, F: AsRawFd> Future for PollWriteVec<'a, F> {
    type Output = Result<(usize, Vec<u8>)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        fn do_write(fd: RawFd, file_offset: u64, buf: &[u8]) -> sys_util::Result<usize> {
            // Safe because we trust the kernel not to write to the buffer, only read from it and
            // the length is guaranteed to be valid from the pointer by the mut slice.
            let ret = unsafe {
                libc::pwrite(
                    fd,
                    buf.as_ptr() as *const _,
                    buf.len(),
                    file_offset as libc::c_long,
                )
            };
            match ret {
                n if n >= 0 => Ok(n as usize),
                _ => sys_util::errno_result(),
            }
        }

        let file_offset = self.file_offset;
        // unwrap s allowed because Futures can panic if polled again after returning Ready, and
        // Ready is the only way for vec to be None.
        let vec = self.vec.take().unwrap();
        let source = &self.writer.source;
        match do_write(source.as_raw_fd(), file_offset, &vec) {
            Ok(v) => Poll::Ready(Ok((v as usize, vec))),
            Err(err) => {
                if err.errno() == libc::EWOULDBLOCK {
                    if self.pending_waker.is_some() {
                        // Already waiting.
                        self.vec = Some(vec);
                        Poll::Pending
                    } else {
                        match add_write_waker(source.as_raw_fd(), cx.waker().clone()) {
                            Ok(pending_waker) => {
                                self.pending_waker = Some(pending_waker);
                                self.vec = Some(vec);
                                Poll::Pending
                            }
                            Err(e) => Poll::Ready(Err(Error::AddingWaker(e))),
                        }
                    }
                } else {
                    Poll::Ready(Err(Error::Write(err)))
                }
            }
        }
    }
}

pub struct PollReadMem<'a, F: AsRawFd> {
    reader: &'a PollSource<F>,
    file_offset: u64,
    mem: Rc<dyn BackingMemory>,
    mem_offsets: &'a [MemRegion],
    pending_waker: Option<PendingWaker>,
}

impl<'a, F: AsRawFd> Future for PollReadMem<'a, F> {
    type Output = Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        fn do_readv(
            fd: RawFd,
            file_offset: u64,
            mem: &dyn BackingMemory,
            mem_offsets: &[MemRegion],
        ) -> sys_util::Result<usize> {
            let mut iovecs = mem_offsets
                .iter()
                .filter_map(|&mem_vec| mem.get_iovec(mem_vec).ok())
                .collect::<Vec<BorrowedIoVec>>();
            // Safe because we trust the kernel not to write path the length given and the length is
            // guaranteed to be valid from the pointer by io_slice_mut.
            let ret = unsafe {
                libc::preadv64(
                    fd,
                    iovecs.as_mut_ptr() as *mut _,
                    iovecs.len() as i32,
                    file_offset as libc::off64_t,
                )
            };
            match ret {
                n if n >= 0 => Ok(n as usize),
                _ => sys_util::errno_result(),
            }
        }

        let file_offset = self.file_offset;
        let source = &self.reader.source;
        match do_readv(
            source.as_raw_fd(),
            file_offset,
            self.mem.borrow(),
            self.mem_offsets,
        ) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(err) => {
                if err.errno() == libc::EWOULDBLOCK {
                    if self.pending_waker.is_some() {
                        Poll::Pending
                    } else {
                        match add_read_waker(source.as_raw_fd(), cx.waker().clone()) {
                            Ok(pending_waker) => {
                                self.pending_waker = Some(pending_waker);
                                Poll::Pending
                            }
                            Err(e) => Poll::Ready(Err(Error::AddingWaker(e))),
                        }
                    }
                } else {
                    Poll::Ready(Err(Error::Read(err)))
                }
            }
        }
    }
}

pub struct PollWriteMem<'a, F: AsRawFd> {
    writer: &'a PollSource<F>,
    file_offset: u64,
    mem: Rc<dyn BackingMemory>,
    mem_offsets: &'a [MemRegion],
    pending_waker: Option<PendingWaker>,
}

impl<'a, F: AsRawFd> Future for PollWriteMem<'a, F> {
    type Output = Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        fn do_writev(
            fd: RawFd,
            file_offset: u64,
            mem: &dyn BackingMemory,
            mem_offsets: &[MemRegion],
        ) -> sys_util::Result<usize> {
            let iovecs = mem_offsets
                .iter()
                .map(|&mem_vec| mem.get_iovec(mem_vec))
                .filter_map(|r| r.ok())
                .collect::<Vec<BorrowedIoVec>>();
            // Safe because we trust the kernel not to write path the length given and the length is
            // guaranteed to be valid from the pointer by io_slice_mut.
            let ret = unsafe {
                libc::pwritev64(
                    fd,
                    iovecs.as_ptr() as *mut _,
                    iovecs.len() as i32,
                    file_offset as libc::off64_t,
                )
            };
            match ret {
                n if n >= 0 => Ok(n as usize),
                _ => sys_util::errno_result(),
            }
        }

        let file_offset = self.file_offset;
        let source = &self.writer.source;
        match do_writev(
            source.as_raw_fd(),
            file_offset,
            self.mem.borrow(),
            self.mem_offsets,
        ) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(err) => {
                if err.errno() == libc::EWOULDBLOCK {
                    if self.pending_waker.is_some() {
                        Poll::Pending
                    } else {
                        match add_write_waker(source.as_raw_fd(), cx.waker().clone()) {
                            Ok(pending_waker) => {
                                self.pending_waker = Some(pending_waker);
                                Poll::Pending
                            }
                            Err(e) => Poll::Ready(Err(Error::AddingWaker(e))),
                        }
                    }
                } else {
                    Poll::Ready(Err(Error::Write(err)))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::path::PathBuf;

    use futures::pin_mut;

    use crate::executor::Executor;

    use super::*;

    #[test]
    fn readvec() {
        async fn go() {
            let f = File::open("/dev/zero").unwrap();
            let async_source = PollSource::new(f).unwrap();
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = async_source.read_to_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
            assert!(ret_v.iter().all(|&b| b == 0));
        }

        let fut = go();
        pin_mut!(fut);
        crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
    }

    #[test]
    fn writevec() {
        async fn go() {
            let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
            let async_source = PollSource::new(f).unwrap();
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = async_source.write_from_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
        }

        let fut = go();
        pin_mut!(fut);
        crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
    }

    #[test]
    fn fallocate() {
        async fn go() {
            let dir = tempfile::TempDir::new().unwrap();
            let mut file_path = PathBuf::from(dir.path());
            file_path.push("test");

            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&file_path)
                .unwrap();
            let source = PollSource::new(f).unwrap();
            source.fallocate(0, 4096, 0).await.unwrap();

            let meta_data = std::fs::metadata(&file_path).unwrap();
            assert_eq!(meta_data.len(), 4096);
        }

        let fut = go();
        pin_mut!(fut);
        crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
    }
}
