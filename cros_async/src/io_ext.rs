// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! # `IoSourceExt`
//!
//! User functions to asynchronously access files.
//! Using `IoSource` directly is inconvenient and requires dealing with state
//! machines for the backing uring, future libraries, etc. `IoSourceExt` instead
//! provides users with a future that can be `await`ed from async context.
//!
//! Each member of `IoSourceExt` returns a future for the supported operation. One or more
//! operation can be pending at a time.
//!
//! Operations can only access memory in a `Vec` or an implementor of `BackingMemory`. See the
//! `URingExecutor` documentation for an explaination of why.

use crate::poll_source::PollSource;
use crate::UringSource;
use async_trait::async_trait;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::rc::Rc;
use thiserror::Error as ThisError;

use crate::uring_mem::{BackingMemory, MemRegion};
use sys_util::net::UnixSeqpacket;

#[derive(ThisError, Debug)]
pub enum Error {
    /// An error with a polled(FD) source.
    #[error("An error with a poll source: {0}")]
    Poll(crate::poll_source::Error),
    /// An error with a uring source.
    #[error("An error with a uring source: {0}")]
    Uring(crate::uring_executor::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Ergonomic methods for async reads.
#[async_trait(?Send)]
pub trait ReadAsync {
    /// Reads from the iosource at `file_offset` and fill the given `vec`.
    async fn read_to_vec<'a>(&'a self, file_offset: u64, vec: Vec<u8>) -> Result<(usize, Vec<u8>)>;

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    async fn read_to_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &'a [MemRegion],
    ) -> Result<usize>;

    /// Wait for the FD of `self` to be readable.
    async fn wait_readable(&self) -> Result<()>;

    /// Reads a single u64 from the current offset.
    async fn read_u64(&self) -> Result<u64>;
}

/// Ergonomic methods for async writes.
#[async_trait(?Send)]
pub trait WriteAsync {
    /// Writes from the given `vec` to the file starting at `file_offset`.
    async fn write_from_vec<'a>(
        &'a self,
        file_offset: u64,
        vec: Vec<u8>,
    ) -> Result<(usize, Vec<u8>)>;

    /// Writes from the given `mem` from the given offsets to the file starting at `file_offset`.
    async fn write_from_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Rc<dyn BackingMemory>,
        mem_offsets: &'a [MemRegion],
    ) -> Result<usize>;

    /// See `fallocate(2)`. Note this op is synchronous when using the Polled backend.
    async fn fallocate(&self, file_offset: u64, len: u64, mode: u32) -> Result<()>;

    /// Sync all completed write operations to the backing storage.
    async fn fsync(&self) -> Result<()>;
}

/// Subtrait for general async IO.
#[async_trait(?Send)]
pub trait IoSourceExt<F>: ReadAsync + WriteAsync {
    /// Yields the underlying IO source.
    fn into_source(self: Box<Self>) -> F;

    /// Provides a mutable ref to the underlying IO source.
    fn as_source_mut(&mut self) -> &mut F;

    /// Provides a ref to the underlying IO source.
    fn as_source(&self) -> &F;
}

/// Marker trait signifying that the implementor is suitable for use with
/// cros_async. Examples of this include File, and sys_util::net::UnixSeqpacket.
///
/// (Note: it'd be really nice to implement a TryFrom for any implementors, and
/// remove our factory functions. Unfortunately
/// https://github.com/rust-lang/rust/issues/50133 makes that too painful.)
pub trait IntoAsync: AsRawFd {}

impl IntoAsync for File {}
impl IntoAsync for UnixSeqpacket {}
impl IntoAsync for &UnixSeqpacket {}

/// Creates a concrete `IoSourceExt` that uses uring if available or falls back to the fd_executor if not.
/// Note that on older kernels (pre 5.6) FDs such as event or timer FDs are unreliable when
/// having readvwritev performed through io_uring. To deal with EventFd or TimerFd, use
/// `IoSourceExt::read_u64`.
pub fn async_from<'a, F: IntoAsync + 'a>(f: F) -> Result<Box<dyn IoSourceExt<F> + 'a>> {
    if crate::uring_executor::use_uring() {
        async_uring_from(f)
    } else {
        async_poll_from(f)
    }
}

/// Creates a concrete `IoSourceExt` using Uring.
pub(crate) fn async_uring_from<'a, F: IntoAsync + 'a>(
    f: F,
) -> Result<Box<dyn IoSourceExt<F> + 'a>> {
    UringSource::new(f)
        .map(|u| Box::new(u) as Box<dyn IoSourceExt<F>>)
        .map_err(Error::Uring)
}

/// Creates a concrete `IoSourceExt` using the fd_executor.
pub(crate) fn async_poll_from<'a, F: IntoAsync + 'a>(f: F) -> Result<Box<dyn IoSourceExt<F> + 'a>> {
    PollSource::new(f)
        .map(|u| Box::new(u) as Box<dyn IoSourceExt<F>>)
        .map_err(Error::Poll)
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};

    use futures::pin_mut;

    use super::*;
    use crate::uring_mem::{MemRegion, VecIoWrapper};
    use crate::Executor;
    use std::os::unix::io::AsRawFd;
    use std::rc::Rc;

    #[test]
    fn readvec() {
        async fn go<F: AsRawFd + Unpin>(async_source: Box<dyn IoSourceExt<F>>) {
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = async_source.read_to_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
            assert!(ret_v.iter().all(|&b| b == 0));
        }

        let f = File::open("/dev/zero").unwrap();
        let uring_source = async_uring_from(f).unwrap();
        let fut = go(uring_source);
        pin_mut!(fut);
        crate::uring_executor::URingExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();

        let f = File::open("/dev/zero").unwrap();
        let poll_source = async_poll_from(f).unwrap();
        let fut = go(poll_source);
        pin_mut!(fut);
        crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
    }

    #[test]
    fn writevec() {
        async fn go<F: AsRawFd + Unpin>(async_source: Box<dyn IoSourceExt<F>>) {
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = async_source.write_from_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
        }

        let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let uring_source = async_uring_from(f).unwrap();
        let fut = go(uring_source);
        pin_mut!(fut);
        crate::uring_executor::URingExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();

        let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let poll_source = async_poll_from(f).unwrap();
        let fut = go(poll_source);
        pin_mut!(fut);
        crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
    }

    #[test]
    fn readmem() {
        async fn go<F: AsRawFd + Unpin>(async_source: Box<dyn IoSourceExt<F>>) {
            let mem = Rc::new(VecIoWrapper::from(vec![0x55u8; 8192]));
            let ret = async_source
                .read_to_mem(
                    0,
                    Rc::<VecIoWrapper>::clone(&mem),
                    &[
                        MemRegion { offset: 0, len: 32 },
                        MemRegion {
                            offset: 200,
                            len: 56,
                        },
                    ],
                )
                .await
                .unwrap();
            assert_eq!(ret, 32 + 56);
            let vec: Vec<u8> = match Rc::try_unwrap(mem) {
                Ok(v) => v.into(),
                Err(_) => panic!("Too many vec refs"),
            };
            assert!(vec.iter().take(32).all(|&b| b == 0));
            assert!(vec.iter().skip(32).take(168).all(|&b| b == 0x55));
            assert!(vec.iter().skip(200).take(56).all(|&b| b == 0));
            assert!(vec.iter().skip(256).all(|&b| b == 0x55));
        }

        let f = File::open("/dev/zero").unwrap();
        let uring_source = async_uring_from(f).unwrap();
        let fut = go(uring_source);
        pin_mut!(fut);
        crate::uring_executor::URingExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();

        let f = File::open("/dev/zero").unwrap();
        let poll_source = async_poll_from(f).unwrap();
        let fut = go(poll_source);
        pin_mut!(fut);
        crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
    }

    #[test]
    fn writemem() {
        async fn go<F: AsRawFd + Unpin>(async_source: Box<dyn IoSourceExt<F>>) {
            let mem = Rc::new(VecIoWrapper::from(vec![0x55u8; 8192]));
            let ret = async_source
                .write_from_mem(
                    0,
                    Rc::<VecIoWrapper>::clone(&mem),
                    &[MemRegion { offset: 0, len: 32 }],
                )
                .await
                .unwrap();
            assert_eq!(ret, 32);
        }

        let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let uring_source = async_uring_from(f).unwrap();
        let fut = go(uring_source);
        pin_mut!(fut);
        crate::uring_executor::URingExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();

        let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let poll_source = async_poll_from(f).unwrap();
        let fut = go(poll_source);
        pin_mut!(fut);
        crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
    }

    #[test]
    fn read_u64s() {
        async fn go(async_source: File) -> u64 {
            let source = async_from(async_source).unwrap();
            source.read_u64().await.unwrap()
        }

        let f = File::open("/dev/zero").unwrap();
        let fut = go(f);
        pin_mut!(fut);
        let val = crate::uring_executor::URingExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(val, 0);
    }

    #[test]
    fn read_eventfds() {
        use sys_util::EventFd;

        async fn go<F: AsRawFd + Unpin>(source: Box<dyn IoSourceExt<F>>) -> u64 {
            source.read_u64().await.unwrap()
        }

        let eventfd = EventFd::new().unwrap();
        eventfd.write(0x55).unwrap();
        let fut = go(async_uring_from(eventfd).unwrap());
        pin_mut!(fut);
        let val = crate::uring_executor::URingExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(val, 0x55);

        let eventfd = EventFd::new().unwrap();
        eventfd.write(0xaa).unwrap();
        let fut = go(async_poll_from(eventfd).unwrap());
        pin_mut!(fut);
        let val = crate::fd_executor::FdExecutor::new(crate::RunOne::new(fut))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(val, 0xaa);
    }

    #[test]
    fn fsync() {
        async fn go<F: AsRawFd + Unpin>(source: Box<dyn IoSourceExt<F>>) {
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = source.write_from_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
            source.fsync().await.unwrap();
        }

        let f = tempfile::tempfile().unwrap();
        let source = async_from(f).unwrap();

        let fut = go(source);
        pin_mut!(fut);
        crate::run_one(fut).unwrap();
    }
}
