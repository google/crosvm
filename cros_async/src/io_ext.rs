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

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use async_trait::async_trait;
use sys_util::net::UnixSeqpacket;
use thiserror::Error as ThisError;

use crate::{BackingMemory, MemRegion};

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

impl From<crate::uring_executor::Error> for Error {
    fn from(err: crate::uring_executor::Error) -> Self {
        Error::Uring(err)
    }
}

impl From<crate::poll_source::Error> for Error {
    fn from(err: crate::poll_source::Error) -> Self {
        Error::Poll(err)
    }
}

/// Ergonomic methods for async reads.
#[async_trait(?Send)]
pub trait ReadAsync {
    /// Reads from the iosource at `file_offset` and fill the given `vec`.
    async fn read_to_vec<'a>(&'a self, file_offset: u64, vec: Vec<u8>) -> Result<(usize, Vec<u8>)>;

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    async fn read_to_mem<'a>(
        &'a self,
        file_offset: u64,
        mem: Arc<dyn BackingMemory + Send + Sync>,
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
        mem: Arc<dyn BackingMemory + Send + Sync>,
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

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::future::Future;
    use std::os::unix::io::AsRawFd;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};
    use std::thread;

    use sync::Mutex;

    use super::*;
    use crate::executor::{async_poll_from, async_uring_from};
    use crate::mem::VecIoWrapper;
    use crate::{Executor, FdExecutor, MemRegion, PollSource, URingExecutor, UringSource};

    struct State {
        should_quit: bool,
        waker: Option<Waker>,
    }

    impl State {
        fn wake(&mut self) {
            self.should_quit = true;
            let waker = self.waker.take();

            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    struct Quit {
        state: Arc<Mutex<State>>,
    }

    impl Future for Quit {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
            let mut state = self.state.lock();
            if state.should_quit {
                return Poll::Ready(());
            }

            state.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    #[test]
    fn await_uring_from_poll() {
        // Start a uring operation and then await the result from an FdExecutor.
        async fn go(source: UringSource<File>) {
            let v = vec![0xa4u8; 16];
            let (len, vec) = source.read_to_vec(0, v).await.unwrap();
            assert_eq!(len, 16);
            assert!(vec.iter().all(|&b| b == 0));
        }

        let state = Arc::new(Mutex::new(State {
            should_quit: false,
            waker: None,
        }));

        let uring_ex = URingExecutor::new().unwrap();
        let f = File::open("/dev/zero").unwrap();
        let source = UringSource::new(f, &uring_ex).unwrap();

        let quit = Quit {
            state: state.clone(),
        };
        let handle = thread::spawn(move || uring_ex.run_until(quit));

        let poll_ex = FdExecutor::new().unwrap();
        poll_ex.run_until(go(source)).unwrap();

        state.lock().wake();
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn await_poll_from_uring() {
        // Start a poll operation and then await the result from a URingExecutor.
        async fn go(source: PollSource<File>) {
            let v = vec![0x2cu8; 16];
            let (len, vec) = source.read_to_vec(0, v).await.unwrap();
            assert_eq!(len, 16);
            assert!(vec.iter().all(|&b| b == 0));
        }

        let state = Arc::new(Mutex::new(State {
            should_quit: false,
            waker: None,
        }));

        let poll_ex = FdExecutor::new().unwrap();
        let f = File::open("/dev/zero").unwrap();
        let source = PollSource::new(f, &poll_ex).unwrap();

        let quit = Quit {
            state: state.clone(),
        };
        let handle = thread::spawn(move || poll_ex.run_until(quit));

        let uring_ex = URingExecutor::new().unwrap();
        uring_ex.run_until(go(source)).unwrap();

        state.lock().wake();
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn readvec() {
        async fn go<F: AsRawFd>(async_source: Box<dyn IoSourceExt<F>>) {
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = async_source.read_to_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
            assert!(ret_v.iter().all(|&b| b == 0));
        }

        let f = File::open("/dev/zero").unwrap();
        let uring_ex = URingExecutor::new().unwrap();
        let uring_source = async_uring_from(f, &uring_ex).unwrap();
        uring_ex.run_until(go(uring_source)).unwrap();

        let f = File::open("/dev/zero").unwrap();
        let poll_ex = FdExecutor::new().unwrap();
        let poll_source = async_poll_from(f, &poll_ex).unwrap();
        poll_ex.run_until(go(poll_source)).unwrap();
    }

    #[test]
    fn writevec() {
        async fn go<F: AsRawFd>(async_source: Box<dyn IoSourceExt<F>>) {
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = async_source.write_from_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
        }

        let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let ex = URingExecutor::new().unwrap();
        let uring_source = async_uring_from(f, &ex).unwrap();
        ex.run_until(go(uring_source)).unwrap();

        let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let poll_ex = FdExecutor::new().unwrap();
        let poll_source = async_poll_from(f, &poll_ex).unwrap();
        poll_ex.run_until(go(poll_source)).unwrap();
    }

    #[test]
    fn readmem() {
        async fn go<F: AsRawFd>(async_source: Box<dyn IoSourceExt<F>>) {
            let mem = Arc::new(VecIoWrapper::from(vec![0x55u8; 8192]));
            let ret = async_source
                .read_to_mem(
                    0,
                    Arc::<VecIoWrapper>::clone(&mem),
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
            let vec: Vec<u8> = match Arc::try_unwrap(mem) {
                Ok(v) => v.into(),
                Err(_) => panic!("Too many vec refs"),
            };
            assert!(vec.iter().take(32).all(|&b| b == 0));
            assert!(vec.iter().skip(32).take(168).all(|&b| b == 0x55));
            assert!(vec.iter().skip(200).take(56).all(|&b| b == 0));
            assert!(vec.iter().skip(256).all(|&b| b == 0x55));
        }

        let f = File::open("/dev/zero").unwrap();
        let ex = URingExecutor::new().unwrap();
        let uring_source = async_uring_from(f, &ex).unwrap();
        ex.run_until(go(uring_source)).unwrap();

        let f = File::open("/dev/zero").unwrap();
        let poll_ex = FdExecutor::new().unwrap();
        let poll_source = async_poll_from(f, &poll_ex).unwrap();
        poll_ex.run_until(go(poll_source)).unwrap();
    }

    #[test]
    fn writemem() {
        async fn go<F: AsRawFd>(async_source: Box<dyn IoSourceExt<F>>) {
            let mem = Arc::new(VecIoWrapper::from(vec![0x55u8; 8192]));
            let ret = async_source
                .write_from_mem(
                    0,
                    Arc::<VecIoWrapper>::clone(&mem),
                    &[MemRegion { offset: 0, len: 32 }],
                )
                .await
                .unwrap();
            assert_eq!(ret, 32);
        }

        let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let ex = URingExecutor::new().unwrap();
        let uring_source = async_uring_from(f, &ex).unwrap();
        ex.run_until(go(uring_source)).unwrap();

        let f = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let poll_ex = FdExecutor::new().unwrap();
        let poll_source = async_poll_from(f, &poll_ex).unwrap();
        poll_ex.run_until(go(poll_source)).unwrap();
    }

    #[test]
    fn read_u64s() {
        async fn go(async_source: File, ex: URingExecutor) -> u64 {
            let source = async_uring_from(async_source, &ex).unwrap();
            source.read_u64().await.unwrap()
        }

        let f = File::open("/dev/zero").unwrap();
        let ex = URingExecutor::new().unwrap();
        let val = ex.run_until(go(f, ex.clone())).unwrap();
        assert_eq!(val, 0);
    }

    #[test]
    fn read_eventfds() {
        use sys_util::EventFd;

        async fn go<F: AsRawFd>(source: Box<dyn IoSourceExt<F>>) -> u64 {
            source.read_u64().await.unwrap()
        }

        let eventfd = EventFd::new().unwrap();
        eventfd.write(0x55).unwrap();
        let ex = URingExecutor::new().unwrap();
        let uring_source = async_uring_from(eventfd, &ex).unwrap();
        let val = ex.run_until(go(uring_source)).unwrap();
        assert_eq!(val, 0x55);

        let eventfd = EventFd::new().unwrap();
        eventfd.write(0xaa).unwrap();
        let poll_ex = FdExecutor::new().unwrap();
        let poll_source = async_poll_from(eventfd, &poll_ex).unwrap();
        let val = poll_ex.run_until(go(poll_source)).unwrap();
        assert_eq!(val, 0xaa);
    }

    #[test]
    fn fsync() {
        async fn go<F: AsRawFd>(source: Box<dyn IoSourceExt<F>>) {
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = source.write_from_vec(0, v).await.unwrap();
            assert_eq!(ret.0, 32);
            let ret_v = ret.1;
            assert_eq!(v_ptr, ret_v.as_ptr());
            source.fsync().await.unwrap();
        }

        let f = tempfile::tempfile().unwrap();
        let ex = Executor::new().unwrap();
        let source = ex.async_from(f).unwrap();

        ex.run_until(go(source)).unwrap();
    }
}
