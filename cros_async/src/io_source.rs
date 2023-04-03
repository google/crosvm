// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::AsRawDescriptor;
use std::sync::Arc;

#[cfg(unix)]
use crate::sys::unix::PollSource;
#[cfg(unix)]
use crate::sys::unix::UringSource;
#[cfg(windows)]
use crate::sys::windows::HandleSource;
#[cfg(windows)]
use crate::sys::windows::OverlappedSource;
use crate::AsyncResult;
use crate::BackingMemory;
use crate::MemRegion;

/// Associates an IO object `F` with cros_async's runtime and exposes an API to perform async IO on
/// that object's descriptor.
pub enum IoSource<F: base::AsRawDescriptor> {
    #[cfg(unix)]
    Uring(UringSource<F>),
    #[cfg(unix)]
    Epoll(PollSource<F>),
    #[cfg(windows)]
    Handle(HandleSource<F>),
    #[cfg(windows)]
    Overlapped(OverlappedSource<F>),
}

pub enum AllocateMode {
    #[cfg(unix)]
    Allocate,
    PunchHole,
    ZeroRange,
}

// This assume we always want KEEP_SIZE
#[cfg(unix)]
impl From<AllocateMode> for u32 {
    fn from(value: AllocateMode) -> Self {
        match value {
            AllocateMode::Allocate => 0,
            AllocateMode::PunchHole => {
                (libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE) as u32
            }
            AllocateMode::ZeroRange => {
                (libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE) as u32
            }
        }
    }
}

/// Invoke a method on the underlying source type and await the result.
///
/// `await_on_inner(io_source, method, ...)` => `inner_source.method(...).await`
macro_rules! await_on_inner {
    ($x:ident, $method:ident $(, $args:expr)*) => {
        match $x {
            #[cfg(unix)]
            IoSource::Uring(x) => UringSource::$method(x, $($args),*).await,
            #[cfg(unix)]
            IoSource::Epoll(x) => PollSource::$method(x, $($args),*).await,
            #[cfg(windows)]
            IoSource::Handle(x) => HandleSource::$method(x, $($args),*).await,
            #[cfg(windows)]
            IoSource::Overlapped(x) => OverlappedSource::$method(x, $($args),*).await,
        }
    };
}

/// Invoke a method on the underlying source type.
///
/// `on_inner(io_source, method, ...)` => `inner_source.method(...)`
macro_rules! on_inner {
    ($x:ident, $method:ident $(, $args:expr)*) => {
        match $x {
            #[cfg(unix)]
            IoSource::Uring(x) => UringSource::$method(x, $($args),*),
            #[cfg(unix)]
            IoSource::Epoll(x) => PollSource::$method(x, $($args),*),
            #[cfg(windows)]
            IoSource::Handle(x) => HandleSource::$method(x, $($args),*),
            #[cfg(windows)]
            IoSource::Overlapped(x) => OverlappedSource::$method(x, $($args),*),
        }
    };
}

impl<F: AsRawDescriptor> IoSource<F> {
    /// Reads at `file_offset` and fills the given `vec`.
    pub async fn read_to_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        await_on_inner!(self, read_to_vec, file_offset, vec)
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    pub async fn read_to_mem<'a>(
        &'a self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        await_on_inner!(self, read_to_mem, file_offset, mem, mem_offsets)
    }

    /// Reads a single u64 at the current offset.
    pub async fn read_u64(&self) -> AsyncResult<u64> {
        await_on_inner!(self, read_u64)
    }

    /// Waits for the object to be readable.
    pub async fn wait_readable(&self) -> AsyncResult<()> {
        await_on_inner!(self, wait_readable)
    }

    /// Writes from the given `vec` to the file starting at `file_offset`.
    pub async fn write_from_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        await_on_inner!(self, write_from_vec, file_offset, vec)
    }

    /// Writes from the given `mem` at the given offsets to the file starting at `file_offset`.
    pub async fn write_from_mem<'a>(
        &'a self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &'a [MemRegion],
    ) -> AsyncResult<usize> {
        await_on_inner!(self, write_from_mem, file_offset, mem, mem_offsets)
    }

    /// See `fallocate(2)`. Note this op is synchronous when using the Polled backend.
    pub async fn fallocate(
        &self,
        file_offset: u64,
        len: u64,
        mode: AllocateMode,
    ) -> AsyncResult<()> {
        await_on_inner!(self, fallocate, file_offset, len, mode)
    }

    /// Sync all completed write operations to the backing storage.
    pub async fn fsync(&self) -> AsyncResult<()> {
        await_on_inner!(self, fsync)
    }

    /// Yields the underlying IO source.
    pub fn into_source(self) -> F {
        on_inner!(self, into_source)
    }

    /// Provides a ref to the underlying IO source.
    pub fn as_source(&self) -> &F {
        on_inner!(self, as_source)
    }

    /// Provides a mutable ref to the underlying IO source.
    pub fn as_source_mut(&mut self) -> &mut F {
        on_inner!(self, as_source_mut)
    }

    /// Waits on a waitable handle.
    ///
    /// Needed for Windows currently, and subject to a potential future upstream.
    pub async fn wait_for_handle(&self) -> AsyncResult<u64> {
        await_on_inner!(self, wait_for_handle)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Waker;
    use std::thread;

    use base::Event;
    use base::EventExt;
    use sync::Mutex;

    use super::*;
    use crate::mem::VecIoWrapper;
    use crate::sys::unix::executor::async_poll_from;
    use crate::sys::unix::executor::async_uring_from;
    use crate::sys::unix::uring_executor::is_uring_stable;
    use crate::sys::unix::FdExecutor;
    use crate::sys::unix::PollSource;
    use crate::sys::unix::URingExecutor;
    use crate::sys::unix::UringSource;
    use crate::Executor;
    use crate::MemRegion;

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
        if !is_uring_stable() {
            return;
        }
        // Start a uring operation and then await the result from an FdExecutor.
        async fn go(source: UringSource<File>) {
            let v = vec![0xa4u8; 16];
            let (len, vec) = source.read_to_vec(None, v).await.unwrap();
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
        if !is_uring_stable() {
            return;
        }
        // Start a poll operation and then await the result from a URingExecutor.
        async fn go(source: PollSource<File>) {
            let v = vec![0x2cu8; 16];
            let (len, vec) = source.read_to_vec(None, v).await.unwrap();
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
        if !is_uring_stable() {
            return;
        }
        async fn go<F: AsRawDescriptor>(async_source: IoSource<F>) {
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = async_source.read_to_vec(None, v).await.unwrap();
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
        if !is_uring_stable() {
            return;
        }
        async fn go<F: AsRawDescriptor>(async_source: IoSource<F>) {
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = async_source.write_from_vec(None, v).await.unwrap();
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
        if !is_uring_stable() {
            return;
        }
        async fn go<F: AsRawDescriptor>(async_source: IoSource<F>) {
            let mem = Arc::new(VecIoWrapper::from(vec![0x55u8; 8192]));
            let ret = async_source
                .read_to_mem(
                    None,
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
        if !is_uring_stable() {
            return;
        }
        async fn go<F: AsRawDescriptor>(async_source: IoSource<F>) {
            let mem = Arc::new(VecIoWrapper::from(vec![0x55u8; 8192]));
            let ret = async_source
                .write_from_mem(
                    None,
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
        if !is_uring_stable() {
            return;
        }
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
        if !is_uring_stable() {
            return;
        }

        async fn go<F: AsRawDescriptor>(source: IoSource<F>) -> u64 {
            source.read_u64().await.unwrap()
        }

        let eventfd = Event::new().unwrap();
        eventfd.write_count(0x55).unwrap();
        let ex = URingExecutor::new().unwrap();
        let uring_source = async_uring_from(eventfd, &ex).unwrap();
        let val = ex.run_until(go(uring_source)).unwrap();
        assert_eq!(val, 0x55);

        let eventfd = Event::new().unwrap();
        eventfd.write_count(0xaa).unwrap();
        let poll_ex = FdExecutor::new().unwrap();
        let poll_source = async_poll_from(eventfd, &poll_ex).unwrap();
        let val = poll_ex.run_until(go(poll_source)).unwrap();
        assert_eq!(val, 0xaa);
    }

    #[test]
    fn fsync() {
        if !is_uring_stable() {
            return;
        }
        async fn go<F: AsRawDescriptor>(source: IoSource<F>) {
            let v = vec![0x55u8; 32];
            let v_ptr = v.as_ptr();
            let ret = source.write_from_vec(None, v).await.unwrap();
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
