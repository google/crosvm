// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use base::sys::FallocateMode;
use base::AsRawDescriptor;

use super::uring_executor::RegisteredSource;
use super::uring_executor::Result;
use super::uring_executor::UringReactor;
use crate::common_executor::RawExecutor;
use crate::mem::BackingMemory;
use crate::mem::MemRegion;
use crate::mem::VecIoWrapper;
use crate::AsyncResult;

/// `UringSource` wraps FD backed IO sources for use with io_uring. It is a thin wrapper around
/// registering an IO source with the uring that provides an `IoSource` implementation.
pub struct UringSource<F: AsRawDescriptor> {
    registered_source: RegisteredSource,
    source: F,
}

impl<F: AsRawDescriptor> UringSource<F> {
    /// Creates a new `UringSource` that wraps the given `io_source` object.
    pub fn new(io_source: F, ex: &Arc<RawExecutor<UringReactor>>) -> Result<UringSource<F>> {
        let r = ex.reactor.register_source(ex, &io_source)?;
        Ok(UringSource {
            registered_source: r,
            source: io_source,
        })
    }

    /// Reads from the iosource at `file_offset` and fill the given `vec`.
    pub async fn read_to_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        let buf = Arc::new(VecIoWrapper::from(vec));
        let op = self.registered_source.start_read_to_mem(
            file_offset,
            buf.clone(),
            [MemRegion {
                offset: 0,
                len: buf.len(),
            }],
        )?;
        let len = op.await?;
        let bytes = if let Ok(v) = Arc::try_unwrap(buf) {
            v.into()
        } else {
            panic!("too many refs on buf");
        };

        Ok((len as usize, bytes))
    }

    /// Wait for the FD of `self` to be readable.
    pub async fn wait_readable(&self) -> AsyncResult<()> {
        let op = self.registered_source.poll_fd_readable()?;
        op.await?;
        Ok(())
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    pub async fn read_to_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: impl IntoIterator<Item = MemRegion>,
    ) -> AsyncResult<usize> {
        let op = self
            .registered_source
            .start_read_to_mem(file_offset, mem, mem_offsets)?;
        let len = op.await?;
        Ok(len as usize)
    }

    /// Writes from the given `vec` to the file starting at `file_offset`.
    pub async fn write_from_vec(
        &self,
        file_offset: Option<u64>,
        vec: Vec<u8>,
    ) -> AsyncResult<(usize, Vec<u8>)> {
        let buf = Arc::new(VecIoWrapper::from(vec));
        let op = self.registered_source.start_write_from_mem(
            file_offset,
            buf.clone(),
            [MemRegion {
                offset: 0,
                len: buf.len(),
            }],
        )?;
        let len = op.await?;
        let bytes = if let Ok(v) = Arc::try_unwrap(buf) {
            v.into()
        } else {
            panic!("too many refs on buf");
        };

        Ok((len as usize, bytes))
    }

    /// Writes from the given `mem` from the given offsets to the file starting at `file_offset`.
    pub async fn write_from_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: impl IntoIterator<Item = MemRegion>,
    ) -> AsyncResult<usize> {
        let op = self
            .registered_source
            .start_write_from_mem(file_offset, mem, mem_offsets)?;
        let len = op.await?;
        Ok(len as usize)
    }

    /// Deallocates the given range of a file.
    pub async fn punch_hole(&self, file_offset: u64, len: u64) -> AsyncResult<()> {
        let op = self.registered_source.start_fallocate(
            file_offset,
            len,
            FallocateMode::PunchHole.into(),
        )?;
        let _ = op.await?;
        Ok(())
    }

    /// Fills the given range with zeroes.
    pub async fn write_zeroes_at(&self, file_offset: u64, len: u64) -> AsyncResult<()> {
        let op = self.registered_source.start_fallocate(
            file_offset,
            len,
            FallocateMode::ZeroRange.into(),
        )?;
        let _ = op.await?;
        Ok(())
    }

    /// Sync all completed write operations to the backing storage.
    pub async fn fsync(&self) -> AsyncResult<()> {
        let op = self.registered_source.start_fsync()?;
        let _ = op.await?;
        Ok(())
    }

    /// Sync all data of completed write operations to the backing storage. Currently, the
    /// implementation is equivalent to fsync.
    pub async fn fdatasync(&self) -> AsyncResult<()> {
        // Currently io_uring does not implement fdatasync. Fall back to fsync.
        // TODO(b/281609112): Implement real fdatasync with io_uring.
        self.fsync().await
    }

    /// Yields the underlying IO source.
    pub fn into_source(self) -> F {
        self.source
    }

    /// Provides a mutable ref to the underlying IO source.
    pub fn as_source(&self) -> &F {
        &self.source
    }

    /// Provides a ref to the underlying IO source.
    pub fn as_source_mut(&mut self) -> &mut F {
        &mut self.source
    }
}

impl<F: AsRawDescriptor> Deref for UringSource<F> {
    type Target = F;

    fn deref(&self) -> &Self::Target {
        &self.source
    }
}

impl<F: AsRawDescriptor> DerefMut for UringSource<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.source
    }
}

// NOTE: Prefer adding tests to io_source.rs if not backend specific.
#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Waker;

    use sync::Mutex;

    use super::super::uring_executor::is_uring_stable;
    use super::super::UringSource;
    use super::*;
    use crate::sys::linux::ExecutorKindSys;
    use crate::Executor;
    use crate::ExecutorTrait;
    use crate::IoSource;

    async fn read_u64<T: AsRawDescriptor>(source: &UringSource<T>) -> u64 {
        // Init a vec that translates to u64::max;
        let u64_mem = vec![0xffu8; std::mem::size_of::<u64>()];
        let (ret, u64_mem) = source.read_to_vec(None, u64_mem).await.unwrap();
        assert_eq!(ret, std::mem::size_of::<u64>());
        let mut val = 0u64.to_ne_bytes();
        val.copy_from_slice(&u64_mem);
        u64::from_ne_bytes(val)
    }

    #[test]
    fn event() {
        if !is_uring_stable() {
            return;
        }

        use base::Event;
        use base::EventExt;

        async fn write_event(ev: Event, wait: Event, ex: &Arc<RawExecutor<UringReactor>>) {
            let wait = UringSource::new(wait, ex).unwrap();
            ev.write_count(55).unwrap();
            read_u64(&wait).await;
            ev.write_count(66).unwrap();
            read_u64(&wait).await;
            ev.write_count(77).unwrap();
            read_u64(&wait).await;
        }

        async fn read_events(ev: Event, signal: Event, ex: &Arc<RawExecutor<UringReactor>>) {
            let source = UringSource::new(ev, ex).unwrap();
            assert_eq!(read_u64(&source).await, 55);
            signal.signal().unwrap();
            assert_eq!(read_u64(&source).await, 66);
            signal.signal().unwrap();
            assert_eq!(read_u64(&source).await, 77);
            signal.signal().unwrap();
        }

        let event = Event::new().unwrap();
        let signal_wait = Event::new().unwrap();
        let ex = RawExecutor::<UringReactor>::new().unwrap();
        let write_task = write_event(
            event.try_clone().unwrap(),
            signal_wait.try_clone().unwrap(),
            &ex,
        );
        let read_task = read_events(event, signal_wait, &ex);
        ex.run_until(futures::future::join(read_task, write_task))
            .unwrap();
    }

    #[test]
    fn pend_on_pipe() {
        if !is_uring_stable() {
            return;
        }

        use std::io::Write;

        use futures::future::Either;

        async fn do_test(ex: &Arc<RawExecutor<UringReactor>>) {
            let (read_source, mut w) = base::pipe().unwrap();
            let source = UringSource::new(read_source, ex).unwrap();
            let done = Box::pin(async { 5usize });
            let pending = Box::pin(read_u64(&source));
            match futures::future::select(pending, done).await {
                Either::Right((5, pending)) => {
                    // Write to the pipe so that the kernel will release the memory associated with
                    // the uring read operation.
                    w.write_all(&[0]).expect("failed to write to pipe");
                    ::std::mem::drop(pending);
                }
                _ => panic!("unexpected select result"),
            };
        }

        let ex = RawExecutor::<UringReactor>::new().unwrap();
        ex.run_until(do_test(&ex)).unwrap();
    }

    #[test]
    fn range_error() {
        if !is_uring_stable() {
            return;
        }

        async fn go(ex: &Arc<RawExecutor<UringReactor>>) {
            let f = File::open("/dev/zero").unwrap();
            let source = UringSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 64];
            let vw = Arc::new(VecIoWrapper::from(v));
            let ret = source
                .read_to_mem(
                    None,
                    Arc::<VecIoWrapper>::clone(&vw),
                    [MemRegion {
                        offset: 32,
                        len: 33,
                    }],
                )
                .await;
            assert!(ret.is_err());
        }

        let ex = RawExecutor::<UringReactor>::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn wait_read() {
        if !is_uring_stable() {
            return;
        }

        async fn go(ex: &Arc<RawExecutor<UringReactor>>) {
            let f = File::open("/dev/zero").unwrap();
            let source = UringSource::new(f, ex).unwrap();
            source.wait_readable().await.unwrap();
        }

        let ex = RawExecutor::<UringReactor>::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

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

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[test]
    fn await_uring_from_poll() {
        if !is_uring_stable() {
            return;
        }
        // Start a uring operation and then await the result from an FdExecutor.
        async fn go(source: IoSource<File>) {
            let v = vec![0xa4u8; 16];
            let (len, vec) = source.read_to_vec(None, v).await.unwrap();
            assert_eq!(len, 16);
            assert!(vec.iter().all(|&b| b == 0));
        }

        let state = Arc::new(Mutex::new(State {
            should_quit: false,
            waker: None,
        }));

        let uring_ex = Executor::with_executor_kind(ExecutorKindSys::Uring.into()).unwrap();
        let f = File::open("/dev/zero").unwrap();
        let source = uring_ex.async_from(f).unwrap();

        let quit = Quit {
            state: state.clone(),
        };
        let handle = std::thread::spawn(move || uring_ex.run_until(quit));

        let poll_ex = Executor::with_executor_kind(ExecutorKindSys::Fd.into()).unwrap();
        poll_ex.run_until(go(source)).unwrap();

        state.lock().wake();
        handle.join().unwrap().unwrap();
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[test]
    fn await_poll_from_uring() {
        if !is_uring_stable() {
            return;
        }
        // Start a poll operation and then await the result
        async fn go(source: IoSource<File>) {
            let v = vec![0x2cu8; 16];
            let (len, vec) = source.read_to_vec(None, v).await.unwrap();
            assert_eq!(len, 16);
            assert!(vec.iter().all(|&b| b == 0));
        }

        let state = Arc::new(Mutex::new(State {
            should_quit: false,
            waker: None,
        }));

        let poll_ex = Executor::with_executor_kind(ExecutorKindSys::Fd.into()).unwrap();
        let f = File::open("/dev/zero").unwrap();
        let source = poll_ex.async_from(f).unwrap();

        let quit = Quit {
            state: state.clone(),
        };
        let handle = std::thread::spawn(move || poll_ex.run_until(quit));

        let uring_ex = Executor::with_executor_kind(ExecutorKindSys::Uring.into()).unwrap();
        uring_ex.run_until(go(source)).unwrap();

        state.lock().wake();
        handle.join().unwrap().unwrap();
    }
}
