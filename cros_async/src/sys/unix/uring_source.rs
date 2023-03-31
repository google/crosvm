// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryInto;
use std::io;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use base::AsRawDescriptor;

use super::uring_executor::Error;
use super::uring_executor::RegisteredSource;
use super::uring_executor::Result;
use super::uring_executor::URingExecutor;
use crate::mem::BackingMemory;
use crate::mem::MemRegion;
use crate::mem::VecIoWrapper;
use crate::AllocateMode;
use crate::AsyncError;
use crate::AsyncResult;

/// `UringSource` wraps FD backed IO sources for use with io_uring. It is a thin wrapper around
/// registering an IO source with the uring that provides an `IoSource` implementation.
pub struct UringSource<F: AsRawDescriptor> {
    registered_source: RegisteredSource,
    source: F,
}

impl<F: AsRawDescriptor> UringSource<F> {
    /// Creates a new `UringSource` that wraps the given `io_source` object.
    pub fn new(io_source: F, ex: &URingExecutor) -> Result<UringSource<F>> {
        let r = ex.register_source(&io_source)?;
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
            &[MemRegion {
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

    /// Reads a single u64 (e.g. from an eventfd).
    pub async fn read_u64(&self) -> AsyncResult<u64> {
        // This doesn't just forward to read_to_vec to avoid an unnecessary extra allocation from
        // async-trait.
        let buf = Arc::new(VecIoWrapper::from(0u64.to_ne_bytes().to_vec()));
        let op = self.registered_source.start_read_to_mem(
            None,
            buf.clone(),
            &[MemRegion {
                offset: 0,
                len: buf.len(),
            }],
        )?;
        let len = op.await?;
        if len != buf.len() as u32 {
            Err(AsyncError::Uring(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("expected to read {} bytes, but read {}", buf.len(), len),
            ))))
        } else {
            let bytes: Vec<u8> = if let Ok(v) = Arc::try_unwrap(buf) {
                v.into()
            } else {
                panic!("too many refs on buf");
            };

            // Will never panic because bytes is of the appropriate size.
            Ok(u64::from_ne_bytes(bytes[..].try_into().unwrap()))
        }
    }

    /// Reads to the given `mem` at the given offsets from the file starting at `file_offset`.
    pub async fn read_to_mem(
        &self,
        file_offset: Option<u64>,
        mem: Arc<dyn BackingMemory + Send + Sync>,
        mem_offsets: &[MemRegion],
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
            &[MemRegion {
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
        mem_offsets: &[MemRegion],
    ) -> AsyncResult<usize> {
        let op = self
            .registered_source
            .start_write_from_mem(file_offset, mem, mem_offsets)?;
        let len = op.await?;
        Ok(len as usize)
    }

    /// See `fallocate(2)`. Note this op is synchronous when using the Polled backend.
    pub async fn fallocate(
        &self,
        file_offset: u64,
        len: u64,
        mode: AllocateMode,
    ) -> AsyncResult<()> {
        let op = self
            .registered_source
            .start_fallocate(file_offset, len, mode.into())?;
        let _ = op.await?;
        Ok(())
    }

    /// Sync all completed write operations to the backing storage.
    pub async fn fsync(&self) -> AsyncResult<()> {
        let op = self.registered_source.start_fsync()?;
        let _ = op.await?;
        Ok(())
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

    pub async fn wait_for_handle(&self) -> AsyncResult<u64> {
        self.read_u64().await
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
    use std::fs::OpenOptions;
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Waker;

    use sync::Mutex;
    use tempfile::tempfile;

    use super::super::uring_executor::is_uring_stable;
    use super::super::UringSource;
    use super::*;
    use crate::Executor;
    use crate::ExecutorKind;
    use crate::IoSource;

    #[test]
    fn readmulti() {
        if !is_uring_stable() {
            return;
        }

        async fn go(ex: &URingExecutor) {
            let f = File::open("/dev/zero").unwrap();
            let source = UringSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 32];
            let v2 = vec![0x55u8; 32];
            let (ret, ret2) = futures::future::join(
                source.read_to_vec(None, v),
                source.read_to_vec(Some(32), v2),
            )
            .await;

            assert!(ret.unwrap().1.iter().all(|&b| b == 0));
            assert!(ret2.unwrap().1.iter().all(|&b| b == 0));
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

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

        async fn write_event(ev: Event, wait: Event, ex: &URingExecutor) {
            let wait = UringSource::new(wait, ex).unwrap();
            ev.write_count(55).unwrap();
            read_u64(&wait).await;
            ev.write_count(66).unwrap();
            read_u64(&wait).await;
            ev.write_count(77).unwrap();
            read_u64(&wait).await;
        }

        async fn read_events(ev: Event, signal: Event, ex: &URingExecutor) {
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
        let ex = URingExecutor::new().unwrap();
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

        async fn do_test(ex: &URingExecutor) {
            let (read_source, mut w) = base::pipe(true).unwrap();
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

        let ex = URingExecutor::new().unwrap();
        ex.run_until(do_test(&ex)).unwrap();
    }

    #[test]
    fn range_error() {
        if !is_uring_stable() {
            return;
        }

        async fn go(ex: &URingExecutor) {
            let f = File::open("/dev/zero").unwrap();
            let source = UringSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 64];
            let vw = Arc::new(VecIoWrapper::from(v));
            let ret = source
                .read_to_mem(
                    None,
                    Arc::<VecIoWrapper>::clone(&vw),
                    &[MemRegion {
                        offset: 32,
                        len: 33,
                    }],
                )
                .await;
            assert!(ret.is_err());
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn fallocate() {
        if !is_uring_stable() {
            return;
        }

        async fn go(ex: &URingExecutor) {
            let dir = tempfile::TempDir::new().unwrap();
            let mut file_path = PathBuf::from(dir.path());
            file_path.push("test");

            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&file_path)
                .unwrap();
            let source = UringSource::new(f, ex).unwrap();
            if let Err(e) = source.fallocate(0, 4096, AllocateMode::Allocate).await {
                match e {
                    crate::io_ext::Error::Uring(super::super::uring_executor::Error::Io(
                        io_err,
                    )) => {
                        if io_err.kind() == std::io::ErrorKind::InvalidInput {
                            // Skip the test on kernels before fallocate support.
                            return;
                        }
                    }
                    _ => panic!("Unexpected uring error on fallocate: {}", e),
                }
            }

            let meta_data = std::fs::metadata(&file_path).unwrap();
            assert_eq!(meta_data.len(), 4096);
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn fsync() {
        if !is_uring_stable() {
            return;
        }

        async fn go(ex: &URingExecutor) {
            let f = tempfile::tempfile().unwrap();
            let source = UringSource::new(f, ex).unwrap();
            source.fsync().await.unwrap();
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn wait_read() {
        if !is_uring_stable() {
            return;
        }

        async fn go(ex: &URingExecutor) {
            let f = File::open("/dev/zero").unwrap();
            let source = UringSource::new(f, ex).unwrap();
            source.wait_readable().await.unwrap();
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn writemulti() {
        if !is_uring_stable() {
            return;
        }

        async fn go(ex: &URingExecutor) {
            let f = tempfile().unwrap();
            let source = UringSource::new(f, ex).unwrap();
            let v = vec![0x55u8; 32];
            let v2 = vec![0x55u8; 32];
            let (r, r2) = futures::future::join(
                source.write_from_vec(None, v),
                source.write_from_vec(Some(32), v2),
            )
            .await;
            assert_eq!(32, r.unwrap().0);
            assert_eq!(32, r2.unwrap().0);
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(go(&ex)).unwrap();
    }

    #[test]
    fn readwrite_current_file_position() {
        if !is_uring_stable() {
            return;
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(async {
            let mut f = tempfile().unwrap();
            let source = UringSource::new(f.try_clone().unwrap(), &ex).unwrap();
            assert_eq!(
                32,
                source
                    .write_from_vec(None, vec![0x55u8; 32])
                    .await
                    .unwrap()
                    .0
            );
            assert_eq!(
                32,
                source
                    .write_from_vec(None, vec![0xffu8; 32])
                    .await
                    .unwrap()
                    .0
            );
            use std::io::Seek;
            f.seek(std::io::SeekFrom::Start(0)).unwrap();
            assert_eq!(
                (32, vec![0x55u8; 32]),
                source.read_to_vec(None, vec![0u8; 32]).await.unwrap()
            );
            assert_eq!(
                (32, vec![0xffu8; 32]),
                source.read_to_vec(None, vec![0u8; 32]).await.unwrap()
            );
        })
        .unwrap();
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

    #[cfg(unix)]
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

        let uring_ex = Executor::with_executor_kind(ExecutorKind::Uring).unwrap();
        let f = File::open("/dev/zero").unwrap();
        let source = uring_ex.async_from(f).unwrap();

        let quit = Quit {
            state: state.clone(),
        };
        let handle = std::thread::spawn(move || uring_ex.run_until(quit));

        let poll_ex = Executor::with_executor_kind(ExecutorKind::Fd).unwrap();
        poll_ex.run_until(go(source)).unwrap();

        state.lock().wake();
        handle.join().unwrap().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn await_poll_from_uring() {
        if !is_uring_stable() {
            return;
        }
        // Start a poll operation and then await the result from a URingExecutor.
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

        let poll_ex = Executor::with_executor_kind(ExecutorKind::Fd).unwrap();
        let f = File::open("/dev/zero").unwrap();
        let source = poll_ex.async_from(f).unwrap();

        let quit = Quit {
            state: state.clone(),
        };
        let handle = std::thread::spawn(move || poll_ex.run_until(quit));

        let uring_ex = Executor::with_executor_kind(ExecutorKind::Uring).unwrap();
        uring_ex.run_until(go(source)).unwrap();

        state.lock().wake();
        handle.join().unwrap().unwrap();
    }
}
