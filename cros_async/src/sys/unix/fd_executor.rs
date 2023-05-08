// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The executor runs all given futures to completion. Futures register wakers associated with file
//! descriptors. The wakers will be called when the FD becomes readable or writable depending on
//! the situation.
//!
//! `FdExecutor` is meant to be used with the `futures-rs` crate that provides combinators and
//! utility functions to combine futures.

use std::fs::File;
use std::future::Future;
use std::io;
use std::mem;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Weak;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use async_task::Task;
use base::add_fd_flags;
use base::warn;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::Event;
use base::EventType;
use base::RawDescriptor;
use base::WaitContext;
use futures::task::noop_waker;
use pin_utils::pin_mut;
use remain::sorted;
use slab::Slab;
use sync::Mutex;
use thiserror::Error as ThisError;

use crate::queue::RunnableQueue;
use crate::waker::new_waker;
use crate::waker::WakerToken;
use crate::waker::WeakWake;
use crate::BlockingPool;
use crate::DetachedTasks;

#[sorted]
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Couldn't clear the wake eventfd")]
    CantClearWakeEvent(base::Error),
    /// Failed to clone the Event for waking the executor.
    #[error("Failed to clone the Event for waking the executor: {0}")]
    CloneEvent(base::Error),
    /// Failed to create the Event for waking the executor.
    #[error("Failed to create the Event for waking the executor: {0}")]
    CreateEvent(base::Error),
    /// Creating a context to wait on FDs failed.
    #[error("An error creating the fd waiting context: {0}")]
    CreatingContext(base::Error),
    /// Failed to copy the FD for the polling context.
    #[error("Failed to copy the FD for the polling context: {0}")]
    DuplicatingFd(base::Error),
    /// The Executor is gone.
    #[error("The FDExecutor is gone")]
    ExecutorGone,
    /// An error occurred when setting the FD non-blocking.
    #[error("An error occurred setting the FD non-blocking: {0}.")]
    SettingNonBlocking(base::Error),
    /// Failed to submit the waker to the polling context.
    #[error("An error adding to the Aio context: {0}")]
    SubmittingWaker(base::Error),
    /// A Waker was canceled, but the operation isn't running.
    #[error("Unknown waker")]
    UnknownWaker,
    /// WaitContext failure.
    #[error("WaitContext failure: {0}")]
    WaitContextError(base::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            CantClearWakeEvent(e) => e.into(),
            CloneEvent(e) => e.into(),
            CreateEvent(e) => e.into(),
            DuplicatingFd(e) => e.into(),
            ExecutorGone => io::Error::new(io::ErrorKind::Other, e),
            CreatingContext(e) => e.into(),
            SettingNonBlocking(e) => e.into(),
            SubmittingWaker(e) => e.into(),
            UnknownWaker => io::Error::new(io::ErrorKind::Other, e),
            WaitContextError(e) => e.into(),
        }
    }
}

// A poll operation that has been submitted and is potentially being waited on.
struct OpData {
    file: File,
    waker: Option<Waker>,
}

// The current status of a submitted operation.
enum OpStatus {
    Pending(OpData),
    Completed,
    // Special status that identifies the "wake up" eventfd, which is essentially always pending.
    WakeEvent,
}

// An IO source previously registered with an FdExecutor. Used to initiate asynchronous IO with the
// associated executor.
pub struct RegisteredSource<F> {
    source: F,
    ex: Weak<RawExecutor>,
}

impl<F: AsRawDescriptor> RegisteredSource<F> {
    // Start an asynchronous operation to wait for this source to become readable. The returned
    // future will not be ready until the source is readable.
    pub fn wait_readable(&self) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;

        let token = ex.add_operation(self.source.as_raw_descriptor(), EventType::Read)?;

        Ok(PendingOperation {
            token: Some(token),
            ex: self.ex.clone(),
        })
    }

    // Start an asynchronous operation to wait for this source to become writable. The returned
    // future will not be ready until the source is writable.
    pub fn wait_writable(&self) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;

        let token = ex.add_operation(self.source.as_raw_descriptor(), EventType::Write)?;

        Ok(PendingOperation {
            token: Some(token),
            ex: self.ex.clone(),
        })
    }
}

impl<F> RegisteredSource<F> {
    // Consume this RegisteredSource and return the inner IO source.
    pub fn into_source(self) -> F {
        self.source
    }
}

impl<F> AsRef<F> for RegisteredSource<F> {
    fn as_ref(&self) -> &F {
        &self.source
    }
}

impl<F> AsMut<F> for RegisteredSource<F> {
    fn as_mut(&mut self) -> &mut F {
        &mut self.source
    }
}

/// A token returned from `add_operation` that can be used to cancel the waker before it completes.
/// Used to manage getting the result from the underlying executor for a completed operation.
/// Dropping a `PendingOperation` will get the result from the executor.
pub struct PendingOperation {
    token: Option<WakerToken>,
    ex: Weak<RawExecutor>,
}

impl Future for PendingOperation {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let token = self
            .token
            .as_ref()
            .expect("PendingOperation polled after returning Poll::Ready");
        if let Some(ex) = self.ex.upgrade() {
            if ex.is_ready(token, cx) {
                self.token = None;
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(Error::ExecutorGone))
        }
    }
}

impl Drop for PendingOperation {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            if let Some(ex) = self.ex.upgrade() {
                let _ = ex.cancel_operation(token);
            }
        }
    }
}

// Indicates that the executor is either within or about to make a WaitContext::wait() call. When a
// waker sees this value, it will write to the wake Event, which will cause the
// WaitContext::wait() call to return.
const WAITING: i32 = 0x1d5b_c019u32 as i32;

// Indicates that the executor is processing any futures that are ready to run.
const PROCESSING: i32 = 0xd474_77bcu32 as i32;

// Indicates that one or more futures may be ready to make progress.
const WOKEN: i32 = 0x3e4d_3276u32 as i32;

struct RawExecutor {
    queue: RunnableQueue,
    poll_ctx: WaitContext<usize>,
    ops: Mutex<Slab<OpStatus>>,
    blocking_pool: BlockingPool,
    state: AtomicI32,
    detached_tasks: Mutex<DetachedTasks>,
    // This event is always present in `poll_ctx` with the special op status `WakeEvent`. It is
    // used by `RawExecutor::wake` to break other threads out of `poll_ctx.wait()` calls (usually
    // to notify them that `queue` has new work).
    wake_event: Event,
}

impl RawExecutor {
    fn new() -> Result<Self> {
        let raw = RawExecutor {
            queue: RunnableQueue::new(),
            poll_ctx: WaitContext::new().map_err(Error::CreatingContext)?,
            ops: Mutex::new(Slab::with_capacity(64)),
            blocking_pool: Default::default(),
            state: AtomicI32::new(PROCESSING),
            wake_event: {
                let wake_event = Event::new().map_err(Error::CreateEvent)?;
                add_fd_flags(wake_event.as_raw_descriptor(), libc::O_NONBLOCK)
                    .map_err(Error::SettingNonBlocking)?;
                wake_event
            },
            detached_tasks: Mutex::new(DetachedTasks::new()),
        };

        // Add the special "wake up" op.
        {
            let mut ops = raw.ops.lock();
            let entry = ops.vacant_entry();
            let next_token = entry.key();
            raw.poll_ctx
                .add_for_event(&raw.wake_event, EventType::Read, next_token)
                .map_err(Error::SubmittingWaker)?;
            entry.insert(OpStatus::WakeEvent);
        }

        Ok(raw)
    }

    fn add_operation(&self, fd: RawFd, event_type: EventType) -> Result<WakerToken> {
        let duped_fd = unsafe {
            // Safe because duplicating an FD doesn't affect memory safety, and the dup'd FD
            // will only be added to the poll loop.
            File::from_raw_fd(dup_fd(fd)?)
        };
        let mut ops = self.ops.lock();
        let entry = ops.vacant_entry();
        let next_token = entry.key();
        self.poll_ctx
            .add_for_event(&duped_fd, event_type, next_token)
            .map_err(Error::SubmittingWaker)?;
        entry.insert(OpStatus::Pending(OpData {
            file: duped_fd,
            waker: None,
        }));
        Ok(WakerToken(next_token))
    }

    fn wake(&self) {
        let oldstate = self.state.swap(WOKEN, Ordering::Release);
        if oldstate == WAITING {
            if let Err(e) = self.wake_event.signal() {
                warn!("Failed to notify executor that a future is ready: {}", e);
            }
        }
    }

    fn spawn<F>(self: &Arc<Self>, f: F) -> FdExecutorTaskHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let raw = Arc::downgrade(self);
        let schedule = move |runnable| {
            if let Some(r) = raw.upgrade() {
                r.queue.push_back(runnable);
                r.wake();
            }
        };
        let (runnable, task) = async_task::spawn(f, schedule);
        runnable.schedule();
        FdExecutorTaskHandle {
            task,
            raw: Arc::downgrade(self),
        }
    }

    fn spawn_local<F>(self: &Arc<Self>, f: F) -> FdExecutorTaskHandle<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let raw = Arc::downgrade(self);
        let schedule = move |runnable| {
            if let Some(r) = raw.upgrade() {
                r.queue.push_back(runnable);
                r.wake();
            }
        };
        let (runnable, task) = async_task::spawn_local(f, schedule);
        runnable.schedule();
        FdExecutorTaskHandle {
            task,
            raw: Arc::downgrade(self),
        }
    }

    fn spawn_blocking<F, R>(self: &Arc<Self>, f: F) -> FdExecutorTaskHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.spawn(self.blocking_pool.spawn(f))
    }

    fn run<F: Future>(&self, cx: &mut Context, done: F) -> Result<F::Output> {
        pin_mut!(done);

        loop {
            self.state.store(PROCESSING, Ordering::Release);
            for runnable in self.queue.iter() {
                runnable.run();
            }

            if let Ok(mut tasks) = self.detached_tasks.try_lock() {
                tasks.poll(cx);
            }

            if let Poll::Ready(val) = done.as_mut().poll(cx) {
                return Ok(val);
            }

            let oldstate = self.state.compare_exchange(
                PROCESSING,
                WAITING,
                Ordering::Acquire,
                Ordering::Acquire,
            );
            if let Err(oldstate) = oldstate {
                debug_assert_eq!(oldstate, WOKEN);
                // One or more futures have become runnable.
                continue;
            }

            let events = self.poll_ctx.wait().map_err(Error::WaitContextError)?;

            // Set the state back to PROCESSING to prevent any tasks woken up by the loop below from
            // writing to the eventfd.
            self.state.store(PROCESSING, Ordering::Release);
            for e in events.iter() {
                let token = e.token;
                let mut ops = self.ops.lock();

                // The op could have been canceled and removed by another thread so ignore it if it
                // doesn't exist.
                if let Some(op) = ops.get_mut(token) {
                    let (file, waker) = match mem::replace(op, OpStatus::Completed) {
                        OpStatus::Pending(OpData { file, waker }) => (file, waker),
                        OpStatus::Completed => panic!("poll operation completed more than once"),
                        OpStatus::WakeEvent => {
                            // NOTE: We set O_NONBLOCK, so there is no risk of this getting stuck.
                            match self.wake_event.wait() {
                                Ok(_) => {}
                                Err(e) if e.errno() == libc::EWOULDBLOCK => {}
                                Err(e) => return Err(Error::CantClearWakeEvent(e)),
                            }
                            continue;
                        }
                    };

                    mem::drop(ops);

                    self.poll_ctx
                        .delete(&file)
                        .map_err(Error::WaitContextError)?;

                    if let Some(waker) = waker {
                        waker.wake();
                    }
                }
            }
        }
    }

    fn is_ready(&self, token: &WakerToken, cx: &mut Context) -> bool {
        let mut ops = self.ops.lock();

        let op = ops
            .get_mut(token.0)
            .expect("`is_ready` called on unknown operation");
        match op {
            OpStatus::Pending(data) => {
                data.waker = Some(cx.waker().clone());
                false
            }
            OpStatus::Completed => {
                ops.remove(token.0);
                true
            }
            // unreachable because we never create a WakerToken for `wake_event`.
            OpStatus::WakeEvent => unreachable!(),
        }
    }

    // Remove the waker for the given token if it hasn't fired yet.
    fn cancel_operation(&self, token: WakerToken) -> Result<()> {
        match self.ops.lock().remove(token.0) {
            OpStatus::Pending(data) => self
                .poll_ctx
                .delete(&data.file)
                .map_err(Error::WaitContextError),
            OpStatus::Completed => Ok(()),
            // unreachable because we never create a WakerToken for `wake_event`.
            OpStatus::WakeEvent => unreachable!(),
        }
    }
}

impl AsRawDescriptors for RawExecutor {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        vec![
            self.poll_ctx.as_raw_descriptor(),
            self.wake_event.as_raw_descriptor(),
        ]
    }
}

impl WeakWake for RawExecutor {
    fn wake_by_ref(weak_self: &Weak<Self>) {
        if let Some(arc_self) = weak_self.upgrade() {
            RawExecutor::wake(&arc_self);
        }
    }
}

impl Drop for RawExecutor {
    fn drop(&mut self) {
        // At this point we have exclusive access to the `RawExecutor`, so no `Arc<RawExecutor>`
        // exists and all the `Weak<RawExecutor>` will fail to upgrade (i.e. no more IO can be
        // submitted).

        // Wake up any futures still waiting on poll operations as they are just going to get an
        // ExecutorGone error now.
        for op in self.ops.get_mut().drain() {
            match op {
                OpStatus::Pending(mut data) => {
                    if let Some(waker) = data.waker.take() {
                        waker.wake();
                    }

                    if let Err(e) = self.poll_ctx.delete(&data.file) {
                        warn!("Failed to remove file from EpollCtx: {}", e);
                    }
                }
                OpStatus::Completed => {}
                OpStatus::WakeEvent => {}
            }
        }

        // Now run the executor one more time to drive any remaining futures to completion.
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        if let Err(e) = self.run(&mut cx, async {}) {
            warn!("Failed to drive FdExecutor to completion: {}", e);
        }
    }
}

pub struct FdExecutorTaskHandle<R> {
    task: Task<R>,
    raw: Weak<RawExecutor>,
}

impl<R: Send + 'static> FdExecutorTaskHandle<R> {
    pub fn detach(self) {
        if let Some(raw) = self.raw.upgrade() {
            raw.detached_tasks.lock().push(self.task);
        }
    }
}

impl<R: 'static> Future for FdExecutorTaskHandle<R> {
    type Output = R;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> std::task::Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx)
    }
}

#[derive(Clone)]
pub struct FdExecutor {
    raw: Arc<RawExecutor>,
}

impl FdExecutor {
    pub fn new() -> Result<FdExecutor> {
        Ok(FdExecutor {
            raw: Arc::new(RawExecutor::new()?),
        })
    }

    pub fn spawn<F>(&self, f: F) -> FdExecutorTaskHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.raw.spawn(f)
    }

    pub fn spawn_local<F>(&self, f: F) -> FdExecutorTaskHandle<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        self.raw.spawn_local(f)
    }

    pub fn spawn_blocking<F, R>(&self, f: F) -> FdExecutorTaskHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.raw.spawn_blocking(f)
    }

    pub fn run_until<F: Future>(&self, f: F) -> Result<F::Output> {
        let waker = new_waker(Arc::downgrade(&self.raw));
        let mut ctx = Context::from_waker(&waker);

        self.raw.run(&mut ctx, f)
    }

    pub(crate) fn register_source<F: AsRawDescriptor>(&self, f: F) -> Result<RegisteredSource<F>> {
        add_fd_flags(f.as_raw_descriptor(), libc::O_NONBLOCK).map_err(Error::SettingNonBlocking)?;
        Ok(RegisteredSource {
            source: f,
            ex: Arc::downgrade(&self.raw),
        })
    }
}

impl AsRawDescriptors for FdExecutor {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        self.raw.as_raw_descriptors()
    }
}

// Used to `dup` the FDs passed to the executor so there is a guarantee they aren't closed while
// waiting in TLS to be added to the main polling context.
unsafe fn dup_fd(fd: RawFd) -> Result<RawFd> {
    let ret = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0);
    if ret < 0 {
        Err(Error::DuplicatingFd(base::Error::last()))
    } else {
        Ok(ret)
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::io::Read;
    use std::io::Write;
    use std::rc::Rc;

    use futures::future::Either;

    use super::*;

    #[test]
    fn test_it() {
        async fn do_test(ex: &FdExecutor) {
            let (r, _w) = base::pipe(true).unwrap();
            let done = Box::pin(async { 5usize });
            let source = ex.register_source(r).unwrap();
            let pending = source.wait_readable().unwrap();
            match futures::future::select(pending, done).await {
                Either::Right((5, pending)) => std::mem::drop(pending),
                _ => panic!("unexpected select result"),
            }
        }

        let ex = FdExecutor::new().unwrap();
        ex.run_until(do_test(&ex)).unwrap();

        // Example of starting the framework and running a future:
        async fn my_async(x: Rc<RefCell<u64>>) {
            x.replace(4);
        }

        let x = Rc::new(RefCell::new(0));
        {
            let ex = FdExecutor::new().unwrap();
            ex.run_until(my_async(x.clone())).unwrap();
        }
        assert_eq!(*x.borrow(), 4);
    }

    #[test]
    fn drop_before_completion() {
        const VALUE: u64 = 0x66ae_cb65_12fb_d260;

        async fn write_value(mut tx: File) {
            let buf = VALUE.to_ne_bytes();
            tx.write_all(&buf[..]).expect("Failed to write to pipe");
        }

        async fn check_op(op: PendingOperation) {
            let err = op.await.expect_err("Task completed successfully");
            match err {
                Error::ExecutorGone => {}
                e => panic!("Unexpected error from task: {}", e),
            }
        }

        let (mut rx, tx) = base::pipe(true).expect("Pipe failed");

        let ex = FdExecutor::new().unwrap();

        let source = ex.register_source(tx.try_clone().unwrap()).unwrap();
        let op = source.wait_writable().unwrap();

        ex.spawn_local(write_value(tx)).detach();
        ex.spawn_local(check_op(op)).detach();

        // Now drop the executor. It should still run until the write to the pipe is complete.
        mem::drop(ex);

        let mut buf = 0u64.to_ne_bytes();
        rx.read_exact(&mut buf[..])
            .expect("Failed to read from pipe");

        assert_eq!(u64::from_ne_bytes(buf), VALUE);
    }

    // Dropping a task that owns a BlockingPool shouldn't leak the pool.
    #[test]
    fn drop_detached_blocking_pool() {
        struct Cleanup(BlockingPool);

        impl Drop for Cleanup {
            fn drop(&mut self) {
                // Make sure we shutdown cleanly (BlockingPool::drop just prints a warning).
                self.0
                    .shutdown(Some(
                        std::time::Instant::now() + std::time::Duration::from_secs(1),
                    ))
                    .unwrap();
            }
        }

        let rc = Rc::new(std::cell::Cell::new(0));
        {
            let ex = FdExecutor::new().unwrap();
            let rc_clone = rc.clone();
            ex.spawn_local(async move {
                rc_clone.set(1);
                let pool = Cleanup(BlockingPool::new(1, std::time::Duration::new(60, 0)));
                let (send, recv) = std::sync::mpsc::sync_channel::<()>(0);
                // Spawn a blocking task.
                let blocking_task = pool.0.spawn(move || {
                    // Rendezvous.
                    assert_eq!(recv.recv(), Ok(()));
                    // Wait for drop.
                    assert_eq!(recv.recv(), Err(std::sync::mpsc::RecvError));
                });
                // Make sure it has actually started (using a "rendezvous channel" send).
                //
                // Without this step, we'll have a race where we can shutdown the blocking pool
                // before the worker thread pops off the task.
                send.send(()).unwrap();
                // Wait for it to finish
                blocking_task.await;
                rc_clone.set(2);
            })
            .detach();
            ex.run_until(async {}).unwrap();
            // `ex` is dropped here. If everything is working as expected, it should drop all of
            // its tasks, including `send` and `pool` (in that order, which is important). `pool`'s
            // `Drop` impl will try to join all the worker threads, which should work because send
            // half of the channel closed.
        }
        assert_eq!(rc.get(), 1);
        Rc::try_unwrap(rc).expect("Rc had too many refs");
    }
}
