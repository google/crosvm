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

// This function exists to guarantee that non-epoll futures will not starve until an epoll future is
// ready to be polled again. The mechanism is very similar to the self-pipe trick used by C programs
// to reliably mix select / poll with signal handling. This is how it works:
//
// * RawExecutor::new creates an eventfd, dupes it, and spawns this async function with the duped fd.
// * The first time notify_task is polled it tries to read from the eventfd and if that fails, waits
//   for the fd to become readable.
// * Meanwhile the RawExecutor keeps the original fd for the eventfd.
// * Whenever RawExecutor::wake is called it will write to the eventfd if it determines that the
//   executor thread is currently blocked inside an io_epoll_enter call. This can happen when a
//   non-epoll future becomes ready to poll.
// * The write to the eventfd causes the fd to become readable, which then allows the epoll() call
//   to return with at least one readable fd.
// * The executor then polls the non-epoll future that became ready, any epoll futures that
//   completed, and the notify_task function, which then queues up another read on the eventfd and
//   the process can repeat.
async fn notify_task(notify: Event, raw: Weak<RawExecutor>) {
    add_fd_flags(notify.as_raw_descriptor(), libc::O_NONBLOCK)
        .expect("Failed to set notify Event as non-blocking");

    loop {
        match notify.wait() {
            Ok(_) => {}
            Err(e) if e.errno() == libc::EWOULDBLOCK => {}
            Err(e) => panic!("Unexpected error while reading notify Event: {}", e),
        }

        if let Some(ex) = raw.upgrade() {
            let token = ex
                .add_operation(notify.as_raw_descriptor(), EventType::Read)
                .expect("Failed to add notify Event to PollCtx");

            // We don't want to hold an active reference to the executor in the .await below.
            mem::drop(ex);

            let op = PendingOperation {
                token: Some(token),
                ex: raw.clone(),
            };

            match op.await {
                Ok(()) => {}
                Err(Error::ExecutorGone) => break,
                Err(e) => panic!("Unexpected error while waiting for notify Event: {}", e),
            }
        } else {
            // The executor is gone so we should also exit.
            break;
        }
    }
}

// Indicates that the executor is either within or about to make a WaitContext::wait() call. When a
// waker sees this value, it will write to the notify Event, which will cause the
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
    notify: Event,
    // Descriptor of the original event that was cloned to create notify.
    // This is only needed for the AsRawDescriptors implementation.
    notify_dup: RawDescriptor,
    detached_tasks: Mutex<DetachedTasks>,
}

impl RawExecutor {
    fn new(notify: &Event) -> Result<Self> {
        // Save the original descriptor before cloning. This descriptor will be used when creating
        // the notify task, so we need to preserve it for AsRawDescriptors.
        let notify_dup = notify.as_raw_descriptor();
        let notify = notify.try_clone().map_err(Error::CloneEvent)?;
        Ok(RawExecutor {
            queue: RunnableQueue::new(),
            poll_ctx: WaitContext::new().map_err(Error::CreatingContext)?,
            ops: Mutex::new(Slab::with_capacity(64)),
            blocking_pool: Default::default(),
            state: AtomicI32::new(PROCESSING),
            notify,
            notify_dup,
            detached_tasks: Mutex::new(DetachedTasks::new()),
        })
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
            if let Err(e) = self.notify.signal() {
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
        }
    }
}

impl AsRawDescriptors for RawExecutor {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        vec![
            self.poll_ctx.as_raw_descriptor(),
            self.notify.as_raw_descriptor(),
            self.notify_dup,
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
        // Wake up the notify_task. We set the state to WAITING here so that wake() will write to
        // the eventfd.
        self.state.store(WAITING, Ordering::Release);
        self.wake();

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
        let notify = Event::new().map_err(Error::CreateEvent)?;
        let raw = RawExecutor::new(&notify).map(Arc::new)?;

        raw.spawn(notify_task(notify, Arc::downgrade(&raw)))
            .detach();

        Ok(FdExecutor { raw })
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
        super::super::run_one_poll(my_async(x.clone())).unwrap();
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
