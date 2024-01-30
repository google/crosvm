// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::future::Future;
use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Weak;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use base::add_fd_flags;
use base::warn;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::Event;
use base::EventType;
use base::RawDescriptor;
use base::WaitContext;
use remain::sorted;
use slab::Slab;
use sync::Mutex;
use thiserror::Error as ThisError;

use crate::common_executor::RawExecutor;
use crate::common_executor::Reactor;
use crate::waker::WakerToken;
use crate::AsyncResult;
use crate::IoSource;

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
    DuplicatingFd(std::io::Error),
    #[error("Executor failed")]
    ExecutorError(anyhow::Error),
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
            DuplicatingFd(e) => e,
            ExecutorError(e) => io::Error::new(io::ErrorKind::Other, e),
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
    file: Arc<std::os::fd::OwnedFd>,
    waker: Option<Waker>,
}

// The current status of a submitted operation.
enum OpStatus {
    Pending(OpData),
    Completed,
    // Special status that identifies the "wake up" eventfd, which is essentially always pending.
    WakeEvent,
}

// An IO source previously registered with an EpollReactor. Used to initiate asynchronous IO with the
// associated executor.
pub struct RegisteredSource<F> {
    pub(crate) source: F,
    ex: Weak<RawExecutor<EpollReactor>>,
    /// A clone of `source`'s underlying FD. Allows us to ensure that the FD isn't closed during
    /// the epoll wait call. There are well defined sematics for closing an FD in an epoll context
    /// so it might be possible to eliminate this dup if someone thinks hard about it.
    pub(crate) duped_fd: Arc<std::os::fd::OwnedFd>,
}

impl<F: AsRawDescriptor> RegisteredSource<F> {
    pub(crate) fn new(raw: &Arc<RawExecutor<EpollReactor>>, f: F) -> Result<Self> {
        let raw_fd = f.as_raw_descriptor();
        assert_ne!(raw_fd, -1);

        add_fd_flags(raw_fd, libc::O_NONBLOCK).map_err(Error::SettingNonBlocking)?;

        // SAFETY: The FD is open for the duration of the BorrowedFd lifetime (this line) and not
        // -1 (checked above).
        let duped_fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw_fd) }
            .try_clone_to_owned()
            .map_err(Error::DuplicatingFd)?;
        Ok(RegisteredSource {
            source: f,
            ex: Arc::downgrade(raw),
            duped_fd: Arc::new(duped_fd),
        })
    }

    // Start an asynchronous operation to wait for this source to become readable. The returned
    // future will not be ready until the source is readable.
    pub fn wait_readable(&self) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;

        let token = ex
            .reactor
            .add_operation(Arc::clone(&self.duped_fd), EventType::Read)?;

        Ok(PendingOperation {
            token: Some(token),
            ex: self.ex.clone(),
        })
    }

    // Start an asynchronous operation to wait for this source to become writable. The returned
    // future will not be ready until the source is writable.
    pub fn wait_writable(&self) -> Result<PendingOperation> {
        let ex = self.ex.upgrade().ok_or(Error::ExecutorGone)?;

        let token = ex
            .reactor
            .add_operation(Arc::clone(&self.duped_fd), EventType::Write)?;

        Ok(PendingOperation {
            token: Some(token),
            ex: self.ex.clone(),
        })
    }
}

/// A token returned from `add_operation` that can be used to cancel the waker before it completes.
/// Used to manage getting the result from the underlying executor for a completed operation.
/// Dropping a `PendingOperation` will get the result from the executor.
pub struct PendingOperation {
    token: Option<WakerToken>,
    ex: Weak<RawExecutor<EpollReactor>>,
}

impl Future for PendingOperation {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let token = self
            .token
            .as_ref()
            .expect("PendingOperation polled after returning Poll::Ready");
        if let Some(ex) = self.ex.upgrade() {
            if ex.reactor.is_ready(token, cx) {
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
                let _ = ex.reactor.cancel_operation(token);
            }
        }
    }
}

/// `Reactor` that manages async IO work using epoll.
pub struct EpollReactor {
    poll_ctx: WaitContext<usize>,
    ops: Mutex<Slab<OpStatus>>,
    // This event is always present in `poll_ctx` with the special op status `WakeEvent`. It is
    // used by `RawExecutor::wake` to break other threads out of `poll_ctx.wait()` calls (usually
    // to notify them that `queue` has new work).
    wake_event: Event,
}

impl EpollReactor {
    fn new() -> Result<Self> {
        let reactor = EpollReactor {
            poll_ctx: WaitContext::new().map_err(Error::CreatingContext)?,
            ops: Mutex::new(Slab::with_capacity(64)),
            wake_event: {
                let wake_event = Event::new().map_err(Error::CreateEvent)?;
                add_fd_flags(wake_event.as_raw_descriptor(), libc::O_NONBLOCK)
                    .map_err(Error::SettingNonBlocking)?;
                wake_event
            },
        };

        // Add the special "wake up" op.
        {
            let mut ops = reactor.ops.lock();
            let entry = ops.vacant_entry();
            let next_token = entry.key();
            reactor
                .poll_ctx
                .add_for_event(&reactor.wake_event, EventType::Read, next_token)
                .map_err(Error::SubmittingWaker)?;
            entry.insert(OpStatus::WakeEvent);
        }

        Ok(reactor)
    }

    fn add_operation(
        &self,
        file: Arc<std::os::fd::OwnedFd>,
        event_type: EventType,
    ) -> Result<WakerToken> {
        let mut ops = self.ops.lock();
        let entry = ops.vacant_entry();
        let next_token = entry.key();
        self.poll_ctx
            .add_for_event(&base::Descriptor(file.as_raw_fd()), event_type, next_token)
            .map_err(Error::SubmittingWaker)?;
        entry.insert(OpStatus::Pending(OpData { file, waker: None }));
        Ok(WakerToken(next_token))
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
                .delete(&base::Descriptor(data.file.as_raw_fd()))
                .map_err(Error::WaitContextError),
            OpStatus::Completed => Ok(()),
            // unreachable because we never create a WakerToken for `wake_event`.
            OpStatus::WakeEvent => unreachable!(),
        }
    }
}

impl Reactor for EpollReactor {
    fn new() -> std::io::Result<Self> {
        Ok(EpollReactor::new()?)
    }

    fn wake(&self) {
        if let Err(e) = self.wake_event.signal() {
            warn!("Failed to notify executor that a future is ready: {}", e);
        }
    }

    fn on_executor_drop<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
        // At this point, there are no strong references to the executor (see `on_executor_drop`
        // docs). That means all the `RegisteredSource::ex` will fail to upgrade and so no more IO
        // work can be submitted.

        // Wake up any futures still waiting on poll operations as they are just going to get an
        // ExecutorGone error now.
        for op in self.ops.lock().drain() {
            match op {
                OpStatus::Pending(mut data) => {
                    if let Some(waker) = data.waker.take() {
                        waker.wake();
                    }

                    if let Err(e) = self
                        .poll_ctx
                        .delete(&base::Descriptor(data.file.as_raw_fd()))
                    {
                        warn!("Failed to remove file from EpollCtx: {}", e);
                    }
                }
                OpStatus::Completed => {}
                OpStatus::WakeEvent => {}
            }
        }

        // Now run the executor one more time to drive any remaining futures to completion.
        Box::pin(async {})
    }

    fn wait_for_work(&self, set_processing: impl Fn()) -> std::io::Result<()> {
        let events = self.poll_ctx.wait().map_err(Error::WaitContextError)?;

        // Set the state back to PROCESSING to prevent any tasks woken up by the loop below from
        // writing to the eventfd.
        set_processing();
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
                        *op = OpStatus::WakeEvent;
                        match self.wake_event.wait() {
                            Ok(_) => {}
                            Err(e) if e.errno() == libc::EWOULDBLOCK => {}
                            Err(e) => return Err(e.into()),
                        }
                        continue;
                    }
                };

                mem::drop(ops);

                self.poll_ctx
                    .delete(&base::Descriptor(file.as_raw_fd()))
                    .map_err(Error::WaitContextError)?;

                if let Some(waker) = waker {
                    waker.wake();
                }
            }
        }
        Ok(())
    }

    fn new_source<F: AsRawDescriptor>(
        &self,
        ex: &Arc<RawExecutor<Self>>,
        f: F,
    ) -> AsyncResult<IoSource<F>> {
        Ok(IoSource::Epoll(super::PollSource::new(f, ex)?))
    }
}

impl AsRawDescriptors for EpollReactor {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        vec![
            self.poll_ctx.as_raw_descriptor(),
            self.wake_event.as_raw_descriptor(),
        ]
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::fs::File;
    use std::io::Read;
    use std::io::Write;
    use std::rc::Rc;

    use futures::future::Either;

    use super::*;
    use crate::BlockingPool;

    #[test]
    fn test_it() {
        async fn do_test(ex: &Arc<RawExecutor<EpollReactor>>) {
            let (r, _w) = base::pipe().unwrap();
            let done = Box::pin(async { 5usize });
            let source = RegisteredSource::new(ex, r).unwrap();
            let pending = source.wait_readable().unwrap();
            match futures::future::select(pending, done).await {
                Either::Right((5, pending)) => std::mem::drop(pending),
                _ => panic!("unexpected select result"),
            }
        }

        let ex = RawExecutor::<EpollReactor>::new().unwrap();
        ex.run_until(do_test(&ex)).unwrap();

        // Example of starting the framework and running a future:
        async fn my_async(x: Rc<RefCell<u64>>) {
            x.replace(4);
        }

        let x = Rc::new(RefCell::new(0));
        {
            let ex = RawExecutor::<EpollReactor>::new().unwrap();
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

        let (mut rx, tx) = base::pipe().expect("Pipe failed");

        let ex = RawExecutor::<EpollReactor>::new().unwrap();

        let source = RegisteredSource::new(&ex, tx.try_clone().unwrap()).unwrap();
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
            let ex = RawExecutor::<EpollReactor>::new().unwrap();
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

    // Test the waker implementation. This code path doesn't get hit by `IoSource`, only by backend
    // agnostic libraries, like `BlockingPool` and `futures::channel`.
    #[test]
    fn test_non_io_waker() {
        use std::task::Poll;

        struct Sleep(Option<u64>);

        impl Future for Sleep {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                if let Some(ms) = self.0.take() {
                    let waker = cx.waker().clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_millis(ms));
                        waker.wake();
                    });
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            }
        }

        let ex = RawExecutor::<EpollReactor>::new().unwrap();
        ex.run_until(async move {
            // Test twice because there was once a bug where the second time panic'd.
            Sleep(Some(1)).await;
            Sleep(Some(1)).await;
        })
        .unwrap();
    }
}
