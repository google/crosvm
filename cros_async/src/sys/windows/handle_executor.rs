// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::mem;
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Weak;
use std::task::Waker;

use async_task::Runnable;
use async_task::Task;
use base::warn;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::RawDescriptor;
use futures::task::Context;
use futures::task::Poll;
use pin_utils::pin_mut;
use sync::Mutex;
use thiserror::Error as ThisError;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::minwinbase::OVERLAPPED;

use crate::queue::RunnableQueue;
use crate::sys::windows::io_completion_port::CompletionPacket;
use crate::sys::windows::io_completion_port::IoCompletionPort;
use crate::waker::new_waker;
use crate::waker::WakerToken;
use crate::waker::WeakWake;
use crate::DetachedTasks;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("IO completion port operation failed: {0}")]
    IocpOperationFailed(SysError),
    #[error("Failed to get future from executor run.")]
    FailedToReadFutureFromWakerChannel(mpsc::RecvError),
    #[error("executor gone before future was dropped.")]
    ExecutorGone,
    #[error("tried to remove overlapped operation but it didn't exist.")]
    RemoveNonExistentOperation,
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            FailedToReadFutureFromWakerChannel(e) => io::Error::new(io::ErrorKind::Other, e),
            IocpOperationFailed(e) => io::Error::new(io::ErrorKind::Other, e),
            ExecutorGone => io::Error::new(io::ErrorKind::Other, e),
            RemoveNonExistentOperation => io::Error::new(io::ErrorKind::Other, e),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct HandleExecutorTaskHandle<R> {
    task: Task<R>,
    raw: Weak<RawExecutor>,
}

impl<R: Send + 'static> HandleExecutorTaskHandle<R> {
    pub fn detach(self) {
        if let Some(raw) = self.raw.upgrade() {
            raw.detached_tasks.lock().push(self.task);
        }
    }
}

impl<R: 'static> Future for HandleExecutorTaskHandle<R> {
    type Output = R;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> std::task::Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx)
    }
}

#[derive(Clone)]
pub struct HandleExecutor {
    raw: Arc<RawExecutor>,
}

impl HandleExecutor {
    pub fn new() -> Result<Self> {
        Ok(Self {
            raw: Arc::new(RawExecutor::new()?),
        })
    }

    pub fn spawn<F>(&self, f: F) -> HandleExecutorTaskHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.raw.spawn(f)
    }

    pub fn spawn_local<F>(&self, f: F) -> HandleExecutorTaskHandle<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        self.raw.spawn_local(f)
    }

    pub fn run_until<F: Future>(&self, f: F) -> Result<F::Output> {
        let waker = new_waker(Arc::downgrade(&self.raw));
        let mut cx = Context::from_waker(&waker);
        self.raw.run(&mut cx, f)
    }

    /// Called to register an overlapped IO source with the executor. From here, the source can
    /// register overlapped operations that will be managed by the executor.
    #[allow(dead_code)]
    pub(crate) fn register_overlapped_source(
        &self,
        rd: &dyn AsRawDescriptor,
    ) -> Result<RegisteredOverlappedSource> {
        RegisteredOverlappedSource::new(rd, &self.raw)
    }
}

/// Represents an overlapped operation that running (or has completed but not yet woken).
struct OpData {
    waker: Option<Waker>,
}

/// The current status of a future that is running or has completed on RawExecutor.
enum OpStatus {
    Pending(OpData),
    Completed(CompletionPacket),
}

struct RawExecutor {
    queue: RunnableQueue,
    iocp: IoCompletionPort,
    overlapped_ops: Mutex<HashMap<WakerToken, OpStatus>>,
    detached_tasks: Mutex<DetachedTasks>,
}

impl RawExecutor {
    fn new() -> Result<Self> {
        let iocp = IoCompletionPort::new()?;
        Ok(Self {
            iocp,
            queue: RunnableQueue::new(),
            overlapped_ops: Mutex::new(HashMap::with_capacity(64)),
            detached_tasks: Mutex::new(DetachedTasks::new()),
        })
    }

    fn make_schedule_fn(self: &Arc<Self>) -> impl Fn(Runnable) {
        let raw = Arc::downgrade(self);
        move |runnable| {
            if let Some(r) = raw.upgrade() {
                r.queue.push_back(runnable);
                r.wake();
            }
        }
    }

    fn spawn<F>(self: &Arc<Self>, f: F) -> HandleExecutorTaskHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (runnable, task) = async_task::spawn(f, self.make_schedule_fn());
        runnable.schedule();
        HandleExecutorTaskHandle {
            task,
            raw: Arc::downgrade(self),
        }
    }

    fn spawn_local<F>(self: &Arc<Self>, f: F) -> HandleExecutorTaskHandle<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let (runnable, task) = async_task::spawn_local(f, self.make_schedule_fn());
        runnable.schedule();
        HandleExecutorTaskHandle {
            task,
            raw: Arc::downgrade(self),
        }
    }

    fn run<F: Future>(&self, cx: &mut Context, done: F) -> Result<F::Output> {
        pin_mut!(done);

        loop {
            for runnable in self.queue.iter() {
                runnable.run();
            }
            if let Ok(mut tasks) = self.detached_tasks.try_lock() {
                tasks.poll(cx);
            }
            if let Poll::Ready(val) = done.as_mut().poll(cx) {
                return Ok(val);
            }

            let completion_packets = self.iocp.poll()?;
            for pkt in completion_packets {
                if pkt.completion_key as RawDescriptor == INVALID_HANDLE_VALUE {
                    // These completion packets aren't from overlapped operations. They're from
                    // something calling HandleExecutor::wake, so they've already enqueued whatever
                    // they think is runnable into the queue. All the packet does is wake up the
                    // executor loop.
                    continue;
                }

                let mut overlapped_ops = self.overlapped_ops.lock();
                if let Some(op) = overlapped_ops.get_mut(&WakerToken(pkt.overlapped_ptr)) {
                    let waker = match mem::replace(op, OpStatus::Completed(pkt)) {
                        OpStatus::Pending(OpData { waker }) => waker,
                        OpStatus::Completed(_) => panic!("operation completed more than once"),
                    };
                    drop(overlapped_ops);
                    if let Some(waker) = waker {
                        waker.wake();
                    } else {
                        // We shouldn't ever get a completion packet for an IO operation that hasn't
                        // registered its waker.
                        warn!(
                            "got a completion packet for an IO operation that had no waker.\
                             future may be stalled."
                        )
                    }
                }
            }
        }
    }

    fn wake(self: &Arc<Self>) {
        self.iocp
            .post_status(0, INVALID_HANDLE_VALUE as usize)
            .expect("wakeup failed on HandleExecutor.");
    }

    /// All descriptors must be first registered with IOCP before any completion packets can be
    /// received for them.
    pub(crate) fn register_descriptor(&self, rd: &dyn AsRawDescriptor) -> Result<()> {
        self.iocp.register_descriptor(rd)
    }

    /// When an overlapped operation is created, it is registered with the executor here. This way,
    /// when the executor's run thread picks up the completion events, it can associate them back
    /// to the correct overlapped operation. Notice that here, no waker is registered. This is
    /// because the await hasn't happened yet, so there is no waker. Once the await is triggered,
    /// we'll invoke get_overlapped_op_if_ready which will register the waker.
    pub(crate) fn register_overlapped_op(&self, token: &WakerToken) {
        let mut ops = self.overlapped_ops.lock();
        ops.insert(*token, OpStatus::Pending(OpData { waker: None }));
    }

    /// Every time an `OverlappedOperation` is polled, this method will be called. It's a trick to
    /// register the waker so that completion events can trigger it from the executor's main thread.
    fn get_overlapped_op_if_ready(
        &self,
        token: &WakerToken,
        cx: &mut Context,
    ) -> Option<CompletionPacket> {
        let mut ops = self.overlapped_ops.lock();

        if let OpStatus::Pending(data) = ops
            .get_mut(token)
            .expect("`get_overlapped_op_if_ready` called on unknown operation")
        {
            data.waker = Some(cx.waker().clone());
            return None;
        }
        if let OpStatus::Completed(pkt) = ops.remove(token).unwrap() {
            return Some(pkt);
        }
        unreachable!("OpStatus didn't match any known variant.");
    }

    /// When an `OverlappedOperation` is dropped, this is called to so we don't leak registered
    /// operations. It's possible the operation was already removed (e.g. via polling), in which
    /// case this has no effect.
    fn remove_overlapped_op(&self, token: &WakerToken) {
        let mut ops = self.overlapped_ops.lock();
        if ops.remove(token).is_none() {
            warn!("Tried to remove non-existent overlapped operation from HandleExecutor.");
        }
    }
}

/// Represents a handle that has been registered for overlapped operations with a specific executor.
/// From here, the OverlappedSource can register overlapped operations with the executor.
pub(crate) struct RegisteredOverlappedSource {
    ex: Weak<RawExecutor>,
}

impl RegisteredOverlappedSource {
    fn new(rd: &dyn AsRawDescriptor, ex: &Arc<RawExecutor>) -> Result<RegisteredOverlappedSource> {
        ex.register_descriptor(rd)?;
        Ok(Self {
            ex: Arc::downgrade(ex),
        })
    }

    /// Registers an overlapped IO operation with this executor. Call this function with the
    /// overlapped struct that represents the operation **before** making the overlapped IO call.
    ///
    /// NOTE: you MUST pass OverlappedOperation::get_overlapped_ptr() as the overlapped IO pointer
    /// in the IO call.
    pub fn register_overlapped_operation(
        &self,
        overlapped: OVERLAPPED,
    ) -> Result<OverlappedOperation> {
        OverlappedOperation::new(overlapped, self.ex.clone())
    }
}

impl WeakWake for RawExecutor {
    fn wake_by_ref(weak_self: &Weak<Self>) {
        if let Some(arc_self) = weak_self.upgrade() {
            RawExecutor::wake(&arc_self);
        }
    }
}

/// Represents a pending overlapped IO operation. This must be used in the following manner or
/// undefined behavior will result:
///     1. The executor in use is a HandleExecutor.
///     2. Immediately after the IO syscall, this future MUST be awaited. We rely on the fact that
///        the executor cannot poll the IOCP before this future is polled for the first time to
///        ensure the waker has been registered. (If the executor polls the IOCP before the waker
///        is registered, the future will stall.)
pub(crate) struct OverlappedOperation {
    overlapped: Pin<Box<OVERLAPPED>>,
    ex: Weak<RawExecutor>,
    completed: bool,
}

impl OverlappedOperation {
    fn new(overlapped: OVERLAPPED, ex: Weak<RawExecutor>) -> Result<Self> {
        let ret = Self {
            overlapped: Box::pin(overlapped),
            ex,
            completed: false,
        };
        ret.register_op()?;
        Ok(ret)
    }

    fn register_op(&self) -> Result<()> {
        self.ex
            .upgrade()
            .ok_or(Error::ExecutorGone)?
            .register_overlapped_op(&self.get_token());
        Ok(())
    }

    /// Returns a pointer to the overlapped struct representing the operation. This MUST be used
    /// when making the overlapped IO call or the executor will not be able to wake the right
    /// future.
    pub fn get_overlapped(&mut self) -> &mut OVERLAPPED {
        &mut self.overlapped
    }

    #[inline]
    pub fn get_token(&self) -> WakerToken {
        WakerToken((&*self.overlapped) as *const _ as usize)
    }
}

impl Future for OverlappedOperation {
    type Output = Result<CompletionPacket>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if self.completed {
            panic!("OverlappedOperation polled after returning Poll::Ready");
        }
        if let Some(ex) = self.ex.upgrade() {
            if let Some(completion_pkt) = ex.get_overlapped_op_if_ready(&self.get_token(), cx) {
                self.completed = true;
                Poll::Ready(Ok(completion_pkt))
            } else {
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(Error::ExecutorGone))
        }
    }
}

impl Drop for OverlappedOperation {
    fn drop(&mut self) {
        if !self.completed {
            if let Some(ex) = self.ex.upgrade() {
                ex.remove_overlapped_op(&self.get_token());
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    const FUT_MSG: i32 = 5;
    use std::rc::Rc;

    use futures::channel::mpsc as fut_mpsc;
    use futures::SinkExt;
    use futures::StreamExt;

    use crate::BlockingPool;

    #[test]
    fn run_future() {
        let (send, recv) = mpsc::channel();
        async fn this_test(send: mpsc::Sender<i32>) {
            send.send(FUT_MSG).unwrap();
        }

        let ex = HandleExecutor::new().unwrap();
        ex.run_until(this_test(send)).unwrap();
        assert_eq!(recv.recv().unwrap(), FUT_MSG);
    }

    #[test]
    fn spawn_future() {
        let (send, recv) = fut_mpsc::channel(1);
        let (send_done_signal, receive_done_signal) = mpsc::channel();

        async fn message_sender(mut send: fut_mpsc::Sender<i32>) {
            send.send(FUT_MSG).await.unwrap();
        }

        async fn message_receiver(mut recv: fut_mpsc::Receiver<i32>, done: mpsc::Sender<bool>) {
            assert_eq!(recv.next().await.unwrap(), FUT_MSG);
            done.send(true).unwrap();
        }

        let ex = HandleExecutor::new().unwrap();
        ex.spawn(message_sender(send)).detach();
        ex.run_until(message_receiver(recv, send_done_signal))
            .unwrap();
        assert_eq!(receive_done_signal.recv().unwrap(), true);
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
            let ex = HandleExecutor::new().unwrap();
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
