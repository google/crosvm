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

use base::warn;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::RawDescriptor;
use futures::task::Context;
use futures::task::Poll;
use sync::Mutex;
use thiserror::Error as ThisError;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::minwinbase::OVERLAPPED;

use crate::common_executor;
use crate::common_executor::RawExecutor;
use crate::sys::windows::executor::DEFAULT_IO_CONCURRENCY;
use crate::sys::windows::io_completion_port::CompletionPacket;
use crate::sys::windows::io_completion_port::IoCompletionPort;
use crate::waker::WakerToken;
use crate::waker::WeakWake;
use crate::AsyncResult;
use crate::IoSource;

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

/// Represents an overlapped operation that running (or has completed but not yet woken).
struct OpData {
    waker: Option<Waker>,
}

/// The current status of a future that is running or has completed on HandleReactor.
enum OpStatus {
    Pending(OpData),
    Completed(CompletionPacket),
}

pub struct HandleReactor {
    iocp: IoCompletionPort,
    overlapped_ops: Mutex<HashMap<WakerToken, OpStatus>>,
}

impl HandleReactor {
    pub fn new_with(concurrency: u32) -> Result<Self> {
        let iocp = IoCompletionPort::new(concurrency)?;
        Ok(Self {
            iocp,
            overlapped_ops: Mutex::new(HashMap::with_capacity(64)),
        })
    }

    fn new() -> Result<Self> {
        Self::new_with(DEFAULT_IO_CONCURRENCY)
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

    /// Called to register an overlapped IO source with the executor. From here, the source can
    /// register overlapped operations that will be managed by the executor.
    #[allow(dead_code)]
    pub(crate) fn register_overlapped_source(
        &self,
        raw: &Arc<RawExecutor<HandleReactor>>,
        rd: &dyn AsRawDescriptor,
    ) -> Result<RegisteredOverlappedSource> {
        RegisteredOverlappedSource::new(rd, raw)
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
            warn!("Tried to remove non-existent overlapped operation from HandleReactor.");
        }
    }
}

impl common_executor::Reactor for HandleReactor {
    fn new() -> std::io::Result<Self> {
        Ok(HandleReactor::new()?)
    }

    fn wake(&self) {
        self.iocp.wake().expect("wakeup failed on HandleReactor.");
    }

    fn on_executor_drop<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
        // TODO: Cancel overlapped ops and/or wait for everything to complete like the linux
        // reactors?
        Box::pin(async {})
    }

    fn wait_for_work(&self, set_processing: impl Fn()) -> std::io::Result<()> {
        let completion_packets = self.iocp.poll()?;

        set_processing();

        for pkt in completion_packets {
            if pkt.completion_key as RawDescriptor == INVALID_HANDLE_VALUE {
                // These completion packets aren't from overlapped operations. They're from
                // something calling HandleReactor::wake, so they've already enqueued whatever
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
        Ok(())
    }

    fn new_source<F: AsRawDescriptor>(
        &self,
        _ex: &Arc<RawExecutor<Self>>,
        f: F,
    ) -> AsyncResult<IoSource<F>> {
        Ok(IoSource::Handle(super::HandleSource::new(
            vec![f].into_boxed_slice(),
        )?))
    }
}

/// Represents a handle that has been registered for overlapped operations with a specific executor.
/// From here, the OverlappedSource can register overlapped operations with the executor.
pub(crate) struct RegisteredOverlappedSource {
    ex: Weak<RawExecutor<HandleReactor>>,
}

impl RegisteredOverlappedSource {
    fn new(
        rd: &dyn AsRawDescriptor,
        ex: &Arc<RawExecutor<HandleReactor>>,
    ) -> Result<RegisteredOverlappedSource> {
        ex.reactor.register_descriptor(rd)?;
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

impl WeakWake for HandleReactor {
    fn wake_by_ref(weak_self: &Weak<Self>) {
        if let Some(arc_self) = weak_self.upgrade() {
            common_executor::Reactor::wake(&*arc_self);
        }
    }
}

/// Represents a pending overlapped IO operation. This must be used in the following manner or
/// undefined behavior will result:
///     1. The reactor in use is a HandleReactor.
///     2. Immediately after the IO syscall, this future MUST be awaited. We rely on the fact that
///        the executor cannot poll the IOCP before this future is polled for the first time to
///        ensure the waker has been registered. (If the executor polls the IOCP before the waker
///        is registered, the future will stall.)
pub(crate) struct OverlappedOperation {
    overlapped: Pin<Box<OVERLAPPED>>,
    ex: Weak<RawExecutor<HandleReactor>>,
    completed: bool,
}

impl OverlappedOperation {
    fn new(overlapped: OVERLAPPED, ex: Weak<RawExecutor<HandleReactor>>) -> Result<Self> {
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
            .reactor
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
            if let Some(completion_pkt) =
                ex.reactor.get_overlapped_op_if_ready(&self.get_token(), cx)
            {
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
                ex.reactor.remove_overlapped_op(&self.get_token());
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

        let ex = RawExecutor::<HandleReactor>::new().unwrap();
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

        let ex = RawExecutor::<HandleReactor>::new().unwrap();
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
            let ex = RawExecutor::<HandleReactor>::new().unwrap();
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
