// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::future::Future;
use std::io::Result;
use std::pin::Pin;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Weak;
use std::task::Context;
use std::task::Poll;

use async_task::Task;
use base::warn;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::RawDescriptor;
use futures::task::noop_waker;
use pin_utils::pin_mut;
use sync::Mutex;

use crate::queue::RunnableQueue;
use crate::waker::WeakWake;
use crate::AsyncError;
use crate::AsyncResult;
use crate::BlockingPool;
use crate::DetachedTasks;
use crate::IoSource;

/// Abstraction for IO backends.
pub trait Reactor: Send + Sync + Sized {
    fn new() -> Result<Self>;

    /// Called when the executor is being dropped to allow orderly shutdown (e.g. cancelling IO
    /// work). The returned future will be run to completion.
    ///
    /// Note that, since this is called from `RawExecutor::drop`, there will not be any
    /// `Arc<Executor>` left, so weak references to the executor will always fail to upgrade at
    /// this point. Reactors can potentially make use of this fact to keep more IO work from being
    /// submitted.
    fn on_executor_drop<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + 'a>>;

    /// Called when an executor run loop starts on a thread.
    fn on_thread_start(&self) {}

    /// Block until an event occurs (e.g. IO work is ready) or until `wake` is called.
    ///
    /// As an optimization, `set_processing` should be called immediately after wake up (i.e.
    /// before any book keeping is done) so that concurrent calls to wakers can safely skip making
    /// redundant calls to `Reactor::wake`.
    fn wait_for_work(&self, set_processing: impl Fn()) -> Result<()>;

    /// Wake up any pending `wait_for_work` calls. If there are none pending, then wake up the next
    /// `wait_for_work` call (necessary to avoid race conditions).
    fn wake(&self);

    /// Create an `IoSource` for the backend.
    fn new_source<F: AsRawDescriptor>(
        &self,
        ex: &Arc<RawExecutor<Self>>,
        f: F,
    ) -> AsyncResult<IoSource<F>>;
}

// Indicates the executor is either within or about to make a `Reactor::wait_for_work` call. When a
// waker sees this value, it will call `Reactor::wake`.
const WAITING: i32 = 0x1d5b_c019u32 as i32;

// Indicates the executor is processing futures.
const PROCESSING: i32 = 0xd474_77bcu32 as i32;

// Indicates one or more futures may be ready to make progress (i.e. causes the main loop to return
// diretly to PROCESSING instead of WAITING).
const WOKEN: i32 = 0x3e4d_3276u32 as i32;

pub struct RawExecutor<Re: Reactor + 'static> {
    pub reactor: Re,
    queue: RunnableQueue,
    blocking_pool: BlockingPool,
    state: AtomicI32,
    detached_tasks: Mutex<DetachedTasks>,
}

impl<Re: Reactor> RawExecutor<Re> {
    pub fn new_with(reactor: Re) -> AsyncResult<Arc<Self>> {
        Ok(Arc::new(RawExecutor {
            reactor,
            queue: RunnableQueue::new(),
            blocking_pool: Default::default(),
            state: AtomicI32::new(PROCESSING),
            detached_tasks: Mutex::new(DetachedTasks::new()),
        }))
    }

    pub fn new() -> AsyncResult<Arc<Self>> {
        Self::new_with(Re::new().map_err(AsyncError::Io)?)
    }

    fn wake(&self) {
        let oldstate = self.state.swap(WOKEN, Ordering::AcqRel);
        if oldstate == WAITING {
            self.reactor.wake();
        }
    }

    pub fn new_source<F: AsRawDescriptor>(self: &Arc<Self>, f: F) -> AsyncResult<IoSource<F>> {
        self.reactor.new_source(self, f)
    }

    pub fn spawn<F>(self: &Arc<Self>, f: F) -> TaskHandle<Re, F::Output>
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
        TaskHandle {
            task,
            raw: Arc::downgrade(self),
        }
    }

    pub fn spawn_local<F>(self: &Arc<Self>, f: F) -> TaskHandle<Re, F::Output>
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
        TaskHandle {
            task,
            raw: Arc::downgrade(self),
        }
    }

    pub fn spawn_blocking<F, R>(self: &Arc<Self>, f: F) -> TaskHandle<Re, R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.spawn(self.blocking_pool.spawn(f))
    }

    fn run<F: Future>(&self, cx: &mut Context, done: F) -> AsyncResult<F::Output> {
        self.reactor.on_thread_start();

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
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            if let Err(oldstate) = oldstate {
                debug_assert_eq!(oldstate, WOKEN);
                // One or more futures have become runnable.
                continue;
            }

            self.reactor
                .wait_for_work(|| self.state.store(PROCESSING, Ordering::Release))
                .map_err(AsyncError::Io)?;
        }
    }

    pub fn run_until<F: Future>(self: &Arc<Self>, f: F) -> AsyncResult<F::Output> {
        let waker = super::waker::new_waker(Arc::downgrade(self));
        let mut ctx = Context::from_waker(&waker);

        self.run(&mut ctx, f)
    }
}

impl<Re: Reactor + AsRawDescriptors> AsRawDescriptors for RawExecutor<Re> {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        self.reactor.as_raw_descriptors()
    }
}

impl<Re: Reactor> WeakWake for RawExecutor<Re> {
    fn wake_by_ref(weak_self: &Weak<Self>) {
        if let Some(arc_self) = weak_self.upgrade() {
            RawExecutor::wake(&arc_self);
        }
    }
}

impl<Re: Reactor> Drop for RawExecutor<Re> {
    fn drop(&mut self) {
        let final_future = self.reactor.on_executor_drop();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        if let Err(e) = self.run(&mut cx, final_future) {
            warn!("Failed to drive RawExecutor to completion: {}", e);
        }
    }
}

pub struct TaskHandle<Re: Reactor + 'static, R> {
    task: Task<R>,
    raw: Weak<RawExecutor<Re>>,
}

impl<Re: Reactor, R: Send + 'static> TaskHandle<Re, R> {
    pub fn detach(self) {
        if let Some(raw) = self.raw.upgrade() {
            raw.detached_tasks.lock().push(self.task);
        }
    }

    pub async fn cancel(self) -> Option<R> {
        self.task.cancel().await
    }
}

impl<Re: Reactor, R: 'static> Future for TaskHandle<Re, R> {
    type Output = R;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> std::task::Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx)
    }
}
