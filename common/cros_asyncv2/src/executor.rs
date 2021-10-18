// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, VecDeque},
    future::{pending, Future},
    num::Wrapping,
    sync::Arc,
    task::{self, Poll, Waker},
    thread::{self, ThreadId},
    time::{Duration, Instant},
};

use anyhow::Result;
use async_task::{Runnable, Task};
use futures::{pin_mut, task::WakerRef};
use once_cell::unsync::Lazy;
use smallvec::SmallVec;
use sync::Mutex;

use crate::{enter::enter, sys, BlockingPool};

thread_local! (static LOCAL_CONTEXT: Lazy<Arc<Mutex<Context>>> = Lazy::new(Default::default));

#[derive(Default)]
struct Context {
    queue: VecDeque<Runnable>,
    timers: BTreeMap<Reverse<Instant>, SmallVec<[Waker; 2]>>,
    waker: Option<Waker>,
}

#[derive(Default)]
struct Shared {
    queue: VecDeque<Runnable>,
    idle_workers: VecDeque<(ThreadId, Waker)>,
    blocking_pool: BlockingPool,
}

pub(crate) fn add_timer(deadline: Instant, waker: &Waker) {
    LOCAL_CONTEXT.with(|local_ctx| {
        let mut ctx = local_ctx.lock();
        let wakers = ctx.timers.entry(Reverse(deadline)).or_default();
        if wakers.iter().all(|w| !w.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    });
}

/// An executor for scheduling tasks that poll futures to completion.
///
/// All asynchronous operations must run within an executor, which is capable of spawning futures as
/// tasks. This executor also provides a mechanism for performing asynchronous I/O operations.
///
/// The returned type is a cheap, clonable handle to the underlying executor. Cloning it will only
/// create a new reference, not a new executor.
///
/// # Examples
///
/// Concurrently wait for multiple files to become readable/writable and then read/write the data.
///
/// ```
/// use std::{
///     cmp::min,
///     convert::TryFrom,
///     fs::OpenOptions,
/// };
///
/// use anyhow::Result;
/// use cros_async::{Executor, File};
/// use futures::future::join3;
///
/// const CHUNK_SIZE: usize = 32;
///
/// // Transfer `len` bytes of data from `from` to `to`.
/// async fn transfer_data(from: File, to: File, len: usize) -> Result<usize> {
///     let mut rem = len;
///     let mut buf = [0u8; CHUNK_SIZE];
///     while rem > 0 {
///         let count = from.read(&mut buf, None).await?;
///
///         if count == 0 {
///             // End of file. Return the number of bytes transferred.
///             return Ok(len - rem);
///         }
///
///         to.write_all(&buf[..count], None).await?;
///
///         rem = rem.saturating_sub(count);
///     }
///
///     Ok(len)
/// }
///
/// # fn do_it() -> Result<()> {
///     let (rx, tx) = sys_util::pipe(true)?;
///     let zero = File::open("/dev/zero")?;
///     let zero_bytes = CHUNK_SIZE * 7;
///     let zero_to_pipe = transfer_data(
///         zero,
///         File::try_from(tx.try_clone()?)?,
///         zero_bytes,
///     );
///
///     let rand = File::open("/dev/urandom")?;
///     let rand_bytes = CHUNK_SIZE * 19;
///     let rand_to_pipe = transfer_data(
///         rand,
///         File::try_from(tx)?,
///         rand_bytes
///     );
///
///     let null = OpenOptions::new().write(true).open("/dev/null")?;
///     let null_bytes = zero_bytes + rand_bytes;
///     let pipe_to_null = transfer_data(
///         File::try_from(rx)?,
///         File::try_from(null)?,
///         null_bytes
///     );
///
///     Executor::new().run_until(join3(
///         async { assert_eq!(pipe_to_null.await.unwrap(), null_bytes) },
///         async { assert_eq!(zero_to_pipe.await.unwrap(), zero_bytes) },
///         async { assert_eq!(rand_to_pipe.await.unwrap(), rand_bytes) },
///     ))?;
///
/// #     Ok(())
/// # }
///
/// # do_it().unwrap();
/// ```
#[derive(Clone, Default)]
pub struct Executor {
    shared: Arc<Mutex<Shared>>,
}

impl Executor {
    /// Create a new `Executor`.
    pub fn new() -> Executor {
        Default::default()
    }

    /// Spawn a new future for this executor to run to completion. Callers may use the returned
    /// `Task` to await on the result of `f`. Dropping the returned `Task` will cancel `f`,
    /// preventing it from being polled again. To drop a `Task` without canceling the future
    /// associated with it use [`Task::detach`]. To cancel a task gracefully and wait until it is
    /// fully destroyed, use [`Task::cancel`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use anyhow::Result;
    /// # fn example_spawn() -> Result<()> {
    /// #      use std::thread;
    /// #
    /// #      use cros_async::Executor;
    /// #
    /// #      let ex = Executor::new();
    /// #
    /// #      // Spawn a thread that runs the executor.
    /// #      let ex2 = ex.clone();
    /// #      thread::spawn(move || ex2.run());
    /// #
    ///       let task = ex.spawn(async { 7 + 13 });
    ///
    ///       let result = ex.run_until(task)?;
    ///       assert_eq!(result, 20);
    /// #     Ok(())
    /// # }
    /// #
    /// # example_spawn().unwrap();
    /// ```
    pub fn spawn<F>(&self, f: F) -> Task<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let weak_shared = Arc::downgrade(&self.shared);
        let schedule = move |runnable| {
            if let Some(shared) = weak_shared.upgrade() {
                let waker = {
                    let mut s = shared.lock();
                    s.queue.push_back(runnable);
                    s.idle_workers.pop_front()
                };

                if let Some((_, w)) = waker {
                    w.wake();
                }
            }
        };
        let (runnable, task) = async_task::spawn(f, schedule);
        runnable.schedule();
        task
    }

    /// Spawn a thread-local task for this executor to drive to completion. Like `spawn` but without
    /// requiring `Send` on `F` or `F::Output`. This method should only be called from the same
    /// thread where `run()` or `run_until()` is called.
    ///
    /// # Panics
    ///
    /// `Executor::run` and `Executor::run_util` will panic if they try to poll a future that was
    /// added by calling `spawn_local` from a different thread.
    ///
    /// # Examples
    ///
    /// ```
    /// # use anyhow::Result;
    /// # fn example_spawn_local() -> Result<()> {
    /// #      use cros_async::Executor;
    /// #
    /// #      let ex = Executor::new();
    /// #
    ///       let task = ex.spawn_local(async { 7 + 13 });
    ///
    ///       let result = ex.run_until(task)?;
    ///       assert_eq!(result, 20);
    /// #     Ok(())
    /// # }
    /// #
    /// # example_spawn_local().unwrap();
    /// ```
    pub fn spawn_local<F>(&self, f: F) -> Task<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let weak_ctx = LOCAL_CONTEXT.with(|ctx| Arc::downgrade(ctx));
        let schedule = move |runnable| {
            if let Some(local_ctx) = weak_ctx.upgrade() {
                let waker = {
                    let mut ctx = local_ctx.lock();
                    ctx.queue.push_back(runnable);
                    ctx.waker.take()
                };

                if let Some(w) = waker {
                    w.wake();
                }
            }
        };
        let (runnable, task) = async_task::spawn_local(f, schedule);
        runnable.schedule();
        task
    }

    /// Run the provided closure on a dedicated thread where blocking is allowed.
    ///
    /// Callers may `await` on the returned `Task` to wait for the result of `f`. Dropping or
    /// canceling the returned `Task` may not cancel the operation if it was already started on a
    /// worker thread.
    ///
    /// # Panics
    ///
    /// `await`ing the `Task` after the `Executor` is dropped will panic if the work was not already
    /// completed.
    ///
    /// # Examples
    ///
    /// ```edition2018
    /// # use cros_async::Executor;
    /// #
    /// # async fn do_it(ex: &Executor) {
    ///     let res = ex.spawn_blocking(move || {
    ///         // Do some CPU-intensive or blocking work here.
    ///
    ///         42
    ///     }).await;
    ///
    ///     assert_eq!(res, 42);
    /// # }
    /// #
    /// # let ex = Executor::new();
    /// # ex.run_until(do_it(&ex)).unwrap();
    /// ```
    pub fn spawn_blocking<F, R>(&self, f: F) -> Task<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.shared.lock().blocking_pool.spawn(f)
    }

    /// Run the executor indefinitely, driving all spawned futures to completion. This method will
    /// block the current thread and only return in the case of an error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use anyhow::Result;
    /// # fn example_run() -> Result<()> {
    ///       use std::thread;
    ///
    ///       use cros_async::Executor;
    ///
    ///       let ex = Executor::new();
    ///
    ///       // Spawn a thread that runs the executor.
    ///       let ex2 = ex.clone();
    ///       thread::spawn(move || ex2.run());
    ///
    ///       let task = ex.spawn(async { 7 + 13 });
    ///
    ///       let result = ex.run_until(task)?;
    ///       assert_eq!(result, 20);
    /// #     Ok(())
    /// # }
    /// #
    /// # example_run().unwrap();
    /// ```
    #[inline]
    pub fn run(&self) -> Result<()> {
        self.run_until(pending())
    }

    /// Drive all futures spawned in this executor until `f` completes. This method will block the
    /// current thread only until `f` is complete and there may still be unfinished futures in the
    /// executor.
    ///
    /// # Examples
    ///
    /// ```
    /// # use anyhow::Result;
    /// # fn example_run_until() -> Result<()> {
    ///       use cros_async::Executor;
    ///
    ///       let ex = Executor::new();
    ///
    ///       let task = ex.spawn_local(async { 7 + 13 });
    ///
    ///       let result = ex.run_until(task)?;
    ///       assert_eq!(result, 20);
    /// #     Ok(())
    /// # }
    /// #
    /// # example_run_until().unwrap();
    /// ```
    pub fn run_until<F: Future>(&self, done: F) -> Result<F::Output> {
        // Prevent nested execution.
        let _guard = enter()?;

        pin_mut!(done);

        let current_thread = thread::current().id();
        let state = sys::platform_state()?;
        let waker = state.waker_ref();
        let mut cx = task::Context::from_waker(&waker);
        let mut done_polled = false;

        LOCAL_CONTEXT.with(|local_ctx| {
            let next_local = || local_ctx.lock().queue.pop_front();
            let next_global = || self.shared.lock().queue.pop_front();

            let mut tick = Wrapping(0u32);

            loop {
                tick += Wrapping(1);

                // If there are always tasks available to run in either the local or the global
                // queue then we may go a long time without fetching completed events from the
                // underlying platform driver. Poll the driver once in a while to prevent this from
                // happening.
                if tick.0 % 31 == 0 {
                    // A zero timeout will fetch new events without blocking.
                    self.get_events(&state, Some(Duration::from_millis(0)))?;
                }

                let was_woken = state.start_processing();
                if was_woken || !done_polled {
                    done_polled = true;
                    if let Poll::Ready(v) = done.as_mut().poll(&mut cx) {
                        return Ok(v);
                    }
                }

                // If there are always tasks in the local queue then any tasks in the global queue
                // will get starved. Pull tasks out of the global queue every once in a while even
                // when there are still local tasks available to prevent this.
                let next_runnable = if tick.0 % 13 == 0 {
                    next_global().or_else(next_local)
                } else {
                    next_local().or_else(next_global)
                };

                if let Some(runnable) = next_runnable {
                    runnable.run();
                    continue;
                }

                // We're about to block so first check that new tasks have not snuck in and set the
                // waker so that we can be woken up when tasks are re-scheduled.
                let deadline = {
                    let mut ctx = local_ctx.lock();
                    if !ctx.queue.is_empty() {
                        // Some more tasks managed to sneak in.  Go back to the start of the loop.
                        continue;
                    }

                    // There are no more tasks to run so set the waker.
                    if ctx.waker.is_none() {
                        ctx.waker = Some(cx.waker().clone());
                    }

                    // TODO: Replace with `last_entry` once it is stabilized.
                    ctx.timers.keys().next_back().cloned()
                };
                {
                    let mut shared = self.shared.lock();
                    if !shared.queue.is_empty() {
                        // More tasks were added to the global queue. Go back to the start of the loop.
                        continue;
                    }

                    // We're going to block so add ourselves to the idle worker list.
                    shared
                        .idle_workers
                        .push_back((current_thread, cx.waker().clone()));
                };

                // Now wait to be woken up.
                let timeout = deadline.map(|d| d.0.saturating_duration_since(Instant::now()));
                self.get_events(&state, timeout)?;

                // Remove from idle workers.
                {
                    let mut shared = self.shared.lock();
                    if let Some(idx) = shared
                        .idle_workers
                        .iter()
                        .position(|(id, _)| id == &current_thread)
                    {
                        shared.idle_workers.swap_remove_back(idx);
                    }
                }

                // Reset the ticks since we just fetched new events from the platform driver.
                tick = Wrapping(0);
            }
        })
    }

    fn get_events<S: PlatformState>(
        &self,
        state: &S,
        timeout: Option<Duration>,
    ) -> anyhow::Result<()> {
        state.wait(timeout)?;

        // Timer maintenance.
        let expired = LOCAL_CONTEXT.with(|local_ctx| {
            let mut ctx = local_ctx.lock();
            let now = Instant::now();
            ctx.timers.split_off(&Reverse(now))
        });

        // We cannot wake the timers while holding the lock because the schedule function for the
        // task that's waiting on the timer may try to acquire the lock.
        for (deadline, wakers) in expired {
            debug_assert!(deadline.0 <= Instant::now());
            for w in wakers {
                w.wake();
            }
        }

        Ok(())
    }
}

// A trait that represents any thread-local platform-specific state that needs to be held on behalf
// of the `Executor`.
pub(crate) trait PlatformState {
    // Indicates that the `Executor` is about to start processing futures that have been woken up.
    //
    // Implementations may use this as an indicator to skip unnecessary work when new tasks are
    // woken up as the `Executor` will eventually get around to processing them on its own.
    //
    // `start_processing` must return true if one or more futures were woken up since the last call
    // to `start_processing`. Otherwise it may return false.
    fn start_processing(&self) -> bool;

    // Returns a `WakerRef` that can be used to wake up the current thread.
    fn waker_ref(&self) -> WakerRef;

    // Waits for one or more futures to be woken up.
    //
    // This method should check with the underlying OS if any asynchronous IO operations have
    // completed and then wake up the associated futures.
    //
    // If `timeout` is provided then this method should block until either one or more futures are
    // woken up or the timeout duration elapses. If `timeout` has a zero duration then this method
    // should fetch completed asynchronous IO operations and then immediately return.
    //
    // If `timeout` is not provided then this method should block until one or more futures are
    // woken up.
    fn wait(&self, timeout: Option<Duration>) -> anyhow::Result<()>;
}

#[cfg(test)]
mod test {
    use super::*;

    use std::{
        convert::TryFrom,
        fs::OpenOptions,
        mem,
        pin::Pin,
        thread::{self, JoinHandle},
        time::Instant,
    };

    use futures::{
        channel::{mpsc, oneshot},
        future::{join3, select, Either},
        sink::SinkExt,
        stream::{self, FuturesUnordered, StreamExt},
    };

    use crate::{File, OwnedIoBuf};

    #[test]
    fn basic() {
        async fn do_it() {
            let (r, _w) = sys_util::pipe(true).unwrap();
            let done = async { 5usize };

            let rx = File::try_from(r).unwrap();
            let mut buf = 0u64.to_ne_bytes();
            let pending = rx.read(&mut buf, None);
            pin_mut!(pending, done);

            match select(pending, done).await {
                Either::Right((5, pending)) => drop(pending),
                _ => panic!("unexpected select result"),
            }
        }

        Executor::new().run_until(do_it()).unwrap();
    }

    #[derive(Default)]
    struct QuitShared {
        wakers: Vec<task::Waker>,
        should_quit: bool,
    }

    #[derive(Clone, Default)]
    struct Quit {
        shared: Arc<Mutex<QuitShared>>,
    }

    impl Quit {
        fn quit(self) {
            let wakers = {
                let mut shared = self.shared.lock();
                shared.should_quit = true;
                mem::take(&mut shared.wakers)
            };

            for w in wakers {
                w.wake();
            }
        }
    }

    impl Future for Quit {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
            let mut shared = self.shared.lock();
            if shared.should_quit {
                return Poll::Ready(());
            }

            if shared.wakers.iter().all(|w| !w.will_wake(cx.waker())) {
                shared.wakers.push(cx.waker().clone());
            }

            Poll::Pending
        }
    }

    #[test]
    fn outer_future_is_send() {
        const NUM_THREADS: usize = 3;
        const CHUNK_SIZE: usize = 32;

        async fn read_iobuf(
            ex: &Executor,
            f: File,
            buf: OwnedIoBuf,
        ) -> (anyhow::Result<usize>, OwnedIoBuf, File) {
            let (tx, rx) = oneshot::channel();
            ex.spawn_local(async move {
                let (res, buf) = f.read_iobuf(buf, None).await;
                let _ = tx.send((res, buf, f));
            })
            .detach();
            rx.await.unwrap()
        }

        async fn write_iobuf(
            ex: &Executor,
            f: File,
            buf: OwnedIoBuf,
        ) -> (anyhow::Result<usize>, OwnedIoBuf, File) {
            let (tx, rx) = oneshot::channel();
            ex.spawn_local(async move {
                let (res, buf) = f.write_iobuf(buf, None).await;
                let _ = tx.send((res, buf, f));
            })
            .detach();
            rx.await.unwrap()
        }

        async fn transfer_data(
            ex: Executor,
            mut from: File,
            mut to: File,
            len: usize,
        ) -> Result<usize> {
            let mut rem = len;
            let mut buf = OwnedIoBuf::new(vec![0xa2u8; CHUNK_SIZE]);
            while rem > 0 {
                let (res, data, f) = read_iobuf(&ex, from, buf).await;
                let count = res?;
                buf = data;
                from = f;
                if count == 0 {
                    // End of file. Return the number of bytes transferred.
                    return Ok(len - rem);
                }
                assert_eq!(count, CHUNK_SIZE);

                let (res, data, t) = write_iobuf(&ex, to, buf).await;
                let count = res?;
                buf = data;
                to = t;
                assert_eq!(count, CHUNK_SIZE);

                rem = rem.saturating_sub(count);
            }

            Ok(len)
        }

        fn do_it() -> anyhow::Result<()> {
            let ex = Executor::new();
            let (rx, tx) = sys_util::pipe(true)?;
            let zero = File::open("/dev/zero")?;
            let zero_bytes = CHUNK_SIZE * 7;
            let zero_to_pipe = ex.spawn(transfer_data(
                ex.clone(),
                zero,
                File::try_from(tx.try_clone()?)?,
                zero_bytes,
            ));

            let rand = File::open("/dev/urandom")?;
            let rand_bytes = CHUNK_SIZE * 19;
            let rand_to_pipe = ex.spawn(transfer_data(
                ex.clone(),
                rand,
                File::try_from(tx)?,
                rand_bytes,
            ));

            let null = OpenOptions::new().write(true).open("/dev/null")?;
            let null_bytes = zero_bytes + rand_bytes;
            let pipe_to_null = ex.spawn(transfer_data(
                ex.clone(),
                File::try_from(rx)?,
                File::try_from(null)?,
                null_bytes,
            ));

            let mut threads = Vec::with_capacity(NUM_THREADS);
            let quit = Quit::default();
            for _ in 0..NUM_THREADS {
                let thread_ex = ex.clone();
                let thread_quit = quit.clone();
                threads.push(thread::spawn(move || thread_ex.run_until(thread_quit)))
            }
            ex.run_until(join3(
                async { assert_eq!(pipe_to_null.await.unwrap(), null_bytes) },
                async { assert_eq!(zero_to_pipe.await.unwrap(), zero_bytes) },
                async { assert_eq!(rand_to_pipe.await.unwrap(), rand_bytes) },
            ))?;

            quit.quit();
            for t in threads {
                t.join().unwrap().unwrap();
            }

            Ok(())
        }

        do_it().unwrap();
    }

    #[test]
    fn thread_pool() {
        const NUM_THREADS: usize = 8;
        const NUM_CHANNELS: usize = 19;
        const NUM_ITERATIONS: usize = 71;

        let ex = Executor::new();

        let tasks = FuturesUnordered::new();
        let (mut tx, mut rx) = mpsc::channel(10);
        tasks.push(ex.spawn(async move {
            for i in 0..NUM_ITERATIONS {
                tx.send(i).await?;
            }

            Ok::<(), anyhow::Error>(())
        }));

        for _ in 0..NUM_CHANNELS {
            let (mut task_tx, task_rx) = mpsc::channel(10);
            tasks.push(ex.spawn(async move {
                while let Some(v) = rx.next().await {
                    task_tx.send(v).await?;
                }

                Ok::<(), anyhow::Error>(())
            }));

            rx = task_rx;
        }

        tasks.push(ex.spawn(async move {
            let mut zip = rx.zip(stream::iter(0..NUM_ITERATIONS));
            while let Some((l, r)) = zip.next().await {
                assert_eq!(l, r);
            }

            Ok::<(), anyhow::Error>(())
        }));

        let quit = Quit::default();
        let mut threads = Vec::with_capacity(NUM_THREADS);
        for _ in 0..NUM_THREADS {
            let thread_ex = ex.clone();
            let thread_quit = quit.clone();
            threads.push(thread::spawn(move || thread_ex.run_until(thread_quit)));
        }

        let results = ex
            .run_until(tasks.collect::<Vec<anyhow::Result<()>>>())
            .unwrap();
        results
            .into_iter()
            .collect::<anyhow::Result<Vec<()>>>()
            .unwrap();

        quit.quit();
        for t in threads {
            t.join().unwrap().unwrap();
        }
    }

    // Sends a message on `tx` once there is an idle worker in `Executor` or 5 seconds have passed.
    // Sends true if this function observed an idle worker and false otherwise.
    fn notify_on_idle_worker(ex: Executor, tx: oneshot::Sender<bool>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            // Wait for the main thread to add itself to the idle worker list.
            if !ex.shared.lock().idle_workers.is_empty() {
                break;
            }

            thread::sleep(Duration::from_millis(10));
        }

        if Instant::now() <= deadline {
            tx.send(true).unwrap();
        } else {
            tx.send(false).unwrap();
        }
    }

    #[test]
    fn wakeup_run_until() {
        let (tx, rx) = oneshot::channel();

        let ex = Executor::new();

        let thread_ex = ex.clone();
        let waker_thread = thread::spawn(move || notify_on_idle_worker(thread_ex, tx));

        // Since we're using `run_until` the wakeup path won't use the regular scheduling functions.
        let success = ex.run_until(rx).unwrap().unwrap();
        assert!(success);
        assert!(ex.shared.lock().idle_workers.is_empty());

        waker_thread.join().unwrap();
    }

    #[test]
    fn wakeup_local_task() {
        let (tx, rx) = oneshot::channel();

        let ex = Executor::new();

        let thread_ex = ex.clone();
        let waker_thread = thread::spawn(move || notify_on_idle_worker(thread_ex, tx));

        // By using `spawn_local`, the wakeup path will go via LOCAL_CTX.
        let task = ex.spawn_local(rx);
        let success = ex.run_until(task).unwrap().unwrap();
        assert!(success);
        assert!(ex.shared.lock().idle_workers.is_empty());

        waker_thread.join().unwrap();
    }

    #[test]
    fn wakeup_global_task() {
        let (tx, rx) = oneshot::channel();

        let ex = Executor::new();

        let thread_ex = ex.clone();
        let waker_thread = thread::spawn(move || notify_on_idle_worker(thread_ex, tx));

        // By using `spawn`, the wakeup path will go via `ex.shared`.
        let task = ex.spawn(rx);
        let success = ex.run_until(task).unwrap().unwrap();
        assert!(success);
        assert!(ex.shared.lock().idle_workers.is_empty());

        waker_thread.join().unwrap();
    }

    #[test]
    fn wake_up_correct_worker() {
        struct ThreadData {
            id: ThreadId,
            sender: mpsc::Sender<()>,
            handle: JoinHandle<anyhow::Result<()>>,
        }

        const NUM_THREADS: usize = 7;
        const NUM_ITERATIONS: usize = 119;

        let ex = Executor::new();

        let (tx, mut rx) = mpsc::channel(0);
        let mut threads = Vec::with_capacity(NUM_THREADS);
        for _ in 0..NUM_THREADS {
            let (sender, mut receiver) = mpsc::channel(0);
            let mut thread_tx = tx.clone();
            let thread_ex = ex.clone();
            let handle = thread::spawn(move || {
                let id = thread::current().id();
                thread_ex
                    .run_until(async move {
                        while let Some(()) = receiver.next().await {
                            thread_tx.send(id).await?;
                        }

                        Ok(())
                    })
                    .unwrap()
            });

            let id = handle.thread().id();
            threads.push(ThreadData { id, sender, handle });
        }

        ex.run_until(async {
            for i in 0..NUM_ITERATIONS {
                let data = &mut threads[i % NUM_THREADS];
                data.sender.send(()).await?;
                assert_eq!(rx.next().await.unwrap(), data.id);
            }

            Ok::<(), anyhow::Error>(())
        })
        .unwrap()
        .unwrap();

        for t in threads {
            let ThreadData { id, sender, handle } = t;

            // Dropping the sender will close the channel and cause the thread to exit.
            drop((id, sender));
            handle.join().unwrap().unwrap();
        }
    }
}
