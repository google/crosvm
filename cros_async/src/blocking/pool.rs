// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::future::Future;
use std::mem;
use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use base::error;
use base::warn;
use futures::channel::oneshot;
use slab::Slab;
use sync::Condvar;
use sync::Mutex;

const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

struct State {
    tasks: VecDeque<Box<dyn FnOnce() + Send>>,
    num_threads: usize,
    num_idle: usize,
    num_notified: usize,
    worker_threads: Slab<JoinHandle<()>>,
    exited_threads: Option<Receiver<usize>>,
    exit: Sender<usize>,
    shutting_down: bool,
}

fn run_blocking_thread(idx: usize, inner: Arc<Inner>, exit: Sender<usize>) {
    let mut state = inner.state.lock();
    while !state.shutting_down {
        if let Some(f) = state.tasks.pop_front() {
            drop(state);
            f();
            state = inner.state.lock();
            continue;
        }

        // No more tasks so wait for more work.
        state.num_idle += 1;

        let (guard, result) = inner
            .condvar
            .wait_timeout_while(state, inner.keepalive, |s| {
                !s.shutting_down && s.num_notified == 0
            });
        state = guard;

        // If `state.num_notified > 0` then this was a real wakeup.
        if state.num_notified > 0 {
            state.num_notified -= 1;
            continue;
        }

        // Only decrement the idle count if we timed out. Otherwise, it was decremented when new
        // work was added to `state.tasks`.
        if result.timed_out() {
            state.num_idle = state
                .num_idle
                .checked_sub(1)
                .expect("`num_idle` underflow on timeout");
            break;
        }
    }

    state.num_threads -= 1;

    // If we're shutting down then the BlockingPool will take care of joining all the threads.
    // Otherwise, we need to join the last worker thread that exited here.
    let last_exited_thread = if let Some(exited_threads) = state.exited_threads.as_mut() {
        exited_threads
            .try_recv()
            .map(|idx| state.worker_threads.remove(idx))
            .ok()
    } else {
        None
    };

    // Drop the lock before trying to join the last exited thread.
    drop(state);

    if let Some(handle) = last_exited_thread {
        let _ = handle.join();
    }

    if let Err(e) = exit.send(idx) {
        error!("Failed to send thread exit event on channel: {}", e);
    }
}

struct Inner {
    state: Mutex<State>,
    condvar: Condvar,
    max_threads: usize,
    keepalive: Duration,
}

impl Inner {
    pub fn spawn<F, R>(self: &Arc<Self>, f: F) -> impl Future<Output = R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let mut state = self.state.lock();

        // If we're shutting down then nothing is going to run this task.
        if state.shutting_down {
            error!("spawn called after shutdown");
            return futures::future::Either::Left(async {
                panic!("tried to poll BlockingPool task after shutdown")
            });
        }

        let (send_chan, recv_chan) = oneshot::channel();
        state.tasks.push_back(Box::new(|| {
            let _ = send_chan.send(f());
        }));

        if state.num_idle == 0 {
            // There are no idle threads.  Spawn a new one if possible.
            if state.num_threads < self.max_threads {
                state.num_threads += 1;
                let exit = state.exit.clone();
                let entry = state.worker_threads.vacant_entry();
                let idx = entry.key();
                let inner = self.clone();
                entry.insert(
                    thread::Builder::new()
                        .name(format!("blockingPool{}", idx))
                        .spawn(move || run_blocking_thread(idx, inner, exit))
                        .unwrap(),
                );
            }
        } else {
            // We have idle threads, wake one up.
            state.num_idle -= 1;
            state.num_notified += 1;
            self.condvar.notify_one();
        }

        futures::future::Either::Right(async {
            recv_chan
                .await
                .expect("BlockingThread task unexpectedly cancelled")
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0} BlockingPool threads did not exit in time and will be detached")]
pub struct ShutdownTimedOut(usize);

/// A thread pool for running work that may block.
///
/// It is generally discouraged to do any blocking work inside an async function. However, this is
/// sometimes unavoidable when dealing with interfaces that don't provide async variants. In this
/// case callers may use the `BlockingPool` to run the blocking work on a different thread and
/// `await` for its result to finish, which will prevent blocking the main thread of the
/// application.
///
/// Since the blocking work is sent to another thread, users should be careful when using the
/// `BlockingPool` for latency-sensitive operations. Additionally, the `BlockingPool` is intended to
/// be used for work that will eventually complete on its own. Users who want to spawn a thread
/// should just use `thread::spawn` directly.
///
/// There is no way to cancel work once it has been picked up by one of the worker threads in the
/// `BlockingPool`. Dropping or shutting down the pool will block up to a timeout (default 10
/// seconds) to wait for any active blocking work to finish. Any threads running tasks that have not
/// completed by that time will be detached.
///
/// # Examples
///
/// Spawn a task to run in the `BlockingPool` and await on its result.
///
/// ```edition2018
/// use cros_async::BlockingPool;
///
/// # async fn do_it() {
///     let pool = BlockingPool::default();
///
///     let res = pool.spawn(move || {
///         // Do some CPU-intensive or blocking work here.
///
///         42
///     }).await;
///
///     assert_eq!(res, 42);
/// # }
/// # cros_async::block_on(do_it());
/// ```
pub struct BlockingPool {
    inner: Arc<Inner>,
}

impl BlockingPool {
    /// Create a new `BlockingPool`.
    ///
    /// The `BlockingPool` will never spawn more than `max_threads` threads to do work, regardless
    /// of the number of tasks that are added to it. This value should be set relatively low (for
    /// example, the number of CPUs on the machine) if the pool is intended to run CPU intensive
    /// work or it should be set relatively high (128 or more) if the pool is intended to be used
    /// for various IO operations that cannot be completed asynchronously. The default value is 256.
    ///
    /// Worker threads are spawned on demand when new work is added to the pool and will
    /// automatically exit after being idle for some time so there is no overhead for setting
    /// `max_threads` to a large value when there is little to no work assigned to the
    /// `BlockingPool`. `keepalive` determines the idle duration after which the worker thread will
    /// exit. The default value is 10 seconds.
    pub fn new(max_threads: usize, keepalive: Duration) -> BlockingPool {
        let (exit, exited_threads) = channel();
        BlockingPool {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    tasks: VecDeque::new(),
                    num_threads: 0,
                    num_idle: 0,
                    num_notified: 0,
                    worker_threads: Slab::new(),
                    exited_threads: Some(exited_threads),
                    exit,
                    shutting_down: false,
                }),
                condvar: Condvar::new(),
                max_threads,
                keepalive,
            }),
        }
    }

    /// Like new but with pre-allocating capacity for up to `max_threads`.
    pub fn with_capacity(max_threads: usize, keepalive: Duration) -> BlockingPool {
        let (exit, exited_threads) = channel();
        BlockingPool {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    tasks: VecDeque::new(),
                    num_threads: 0,
                    num_idle: 0,
                    num_notified: 0,
                    worker_threads: Slab::with_capacity(max_threads),
                    exited_threads: Some(exited_threads),
                    exit,
                    shutting_down: false,
                }),
                condvar: Condvar::new(),
                max_threads,
                keepalive,
            }),
        }
    }

    /// Spawn a task to run in the `BlockingPool`.
    ///
    /// Callers may `await` the returned `Future` to be notified when the work is completed.
    /// Dropping the future will not cancel the task.
    ///
    /// # Panics
    ///
    /// `await`ing a `Task` after dropping the `BlockingPool` or calling `BlockingPool::shutdown`
    /// will panic if the work was not completed before the pool was shut down.
    pub fn spawn<F, R>(&self, f: F) -> impl Future<Output = R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.inner.spawn(f)
    }

    /// Shut down the `BlockingPool`.
    ///
    /// If `deadline` is provided then this will block until either all worker threads exit or the
    /// deadline is exceeded. If `deadline` is not given then this will block indefinitely until all
    /// worker threads exit. Any work that was added to the `BlockingPool` but not yet picked up by
    /// a worker thread will not complete and `await`ing on the `Task` for that work will panic.
    pub fn shutdown(&self, deadline: Option<Instant>) -> Result<(), ShutdownTimedOut> {
        let mut state = self.inner.state.lock();

        if state.shutting_down {
            // We've already shut down this BlockingPool.
            return Ok(());
        }

        state.shutting_down = true;
        let exited_threads = state.exited_threads.take().expect("exited_threads missing");
        let unfinished_tasks = std::mem::take(&mut state.tasks);
        let mut worker_threads = mem::replace(&mut state.worker_threads, Slab::new());
        drop(state);

        self.inner.condvar.notify_all();

        // Cancel any unfinished work after releasing the lock.
        drop(unfinished_tasks);

        // Now wait for all worker threads to exit.
        if let Some(deadline) = deadline {
            let mut now = Instant::now();
            while now < deadline && !worker_threads.is_empty() {
                if let Ok(idx) = exited_threads.recv_timeout(deadline - now) {
                    let _ = worker_threads.remove(idx).join();
                }
                now = Instant::now();
            }

            // Any threads that have not yet joined will just be detached.
            if !worker_threads.is_empty() {
                return Err(ShutdownTimedOut(worker_threads.len()));
            }

            Ok(())
        } else {
            // Block indefinitely until all worker threads exit.
            for handle in worker_threads.drain() {
                let _ = handle.join();
            }

            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn shutting_down(&self) -> bool {
        self.inner.state.lock().shutting_down
    }
}

impl Default for BlockingPool {
    fn default() -> BlockingPool {
        BlockingPool::new(256, Duration::from_secs(10))
    }
}

impl Drop for BlockingPool {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown(Some(Instant::now() + DEFAULT_SHUTDOWN_TIMEOUT)) {
            warn!("{}", e);
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;
    use std::time::Instant;

    use futures::executor::block_on;
    use futures::stream::FuturesUnordered;
    use futures::StreamExt;
    use sync::Condvar;
    use sync::Mutex;

    use super::super::super::BlockingPool;

    #[test]
    fn blocking_sleep() {
        let pool = BlockingPool::default();

        let res = block_on(pool.spawn(|| 42));
        assert_eq!(res, 42);
    }

    #[test]
    fn drop_doesnt_block() {
        let pool = BlockingPool::default();
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        // The blocking work should continue even though we drop the future.
        //
        // If we cancelled the work, then the recv call would fail. If we blocked on the work, then
        // the send would never complete because the channel is size zero and so waits for a
        // matching recv call.
        std::mem::drop(pool.spawn(move || tx.send(()).unwrap()));
        rx.recv().unwrap();
    }

    #[test]
    fn fast_tasks_with_short_keepalive() {
        let pool = BlockingPool::new(256, Duration::from_millis(1));

        let streams = FuturesUnordered::new();
        for _ in 0..2 {
            for _ in 0..256 {
                let task = pool.spawn(|| ());
                streams.push(task);
            }

            thread::sleep(Duration::from_millis(1));
        }

        block_on(streams.collect::<Vec<_>>());

        // The test passes if there are no panics, which would happen if one of the worker threads
        // triggered an underflow on `pool.inner.state.num_idle`.
    }

    #[test]
    fn more_tasks_than_threads() {
        let pool = BlockingPool::new(4, Duration::from_secs(10));

        let stream = (0..19)
            .map(|_| pool.spawn(|| thread::sleep(Duration::from_millis(5))))
            .collect::<FuturesUnordered<_>>();

        let results = block_on(stream.collect::<Vec<_>>());
        assert_eq!(results.len(), 19);
    }

    #[test]
    fn shutdown() {
        let pool = BlockingPool::default();

        let stream = (0..19)
            .map(|_| pool.spawn(|| thread::sleep(Duration::from_millis(5))))
            .collect::<FuturesUnordered<_>>();

        let results = block_on(stream.collect::<Vec<_>>());
        assert_eq!(results.len(), 19);

        pool.shutdown(Some(Instant::now() + Duration::from_secs(10)))
            .unwrap();
        let state = pool.inner.state.lock();
        assert_eq!(state.num_threads, 0);
    }

    #[test]
    fn keepalive_timeout() {
        // Set the keepalive to a very low value so that threads will exit soon after they run out
        // of work.
        let pool = BlockingPool::new(7, Duration::from_millis(1));

        let stream = (0..19)
            .map(|_| pool.spawn(|| thread::sleep(Duration::from_millis(5))))
            .collect::<FuturesUnordered<_>>();

        let results = block_on(stream.collect::<Vec<_>>());
        assert_eq!(results.len(), 19);

        // Wait for all threads to exit.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
            let state = pool.inner.state.lock();
            if state.num_threads == 0 {
                break;
            }
        }

        {
            let state = pool.inner.state.lock();
            assert_eq!(state.num_threads, 0);
            assert_eq!(state.num_idle, 0);
        }
    }

    #[test]
    #[should_panic]
    fn shutdown_with_pending_work() {
        let pool = BlockingPool::new(1, Duration::from_secs(10));

        let mu = Arc::new(Mutex::new(false));
        let cv = Arc::new(Condvar::new());

        // First spawn a thread that blocks the pool.
        let task_mu = mu.clone();
        let task_cv = cv.clone();
        let _blocking_task = pool.spawn(move || {
            let mut ready = task_mu.lock();
            while !*ready {
                ready = task_cv.wait(ready);
            }
        });

        // This task will never finish because we will shut down the pool first.
        let unfinished = pool.spawn(|| 5);

        // Spawn a thread to unblock the work we started earlier once it sees that the pool is
        // shutting down.
        let inner = pool.inner.clone();
        thread::spawn(move || {
            let mut state = inner.state.lock();
            while !state.shutting_down {
                state = inner.condvar.wait(state);
            }

            *mu.lock() = true;
            cv.notify_all();
        });
        pool.shutdown(None).unwrap();

        // This should panic.
        assert_eq!(block_on(unfinished), 5);
    }

    #[test]
    fn unfinished_worker_thread() {
        let pool = BlockingPool::default();

        let ready = Arc::new(Mutex::new(false));
        let cv = Arc::new(Condvar::new());
        let barrier = Arc::new(Barrier::new(2));

        let thread_ready = ready.clone();
        let thread_barrier = barrier.clone();
        let thread_cv = cv.clone();

        let task = pool.spawn(move || {
            thread_barrier.wait();
            let mut ready = thread_ready.lock();
            while !*ready {
                ready = thread_cv.wait(ready);
            }
        });

        // Wait to shut down the pool until after the worker thread has started.
        barrier.wait();
        pool.shutdown(Some(Instant::now() + Duration::from_millis(5)))
            .unwrap_err();

        let num_threads = pool.inner.state.lock().num_threads;
        assert_eq!(num_threads, 1);

        // Now wake up the blocked task so we don't leak the thread.
        *ready.lock() = true;
        cv.notify_all();

        block_on(task);

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
            let state = pool.inner.state.lock();
            if state.num_threads == 0 {
                break;
            }
        }

        {
            let state = pool.inner.state.lock();
            assert_eq!(state.num_threads, 0);
            assert_eq!(state.num_idle, 0);
        }
    }
}
