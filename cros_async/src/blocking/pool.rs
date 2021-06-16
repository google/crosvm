// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    collections::VecDeque,
    mem,
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};

use async_task::{Runnable, Task};
use slab::Slab;
use sync::{Condvar, Mutex};

#[derive(Default)]
struct State {
    tasks: VecDeque<Runnable>,
    num_threads: usize,
    num_idle: usize,
    worker_threads: Slab<JoinHandle<()>>,
    last_exited_thread: Option<JoinHandle<()>>,
    shutting_down: bool,
}

fn run_blocking_thread(idx: usize, inner: Arc<Inner>) {
    let mut state = inner.state.lock();
    while !state.shutting_down {
        if let Some(runnable) = state.tasks.pop_front() {
            drop(state);
            runnable.run();
            state = inner.state.lock();
            continue;
        }

        // No more tasks so wait for more work.
        state.num_idle += 1;

        let (guard, result) = inner
            .condvar
            .wait_timeout_while(state, inner.keepalive, |s| {
                !s.shutting_down && s.tasks.is_empty()
            });
        state = guard;

        // Only decrement the idle count if we timed out. Otherwise, it was decremented when new
        // work was added to `state.tasks`.
        if result.timed_out() {
            state.num_idle -= 1;
            break;
        }
    }

    state.num_threads -= 1;

    // If we're shutting down then the BlockingPool will take care of joining all the threads.
    // Otherwise, we need to join the last worker thread that exited here.
    let last_exited_thread = if !state.shutting_down {
        let this_thread = state.worker_threads.remove(idx);
        mem::replace(&mut state.last_exited_thread, Some(this_thread))
    } else {
        None
    };

    // Drop the lock before trying to join the last exited thread.
    drop(state);

    if let Some(handle) = last_exited_thread {
        let _ = handle.join();
    }
}

struct Inner {
    state: Mutex<State>,
    condvar: Condvar,
    max_threads: usize,
    keepalive: Duration,
}

impl Inner {
    fn schedule(self: &Arc<Inner>, runnable: Runnable) {
        let mut state = self.state.lock();

        // If we're shutting down then nothing is going to run this task.
        if state.shutting_down {
            return;
        }

        state.tasks.push_back(runnable);

        if state.num_idle == 0 {
            // There are no idle threads.  Spawn a new one if possible.
            if state.num_threads < self.max_threads {
                state.num_threads += 1;
                let entry = state.worker_threads.vacant_entry();
                let idx = entry.key();
                let inner = self.clone();
                entry.insert(thread::spawn(move || run_blocking_thread(idx, inner)));
            }
        } else {
            // We have idle threads, wake one up.
            state.num_idle -= 1;
            self.condvar.notify_one();
        }
    }
}

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
/// `BlockingPool` and dropping or shutting down the pool will block until all worker threads finish
/// their current task.
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
        BlockingPool {
            inner: Arc::new(Inner {
                state: Default::default(),
                condvar: Condvar::new(),
                max_threads,
                keepalive,
            }),
        }
    }

    /// Like new but with pre-allocating capacity for up to `max_threads`.
    pub fn with_capacity(max_threads: usize, keepalive: Duration) -> BlockingPool {
        BlockingPool {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    tasks: VecDeque::new(),
                    num_threads: 0,
                    num_idle: 0,
                    worker_threads: Slab::with_capacity(max_threads),
                    last_exited_thread: None,
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
    /// Callers may `await` the returned `Task` to be notified when the work is completed.
    ///
    /// # Panics
    ///
    /// `await`ing a `Task` after dropping the `BlockingPool` or calling `BlockingPool::shutdown`
    /// will panic if the work was not completed before the pool was shut down.
    pub fn spawn<F, R>(&self, f: F) -> Task<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let raw = Arc::downgrade(&self.inner);
        let schedule = move |runnable| {
            if let Some(i) = raw.upgrade() {
                i.schedule(runnable);
            }
        };

        let (runnable, task) = async_task::spawn(async move { f() }, schedule);
        runnable.schedule();

        task
    }

    /// Shut down the `BlockingPool`.
    ///
    /// This will block until all work that has been started by the worker threads is finished. Any
    /// work that was added to the `BlockingPool` but not yet picked up by a worker thread will not
    /// complete and `await`ing on the `Task` for that work will panic.
    pub fn shutdown(&self) {
        let mut state = self.inner.state.lock();

        if state.shutting_down {
            // We've already shut down this BlockingPool.
            return;
        }

        state.shutting_down = true;
        let last_exited_thread = state.last_exited_thread.take();
        let unfinished_tasks = mem::replace(&mut state.tasks, VecDeque::new());
        let mut worker_threads = mem::replace(&mut state.worker_threads, Slab::new());
        drop(state);

        self.inner.condvar.notify_all();

        // Cancel any unfinished work after releasing the lock.
        drop(unfinished_tasks);

        // Now wait for all worker threads to exit.
        if let Some(handle) = last_exited_thread {
            let _ = handle.join();
        }

        for handle in worker_threads.drain() {
            let _ = handle.join();
        }
    }
}

impl Default for BlockingPool {
    fn default() -> BlockingPool {
        BlockingPool::new(256, Duration::from_secs(10))
    }
}

impl Drop for BlockingPool {
    fn drop(&mut self) {
        self.shutdown()
    }
}

#[cfg(test)]
mod test {
    use std::{
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };

    use futures::{stream::FuturesUnordered, StreamExt};
    use sync::{Condvar, Mutex};

    use crate::{block_on, BlockingPool};

    #[test]
    fn blocking_sleep() {
        let pool = BlockingPool::default();

        let res = block_on(pool.spawn(|| 42));
        assert_eq!(res, 42);
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

        pool.shutdown();
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
        pool.spawn(move || {
            let mut ready = task_mu.lock();
            while !*ready {
                ready = task_cv.wait(ready);
            }
        })
        .detach();

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
        pool.shutdown();

        // This should panic.
        assert_eq!(block_on(unfinished), 5);
    }
}
