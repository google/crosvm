// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides an async blocking pool whose tasks can be cancelled.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use once_cell::sync::Lazy;
use sync::Condvar;
use sync::Mutex;
use thiserror::Error as ThisError;

use crate::BlockingPool;

/// Global executor.
///
/// This is convenient, though not preferred. Pros/cons:
/// + It avoids passing executor all the way to each call sites.
/// + The call site can assume that executor will never shutdown.
/// + Provides similar functionality as async_task with a few improvements
///   around ability to cancel.
/// - Globals are harder to reason about.
static EXECUTOR: Lazy<CancellableBlockingPool> =
    Lazy::new(|| CancellableBlockingPool::new(256, Duration::from_secs(10)));

const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(PartialEq, Eq, PartialOrd, Default)]
enum WindDownStates {
    #[default]
    Armed,
    Disarmed,
    ShuttingDown,
    ShutDown,
}

#[derive(Default)]
struct State {
    wind_down: WindDownStates,

    /// Helps to generate unique id to associate `cancel` with task.
    current_cancellable_id: u64,

    /// A map of all the `cancel` routines of queued/in-flight tasks.
    cancellables: HashMap<u64, Box<dyn Fn() + Send + 'static>>,
}

#[derive(Debug, Clone, Copy)]
pub enum TimeoutAction {
    /// Do nothing on timeout.
    None,
    /// Panic the thread on timeout.
    Panic,
}

#[derive(ThisError, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("Timeout occurred while trying to join threads")]
    Timedout,
    #[error("Shutdown is in progress")]
    ShutdownInProgress,
    #[error("Already shut down")]
    AlreadyShutdown,
}

struct Inner {
    blocking_pool: BlockingPool,
    state: Mutex<State>,

    /// This condvar gets notified when `cancellables` is empty after removing an
    /// entry.
    cancellables_cv: Condvar,
}

impl Inner {
    pub fn spawn<F, R>(self: &Arc<Self>, f: F) -> impl Future<Output = R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.blocking_pool.spawn(f)
    }

    /// Adds cancel to a cancellables and returns an `id` with which `cancel` can be
    /// accessed/removed.
    fn add_cancellable(&self, cancel: Box<dyn Fn() + Send + 'static>) -> u64 {
        let mut state = self.state.lock();
        let id = state.current_cancellable_id;
        state.current_cancellable_id += 1;
        state.cancellables.insert(id, cancel);
        id
    }
}

/// A thread pool for running work that may block.
///
/// This is a wrapper around `BlockingPool` with an ability to cancel queued tasks.
/// See [BlockingPool] for more info.
///
/// # Examples
///
/// Spawn a task to run in the `CancellableBlockingPool` and await on its result.
///
/// ```edition2018
/// use cros_async::CancellableBlockingPool;
///
/// # async fn do_it() {
///     let pool = CancellableBlockingPool::default();
///     let CANCELLED = 0;
///
///     let res = pool.spawn(move || {
///         // Do some CPU-intensive or blocking work here.
///
///         42
///     }, move || CANCELLED).await;
///
///     assert_eq!(res, 42);
/// # }
/// # futures::executor::block_on(do_it());
/// ```
#[derive(Clone)]
pub struct CancellableBlockingPool {
    inner: Arc<Inner>,
}

impl CancellableBlockingPool {
    const RETRY_COUNT: usize = 10;
    const SLEEP_DURATION: Duration = Duration::from_millis(100);

    /// Create a new `CancellableBlockingPool`.
    ///
    /// When we try to shutdown or drop `CancellableBlockingPool`, it may happen that a hung thread
    /// might prevent `CancellableBlockingPool` pool from getting dropped. On failure to shutdown in
    /// `watchdog_opts.timeout` duration, `CancellableBlockingPool` can take an action specified by
    /// `watchdog_opts.action`.
    ///
    /// See also: [BlockingPool::new()](BlockingPool::new)
    pub fn new(max_threads: usize, keepalive: Duration) -> CancellableBlockingPool {
        CancellableBlockingPool {
            inner: Arc::new(Inner {
                blocking_pool: BlockingPool::new(max_threads, keepalive),
                state: Default::default(),
                cancellables_cv: Condvar::new(),
            }),
        }
    }

    /// Like [Self::new] but with pre-allocating capacity for up to `max_threads`.
    pub fn with_capacity(max_threads: usize, keepalive: Duration) -> CancellableBlockingPool {
        CancellableBlockingPool {
            inner: Arc::new(Inner {
                blocking_pool: BlockingPool::with_capacity(max_threads, keepalive),
                state: Mutex::new(State::default()),
                cancellables_cv: Condvar::new(),
            }),
        }
    }

    /// Spawn a task to run in the `CancellableBlockingPool`.
    ///
    /// Callers may `await` the returned `Task` to be notified when the work is completed.
    /// Dropping the future will not cancel the task.
    ///
    /// `cancel` helps to cancel a queued or in-flight operation `f`.
    /// `cancel` may be called more than once if `f` doesn't respond to `cancel`.
    /// `cancel` is not called if `f` completes successfully. For example,
    /// # Examples
    ///
    /// ```edition2018
    /// use {cros_async::CancellableBlockingPool, std::sync::{Arc, Mutex, Condvar}};
    ///
    /// # async fn cancel_it() {
    ///    let pool = CancellableBlockingPool::default();
    ///    let cancelled: i32 = 1;
    ///    let success: i32 = 2;
    ///
    ///    let shared = Arc::new((Mutex::new(0), Condvar::new()));
    ///    let shared2 = shared.clone();
    ///    let shared3 = shared.clone();
    ///
    ///    let res = pool
    ///        .spawn(
    ///            move || {
    ///                let guard = shared.0.lock().unwrap();
    ///                let mut guard = shared.1.wait_while(guard, |state| *state == 0).unwrap();
    ///                if *guard != cancelled {
    ///                    *guard = success;
    ///                }
    ///            },
    ///            move || {
    ///                *shared2.0.lock().unwrap() = cancelled;
    ///                shared2.1.notify_all();
    ///            },
    ///        )
    ///        .await;
    ///    pool.shutdown();
    ///
    ///    assert_eq!(*shared3.0.lock().unwrap(), cancelled);
    /// # }
    /// ```
    pub fn spawn<F, R, G>(&self, f: F, cancel: G) -> impl Future<Output = R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
        G: Fn() -> R + Send + 'static,
    {
        let inner = self.inner.clone();
        let cancelled = Arc::new(Mutex::new(None));
        let cancelled_spawn = cancelled.clone();
        let id = inner.add_cancellable(Box::new(move || {
            let mut c = cancelled.lock();
            *c = Some(cancel());
        }));

        self.inner.spawn(move || {
            if let Some(res) = cancelled_spawn.lock().take() {
                return res;
            }
            let ret = f();
            let mut state = inner.state.lock();
            state.cancellables.remove(&id);
            if state.cancellables.is_empty() {
                inner.cancellables_cv.notify_one();
            }
            ret
        })
    }

    /// Iterates over all the queued tasks and marks them as cancelled.
    fn drain_cancellables(&self) {
        let mut state = self.inner.state.lock();
        // Iterate a few times to try cancelling all the tasks.
        for _ in 0..Self::RETRY_COUNT {
            // Nothing left to do.
            if state.cancellables.is_empty() {
                return;
            }

            // We only cancel the task and do not remove it from the cancellables. It is runner's
            // job to remove from state.cancellables.
            for cancel in state.cancellables.values() {
                cancel();
            }
            // Hold the state lock in a block before sleeping so that woken up threads can get to
            // hold the lock.
            // Wait for a while so that the threads get a chance complete task in flight.
            let (state1, _cv_timeout) = self
                .inner
                .cancellables_cv
                .wait_timeout(state, Self::SLEEP_DURATION);
            state = state1;
        }
    }

    /// Marks all the queued and in-flight tasks as cancelled. Any tasks queued after `disarm`ing
    /// will be cancelled.
    /// Does not wait for all the tasks to get cancelled.
    pub fn disarm(&self) {
        {
            let mut state = self.inner.state.lock();

            if state.wind_down >= WindDownStates::Disarmed {
                return;
            }

            // At this point any new incoming request will be cancelled when run.
            state.wind_down = WindDownStates::Disarmed;
        }
        self.drain_cancellables();
    }

    /// Shut down the `CancellableBlockingPool`.
    ///
    /// This will block until all work that has been started by the worker threads is finished. Any
    /// work that was added to the `CancellableBlockingPool` but not yet picked up by a worker
    /// thread will not complete and `await`ing on the `Task` for that work will panic.
    ///
    pub fn shutdown(&self) -> Result<(), Error> {
        self.shutdown_with_timeout(DEFAULT_SHUTDOWN_TIMEOUT)
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> Result<(), Error> {
        self.disarm();
        {
            let mut state = self.inner.state.lock();
            if state.wind_down == WindDownStates::ShuttingDown {
                return Err(Error::ShutdownInProgress);
            }
            if state.wind_down == WindDownStates::ShutDown {
                return Err(Error::AlreadyShutdown);
            }
            state.wind_down = WindDownStates::ShuttingDown;
        }

        let res = self
            .inner
            .blocking_pool
            .shutdown(/* deadline: */ Some(Instant::now() + timeout));

        self.inner.state.lock().wind_down = WindDownStates::ShutDown;
        match res {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::Timedout),
        }
    }
}

impl Default for CancellableBlockingPool {
    fn default() -> CancellableBlockingPool {
        CancellableBlockingPool::new(256, Duration::from_secs(10))
    }
}

impl Drop for CancellableBlockingPool {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            base::error!("CancellableBlockingPool::shutdown failed: {}", e);
        }
    }
}

/// Spawn a task to run in the `CancellableBlockingPool` static executor.
///
/// `cancel` in-flight operation. cancel is called on operation during `disarm` or during
/// `shutdown`.  Cancel may be called multiple times if running task doesn't get cancelled on first
/// attempt.
///
/// Callers may `await` the returned `Task` to be notified when the work is completed.
///
/// See also: `spawn`.
pub fn unblock<F, R, G>(f: F, cancel: G) -> impl Future<Output = R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
    G: Fn() -> R + Send + 'static,
{
    EXECUTOR.spawn(f, cancel)
}

/// Marks all the queued and in-flight tasks as cancelled. Any tasks queued after `disarm`ing
/// will be cancelled.
/// Doesn't not wait for all the tasks to get cancelled.
pub fn unblock_disarm() {
    EXECUTOR.disarm()
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;

    use futures::executor::block_on;
    use sync::Condvar;
    use sync::Mutex;

    use crate::blocking::Error;
    use crate::CancellableBlockingPool;

    #[test]
    fn disarm_with_pending_work() {
        // Create a pool with only one thread.
        let pool = CancellableBlockingPool::new(1, Duration::from_secs(10));

        let mu = Arc::new(Mutex::new(false));
        let cv = Arc::new(Condvar::new());
        let blocker_is_running = Arc::new(Barrier::new(2));

        // First spawn a thread that blocks the pool.
        let task_mu = mu.clone();
        let task_cv = cv.clone();
        let task_blocker_is_running = blocker_is_running.clone();
        let _blocking_task = pool.spawn(
            move || {
                task_blocker_is_running.wait();
                let mut ready = task_mu.lock();
                while !*ready {
                    ready = task_cv.wait(ready);
                }
            },
            move || {},
        );

        // Wait for the worker to start running the blocking thread.
        blocker_is_running.wait();

        // This task will never finish because we will disarm the pool first.
        let unfinished = pool.spawn(|| 5, || 0);

        // Disarming should cancel the task.
        pool.disarm();

        // Shutdown the blocking thread. This will allow a worker to pick up the task that has
        // to be cancelled.
        *mu.lock() = true;
        cv.notify_all();

        // We expect the cancelled value to be returned.
        assert_eq!(block_on(unfinished), 0);

        // Now the pool is empty and can be shutdown without blocking.
        pool.shutdown().unwrap();
    }

    #[test]
    fn shutdown_with_blocked_work_should_timeout() {
        let pool = CancellableBlockingPool::new(1, Duration::from_secs(10));

        let running = Arc::new((Mutex::new(false), Condvar::new()));
        let running1 = running.clone();
        let _blocking_task = pool.spawn(
            move || {
                *running1.0.lock() = true;
                running1.1.notify_one();
                thread::sleep(Duration::from_secs(10000));
            },
            move || {},
        );

        let mut is_running = running.0.lock();
        while !*is_running {
            is_running = running.1.wait(is_running);
        }

        // This shutdown will wait for the full timeout period, so use a short timeout.
        assert_eq!(
            pool.shutdown_with_timeout(Duration::from_millis(1)),
            Err(Error::Timedout)
        );
    }

    #[test]
    fn multiple_shutdown_returns_error() {
        let pool = CancellableBlockingPool::new(1, Duration::from_secs(10));
        let _ = pool.shutdown();
        assert_eq!(pool.shutdown(), Err(Error::AlreadyShutdown));
    }

    #[test]
    fn shutdown_in_progress() {
        let pool = CancellableBlockingPool::new(1, Duration::from_secs(10));

        let running = Arc::new((Mutex::new(false), Condvar::new()));
        let running1 = running.clone();
        let _blocking_task = pool.spawn(
            move || {
                *running1.0.lock() = true;
                running1.1.notify_one();
                thread::sleep(Duration::from_secs(10000));
            },
            move || {},
        );

        let mut is_running = running.0.lock();
        while !*is_running {
            is_running = running.1.wait(is_running);
        }

        let pool_clone = pool.clone();
        thread::spawn(move || {
            while !pool_clone.inner.blocking_pool.shutting_down() {}
            assert_eq!(pool_clone.shutdown(), Err(Error::ShutdownInProgress));
        });

        // This shutdown will wait for the full timeout period, so use a short timeout.
        // However, it also needs to wait long enough for the thread spawned above to observe the
        // shutting_down state, so don't make it too short.
        assert_eq!(
            pool.shutdown_with_timeout(Duration::from_millis(200)),
            Err(Error::Timedout)
        );
    }
}
