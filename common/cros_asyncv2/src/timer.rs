// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use futures::{
    future::{select, Either},
    pin_mut,
};
use thiserror::Error as ThisError;

use crate::executor;

/// A timer that expires at a specific time.
#[derive(Debug, Clone)]
pub struct Timer {
    deadline: Instant,
}

impl Timer {
    /// Start a timer that will expire at `deadline`.
    ///
    /// This function only guarantees that the timer will not expire before `deadline`. The actual
    /// elapsed time may be much longer depending on various factors such as the current load in the
    /// application as well as the OS scheduler.
    ///
    /// If `deadline` is in the future then any tasks await-ing on this `Timer` will only be
    /// notified if it is created on a thread that is currently running or will run the
    /// `Executor::run` or `Executor::run_until` methods.
    ///
    /// The returned `Timer` can be cheaply cloned and all clones will share the same deadline.
    ///
    /// # Examples
    ///
    /// Put the current task to sleep for 10 milliseconds.
    ///
    /// ```
    /// # use std::time::{Duration, Instant};
    /// # use cros_async::{Timer, Executor};
    /// #
    /// # async fn sleep() {
    ///     Timer::new(Instant::now() + Duration::from_millis(10)).await;
    /// # }
    /// #
    /// # let ex = Executor::new();
    /// # let start = Instant::now();
    /// # ex.run_until(sleep()).unwrap();
    /// # assert!(start.elapsed() >= Duration::from_millis(10));
    /// ```
    pub fn new(deadline: Instant) -> Timer {
        Timer { deadline }
    }

    /// Returns the time at which this `Timer` expires.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

impl Future for Timer {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.deadline <= Instant::now() {
            Poll::Ready(())
        } else {
            executor::add_timer(self.deadline, cx.waker());

            Poll::Pending
        }
    }
}

/// The error returned from `with_deadline` when the deadline expires before the future completes.
///
/// # Examples
///
/// Convert the `TimedOut` error into an `io::Error`.
///
/// ```
/// # use std::{
/// #     future::{pending, Future},
/// #     io,
/// #     time::Instant
/// # };
/// use cros_async::with_deadline;
///
/// async fn deadline_with_io_error<F: Future>(deadline: Instant, f: F) -> io::Result<F::Output> {
///     with_deadline(deadline, f)
///         .await
///         .map_err(io::Error::from)
/// }
/// # let err = cros_async::Executor::new()
/// #     .run_until(deadline_with_io_error(Instant::now(), pending::<()>()))
/// #     .unwrap()
/// #     .unwrap_err();
/// # assert_eq!(err.kind(), io::ErrorKind::TimedOut);
/// ```
#[derive(Debug, ThisError)]
#[error("Operation timed out")]
pub struct TimedOut;

impl From<TimedOut> for io::Error {
    fn from(_: TimedOut) -> Self {
        io::Error::from(io::ErrorKind::TimedOut)
    }
}

/// Add a deadline to an asynchronous operation.
///
/// Returns the output of the asynchronous operation if it completes before the deadline
/// expires. Otherwise returns a `TimedOut` error.
///
/// If the deadline expires before the asynchronous operation completes then `f` is dropped.
/// However, this may not cancel any underlying asynchronous I/O operations registered with the OS.
///
/// # Examples
///
/// Set a timeout for reading from a data source.
///
/// ```
/// use std::time::{Duration, Instant};
///
/// use cros_async::{with_deadline, File};
///
/// async fn read_with_timeout(
///     rx: &File,
///     buf: &mut [u8],
///     timeout: Duration,
/// ) -> anyhow::Result<usize> {
///     with_deadline(Instant::now() + timeout, rx.read(buf, None)).await?
/// }
/// #
/// # use std::io;
/// # use cros_async::{Executor, TimedOut};
/// #
/// # let ex = Executor::new();
/// # let (rx, _tx) = sys_util::pipe(true).unwrap();
/// # let rx = cros_async::File::from_std(rx).unwrap();
/// # let mut buf = 0u64.to_ne_bytes();
/// #
/// # let _err = ex
/// #     .run_until(read_with_timeout(&rx, &mut buf, Duration::from_millis(10)))
/// #     .unwrap()
/// #     .unwrap_err()
/// #     .downcast::<TimedOut>()
/// #     .unwrap();
/// ```
pub async fn with_deadline<F: Future>(deadline: Instant, f: F) -> Result<F::Output, TimedOut> {
    let timer = Timer::new(deadline);
    pin_mut!(timer, f);
    match select(timer, f).await {
        Either::Left(((), _)) => Err(TimedOut),
        Either::Right((v, _)) => Ok(v),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::{mem, sync::Arc, task, thread, time::Duration};

    use futures::{future::join5, stream::FuturesUnordered, StreamExt};
    use sync::Mutex;

    use crate::Executor;

    #[test]
    fn basic() {
        let ex = Executor::new();

        let dur = Duration::from_millis(5);
        let start = Instant::now();
        let sleep = Timer::new(start + dur);

        ex.run_until(sleep).unwrap();

        assert!(start.elapsed() >= dur);
    }

    #[test]
    fn multiple() {
        let ex = Executor::new();

        let start = Instant::now();
        let t1 = Timer::new(start + Duration::from_millis(10));
        let t2 = Timer::new(start + Duration::from_secs(10));

        match ex.run_until(select(t1, t2)).unwrap() {
            Either::Left(_) => {
                let elapsed = start.elapsed();
                assert!(elapsed >= Duration::from_millis(10));
                assert!(elapsed < Duration::from_secs(10));
            }
            Either::Right(_) => panic!("Longer deadline finished first"),
        }
    }

    #[test]
    fn run_until_identical_deadline() {
        let ex = Executor::new();

        let start = Instant::now();
        let deadline = start + Duration::from_millis(10);
        let t1 = Timer::new(deadline);
        let t2 = Timer::new(deadline);
        let t3 = Timer::new(deadline);
        let t4 = Timer::new(deadline);
        let t5 = Timer::new(deadline);

        ex.run_until(join5(t1, t2, t3, t4, t5)).unwrap();
        assert!(deadline <= Instant::now());
    }

    #[test]
    fn spawn_identical_deadline() {
        let ex = Executor::new();

        let start = Instant::now();
        let deadline = start + Duration::from_millis(10);
        let t1 = ex.spawn(Timer::new(deadline));
        let t2 = ex.spawn(Timer::new(deadline));
        let t3 = ex.spawn(Timer::new(deadline));
        let t4 = ex.spawn(Timer::new(deadline));
        let t5 = ex.spawn(Timer::new(deadline));

        ex.run_until(join5(t1, t2, t3, t4, t5)).unwrap();
        assert!(deadline <= Instant::now());
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
    fn multiple_threads() {
        const NUM_THREADS: usize = 7;
        const NUM_TIMERS: usize = 19;

        let ex = Executor::new();
        let quit = Quit::default();
        let mut threads = Vec::with_capacity(NUM_THREADS);
        for _ in 0..NUM_THREADS {
            let thread_ex = ex.clone();
            let thread_quit = quit.clone();
            threads.push(thread::spawn(move || thread_ex.run_until(thread_quit)));
        }

        let start = Instant::now();
        let timers = FuturesUnordered::new();
        let deadline = start + Duration::from_millis(10);
        for _ in 0..NUM_TIMERS {
            timers.push(ex.spawn(Timer::new(deadline)));
        }

        ex.run_until(timers.collect::<Vec<()>>()).unwrap();
        quit.quit();

        for t in threads {
            t.join().unwrap().unwrap();
        }
    }
}
