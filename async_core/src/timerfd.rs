// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::future::Future;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use libc::{EWOULDBLOCK, O_NONBLOCK};

use cros_async::Error as ExecutorError;
use cros_async::{add_read_waker, cancel_waker, WakerToken};
use sys_util::{self, add_fd_flags};

/// Errors generated while polling for events.
#[derive(Debug)]
pub enum Error {
    /// An error occurred attempting to register a waker with the executor.
    AddingWaker(ExecutorError),
    /// An error occurred when reading the timer FD.
    TimerFdRead(sys_util::Error),
    /// An error occurred when resetting the timer FD.
    TimerFdReset(sys_util::Error),
    /// An error occurred when setting the timer FD non-blocking.
    SettingNonBlocking(sys_util::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            AddingWaker(e) => write!(
                f,
                "An error occurred attempting to register a waker with the executor: {}.",
                e
            ),
            TimerFdRead(e) => write!(f, "An error occurred when reading the timer FD: {}.", e),
            TimerFdReset(e) => write!(f, "An error occurred when resetting the timer FD: {}.", e),
            SettingNonBlocking(e) => {
                write!(f, "An error occurred setting the FD non-blocking: {}.", e)
            }
        }
    }
}

/// Asynchronous version of `sys_util::TimerFd`. Provides a method for asynchronously waiting for a
/// timer to fire.
///
/// # Example
///
/// ```
/// use std::convert::TryInto;
///
/// use async_core::TimerFd;
/// use sys_util::{self, Result};
/// async fn process_events() -> Result<()> {
///     let mut async_timer: TimerFd = sys_util::TimerFd::new()?.try_into().unwrap();
///     while let Ok(e) = async_timer.next_expiration().await {
///         // Handle timer here.
///     }
///     Ok(())
/// }
/// ```
pub struct TimerFd(sys_util::TimerFd);

impl TimerFd {
    /// Reset the inner timer to a new duration.
    pub fn reset(&self, dur: Duration, interval: Option<Duration>) -> Result<()> {
        self.0.reset(dur, interval).map_err(Error::TimerFdReset)
    }

    /// Asynchronously wait for the timer to fire.
    /// Returns a Future that can be `awaited` for the next interval.
    ///
    /// # Example
    ///
    /// ```
    /// use async_core::TimerFd;
    /// async fn print_events(mut timer_fd: TimerFd) {
    ///     loop {
    ///         match timer_fd.next_expiration().await {
    ///             Ok(_) => println!("timer fired"),
    ///             Err(e) => break,
    ///         }
    ///     }
    /// }
    /// ```
    pub fn next_expiration(&self) -> TimerFuture {
        TimerFuture::new(&self.0)
    }
}

impl TryFrom<sys_util::TimerFd> for TimerFd {
    type Error = Error;

    fn try_from(timerfd: sys_util::TimerFd) -> Result<TimerFd> {
        let fd = timerfd.as_raw_fd();
        add_fd_flags(fd, O_NONBLOCK).map_err(Error::SettingNonBlocking)?;
        Ok(TimerFd(timerfd))
    }
}

/// A Future that yields completes when the timer has fired the next time.
pub struct TimerFuture<'a> {
    inner: &'a sys_util::TimerFd,
    waker_token: Option<WakerToken>,
}

impl<'a> TimerFuture<'a> {
    fn new(inner: &'a sys_util::TimerFd) -> TimerFuture<'a> {
        TimerFuture {
            inner,
            waker_token: None,
        }
    }
}

impl<'a> Future for TimerFuture<'a> {
    type Output = Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if let Some(token) = self.waker_token.take() {
            let _ = cancel_waker(token);
        }

        match self.inner.wait() {
            Ok(count) => Poll::Ready(Ok(count)),
            Err(e) => {
                if e.errno() == EWOULDBLOCK {
                    match add_read_waker(self.inner.as_raw_fd(), cx.waker().clone()) {
                        Ok(token) => {
                            self.waker_token = Some(token);
                            Poll::Pending
                        }
                        Err(e) => Poll::Ready(Err(Error::AddingWaker(e))),
                    }
                } else {
                    // Indicate something went wrong and no more events will be provided.
                    Poll::Ready(Err(Error::TimerFdRead(e)))
                }
            }
        }
    }
}

impl<'a> Drop for TimerFuture<'a> {
    fn drop(&mut self) {
        if let Some(token) = self.waker_token.take() {
            let _ = cancel_waker(token);
        }
    }
}

impl AsRef<sys_util::TimerFd> for TimerFd {
    fn as_ref(&self) -> &sys_util::TimerFd {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use cros_async::{run_one, select2, SelectResult};
    use futures::future::pending;
    use futures::future::Either;
    use futures::pin_mut;

    use super::*;

    #[test]
    fn timer_timeout() {
        async fn timeout(duration: Duration) -> u64 {
            let t = sys_util::TimerFd::new().unwrap();
            let async_timer = TimerFd::try_from(t).unwrap();
            async_timer.reset(duration, None).unwrap();
            async_timer.next_expiration().await.unwrap()
        }

        let to = timeout(Duration::from_millis(10));
        pin_mut!(to);
        if let Ok((SelectResult::Finished(timer_count), SelectResult::Pending(_pend_fut))) =
            select2(to, pending::<()>())
        {
            assert_eq!(timer_count, 1);
        } else {
            panic!("wrong futures returned from select2");
        }
    }

    #[test]
    fn select_with_eventfd() {
        async fn async_test() {
            let mut e = crate::eventfd::EventFd::new().unwrap();
            let t = sys_util::TimerFd::new().unwrap();
            let async_timer = TimerFd::try_from(t).unwrap();
            async_timer.reset(Duration::from_millis(10), None).unwrap();
            let timer = async_timer.next_expiration();
            let event = e.read_next();
            pin_mut!(timer);
            pin_mut!(event);
            match futures::future::select(timer, event).await {
                Either::Left((_timer, _event)) => (),
                _ => panic!("unexpected select result"),
            }
        }

        let fut = async_test();

        run_one(Box::pin(fut)).unwrap();
    }

    #[test]
    fn pend_unarmed_cancel() {
        async fn async_test() {
            let t = sys_util::TimerFd::new().unwrap();
            let async_timer = TimerFd::try_from(t).unwrap();
            let done = async {
                std::thread::sleep(Duration::from_millis(10));
                5usize
            };
            let timer = async_timer.next_expiration();
            pin_mut!(done);
            pin_mut!(timer);
            match futures::future::select(timer, done).await {
                Either::Right((_, _timer)) => (),
                _ => panic!("unexpected select result"),
            }
        }

        let fut = async_test();

        run_one(Box::pin(fut)).unwrap();
    }
}
