// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::future::Future;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use libc::{EWOULDBLOCK, O_NONBLOCK};

use cros_async::{self, add_read_waker, cancel_waker, WakerToken};
use sys_util::{self, add_fd_flags};

/// Errors generated while polling for events.
#[derive(Debug)]
pub enum Error {
    /// An error occurred attempting to register a waker with the executor.
    AddingWaker(cros_async::Error),
    /// Failure creating the event FD.
    EventFdCreate(sys_util::Error),
    /// An error occurred when reading the event FD.
    EventFdRead(sys_util::Error),
    /// An error occurred when setting the event FD non-blocking.
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
            EventFdCreate(e) => write!(f, "An error occurred when creating the event FD: {}.", e),
            EventFdRead(e) => write!(f, "An error occurred when reading the event FD: {}.", e),
            SettingNonBlocking(e) => {
                write!(f, "An error occurred setting the FD non-blocking: {}.", e)
            }
        }
    }
}

/// Asynchronous version of `sys_util::EventFd`. Provides asynchronous values that complete when the
/// next event can be read from the eventfd.
///
/// # Example
///
/// ```
/// use std::convert::TryInto;
///
/// use async_core::{EventFd};
/// use sys_util::{self};
///
/// async fn process_events() -> std::result::Result<(), Box<dyn std::error::Error>> {
///     let mut async_events: EventFd = sys_util::EventFd::new()?.try_into()?;
///     while let Ok(e) = async_events.read_next().await {
///         // Handle event here.
///     }
///     Ok(())
/// }
/// ```
pub struct EventFd {
    inner: sys_util::EventFd,
}

impl EventFd {
    pub fn new() -> Result<EventFd> {
        Self::try_from(sys_util::EventFd::new().map_err(Error::EventFdCreate)?)
    }

    /// Asynchronously read the next value from the eventfd.
    /// Returns a Future that can be `awaited` for the next value.
    ///
    /// # Example
    ///
    /// ```
    /// use async_core::EventFd;
    /// async fn print_events(mut event_fd: EventFd) {
    ///     loop {
    ///         match event_fd.read_next().await {
    ///             Ok(e) => println!("Got event: {}", e),
    ///             Err(e) => break,
    ///         }
    ///     }
    /// }
    /// ```
    pub fn read_next(&mut self) -> NextValFuture {
        NextValFuture::new(self)
    }
}

impl TryFrom<sys_util::EventFd> for EventFd {
    type Error = crate::eventfd::Error;

    fn try_from(eventfd: sys_util::EventFd) -> Result<EventFd> {
        let fd = eventfd.as_raw_fd();
        add_fd_flags(fd, O_NONBLOCK).map_err(Error::SettingNonBlocking)?;
        Ok(EventFd { inner: eventfd })
    }
}

/// A Future that yields the next value from the eventfd when it is ready.
pub struct NextValFuture<'a> {
    eventfd: &'a mut EventFd,
    waker_token: Option<WakerToken>,
}

impl<'a> NextValFuture<'a> {
    fn new(eventfd: &'a mut EventFd) -> NextValFuture<'a> {
        NextValFuture {
            eventfd,
            waker_token: None,
        }
    }
}

impl<'a> Future for NextValFuture<'a> {
    type Output = Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if let Some(token) = self.waker_token.take() {
            let _ = cancel_waker(token);
        }

        match self.eventfd.inner.read() {
            Ok(v) => Poll::Ready(Ok(v)),
            Err(e) => {
                if e.errno() == EWOULDBLOCK {
                    match add_read_waker(self.eventfd.inner.as_raw_fd(), cx.waker().clone()) {
                        Ok(token) => {
                            self.waker_token = Some(token);
                            Poll::Pending
                        }
                        Err(e) => Poll::Ready(Err(Error::AddingWaker(e))),
                    }
                } else {
                    Poll::Ready(Err(Error::EventFdRead(e)))
                }
            }
        }
    }
}

impl<'a> Drop for NextValFuture<'a> {
    fn drop(&mut self) {
        if let Some(token) = self.waker_token.take() {
            let _ = cancel_waker(token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cros_async::{select2, SelectResult};
    use futures::future::pending;
    use futures::pin_mut;

    #[test]
    fn eventfd_write_read() {
        let evt = EventFd::new().unwrap();
        async fn read_one(mut evt: EventFd) -> u64 {
            if let Ok(e) = evt.read_next().await {
                e
            } else {
                66
            }
        }
        async fn write_pend(evt: sys_util::EventFd) {
            evt.write(55).unwrap();
            let () = pending().await;
        }
        let write_evt = evt.inner.try_clone().unwrap();

        let r = read_one(evt);
        pin_mut!(r);
        let w = write_pend(write_evt);
        pin_mut!(w);

        if let Ok((SelectResult::Finished(read_res), SelectResult::Pending(_pend_fut))) =
            select2(r, w)
        {
            assert_eq!(read_res, 55);
        } else {
            panic!("wrong futures returned from select2");
        }
    }
}
