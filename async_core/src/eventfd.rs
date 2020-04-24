// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use futures::Stream;
use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use libc::{EWOULDBLOCK, O_NONBLOCK};

use sys_util::{self, add_fd_flags};

use cros_async::fd_executor::{self, add_read_waker};

/// Errors generated while polling for events.
#[derive(Debug)]
pub enum Error {
    /// An error occurred attempting to register a waker with the executor.
    AddingWaker(fd_executor::Error),
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

/// Asynchronous version of `sys_util::EventFd`. Provides an implementation of `futures::Stream` so
/// that events can be consumed in an async context.
///
/// # Example
///
/// ```
/// use std::convert::TryInto;
///
/// use async_core::{EventFd };
/// use futures::StreamExt;
/// use sys_util::{self};
///
/// async fn process_events() -> std::result::Result<(), Box<dyn std::error::Error>> {
///     let mut async_events: EventFd = sys_util::EventFd::new()?.try_into()?;
///     while let Some(e) = async_events.next().await {
///         // Handle event here.
///     }
///     Ok(())
/// }
/// ```
pub struct EventFd {
    inner: sys_util::EventFd,
    done: bool,
}

impl EventFd {
    pub fn new() -> Result<EventFd> {
        Self::try_from(sys_util::EventFd::new().map_err(Error::EventFdCreate)?)
    }
}

impl TryFrom<sys_util::EventFd> for EventFd {
    type Error = crate::eventfd::Error;

    fn try_from(eventfd: sys_util::EventFd) -> Result<EventFd> {
        let fd = eventfd.as_raw_fd();
        add_fd_flags(fd, O_NONBLOCK).map_err(Error::SettingNonBlocking)?;
        Ok(EventFd {
            inner: eventfd,
            done: false,
        })
    }
}

impl Stream for EventFd {
    type Item = Result<u64>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }

        let res = self
            .inner
            .read()
            .map(|v| Poll::Ready(Some(Ok(v))))
            .or_else(|e| {
                if e.errno() == EWOULDBLOCK {
                    add_read_waker(self.inner.as_raw_fd(), cx.waker().clone())
                        .map(|_token| Poll::Pending)
                        .map_err(Error::AddingWaker)
                } else {
                    Err(Error::EventFdRead(e))
                }
            });

        match res {
            Ok(v) => v,
            Err(e) => {
                self.done = true;
                Poll::Ready(Some(Err(e)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cros_async::{select2, SelectResult};
    use futures::future::pending;
    use futures::pin_mut;
    use futures::stream::StreamExt;

    #[test]
    fn eventfd_write_read() {
        let evt = EventFd::new().unwrap();
        async fn read_one(mut evt: EventFd) -> u64 {
            if let Some(Ok(e)) = evt.next().await {
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
