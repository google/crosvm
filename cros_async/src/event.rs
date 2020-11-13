// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::io_ext::async_from;
use crate::{AsyncError, AsyncResult, IntoAsync, IoSourceExt};
use std::convert::TryFrom;
use sys_util::EventFd;

/// An async version of `sys_util::EventFd`.
pub struct EventAsync {
    io_source: Box<dyn IoSourceExt<EventFd>>,
}

impl EventAsync {
    #[cfg(test)]
    pub(crate) fn new_poll(event: EventFd) -> AsyncResult<EventAsync> {
        Ok(EventAsync {
            io_source: crate::io_ext::async_poll_from(event)?,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_uring(event: EventFd) -> AsyncResult<EventAsync> {
        Ok(EventAsync {
            io_source: crate::io_ext::async_uring_from(event)?,
        })
    }

    /// Gets the next value from the eventfd.
    #[allow(dead_code)]
    pub async fn next_val(&self) -> AsyncResult<u64> {
        self.io_source.read_u64().await
    }
}

impl TryFrom<EventFd> for EventAsync {
    type Error = AsyncError;

    /// Creates a new EventAsync wrapper around the provided eventfd.
    fn try_from(event: EventFd) -> AsyncResult<Self> {
        Ok(EventAsync {
            io_source: async_from(event)?,
        })
    }
}

impl IntoAsync for EventFd {}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::pin_mut;
    use std::convert::TryInto;

    #[test]
    fn next_val_reads_value() {
        async fn go(event: EventFd) -> u64 {
            let event_async: EventAsync = event.try_into().unwrap();
            event_async.next_val().await.unwrap()
        }

        let eventfd = EventFd::new().unwrap();
        eventfd.write(0xaa).unwrap();
        let fut = go(eventfd);
        pin_mut!(fut);
        let val = crate::run_executor(crate::RunOne::new(fut)).unwrap();
        assert_eq!(val, 0xaa);
    }

    #[test]
    fn next_val_reads_value_poll_and_ring() {
        async fn go(event_async: EventAsync) -> u64 {
            event_async.next_val().await.unwrap()
        }

        let eventfd = EventFd::new().unwrap();
        eventfd.write(0xaa).unwrap();
        let fut = go(EventAsync::new_uring(eventfd).unwrap());
        pin_mut!(fut);
        let val = crate::run_one_uring(fut).unwrap();
        assert_eq!(val, 0xaa);

        let eventfd = EventFd::new().unwrap();
        eventfd.write(0xaa).unwrap();
        let fut = go(EventAsync::new_poll(eventfd).unwrap());
        pin_mut!(fut);
        let val = crate::run_one_poll(fut).unwrap();
        assert_eq!(val, 0xaa);
    }
}
