// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::EventFd;

use super::{AsyncResult, Executor, IntoAsync, IoSourceExt};

/// An async version of `base::EventFd`.
pub struct EventAsync {
    io_source: Box<dyn IoSourceExt<EventFd>>,
}

impl EventAsync {
    pub fn new(event: EventFd, ex: &Executor) -> AsyncResult<EventAsync> {
        ex.async_from(event)
            .map(|io_source| EventAsync { io_source })
    }

    #[cfg(test)]
    pub(crate) fn new_poll(event: EventFd, ex: &super::FdExecutor) -> AsyncResult<EventAsync> {
        super::executor::async_poll_from(event, ex).map(|io_source| EventAsync { io_source })
    }

    #[cfg(test)]
    pub(crate) fn new_uring(event: EventFd, ex: &super::URingExecutor) -> AsyncResult<EventAsync> {
        super::executor::async_uring_from(event, ex).map(|io_source| EventAsync { io_source })
    }

    /// Gets the next value from the eventfd.
    #[allow(dead_code)]
    pub async fn next_val(&self) -> AsyncResult<u64> {
        self.io_source.read_u64().await
    }
}

impl IntoAsync for EventFd {}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::{uring_executor::use_uring, Executor, FdExecutor, URingExecutor};

    #[test]
    fn next_val_reads_value() {
        async fn go(event: EventFd, ex: &Executor) -> u64 {
            let event_async = EventAsync::new(event, ex).unwrap();
            event_async.next_val().await.unwrap()
        }

        let eventfd = EventFd::new().unwrap();
        eventfd.write(0xaa).unwrap();
        let ex = Executor::new().unwrap();
        let val = ex.run_until(go(eventfd, &ex)).unwrap();
        assert_eq!(val, 0xaa);
    }

    #[test]
    fn next_val_reads_value_poll_and_ring() {
        if !use_uring() {
            return;
        }

        async fn go(event_async: EventAsync) -> u64 {
            event_async.next_val().await.unwrap()
        }

        let eventfd = EventFd::new().unwrap();
        eventfd.write(0xaa).unwrap();
        let uring_ex = URingExecutor::new().unwrap();
        let val = uring_ex
            .run_until(go(EventAsync::new_uring(eventfd, &uring_ex).unwrap()))
            .unwrap();
        assert_eq!(val, 0xaa);

        let eventfd = EventFd::new().unwrap();
        eventfd.write(0xaa).unwrap();
        let poll_ex = FdExecutor::new().unwrap();
        let val = poll_ex
            .run_until(go(EventAsync::new_poll(eventfd, &poll_ex).unwrap()))
            .unwrap();
        assert_eq!(val, 0xaa);
    }
}
