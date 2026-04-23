// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Event;

use crate::AsyncError;
use crate::AsyncResult;
use crate::EventAsync;
use crate::Executor;

impl EventAsync {
    pub fn new(event: Event, ex: &Executor) -> AsyncResult<EventAsync> {
        ex.async_from(event)
            .map(|io_source| EventAsync { io_source })
    }

    /// Gets the next value from the eventfd.
    pub async fn next_val(&self) -> AsyncResult<u64> {
        let (n, v) = self
            .io_source
            .read_to_vec(None, 0u64.to_ne_bytes().to_vec())
            .await?;
        if n != 8 {
            return Err(AsyncError::EventAsync(base::Error::new(libc::ENODATA)));
        }
        Ok(u64::from_ne_bytes(v.try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use base::EventExt;

    use super::super::fd_executor::EpollReactor;
    use super::super::uring_executor::UringReactor;
    use super::*;
    use crate::common_executor::RawExecutor;
    use crate::sys::linux::uring_executor::is_uring_stable;
    use crate::ExecutorTrait;

    pub(crate) fn new_poll(
        event: Event,
        ex: &Arc<RawExecutor<EpollReactor>>,
    ) -> AsyncResult<EventAsync> {
        ex.async_from(event)
            .map(|io_source| EventAsync { io_source })
    }

    pub(crate) fn new_uring(
        event: Event,
        ex: &Arc<RawExecutor<UringReactor>>,
    ) -> AsyncResult<EventAsync> {
        ex.async_from(event)
            .map(|io_source| EventAsync { io_source })
    }

    #[test]
    fn next_val_reads_value() {
        async fn go(event: Event, ex: &Executor) -> u64 {
            let event_async = EventAsync::new(event, ex).unwrap();
            event_async.next_val().await.unwrap()
        }

        let eventfd = Event::new().unwrap();
        eventfd.write_count(0xaa).unwrap();
        let ex = Executor::new().unwrap();
        let val = ex.run_until(go(eventfd, &ex)).unwrap();
        assert_eq!(val, 0xaa);
    }

    #[test]
    fn next_val_reads_value_poll_and_ring() {
        if !is_uring_stable() {
            return;
        }

        async fn go(event_async: EventAsync) -> u64 {
            event_async.next_val().await.unwrap()
        }

        let eventfd = Event::new().unwrap();
        eventfd.write_count(0xaa).unwrap();
        let uring_ex = RawExecutor::<UringReactor>::new().unwrap();
        let val = uring_ex
            .run_until(go(new_uring(eventfd, &uring_ex).unwrap()))
            .unwrap();
        assert_eq!(val, 0xaa);

        let eventfd = Event::new().unwrap();
        eventfd.write_count(0xaa).unwrap();
        let poll_ex = RawExecutor::<EpollReactor>::new().unwrap();
        let val = poll_ex
            .run_until(go(new_poll(eventfd, &poll_ex).unwrap()))
            .unwrap();
        assert_eq!(val, 0xaa);
    }
}
