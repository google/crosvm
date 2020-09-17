// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{new, AsyncResult, IoSourceExt};
use std::os::unix::io::AsRawFd;

/// An async version of sys_util::EventFd.
pub struct EventAsync<F: AsRawFd + 'static> {
    io_source: Box<dyn IoSourceExt<F> + 'static>,
}

impl<F: AsRawFd + 'static> EventAsync<F> {
    /// Creates a new EventAsync wrapper around the provided eventfd.
    #[allow(dead_code)]
    pub fn new(f: F) -> AsyncResult<EventAsync<F>> {
        Ok(EventAsync { io_source: new(f)? })
    }

    /// Gets the next value from the eventfd.
    #[allow(dead_code)]
    pub async fn next_val(&self) -> AsyncResult<u64> {
        self.io_source.read_u64().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::Event;
    use futures::pin_mut;

    #[test]
    fn next_val_reads_value() {
        async fn go(event: Event) -> u64 {
            let event_async = EventAsync::new(event).unwrap();
            event_async.next_val().await.unwrap()
        }

        let eventfd = Event::new().unwrap();
        eventfd.write(0xaa).unwrap();
        let fut = go(eventfd);
        pin_mut!(fut);
        let val = crate::run_executor(crate::RunOne::new(fut)).unwrap();
        assert_eq!(val, 0xaa);
    }
}
