// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;

use crate::sys;

/// An asynchronous version of a `base::Event`.
#[derive(Debug)]
pub struct Event {
    inner: sys::Event,
}

impl Event {
    /// Creates a new `Event` in an unsignaled state.
    pub fn new() -> anyhow::Result<Event> {
        sys::Event::new().map(|inner| Event { inner })
    }

    /// Wait until the event is signaled.
    ///
    /// Blocks until the internal counter for the `Event` reaches a nonzero value, at which point
    /// the internal counter for the `Event` is reset to 0 and the previous value is returned.
    pub async fn next_val(&self) -> anyhow::Result<u64> {
        self.inner.next_val().await
    }

    /// Trigger the event, waking up any task that was blocked on it.
    pub async fn notify(&self) -> anyhow::Result<()> {
        self.inner.notify().await
    }

    /// Attempt to clone the `Event`.
    ///
    /// If successful, the returned `Event` will have its own unique OS handle for the underlying
    /// event.
    pub fn try_clone(&self) -> anyhow::Result<Event> {
        self.inner.try_clone().map(|inner| Event { inner })
    }
}

#[cfg(unix)]
impl TryFrom<base::Event> for Event {
    type Error = anyhow::Error;

    fn try_from(evt: base::Event) -> anyhow::Result<Event> {
        sys::Event::try_from(evt).map(|inner| Event { inner })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use futures::channel::oneshot::channel;
    use futures::channel::oneshot::Receiver;
    use futures::channel::oneshot::Sender;

    use super::*;
    use crate::Executor;

    use base::EventExt;

    #[test]
    fn next_val_with_nonzero_count() {
        let ex = Executor::new();

        let event = Event::new().unwrap();
        ex.run_until(event.notify()).unwrap().unwrap();
        let count = ex.run_until(event.next_val()).unwrap().unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    #[cfg(unix)]
    fn next_val_reads_value() {
        async fn go(event: Event) -> u64 {
            event.next_val().await.unwrap()
        }

        let sync_event = base::Event::new().unwrap();
        sync_event.write_count(0xaa).unwrap();
        let ex = Executor::new();
        let val = ex.run_until(go(sync_event.try_into().unwrap())).unwrap();
        assert_eq!(val, 0xaa);
    }

    #[test]
    fn write_wakes_up_task() {
        async fn wakeup(event: Event, ready: Receiver<()>) {
            ready.await.expect("failed to wait for wakeup");
            event.notify().await.unwrap();
        }

        async fn go(event: Event, ready: Sender<()>) -> u64 {
            ready.send(()).expect("failed to wake up notifier");
            event.next_val().await.unwrap()
        }

        let event = Event::new().unwrap();
        let ex = Executor::new();
        let (tx, rx) = channel();
        ex.spawn_local(wakeup(event.try_clone().unwrap(), rx))
            .detach();

        let val = ex.run_until(go(event, tx)).unwrap();
        assert_eq!(val, 0x1);
    }
}
