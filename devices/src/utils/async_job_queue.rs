// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::{Error, Result};
use super::{EventHandler, EventLoop};

use anyhow::Context;
use base::{Event, WatchingEvents};
use std::mem;
use std::sync::Arc;
use sync::Mutex;

/// Async Job Queue can schedule async jobs.
pub struct AsyncJobQueue {
    jobs: Mutex<Vec<Box<dyn FnMut() + Send>>>,
    evt: Event,
}

impl AsyncJobQueue {
    /// Init job queue on event loop.
    pub fn init(event_loop: &EventLoop) -> Result<Arc<AsyncJobQueue>> {
        let evt = Event::new().map_err(Error::CreateEvent)?;
        let queue = Arc::new(AsyncJobQueue {
            jobs: Mutex::new(Vec::new()),
            evt,
        });
        let handler: Arc<dyn EventHandler> = queue.clone();
        event_loop.add_event(
            &queue.evt,
            WatchingEvents::empty().set_read(),
            Arc::downgrade(&handler),
        )?;
        Ok(queue)
    }

    /// Queue a new job. It will be invoked on event loop.
    pub fn queue_job<T: Fn() + 'static + Send>(&self, cb: T) -> Result<()> {
        self.jobs.lock().push(Box::new(cb));
        self.evt.write(1).map_err(Error::WriteEvent)
    }
}

impl EventHandler for AsyncJobQueue {
    fn on_event(&self) -> anyhow::Result<()> {
        // We want to read out the event, but the value is not important.
        let _ = self.evt.read().context("read event failed")?;

        let jobs = mem::take(&mut *self.jobs.lock());
        for mut cb in jobs {
            cb();
        }
        Ok(())
    }
}
