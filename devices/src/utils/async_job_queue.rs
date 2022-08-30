// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::sync::Arc;

use anyhow::Context;
use base::Event;
use base::EventType;
use sync::Mutex;

use super::Error;
use super::EventHandler;
use super::EventLoop;
use super::Result;

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
        event_loop.add_event(&queue.evt, EventType::Read, Arc::downgrade(&handler))?;
        Ok(queue)
    }

    /// Queue a new job. It will be invoked on event loop.
    pub fn queue_job<T: Fn() + 'static + Send>(&self, cb: T) -> Result<()> {
        self.jobs.lock().push(Box::new(cb));
        self.evt.signal().map_err(Error::WriteEvent)
    }
}

impl EventHandler for AsyncJobQueue {
    fn on_event(&self) -> anyhow::Result<()> {
        // We want to read out the event.
        self.evt.wait().context("read event failed")?;

        let jobs = mem::take(&mut *self.jobs.lock());
        for mut cb in jobs {
            cb();
        }
        Ok(())
    }
}
