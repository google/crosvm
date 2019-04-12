// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::{Error, Result};
use super::{EventHandler, EventLoop};
use std::mem;
use std::sync::Arc;
use sync::Mutex;
use sys_util::{error, EventFd, WatchingEvents};

/// Async Job Queue can schedule async jobs.
pub struct AsyncJobQueue {
    jobs: Mutex<Vec<Box<dyn FnMut() + Send>>>,
    evt: EventFd,
}

impl AsyncJobQueue {
    /// Init job queue on event loop.
    pub fn init(event_loop: &EventLoop) -> Result<Arc<AsyncJobQueue>> {
        let evt = EventFd::new().map_err(Error::CreateEventFd)?;
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
        self.evt.write(1).map_err(Error::WriteEventFd)
    }
}

impl EventHandler for AsyncJobQueue {
    fn on_event(&self) -> std::result::Result<(), ()> {
        // We want to read out the event, but the value is not important.
        match self.evt.read() {
            Ok(_) => {}
            Err(e) => {
                error!("read event fd failed {}", e);
                return Err(());
            }
        }

        let jobs = mem::replace(&mut *self.jobs.lock(), Vec::new());
        for mut cb in jobs {
            cb();
        }
        Ok(())
    }
}
