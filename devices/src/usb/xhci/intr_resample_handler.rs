// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::interrupter::Interrupter;
use crate::utils::{EventHandler, EventLoop};
use std::sync::Arc;
use sync::Mutex;
use sys_util::{error, EventFd, WatchingEvents};

/// Interrupt Resample handler handles resample event. It will reassert interrupt if needed.
pub struct IntrResampleHandler {
    interrupter: Arc<Mutex<Interrupter>>,
    resample_evt: EventFd,
}

impl IntrResampleHandler {
    /// Start resample handler.
    pub fn start(
        event_loop: &EventLoop,
        interrupter: Arc<Mutex<Interrupter>>,
        resample_evt: EventFd,
    ) -> Option<Arc<IntrResampleHandler>> {
        let handler = Arc::new(IntrResampleHandler {
            interrupter,
            resample_evt,
        });
        let tmp_handler: Arc<dyn EventHandler> = handler.clone();
        if let Err(e) = event_loop.add_event(
            &handler.resample_evt,
            WatchingEvents::empty().set_read(),
            Arc::downgrade(&tmp_handler),
        ) {
            error!("cannot add intr resample handler to event loop: {}", e);
            return None;
        }
        Some(handler)
    }
}
impl EventHandler for IntrResampleHandler {
    fn on_event(&self) -> Result<(), ()> {
        match self.resample_evt.read() {
            Ok(_) => {}
            Err(e) => {
                error!("cannot read resample evt: {}", e);
                return Err(());
            }
        }
        usb_debug!("resample triggered");
        let mut interrupter = self.interrupter.lock();
        if !interrupter.event_ring_is_empty() {
            usb_debug!("irq resample re-assert irq event");
            // There could be a race condition. When we get resample_evt and other
            // component is sending interrupt at the same time.
            // This might result in one more interrupt than we want. It's handled by
            // kernel correctly.
            if let Err(e) = interrupter.interrupt() {
                error!("cannot send interrupt: {}", e);
                return Err(());
            }
        }
        Ok(())
    }
}
