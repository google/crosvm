// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::{error, Event};
use cros_async::{select2, AsyncError, EventAsync, Executor, SelectResult};
use futures::pin_mut;
use thiserror::Error as ThisError;
use vm_memory::GuestMemory;

use crate::virtio::interrupt::SignalableInterrupt;
use crate::virtio::{Interrupt, Queue};

#[derive(ThisError, Debug)]
enum Error {
    /// Failed to read the resample event.
    #[error("failed to read the resample event: {0}")]
    ReadResampleEvent(AsyncError),
}

pub struct Worker {
    pub queues: Vec<Queue>,
    pub mem: GuestMemory,
    pub kill_evt: Event,
}

impl Worker {
    // Processes any requests to resample the irq value.
    async fn handle_irq_resample(
        resample_evt: EventAsync,
        interrupt: Interrupt,
    ) -> Result<(), Error> {
        loop {
            let _ = resample_evt
                .next_val()
                .await
                .map_err(Error::ReadResampleEvent)?;
            interrupt.do_interrupt_resample();
        }
    }

    // Waits until the kill event is triggered.
    async fn wait_kill(kill_evt: EventAsync) {
        // Once this event is readable, exit. Exiting this future will cause the main loop to
        // break and the device process to exit.
        let _ = kill_evt.next_val().await;
    }

    // Runs asynchronous tasks.
    pub fn run(&mut self, ex: &Executor, interrupt: Interrupt) -> Result<(), String> {
        let resample_evt = interrupt
            .get_resample_evt()
            .expect("resample event required")
            .try_clone()
            .expect("failed to clone resample event");
        let async_resample_evt =
            EventAsync::new(resample_evt.0, ex).expect("failed to create async resample event");
        let resample = Self::handle_irq_resample(async_resample_evt, interrupt);
        pin_mut!(resample);

        let kill_evt = EventAsync::new(
            self.kill_evt
                .try_clone()
                .expect("failed to clone kill_evt")
                .0,
            &ex,
        )
        .expect("failed to create async kill event fd");
        let kill = Self::wait_kill(kill_evt);
        pin_mut!(kill);

        match ex.run_until(select2(resample, kill)) {
            Ok((resample_res, _)) => {
                if let SelectResult::Finished(Err(e)) = resample_res {
                    return Err(format!("failed to resample a irq value: {:?}", e));
                }
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }
}
