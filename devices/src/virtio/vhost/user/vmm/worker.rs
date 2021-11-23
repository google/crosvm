// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::rc::Rc;

use base::Event;
use cros_async::{select2, Executor, SelectResult};
use futures::pin_mut;
use vm_memory::GuestMemory;

use crate::virtio::{async_utils, Interrupt, Queue};

pub struct Worker {
    pub queues: Vec<Queue>,
    pub mem: GuestMemory,
    pub kill_evt: Event,
}

impl Worker {
    // Runs asynchronous tasks.
    pub fn run(&mut self, interrupt: Interrupt) -> Result<(), String> {
        let ex = Executor::new().expect("failed to create an executor");

        let interrupt = Rc::new(RefCell::new(interrupt));
        let resample = async_utils::handle_irq_resample(&ex, interrupt);
        pin_mut!(resample);

        let kill_evt = self.kill_evt.try_clone().expect("failed to clone kill_evt");
        let kill = async_utils::await_and_exit(&ex, kill_evt);
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
