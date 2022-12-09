// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Event;
use cros_async::select3;
use cros_async::Executor;
use cros_async::SelectResult;
use futures::pin_mut;
use vm_memory::GuestMemory;

use crate::virtio::async_utils;
use crate::virtio::vhost::user::vmm::handler::sys::run_backend_request_handler;
use crate::virtio::vhost::user::vmm::handler::BackendReqHandler;
use crate::virtio::Interrupt;
use crate::virtio::Queue;

pub struct Worker {
    pub queues: Vec<(Queue, Event)>,
    pub mem: GuestMemory,
    pub kill_evt: Event,
    pub backend_req_handler: Option<BackendReqHandler>,
}

impl Worker {
    // Runs asynchronous tasks.
    pub fn run(&mut self, interrupt: Interrupt) -> Result<(), String> {
        let ex = Executor::new().expect("failed to create an executor");

        let resample = async_utils::handle_irq_resample(&ex, interrupt);
        pin_mut!(resample);

        let kill_evt = self.kill_evt.try_clone().expect("failed to clone kill_evt");
        let kill = async_utils::await_and_exit(&ex, kill_evt);
        pin_mut!(kill);

        let req_handler = run_backend_request_handler(self.backend_req_handler.take(), &ex);
        pin_mut!(req_handler);

        match ex.run_until(select3(resample, kill, req_handler)) {
            Ok((resample_res, _, backend_result)) => {
                if let SelectResult::Finished(Err(e)) = resample_res {
                    return Err(format!("failed to resample a irq value: {:?}", e));
                }
                if let SelectResult::Finished(Err(e)) = backend_result {
                    return Err(format!("backend request failure: {:#}", e));
                }
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }
}
