// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Event;
use cros_async::select4;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::SelectResult;
use futures::pin_mut;
use vm_memory::GuestMemory;

use crate::virtio::async_utils;
use crate::virtio::vhost_user_frontend::handler::BackendReqHandler;
use crate::virtio::vhost_user_frontend::sys::run_backend_request_handler;
use crate::virtio::Interrupt;
use crate::virtio::VIRTIO_MSI_NO_VECTOR;

pub struct Worker {
    pub mem: GuestMemory,
    pub kill_evt: Event,
    pub non_msix_evt: Event,
    pub backend_req_handler: Option<BackendReqHandler>,
}

impl Worker {
    // Runs asynchronous tasks.
    pub fn run(&mut self, interrupt: Interrupt) -> Result<(), String> {
        let ex = Executor::new().expect("failed to create an executor");

        let non_msix_evt = self
            .non_msix_evt
            .try_clone()
            .expect("failed to clone non_msix_evt");
        let handle_non_msix_evt = handle_non_msix_evt(&ex, non_msix_evt, interrupt.clone());
        pin_mut!(handle_non_msix_evt);

        let resample = async_utils::handle_irq_resample(&ex, interrupt);
        pin_mut!(resample);

        let kill_evt = self.kill_evt.try_clone().expect("failed to clone kill_evt");
        let kill = async_utils::await_and_exit(&ex, kill_evt);
        pin_mut!(kill);

        let req_handler = run_backend_request_handler(self.backend_req_handler.take(), &ex);
        pin_mut!(req_handler);

        match ex.run_until(select4(handle_non_msix_evt, resample, kill, req_handler)) {
            Ok((non_msix_evt_result, resample_res, _, backend_result)) => {
                if let SelectResult::Finished(Err(e)) = non_msix_evt_result {
                    return Err(format!("non msix event failure: {:#}", e));
                }
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

// The vhost-user protocol allows the backend to signal events, but for non-MSI-X devices,
// a device must also update the interrupt status mask. `handle_non_msix_evt` proxies events
// from the vhost-user backend to update the status mask.
async fn handle_non_msix_evt(
    ex: &Executor,
    non_msix_evt: Event,
    interrupt: Interrupt,
) -> Result<(), String> {
    let event_async =
        EventAsync::new(non_msix_evt, ex).expect("failed to create async non_msix_evt");
    loop {
        let _ = event_async.next_val().await;
        // The parameter vector of signal_used_queue is used only when msix is enabled.
        interrupt.signal_used_queue(VIRTIO_MSI_NO_VECTOR);
    }
}
