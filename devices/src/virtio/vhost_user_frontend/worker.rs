// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::pin::pin;

use anyhow::Context;
use base::Event;
use cros_async::EventAsync;
use cros_async::Executor;
use futures::channel::oneshot;
use futures::select_biased;
use futures::FutureExt;

use crate::virtio::async_utils;
use crate::virtio::vhost_user_frontend::handler::BackendReqHandler;
use crate::virtio::vhost_user_frontend::sys::run_backend_request_handler;
use crate::virtio::Interrupt;
use crate::virtio::VIRTIO_MSI_NO_VECTOR;

pub struct Worker {
    pub kill_evt: Event,
    pub non_msix_evt: Event,
    pub backend_req_handler: Option<BackendReqHandler>,
}

impl Worker {
    // Runs asynchronous tasks.
    pub async fn run(&mut self, ex: &Executor, interrupt: Interrupt) -> anyhow::Result<()> {
        let non_msix_evt = self
            .non_msix_evt
            .try_clone()
            .expect("failed to clone non_msix_evt");
        let mut handle_non_msix_evt =
            pin!(handle_non_msix_evt(ex, non_msix_evt, interrupt.clone()).fuse());

        let mut resample = pin!(async_utils::handle_irq_resample(ex, interrupt).fuse());

        let kill_evt = self.kill_evt.try_clone().expect("failed to clone kill_evt");
        let mut kill = pin!(async_utils::await_and_exit(ex, kill_evt).fuse());

        let (stop_tx, stop_rx) = oneshot::channel();
        let mut req_handler = pin!(if let Some(backend_req_handler) =
            self.backend_req_handler.as_mut()
        {
            run_backend_request_handler(ex, backend_req_handler, stop_rx)
                .fuse()
                .left_future()
        } else {
            stop_rx.map(|_| Ok(())).right_future()
        }
        .fuse());

        select_biased! {
            r = kill => {
                r.context("failed to wait on the kill event")?;
                // Stop req_handler cooperatively.
                let _ = stop_tx.send(());
                req_handler.await.context("backend request failure on stop")?;
            }
            r = handle_non_msix_evt => r.context("non msix event failure")?,
            r = resample => r.context("failed to resample a irq value")?,
            r = req_handler => r.context("backend request failure")?,
        }

        Ok(())
    }
}

// The vhost-user protocol allows the backend to signal events, but for non-MSI-X devices,
// a device must also update the interrupt status mask. `handle_non_msix_evt` proxies events
// from the vhost-user backend to update the status mask.
async fn handle_non_msix_evt(
    ex: &Executor,
    non_msix_evt: Event,
    interrupt: Interrupt,
) -> anyhow::Result<()> {
    let event_async =
        EventAsync::new(non_msix_evt, ex).expect("failed to create async non_msix_evt");
    loop {
        let _ = event_async.next_val().await;
        // The parameter vector of signal_used_queue is used only when msix is enabled.
        interrupt.signal_used_queue(VIRTIO_MSI_NO_VECTOR);
    }
}
