// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Context;
use anyhow::Result;
use base::info;
use base::CloseNotifier;
use base::ReadNotifier;
use base::Tube;
use cros_async::EventAsync;
use cros_async::Executor;
use futures::pin_mut;
use futures::select;
use futures::FutureExt;
use vmm_vhost::connection::TubePlatformConnection;
use vmm_vhost::message::MasterReq;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::Master;
use vmm_vhost::MasterReqHandler;

use crate::virtio::vhost::user::vmm::handler::BackendReqHandler;
use crate::virtio::vhost::user::vmm::handler::BackendReqHandlerImpl;
use crate::virtio::vhost::user::vmm::Error;
use crate::virtio::vhost::user::vmm::Result as VhostResult;

pub fn create_backend_req_handler(
    h: BackendReqHandlerImpl,
    backend_pid: Option<u32>,
) -> VhostResult<BackendReqHandler> {
    let backend_pid = backend_pid.expect("tube needs target pid for backend requests");
    let mut handler =
        MasterReqHandler::with_tube(h, backend_pid).map_err(Error::CreateBackendReqHandler)?;
    Ok(handler)
}

pub async fn run_backend_request_handler(
    handler: Option<BackendReqHandler>,
    ex: &Executor,
) -> Result<()> {
    let mut handler = match handler {
        Some(h) => h,
        None => std::future::pending().await,
    };

    let read_notifier = handler.get_read_notifier();
    let close_notifier = handler.get_close_notifier();

    let read_event = EventAsync::clone_raw_without_reset(read_notifier, ex)
        .context("failed to create an async event")?;
    let close_event = EventAsync::clone_raw_without_reset(close_notifier, ex)
        .context("failed to create an async event")?;

    let read_event_fut = read_event.next_val().fuse();
    let close_event_fut = close_event.next_val().fuse();
    pin_mut!(read_event_fut);
    pin_mut!(close_event_fut);

    loop {
        select! {
            _read_res = read_event_fut => {
                handler
                    .handle_request()
                    .context("failed to handle a vhost-user request")?;
                read_event_fut.set(read_event.next_val().fuse());
            }
            // Tube closed event.
            _close_res = close_event_fut => {
                info!("exit run loop: got close event");
                return Ok(())
            }
        }
    }
}
