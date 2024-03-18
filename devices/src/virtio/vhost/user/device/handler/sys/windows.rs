// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Context;
use anyhow::Result;
use base::info;
use base::named_pipes::BlockingMode;
use base::named_pipes::FramingMode;
use base::named_pipes::PipeConnection;
use base::CloseNotifier;
use base::Event;
use base::RawDescriptor;
use base::ReadNotifier;
use base::Tube;
use cros_async::EventAsync;
use cros_async::Executor;
use futures::pin_mut;
use futures::select;
use futures::FutureExt;
use tube_transporter::TubeTransferDataList;
use tube_transporter::TubeTransporterReader;
use vmm_vhost::message::FrontendReq;
use vmm_vhost::message::VhostUserMsgHeader;
use vmm_vhost::BackendServer;

use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;

pub fn read_from_tube_transporter(
    raw_transport_tube: RawDescriptor,
) -> anyhow::Result<TubeTransferDataList> {
    let tube_transporter = TubeTransporterReader::create_tube_transporter_reader(
        // SAFETY:
        // Safe because we know that raw_transport_tube is valid (passed by inheritance), and that
        // the blocking & framing modes are accurate because we create them ourselves in the
        // broker.
        unsafe {
            PipeConnection::from_raw_descriptor(
                raw_transport_tube,
                FramingMode::Message,
                BlockingMode::Wait,
            )
        },
    );

    tube_transporter.read_tubes().map_err(anyhow::Error::msg)
}

pub async fn run_handler(
    handler: Box<dyn vmm_vhost::Backend>,
    vhost_user_tube: Tube,
    exit_event: Event,
    ex: &Executor,
) -> Result<()> {
    let read_notifier = vhost_user_tube.get_read_notifier();
    let close_notifier = vhost_user_tube.get_close_notifier();

    let read_event = EventAsync::clone_raw_without_reset(read_notifier, ex)
        .context("failed to create an async event")?;
    let close_event = EventAsync::clone_raw_without_reset(close_notifier, ex)
        .context("failed to create an async event")?;
    let exit_event = EventAsync::new(exit_event, ex).context("failed to create an async event")?;

    let mut backend_server = BackendServer::from_stream(vhost_user_tube, handler);

    let read_event_fut = read_event.next_val().fuse();
    let close_event_fut = close_event.next_val().fuse();
    let exit_event_fut = exit_event.next_val().fuse();
    pin_mut!(read_event_fut);
    pin_mut!(close_event_fut);
    pin_mut!(exit_event_fut);

    let mut pending_header: Option<(VhostUserMsgHeader<FrontendReq>, Vec<std::fs::File>)> = None;
    loop {
        select! {
            _read_res = read_event_fut => {
                match pending_header.take() {
                    None => {
                        let (hdr, files) = backend_server
                            .recv_header()
                            .context("failed to handle a vhost-user request")?;
                        if backend_server.needs_wait_for_payload(&hdr) {
                            // Wait for the message body being notified.
                            pending_header = Some((hdr, files));
                        } else {
                            backend_server
                                .process_message(hdr, files)
                                .context("failed to handle a vhost-user request")?;
                        }
                    }
                    Some((hdr, files)) => {
                        backend_server
                            .process_message(hdr, files)
                            .context("failed to handle a vhost-user request")?;
                    }
                }
                read_event_fut.set(read_event.next_val().fuse());
            }
            // Tube closed event.
            _close_res = close_event_fut => {
                info!("exit run loop: got close event");
                return Ok(())
            }
            // Broker exit event.
            _exit_res = exit_event_fut => {
                info!("exit run loop: got exit event");
                return Ok(())
            }
        }
    }
}

#[cfg(test)]
pub mod test_helpers {
    use base::Tube;
    use vmm_vhost::message::FrontendReq;
    use vmm_vhost::BackendServer;

    pub(crate) fn setup() -> (Tube, Tube) {
        Tube::pair().unwrap()
    }

    pub(crate) fn connect(tube: Tube) -> Tube {
        tube
    }

    pub(crate) fn listen<S: vmm_vhost::Backend>(dev_tube: Tube, handler: S) -> BackendServer<S> {
        BackendServer::from_stream(dev_tube, handler)
    }
}
