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
use vmm_vhost::message::MasterReq;
use vmm_vhost::message::VhostUserMsgHeader;
use vmm_vhost::SlaveReqHandler;

use crate::virtio::vhost::user::device::handler::CallEvent;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::handler::VhostUserRegularOps;

pub type Doorbell = CallEvent;

pub fn read_from_tube_transporter(
    raw_transport_tube: RawDescriptor,
) -> anyhow::Result<TubeTransferDataList> {
    // Safe because we know that raw_transport_tube is valid (passed by inheritance), and that
    // the blocking & framing modes are accurate because we create them ourselves in the broker.
    let tube_transporter = TubeTransporterReader::create_tube_transporter_reader(unsafe {
        PipeConnection::from_raw_descriptor(
            raw_transport_tube,
            FramingMode::Message,
            BlockingMode::Wait,
        )
    });

    tube_transporter.read_tubes().map_err(anyhow::Error::msg)
}

impl DeviceRequestHandler<VhostUserRegularOps> {
    pub async fn run(self, vhost_user_tube: Tube, exit_event: Event, ex: &Executor) -> Result<()> {
        let read_notifier = vhost_user_tube.get_read_notifier();
        let close_notifier = vhost_user_tube.get_close_notifier();

        let read_event = EventAsync::clone_raw_without_reset(read_notifier, ex)
            .context("failed to create an async event")?;
        let close_event = EventAsync::clone_raw_without_reset(close_notifier, ex)
            .context("failed to create an async event")?;
        let exit_event =
            EventAsync::new(exit_event, ex).context("failed to create an async event")?;

        let mut req_handler =
            SlaveReqHandler::from_stream(vhost_user_tube, std::sync::Mutex::new(self));

        let read_event_fut = read_event.next_val().fuse();
        let close_event_fut = close_event.next_val().fuse();
        let exit_event_fut = exit_event.next_val().fuse();
        pin_mut!(read_event_fut);
        pin_mut!(close_event_fut);
        pin_mut!(exit_event_fut);

        let mut pending_header: Option<(
            VhostUserMsgHeader<MasterReq>,
            Option<Vec<std::fs::File>>,
        )> = None;
        loop {
            select! {
                _read_res = read_event_fut => {
                    match pending_header.take() {
                        None => {
                            let (hdr, files) = req_handler
                                .recv_header()
                                .context("failed to handle a vhost-user request")?;
                            if req_handler.needs_wait_for_payload(&hdr) {
                                // Wait for the message body being notified.
                                pending_header = Some((hdr, files));
                            } else {
                                req_handler
                                    .process_message(hdr, files)
                                    .context("failed to handle a vhost-user request")?;
                            }
                        }
                        Some((hdr, files)) => {
                            req_handler
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
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;

    use super::*;
    use crate::virtio::vhost::user::device::handler::tests::*;
    use crate::virtio::vhost::user::device::handler::*;
    use crate::virtio::vhost::user::vmm::VhostUserHandler;
    #[test]
    fn test_vhost_user_activate() {
        const QUEUES_NUM: usize = 2;

        let (dev_tube, main_tube) = Tube::pair().unwrap();

        let vmm_bar = Arc::new(Barrier::new(2));
        let dev_bar = vmm_bar.clone();

        std::thread::spawn(move || {
            // VMM side
            let allow_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            let init_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            let allow_protocol_features = VhostUserProtocolFeatures::CONFIG;

            let mut vmm_handler = VhostUserHandler::new_from_connection(
                main_tube,
                QUEUES_NUM as u64,
                allow_features,
                init_features,
                allow_protocol_features,
            )
            .unwrap();

            vmm_handler_send_requests(&mut vmm_handler, QUEUES_NUM);

            vmm_bar.wait();
        });

        // Device side
        let backend =
            std::sync::Mutex::new(DeviceRequestHandler::new(Box::new(FakeBackend::new())));

        let mut req_handler = SlaveReqHandler::from_stream(dev_tube, backend);

        test_handle_requests(&mut req_handler, QUEUES_NUM);

        dev_bar.wait();
    }
}
