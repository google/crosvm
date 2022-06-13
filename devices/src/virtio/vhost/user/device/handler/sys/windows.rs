// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub(crate) use base::SharedMemoryWindows as SharedMemorySys;

use std::fs::File;
use std::mem::ManuallyDrop;
use std::sync::Arc;

use anyhow::{Context, Result};
use base::named_pipes::{BlockingMode, FramingMode, PipeConnection};
use base::{info, CloseNotifier, Event, FromRawDescriptor, RawDescriptor, ReadNotifier, Tube};
use cros_async::{EventAsync, Executor};
use futures::FutureExt;
use futures::{pin_mut, select};
use tube_transporter::{TubeTransferDataList, TubeTransporterReader};
use vm_memory::GuestMemory;
use vmm_vhost::{Protocol, SlaveReqHandler};

use crate::virtio::vhost::user::device::handler::{
    DeviceRequestHandler, Doorbell, MappingInfo, VhostUserBackend,
};
use crate::virtio::vhost::user::device::handler::{VhostResult, VhostUserMemoryRegion};

#[allow(dead_code)]
pub(crate) enum HandlerTypeSys {}

#[allow(dead_code)]
pub enum DoorbellSys {}

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

pub(in crate::virtio::vhost::user::device::handler) fn system_protocol(
    _handler_type: &HandlerTypeSys,
) -> Protocol {
    unimplemented!("This method shouldn't be called on Windows");
}

pub(in crate::virtio::vhost::user::device::handler) fn system_set_mem_table(
    _handler_type_sys: &HandlerTypeSys,
    _files: Vec<File>,
    _contexts: &[VhostUserMemoryRegion],
) -> VhostResult<(GuestMemory, Vec<MappingInfo>)> {
    unimplemented!("This method shouldn't be called on Windows");
}

pub(in crate::virtio::vhost::user::device::handler) fn system_get_kick_evt(
    _handler_type_sys: &HandlerTypeSys,
    _index: u8,
    _file: Option<File>,
) -> VhostResult<Event> {
    unimplemented!("This method shouldn't be called on Windows");
}

pub(in crate::virtio::vhost::user::device::handler) fn system_create_doorbell(
    _handler_type_sys: &HandlerTypeSys,
    _index: u8,
) -> VhostResult<Doorbell> {
    unimplemented!("This method shouldn't be called on Windows");
}

pub(in crate::virtio::vhost::user::device::handler) fn system_signal(
    _doorbell_sys: &DoorbellSys,
    _vector: u16,
    _interrupt_status_mask: u32,
) {
    unimplemented!("This method shouldn't be called on Windows");
}

pub(in crate::virtio::vhost::user::device::handler) fn system_signal_config_changed(
    _doorbell_sys: &DoorbellSys,
) {
    unimplemented!("This method shouldn't be called on Windows");
}

pub(in crate::virtio::vhost::user::device::handler) fn system_get_resample_evt(
    _doorbell_sys: &DoorbellSys,
) -> Option<&Event> {
    unimplemented!("This method shouldn't be called on Windows");
}

pub(in crate::virtio::vhost::user::device::handler) fn system_do_interrupt_resample(
    _doorbell_sys: &DoorbellSys,
) {
    unimplemented!("This method shouldn't be called on Windows");
}

/// Window's doesn't require clearing rd flags, so this is a no-op.
pub(in crate::virtio::vhost::user::device::handler) fn system_clear_rd_flags(
    _file: &File,
) -> VhostResult<()> {
    Ok(())
}

impl DeviceRequestHandler {
    pub async fn run(self, vhost_user_tube: Tube, exit_event: Event, ex: &Executor) -> Result<()> {
        let read_notifier = vhost_user_tube.get_read_notifier();
        let close_notifier = vhost_user_tube.get_close_notifier();

        // Safe because:
        // a) the underlying Event is guaranteed valid by the Tube.
        // b) we do NOT take ownership of the underlying Event. If we did that would cause an early
        //    free (and later a double free @ the end of this scope). This is why we have to wrap
        //    it in ManuallyDrop.
        // c) we own the clone that is produced exclusively, so it is safe to take ownership of it.
        let read_event = EventAsync::new(
            // Safe, see block comment.
            unsafe {
                ManuallyDrop::new(Event::from_raw_descriptor(
                    read_notifier.as_raw_descriptor(),
                ))
            }
            .try_clone()
            .context("failed to clone event")?,
            ex,
        )
        .context("failed to create an async event")?;
        let close_event = EventAsync::new(
            // Safe, see block comment.
            unsafe {
                ManuallyDrop::new(Event::from_raw_descriptor(
                    close_notifier.as_raw_descriptor(),
                ))
            }
            .try_clone()
            .context("failed to clone event")?,
            ex,
        )
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

        loop {
            select! {
                _read_res = read_event_fut => {
                    req_handler
                        .handle_request()
                        .context("failed to handle a vhost-user request")?;
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
    use super::*;

    use crate::virtio::vhost::user::device::handler::tests::*;
    use crate::virtio::vhost::user::device::handler::*;
    use crate::virtio::vhost::user::vmm::VhostUserHandler;

    use std::sync::Barrier;
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

            let mut vmm_handler = VhostUserHandler::new_from_tube(
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
