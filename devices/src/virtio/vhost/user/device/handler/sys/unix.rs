// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Context;
use anyhow::Result;
use base::info;
use base::AsRawDescriptor;
use base::SafeDescriptor;
use cros_async::AsyncWrapper;
use cros_async::Executor;
use vmm_vhost::connection::Endpoint;
use vmm_vhost::message::MasterReq;
use vmm_vhost::Error as VhostError;
use vmm_vhost::SlaveReqHandler;
use vmm_vhost::VhostUserSlaveReqHandler;

/// Performs the run loop for an already-constructor request handler.
pub async fn run_handler<S, E>(mut req_handler: SlaveReqHandler<S, E>, ex: &Executor) -> Result<()>
where
    S: VhostUserSlaveReqHandler,
    E: Endpoint<MasterReq> + AsRawDescriptor,
{
    let h = SafeDescriptor::try_from(&req_handler as &dyn AsRawDescriptor)
        .map(AsyncWrapper::new)
        .context("failed to get safe descriptor for handler")?;
    let handler_source = ex
        .async_from(h)
        .context("failed to create an async source")?;

    loop {
        handler_source
            .wait_readable()
            .await
            .context("failed to wait for the handler to become readable")?;
        let (hdr, files) = match req_handler.recv_header() {
            Ok((hdr, files)) => (hdr, files),
            Err(VhostError::ClientExit) => {
                info!("vhost-user connection closed");
                // Exit as the client closed the connection.
                return Ok(());
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        if req_handler.needs_wait_for_payload(&hdr) {
            handler_source
                .wait_readable()
                .await
                .context("failed to wait for the handler to become readable")?;
        }
        req_handler.process_message(hdr, files)?;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::channel;
    use std::sync::Barrier;

    use tempfile::Builder;
    use tempfile::TempDir;
    use vmm_vhost::connection::Listener;

    use super::*;
    use crate::virtio::vhost::user::device::handler::tests::*;
    use crate::virtio::vhost::user::device::handler::*;
    use crate::virtio::vhost::user::vmm::VhostUserHandler;

    fn temp_dir() -> TempDir {
        Builder::new().prefix("/tmp/vhost_test").tempdir().unwrap()
    }

    #[test]
    fn test_vhost_user_activate() {
        use std::os::unix::net::UnixStream;

        use vmm_vhost::connection::socket::Listener as SocketListener;

        const QUEUES_NUM: usize = 2;

        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let mut listener = SocketListener::new(&path, true).unwrap();

        let vmm_bar = Arc::new(Barrier::new(2));
        let dev_bar = vmm_bar.clone();

        let (tx, rx) = channel();

        std::thread::spawn(move || {
            // VMM side
            rx.recv().unwrap(); // Ensure the device is ready.

            let allow_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            let init_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            let allow_protocol_features = VhostUserProtocolFeatures::CONFIG;
            let connection = UnixStream::connect(&path).unwrap();
            let mut vmm_handler = VhostUserHandler::new_from_connection(
                connection,
                allow_features,
                init_features,
                allow_protocol_features,
            )
            .unwrap();

            vmm_handler_send_requests(&mut vmm_handler, QUEUES_NUM);

            // The VMM side is supposed to stop before the device side.
            drop(vmm_handler);

            vmm_bar.wait();
        });

        // Device side
        let handler = std::sync::Mutex::new(DeviceRequestHandler::new(
            Box::new(FakeBackend::new()),
            Box::new(VhostUserRegularOps),
        ));

        // Notify listener is ready.
        tx.send(()).unwrap();

        let endpoint = listener.accept().unwrap().unwrap();
        let mut req_handler = SlaveReqHandler::new(endpoint, handler);

        test_handle_requests(&mut req_handler, QUEUES_NUM);

        dev_bar.wait();

        match req_handler.recv_header() {
            Err(VhostError::ClientExit) => (),
            r => panic!("Err(ClientExit) was expected but {:?}", r),
        }
    }
}
