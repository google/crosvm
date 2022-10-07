// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows specific code that keeps rest of the code in the crate platform independent.

use std::sync::Arc;

use base::AsRawDescriptor;
use base::CloseNotifier;
use base::ReadNotifier;
use tube_transporter::packed_tube;

use crate::master_req_handler::MasterReqHandler;
use crate::Result;
use crate::VhostUserMasterReqHandler;

impl<S: VhostUserMasterReqHandler> MasterReqHandler<S> {
    /// Create a `MasterReqHandler` that uses a Tube internally. Must specify the backend process
    /// which will receive the Tube.
    pub fn with_tube(backend: Arc<S>, backend_pid: u32) -> Result<Self> {
        Self::new(
            backend,
            Box::new(move |tube| unsafe {
                // Safe because we expect the tube to be unpacked in the other process.
                packed_tube::pack(tube, backend_pid).expect("packed tube")
            }),
        )
    }
}

impl<S: VhostUserMasterReqHandler> ReadNotifier for MasterReqHandler<S> {
    /// Used for polling.
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self.sub_sock.get_tube().get_read_notifier()
    }
}

impl<S: VhostUserMasterReqHandler> CloseNotifier for MasterReqHandler<S> {
    /// Used for closing.
    fn get_close_notifier(&self) -> &dyn AsRawDescriptor {
        self.sub_sock.get_tube().get_close_notifier()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use base::AsRawDescriptor;
    use base::Descriptor;
    use base::INVALID_DESCRIPTOR;

    use super::*;
    use crate::message::VhostUserFSSlaveMsg;
    use crate::HandlerResult;
    #[cfg(feature = "device")]
    use crate::Slave;
    use crate::VhostUserMasterReqHandlerMut;

    struct MockMasterReqHandler {}

    impl VhostUserMasterReqHandlerMut for MockMasterReqHandler {
        /// Handle virtio-fs map file requests from the slave.
        fn fs_slave_map(
            &mut self,
            _fs: &VhostUserFSSlaveMsg,
            _fd: &dyn AsRawDescriptor,
        ) -> HandlerResult<u64> {
            Ok(0)
        }

        /// Handle virtio-fs unmap file requests from the slave.
        fn fs_slave_unmap(&mut self, _fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
            Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
        }
    }

    #[test]
    fn test_new_master_req_handler() {
        let backend = Arc::new(Mutex::new(MockMasterReqHandler {}));
        let handler = MasterReqHandler::with_tube(backend, std::process::id()).unwrap();

        assert!(handler.get_read_notifier().as_raw_descriptor() != INVALID_DESCRIPTOR);
        assert!(handler.get_close_notifier().as_raw_descriptor() != INVALID_DESCRIPTOR);
    }

    #[cfg(feature = "device")]
    #[test]
    fn test_master_slave_req_handler() {
        let backend = Arc::new(Mutex::new(MockMasterReqHandler {}));
        let mut handler = MasterReqHandler::with_tube(backend, std::process::id()).unwrap();

        let event = base::Event::new().unwrap();
        let tx_descriptor = handler.take_tx_descriptor();
        // Safe because we only do it once.
        let stream = unsafe { packed_tube::unpack(tx_descriptor).unwrap() };
        let fs_cache = Slave::from_stream(stream);

        std::thread::spawn(move || {
            let res = handler.handle_request().unwrap();
            assert_eq!(res, 0);
            handler.handle_request().unwrap_err();
        });

        fs_cache
            .fs_slave_map(
                &VhostUserFSSlaveMsg::default(),
                &Descriptor(event.as_raw_descriptor()),
            )
            .unwrap();
        // When REPLY_ACK has not been negotiated, the master has no way to detect failure from
        // slave side.
        fs_cache
            .fs_slave_unmap(&VhostUserFSSlaveMsg::default())
            .unwrap();
    }

    #[cfg(feature = "device")]
    #[test]
    fn test_master_slave_req_handler_with_ack() {
        let backend = Arc::new(Mutex::new(MockMasterReqHandler {}));
        let mut handler = MasterReqHandler::with_tube(backend, std::process::id()).unwrap();
        handler.set_reply_ack_flag(true);

        let event = base::Event::new().unwrap();
        let tx_descriptor = handler.take_tx_descriptor();
        // Safe because we only do it once.
        let stream = unsafe { packed_tube::unpack(tx_descriptor).unwrap() };
        let fs_cache = Slave::from_stream(stream);

        std::thread::spawn(move || {
            let res = handler.handle_request().unwrap();
            assert_eq!(res, 0);
            handler.handle_request().unwrap_err();
        });

        fs_cache.set_reply_ack_flag(true);
        fs_cache
            .fs_slave_map(
                &VhostUserFSSlaveMsg::default(),
                &Descriptor(event.as_raw_descriptor()),
            )
            .unwrap();
        fs_cache
            .fs_slave_unmap(&VhostUserFSSlaveMsg::default())
            .unwrap_err();
    }
}
