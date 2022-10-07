// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unix specific code that keeps rest of the code in the crate platform independent.

use std::os::unix::io::IntoRawFd;
use std::sync::Arc;

use base::AsRawDescriptor;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::SafeDescriptor;

use crate::master_req_handler::MasterReqHandler;
use crate::Result;
use crate::VhostUserMasterReqHandler;

impl<S: VhostUserMasterReqHandler> AsRawDescriptor for MasterReqHandler<S> {
    /// Used for polling.
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.sub_sock.as_raw_descriptor()
    }
}

impl<S: VhostUserMasterReqHandler> MasterReqHandler<S> {
    /// Create a `MasterReqHandler` that uses a Unix stream internally.
    pub fn with_stream(backend: Arc<S>) -> Result<Self> {
        Self::new(
            backend,
            Box::new(|stream| unsafe {
                // Safe because we own the raw fd.
                SafeDescriptor::from_raw_descriptor(stream.into_raw_fd())
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use base::AsRawDescriptor;
    use base::Descriptor;
    use base::FromRawDescriptor;
    use base::INVALID_DESCRIPTOR;

    use super::*;
    use crate::message::VhostUserFSSlaveMsg;
    use crate::HandlerResult;
    #[cfg(feature = "device")]
    use crate::Slave;
    use crate::SystemStream;
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
        let mut handler = MasterReqHandler::with_stream(backend).unwrap();

        let tx_descriptor = handler.take_tx_descriptor();
        assert!(tx_descriptor.as_raw_descriptor() >= 0);
        assert!(handler.as_raw_descriptor() != INVALID_DESCRIPTOR);
    }

    #[cfg(feature = "device")]
    #[test]
    fn test_master_slave_req_handler() {
        let backend = Arc::new(Mutex::new(MockMasterReqHandler {}));
        let mut handler = MasterReqHandler::with_stream(backend).unwrap();

        let tx_descriptor = handler.take_tx_descriptor();
        let fd = unsafe { libc::dup(tx_descriptor.as_raw_descriptor()) };
        if fd < 0 {
            panic!("failed to duplicated tx fd!");
        }
        let stream = unsafe { SystemStream::from_raw_descriptor(fd) };
        let fs_cache = Slave::from_stream(stream);

        std::thread::spawn(move || {
            let res = handler.handle_request().unwrap();
            assert_eq!(res, 0);
            handler.handle_request().unwrap_err();
        });

        fs_cache
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &Descriptor(fd))
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
        let mut handler = MasterReqHandler::with_stream(backend).unwrap();
        handler.set_reply_ack_flag(true);

        let tx_descriptor = handler.take_tx_descriptor();
        let fd = unsafe { libc::dup(tx_descriptor.as_raw_descriptor()) };
        if fd < 0 {
            panic!("failed to duplicated tx fd!");
        }
        let stream = unsafe { SystemStream::from_raw_descriptor(fd) };
        let fs_cache = Slave::from_stream(stream);

        std::thread::spawn(move || {
            let res = handler.handle_request().unwrap();
            assert_eq!(res, 0);
            handler.handle_request().unwrap_err();
        });

        fs_cache.set_reply_ack_flag(true);
        fs_cache
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &Descriptor(fd))
            .unwrap();
        fs_cache
            .fs_slave_unmap(&VhostUserFSSlaveMsg::default())
            .unwrap_err();
    }
}
