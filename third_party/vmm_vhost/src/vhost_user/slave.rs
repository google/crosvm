// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Traits and Structs for vhost-user slave.

use std::sync::Arc;

use super::connection::{Endpoint, Listener};
use super::message::*;
use super::{Result, SlaveReqHandler, VhostUserSlaveReqHandler};

/// Vhost-user slave side connection listener.
pub struct SlaveListener<S: VhostUserSlaveReqHandler> {
    listener: Listener,
    backend: Option<Arc<S>>,
}

/// Sets up a listener for incoming master connections, and handles construction
/// of a Slave on success.
impl<S: VhostUserSlaveReqHandler> SlaveListener<S> {
    /// Create a unix domain socket for incoming master connections.
    pub fn new(listener: Listener, backend: Arc<S>) -> Result<Self> {
        Ok(SlaveListener {
            listener,
            backend: Some(backend),
        })
    }

    /// Accept an incoming connection from the master, returning Some(Slave) on
    /// success, or None if the socket is nonblocking and no incoming connection
    /// was detected
    pub fn accept(&mut self) -> Result<Option<SlaveReqHandler<S>>> {
        if let Some(fd) = self.listener.accept()? {
            return Ok(Some(SlaveReqHandler::new(
                Endpoint::<MasterReq>::from_stream(fd),
                self.backend.take().unwrap(),
            )));
        }
        Ok(None)
    }

    /// Change blocking status on the listener.
    pub fn set_nonblocking(&self, block: bool) -> Result<()> {
        self.listener.set_nonblocking(block)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::vhost_user::dummy_slave::DummySlaveReqHandler;

    #[test]
    fn test_slave_listener_set_nonblocking() {
        let backend = Arc::new(Mutex::new(DummySlaveReqHandler::new()));
        let listener =
            Listener::new("/tmp/vhost_user_lib_unit_test_slave_nonblocking", true).unwrap();
        let slave_listener = SlaveListener::new(listener, backend).unwrap();

        slave_listener.set_nonblocking(true).unwrap();
        slave_listener.set_nonblocking(false).unwrap();
        slave_listener.set_nonblocking(false).unwrap();
        slave_listener.set_nonblocking(true).unwrap();
        slave_listener.set_nonblocking(true).unwrap();
    }

    #[cfg(feature = "vhost-user-master")]
    #[test]
    fn test_slave_listener_accept() {
        use super::super::Master;

        let path = "/tmp/vhost_user_lib_unit_test_slave_accept";
        let backend = Arc::new(Mutex::new(DummySlaveReqHandler::new()));
        let listener = Listener::new(path, true).unwrap();
        let mut slave_listener = SlaveListener::new(listener, backend).unwrap();

        slave_listener.set_nonblocking(true).unwrap();
        assert!(slave_listener.accept().unwrap().is_none());
        assert!(slave_listener.accept().unwrap().is_none());

        let _master = Master::connect(path, 1).unwrap();
        let _slave = slave_listener.accept().unwrap().unwrap();
    }
}
