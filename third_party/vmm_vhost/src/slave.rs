// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Traits and Structs for vhost-user slave.
//!
//! These are used on platforms where the slave has to listen for connections (e.g. POSIX only).

use std::sync::Arc;

use super::connection::{Endpoint, Listener};
use super::message::*;
use super::{Result, SlaveReqHandler, VhostUserSlaveReqHandler};

/// Vhost-user slave side connection listener.
pub struct SlaveListener<E: Endpoint<MasterReq>, S: VhostUserSlaveReqHandler> {
    listener: E::Listener,
    backend: Option<Arc<S>>,
}

/// Sets up a listener for incoming master connections, and handles construction
/// of a Slave on success.
impl<E: Endpoint<MasterReq>, S: VhostUserSlaveReqHandler> SlaveListener<E, S> {
    /// Create a unix domain socket for incoming master connections.
    pub fn new(listener: E::Listener, backend: Arc<S>) -> Result<Self> {
        Ok(SlaveListener {
            listener,
            backend: Some(backend),
        })
    }

    /// Accept an incoming connection from the master, returning Some(Slave) on
    /// success, or None if the socket is nonblocking and no incoming connection
    /// was detected
    pub fn accept(&mut self) -> Result<Option<SlaveReqHandler<S, E>>> {
        if let Some(fd) = self.listener.accept()? {
            return Ok(Some(SlaveReqHandler::new(
                E::from_connection(fd),
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
    use crate::connection::socket::{Endpoint, Listener};
    use crate::dummy_slave::DummySlaveReqHandler;

    #[test]
    fn test_slave_listener_set_nonblocking() {
        let backend = Arc::new(Mutex::new(DummySlaveReqHandler::new()));
        let listener =
            Listener::new("/tmp/vhost_user_lib_unit_test_slave_nonblocking", true).unwrap();
        let slave_listener = SlaveListener::<Endpoint<_>, _>::new(listener, backend).unwrap();

        slave_listener.set_nonblocking(true).unwrap();
        slave_listener.set_nonblocking(false).unwrap();
        slave_listener.set_nonblocking(false).unwrap();
        slave_listener.set_nonblocking(true).unwrap();
        slave_listener.set_nonblocking(true).unwrap();
    }

    #[cfg(feature = "vmm")]
    #[test]
    fn test_slave_listener_accept() {
        use crate::connection::socket::Endpoint as SocketEndpoint;
        use crate::Master;

        let path = "/tmp/vhost_user_lib_unit_test_slave_accept";
        let backend = Arc::new(Mutex::new(DummySlaveReqHandler::new()));
        let listener = Listener::new(path, true).unwrap();
        let mut slave_listener = SlaveListener::<Endpoint<_>, _>::new(listener, backend).unwrap();

        slave_listener.set_nonblocking(true).unwrap();
        assert!(slave_listener.accept().unwrap().is_none());
        assert!(slave_listener.accept().unwrap().is_none());

        let _master = Master::<SocketEndpoint<_>>::connect(path, 1).unwrap();
        let _slave = slave_listener.accept().unwrap().unwrap();
    }
}
