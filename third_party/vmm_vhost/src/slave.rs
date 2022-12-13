// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Traits and Structs for vhost-user slave.
//!
//! These are used on platforms where the slave has to listen for connections (e.g. POSIX only).

use base::AsRawDescriptor;

use crate::connection::Endpoint;
use crate::connection::Listener;
use crate::message::*;
use crate::Result;
use crate::SlaveReqHandler;
use crate::VhostUserSlaveReqHandler;

/// Vhost-user slave side connection listener.
pub struct SlaveListener<L: Listener, S: VhostUserSlaveReqHandler> {
    listener: L,
    backend: Option<S>,
}

/// Sets up a listener for incoming master connections, and handles construction
/// of a Slave on success.
impl<L: Listener, S: VhostUserSlaveReqHandler> SlaveListener<L, S> {
    /// Create a unix domain socket for incoming master connections.
    pub fn new(listener: L, backend: S) -> Result<Self> {
        Ok(SlaveListener {
            listener,
            backend: Some(backend),
        })
    }

    /// Accept an incoming connection from the master, returning Some(Slave) on
    /// success, or None if the socket is nonblocking and no incoming connection
    /// was detected
    pub fn accept(&mut self) -> Result<Option<SlaveReqHandler<S, L::Endpoint>>>
    where
        <L as Listener>::Endpoint: Endpoint<MasterReq>,
    {
        if let Some(ep) = self.listener.accept()? {
            return Ok(Some(SlaveReqHandler::new(ep, self.backend.take().unwrap())));
        }
        Ok(None)
    }

    /// Change blocking status on the listener.
    pub fn set_nonblocking(&self, block: bool) -> Result<()> {
        self.listener.set_nonblocking(block)
    }
}

impl<L, S> AsRawDescriptor for SlaveListener<L, S>
where
    L: Listener + AsRawDescriptor,
    S: VhostUserSlaveReqHandler,
{
    fn as_raw_descriptor(&self) -> base::RawDescriptor {
        self.listener.as_raw_descriptor()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::connection::socket::Listener;
    use crate::dummy_slave::DummySlaveReqHandler;

    #[test]
    fn test_slave_listener_set_nonblocking() {
        let backend = Mutex::new(DummySlaveReqHandler::new());
        let listener =
            Listener::new("/tmp/vhost_user_lib_unit_test_slave_nonblocking", true).unwrap();
        let slave_listener = SlaveListener::<Listener, _>::new(listener, backend).unwrap();

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
        let backend = Mutex::new(DummySlaveReqHandler::new());
        let listener = Listener::new(path, true).unwrap();
        let mut slave_listener = SlaveListener::<Listener, _>::new(listener, backend).unwrap();

        slave_listener.set_nonblocking(true).unwrap();
        assert!(slave_listener.accept().unwrap().is_none());
        assert!(slave_listener.accept().unwrap().is_none());

        let _master = Master::<SocketEndpoint<_>>::connect(path).unwrap();
        let _slave = slave_listener.accept().unwrap().unwrap();
    }
}
