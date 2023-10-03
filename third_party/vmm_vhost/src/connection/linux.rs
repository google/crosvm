// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unix specific code that keeps rest of the code in the crate platform independent.

#[cfg(all(test, feature = "vmm"))]
pub(crate) mod tests {
    use tempfile::Builder;
    use tempfile::TempDir;

    use crate::connection::socket::Endpoint as SocketEndpoint;
    use crate::connection::socket::Listener as SocketListener;
    use crate::connection::Listener;
    use crate::master::Master;
    use crate::message::MasterReq;
    use crate::slave_req_handler::SlaveReqHandler;
    use crate::slave_req_handler::VhostUserSlaveReqHandler;

    pub(crate) type TestMaster = Master<SocketEndpoint<MasterReq>>;
    pub(crate) type TestEndpoint = SocketEndpoint<MasterReq>;
    pub(crate) fn temp_dir() -> TempDir {
        Builder::new().prefix("/tmp/vhost_test").tempdir().unwrap()
    }

    pub(crate) fn create_pair() -> (Master<SocketEndpoint<MasterReq>>, SocketEndpoint<MasterReq>) {
        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let mut listener = SocketListener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let master = Master::connect(path).unwrap();
        let slave = listener.accept().unwrap().unwrap();
        (master, slave)
    }

    #[cfg(feature = "device")]
    pub(crate) fn create_master_slave_pair<S>(
        backend: S,
    ) -> (TestMaster, SlaveReqHandler<S, TestEndpoint>)
    where
        S: VhostUserSlaveReqHandler,
    {
        let dir = Builder::new().prefix("/tmp/vhost_test").tempdir().unwrap();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let mut listener = SocketListener::new(&path, true).unwrap();
        let master = Master::connect(&path).unwrap();
        let endpoint = listener.accept().unwrap().unwrap();
        let req_handler = SlaveReqHandler::new(endpoint, backend);
        (master, req_handler)
    }

    // Create failures don't happen on using Tubes because there is no "connection". (The channel is
    // already up when we invoke this library.)
    #[test]
    fn test_create_failure() {
        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let _ = SocketListener::new(&path, true).unwrap();
        let _ = SocketListener::new(&path, false).is_err();
        assert!(Master::<SocketEndpoint<_>>::connect(&path).is_err());

        let mut listener = SocketListener::new(&path, true).unwrap();
        assert!(SocketListener::new(&path, false).is_err());
        listener.set_nonblocking(true).unwrap();

        let _master = Master::<SocketEndpoint<_>>::connect(&path).unwrap();
        let _slave = listener.accept().unwrap().unwrap();
    }
}
