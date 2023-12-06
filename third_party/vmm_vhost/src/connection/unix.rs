// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unix specific code that keeps rest of the code in the crate platform independent.

#[cfg(test)]
pub(crate) mod tests {
    use tempfile::Builder;
    use tempfile::TempDir;

    use crate::connection::socket::SocketListener;
    use crate::connection::Listener;
    use crate::master::Master;
    use crate::message::MasterReq;
    use crate::slave_req_handler::SlaveReqHandler;
    use crate::slave_req_handler::VhostUserSlaveReqHandler;
    use crate::Connection;

    pub(crate) fn temp_dir() -> TempDir {
        Builder::new().prefix("/tmp/vhost_test").tempdir().unwrap()
    }

    pub(crate) fn create_pair() -> (Master, Connection<MasterReq>) {
        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let mut listener = SocketListener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let master = Master::connect(path).unwrap();
        let slave = listener.accept().unwrap().unwrap();
        (master, slave)
    }

    pub(crate) fn create_connection_pair() -> (Connection<MasterReq>, Connection<MasterReq>) {
        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let mut listener = SocketListener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let master = Connection::<MasterReq>::connect(path).unwrap();
        let slave = listener.accept().unwrap().unwrap();
        (master, slave)
    }

    pub(crate) fn create_master_slave_pair<S>(backend: S) -> (Master, SlaveReqHandler<S>)
    where
        S: VhostUserSlaveReqHandler,
    {
        let dir = Builder::new().prefix("/tmp/vhost_test").tempdir().unwrap();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let mut listener = SocketListener::new(&path, true).unwrap();
        let master = Master::connect(&path).unwrap();
        let connection = listener.accept().unwrap().unwrap();
        let req_handler = SlaveReqHandler::new(connection, backend);
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
        assert!(Master::connect(&path).is_err());

        let mut listener = SocketListener::new(&path, true).unwrap();
        assert!(SocketListener::new(&path, false).is_err());
        listener.set_nonblocking(true).unwrap();

        let _master = Master::connect(&path).unwrap();
        let _slave = listener.accept().unwrap().unwrap();
    }
}
