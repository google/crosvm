// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows specific code that keeps rest of the code in the crate platform independent.

#[cfg(test)]
pub(crate) mod tests {
    use crate::master::Master;
    use crate::message::MasterReq;
    use crate::slave_req_handler::SlaveReqHandler;
    use crate::slave_req_handler::VhostUserSlaveReqHandler;
    use crate::Endpoint;
    use crate::SystemStream;

    pub(crate) fn create_pair() -> (Master, Endpoint<MasterReq>) {
        let (master_tube, slave_tube) = SystemStream::pair().unwrap();
        let master = Master::from_stream(master_tube);
        (master, Endpoint::from(slave_tube))
    }

    pub(crate) fn create_master_slave_pair<S>(backend: S) -> (Master, SlaveReqHandler<S>)
    where
        S: VhostUserSlaveReqHandler,
    {
        let (master_tube, slave_tube) = SystemStream::pair().unwrap();
        let master = Master::from_stream(master_tube);
        (
            master,
            SlaveReqHandler::<S>::from_stream(slave_tube, backend),
        )
    }
}
