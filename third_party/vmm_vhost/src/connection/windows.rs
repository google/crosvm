// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows specific code that keeps rest of the code in the crate platform independent.

#[cfg(all(test, feature = "vmm"))]
pub(crate) mod tests {
    use crate::connection::TubeEndpoint;
    use crate::master::Master;
    use crate::message::MasterReq;
    use crate::slave_req_handler::SlaveReqHandler;
    use crate::slave_req_handler::VhostUserSlaveReqHandler;
    use crate::SystemStream;
    pub(crate) type TestEndpoint = TubeEndpoint<MasterReq>;
    pub(crate) type TestMaster = Master<TestEndpoint>;

    pub(crate) fn create_pair() -> (TestMaster, TestEndpoint) {
        let (master_tube, slave_tube) = SystemStream::pair().unwrap();
        let master = Master::from_stream(master_tube);
        (master, TubeEndpoint::from(slave_tube))
    }

    #[cfg(feature = "device")]
    pub(crate) fn create_master_slave_pair<S>(
        backend: S,
    ) -> (TestMaster, SlaveReqHandler<S, TestEndpoint>)
    where
        S: VhostUserSlaveReqHandler,
    {
        let (master_tube, slave_tube) = SystemStream::pair().unwrap();
        let master = Master::from_stream(master_tube);
        (
            master,
            SlaveReqHandler::<S, TubeEndpoint<MasterReq>>::from_stream(slave_tube, backend),
        )
    }
}
