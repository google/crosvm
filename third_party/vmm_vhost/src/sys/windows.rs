// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows specific code that keeps rest of the code in the crate platform independent.

use base::Tube;

/// Alias to enable platform independent code.
pub type SystemStream = Tube;

cfg_if::cfg_if! {
    if #[cfg(feature = "device")] {
        use crate::connection::TubeEndpoint;
        use crate::message::{MasterReq, SlaveReq};

        pub(crate) type SlaveReqEndpoint = TubeEndpoint<SlaveReq>;
        pub(crate) type MasterReqEndpoint = TubeEndpoint<MasterReq>;
    }
}
