// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows specific code that keeps rest of the code in the crate platform independent.

use base::Tube;

/// Alias to enable platform independent code.
pub type SystemStream = Tube;

pub(crate) use crate::connection::TubeEndpoint as PlatformEndpoint;
