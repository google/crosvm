// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub(crate) mod controller;
pub mod gpu_metrics;
pub mod system_metrics;

use std::time::Duration;

pub use gpu_metrics::*;

pub const METRICS_UPLOAD_INTERVAL: Duration = Duration::from_secs(60);
pub const API_GUEST_ANGLE_VK_ENUM_NAME: &str = "API_GUEST_ANGLE_VK";
pub const API_HOST_ANGLE_D3D_ENUM_NAME: &str = "API_HOST_ANGLE_D3D";

#[derive(Debug)]
pub enum Error {
    CannotCloneEvent,
    CannotInstantiateEvent,
    InstanceAlreadyExists,
}

pub type Result<T> = std::result::Result<T, Error>;
