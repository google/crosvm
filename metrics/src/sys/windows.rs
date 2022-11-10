// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub(crate) mod controller;
pub mod gpu_metrics;
pub(crate) mod system_metrics;
pub mod wmi;

pub use gpu_metrics::*;
use win_util::ProcessType;

use crate::protos::event_details::EmulatorProcessType;

pub const METRIC_UPLOAD_INTERVAL_SECONDS: i64 = 60;
pub const API_GUEST_ANGLE_VK_ENUM_NAME: &str = "API_GUEST_ANGLE_VK";
pub const API_HOST_ANGLE_D3D_ENUM_NAME: &str = "API_HOST_ANGLE_D3D";
pub const API_UNKNOWN_ENUM_NAME: &str = "API_UNKNOWN";

#[derive(Debug)]
pub enum Error {
    CannotCloneEvent,
    CannotInstantiateEvent,
    InstanceAlreadyExists,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<ProcessType> for EmulatorProcessType {
    fn from(process_type: ProcessType) -> Self {
        match process_type {
            ProcessType::Block => EmulatorProcessType::PROCESS_TYPE_BLOCK,
            ProcessType::Main => EmulatorProcessType::PROCESS_TYPE_MAIN,
            ProcessType::Metrics => EmulatorProcessType::PROCESS_TYPE_METRICS,
            ProcessType::Net => EmulatorProcessType::PROCESS_TYPE_NET,
            ProcessType::Slirp => EmulatorProcessType::PROCESS_TYPE_SLIRP,
        }
    }
}
