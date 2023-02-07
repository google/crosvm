// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;

use anyhow::Result;
use base::RecvTube;
use base::SendTube;
use serde::Deserialize;
use serde::Serialize;
#[cfg(windows)]
use win_util::ProcessType;

#[cfg(unix)]
pub enum ProcessType {}

/// The reason a SimulatedException crash report is being requested.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum CrashReportReason {
    /// A default value for unspecified crash report reason.
    Unknown,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
enum CrashTubeCommand {
    UploadCrashReport(CrashReportReason),
}

pub mod product_type {
    pub const EMULATOR: &str = "KiwiEmulator_main";
    pub const BROKER: &str = "KiwiEmulator_broker";
    pub const DISK: &str = "KiwiEmulator_disk";
    pub const NET: &str = "KiwiEmulator_net";
    pub const SLIRP: &str = "KiwiEmulator_slirp";
    pub const METRICS: &str = "KiwiEmulator_metrics";
    pub const GPU: &str = "KiwiEmulator_gpu";
}

/// Attributes about a process that are required to set up annotations for crash reports.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CrashReportAttributes {
    pub product_type: String,
    pub pipe_name: Option<String>,
    pub report_uuid: Option<String>,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
}

/// Handler for remote crash requests from other processes.
pub struct RemoteCrashHandler {}

impl RemoteCrashHandler {
    /// Creates a handler for remote crash requests from other processes.
    pub fn new(_crash_tube: RecvTube) -> Result<Self> {
        Ok(Self {})
    }
}

impl Drop for RemoteCrashHandler {
    fn drop(&mut self) {}
}

/// Setup crash reporting for a process. Each process MUST provide a unique `product_type` to avoid
/// making crash reports incomprehensible.
pub fn setup_crash_reporting(mut _attrs: CrashReportAttributes) -> Result<String> {
    Ok(String::new())
}

/// Sets a map of tubes to trigger SimulatedException crash reports for each process type.  Should
/// only be called on the main process.
pub fn set_crash_tube_map(_map: HashMap<ProcessType, Vec<SendTube>>) {}

/// Captures a crash dump and uploads a crash report, without crashing the process.
///
/// A crash report from the current process is always taken, modulo rate limiting.  Additionally,
/// crash reports can be triggered on other processes, if the caller is the main process and
/// `reason` was mapped to process types with `set_crash_tube_map`.
pub fn upload_crash_report(_reason: CrashReportReason) {}

/// Sets the package name to given `_package_name`.
pub fn set_package_name(_package_name: &str) {}
