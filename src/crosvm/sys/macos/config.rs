// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str::FromStr;

use devices::SerialParameters;
use serde::Deserialize;
use serde::Serialize;

use crate::crosvm::config::Config;

pub fn check_serial_params(
    _serial_params: &SerialParameters,
) -> Result<(), String> {
    Ok(())
}

pub fn validate_config(_cfg: &mut Config) -> std::result::Result<(), String> {
    Ok(())
}

/// Hypervisor backend for macOS.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub enum HypervisorKind {
    #[cfg(target_arch = "aarch64")]
    Hvf,
}

impl FromStr for HypervisorKind {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            #[cfg(target_arch = "aarch64")]
            "hvf" => Ok(HypervisorKind::Hvf),
            _ => Err("unknown hypervisor backend"),
        }
    }
}

impl Default for HypervisorKind {
    fn default() -> Self {
        #[cfg(target_arch = "aarch64")]
        return HypervisorKind::Hvf;
    }
}
