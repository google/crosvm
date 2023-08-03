// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str::FromStr;

#[cfg(feature = "prod-build")]
use devices::serial_device::SerialType;
use devices::SerialParameters;
use serde::Deserialize;
use serde::Serialize;

use crate::crosvm::config::Config;

pub fn check_serial_params(
    #[allow(unused_variables)] serial_params: &SerialParameters,
) -> Result<(), String> {
    #[cfg(feature = "prod-build")]
    {
        if matches!(serial_params.type_, SerialType::SystemSerialType) {
            return Err(format!(
                "device type not supported: {}",
                serial_params.type_.to_string()
            ));
        }
        if serial_params.stdin {
            return Err(format!("parameter not supported: stdin"));
        }
    }
    Ok(())
}

pub fn validate_config(_cfg: &mut Config) -> std::result::Result<(), String> {
    Ok(())
}

/// Hypervisor backend.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub enum HypervisorKind {
    #[cfg(feature = "gvm")]
    Gvm,
    #[cfg(feature = "haxm")]
    Haxm,
    #[cfg(feature = "haxm")]
    Ghaxm,
    #[cfg(feature = "whpx")]
    Whpx,
}

impl FromStr for HypervisorKind {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "gvm")]
            "gvm" => Ok(HypervisorKind::Gvm),
            #[cfg(feature = "haxm")]
            "haxm" => Ok(HypervisorKind::Haxm),
            #[cfg(feature = "haxm")]
            "ghaxm" => Ok(HypervisorKind::Ghaxm),
            #[cfg(feature = "whpx")]
            "whpx" => Ok(HypervisorKind::Whpx),
            _ => Err("invalid hypervisor backend"),
        }
    }
}
