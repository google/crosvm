// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str::FromStr;

#[cfg(all(feature = "prod-build", feature = "kiwi"))]
use devices::serial_device::SerialType;
#[cfg(feature = "audio")]
use devices::Ac97Parameters;
use devices::SerialParameters;
use serde::Deserialize;
use serde::Serialize;

use crate::crosvm::config::Config;

#[cfg(feature = "audio")]
pub fn parse_ac97_options(
    _ac97_params: &mut Ac97Parameters,
    key: &str,
    value: &str,
) -> Result<(), String> {
    Err(format!("unknown ac97 parameter {} {}", key, value))
}

pub fn check_serial_params(
    #[allow(unused_variables)] serial_params: &SerialParameters,
) -> Result<(), String> {
    #[cfg(all(feature = "prod-build", feature = "kiwi"))]
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

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum IrqChipKind {
    /// All interrupt controllers are emulated in the kernel.
    Kernel,
    /// APIC is emulated in the kernel.  All other interrupt controllers are in userspace.
    Split,
    /// All interrupt controllers are emulated in userspace.
    Userspace,
}

impl FromStr for IrqChipKind {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "kernel" => Ok(Self::Kernel),
            "split" => Ok(Self::Split),
            "userspace" => Ok(Self::Userspace),
            _ => Err("invalid irqchip kind: expected \"kernel\", \"split\", or \"userspace\""),
        }
    }
}

/// Hypervisor backend.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "audio")]
    #[test]
    fn parse_ac97_vaild() {
        crate::crosvm::config::parse_ac97_options("backend=win_audio")
            .expect("parse should have succeded");
    }
}
