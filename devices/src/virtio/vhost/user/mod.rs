// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod device;
pub mod vmm;

use std::fmt::Debug;

pub use self::device::*;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod proxy;
        pub use self::proxy::*;
    } else if #[cfg(windows)] {}
}

use argh::FromArgValue;
use serde::Deserialize;

/// Extends any device configuration with a mandatory extra "vhost" parameter to specify the socket
/// or PCI device to use in order to communicate with a vhost client.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VhostUserParams<T: Debug> {
    pub vhost: String,
    #[serde(flatten)]
    pub device: T,
}

impl<T> FromArgValue for VhostUserParams<T>
where
    T: Debug + for<'de> Deserialize<'de>,
{
    fn from_arg_value(value: &str) -> std::result::Result<Self, String> {
        serde_keyvalue::from_key_values(value).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use argh::FromArgValue;
    use serde::Deserialize;
    use serde_keyvalue::*;

    use super::VhostUserParams;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    struct DummyDevice {
        path: PathBuf,
        #[serde(default)]
        boom_range: u32,
    }

    fn from_arg_value(s: &str) -> Result<VhostUserParams<DummyDevice>, String> {
        VhostUserParams::<DummyDevice>::from_arg_value(s)
    }

    #[test]
    fn vhost_user_params() {
        let device = from_arg_value("vhost=vhost_sock,path=/path/to/dummy,boom-range=42").unwrap();
        assert_eq!(device.vhost.as_str(), "vhost_sock");
        assert_eq!(
            device.device,
            DummyDevice {
                path: "/path/to/dummy".into(),
                boom_range: 42,
            }
        );

        // Default parameter of device not specified.
        let device = from_arg_value("vhost=vhost_sock,path=/path/to/dummy").unwrap();
        assert_eq!(device.vhost.as_str(), "vhost_sock");
        assert_eq!(
            device.device,
            DummyDevice {
                path: "/path/to/dummy".into(),
                boom_range: Default::default(),
            }
        );

        // Invalid parameter is rejected.
        assert_eq!(
            from_arg_value("vhost=vhost_sock,path=/path/to/dummy,boom-range=42,invalid-param=10")
                .unwrap_err(),
            "unknown field `invalid-param`".to_string(),
        );
    }
}
