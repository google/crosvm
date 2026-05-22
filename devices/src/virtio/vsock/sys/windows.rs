// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod protocol;
pub mod vsock;

pub(crate) use protocol::*;
use serde::Deserialize;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;
pub use vsock::Vsock;
pub use vsock::VsockError;

use crate::virtio::VirtioDevice;
use crate::VirtioDeviceArgs;
use crate::VirtioDeviceModule;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, FromKeyValues)]
#[serde(deny_unknown_fields)]
// Configuration for a Vsock device.
pub struct VsockConfig {
    /// CID to be used for this vsock device.
    pub cid: u64,
}

impl VsockConfig {
    /// Create a new vsock configuration.
    pub fn new(cid: u64) -> Self {
        Self { cid }
    }
}

#[derive(Serialize, Deserialize)]
pub struct VirtioVsockModule {
    config: VsockConfig,
    host_guid: Option<String>,
}

impl VirtioVsockModule {
    pub fn new(config: VsockConfig, host_guid: Option<String>) -> Self {
        Self { config, host_guid }
    }
}

impl VirtioDeviceModule for VirtioVsockModule {
    fn sort_name(&self) -> &'static str {
        "vsock"
    }

    fn create(&self, args: &mut VirtioDeviceArgs<'_>) -> anyhow::Result<Box<dyn VirtioDevice>> {
        let dev = Vsock::new(
            self.config.cid,
            self.host_guid.clone(),
            crate::virtio::base_features(args.protection_type),
        )?;
        Ok(Box::new(dev))
    }
}

#[cfg(test)]
mod tests {
    use serde_keyvalue::from_key_values;
    use serde_keyvalue::ErrorKind;
    use serde_keyvalue::ParseError;

    use super::*;

    fn from_vsock_arg(options: &str) -> Result<VsockConfig, ParseError> {
        from_key_values(options)
    }

    #[test]
    fn params_from_key_values() {
        // Default device
        assert_eq!(from_vsock_arg("cid=56").unwrap(), VsockConfig { cid: 56 });

        // No argument
        assert_eq!(
            from_vsock_arg("").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("missing field `cid`".into()),
                pos: 0
            }
        );

        // Cid passed twice
        assert_eq!(
            from_vsock_arg("cid=42,cid=56").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("duplicate field `cid`".into()),
                pos: 0,
            }
        );

        // Invalid argument
        assert_eq!(
            from_vsock_arg("invalid=foo").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("unknown field `invalid`, expected `cid`".into()),
                pos: 0,
            }
        );
    }
}
