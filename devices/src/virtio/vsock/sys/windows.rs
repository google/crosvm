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
