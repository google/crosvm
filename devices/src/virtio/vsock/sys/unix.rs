// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

static VHOST_VSOCK_DEFAULT_PATH: &str = "/dev/vhost-vsock";

fn default_vsock_path() -> PathBuf {
    PathBuf::from(VHOST_VSOCK_DEFAULT_PATH)
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]

/// Configuration for a Vsock device.
pub struct VsockConfig {
    /// CID to be used for this vsock device.
    pub cid: u64,
    /// Path to the vhost-vsock device.
    #[serde(default = "default_vsock_path", rename = "device")]
    pub vhost_device: PathBuf,
}

impl VsockConfig {
    /// Create a new vsock configuration. If `vhost_device` is `None`, the default vhost-vsock
    /// device path will be used.
    pub fn new<P: AsRef<Path>>(cid: u64, vhost_device: Option<P>) -> Self {
        Self {
            cid,
            #[cfg(unix)]
            vhost_device: vhost_device
                .map(|p| PathBuf::from(p.as_ref()))
                .unwrap_or_else(|| PathBuf::from(VHOST_VSOCK_DEFAULT_PATH)),
        }
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
        assert_eq!(
            from_vsock_arg("cid=56").unwrap(),
            VsockConfig {
                vhost_device: VHOST_VSOCK_DEFAULT_PATH.into(),
                cid: 56,
            }
        );

        // No argument
        assert_eq!(
            from_vsock_arg("").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("missing field `cid`".into()),
                pos: 0
            }
        );

        // CID passed without key
        assert_eq!(
            from_vsock_arg("78").unwrap(),
            VsockConfig {
                #[cfg(unix)]
                vhost_device: VHOST_VSOCK_DEFAULT_PATH.into(),
                cid: 78,
            }
        );

        // CID passed twice
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
                kind: ErrorKind::SerdeError(
                    "unknown field `invalid`, expected `cid` or `device`".into()
                ),
                pos: 0,
            }
        );

        // Path device
        assert_eq!(
            from_vsock_arg("device=/some/path,cid=56").unwrap(),
            VsockConfig {
                vhost_device: "/some/path".into(),
                cid: 56,
            }
        );

        // CID passed without key
        assert_eq!(
            from_vsock_arg("56,device=/some/path").unwrap(),
            VsockConfig {
                vhost_device: "/some/path".into(),
                cid: 56,
            }
        );

        // Missing cid
        assert_eq!(
            from_vsock_arg("device=42").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("missing field `cid`".into()),
                pos: 0,
            }
        );

        // Device passed twice
        assert_eq!(
            from_vsock_arg("cid=56,device=42,device=/some/path").unwrap_err(),
            ParseError {
                kind: ErrorKind::SerdeError("duplicate field `device`".into()),
                pos: 0,
            }
        );
    }
}
