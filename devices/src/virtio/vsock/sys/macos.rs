// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::Path;

use serde::Deserialize;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
/// Configuration for a Vsock device.
pub struct VsockConfig {
    /// CID to be used for this vsock device.
    pub cid: u64,
    #[serde(default)]
    pub max_queue_sizes: Option<[u16; 3]>,
}

impl VsockConfig {
    /// Create a new vsock configuration.
    pub fn new<P: AsRef<Path>>(cid: u64, _vhost_device: Option<P>) -> Self {
        Self {
            cid,
            max_queue_sizes: None,
        }
    }
}
