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
