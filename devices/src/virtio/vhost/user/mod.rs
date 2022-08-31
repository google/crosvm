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
use serde_keyvalue::ErrorKind;
use serde_keyvalue::KeyValueDeserializer;

/// Extends any device configuration with a mandatory extra "vhost" parameter to specify the socket
/// or PCI device to use in order to communicate with a vhost client.
///
/// The `vhost` argument must come first, followed by all the arguments required by `device`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VhostUserParams<T: Debug> {
    pub vhost: String,
    pub device: T,
}

impl<T> FromArgValue for VhostUserParams<T>
where
    T: Debug + for<'de> Deserialize<'de>,
{
    fn from_arg_value(value: &str) -> std::result::Result<Self, String> {
        // `from_arg_value` returns a `String` as error, but our deserializer API defines its own
        // error type. Perform parsing from a closure so we can easily map returned errors.
        let builder = move || {
            let mut deserializer = KeyValueDeserializer::from(value);

            // Parse the "vhost" parameter
            let id = deserializer.parse_identifier()?;
            if id != "vhost" {
                return Err(deserializer
                    .error_here(ErrorKind::SerdeError("expected \"vhost\" parameter".into())));
            }
            if deserializer.next_char() != Some('=') {
                return Err(deserializer.error_here(ErrorKind::ExpectedEqual));
            }
            let vhost = deserializer.parse_string()?;
            match deserializer.next_char() {
                Some(',') | None => (),
                _ => return Err(deserializer.error_here(ErrorKind::ExpectedComma)),
            }

            // Parse the device-specific parameters and finish
            let device = T::deserialize(&mut deserializer)?;
            deserializer.finish()?;

            Ok(Self {
                vhost: vhost.into(),
                device,
            })
        };

        builder().map_err(|e| e.to_string())
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
            "unknown field `invalid-param`, expected `path` or `boom-range`".to_string(),
        );

        // Device path can be parsed even if specified as a number.
        // This ensures that we don't flatten the `device` member, which would result in
        // `deserialize_any` being called and the type of `path` to be mistaken for an integer.
        let device = from_arg_value("vhost=vhost_sock,path=10").unwrap();
        assert_eq!(device.vhost.as_str(), "vhost_sock");
        assert_eq!(
            device.device,
            DummyDevice {
                path: "10".into(),
                boom_range: Default::default(),
            }
        );

        // Misplaced `vhost` parameter is rejected
        let _ = from_arg_value("path=/path/to/dummy,vhost=vhost_sock,boom-range=42").unwrap_err();
    }
}
