// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

pub(crate) mod sys;

pub mod commands;
pub mod constants;
mod device;

pub use device::Controller;
pub use device::DiskConfig;

fn scsi_option_block_size_default() -> u32 {
    512
}

/// Parameters for setting up a SCSI device.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, serde_keyvalue::FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ScsiOption {
    // Path to the SCSI image.
    pub path: PathBuf,
    // Indicates whether the device is ready only.
    #[serde(default, rename = "ro")]
    pub read_only: bool,
    // The block size of the device.
    #[serde(default = "scsi_option_block_size_default")]
    pub block_size: u32,
    /// Whether this scsi device should be the root device. Can only be set once. Only useful for
    /// adding specific command-line options.
    #[serde(default)]
    pub root: bool,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use serde_keyvalue::from_key_values;

    #[test]
    fn parse_scsi_options() {
        let scsi_option = from_key_values::<ScsiOption>("/path/to/image").unwrap();
        assert_eq!(
            scsi_option,
            ScsiOption {
                path: Path::new("/path/to/image").to_path_buf(),
                read_only: false,
                block_size: 512,
                root: false,
            }
        );

        let scsi_option = from_key_values::<ScsiOption>("/path/to/image,ro").unwrap();
        assert_eq!(
            scsi_option,
            ScsiOption {
                path: Path::new("/path/to/image").to_path_buf(),
                read_only: true,
                block_size: 512,
                root: false,
            }
        );

        let scsi_option = from_key_values::<ScsiOption>("/path/to/image,block-size=1024").unwrap();
        assert_eq!(
            scsi_option,
            ScsiOption {
                path: Path::new("/path/to/image").to_path_buf(),
                read_only: false,
                block_size: 1024,
                root: false,
            }
        );

        let scsi_option =
            from_key_values::<ScsiOption>("/path/to/image,block-size=1024,root").unwrap();
        assert_eq!(
            scsi_option,
            ScsiOption {
                path: Path::new("/path/to/image").to_path_buf(),
                read_only: false,
                block_size: 1024,
                root: true,
            }
        );
    }
}
