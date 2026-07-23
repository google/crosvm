// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;

use anyhow::Context;
use devices::virtio::VirtioDevice;
use devices::VirtioDeviceArgs;
use devices::VirtioDeviceModule;
use serde::Deserialize;
use serde::Serialize;

pub(crate) mod sys;

pub mod commands;
pub mod constants;
mod device;

pub use device::Controller;
pub use device::DiskConfig;

fn scsi_option_lock_default() -> bool {
    true
}
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
    /// Whether to lock the disk files. Uses flock on Unix and FILE_SHARE_* flags on Windows.
    #[serde(default = "scsi_option_lock_default")]
    pub lock: bool,
    // The block size of the device.
    #[serde(default = "scsi_option_block_size_default")]
    pub block_size: u32,
    /// Whether this scsi device should be the root device. Can only be set once. Only useful for
    /// adding specific command-line options.
    #[serde(default)]
    pub root: bool,
}

/// Module for creating a Virtio SCSI controller device.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VirtioScsiModule {
    pub disks: Vec<ScsiOption>,
}

impl VirtioScsiModule {
    pub fn new(disks: Vec<ScsiOption>) -> Self {
        Self { disks }
    }
}

impl VirtioDeviceModule for VirtioScsiModule {
    fn sort_name(&self) -> &'static str {
        "scsi"
    }

    fn create(&self, args: &mut VirtioDeviceArgs<'_>) -> anyhow::Result<Box<dyn VirtioDevice>> {
        let base_features = devices::virtio::base_features(args.protection_type);
        let disks = self
            .disks
            .iter()
            .map(|op| {
                base::info!("Trying to attach a scsi device: {}", op.path.display());
                Ok(DiskConfig {
                    file: op.open()?,
                    block_size: op.block_size,
                    read_only: op.read_only,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let controller =
            Controller::new(base_features, disks).context("failed to create a scsi controller")?;
        Ok(Box::new(controller))
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn create_jail(
        &self,
        jail_config: &jail::JailConfig,
    ) -> anyhow::Result<Option<minijail::Minijail>> {
        let jail = jail::simple_jail(
            Some(jail_config),
            &devices::virtio::VirtioDeviceType::Regular.seccomp_policy_file("scsi"),
        )?;
        Ok(jail)
    }
}

#[cfg(test)]
impl Default for ScsiOption {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
            read_only: false,
            lock: scsi_option_lock_default(),
            block_size: scsi_option_block_size_default(),
            root: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_keyvalue::from_key_values;

    use super::*;

    #[test]
    fn parse_scsi_options() {
        let scsi_option = from_key_values::<ScsiOption>("/path/to/image").unwrap();
        assert_eq!(
            scsi_option,
            ScsiOption {
                path: Path::new("/path/to/image").to_path_buf(),
                ..Default::default()
            }
        );

        let scsi_option = from_key_values::<ScsiOption>("/path/to/image,ro").unwrap();
        assert_eq!(
            scsi_option,
            ScsiOption {
                path: Path::new("/path/to/image").to_path_buf(),
                read_only: true,
                ..Default::default()
            }
        );

        let scsi_option = from_key_values::<ScsiOption>("/path/to/image,block-size=1024").unwrap();
        assert_eq!(
            scsi_option,
            ScsiOption {
                path: Path::new("/path/to/image").to_path_buf(),
                block_size: 1024,
                ..Default::default()
            }
        );

        let scsi_option =
            from_key_values::<ScsiOption>("/path/to/image,block-size=1024,root").unwrap();
        assert_eq!(
            scsi_option,
            ScsiOption {
                path: Path::new("/path/to/image").to_path_buf(),
                block_size: 1024,
                root: true,
                ..Default::default()
            }
        );
    }
}
