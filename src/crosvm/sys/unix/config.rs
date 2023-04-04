// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;

use devices::IommuDevType;
use devices::PciAddress;
use devices::SerialParameters;
use serde::Deserialize;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;

use crate::crosvm::config::Config;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum HypervisorKind {
    Kvm {
        device: Option<PathBuf>,
    },
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    #[cfg(feature = "geniezone")]
    Geniezone {
        device: Option<PathBuf>,
    },
    #[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), feature = "gunyah"))]
    Gunyah {
        device: Option<PathBuf>,
    },
}

#[cfg(feature = "audio")]
pub fn parse_ac97_options(
    #[allow(unused_variables)] ac97_params: &mut devices::Ac97Parameters,
    key: &str,
    #[allow(unused_variables)] value: &str,
) -> Result<(), String> {
    match key {
        #[cfg(feature = "audio_cras")]
        "client_type" => ac97_params
            .set_client_type(value)
            .map_err(|e| crate::crosvm::config::invalid_value_err(value, e)),
        #[cfg(feature = "audio_cras")]
        "socket_type" => ac97_params
            .set_socket_type(value)
            .map_err(|e| crate::crosvm::config::invalid_value_err(value, e)),
        _ => Err(format!("unknown ac97 parameter {}", key)),
    }
}

// Doesn't do anything on unix.
pub fn check_serial_params(_serial_params: &SerialParameters) -> Result<(), String> {
    Ok(())
}

pub fn validate_config(_cfg: &mut Config) -> std::result::Result<(), String> {
    Ok(())
}

/// VFIO device structure for creating a new instance based on command line options.
#[derive(Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct VfioOption {
    /// Path to the VFIO device.
    pub path: PathBuf,

    /// IOMMU type to use for this VFIO device.
    #[serde(default)]
    pub iommu: IommuDevType,

    /// PCI address to use for the VFIO device in the guest.
    /// If not specified, defaults to mirroring the host PCI address.
    pub guest_address: Option<PciAddress>,

    /// Apply special handling for Intel LPSS devices.
    #[cfg(feature = "direct")]
    #[serde(default)]
    pub intel_lpss: bool,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use argh::FromArgs;

    use super::*;
    use crate::crosvm::config::from_key_values;
    #[cfg(feature = "audio_cras")]
    use crate::crosvm::config::parse_ac97_options;
    use crate::crosvm::config::BindMount;
    use crate::crosvm::config::DEFAULT_TOUCH_DEVICE_HEIGHT;
    use crate::crosvm::config::DEFAULT_TOUCH_DEVICE_WIDTH;

    #[cfg(feature = "audio_cras")]
    #[test]
    fn parse_ac97_socket_type() {
        parse_ac97_options("socket_type=unified").expect("parse should have succeded");
        parse_ac97_options("socket_type=legacy").expect("parse should have succeded");
    }

    #[test]
    fn parse_coiommu_options() {
        use std::time::Duration;

        use devices::CoIommuParameters;
        use devices::CoIommuUnpinPolicy;

        // unpin_policy
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_policy=off").unwrap();
        assert_eq!(
            coiommu_params,
            CoIommuParameters {
                unpin_policy: CoIommuUnpinPolicy::Off,
                ..Default::default()
            }
        );
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_policy=lru").unwrap();
        assert_eq!(
            coiommu_params,
            CoIommuParameters {
                unpin_policy: CoIommuUnpinPolicy::Lru,
                ..Default::default()
            }
        );
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_policy=foo");
        assert!(coiommu_params.is_err());

        // unpin_interval
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_interval=42").unwrap();
        assert_eq!(
            coiommu_params,
            CoIommuParameters {
                unpin_interval: Duration::from_secs(42),
                ..Default::default()
            }
        );
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_interval=foo");
        assert!(coiommu_params.is_err());

        // unpin_limit
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_limit=256").unwrap();
        assert_eq!(
            coiommu_params,
            CoIommuParameters {
                unpin_limit: Some(256),
                ..Default::default()
            }
        );
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_limit=0");
        assert!(coiommu_params.is_err());
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_limit=foo");
        assert!(coiommu_params.is_err());

        // unpin_gen_threshold
        let coiommu_params =
            from_key_values::<CoIommuParameters>("unpin_gen_threshold=32").unwrap();
        assert_eq!(
            coiommu_params,
            CoIommuParameters {
                unpin_gen_threshold: 32,
                ..Default::default()
            }
        );
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_gen_threshold=foo");
        assert!(coiommu_params.is_err());

        // All together
        let coiommu_params = from_key_values::<CoIommuParameters>(
            "unpin_policy=lru,unpin_interval=90,unpin_limit=8,unpin_gen_threshold=64",
        )
        .unwrap();
        assert_eq!(
            coiommu_params,
            CoIommuParameters {
                unpin_policy: CoIommuUnpinPolicy::Lru,
                unpin_interval: Duration::from_secs(90),
                unpin_limit: Some(8),
                unpin_gen_threshold: 64,
            }
        );

        // invalid parameter
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_invalid_param=0");
        assert!(coiommu_params.is_err());
    }

    #[test]
    fn parse_plugin_mount_valid() {
        let opt: BindMount = "/dev/null:/dev/zero:true".parse().unwrap();

        assert_eq!(opt.src, PathBuf::from("/dev/null"));
        assert_eq!(opt.dst, PathBuf::from("/dev/zero"));
        assert!(opt.writable);
    }

    #[test]
    fn parse_plugin_mount_valid_shorthand() {
        let opt: BindMount = "/dev/null".parse().unwrap();
        assert_eq!(opt.dst, PathBuf::from("/dev/null"));
        assert!(!opt.writable);

        let opt: BindMount = "/dev/null:/dev/zero".parse().unwrap();
        assert_eq!(opt.dst, PathBuf::from("/dev/zero"));
        assert!(!opt.writable);

        let opt: BindMount = "/dev/null::true".parse().unwrap();
        assert_eq!(opt.dst, PathBuf::from("/dev/null"));
        assert!(opt.writable);
    }

    #[test]
    fn single_touch_spec_and_track_pad_spec_default_size() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--single-touch",
                "/dev/single-touch-test",
                "--trackpad",
                "/dev/single-touch-test",
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.virtio_single_touch.first().unwrap().get_size(),
            (DEFAULT_TOUCH_DEVICE_WIDTH, DEFAULT_TOUCH_DEVICE_HEIGHT)
        );
        assert_eq!(
            config.virtio_trackpad.first().unwrap().get_size(),
            (DEFAULT_TOUCH_DEVICE_WIDTH, DEFAULT_TOUCH_DEVICE_HEIGHT)
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn single_touch_spec_default_size_from_gpu() {
        let width = 12345u32;
        let height = 54321u32;

        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--single-touch",
                "/dev/single-touch-test",
                "--gpu",
                &format!("width={},height={}", width, height),
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.virtio_single_touch.first().unwrap().get_size(),
            (width, height)
        );
    }

    #[test]
    fn single_touch_spec_and_track_pad_spec_with_size() {
        let width = 12345u32;
        let height = 54321u32;
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--single-touch",
                &format!("/dev/single-touch-test:{}:{}", width, height),
                "--trackpad",
                &format!("/dev/single-touch-test:{}:{}", width, height),
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.virtio_single_touch.first().unwrap().get_size(),
            (width, height)
        );
        assert_eq!(
            config.virtio_trackpad.first().unwrap().get_size(),
            (width, height)
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn single_touch_spec_with_size_independent_from_gpu() {
        let touch_width = 12345u32;
        let touch_height = 54321u32;
        let display_width = 1234u32;
        let display_height = 5432u32;
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--single-touch",
                &format!("/dev/single-touch-test:{}:{}", touch_width, touch_height),
                "--gpu",
                &format!("width={},height={}", display_width, display_height),
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.virtio_single_touch.first().unwrap().get_size(),
            (touch_width, touch_height)
        );
    }

    #[test]
    fn virtio_switches() {
        let mut config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--switches", "/dev/switches-test", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.virtio_switches.pop().unwrap(),
            PathBuf::from("/dev/switches-test")
        );
    }

    #[test]
    fn vfio_pci_path() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--vfio", "/path/to/dev", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let vfio = config.vfio.first().unwrap();

        assert_eq!(vfio.path, PathBuf::from("/path/to/dev"));
        assert_eq!(vfio.iommu, IommuDevType::NoIommu);
        assert_eq!(vfio.guest_address, None);
    }

    #[test]
    fn vfio_pci_path_coiommu() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--vfio", "/path/to/dev,iommu=coiommu", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let vfio = config.vfio.first().unwrap();

        assert_eq!(vfio.path, PathBuf::from("/path/to/dev"));
        assert_eq!(vfio.iommu, IommuDevType::CoIommu);
        assert_eq!(vfio.guest_address, None);
    }

    #[test]
    fn vfio_pci_path_viommu_guest_address() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--vfio",
                "/path/to/dev,iommu=viommu,guest-address=42:15.4",
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let vfio = config.vfio.first().unwrap();

        assert_eq!(vfio.path, PathBuf::from("/path/to/dev"));
        assert_eq!(vfio.iommu, IommuDevType::VirtioIommu);
        assert_eq!(
            vfio.guest_address,
            Some(PciAddress::new(0, 0x42, 0x15, 4).unwrap())
        );
    }

    #[test]
    #[cfg(feature = "direct")]
    fn vfio_pci_intel_lpss() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--vfio", "/path/to/dev,intel-lpss=true", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let vfio = config.vfio.first().unwrap();

        assert_eq!(vfio.intel_lpss, true);
    }

    #[test]
    fn vfio_platform() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--vfio-platform", "/path/to/dev", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let vfio = config.vfio.first().unwrap();

        assert_eq!(vfio.path, PathBuf::from("/path/to/dev"));
    }
}
