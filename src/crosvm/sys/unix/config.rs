// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use devices::IommuDevType;
use devices::PciAddress;
use devices::SerialParameters;
use libc::getegid;
use libc::geteuid;
use serde::Deserialize;
use serde::Serialize;
use serde_keyvalue::from_key_values;
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

#[derive(Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum SharedDirKind {
    FS,
    #[default]
    P9,
}

impl FromStr for SharedDirKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use SharedDirKind::*;
        match s {
            "fs" | "FS" => Ok(FS),
            "9p" | "9P" | "p9" | "P9" => Ok(P9),
            _ => {
                bail!("invalid file system type");
            }
        }
    }
}

pub struct SharedDir {
    pub src: PathBuf,
    pub tag: String,
    pub kind: SharedDirKind,
    pub ugid: (Option<u32>, Option<u32>),
    pub uid_map: String,
    pub gid_map: String,
    pub fs_cfg: devices::virtio::fs::Config,
    pub p9_cfg: p9::Config,
}

impl Default for SharedDir {
    fn default() -> SharedDir {
        SharedDir {
            src: Default::default(),
            tag: Default::default(),
            kind: Default::default(),
            ugid: (None, None),
            uid_map: format!("0 {} 1", unsafe { geteuid() }),
            gid_map: format!("0 {} 1", unsafe { getegid() }),
            fs_cfg: Default::default(),
            p9_cfg: Default::default(),
        }
    }
}

impl FromStr for SharedDir {
    type Err = anyhow::Error;

    fn from_str(param: &str) -> Result<Self, Self::Err> {
        // This is formatted as multiple fields, each separated by ":". The first 2 fields are
        // fixed (src:tag).  The rest may appear in any order:
        //
        // * type=TYPE - must be one of "p9" or "fs" (default: p9)
        // * uidmap=UIDMAP - a uid map in the format "inner outer count[,inner outer count]"
        //   (default: "0 <current euid> 1")
        // * gidmap=GIDMAP - a gid map in the same format as uidmap
        //   (default: "0 <current egid> 1")
        // * privileged_quota_uids=UIDS - Space-separated list of privileged uid values. When
        //   performing quota-related operations, these UIDs are treated as if they have
        //   CAP_FOWNER.
        // * timeout=TIMEOUT - a timeout value in seconds, which indicates how long attributes
        //   and directory contents should be considered valid (default: 5)
        // * cache=CACHE - one of "never", "always", or "auto" (default: auto)
        // * writeback=BOOL - indicates whether writeback caching should be enabled (default: false)
        // * uid=UID - uid of the device process in the user namespace created by minijail.
        //   (default: 0)
        // * gid=GID - gid of the device process in the user namespace created by minijail.
        //   (default: 0)
        // These two options (uid/gid) are useful when the crosvm process has no
        // CAP_SETGID/CAP_SETUID but an identity mapping of the current user/group
        // between the VM and the host is required.
        // Say the current user and the crosvm process has uid 5000, a user can use
        // "uid=5000" and "uidmap=5000 5000 1" such that files owned by user 5000
        // still appear to be owned by user 5000 in the VM. These 2 options are
        // useful only when there is 1 user in the VM accessing shared files.
        // If multiple users want to access the shared file, gid/uid options are
        // useless. It'd be better to create a new user namespace and give
        // CAP_SETUID/CAP_SETGID to the crosvm.
        let mut components = param.split(':');
        let src = PathBuf::from(
            components
                .next()
                .context("missing source path for `shared-dir`")?,
        );
        let tag = components
            .next()
            .context("missing tag for `shared-dir`")?
            .to_owned();

        if !src.is_dir() {
            bail!("source path for `shared-dir` must be a directory");
        }

        let mut shared_dir = SharedDir {
            src,
            tag,
            ..Default::default()
        };
        let mut type_opts = vec![];
        for opt in components {
            let mut o = opt.splitn(2, '=');
            let kind = o.next().context("`shared-dir` options must not be empty")?;
            let value = o
                .next()
                .context("`shared-dir` options must be of the form `kind=value`")?;

            match kind {
                "type" => {
                    shared_dir.kind = value.parse().with_context(|| {
                        anyhow!("`type` must be one of `fs` or `9p` but {value}")
                    })?
                }
                "uidmap" => shared_dir.uid_map = value.into(),
                "gidmap" => shared_dir.gid_map = value.into(),
                "uid" => {
                    shared_dir.ugid.0 = Some(value.parse().context("`uid` must be an integer")?);
                }
                "gid" => {
                    shared_dir.ugid.1 = Some(value.parse().context("`gid` must be an integer")?);
                }
                _ => type_opts.push(opt),
            }
        }
        match shared_dir.kind {
            SharedDirKind::FS => {
                shared_dir.fs_cfg = from_key_values(&type_opts.join(","))
                    .map_err(|e| anyhow!("failed to parse fs config '{:?}': {e}", type_opts))?;
            }
            SharedDirKind::P9 => {
                shared_dir.p9_cfg = type_opts
                    .join(":")
                    .parse()
                    .map_err(|e| anyhow!("failed to parse 9p config '{:?}': {e}", type_opts))?;
            }
        }
        Ok(shared_dir)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::Duration;

    use argh::FromArgs;
    use devices::virtio::fs::CachePolicy;

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
    fn virtio_rotary() {
        let mut config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--rotary", "/dev/rotary-test", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.virtio_rotary.pop().unwrap(),
            PathBuf::from("/dev/rotary-test")
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

    #[test]
    fn hypervisor_default() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(&[], &["/dev/null"])
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(config.hypervisor, None);
    }

    #[test]
    fn hypervisor_kvm() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--hypervisor", "kvm", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.hypervisor,
            Some(HypervisorKind::Kvm { device: None })
        );
    }

    #[test]
    fn hypervisor_kvm_device() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--hypervisor", "kvm[device=/not/default]", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.hypervisor,
            Some(HypervisorKind::Kvm {
                device: Some(PathBuf::from("/not/default"))
            })
        );
    }

    #[test]
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    #[cfg(feature = "geniezone")]
    fn hypervisor_geniezone() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--hypervisor", "geniezone", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.hypervisor,
            Some(HypervisorKind::Geniezone { device: None })
        );
    }

    #[test]
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    #[cfg(feature = "geniezone")]
    fn hypervisor_geniezone_device() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--hypervisor",
                "geniezone[device=/not/default]",
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.hypervisor,
            Some(HypervisorKind::Geniezone {
                device: Some(PathBuf::from("/not/default"))
            })
        );
    }

    #[test]
    #[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), feature = "gunyah"))]
    fn hypervisor_gunyah() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--hypervisor", "gunyah", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.hypervisor,
            Some(HypervisorKind::Gunyah { device: None })
        );
    }

    #[test]
    #[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), feature = "gunyah"))]
    fn hypervisor_gunyah_device() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--hypervisor", "gunyah[device=/not/default]", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.hypervisor,
            Some(HypervisorKind::Gunyah {
                device: Some(PathBuf::from("/not/default"))
            })
        );
    }

    #[test]
    fn parse_shared_dir() {
        // Although I want to test /usr/local/bin, Use / instead of
        // /usr/local/bin, as /usr/local/bin doesn't always exist.
        let s = "/:usr_local_bin:type=fs:cache=always:uidmap=0 655360 5000,5000 600 50,5050 660410 1994950:gidmap=0 655360 1065,1065 20119 1,1066 656426 3934,5000 600 50,5050 660410 1994950:timeout=3600:rewrite-security-xattrs=true:writeback=true";

        let shared_dir: SharedDir = s.parse().unwrap();
        assert_eq!(shared_dir.src, Path::new("/").to_path_buf());
        assert_eq!(shared_dir.tag, "usr_local_bin");
        assert!(shared_dir.kind == SharedDirKind::FS);
        assert_eq!(
            shared_dir.uid_map,
            "0 655360 5000,5000 600 50,5050 660410 1994950"
        );
        assert_eq!(
            shared_dir.gid_map,
            "0 655360 1065,1065 20119 1,1066 656426 3934,5000 600 50,5050 660410 1994950"
        );
        assert_eq!(shared_dir.fs_cfg.ascii_casefold, false);
        assert_eq!(shared_dir.fs_cfg.timeout, Duration::from_secs(3600));
        assert_eq!(shared_dir.fs_cfg.negative_timeout, Duration::ZERO);
        assert_eq!(shared_dir.fs_cfg.writeback, true);
        assert_eq!(
            shared_dir.fs_cfg.cache_policy,
            devices::virtio::fs::CachePolicy::Always
        );
        assert_eq!(shared_dir.fs_cfg.rewrite_security_xattrs, true);
        assert_eq!(shared_dir.fs_cfg.use_dax, false);
        assert_eq!(shared_dir.fs_cfg.posix_acl, true);
        assert_eq!(shared_dir.ugid, (None, None));
    }

    #[test]
    fn parse_shared_dir_parses_ascii_casefold_and_posix_acl() {
        // Although I want to test /usr/local/bin, Use / instead of
        // /usr/local/bin, as /usr/local/bin doesn't always exist.
        let s = "/:usr_local_bin:type=fs:ascii_casefold=true:posix_acl=false";

        let shared_dir: SharedDir = s.parse().unwrap();
        assert_eq!(shared_dir.fs_cfg.ascii_casefold, true);
        assert_eq!(shared_dir.fs_cfg.posix_acl, false);
    }

    #[test]
    fn parse_shared_dir_negative_timeout() {
        // Although I want to test /usr/local/bin, Use / instead of
        // /usr/local/bin, as /usr/local/bin doesn't always exist.
        let s = "/:usr_local_bin:type=fs:cache=always:timeout=3600:negative_timeout=60";

        let shared_dir: SharedDir = s.parse().unwrap();
        assert_eq!(shared_dir.src, Path::new("/").to_path_buf());
        assert_eq!(shared_dir.tag, "usr_local_bin");
        assert!(shared_dir.kind == SharedDirKind::FS);
        assert_eq!(
            shared_dir.fs_cfg.cache_policy,
            devices::virtio::fs::CachePolicy::Always
        );
        assert_eq!(shared_dir.fs_cfg.timeout, Duration::from_secs(3600));
        assert_eq!(shared_dir.fs_cfg.negative_timeout, Duration::from_secs(60));
    }

    #[test]
    fn parse_shared_dir_oem() {
        let shared_dir: SharedDir = "/:oem_etc:type=fs:cache=always:uidmap=0 299 1, 5000 600 50:gidmap=0 300 1, 5000 600 50:timeout=3600:rewrite-security-xattrs=true".parse().unwrap();
        assert_eq!(shared_dir.src, Path::new("/").to_path_buf());
        assert_eq!(shared_dir.tag, "oem_etc");
        assert!(shared_dir.kind == SharedDirKind::FS);
        assert_eq!(shared_dir.uid_map, "0 299 1, 5000 600 50");
        assert_eq!(shared_dir.gid_map, "0 300 1, 5000 600 50");
        assert_eq!(shared_dir.fs_cfg.ascii_casefold, false);
        assert_eq!(shared_dir.fs_cfg.timeout, Duration::from_secs(3600));
        assert_eq!(shared_dir.fs_cfg.negative_timeout, Duration::ZERO);
        assert_eq!(shared_dir.fs_cfg.writeback, false);
        assert_eq!(
            shared_dir.fs_cfg.cache_policy,
            devices::virtio::fs::CachePolicy::Always
        );
        assert_eq!(shared_dir.fs_cfg.rewrite_security_xattrs, true);
        assert_eq!(shared_dir.fs_cfg.use_dax, false);
        assert_eq!(shared_dir.fs_cfg.posix_acl, true);
        assert_eq!(shared_dir.ugid, (None, None));
    }

    #[test]
    #[cfg(feature = "arc_quota")]
    fn parse_shared_dir_arcvm_data() {
        // Test an actual ARCVM argument for /data/, where the path is replaced with `/`.
        let arcvm_arg = "/:_data:type=fs:cache=always:uidmap=0 655360 5000,5000 600 50,5050 660410 1994950:gidmap=0 655360 1065,1065 20119 1,1066 656426 3934,5000 600 50,5050 660410 1994950:timeout=3600:rewrite-security-xattrs=true:writeback=true:privileged_quota_uids=0";
        assert_eq!(
            arcvm_arg.parse::<SharedDir>().unwrap().fs_cfg,
            devices::virtio::fs::Config {
                cache_policy: CachePolicy::Always,
                timeout: Duration::from_secs(3600),
                rewrite_security_xattrs: true,
                writeback: true,
                privileged_quota_uids: vec![0],
                ..Default::default()
            }
        );
    }

    #[test]
    fn parse_shared_dir_ugid_set() {
        let shared_dir: SharedDir =
            "/:hostRoot:type=fs:uidmap=40417 40417 1:gidmap=5000 5000 1:uid=40417:gid=5000"
                .parse()
                .unwrap();
        assert_eq!(shared_dir.src, Path::new("/").to_path_buf());
        assert_eq!(shared_dir.tag, "hostRoot");
        assert!(shared_dir.kind == SharedDirKind::FS);
        assert_eq!(shared_dir.uid_map, "40417 40417 1");
        assert_eq!(shared_dir.gid_map, "5000 5000 1");
        assert_eq!(shared_dir.ugid, (Some(40417), Some(5000)));
    }

    #[test]
    fn parse_cache_policy() {
        // The default policy is `auto`.
        assert_eq!(
            "/:_data:type=fs"
                .parse::<SharedDir>()
                .unwrap()
                .fs_cfg
                .cache_policy,
            CachePolicy::Auto
        );
        assert_eq!(
            "/:_data:type=fs:cache=always"
                .parse::<SharedDir>()
                .unwrap()
                .fs_cfg
                .cache_policy,
            CachePolicy::Always
        );
        assert_eq!(
            "/:_data:type=fs:cache=auto"
                .parse::<SharedDir>()
                .unwrap()
                .fs_cfg
                .cache_policy,
            CachePolicy::Auto
        );
        assert_eq!(
            "/:_data:type=fs:cache=never"
                .parse::<SharedDir>()
                .unwrap()
                .fs_cfg
                .cache_policy,
            CachePolicy::Never
        );

        // cache policy is case-sensitive
        assert!("/:_data:type=fs:cache=Always".parse::<SharedDir>().is_err());
        assert!("/:_data:type=fs:cache=ALWAYS".parse::<SharedDir>().is_err());
        assert!("/:_data:type=fs:cache=Auto".parse::<SharedDir>().is_err());
        assert!("/:_data:type=fs:cache=AUTO".parse::<SharedDir>().is_err());
        assert!("/:_data:type=fs:cache=Never".parse::<SharedDir>().is_err());
        assert!("/:_data:type=fs:cache=NEVER".parse::<SharedDir>().is_err());

        // we don't accept unknown policy
        assert!("/:_data:type=fs:cache=foobar".parse::<SharedDir>().is_err());
    }

    #[cfg(feature = "arc_quota")]
    #[test]
    fn parse_privileged_quota_uids() {
        assert_eq!(
            "/:_data:type=fs:privileged_quota_uids=0"
                .parse::<SharedDir>()
                .unwrap()
                .fs_cfg
                .privileged_quota_uids,
            vec![0]
        );
        assert_eq!(
            "/:_data:type=fs:privileged_quota_uids=0 1 2 3 4"
                .parse::<SharedDir>()
                .unwrap()
                .fs_cfg
                .privileged_quota_uids,
            vec![0, 1, 2, 3, 4]
        );
    }
}
