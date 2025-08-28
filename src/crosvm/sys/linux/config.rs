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
    #[cfg(feature = "halla")]
    Halla {
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
        qcom_trusted_vm_id: Option<u16>,
        qcom_trusted_vm_pas_id: Option<u32>,
    },
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

    /// The symbol that labels the overlay device tree node which corresponds to this
    /// VFIO device.
    pub dt_symbol: Option<String>,
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
            // SAFETY: trivially safe
            uid_map: format!("0 {} 1", unsafe { geteuid() }),
            // SAFETY: trivially safe
            gid_map: format!("0 {} 1", unsafe { getegid() }),
            fs_cfg: Default::default(),
            p9_cfg: Default::default(),
        }
    }
}

struct UgidConfig {
    uid: Option<u32>,
    gid: Option<u32>,
    uid_map: String,
    gid_map: String,
}

impl Default for UgidConfig {
    fn default() -> Self {
        Self {
            uid: None,
            gid: None,
            // SAFETY: geteuid never fails.
            uid_map: format!("0 {} 1", unsafe { geteuid() }),
            // SAFETY: getegid never fails.
            gid_map: format!("0 {} 1", unsafe { getegid() }),
        }
    }
}

impl UgidConfig {
    /// Parse a key-value pair of ugid config to update `UgidConfig`.
    /// Returns whether `self` was updated or not.
    fn parse_ugid_config(&mut self, kind: &str, value: &str) -> anyhow::Result<bool> {
        match kind {
            "uid" => {
                self.uid = Some(value.parse().context("`uid` must be an integer")?);
            }
            "gid" => {
                self.gid = Some(value.parse().context("`gid` must be an integer")?);
            }
            "uidmap" => self.uid_map = value.into(),
            "gidmap" => self.gid_map = value.into(),
            _ => {
                return Ok(false);
            }
        }
        Ok(true)
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
        // * gidmap=GIDMAP - a gid map in the same format as uidmap (default: "0 <current egid> 1")
        // * privileged_quota_uids=UIDS - Space-separated list of privileged uid values. When
        //   performing quota-related operations, these UIDs are treated as if they have CAP_FOWNER.
        // * timeout=TIMEOUT - a timeout value in seconds, which indicates how long attributes and
        //   directory contents should be considered valid (default: 5)
        // * cache=CACHE - one of "never", "always", or "auto" (default: auto)
        // * writeback=BOOL - indicates whether writeback caching should be enabled (default: false)
        // * uid=UID - uid of the device process in the user namespace created by minijail.
        //   (default: 0)
        // * gid=GID - gid of the device process in the user namespace created by minijail.
        //   (default: 0)
        // * max_dynamic_perm=uint - number of maximum number of dynamic permissions paths (default:
        //   0) This feature is arc_quota specific feature.
        // * max_dynamic_xattr=uint - number of maximum number of dynamic xattr paths (default: 0).
        //   This feature is arc_quota specific feature.
        // * security_ctx=BOOL - indicates whether use FUSE_SECURITY_CONTEXT feature or not.
        //
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
        let mut ugid_cfg = UgidConfig::default();
        for opt in components {
            let mut o = opt.splitn(2, '=');
            let kind = o.next().context("`shared-dir` options must not be empty")?;
            let value = o
                .next()
                .context("`shared-dir` options must be of the form `kind=value`")?;

            if !ugid_cfg
                .parse_ugid_config(kind, value)
                .context("failed to parse ugid config")?
            {
                match kind {
                    "type" => {
                        shared_dir.kind = value.parse().with_context(|| {
                            anyhow!("`type` must be one of `fs` or `9p` but {value}")
                        })?
                    }
                    _ => type_opts.push(opt),
                }
            }
        }
        shared_dir.ugid = (ugid_cfg.uid, ugid_cfg.gid);
        shared_dir.uid_map = ugid_cfg.uid_map;
        shared_dir.gid_map = ugid_cfg.gid_map;

        match shared_dir.kind {
            SharedDirKind::FS => {
                shared_dir.fs_cfg = from_key_values(&type_opts.join(","))
                    .map_err(|e| anyhow!("failed to parse fs config '{:?}': {e}", type_opts))?;

                if shared_dir.fs_cfg.ascii_casefold && !shared_dir.fs_cfg.negative_timeout.is_zero()
                {
                    // Disallow the combination of `ascii_casefold` and `negative_timeout` because
                    // negative dentry caches doesn't wort well in scenarios like the following:
                    // 1. Lookup "foo", an non-existing file. Negative dentry is cached on the
                    //    guest.
                    // 2. Create "FOO".
                    // 3. Lookup "foo". This needs to be successful on the casefold directory, but
                    //    the lookup can fail due the negative cache created at 1.
                    bail!("'negative_timeout' cannot be used with 'ascii_casefold'");
                }
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PmemExt2Option {
    pub path: PathBuf,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub size: u32,
    pub ugid: (Option<u32>, Option<u32>),
    pub uid_map: String,
    pub gid_map: String,
}

impl Default for PmemExt2Option {
    fn default() -> Self {
        let blocks_per_group = 4096;
        let inodes_per_group = 1024;
        let size = ext2::BLOCK_SIZE as u32 * blocks_per_group; // only one block group
        let ugid_cfg = UgidConfig::default();
        Self {
            path: Default::default(),
            blocks_per_group,
            inodes_per_group,
            size,
            ugid: (ugid_cfg.uid, ugid_cfg.gid),
            uid_map: ugid_cfg.uid_map,
            gid_map: ugid_cfg.gid_map,
        }
    }
}

pub fn parse_pmem_ext2_option(param: &str) -> Result<PmemExt2Option, String> {
    let mut opt = PmemExt2Option::default();
    let mut components = param.split(':');
    opt.path = PathBuf::from(
        components
            .next()
            .ok_or("missing source path for `pmem-ext2`")?,
    );

    let mut ugid_cfg = UgidConfig::default();
    for c in components {
        let mut o = c.splitn(2, '=');
        let kind = o.next().ok_or("`pmem-ext2` options must not be empty")?;
        let value = o
            .next()
            .ok_or("`pmem-ext2` options must be of the form `kind=value`")?;

        if !ugid_cfg
            .parse_ugid_config(kind, value)
            .map_err(|e| format!("failed to parse ugid config for pmem-ext2: {:#}", e))?
        {
            match kind {
                "blocks_per_group" => {
                    opt.blocks_per_group = value.parse().map_err(|e| {
                        format!("failed to parse blocks_per_groups '{value}': {:#}", e)
                    })?
                }
                "inodes_per_group" => {
                    opt.inodes_per_group = value.parse().map_err(|e| {
                        format!("failed to parse inodes_per_groups '{value}': {:#}", e)
                    })?
                }
                "size" => {
                    opt.size = value
                        .parse()
                        .map_err(|e| format!("failed to parse memory size '{value}': {:#}", e))?
                }
                _ => return Err(format!("invalid `pmem-ext2` option: {}", kind)),
            }
        }
    }
    opt.ugid = (ugid_cfg.uid, ugid_cfg.gid);
    opt.uid_map = ugid_cfg.uid_map;
    opt.gid_map = ugid_cfg.gid_map;

    Ok(opt)
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
    #[cfg(feature = "halla")]
    fn hypervisor_halla() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--hypervisor", "halla", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.hypervisor,
            Some(HypervisorKind::Halla { device: None })
        );
    }

    #[test]
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    #[cfg(feature = "halla")]
    fn hypervisor_halla_device() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--hypervisor", "halla[device=/not/default]", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.hypervisor,
            Some(HypervisorKind::Halla {
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
            Some(HypervisorKind::Gunyah {
                device: None,
                qcom_trusted_vm_id: None,
                qcom_trusted_vm_pas_id: None,
            })
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
                device: Some(PathBuf::from("/not/default")),
                qcom_trusted_vm_id: None,
                qcom_trusted_vm_pas_id: None,
            })
        );
    }

    #[test]
    #[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), feature = "gunyah"))]
    fn hypervisor_gunyah_device_with_qtvm_ids() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--hypervisor",
                "gunyah[device=/not/default,qcom_trusted_vm_id=0,qcom_trusted_vm_pas_id=0]",
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.hypervisor,
            Some(HypervisorKind::Gunyah {
                device: Some(PathBuf::from("/not/default")),
                qcom_trusted_vm_id: Some(0),
                qcom_trusted_vm_pas_id: Some(0),
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
    fn parse_shared_dir_vm_fio() {
        // Tests shared-dir argurments used in ChromeOS's vm.Fio tast tests.

        // --shared-dir for rootfs
        let shared_dir: SharedDir =
            "/:root:type=fs:cache=always:timeout=5:writeback=false:dax=false:ascii_casefold=false"
                .parse()
                .unwrap();
        assert_eq!(
            shared_dir.fs_cfg,
            devices::virtio::fs::Config {
                cache_policy: CachePolicy::Always,
                timeout: Duration::from_secs(5),
                writeback: false,
                use_dax: false,
                ascii_casefold: false,
                ..Default::default()
            }
        );

        // --shared-dir for vm.Fio.virtiofs_dax_*
        let shared_dir: SharedDir =
            "/:shared:type=fs:cache=auto:timeout=1:writeback=true:dax=true:ascii_casefold=false"
                .parse()
                .unwrap();
        assert_eq!(
            shared_dir.fs_cfg,
            devices::virtio::fs::Config {
                cache_policy: CachePolicy::Auto,
                timeout: Duration::from_secs(1),
                writeback: true,
                use_dax: true,
                ascii_casefold: false,
                ..Default::default()
            }
        );
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

    #[test]
    fn parse_dax() {
        // DAX is disabled by default
        assert!(
            !"/:_data:type=fs"
                .parse::<SharedDir>()
                .unwrap()
                .fs_cfg
                .use_dax
        );
        assert!(
            "/:_data:type=fs:dax=true"
                .parse::<SharedDir>()
                .unwrap()
                .fs_cfg
                .use_dax
        );
        assert!(
            !"/:_data:type=fs:dax=false"
                .parse::<SharedDir>()
                .unwrap()
                .fs_cfg
                .use_dax
        );
    }

    #[test]
    fn parse_pmem_ext2() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--pmem-ext2", "/path/to/dir", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let opt = config.pmem_ext2.first().unwrap();

        assert_eq!(opt.path, PathBuf::from("/path/to/dir"));
    }

    #[test]
    fn parse_pmem_ext2_size() {
        let blocks_per_group = 2048;
        let inodes_per_group = 1024;
        let size = 4096 * blocks_per_group;

        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--pmem-ext2",
                &format!("/path/to/dir:blocks_per_group={blocks_per_group}:inodes_per_group={inodes_per_group}:size={size}"),
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let opt = config.pmem_ext2.first().unwrap();

        assert_eq!(opt.path, PathBuf::from("/path/to/dir"));
        assert_eq!(opt.blocks_per_group, blocks_per_group);
        assert_eq!(opt.inodes_per_group, inodes_per_group);
        assert_eq!(opt.size, size);
    }
}
