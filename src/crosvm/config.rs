// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use std::arch::x86_64::__cpuid;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use std::arch::x86_64::__cpuid_count;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use arch::set_default_serial_parameters;
use arch::CpuSet;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use arch::MsrAction;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use arch::MsrConfig;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use arch::MsrFilter;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use arch::MsrRWType;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use arch::MsrValueFrom;
use arch::Pstore;
use arch::VcpuAffinity;
use base::debug;
use base::pagesize;
use cros_async::ExecutorKind;
use devices::serial_device::SerialHardware;
use devices::serial_device::SerialParameters;
use devices::virtio::block::DiskOption;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
use devices::virtio::device_constants::video::VideoDeviceConfig;
#[cfg(feature = "gpu")]
use devices::virtio::gpu::GpuParameters;
#[cfg(feature = "audio")]
use devices::virtio::snd::parameters::Parameters as SndParameters;
#[cfg(all(windows, feature = "gpu"))]
use devices::virtio::vhost::user::device::gpu::sys::windows::GpuBackendConfig;
#[cfg(all(windows, feature = "gpu"))]
use devices::virtio::vhost::user::device::gpu::sys::windows::GpuVmmConfig;
#[cfg(all(windows, feature = "audio"))]
use devices::virtio::vhost::user::device::snd::sys::windows::SndSplitConfig;
use devices::virtio::vsock::VsockConfig;
use devices::virtio::NetParameters;
#[cfg(feature = "audio")]
use devices::Ac97Backend;
#[cfg(feature = "audio")]
use devices::Ac97Parameters;
#[cfg(feature = "direct")]
use devices::BusRange;
use devices::PciAddress;
use devices::PflashParameters;
use devices::StubPciParameters;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use hypervisor::CpuHybridType;
use hypervisor::ProtectionType;
use jail::JailConfig;
use resources::AddressRange;
use serde::Deserialize;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;
use uuid::Uuid;
use vm_control::BatteryType;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::check_host_hybrid_support;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::set_enable_pnp_data_msr_config;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::CpuIdCall;

pub(crate) use super::sys::HypervisorKind;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use devices::virtio::fs::passthrough;
        #[cfg(feature = "gpu")]
        use crate::crosvm::sys::GpuRenderServerParameters;
        use libc::{getegid, geteuid};

        static VHOST_NET_PATH: &str = "/dev/vhost-net";
    } else if #[cfg(windows)] {
        use base::{Event, Tube};
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const ONE_MB: u64 = 1 << 20;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const MB_ALIGNED: u64 = ONE_MB - 1;
// the max bus number is 256 and each bus occupy 1MB, so the max pcie cfg mmio size = 256M
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const MAX_PCIE_ECAM_SIZE: u64 = ONE_MB * 256;

/// Indicates the location and kind of executable kernel for a VM.
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub enum Executable {
    /// An executable intended to be run as a BIOS directly.
    Bios(PathBuf),
    /// A elf linux kernel, loaded and executed by crosvm.
    Kernel(PathBuf),
    /// Path to a plugin executable that is forked by crosvm.
    Plugin(PathBuf),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum IrqChipKind {
    /// All interrupt controllers are emulated in the kernel.
    Kernel,
    /// APIC is emulated in the kernel.  All other interrupt controllers are in userspace.
    Split,
    /// All interrupt controllers are emulated in userspace.
    Userspace,
}

/// The core types in hybrid architecture.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct CpuCoreType {
    /// Intel Atom.
    pub atom: CpuSet,
    /// Intel Core.
    pub core: CpuSet,
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct CpuOptions {
    /// Number of CPU cores.
    #[serde(default)]
    pub num_cores: Option<usize>,
    /// Vector of CPU ids to be grouped into the same cluster.
    #[serde(default)]
    pub clusters: Vec<CpuSet>,
    /// Core Type of CPUs.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub core_types: Option<CpuCoreType>,
}

#[derive(Debug, Default, Deserialize, Serialize, FromKeyValues, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct MemOptions {
    /// Amount of guest memory in MiB.
    #[serde(default)]
    pub size: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct VhostUserOption {
    pub socket: PathBuf,
}

impl FromStr for VhostUserOption {
    type Err = <PathBuf as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self { socket: s.parse()? })
    }
}

#[derive(Serialize, Deserialize)]
pub struct VhostUserFsOption {
    pub socket: PathBuf,
    pub tag: String,
}

impl FromStr for VhostUserFsOption {
    type Err = &'static str;

    fn from_str(param: &str) -> Result<Self, Self::Err> {
        // (socket:tag)
        let mut components = param.split(':');
        let socket = PathBuf::from(
            components
                .next()
                .ok_or("missing socket path for `vhost-user-fs`")?,
        );
        let tag = components
            .next()
            .ok_or("missing tag for `vhost-user-fs`")?
            .to_owned();

        Ok(Self { socket, tag })
    }
}

/// Options for virtio-vhost-user proxy device.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, serde_keyvalue::FromKeyValues)]
pub struct VvuOption {
    pub socket: PathBuf,
    pub addr: Option<PciAddress>,
    pub uuid: Option<Uuid>,
}

/// A bind mount for directories in the plugin process.
#[derive(Debug, Serialize, Deserialize)]
pub struct BindMount {
    pub src: PathBuf,
    pub dst: PathBuf,
    pub writable: bool,
}

impl FromStr for BindMount {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let components: Vec<&str> = value.split(':').collect();
        if components.is_empty() || components.len() > 3 || components[0].is_empty() {
            return Err(invalid_value_err(
                value,
                "`plugin-mount` should be in a form of: <src>[:[<dst>][:<writable>]]",
            ));
        }

        let src = PathBuf::from(components[0]);
        if src.is_relative() {
            return Err(invalid_value_err(
                components[0],
                "the source path for `plugin-mount` must be absolute",
            ));
        }
        if !src.exists() {
            return Err(invalid_value_err(
                components[0],
                "the source path for `plugin-mount` does not exist",
            ));
        }

        let dst = PathBuf::from(match components.get(1) {
            None | Some(&"") => components[0],
            Some(path) => path,
        });
        if dst.is_relative() {
            return Err(invalid_value_err(
                components[1],
                "the destination path for `plugin-mount` must be absolute",
            ));
        }

        let writable: bool = match components.get(2) {
            None => false,
            Some(s) => s.parse().map_err(|_| {
                invalid_value_err(
                    components[2],
                    "the <writable> component for `plugin-mount` is not valid bool",
                )
            })?,
        };

        Ok(BindMount { src, dst, writable })
    }
}

/// A mapping of linux group IDs for the plugin process.
#[cfg(feature = "plugin")]
#[derive(Debug, Deserialize, Serialize)]
pub struct GidMap {
    pub inner: base::platform::Gid,
    pub outer: base::platform::Gid,
    pub count: u32,
}

#[cfg(feature = "plugin")]
impl FromStr for GidMap {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let components: Vec<&str> = value.split(':').collect();
        if components.is_empty() || components.len() > 3 || components[0].is_empty() {
            return Err(invalid_value_err(
                value,
                "`plugin-gid-map` must have exactly 3 components: <inner>[:[<outer>][:<count>]]",
            ));
        }

        let inner: base::platform::Gid = components[0].parse().map_err(|_| {
            invalid_value_err(
                components[0],
                "the <inner> component for `plugin-gid-map` is not valid gid",
            )
        })?;

        let outer: base::platform::Gid = match components.get(1) {
            None | Some(&"") => inner,
            Some(s) => s.parse().map_err(|_| {
                invalid_value_err(
                    components[1],
                    "the <outer> component for `plugin-gid-map` is not valid gid",
                )
            })?,
        };

        let count: u32 = match components.get(2) {
            None => 1,
            Some(s) => s.parse().map_err(|_| {
                invalid_value_err(
                    components[2],
                    "the <count> component for `plugin-gid-map` is not valid number",
                )
            })?,
        };

        Ok(GidMap {
            inner,
            outer,
            count,
        })
    }
}

/// Direct IO forwarding options
#[cfg(feature = "direct")]
#[derive(Debug, Deserialize, Serialize)]
pub struct DirectIoOption {
    pub path: PathBuf,
    pub ranges: Vec<BusRange>,
}

pub const DEFAULT_TOUCH_DEVICE_HEIGHT: u32 = 1024;
pub const DEFAULT_TOUCH_DEVICE_WIDTH: u32 = 1280;

#[derive(Serialize, Deserialize)]
pub struct TouchDeviceOption {
    path: PathBuf,
    width: Option<u32>,
    height: Option<u32>,
    default_width: u32,
    default_height: u32,
}

impl TouchDeviceOption {
    pub fn new(path: PathBuf) -> TouchDeviceOption {
        TouchDeviceOption {
            path,
            width: None,
            height: None,
            default_width: DEFAULT_TOUCH_DEVICE_WIDTH,
            default_height: DEFAULT_TOUCH_DEVICE_HEIGHT,
        }
    }

    /// Getter for the path to the input event streams.
    #[cfg_attr(windows, allow(unused))]
    pub fn get_path(&self) -> &Path {
        self.path.as_path()
    }

    /// When a user specifies the parameters for a touch device, width and height are optional.
    /// If the width and height are missing, default values are used. Default values can be set
    /// dynamically, for example from the display sizes specified by the gpu argument.
    #[cfg(feature = "gpu")]
    pub fn set_default_size(&mut self, width: u32, height: u32) {
        self.default_width = width;
        self.default_height = height;
    }

    /// Setter for the width specified by the user.
    pub fn set_width(&mut self, width: u32) {
        self.width.replace(width);
    }

    /// Setter for the height specified by the user.
    pub fn set_height(&mut self, height: u32) {
        self.height.replace(height);
    }

    /// If the user specifies the size, use it. Otherwise, use the default values.
    #[cfg(any(unix, feature = "gpu"))]
    pub fn get_size(&self) -> (u32, u32) {
        (
            self.width.unwrap_or(self.default_width),
            self.height.unwrap_or(self.default_height),
        )
    }
}

impl FromStr for TouchDeviceOption {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut it = s.split(':');
        let mut touch_spec = TouchDeviceOption::new(PathBuf::from(it.next().unwrap().to_owned()));
        if let Some(width) = it.next() {
            touch_spec.set_width(width.trim().parse().unwrap());
        }
        if let Some(height) = it.next() {
            touch_spec.set_height(height.trim().parse().unwrap());
        }
        Ok(touch_spec)
    }
}

#[derive(Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum SharedDirKind {
    FS,
    #[default]
    P9,
}

impl FromStr for SharedDirKind {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use SharedDirKind::*;
        match s {
            "fs" | "FS" => Ok(FS),
            "9p" | "9P" | "p9" | "P9" => Ok(P9),
            _ => Err("invalid file system type"),
        }
    }
}

#[cfg(unix)]
pub struct SharedDir {
    pub src: PathBuf,
    pub tag: String,
    pub kind: SharedDirKind,
    pub ugid: (Option<u32>, Option<u32>),
    pub uid_map: String,
    pub gid_map: String,
    pub fs_cfg: passthrough::Config,
    pub p9_cfg: p9::Config,
}

#[cfg(unix)]
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

#[cfg(unix)]
impl FromStr for SharedDir {
    type Err = &'static str;

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
                .ok_or("missing source path for `shared-dir`")?,
        );
        let tag = components
            .next()
            .ok_or("missing tag for `shared-dir`")?
            .to_owned();

        if !src.is_dir() {
            return Err("source path for `shared-dir` must be a directory");
        }

        let mut shared_dir = SharedDir {
            src,
            tag,
            ..Default::default()
        };
        let mut type_opts = vec![];
        for opt in components {
            let mut o = opt.splitn(2, '=');
            let kind = o.next().ok_or("`shared-dir` options must not be empty")?;
            let value = o
                .next()
                .ok_or("`shared-dir` options must be of the form `kind=value`")?;

            match kind {
                "type" => {
                    shared_dir.kind = value
                        .parse()
                        .map_err(|_| "`type` must be one of `fs` or `9p`")?
                }
                "uidmap" => shared_dir.uid_map = value.into(),
                "gidmap" => shared_dir.gid_map = value.into(),
                "uid" => {
                    shared_dir.ugid.0 = Some(value.parse().map_err(|_| "`uid` must be an integer")?)
                }
                "gid" => {
                    shared_dir.ugid.1 = Some(value.parse().map_err(|_| "`gid` must be an integer")?)
                }
                _ => type_opts.push(opt),
            }
        }
        match shared_dir.kind {
            SharedDirKind::FS => {
                shared_dir.fs_cfg = type_opts.join(":").parse()?;
            }
            SharedDirKind::P9 => {
                shared_dir.p9_cfg = type_opts.join(":").parse()?;
            }
        }
        Ok(shared_dir)
    }
}

#[derive(Debug, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields)]
pub struct FileBackedMappingParameters {
    pub path: PathBuf,
    #[serde(rename = "addr")]
    pub address: u64,
    pub size: u64,
    #[serde(default)]
    pub offset: u64,
    #[serde(rename = "rw", default)]
    pub writable: bool,
    #[serde(default)]
    pub sync: bool,
    #[serde(default)]
    pub align: bool,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct HostPcieRootPortParameters {
    pub host_path: PathBuf,
    pub hp_gpe: Option<u32>,
}

fn parse_hex_or_decimal(maybe_hex_string: &str) -> Result<u64, String> {
    // Parse string starting with 0x as hex and others as numbers.
    if let Some(hex_string) = maybe_hex_string.strip_prefix("0x") {
        u64::from_str_radix(hex_string, 16)
    } else if let Some(hex_string) = maybe_hex_string.strip_prefix("0X") {
        u64::from_str_radix(hex_string, 16)
    } else {
        u64::from_str(maybe_hex_string)
    }
    .map_err(|e| format!("invalid numeric value {}: {}", maybe_hex_string, e))
}

pub fn parse_mmio_address_range(s: &str) -> Result<Vec<AddressRange>, String> {
    s.split(",")
        .map(|s| {
            let r: Vec<&str> = s.split("-").collect();
            if r.len() != 2 {
                return Err(invalid_value_err(s, "invalid range"));
            }
            let parse = |s: &str| -> Result<u64, String> {
                match parse_hex_or_decimal(s) {
                    Ok(v) => Ok(v),
                    Err(_) => Err(invalid_value_err(s, "expected u64 value")),
                }
            };
            Ok(AddressRange {
                start: parse(r[0])?,
                end: parse(r[1])?,
            })
        })
        .collect()
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Deserialize, Serialize, serde_keyvalue::FromKeyValues)]
#[serde(deny_unknown_fields)]
struct UserspaceMsrOptions {
    pub index: u32,
    #[serde(rename = "type")]
    pub rw_type: MsrRWType,
    pub action: MsrAction,
    #[serde(default = "default_msr_value_from")]
    pub from: MsrValueFrom,
    #[serde(default = "default_msr_filter")]
    pub filter: MsrFilter,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn default_msr_value_from() -> MsrValueFrom {
    MsrValueFrom::RWFromRunningCPU
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn default_msr_filter() -> MsrFilter {
    MsrFilter::Default
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn parse_userspace_msr_options(value: &str) -> Result<(u32, MsrConfig), String> {
    let options: UserspaceMsrOptions = from_key_values(value)?;

    Ok((
        options.index,
        MsrConfig {
            rw_type: options.rw_type,
            action: options.action,
            from: options.from,
            filter: options.filter,
        },
    ))
}

pub fn validate_serial_parameters(params: &SerialParameters) -> Result<(), String> {
    if params.stdin && params.input.is_some() {
        return Err("Cannot specify both stdin and input options".to_string());
    }
    if params.num < 1 {
        return Err(invalid_value_err(
            params.num.to_string(),
            "Serial port num must be at least 1",
        ));
    }

    if params.hardware == SerialHardware::Serial && params.num > 4 {
        return Err(invalid_value_err(
            format!("{}", params.num),
            "Serial port num must be 4 or less",
        ));
    }

    Ok(())
}

pub fn parse_serial_options(s: &str) -> Result<SerialParameters, String> {
    let params: SerialParameters = from_key_values(s)?;

    validate_serial_parameters(&params)?;

    Ok(params)
}

#[cfg(feature = "plugin")]
pub fn parse_plugin_mount_option(value: &str) -> Result<BindMount, String> {
    let components: Vec<&str> = value.split(':').collect();
    if components.is_empty() || components.len() > 3 || components[0].is_empty() {
        return Err(invalid_value_err(
            value,
            "`plugin-mount` should be in a form of: <src>[:[<dst>][:<writable>]]",
        ));
    }

    let src = PathBuf::from(components[0]);
    if src.is_relative() {
        return Err(invalid_value_err(
            components[0],
            "the source path for `plugin-mount` must be absolute",
        ));
    }
    if !src.exists() {
        return Err(invalid_value_err(
            components[0],
            "the source path for `plugin-mount` does not exist",
        ));
    }

    let dst = PathBuf::from(match components.get(1) {
        None | Some(&"") => components[0],
        Some(path) => path,
    });
    if dst.is_relative() {
        return Err(invalid_value_err(
            components[1],
            "the destination path for `plugin-mount` must be absolute",
        ));
    }

    let writable: bool = match components.get(2) {
        None => false,
        Some(s) => s.parse().map_err(|_| {
            invalid_value_err(
                components[2],
                "the <writable> component for `plugin-mount` is not valid bool",
            )
        })?,
    };

    Ok(BindMount { src, dst, writable })
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn parse_memory_region(value: &str) -> Result<AddressRange, String> {
    let paras: Vec<&str> = value.split(',').collect();
    if paras.len() != 2 {
        return Err(invalid_value_err(
            value,
            "pcie-ecam must have exactly 2 parameters: ecam_base,ecam_size",
        ));
    }
    let base = parse_hex_or_decimal(paras[0]).map_err(|_| {
        invalid_value_err(
            value,
            "pcie-ecam, the first parameter base should be integer",
        )
    })?;
    let mut len = parse_hex_or_decimal(paras[1]).map_err(|_| {
        invalid_value_err(
            value,
            "pcie-ecam, the second parameter size should be integer",
        )
    })?;

    if (base & MB_ALIGNED != 0) || (len & MB_ALIGNED != 0) {
        return Err(invalid_value_err(
            value,
            "pcie-ecam, the base and len should be aligned to 1MB",
        ));
    }

    if len > MAX_PCIE_ECAM_SIZE {
        len = MAX_PCIE_ECAM_SIZE;
    }

    if base + len >= 0x1_0000_0000 {
        return Err(invalid_value_err(
            value,
            "pcie-ecam, the end address couldn't beyond 4G",
        ));
    }

    if base % len != 0 {
        return Err(invalid_value_err(
            value,
            "pcie-ecam, base should be multiple of len",
        ));
    }

    if let Some(range) = AddressRange::from_start_and_size(base, len) {
        Ok(range)
    } else {
        Err(invalid_value_err(
            value,
            "pcie-ecam must be representable as AddressRange",
        ))
    }
}

#[cfg(feature = "direct")]
pub fn parse_pcie_root_port_params(value: &str) -> Result<HostPcieRootPortParameters, String> {
    let opts: Vec<_> = value.split(',').collect();
    if opts.len() > 2 {
        return Err(invalid_value_err(
            value,
            "pcie-root-port has maxmimum two arguments",
        ));
    }
    let pcie_path = PathBuf::from(opts[0]);
    if !pcie_path.exists() {
        return Err(invalid_value_err(
            value,
            "the pcie root port path does not exist",
        ));
    }
    if !pcie_path.is_dir() {
        return Err(invalid_value_err(
            value,
            "the pcie root port path should be directory",
        ));
    }

    let hp_gpe = if opts.len() == 2 {
        let gpes: Vec<&str> = opts[1].split('=').collect();
        if gpes.len() != 2 || gpes[0] != "hp_gpe" {
            return Err(invalid_value_err(value, "it should be hp_gpe=Num"));
        }
        match gpes[1].parse::<u32>() {
            Ok(gpe) => Some(gpe),
            Err(_) => {
                return Err(invalid_value_err(
                    value,
                    "host hp gpe must be a non-negative integer",
                ));
            }
        }
    } else {
        None
    };

    Ok(HostPcieRootPortParameters {
        host_path: pcie_path,
        hp_gpe,
    })
}

pub fn parse_bus_id_addr(v: &str) -> Result<(u8, u8, u16, u16), String> {
    debug!("parse_bus_id_addr: {}", v);
    let mut ids = v.split(':');
    let errorre = move |item| move |e| format!("{}: {}", item, e);
    match (ids.next(), ids.next(), ids.next(), ids.next()) {
        (Some(bus_id), Some(addr), Some(vid), Some(pid)) => {
            let bus_id = bus_id.parse::<u8>().map_err(errorre("bus_id"))?;
            let addr = addr.parse::<u8>().map_err(errorre("addr"))?;
            let vid = u16::from_str_radix(vid, 16).map_err(errorre("vid"))?;
            let pid = u16::from_str_radix(pid, 16).map_err(errorre("pid"))?;
            Ok((bus_id, addr, vid, pid))
        }
        _ => Err(String::from("BUS_ID:ADDR:BUS_NUM:DEV_NUM")),
    }
}

#[cfg(feature = "audio")]
pub fn parse_ac97_options(s: &str) -> Result<Ac97Parameters, String> {
    let mut ac97_params: Ac97Parameters = Default::default();

    let opts = s
        .split(',')
        .map(|frag| frag.split('='))
        .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

    for (k, v) in opts {
        match k {
            "backend" => {
                ac97_params.backend = v
                    .parse::<Ac97Backend>()
                    .map_err(|e| invalid_value_err(v, e))?;
            }
            "capture" => {
                ac97_params.capture = v
                    .parse::<bool>()
                    .map_err(|e| format!("invalid capture option: {}", e))?;
            }
            _ => {
                super::sys::config::parse_ac97_options(&mut ac97_params, k, v)?;
            }
        }
    }

    Ok(ac97_params)
}

pub fn invalid_value_err<T: AsRef<str>, S: ToString>(value: T, expected: S) -> String {
    format!("invalid value {}: {}", value.as_ref(), expected.to_string())
}

#[derive(Debug, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct BatteryConfig {
    #[serde(rename = "type", default)]
    pub type_: BatteryType,
}

pub fn parse_cpu_capacity(s: &str) -> Result<BTreeMap<usize, u32>, String> {
    let mut cpu_capacity: BTreeMap<usize, u32> = BTreeMap::default();
    for cpu_pair in s.split(',') {
        let assignment: Vec<&str> = cpu_pair.split('=').collect();
        if assignment.len() != 2 {
            return Err(invalid_value_err(cpu_pair, "invalid CPU capacity syntax"));
        }
        let cpu = assignment[0].parse().map_err(|_| {
            invalid_value_err(assignment[0], "CPU index must be a non-negative integer")
        })?;
        let capacity = assignment[1].parse().map_err(|_| {
            invalid_value_err(assignment[1], "CPU capacity must be a non-negative integer")
        })?;
        if cpu_capacity.insert(cpu, capacity).is_some() {
            return Err(invalid_value_err(cpu_pair, "CPU index must be unique"));
        }
    }
    Ok(cpu_capacity)
}

pub fn parse_dynamic_power_coefficient(s: &str) -> Result<BTreeMap<usize, u32>, String> {
    let mut dyn_power_coefficient: BTreeMap<usize, u32> = BTreeMap::default();
    for cpu_pair in s.split(',') {
        let assignment: Vec<&str> = cpu_pair.split('=').collect();
        if assignment.len() != 2 {
            return Err(invalid_value_err(
                cpu_pair,
                "invalid CPU dynamic power pair syntax",
            ));
        }
        let cpu = assignment[0].parse().map_err(|_| {
            invalid_value_err(assignment[0], "CPU index must be a non-negative integer")
        })?;
        let power_coefficient = assignment[1].parse().map_err(|_| {
            invalid_value_err(
                assignment[1],
                "Power coefficient must be a non-negative integer",
            )
        })?;
        if dyn_power_coefficient
            .insert(cpu, power_coefficient)
            .is_some()
        {
            return Err(invalid_value_err(cpu_pair, "CPU index must be unique"));
        }
    }
    Ok(dyn_power_coefficient)
}

pub fn from_key_values<'a, T: Deserialize<'a>>(value: &'a str) -> Result<T, String> {
    serde_keyvalue::from_key_values(value).map_err(|e| e.to_string())
}

/// Parse a list of guest to host CPU mappings.
///
/// Each mapping consists of a single guest CPU index mapped to one or more host CPUs in the form
/// accepted by `CpuSet::from_str`:
///
///  `<GUEST-CPU>=<HOST-CPU-SET>[:<GUEST-CPU>=<HOST-CPU-SET>[:...]]`
pub fn parse_cpu_affinity(s: &str) -> Result<VcpuAffinity, String> {
    if s.contains('=') {
        let mut affinity_map = BTreeMap::new();
        for cpu_pair in s.split(':') {
            let assignment: Vec<&str> = cpu_pair.split('=').collect();
            if assignment.len() != 2 {
                return Err(invalid_value_err(
                    cpu_pair,
                    "invalid VCPU assignment syntax",
                ));
            }
            let guest_cpu = assignment[0].parse().map_err(|_| {
                invalid_value_err(assignment[0], "CPU index must be a non-negative integer")
            })?;
            let host_cpu_set = CpuSet::from_str(assignment[1])?;
            if affinity_map.insert(guest_cpu, host_cpu_set).is_some() {
                return Err(invalid_value_err(cpu_pair, "VCPU index must be unique"));
            }
        }
        Ok(VcpuAffinity::PerVcpu(affinity_map))
    } else {
        Ok(VcpuAffinity::Global(CpuSet::from_str(s)?))
    }
}

#[cfg(feature = "direct")]
pub fn parse_direct_io_options(s: &str) -> Result<DirectIoOption, String> {
    let parts: Vec<&str> = s.splitn(2, '@').collect();
    if parts.len() != 2 {
        return Err(invalid_value_err(
            s,
            "missing port range, use /path@X-Y,Z,.. syntax",
        ));
    }
    let path = PathBuf::from(parts[0]);
    if !path.exists() {
        return Err(invalid_value_err(parts[0], "the path does not exist"));
    };
    let ranges: Result<Vec<BusRange>, String> = parts[1]
        .split(',')
        .map(|frag| frag.split('-'))
        .map(|mut range| {
            let base = range
                .next()
                .map(parse_hex_or_decimal)
                .map_or(Ok(None), |r| r.map(Some));
            let last = range
                .next()
                .map(parse_hex_or_decimal)
                .map_or(Ok(None), |r| r.map(Some));
            (base, last)
        })
        .map(|range| match range {
            (Ok(Some(base)), Ok(None)) => Ok(BusRange { base, len: 1 }),
            (Ok(Some(base)), Ok(Some(last))) => Ok(BusRange {
                base,
                len: last.saturating_sub(base).saturating_add(1),
            }),
            (Err(_), _) => Err(invalid_value_err(s, "invalid base range value")),
            (_, Err(_)) => Err(invalid_value_err(s, "invalid last range value")),
            _ => Err(invalid_value_err(s, "invalid range format")),
        })
        .collect();
    Ok(DirectIoOption {
        path,
        ranges: ranges?,
    })
}

pub fn executable_is_plugin(executable: &Option<Executable>) -> bool {
    matches!(executable, Some(Executable::Plugin(_)))
}

pub fn parse_pflash_parameters(s: &str) -> Result<PflashParameters, String> {
    let pflash_parameters: PflashParameters = from_key_values(s)?;

    Ok(pflash_parameters)
}

// BTreeMaps serialize fine, as long as their keys are trivial types. A tuple does not
// work, hence the need to convert to/from a vector form.
mod serde_serial_params {
    use std::iter::FromIterator;

    use serde::Deserializer;
    use serde::Serializer;

    use super::*;

    pub fn serialize<S>(
        params: &BTreeMap<(SerialHardware, u8), SerialParameters>,
        ser: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let v: Vec<(&(SerialHardware, u8), &SerialParameters)> = params.iter().collect();
        serde::Serialize::serialize(&v, ser)
    }

    pub fn deserialize<'a, D>(
        de: D,
    ) -> Result<BTreeMap<(SerialHardware, u8), SerialParameters>, D::Error>
    where
        D: Deserializer<'a>,
    {
        let params: Vec<((SerialHardware, u8), SerialParameters)> =
            serde::Deserialize::deserialize(de)?;
        Ok(BTreeMap::from_iter(params.into_iter()))
    }
}

/// Aggregate of all configurable options for a running VM.
#[derive(Serialize, Deserialize)]
#[remain::sorted]
pub struct Config {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), unix))]
    pub ac_adapter: bool,
    #[cfg(feature = "audio")]
    pub ac97_parameters: Vec<Ac97Parameters>,
    pub acpi_tables: Vec<PathBuf>,
    pub android_fstab: Option<PathBuf>,
    pub async_executor: Option<ExecutorKind>,
    pub balloon: bool,
    pub balloon_bias: i64,
    pub balloon_control: Option<PathBuf>,
    pub balloon_page_reporting: bool,
    pub balloon_wss_reporting: bool,
    pub battery_config: Option<BatteryConfig>,
    #[cfg(windows)]
    pub block_control_tube: Vec<Tube>,
    #[cfg(windows)]
    pub block_vhost_user_tube: Vec<Tube>,
    #[cfg(windows)]
    pub broker_shutdown_event: Option<Event>,
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), unix))]
    pub bus_lock_ratelimit: u64,
    #[cfg(unix)]
    pub coiommu_param: Option<devices::CoIommuParameters>,
    pub cpu_capacity: BTreeMap<usize, u32>, // CPU index -> capacity
    pub cpu_clusters: Vec<CpuSet>,
    #[cfg(feature = "crash-report")]
    pub crash_pipe_name: Option<String>,
    #[cfg(feature = "crash-report")]
    pub crash_report_uuid: Option<String>,
    pub delay_rt: bool,
    #[cfg(feature = "direct")]
    pub direct_edge_irq: Vec<u32>,
    #[cfg(feature = "direct")]
    pub direct_fixed_evts: Vec<devices::ACPIPMFixedEvent>,
    #[cfg(feature = "direct")]
    pub direct_gpe: Vec<u32>,
    #[cfg(feature = "direct")]
    pub direct_level_irq: Vec<u32>,
    #[cfg(feature = "direct")]
    pub direct_mmio: Option<DirectIoOption>,
    #[cfg(feature = "direct")]
    pub direct_pmio: Option<DirectIoOption>,
    pub disable_virtio_intx: bool,
    pub disks: Vec<DiskOption>,
    pub display_window_keyboard: bool,
    pub display_window_mouse: bool,
    pub dump_device_tree_blob: Option<PathBuf>,
    pub dynamic_power_coefficient: BTreeMap<usize, u32>,
    pub enable_hwp: bool,
    pub enable_pnp_data: bool,
    pub executable_path: Option<Executable>,
    #[cfg(windows)]
    pub exit_stats: bool,
    pub file_backed_mappings: Vec<FileBackedMappingParameters>,
    pub force_calibrated_tsc_leaf: bool,
    pub force_s2idle: bool,
    #[cfg(feature = "gdb")]
    pub gdb: Option<u32>,
    #[cfg(all(windows, feature = "gpu"))]
    pub gpu_backend_config: Option<GpuBackendConfig>,
    #[cfg(all(unix, feature = "gpu"))]
    pub gpu_cgroup_path: Option<PathBuf>,
    #[cfg(feature = "gpu")]
    pub gpu_parameters: Option<GpuParameters>,
    #[cfg(all(unix, feature = "gpu"))]
    pub gpu_render_server_parameters: Option<GpuRenderServerParameters>,
    #[cfg(all(unix, feature = "gpu"))]
    pub gpu_server_cgroup_path: Option<PathBuf>,
    #[cfg(all(windows, feature = "gpu"))]
    pub gpu_vmm_config: Option<GpuVmmConfig>,
    pub host_cpu_topology: bool,
    #[cfg(windows)]
    pub host_guid: Option<String>,
    pub hugepages: bool,
    pub hypervisor: Option<HypervisorKind>,
    pub init_memory: Option<u64>,
    pub initrd_path: Option<PathBuf>,
    pub irq_chip: Option<IrqChipKind>,
    pub itmt: bool,
    pub jail_config: Option<JailConfig>,
    #[cfg(windows)]
    pub kernel_log_file: Option<String>,
    #[cfg(unix)]
    pub lock_guest_memory: bool,
    #[cfg(windows)]
    pub log_file: Option<String>,
    #[cfg(windows)]
    pub logs_directory: Option<String>,
    pub memory: Option<u64>,
    pub memory_file: Option<PathBuf>,
    pub mmio_address_ranges: Vec<AddressRange>,
    #[cfg(target_arch = "aarch64")]
    pub mte: bool,
    pub net: Vec<NetParameters>,
    #[cfg(windows)]
    pub net_vhost_user_tube: Option<Tube>,
    pub no_i8042: bool,
    pub no_rtc: bool,
    pub no_smt: bool,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub oem_strings: Vec<String>,
    pub params: Vec<String>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub pci_low_start: Option<u64>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub pcie_ecam: Option<AddressRange>,
    #[cfg(feature = "direct")]
    pub pcie_rp: Vec<HostPcieRootPortParameters>,
    pub per_vm_core_scheduling: bool,
    pub pflash_parameters: Option<PflashParameters>,
    #[cfg(feature = "plugin")]
    pub plugin_gid_maps: Vec<GidMap>,
    pub plugin_mounts: Vec<BindMount>,
    pub plugin_root: Option<PathBuf>,
    pub pmem_devices: Vec<DiskOption>,
    #[cfg(feature = "process-invariants")]
    pub process_invariants_data_handle: Option<u64>,
    #[cfg(feature = "process-invariants")]
    pub process_invariants_data_size: Option<usize>,
    #[cfg(windows)]
    pub product_channel: Option<String>,
    #[cfg(windows)]
    pub product_name: Option<String>,
    #[cfg(windows)]
    pub product_version: Option<String>,
    pub protection_type: ProtectionType,
    pub pstore: Option<Pstore>,
    #[cfg(windows)]
    pub pvclock: bool,
    /// Must be `Some` iff `protection_type == ProtectionType::UnprotectedWithFirmware`.
    pub pvm_fw: Option<PathBuf>,
    pub restore_path: Option<PathBuf>,
    pub rng: bool,
    pub rt_cpus: CpuSet,
    #[serde(with = "serde_serial_params")]
    pub serial_parameters: BTreeMap<(SerialHardware, u8), SerialParameters>,
    #[cfg(windows)]
    pub service_pipe_name: Option<String>,
    #[cfg(unix)]
    #[serde(skip)]
    pub shared_dirs: Vec<SharedDir>,
    #[cfg(feature = "slirp-ring-capture")]
    pub slirp_capture_file: Option<String>,
    #[cfg(all(windows, feature = "audio"))]
    pub snd_split_config: Option<SndSplitConfig>,
    pub socket_path: Option<PathBuf>,
    #[cfg(feature = "tpm")]
    pub software_tpm: bool,
    #[cfg(feature = "audio")]
    pub sound: Option<PathBuf>,
    pub strict_balloon: bool,
    pub stub_pci_devices: Vec<StubPciParameters>,
    pub swap_dir: Option<PathBuf>,
    pub swiotlb: Option<u64>,
    #[cfg(target_os = "android")]
    pub task_profiles: Vec<String>,
    #[cfg(unix)]
    pub unmap_guest_memory_on_fork: bool,
    pub usb: bool,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub userspace_msr: BTreeMap<u32, MsrConfig>,
    pub vcpu_affinity: Option<VcpuAffinity>,
    pub vcpu_cgroup_path: Option<PathBuf>,
    pub vcpu_count: Option<usize>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub vcpu_hybrid_type: BTreeMap<usize, CpuHybridType>, // CPU index -> hybrid type
    #[cfg(unix)]
    pub vfio: Vec<super::sys::config::VfioOption>,
    #[cfg(unix)]
    pub vfio_isolate_hotplug: bool,
    #[cfg(unix)]
    pub vhost_net_device_path: PathBuf,
    pub vhost_user_blk: Vec<VhostUserOption>,
    pub vhost_user_console: Vec<VhostUserOption>,
    pub vhost_user_fs: Vec<VhostUserFsOption>,
    pub vhost_user_gpu: Vec<VhostUserOption>,
    pub vhost_user_mac80211_hwsim: Option<VhostUserOption>,
    pub vhost_user_net: Vec<VhostUserOption>,
    pub vhost_user_snd: Vec<VhostUserOption>,
    pub vhost_user_video_dec: Vec<VhostUserOption>,
    pub vhost_user_vsock: Vec<VhostUserOption>,
    pub vhost_user_wl: Option<VhostUserOption>,
    #[cfg(feature = "video-decoder")]
    pub video_dec: Vec<VideoDeviceConfig>,
    #[cfg(feature = "video-encoder")]
    pub video_enc: Vec<VideoDeviceConfig>,
    pub virt_cpufreq: bool,
    pub virtio_input_evdevs: Vec<PathBuf>,
    pub virtio_keyboard: Vec<PathBuf>,
    pub virtio_mice: Vec<PathBuf>,
    pub virtio_multi_touch: Vec<TouchDeviceOption>,
    pub virtio_single_touch: Vec<TouchDeviceOption>,
    #[cfg(feature = "audio")]
    #[serde(skip)]
    pub virtio_snds: Vec<SndParameters>,
    pub virtio_switches: Vec<PathBuf>,
    pub virtio_trackpad: Vec<TouchDeviceOption>,
    pub vsock: Option<VsockConfig>,
    #[cfg(all(feature = "vtpm", target_arch = "x86_64"))]
    pub vtpm_proxy: bool,
    pub vvu_proxy: Vec<VvuOption>,
    pub wayland_socket_paths: BTreeMap<String, PathBuf>,
    pub x_display: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), unix))]
            ac_adapter: false,
            #[cfg(feature = "audio")]
            ac97_parameters: Vec::new(),
            acpi_tables: Vec::new(),
            android_fstab: None,
            async_executor: None,
            balloon: true,
            balloon_bias: 0,
            balloon_control: None,
            balloon_page_reporting: false,
            balloon_wss_reporting: false,
            battery_config: None,
            #[cfg(windows)]
            block_control_tube: Vec::new(),
            #[cfg(windows)]
            block_vhost_user_tube: Vec::new(),
            #[cfg(windows)]
            broker_shutdown_event: None,
            #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), unix))]
            bus_lock_ratelimit: 0,
            #[cfg(unix)]
            coiommu_param: None,
            #[cfg(feature = "crash-report")]
            crash_pipe_name: None,
            #[cfg(feature = "crash-report")]
            crash_report_uuid: None,
            cpu_capacity: BTreeMap::new(),
            cpu_clusters: Vec::new(),
            delay_rt: false,
            #[cfg(feature = "direct")]
            direct_edge_irq: Vec::new(),
            #[cfg(feature = "direct")]
            direct_fixed_evts: Vec::new(),
            #[cfg(feature = "direct")]
            direct_gpe: Vec::new(),
            #[cfg(feature = "direct")]
            direct_level_irq: Vec::new(),
            #[cfg(feature = "direct")]
            direct_mmio: None,
            #[cfg(feature = "direct")]
            direct_pmio: None,
            disks: Vec::new(),
            disable_virtio_intx: false,
            display_window_keyboard: false,
            display_window_mouse: false,
            dump_device_tree_blob: None,
            dynamic_power_coefficient: BTreeMap::new(),
            enable_hwp: false,
            enable_pnp_data: false,
            executable_path: None,
            #[cfg(windows)]
            exit_stats: false,
            file_backed_mappings: Vec::new(),
            force_calibrated_tsc_leaf: false,
            force_s2idle: false,
            #[cfg(feature = "gdb")]
            gdb: None,
            #[cfg(all(windows, feature = "gpu"))]
            gpu_backend_config: None,
            #[cfg(feature = "gpu")]
            gpu_parameters: None,
            #[cfg(all(unix, feature = "gpu"))]
            gpu_render_server_parameters: None,
            #[cfg(all(unix, feature = "gpu"))]
            gpu_cgroup_path: None,
            #[cfg(all(unix, feature = "gpu"))]
            gpu_server_cgroup_path: None,
            #[cfg(all(windows, feature = "gpu"))]
            gpu_vmm_config: None,
            host_cpu_topology: false,
            #[cfg(windows)]
            host_guid: None,
            #[cfg(windows)]
            product_version: None,
            #[cfg(windows)]
            product_channel: None,
            hugepages: false,
            hypervisor: None,
            init_memory: None,
            initrd_path: None,
            irq_chip: None,
            itmt: false,
            jail_config: if !cfg!(feature = "default-no-sandbox") {
                Some(Default::default())
            } else {
                None
            },
            #[cfg(windows)]
            kernel_log_file: None,
            #[cfg(unix)]
            lock_guest_memory: false,
            #[cfg(windows)]
            log_file: None,
            #[cfg(windows)]
            logs_directory: None,
            memory: None,
            memory_file: None,
            mmio_address_ranges: Vec::new(),
            #[cfg(target_arch = "aarch64")]
            mte: false,
            net: Vec::new(),
            #[cfg(windows)]
            net_vhost_user_tube: None,
            no_i8042: false,
            no_rtc: false,
            no_smt: false,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            oem_strings: Vec::new(),
            params: Vec::new(),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            pci_low_start: None,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            pcie_ecam: None,
            #[cfg(feature = "direct")]
            pcie_rp: Vec::new(),
            per_vm_core_scheduling: false,
            pflash_parameters: None,
            #[cfg(feature = "plugin")]
            plugin_gid_maps: Vec::new(),
            plugin_mounts: Vec::new(),
            plugin_root: None,
            pmem_devices: Vec::new(),
            #[cfg(feature = "process-invariants")]
            process_invariants_data_handle: None,
            #[cfg(feature = "process-invariants")]
            process_invariants_data_size: None,
            #[cfg(windows)]
            product_name: None,
            protection_type: ProtectionType::Unprotected,
            pstore: None,
            #[cfg(windows)]
            pvclock: false,
            pvm_fw: None,
            restore_path: None,
            rng: true,
            rt_cpus: Default::default(),
            serial_parameters: BTreeMap::new(),
            #[cfg(windows)]
            service_pipe_name: None,
            #[cfg(unix)]
            shared_dirs: Vec::new(),
            #[cfg(feature = "slirp-ring-capture")]
            slirp_capture_file: None,
            #[cfg(all(windows, feature = "audio"))]
            snd_split_config: None,
            swap_dir: None,
            socket_path: None,
            #[cfg(feature = "tpm")]
            software_tpm: false,
            #[cfg(feature = "audio")]
            sound: None,
            strict_balloon: false,
            stub_pci_devices: Vec::new(),
            swiotlb: None,
            #[cfg(target_os = "android")]
            task_profiles: Vec::new(),
            #[cfg(unix)]
            unmap_guest_memory_on_fork: false,
            usb: true,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            userspace_msr: BTreeMap::new(),
            vcpu_affinity: None,
            vcpu_cgroup_path: None,
            vcpu_count: None,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            vcpu_hybrid_type: BTreeMap::new(),
            #[cfg(unix)]
            vfio: Vec::new(),
            #[cfg(unix)]
            vfio_isolate_hotplug: false,
            #[cfg(unix)]
            vhost_net_device_path: PathBuf::from(VHOST_NET_PATH),
            vhost_user_blk: Vec::new(),
            vhost_user_console: Vec::new(),
            vhost_user_video_dec: Vec::new(),
            vhost_user_fs: Vec::new(),
            vhost_user_gpu: Vec::new(),
            vhost_user_mac80211_hwsim: None,
            vhost_user_net: Vec::new(),
            vhost_user_snd: Vec::new(),
            vhost_user_vsock: Vec::new(),
            vhost_user_wl: None,
            vsock: None,
            #[cfg(feature = "video-decoder")]
            video_dec: Vec::new(),
            #[cfg(feature = "video-encoder")]
            video_enc: Vec::new(),
            virt_cpufreq: false,
            virtio_input_evdevs: Vec::new(),
            virtio_keyboard: Vec::new(),
            virtio_mice: Vec::new(),
            virtio_multi_touch: Vec::new(),
            virtio_single_touch: Vec::new(),
            #[cfg(feature = "audio")]
            virtio_snds: Vec::new(),
            virtio_switches: Vec::new(),
            virtio_trackpad: Vec::new(),
            #[cfg(all(feature = "vtpm", target_arch = "x86_64"))]
            vtpm_proxy: false,
            vvu_proxy: Vec::new(),
            wayland_socket_paths: BTreeMap::new(),
            x_display: None,
        }
    }
}

pub fn validate_config(cfg: &mut Config) -> std::result::Result<(), String> {
    if cfg.executable_path.is_none() {
        return Err("Executable is not specified".to_string());
    }

    if cfg.plugin_root.is_some() && !executable_is_plugin(&cfg.executable_path) {
        return Err("`plugin-root` requires `plugin`".to_string());
    }

    #[cfg(feature = "gpu")]
    {
        crate::crosvm::gpu_config::validate_gpu_config(cfg)?;
    }
    #[cfg(feature = "gdb")]
    if cfg.gdb.is_some() && cfg.vcpu_count.unwrap_or(1) != 1 {
        return Err("`gdb` requires the number of vCPU to be 1".to_string());
    }
    if cfg.host_cpu_topology {
        if cfg.no_smt {
            return Err(
                "`host-cpu-topology` cannot be set at the same time as `no_smt`, since \
                the smt of the Guest is the same as that of the Host when \
                `host-cpu-topology` is set."
                    .to_string(),
            );
        }

        let pcpu_count =
            base::number_of_logical_cores().expect("Could not read number of logical cores");
        if let Some(vcpu_count) = cfg.vcpu_count {
            if pcpu_count != vcpu_count {
                return Err(format!(
                    "`host-cpu-topology` requires the count of vCPUs({}) to equal the \
                            count of CPUs({}) on host.",
                    vcpu_count, pcpu_count
                ));
            }
        } else {
            cfg.vcpu_count = Some(pcpu_count);
        }

        match &cfg.vcpu_affinity {
            None => {
                let mut affinity_map = BTreeMap::new();
                for cpu_id in 0..cfg.vcpu_count.unwrap() {
                    affinity_map.insert(cpu_id, CpuSet::new([cpu_id]));
                }
                cfg.vcpu_affinity = Some(VcpuAffinity::PerVcpu(affinity_map));
            }
            _ => {
                return Err(
                    "`host-cpu-topology` requires not to set `cpu-affinity` at the same time"
                        .to_string(),
                );
            }
        }
    } else {
        // TODO(b/215297064): Support generic cpuaffinity if there's a need.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if !cfg.userspace_msr.is_empty() {
            for (_, msr_config) in cfg.userspace_msr.iter() {
                if msr_config.from == MsrValueFrom::RWFromRunningCPU {
                    return Err(
                        "`userspace-msr` must set `cpu0` if `host-cpu-topology` is not set"
                            .to_string(),
                    );
                }
            }
        }
    }
    if cfg.virt_cpufreq {
        if !cfg.host_cpu_topology && (cfg.vcpu_affinity.is_none() || cfg.cpu_capacity.is_empty()) {
            return Err("`virt-cpufreq` requires 'host-cpu-topology' enabled or \
                       have vcpu_affinity and cpu_capacity configured"
                .to_string());
        }
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if !cfg.vcpu_hybrid_type.is_empty() {
        if cfg.host_cpu_topology {
            return Err("`core-types` cannot be set with `host-cpu-topology`.".to_string());
        }
        check_host_hybrid_support(&CpuIdCall::new(__cpuid_count, __cpuid))
            .map_err(|e| format!("the cpu doesn't support `core-types`: {}", e))?;
        if cfg.vcpu_hybrid_type.len() != cfg.vcpu_count.unwrap_or(1) {
            return Err("`core-types` must be set for all virtual CPUs".to_string());
        }
        for cpu_id in 0..cfg.vcpu_count.unwrap_or(1) {
            if !cfg.vcpu_hybrid_type.contains_key(&cpu_id) {
                return Err("`core-types` must be set for all virtual CPUs".to_string());
            }
        }
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if cfg.enable_hwp && !cfg.host_cpu_topology {
        return Err("setting `enable-hwp` requires `host-cpu-topology` is set.".to_string());
    }
    if cfg.enable_pnp_data {
        if !cfg.host_cpu_topology {
            return Err(
                "setting `enable_pnp_data` must require `host-cpu-topology` is set previously."
                    .to_string(),
            );
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        set_enable_pnp_data_msr_config(&mut cfg.userspace_msr)
            .map_err(|e| format!("MSR can't be passed through {}", e))?;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if cfg.itmt {
        use std::collections::BTreeSet;
        // ITMT only works on the case each vCPU is 1:1 mapping to a pCPU.
        // `host-cpu-topology` has already set this 1:1 mapping. If no
        // `host-cpu-topology`, we need check the cpu affinity setting.
        if !cfg.host_cpu_topology {
            // only VcpuAffinity::PerVcpu supports setting cpu affinity
            // for each vCPU.
            if let Some(VcpuAffinity::PerVcpu(v)) = &cfg.vcpu_affinity {
                // ITMT allows more pCPUs than vCPUs.
                if v.len() != cfg.vcpu_count.unwrap_or(1) {
                    return Err("`itmt` requires affinity to be set for every vCPU.".to_string());
                }

                let mut pcpu_set = BTreeSet::new();
                for cpus in v.values() {
                    if cpus.len() != 1 {
                        return Err(
                            "`itmt` requires affinity to be set 1 pCPU for 1 vCPU.".to_owned()
                        );
                    }
                    // Ensure that each vCPU corresponds to a different pCPU to avoid pCPU sharing,
                    // otherwise it will seriously affect the ITMT scheduling optimization effect.
                    if !pcpu_set.insert(cpus[0]) {
                        return Err(
                            "`cpu_host` requires affinity to be set different pVPU for each vCPU."
                                .to_owned(),
                        );
                    }
                }
            } else {
                return Err("`itmt` requires affinity to be set for every vCPU.".to_string());
            }
        }
        if !cfg.enable_hwp {
            return Err("setting `itmt` requires `enable-hwp` is set.".to_string());
        }
    }

    if !cfg.balloon && cfg.balloon_control.is_some() {
        return Err("'balloon-control' requires enabled balloon".to_string());
    }

    if !cfg.balloon && cfg.balloon_page_reporting {
        return Err("'balloon_page_reporting' requires enabled balloon".to_string());
    }

    #[cfg(unix)]
    if cfg.lock_guest_memory && cfg.jail_config.is_none() {
        return Err("'lock-guest-memory' and 'disable-sandbox' are mutually exclusive".to_string());
    }

    // TODO(b/253386409): Vmm-swap only support sandboxed devices until vmm-swap use
    // `devices::Suspendable` to suspend devices.
    #[cfg(feature = "swap")]
    if cfg.swap_dir.is_some() && cfg.jail_config.is_none() {
        return Err("'swap' and 'disable-sandbox' are mutually exclusive".to_string());
    }

    set_default_serial_parameters(
        &mut cfg.serial_parameters,
        !cfg.vhost_user_console.is_empty(),
    );

    for mapping in cfg.file_backed_mappings.iter_mut() {
        validate_file_backed_mapping(mapping)?;
    }

    // Validate platform specific things
    super::sys::config::validate_config(cfg)
}

fn validate_file_backed_mapping(mapping: &mut FileBackedMappingParameters) -> Result<(), String> {
    let pagesize_mask = pagesize() as u64 - 1;
    let aligned_address = mapping.address & !pagesize_mask;
    let aligned_size =
        ((mapping.address + mapping.size + pagesize_mask) & !pagesize_mask) - aligned_address;

    if mapping.align {
        mapping.address = aligned_address;
        mapping.size = aligned_size;
    } else if aligned_address != mapping.address || aligned_size != mapping.size {
        return Err(
            "--file-backed-mapping addr and size parameters must be page size aligned".to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::needless_update)]
mod tests {
    #[cfg(unix)]
    use std::time::Duration;

    use argh::FromArgs;
    use devices::PciClassCode;
    use devices::StubPciParameters;

    use super::*;

    #[test]
    fn parse_cpu_opts() {
        let res: CpuOptions = from_key_values("").unwrap();
        assert_eq!(res, CpuOptions::default());

        // num_cores
        let res: CpuOptions = from_key_values("12").unwrap();
        assert_eq!(
            res,
            CpuOptions {
                num_cores: Some(12),
                ..Default::default()
            }
        );

        let res: CpuOptions = from_key_values("num-cores=16").unwrap();
        assert_eq!(
            res,
            CpuOptions {
                num_cores: Some(16),
                ..Default::default()
            }
        );

        // clusters
        let res: CpuOptions = from_key_values("clusters=[[0],[1],[2],[3]]").unwrap();
        assert_eq!(
            res,
            CpuOptions {
                clusters: vec![
                    CpuSet::new([0]),
                    CpuSet::new([1]),
                    CpuSet::new([2]),
                    CpuSet::new([3])
                ],
                ..Default::default()
            }
        );

        let res: CpuOptions = from_key_values("clusters=[[0-3]]").unwrap();
        assert_eq!(
            res,
            CpuOptions {
                clusters: vec![CpuSet::new([0, 1, 2, 3])],
                ..Default::default()
            }
        );

        let res: CpuOptions = from_key_values("clusters=[[0,2],[1,3],[4-7,12]]").unwrap();
        assert_eq!(
            res,
            CpuOptions {
                clusters: vec![
                    CpuSet::new([0, 2]),
                    CpuSet::new([1, 3]),
                    CpuSet::new([4, 5, 6, 7, 12])
                ],
                ..Default::default()
            }
        );

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            let res: CpuOptions = from_key_values("core-types=[atom=[1,3-7],core=[0,2]]").unwrap();
            assert_eq!(
                res,
                CpuOptions {
                    core_types: Some(CpuCoreType {
                        atom: CpuSet::new([1, 3, 4, 5, 6, 7]),
                        core: CpuSet::new([0, 2])
                    }),
                    ..Default::default()
                }
            );
        }

        // All together
        let res: CpuOptions = from_key_values("16,clusters=[[0],[4-6],[7]]").unwrap();
        assert_eq!(
            res,
            CpuOptions {
                num_cores: Some(16),
                clusters: vec![CpuSet::new([0]), CpuSet::new([4, 5, 6]), CpuSet::new([7])],
                ..Default::default()
            }
        );

        let res: CpuOptions = from_key_values("clusters=[[0-7],[30-31]],num-cores=32").unwrap();
        assert_eq!(
            res,
            CpuOptions {
                num_cores: Some(32),
                clusters: vec![CpuSet::new([0, 1, 2, 3, 4, 5, 6, 7]), CpuSet::new([30, 31])],
                ..Default::default()
            }
        );
    }

    #[test]
    fn parse_cpu_set_single() {
        assert_eq!(
            CpuSet::from_str("123").expect("parse failed"),
            CpuSet::new([123])
        );
    }

    #[test]
    fn parse_cpu_set_list() {
        assert_eq!(
            CpuSet::from_str("0,1,2,3").expect("parse failed"),
            CpuSet::new([0, 1, 2, 3])
        );
    }

    #[test]
    fn parse_cpu_set_range() {
        assert_eq!(
            CpuSet::from_str("0-3").expect("parse failed"),
            CpuSet::new([0, 1, 2, 3])
        );
    }

    #[test]
    fn parse_cpu_set_list_of_ranges() {
        assert_eq!(
            CpuSet::from_str("3-4,7-9,18").expect("parse failed"),
            CpuSet::new([3, 4, 7, 8, 9, 18])
        );
    }

    #[test]
    fn parse_cpu_set_repeated() {
        // For now, allow duplicates - they will be handled gracefully by the vec to cpu_set_t conversion.
        assert_eq!(
            CpuSet::from_str("1,1,1").expect("parse failed"),
            CpuSet::new([1, 1, 1])
        );
    }

    #[test]
    fn parse_cpu_set_negative() {
        // Negative CPU numbers are not allowed.
        CpuSet::from_str("-3").expect_err("parse should have failed");
    }

    #[test]
    fn parse_cpu_set_reverse_range() {
        // Ranges must be from low to high.
        CpuSet::from_str("5-2").expect_err("parse should have failed");
    }

    #[test]
    fn parse_cpu_set_open_range() {
        CpuSet::from_str("3-").expect_err("parse should have failed");
    }

    #[test]
    fn parse_cpu_set_extra_comma() {
        CpuSet::from_str("0,1,2,").expect_err("parse should have failed");
    }

    #[test]
    fn parse_cpu_affinity_global() {
        assert_eq!(
            parse_cpu_affinity("0,5-7,9").expect("parse failed"),
            VcpuAffinity::Global(CpuSet::new([0, 5, 6, 7, 9])),
        );
    }

    #[test]
    fn parse_cpu_affinity_per_vcpu_one_to_one() {
        let mut expected_map = BTreeMap::new();
        expected_map.insert(0, CpuSet::new([0]));
        expected_map.insert(1, CpuSet::new([1]));
        expected_map.insert(2, CpuSet::new([2]));
        expected_map.insert(3, CpuSet::new([3]));
        assert_eq!(
            parse_cpu_affinity("0=0:1=1:2=2:3=3").expect("parse failed"),
            VcpuAffinity::PerVcpu(expected_map),
        );
    }

    #[test]
    fn parse_cpu_affinity_per_vcpu_sets() {
        let mut expected_map = BTreeMap::new();
        expected_map.insert(0, CpuSet::new([0, 1, 2]));
        expected_map.insert(1, CpuSet::new([3, 4, 5]));
        expected_map.insert(2, CpuSet::new([6, 7, 8]));
        assert_eq!(
            parse_cpu_affinity("0=0,1,2:1=3-5:2=6,7-8").expect("parse failed"),
            VcpuAffinity::PerVcpu(expected_map),
        );
    }

    #[test]
    fn parse_mem_opts() {
        let res: MemOptions = from_key_values("").unwrap();
        assert_eq!(res.size, None);

        let res: MemOptions = from_key_values("1024").unwrap();
        assert_eq!(res.size, Some(1024));

        let res: MemOptions = from_key_values("size=0x4000").unwrap();
        assert_eq!(res.size, Some(16384));
    }

    #[cfg(feature = "audio_cras")]
    #[test]
    fn parse_ac97_vaild() {
        parse_ac97_options("backend=cras").expect("parse should have succeded");
    }

    #[cfg(feature = "audio")]
    #[test]
    fn parse_ac97_null_vaild() {
        parse_ac97_options("backend=null").expect("parse should have succeded");
    }

    #[cfg(feature = "audio_cras")]
    #[test]
    fn parse_ac97_capture_vaild() {
        parse_ac97_options("backend=cras,capture=true").expect("parse should have succeded");
    }

    #[cfg(feature = "audio_cras")]
    #[test]
    fn parse_ac97_client_type() {
        parse_ac97_options("backend=cras,capture=true,client_type=crosvm")
            .expect("parse should have succeded");
        parse_ac97_options("backend=cras,capture=true,client_type=arcvm")
            .expect("parse should have succeded");
        parse_ac97_options("backend=cras,capture=true,client_type=none")
            .expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_vaild() {
        parse_serial_options("type=syslog,num=1,console=true,stdin=true")
            .expect("parse should have succeded");
    }

    #[test]
    fn parse_serial_virtio_console_vaild() {
        parse_serial_options("type=syslog,num=5,console=true,stdin=true,hardware=virtio-console")
            .expect("parse should have succeded");
    }

    #[test]
    fn parse_serial_valid_no_num() {
        parse_serial_options("type=syslog").expect("parse should have succeded");
    }

    #[test]
    fn parse_serial_equals_in_value() {
        let parsed = parse_serial_options("type=syslog,path=foo=bar==.log")
            .expect("parse should have succeded");
        assert_eq!(parsed.path, Some(PathBuf::from("foo=bar==.log")));
    }

    #[test]
    fn parse_serial_invalid_type() {
        parse_serial_options("type=wormhole,num=1").expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_invalid_num_upper() {
        parse_serial_options("type=syslog,num=5").expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_invalid_num_lower() {
        parse_serial_options("type=syslog,num=0").expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_virtio_console_invalid_num_lower() {
        parse_serial_options("type=syslog,hardware=virtio-console,num=0")
            .expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_invalid_num_string() {
        parse_serial_options("type=syslog,num=number3").expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_invalid_option() {
        parse_serial_options("type=syslog,speed=lightspeed").expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_invalid_two_stdin() {
        assert!(TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &[
                    "--serial",
                    "num=1,type=stdout,stdin=true",
                    "--serial",
                    "num=2,type=stdout,stdin=true"
                ]
            )
            .unwrap()
        )
        .is_err())
    }

    #[test]
    fn parse_plugin_mount_invalid() {
        "".parse::<BindMount>().expect_err("parse should fail");
        "/dev/null:/dev/null:true:false"
            .parse::<BindMount>()
            .expect_err("parse should fail because too many arguments");

        "null:/dev/null:true"
            .parse::<BindMount>()
            .expect_err("parse should fail because source is not absolute");
        "/dev/null:null:true"
            .parse::<BindMount>()
            .expect_err("parse should fail because source is not absolute");
        "/dev/null:null:blah"
            .parse::<BindMount>()
            .expect_err("parse should fail because flag is not boolean");
    }

    #[cfg(feature = "plugin")]
    #[test]
    fn parse_plugin_gid_map_valid() {
        let opt: GidMap = "1:2:3".parse().expect("parse should succeed");
        assert_eq!(opt.inner, 1);
        assert_eq!(opt.outer, 2);
        assert_eq!(opt.count, 3);
    }

    #[cfg(feature = "plugin")]
    #[test]
    fn parse_plugin_gid_map_valid_shorthand() {
        let opt: GidMap = "1".parse().expect("parse should succeed");
        assert_eq!(opt.inner, 1);
        assert_eq!(opt.outer, 1);
        assert_eq!(opt.count, 1);

        let opt: GidMap = "1:2".parse().expect("parse should succeed");
        assert_eq!(opt.inner, 1);
        assert_eq!(opt.outer, 2);
        assert_eq!(opt.count, 1);

        let opt: GidMap = "1::3".parse().expect("parse should succeed");
        assert_eq!(opt.inner, 1);
        assert_eq!(opt.outer, 1);
        assert_eq!(opt.count, 3);
    }

    #[cfg(feature = "plugin")]
    #[test]
    fn parse_plugin_gid_map_invalid() {
        "".parse::<GidMap>().expect_err("parse should fail");
        "1:2:3:4"
            .parse::<GidMap>()
            .expect_err("parse should fail because too many arguments");
        "blah:2:3"
            .parse::<GidMap>()
            .expect_err("parse should fail because inner is not a number");
        "1:blah:3"
            .parse::<GidMap>()
            .expect_err("parse should fail because outer is not a number");
        "1:2:blah"
            .parse::<GidMap>()
            .expect_err("parse should fail because count is not a number");
    }

    #[test]
    fn parse_battery_valid() {
        let bat_config: BatteryConfig = from_key_values("type=goldfish").unwrap();
        assert_eq!(bat_config.type_, BatteryType::Goldfish);
    }

    #[test]
    fn parse_battery_valid_no_type() {
        let bat_config: BatteryConfig = from_key_values("").unwrap();
        assert_eq!(bat_config.type_, BatteryType::Goldfish);
    }

    #[test]
    fn parse_battery_invalid_parameter() {
        from_key_values::<BatteryConfig>("tyep=goldfish").expect_err("parse should have failed");
    }

    #[test]
    fn parse_battery_invalid_type_value() {
        from_key_values::<BatteryConfig>("type=xxx").expect_err("parse should have failed");
    }

    #[test]
    fn parse_irqchip_kernel() {
        let cfg = TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &["--irqchip", "kernel", "/dev/null"],
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(cfg.irq_chip, Some(IrqChipKind::Kernel));
    }

    #[test]
    fn parse_irqchip_split() {
        let cfg = TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &["--irqchip", "split", "/dev/null"],
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(cfg.irq_chip, Some(IrqChipKind::Split));
    }

    #[test]
    fn parse_irqchip_userspace() {
        let cfg = TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &["--irqchip", "userspace", "/dev/null"],
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(cfg.irq_chip, Some(IrqChipKind::Userspace));
    }

    #[test]
    fn parse_stub_pci() {
        let params = from_key_values::<StubPciParameters>("0000:01:02.3,vendor=0xfffe,device=0xfffd,class=0xffc1c2,subsystem_vendor=0xfffc,subsystem_device=0xfffb,revision=0xa").unwrap();
        assert_eq!(params.address.bus, 1);
        assert_eq!(params.address.dev, 2);
        assert_eq!(params.address.func, 3);
        assert_eq!(params.vendor, 0xfffe);
        assert_eq!(params.device, 0xfffd);
        assert_eq!(params.class.class as u8, PciClassCode::Other as u8);
        assert_eq!(params.class.subclass, 0xc1);
        assert_eq!(params.class.programming_interface, 0xc2);
        assert_eq!(params.subsystem_vendor, 0xfffc);
        assert_eq!(params.subsystem_device, 0xfffb);
        assert_eq!(params.revision, 0xa);
    }

    #[cfg(feature = "direct")]
    #[test]
    fn parse_direct_io_options_valid() {
        // Use /dev/zero here which is usually available on any systems,
        // /dev/mem may not.
        let params = parse_direct_io_options("/dev/zero@1,100-110").unwrap();
        assert_eq!(params.path.to_str(), Some("/dev/zero"));
        assert_eq!(params.ranges[0], BusRange { base: 1, len: 1 });
        assert_eq!(params.ranges[1], BusRange { base: 100, len: 11 });
    }

    #[cfg(feature = "direct")]
    #[test]
    fn parse_direct_io_options_hex() {
        // Use /dev/zero here which is usually available on any systems,
        // /dev/mem may not.
        let params = parse_direct_io_options("/dev/zero@1,0x10,100-110,0x10-0x20").unwrap();
        assert_eq!(params.path.to_str(), Some("/dev/zero"));
        assert_eq!(params.ranges[0], BusRange { base: 1, len: 1 });
        assert_eq!(params.ranges[1], BusRange { base: 0x10, len: 1 });
        assert_eq!(params.ranges[2], BusRange { base: 100, len: 11 });
        assert_eq!(
            params.ranges[3],
            BusRange {
                base: 0x10,
                len: 0x11
            }
        );
    }

    #[cfg(feature = "direct")]
    #[test]
    fn parse_direct_io_options_invalid() {
        // Use /dev/zero here which is usually available on any systems,
        // /dev/mem may not.
        assert!(parse_direct_io_options("/dev/zero@0y10")
            .unwrap_err()
            .to_string()
            .contains("invalid base range value"));

        assert!(parse_direct_io_options("/dev/zero@")
            .unwrap_err()
            .to_string()
            .contains("invalid base range value"));
    }

    #[test]
    fn parse_file_backed_mapping_valid() {
        let params = from_key_values::<FileBackedMappingParameters>(
            "addr=0x1000,size=0x2000,path=/dev/mem,offset=0x3000,rw,sync",
        )
        .unwrap();
        assert_eq!(params.address, 0x1000);
        assert_eq!(params.size, 0x2000);
        assert_eq!(params.path, PathBuf::from("/dev/mem"));
        assert_eq!(params.offset, 0x3000);
        assert!(params.writable);
        assert!(params.sync);
    }

    #[test]
    fn parse_file_backed_mapping_incomplete() {
        assert!(
            from_key_values::<FileBackedMappingParameters>("addr=0x1000,size=0x2000")
                .unwrap_err()
                .contains("missing field `path`")
        );
        assert!(
            from_key_values::<FileBackedMappingParameters>("size=0x2000,path=/dev/mem")
                .unwrap_err()
                .contains("missing field `addr`")
        );
        assert!(
            from_key_values::<FileBackedMappingParameters>("addr=0x1000,path=/dev/mem")
                .unwrap_err()
                .contains("missing field `size`")
        );
    }

    #[test]
    fn parse_file_backed_mapping_unaligned_addr() {
        let mut params =
            from_key_values::<FileBackedMappingParameters>("addr=0x1001,size=0x2000,path=/dev/mem")
                .unwrap();
        assert!(validate_file_backed_mapping(&mut params)
            .unwrap_err()
            .contains("aligned"));
    }
    #[test]
    fn parse_file_backed_mapping_unaligned_size() {
        let mut params =
            from_key_values::<FileBackedMappingParameters>("addr=0x1000,size=0x2001,path=/dev/mem")
                .unwrap();
        assert!(validate_file_backed_mapping(&mut params)
            .unwrap_err()
            .contains("aligned"));
    }

    #[test]
    fn parse_file_backed_mapping_align() {
        let mut params = from_key_values::<FileBackedMappingParameters>(
            "addr=0x3042,size=0xff0,path=/dev/mem,align",
        )
        .unwrap();
        assert_eq!(params.address, 0x3042);
        assert_eq!(params.size, 0xff0);
        validate_file_backed_mapping(&mut params).unwrap();
        assert_eq!(params.address, 0x3000);
        assert_eq!(params.size, 0x2000);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn parse_userspace_msr_options_test() {
        let (pass_cpu0_index, pass_cpu0_cfg) =
            parse_userspace_msr_options("0x10,type=w,action=pass,filter=yes").unwrap();
        assert_eq!(pass_cpu0_index, 0x10);
        assert_eq!(pass_cpu0_cfg.rw_type, MsrRWType::WriteOnly);
        assert_eq!(pass_cpu0_cfg.action, MsrAction::MsrPassthrough);
        assert_eq!(pass_cpu0_cfg.filter, MsrFilter::Override);

        let (pass_cpu0_index, pass_cpu0_cfg) =
            parse_userspace_msr_options("0x10,type=r,action=pass,from=cpu0").unwrap();
        assert_eq!(pass_cpu0_index, 0x10);
        assert_eq!(pass_cpu0_cfg.rw_type, MsrRWType::ReadOnly);
        assert_eq!(pass_cpu0_cfg.action, MsrAction::MsrPassthrough);
        assert_eq!(pass_cpu0_cfg.from, MsrValueFrom::RWFromCPU0);

        let (pass_cpus_index, pass_cpus_cfg) =
            parse_userspace_msr_options("0x10,type=rw,action=pass").unwrap();
        assert_eq!(pass_cpus_index, 0x10);
        assert_eq!(pass_cpus_cfg.rw_type, MsrRWType::ReadWrite);
        assert_eq!(pass_cpus_cfg.action, MsrAction::MsrPassthrough);
        assert_eq!(pass_cpus_cfg.from, MsrValueFrom::RWFromRunningCPU);

        let (pass_cpus_index, pass_cpus_cfg) =
            parse_userspace_msr_options("0x10,type=rw,action=emu").unwrap();
        assert_eq!(pass_cpus_index, 0x10);
        assert_eq!(pass_cpus_cfg.rw_type, MsrRWType::ReadWrite);
        assert_eq!(pass_cpus_cfg.action, MsrAction::MsrEmulate);
        assert_eq!(pass_cpus_cfg.from, MsrValueFrom::RWFromRunningCPU);

        assert!(parse_userspace_msr_options("0x10,action=none").is_err());
        assert!(parse_userspace_msr_options("0x10,action=pass").is_err());
        assert!(parse_userspace_msr_options("0x10,type=none").is_err());
        assert!(parse_userspace_msr_options("0x10,type=rw").is_err());
        assert!(parse_userspace_msr_options("0x10,type=w,action=pass,from=f").is_err());
        assert!(parse_userspace_msr_options("0x10").is_err());
        assert!(parse_userspace_msr_options("hoge").is_err());
    }

    #[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
    #[test]
    fn parse_video() {
        use devices::virtio::device_constants::video::VideoBackendType;

        #[cfg(feature = "libvda")]
        {
            let params: VideoDeviceConfig = from_key_values("libvda").unwrap();
            assert_eq!(params.backend, VideoBackendType::Libvda);

            let params: VideoDeviceConfig = from_key_values("libvda-vd").unwrap();
            assert_eq!(params.backend, VideoBackendType::LibvdaVd);
        }

        #[cfg(feature = "ffmpeg")]
        {
            let params: VideoDeviceConfig = from_key_values("ffmpeg").unwrap();
            assert_eq!(params.backend, VideoBackendType::Ffmpeg);
        }

        #[cfg(feature = "vaapi")]
        {
            let params: VideoDeviceConfig = from_key_values("vaapi").unwrap();
            assert_eq!(params.backend, VideoBackendType::Vaapi);
        }
    }

    #[test]
    fn parse_vvu() {
        assert_eq!(
            from_key_values::<VvuOption>(
                "/tmp/vvu-sock,addr=05:2.1,uuid=23546c3d-962d-4ebc-94d9-4acf50996944"
            )
            .unwrap(),
            VvuOption {
                socket: PathBuf::from("/tmp/vvu-sock"),
                addr: Some(PciAddress::new(0, 0x05, 0x02, 1).unwrap()),
                uuid: Some(Uuid::parse_str("23546c3d-962d-4ebc-94d9-4acf50996944").unwrap()),
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_shared_dir() {
        // Although I want to test /usr/local/bin, Use / instead of
        // /usr/local/bin, as /usr/local/bin doesn't always exist.
        let s = "/:usr_local_bin:type=fs:cache=always:uidmap=0 655360 5000,5000 600 50,5050 660410 1994950:gidmap=0 655360 1065,1065 20119 1,1066 656426 3934,5000 600 50,5050 660410 1994950:timeout=3600:rewrite-security-xattrs=true:ascii_casefold=false:writeback=true:posix_acl=true";

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
        assert_eq!(shared_dir.fs_cfg.attr_timeout, Duration::from_secs(3600));
        assert_eq!(shared_dir.fs_cfg.entry_timeout, Duration::from_secs(3600));
        assert_eq!(shared_dir.fs_cfg.writeback, true);
        assert_eq!(
            shared_dir.fs_cfg.cache_policy,
            passthrough::CachePolicy::Always
        );
        assert_eq!(shared_dir.fs_cfg.rewrite_security_xattrs, true);
        assert_eq!(shared_dir.fs_cfg.use_dax, false);
        assert_eq!(shared_dir.fs_cfg.posix_acl, true);
        assert_eq!(shared_dir.ugid, (None, None));
    }

    #[cfg(unix)]
    #[test]
    fn parse_shared_dir_oem() {
        let shared_dir: SharedDir = "/:oem_etc:type=fs:cache=always:uidmap=0 299 1, 5000 600 50:gidmap=0 300 1, 5000 600 50:timeout=3600:rewrite-security-xattrs=true".parse().unwrap();
        assert_eq!(shared_dir.src, Path::new("/").to_path_buf());
        assert_eq!(shared_dir.tag, "oem_etc");
        assert!(shared_dir.kind == SharedDirKind::FS);
        assert_eq!(shared_dir.uid_map, "0 299 1, 5000 600 50");
        assert_eq!(shared_dir.gid_map, "0 300 1, 5000 600 50");
        assert_eq!(shared_dir.fs_cfg.ascii_casefold, false);
        assert_eq!(shared_dir.fs_cfg.attr_timeout, Duration::from_secs(3600));
        assert_eq!(shared_dir.fs_cfg.entry_timeout, Duration::from_secs(3600));
        assert_eq!(shared_dir.fs_cfg.writeback, false);
        assert_eq!(
            shared_dir.fs_cfg.cache_policy,
            passthrough::CachePolicy::Always
        );
        assert_eq!(shared_dir.fs_cfg.rewrite_security_xattrs, true);
        assert_eq!(shared_dir.fs_cfg.use_dax, false);
        assert_eq!(shared_dir.fs_cfg.posix_acl, true);
        assert_eq!(shared_dir.ugid, (None, None));
    }

    #[cfg(unix)]
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
}
