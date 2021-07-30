// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The root level module that includes the config and aggregate of the submodules for running said
//! configs.

pub mod argument;
pub mod error;
#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
pub mod gdb;
#[path = "linux.rs"]
pub mod platform;
#[cfg(feature = "plugin")]
pub mod plugin;

use std::collections::BTreeMap;
use std::net;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use arch::{Pstore, SerialHardware, SerialParameters, VcpuAffinity};
use devices::virtio::fs::passthrough;
#[cfg(feature = "gpu")]
use devices::virtio::gpu::GpuParameters;
#[cfg(feature = "audio")]
use devices::Ac97Parameters;
use devices::ProtectionType;
use libc::{getegid, geteuid};
use vm_control::BatteryType;

static KVM_PATH: &str = "/dev/kvm";
static VHOST_VSOCK_PATH: &str = "/dev/vhost-vsock";
static VHOST_NET_PATH: &str = "/dev/vhost-net";
static SECCOMP_POLICY_DIR: &str = "/usr/share/policy/crosvm";

/// Indicates the location and kind of executable kernel for a VM.
#[derive(Debug)]
pub enum Executable {
    /// An executable intended to be run as a BIOS directly.
    Bios(PathBuf),
    /// A elf linux kernel, loaded and executed by crosvm.
    Kernel(PathBuf),
    /// Path to a plugin executable that is forked by crosvm.
    Plugin(PathBuf),
}

/// Maximum length of a `DiskOption` identifier.
///
/// This is based on the virtio-block ID length limit.
pub const DISK_ID_LEN: usize = 20;

pub struct DiskOption {
    pub path: PathBuf,
    pub read_only: bool,
    pub sparse: bool,
    pub o_direct: bool,
    pub block_size: u32,
    pub id: Option<[u8; DISK_ID_LEN]>,
}

pub struct VhostUserOption {
    pub socket: PathBuf,
}

pub struct VhostUserFsOption {
    pub socket: PathBuf,
    pub tag: String,
}

pub struct VhostUserWlOption {
    pub socket: PathBuf,
    pub vm_tube: PathBuf,
}

/// A bind mount for directories in the plugin process.
pub struct BindMount {
    pub src: PathBuf,
    pub dst: PathBuf,
    pub writable: bool,
}

/// A mapping of linux group IDs for the plugin process.
pub struct GidMap {
    pub inner: libc::gid_t,
    pub outer: libc::gid_t,
    pub count: u32,
}

/// Direct IO forwarding options
#[cfg(feature = "direct")]
pub struct DirectIoOption {
    pub path: PathBuf,
    pub ranges: Vec<(u64, u64)>,
}

pub const DEFAULT_TOUCH_DEVICE_HEIGHT: u32 = 1024;
pub const DEFAULT_TOUCH_DEVICE_WIDTH: u32 = 1280;

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
    pub fn get_path(&self) -> &Path {
        self.path.as_path()
    }

    /// When a user specifies the parameters for a touch device, width and height are optional.
    /// If the width and height are missing, default values are used. Default values can be set
    /// dynamically, for example from the display sizes specified by the gpu argument.
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
    pub fn get_size(&self) -> (u32, u32) {
        (
            self.width.unwrap_or(self.default_width),
            self.height.unwrap_or(self.default_height),
        )
    }
}

#[derive(Eq, PartialEq)]
pub enum SharedDirKind {
    FS,
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

impl Default for SharedDirKind {
    fn default() -> SharedDirKind {
        SharedDirKind::P9
    }
}

pub struct SharedDir {
    pub src: PathBuf,
    pub tag: String,
    pub kind: SharedDirKind,
    pub uid_map: String,
    pub gid_map: String,
    pub fs_cfg: passthrough::Config,
    pub p9_cfg: p9::Config,
}

impl Default for SharedDir {
    fn default() -> SharedDir {
        SharedDir {
            src: Default::default(),
            tag: Default::default(),
            kind: Default::default(),
            uid_map: format!("0 {} 1", unsafe { geteuid() }),
            gid_map: format!("0 {} 1", unsafe { getegid() }),
            fs_cfg: Default::default(),
            p9_cfg: Default::default(),
        }
    }
}

/// Aggregate of all configurable options for a running VM.
pub struct Config {
    pub kvm_device_path: PathBuf,
    pub vhost_vsock_device_path: PathBuf,
    pub vhost_net_device_path: PathBuf,
    pub vcpu_count: Option<usize>,
    pub rt_cpus: Vec<usize>,
    pub vcpu_affinity: Option<VcpuAffinity>,
    pub cpu_clusters: Vec<Vec<usize>>,
    pub cpu_capacity: BTreeMap<usize, u32>, // CPU index -> capacity
    pub delay_rt: bool,
    pub no_smt: bool,
    pub memory: Option<u64>,
    pub swiotlb: Option<u64>,
    pub hugepages: bool,
    pub memory_file: Option<PathBuf>,
    pub executable_path: Option<Executable>,
    pub android_fstab: Option<PathBuf>,
    pub initrd_path: Option<PathBuf>,
    pub params: Vec<String>,
    pub socket_path: Option<PathBuf>,
    pub plugin_root: Option<PathBuf>,
    pub plugin_mounts: Vec<BindMount>,
    pub plugin_gid_maps: Vec<GidMap>,
    pub disks: Vec<DiskOption>,
    pub pmem_devices: Vec<DiskOption>,
    pub pstore: Option<Pstore>,
    pub host_ip: Option<net::Ipv4Addr>,
    pub netmask: Option<net::Ipv4Addr>,
    pub mac_address: Option<net_util::MacAddress>,
    pub net_vq_pairs: Option<u16>,
    pub vhost_net: bool,
    pub tap_fd: Vec<RawFd>,
    pub cid: Option<u64>,
    pub wayland_socket_paths: BTreeMap<String, PathBuf>,
    pub x_display: Option<String>,
    pub shared_dirs: Vec<SharedDir>,
    pub sandbox: bool,
    pub seccomp_policy_dir: PathBuf,
    pub seccomp_log_failures: bool,
    #[cfg(feature = "gpu")]
    pub gpu_parameters: Option<GpuParameters>,
    pub software_tpm: bool,
    pub display_window_keyboard: bool,
    pub display_window_mouse: bool,
    #[cfg(feature = "audio")]
    pub ac97_parameters: Vec<Ac97Parameters>,
    #[cfg(feature = "audio")]
    pub sound: Option<PathBuf>,
    pub serial_parameters: BTreeMap<(SerialHardware, u8), SerialParameters>,
    pub syslog_tag: Option<String>,
    pub virtio_single_touch: Vec<TouchDeviceOption>,
    pub virtio_multi_touch: Vec<TouchDeviceOption>,
    pub virtio_trackpad: Vec<TouchDeviceOption>,
    pub virtio_mice: Vec<PathBuf>,
    pub virtio_keyboard: Vec<PathBuf>,
    pub virtio_switches: Vec<PathBuf>,
    pub virtio_input_evdevs: Vec<PathBuf>,
    pub split_irqchip: bool,
    pub vfio: BTreeMap<PathBuf, bool>,
    pub video_dec: bool,
    pub video_enc: bool,
    pub acpi_tables: Vec<PathBuf>,
    pub protected_vm: ProtectionType,
    pub battery_type: Option<BatteryType>,
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    pub gdb: Option<u32>,
    pub balloon_bias: i64,
    pub vhost_user_blk: Vec<VhostUserOption>,
    pub vhost_user_console: Vec<VhostUserOption>,
    pub vhost_user_fs: Vec<VhostUserFsOption>,
    pub vhost_user_mac80211_hwsim: Option<VhostUserOption>,
    pub vhost_user_net: Vec<VhostUserOption>,
    pub vhost_user_wl: Vec<VhostUserWlOption>,
    #[cfg(feature = "direct")]
    pub direct_pmio: Option<DirectIoOption>,
    #[cfg(feature = "direct")]
    pub direct_level_irq: Vec<u32>,
    #[cfg(feature = "direct")]
    pub direct_edge_irq: Vec<u32>,
    pub dmi_path: Option<PathBuf>,
    pub no_legacy: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            kvm_device_path: PathBuf::from(KVM_PATH),
            vhost_vsock_device_path: PathBuf::from(VHOST_VSOCK_PATH),
            vhost_net_device_path: PathBuf::from(VHOST_NET_PATH),
            vcpu_count: None,
            rt_cpus: Vec::new(),
            vcpu_affinity: None,
            cpu_clusters: Vec::new(),
            cpu_capacity: BTreeMap::new(),
            delay_rt: false,
            no_smt: false,
            memory: None,
            swiotlb: None,
            hugepages: false,
            memory_file: None,
            executable_path: None,
            android_fstab: None,
            initrd_path: None,
            params: Vec::new(),
            socket_path: None,
            plugin_root: None,
            plugin_mounts: Vec::new(),
            plugin_gid_maps: Vec::new(),
            disks: Vec::new(),
            pmem_devices: Vec::new(),
            pstore: None,
            host_ip: None,
            netmask: None,
            mac_address: None,
            net_vq_pairs: None,
            vhost_net: false,
            tap_fd: Vec::new(),
            cid: None,
            #[cfg(feature = "gpu")]
            gpu_parameters: None,
            software_tpm: false,
            wayland_socket_paths: BTreeMap::new(),
            x_display: None,
            display_window_keyboard: false,
            display_window_mouse: false,
            shared_dirs: Vec::new(),
            sandbox: !cfg!(feature = "default-no-sandbox"),
            seccomp_policy_dir: PathBuf::from(SECCOMP_POLICY_DIR),
            seccomp_log_failures: false,
            #[cfg(feature = "audio")]
            ac97_parameters: Vec::new(),
            #[cfg(feature = "audio")]
            sound: None,
            serial_parameters: BTreeMap::new(),
            syslog_tag: None,
            virtio_single_touch: Vec::new(),
            virtio_multi_touch: Vec::new(),
            virtio_trackpad: Vec::new(),
            virtio_mice: Vec::new(),
            virtio_keyboard: Vec::new(),
            virtio_switches: Vec::new(),
            virtio_input_evdevs: Vec::new(),
            split_irqchip: false,
            vfio: BTreeMap::new(),
            video_dec: false,
            video_enc: false,
            acpi_tables: Vec::new(),
            protected_vm: ProtectionType::Unprotected,
            battery_type: None,
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            gdb: None,
            balloon_bias: 0,
            vhost_user_blk: Vec::new(),
            vhost_user_console: Vec::new(),
            vhost_user_fs: Vec::new(),
            vhost_user_mac80211_hwsim: None,
            vhost_user_net: Vec::new(),
            vhost_user_wl: Vec::new(),
            #[cfg(feature = "direct")]
            direct_pmio: None,
            #[cfg(feature = "direct")]
            direct_level_irq: Vec::new(),
            #[cfg(feature = "direct")]
            direct_edge_irq: Vec::new(),
            dmi_path: None,
            no_legacy: false,
        }
    }
}
