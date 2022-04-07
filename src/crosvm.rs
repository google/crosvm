// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The root level module that includes the config and aggregate of the submodules for running said
//! configs.

pub mod argument;
#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
pub mod gdb;
#[path = "linux/mod.rs"]
pub mod platform;
#[cfg(feature = "plugin")]
pub mod plugin;

use std::collections::{BTreeMap, BTreeSet};
use std::net;
use std::ops::RangeInclusive;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use arch::{Pstore, VcpuAffinity};
use devices::serial_device::{SerialHardware, SerialParameters};
use devices::virtio::block::block::DiskOption;
#[cfg(feature = "audio_cras")]
use devices::virtio::cras_backend::Parameters as CrasSndParameters;
use devices::virtio::fs::passthrough;
#[cfg(feature = "gpu")]
use devices::virtio::gpu::GpuParameters;
use devices::virtio::vhost::vsock::VhostVsockDeviceParameter;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
use devices::virtio::VideoBackendType;
#[cfg(feature = "audio")]
use devices::Ac97Parameters;
#[cfg(feature = "direct")]
use devices::BusRange;
use devices::{IommuDevType, PciAddress, StubPciParameters};
use hypervisor::ProtectionType;
use libc::{getegid, geteuid};
#[cfg(feature = "gpu")]
use platform::GpuRenderServerParameters;
use uuid::Uuid;
use vm_control::BatteryType;

static KVM_PATH: &str = "/dev/kvm";
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

/// Options for virtio-vhost-user proxy device.
pub struct VvuOption {
    pub socket: PathBuf,
    pub addr: Option<PciAddress>,
    pub uuid: Option<Uuid>,
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
#[derive(Debug)]
pub struct DirectIoOption {
    pub path: PathBuf,
    pub ranges: Vec<BusRange>,
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

/// Vfio device type, recognized based on command line option.
#[derive(Eq, PartialEq, Clone, Copy)]
pub enum VfioType {
    Pci,
    Platform,
}

impl FromStr for VfioType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use VfioType::*;
        match s {
            "vfio" => Ok(Pci),
            "vfio-platform" => Ok(Platform),
            _ => Err("invalid vfio device type, must be 'vfio|vfio-platform'"),
        }
    }
}

/// VFIO device structure for creating a new instance based on command line options.
pub struct VfioCommand {
    vfio_path: PathBuf,
    dev_type: VfioType,
    params: BTreeMap<String, String>,
}

impl VfioCommand {
    pub fn new(dev_type: VfioType, path: &str) -> argument::Result<VfioCommand> {
        let mut param = path.split(',');
        let vfio_path =
            PathBuf::from(param.next().ok_or_else(|| argument::Error::InvalidValue {
                value: path.to_owned(),
                expected: String::from("missing vfio path"),
            })?);

        if !vfio_path.exists() {
            return Err(argument::Error::InvalidValue {
                value: path.to_owned(),
                expected: String::from("the vfio path does not exist"),
            });
        }
        if !vfio_path.is_dir() {
            return Err(argument::Error::InvalidValue {
                value: path.to_owned(),
                expected: String::from("the vfio path should be directory"),
            });
        }

        let mut params = BTreeMap::new();
        for p in param {
            let mut kv = p.splitn(2, '=');
            if let (Some(kind), Some(value)) = (kv.next(), kv.next()) {
                Self::validate_params(kind, value)?;
                params.insert(kind.to_owned(), value.to_owned());
            };
        }
        Ok(VfioCommand {
            vfio_path,
            params,
            dev_type,
        })
    }

    fn validate_params(kind: &str, value: &str) -> Result<(), argument::Error> {
        match kind {
            "guest-address" => {
                if value.eq_ignore_ascii_case("auto") || PciAddress::from_str(value).is_ok() {
                    Ok(())
                } else {
                    Err(argument::Error::InvalidValue {
                        value: format!("{}={}", kind.to_owned(), value.to_owned()),
                        expected: String::from(
                            "option must be `guest-address=auto|<BUS:DEVICE.FUNCTION>`",
                        ),
                    })
                }
            }
            "iommu" => {
                if IommuDevType::from_str(value).is_ok() {
                    Ok(())
                } else {
                    Err(argument::Error::InvalidValue {
                        value: format!("{}={}", kind.to_owned(), value.to_owned()),
                        expected: String::from("option must be `iommu=viommu|coiommu|off`"),
                    })
                }
            }
            _ => Err(argument::Error::InvalidValue {
                value: format!("{}={}", kind.to_owned(), value.to_owned()),
                expected: String::from("option must be `guest-address=<val>` and/or `iommu=<val>`"),
            }),
        }
    }

    pub fn get_type(&self) -> VfioType {
        self.dev_type
    }

    pub fn guest_address(&self) -> Option<PciAddress> {
        self.params
            .get("guest-address")
            .and_then(|addr| PciAddress::from_str(addr).ok())
    }

    pub fn iommu_dev_type(&self) -> IommuDevType {
        if let Some(iommu) = self.params.get("iommu") {
            if let Ok(v) = IommuDevType::from_str(iommu) {
                return v;
            }
        }
        IommuDevType::NoIommu
    }
}

#[derive(Debug)]
pub struct FileBackedMappingParameters {
    pub address: u64,
    pub size: u64,
    pub path: PathBuf,
    pub offset: u64,
    pub writable: bool,
    pub sync: bool,
}

#[derive(Clone)]
pub struct HostPcieRootPortParameters {
    pub host_path: PathBuf,
    pub hp_gpe: Option<u32>,
}

#[derive(Debug)]
pub struct JailConfig {
    pub pivot_root: PathBuf,
    pub seccomp_policy_dir: PathBuf,
    pub seccomp_log_failures: bool,
}

impl Default for JailConfig {
    fn default() -> Self {
        JailConfig {
            pivot_root: PathBuf::from(option_env!("DEFAULT_PIVOT_ROOT").unwrap_or("/var/empty")),
            seccomp_policy_dir: PathBuf::from(SECCOMP_POLICY_DIR),
            seccomp_log_failures: false,
        }
    }
}

/// Aggregate of all configurable options for a running VM.
pub struct Config {
    pub kvm_device_path: PathBuf,
    pub vhost_vsock_device: Option<VhostVsockDeviceParameter>,
    pub vhost_net_device_path: PathBuf,
    pub vcpu_count: Option<usize>,
    pub vcpu_cgroup_path: Option<PathBuf>,
    pub rt_cpus: Vec<usize>,
    pub vcpu_affinity: Option<VcpuAffinity>,
    pub cpu_clusters: Vec<Vec<usize>>,
    pub cpu_capacity: BTreeMap<usize, u32>, // CPU index -> capacity
    pub per_vm_core_scheduling: bool,
    #[cfg(feature = "audio_cras")]
    pub cras_snds: Vec<CrasSndParameters>,
    pub delay_rt: bool,
    pub no_smt: bool,
    pub memory: Option<u64>,
    pub swiotlb: Option<u64>,
    pub hugepages: bool,
    pub memory_file: Option<PathBuf>,
    pub executable_path: Option<Executable>,
    pub android_fstab: Option<PathBuf>,
    pub initrd_path: Option<PathBuf>,
    pub jail_config: Option<JailConfig>,
    pub jail_enabled: bool,
    pub params: Vec<String>,
    pub socket_path: Option<PathBuf>,
    pub balloon_control: Option<PathBuf>,
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
    pub tap_name: Vec<String>,
    pub cid: Option<u64>,
    pub wayland_socket_paths: BTreeMap<String, PathBuf>,
    pub x_display: Option<String>,
    pub shared_dirs: Vec<SharedDir>,
    #[cfg(feature = "gpu")]
    pub gpu_parameters: Option<GpuParameters>,
    #[cfg(feature = "gpu")]
    pub gpu_render_server_parameters: Option<GpuRenderServerParameters>,
    pub software_tpm: bool,
    pub display_window_keyboard: bool,
    pub display_window_mouse: bool,
    #[cfg(feature = "audio")]
    pub ac97_parameters: Vec<Ac97Parameters>,
    #[cfg(feature = "audio")]
    pub sound: Option<PathBuf>,
    pub serial_parameters: BTreeMap<(SerialHardware, u8), SerialParameters>,
    pub syslog_tag: Option<String>,
    pub usb: bool,
    pub virtio_single_touch: Vec<TouchDeviceOption>,
    pub virtio_multi_touch: Vec<TouchDeviceOption>,
    pub virtio_trackpad: Vec<TouchDeviceOption>,
    pub virtio_mice: Vec<PathBuf>,
    pub virtio_keyboard: Vec<PathBuf>,
    pub virtio_switches: Vec<PathBuf>,
    pub virtio_input_evdevs: Vec<PathBuf>,
    pub virtio_iommu: bool,
    pub split_irqchip: bool,
    pub vfio: Vec<VfioCommand>,
    #[cfg(feature = "video-decoder")]
    pub video_dec: Option<VideoBackendType>,
    #[cfg(feature = "video-encoder")]
    pub video_enc: Option<VideoBackendType>,
    pub acpi_tables: Vec<PathBuf>,
    pub protected_vm: ProtectionType,
    pub battery_type: Option<BatteryType>,
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    pub gdb: Option<u32>,
    pub balloon: bool,
    pub balloon_bias: i64,
    pub vhost_user_blk: Vec<VhostUserOption>,
    pub vhost_user_console: Vec<VhostUserOption>,
    pub vhost_user_fs: Vec<VhostUserFsOption>,
    pub vhost_user_gpu: Vec<VhostUserOption>,
    pub vhost_user_mac80211_hwsim: Option<VhostUserOption>,
    pub vhost_user_net: Vec<VhostUserOption>,
    #[cfg(feature = "audio")]
    pub vhost_user_snd: Vec<VhostUserOption>,
    pub vhost_user_vsock: Vec<VhostUserOption>,
    pub vhost_user_wl: Vec<VhostUserWlOption>,
    #[cfg(feature = "direct")]
    pub direct_pmio: Option<DirectIoOption>,
    #[cfg(feature = "direct")]
    pub direct_mmio: Option<DirectIoOption>,
    #[cfg(feature = "direct")]
    pub direct_level_irq: Vec<u32>,
    #[cfg(feature = "direct")]
    pub direct_edge_irq: Vec<u32>,
    #[cfg(feature = "direct")]
    pub direct_wake_irq: Vec<u32>,
    #[cfg(feature = "direct")]
    pub direct_gpe: Vec<u32>,
    pub dmi_path: Option<PathBuf>,
    pub no_legacy: bool,
    pub host_cpu_topology: bool,
    pub privileged_vm: bool,
    pub stub_pci_devices: Vec<StubPciParameters>,
    pub vvu_proxy: Vec<VvuOption>,
    pub coiommu_param: Option<devices::CoIommuParameters>,
    pub file_backed_mappings: Vec<FileBackedMappingParameters>,
    pub init_memory: Option<u64>,
    #[cfg(feature = "direct")]
    pub pcie_rp: Vec<HostPcieRootPortParameters>,
    pub rng: bool,
    pub force_s2idle: bool,
    pub strict_balloon: bool,
    pub mmio_address_ranges: Vec<RangeInclusive<u64>>,
    pub userspace_msr: BTreeSet<u32>,
    #[cfg(target_os = "android")]
    pub task_profiles: Vec<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            kvm_device_path: PathBuf::from(KVM_PATH),
            vhost_vsock_device: None,
            vhost_net_device_path: PathBuf::from(VHOST_NET_PATH),
            vcpu_count: None,
            vcpu_cgroup_path: None,
            rt_cpus: Vec::new(),
            vcpu_affinity: None,
            cpu_clusters: Vec::new(),
            cpu_capacity: BTreeMap::new(),
            per_vm_core_scheduling: false,
            #[cfg(feature = "audio_cras")]
            cras_snds: Vec::new(),
            delay_rt: false,
            no_smt: false,
            memory: None,
            swiotlb: None,
            hugepages: false,
            memory_file: None,
            executable_path: None,
            android_fstab: None,
            initrd_path: None,
            // We initialize the jail configuration with a default value so jail-related options can
            // apply irrespective of whether jail is enabled or not. `jail_config` will then be
            // assigned `None` if it turns out that `jail_enabled` is `false` after we parse all the
            // arguments.
            jail_config: Some(Default::default()),
            jail_enabled: !cfg!(feature = "default-no-sandbox"),
            params: Vec::new(),
            socket_path: None,
            balloon_control: None,
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
            tap_name: Vec::new(),
            cid: None,
            #[cfg(feature = "gpu")]
            gpu_parameters: None,
            #[cfg(feature = "gpu")]
            gpu_render_server_parameters: None,
            software_tpm: false,
            wayland_socket_paths: BTreeMap::new(),
            x_display: None,
            display_window_keyboard: false,
            display_window_mouse: false,
            shared_dirs: Vec::new(),
            #[cfg(feature = "audio")]
            ac97_parameters: Vec::new(),
            #[cfg(feature = "audio")]
            sound: None,
            serial_parameters: BTreeMap::new(),
            syslog_tag: None,
            usb: true,
            virtio_single_touch: Vec::new(),
            virtio_multi_touch: Vec::new(),
            virtio_trackpad: Vec::new(),
            virtio_mice: Vec::new(),
            virtio_keyboard: Vec::new(),
            virtio_switches: Vec::new(),
            virtio_input_evdevs: Vec::new(),
            virtio_iommu: false,
            split_irqchip: false,
            vfio: Vec::new(),
            #[cfg(feature = "video-decoder")]
            video_dec: None,
            #[cfg(feature = "video-encoder")]
            video_enc: None,
            acpi_tables: Vec::new(),
            protected_vm: ProtectionType::Unprotected,
            battery_type: None,
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            gdb: None,
            balloon: true,
            balloon_bias: 0,
            vhost_user_blk: Vec::new(),
            vhost_user_console: Vec::new(),
            vhost_user_gpu: Vec::new(),
            vhost_user_fs: Vec::new(),
            vhost_user_mac80211_hwsim: None,
            vhost_user_net: Vec::new(),
            #[cfg(feature = "audio")]
            vhost_user_snd: Vec::new(),
            vhost_user_vsock: Vec::new(),
            vhost_user_wl: Vec::new(),
            vvu_proxy: Vec::new(),
            #[cfg(feature = "direct")]
            direct_pmio: None,
            #[cfg(feature = "direct")]
            direct_mmio: None,
            #[cfg(feature = "direct")]
            direct_level_irq: Vec::new(),
            #[cfg(feature = "direct")]
            direct_edge_irq: Vec::new(),
            #[cfg(feature = "direct")]
            direct_wake_irq: Vec::new(),
            #[cfg(feature = "direct")]
            direct_gpe: Vec::new(),
            dmi_path: None,
            no_legacy: false,
            host_cpu_topology: false,
            privileged_vm: false,
            stub_pci_devices: Vec::new(),
            coiommu_param: None,
            file_backed_mappings: Vec::new(),
            init_memory: None,
            #[cfg(feature = "direct")]
            pcie_rp: Vec::new(),
            rng: true,
            force_s2idle: false,
            strict_balloon: false,
            mmio_address_ranges: Vec::new(),
            userspace_msr: BTreeSet::new(),
            #[cfg(target_os = "android")]
            task_profiles: Vec::new(),
        }
    }
}
