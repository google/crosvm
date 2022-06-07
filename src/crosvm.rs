// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The root level module that includes the config and aggregate of the submodules for running said
//! configs.

pub mod argument;
#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
pub mod gdb;
#[path = "crosvm/linux/mod.rs"]
pub mod platform;
#[cfg(feature = "plugin")]
pub mod plugin;

use std::collections::BTreeMap;
use std::net;
use std::ops::RangeInclusive;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use argh::FromArgs;
use base::debug;
use devices::virtio::vhost::user::device;

use super::sys;
use arch::{MsrConfig, Pstore, VcpuAffinity};
use argh_helpers::generate_catchall_args;
use devices::serial_device::{SerialHardware, SerialParameters};
use devices::virtio::block::block::DiskOption;
#[cfg(feature = "audio_cras")]
use devices::virtio::cras_backend::Parameters as CrasSndParameters;
use devices::virtio::fs::passthrough;
#[cfg(feature = "gpu")]
use devices::virtio::gpu::GpuParameters;
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
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use resources::MemRegion;
use uuid::Uuid;
use vm_control::BatteryType;

static KVM_PATH: &str = "/dev/kvm";
static VHOST_NET_PATH: &str = "/dev/vhost-net";
static SECCOMP_POLICY_DIR: &str = "/usr/share/policy/crosvm";

// Commandline arguments

#[derive(FromArgs)]
/// crosvm
pub struct CrosvmCmdlineArgs {
    #[argh(switch)]
    /// use extended exit status
    pub extended_status: bool,
    #[argh(option, default = r#"String::from("info")"#)]
    /// specify log level, eg "off", "error", "debug,disk=off", etc
    pub log_level: String,
    #[argh(switch)]
    /// disable output to syslog
    pub no_syslog: bool,
    #[argh(subcommand)]
    pub command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum Command {
    Balloon(BalloonCommand),
    BalloonStats(BalloonStatsCommand),
    Battery(BatteryCommand),
    #[cfg(feature = "composite-disk")]
    CreateComposite(CreateCompositeCommand),
    CreateQcow2(CreateQcow2Command),
    Device(DevicesCommand),
    Disk(DiskCommand),
    MakeRT(MakeRTCommand),
    Resume(ResumeCommand),
    Run(RunCommand),
    Stop(StopCommand),
    Suspend(SuspendCommand),
    Powerbtn(PowerbtnCommand),
    Sleepbtn(SleepCommand),
    Gpe(GpeCommand),
    Usb(UsbCommand),
    Version(VersionCommand),
    Vfio(VfioCrosvmCommand),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "balloon")]
/// Set balloon size of the crosvm instance to `SIZE` bytes
pub struct BalloonCommand {
    #[argh(positional, arg_name = "SIZE")]
    /// amount of bytes
    pub num_bytes: u64,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(argh::FromArgs)]
#[argh(subcommand, name = "balloon_stats")]
/// Prints virtio balloon statistics for a `VM_SOCKET`
pub struct BalloonStatsCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "battery")]
/// Modify battery
pub struct BatteryCommand {
    #[argh(positional, arg_name = "BATTERY_TYPE")]
    /// battery type
    pub battery_type: String,
    #[argh(positional)]
    /// battery property
    /// status | present | health | capacity | aconline
    pub property: String,
    #[argh(positional)]
    /// battery property target
    /// STATUS | PRESENT | HEALTH | CAPACITY | ACONLINE
    pub target: String,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[cfg(feature = "composite-disk")]
#[derive(FromArgs)]
#[argh(subcommand, name = "create_composite")]
/// Create a new composite disk image file
pub struct CreateCompositeCommand {
    #[argh(positional, arg_name = "PATH")]
    /// image path
    pub path: String,
    #[argh(positional, arg_name = "LABEL:PARTITION")]
    /// partitions
    pub partitions: Vec<String>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "create_qcow2")]
/// Create Qcow2 image given path and size
pub struct CreateQcow2Command {
    #[argh(positional, arg_name = "PATH")]
    /// path to the new qcow2 file to create
    pub file_path: String,
    #[argh(positional, arg_name = "SIZE")]
    /// desired size of the image in bytes; required if not using --backing-file
    pub size: Option<u64>,
    #[argh(option)]
    /// path to backing file; if specified, the image will be the same size as the backing file, and
    /// SIZE may not be specified
    pub backing_file: Option<String>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum DiskSubcommand {
    Resize(ResizeDiskSubcommand),
}

#[derive(FromArgs)]
/// resize disk
#[argh(subcommand, name = "resize")]
pub struct ResizeDiskSubcommand {
    #[argh(positional, arg_name = "DISK_INDEX")]
    /// disk index
    pub disk_index: usize,
    #[argh(positional, arg_name = "NEW_SIZE")]
    /// new disk size
    pub disk_size: u64,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "disk")]
/// Manage attached virtual disk devices
pub struct DiskCommand {
    #[argh(subcommand)]
    pub command: DiskSubcommand,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "make_rt")]
/// Enables real-time vcpu priority for crosvm instances started with `--delay-rt`
pub struct MakeRTCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "resume")]
/// Resumes the crosvm instance
pub struct ResumeCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[generate_catchall_args]
#[argh(subcommand, name = "run")]
/// Start a new crosvm instance
pub struct RunCommand {}

#[derive(FromArgs)]
#[argh(subcommand, name = "stop")]
/// Stops crosvm instances via their control sockets
pub struct StopCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "suspend")]
/// Suspends the crosvm instance
pub struct SuspendCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "powerbtn")]
/// Triggers a power button event in the crosvm instance
pub struct PowerbtnCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "sleepbtn")]
/// Triggers a sleep button event in the crosvm instance
pub struct SleepCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "gpe")]
/// Injects a general-purpose event into the crosvm instance
pub struct GpeCommand {
    #[argh(positional)]
    /// GPE #
    pub gpe: u32,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "usb")]
/// Manage attached virtual USB devices.
pub struct UsbCommand {
    #[argh(subcommand)]
    pub command: UsbSubCommand,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "version")]
/// Show package version.
pub struct VersionCommand {}

#[derive(FromArgs)]
#[argh(subcommand, name = "add")]
/// ADD
pub struct VfioAddSubCommand {
    #[argh(positional)]
    /// path to host's vfio sysfs
    pub vfio_path: PathBuf,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "remove")]
/// REMOVE
pub struct VfioRemoveSubCommand {
    #[argh(positional)]
    /// path to host's vfio sysfs
    pub vfio_path: PathBuf,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum VfioSubCommand {
    Add(VfioAddSubCommand),
    Remove(VfioRemoveSubCommand),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "vfio")]
/// add/remove host vfio pci device into guest
pub struct VfioCrosvmCommand {
    #[argh(subcommand)]
    pub command: VfioSubCommand,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "device")]
/// Start a device process
pub struct DevicesCommand {
    #[argh(subcommand)]
    pub command: DevicesSubcommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
/// Cross-platform Devices
pub enum CrossPlatformDevicesCommands {
    Block(device::BlockOptions),
    Net(device::NetOptions),
}

#[derive(argh_helpers::FlattenSubcommand)]
pub enum DevicesSubcommand {
    CrossPlatform(CrossPlatformDevicesCommands),
    Sys(sys::DevicesSubcommand),
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum UsbSubCommand {
    Attach(UsbAttachCommand),
    Detach(UsbDetachCommand),
    List(UsbListCommand),
}

#[derive(FromArgs)]
/// Attach usb device
#[argh(subcommand, name = "attach")]
pub struct UsbAttachCommand {
    #[argh(
        positional,
        arg_name = "BUS_ID:ADDR:BUS_NUM:DEV_NUM",
        from_str_fn(parse_bus_id_addr)
    )]
    pub addr: (u8, u8, u16, u16),
    #[argh(positional)]
    /// usb device path
    pub dev_path: String,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
/// Detach usb device
#[argh(subcommand, name = "detach")]
pub struct UsbDetachCommand {
    #[argh(positional, arg_name = "PORT")]
    /// usb port
    pub port: u8,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
/// Detach usb device
#[argh(subcommand, name = "list")]
pub struct UsbListCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

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

fn parse_bus_id_addr(v: &str) -> Result<(u8, u8, u16, u16), String> {
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

/// Aggregate of all configurable options for a running VM.
#[remain::sorted]
pub struct Config {
    #[cfg(feature = "audio")]
    pub ac97_parameters: Vec<Ac97Parameters>,
    pub acpi_tables: Vec<PathBuf>,
    pub android_fstab: Option<PathBuf>,
    pub balloon: bool,
    pub balloon_bias: i64,
    pub balloon_control: Option<PathBuf>,
    pub battery_type: Option<BatteryType>,
    pub cid: Option<u64>,
    pub coiommu_param: Option<devices::CoIommuParameters>,
    pub cpu_capacity: BTreeMap<usize, u32>, // CPU index -> capacity
    pub cpu_clusters: Vec<Vec<usize>>,
    #[cfg(feature = "audio_cras")]
    pub cras_snds: Vec<CrasSndParameters>,
    pub delay_rt: bool,
    #[cfg(feature = "direct")]
    pub direct_edge_irq: Vec<u32>,
    #[cfg(feature = "direct")]
    pub direct_gpe: Vec<u32>,
    #[cfg(feature = "direct")]
    pub direct_level_irq: Vec<u32>,
    #[cfg(feature = "direct")]
    pub direct_mmio: Option<DirectIoOption>,
    #[cfg(feature = "direct")]
    pub direct_pmio: Option<DirectIoOption>,
    pub disks: Vec<DiskOption>,
    pub display_window_keyboard: bool,
    pub display_window_mouse: bool,
    pub dmi_path: Option<PathBuf>,
    pub enable_pnp_data: bool,
    pub executable_path: Option<Executable>,
    pub file_backed_mappings: Vec<FileBackedMappingParameters>,
    pub force_s2idle: bool,
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    pub gdb: Option<u32>,
    #[cfg(feature = "gpu")]
    pub gpu_parameters: Option<GpuParameters>,
    #[cfg(feature = "gpu")]
    pub gpu_render_server_parameters: Option<GpuRenderServerParameters>,
    pub host_cpu_topology: bool,
    pub host_ip: Option<net::Ipv4Addr>,
    pub hugepages: bool,
    pub init_memory: Option<u64>,
    pub initrd_path: Option<PathBuf>,
    pub itmt: bool,
    pub jail_config: Option<JailConfig>,
    pub jail_enabled: bool,
    pub kvm_device_path: PathBuf,
    pub mac_address: Option<net_util::MacAddress>,
    pub memory: Option<u64>,
    pub memory_file: Option<PathBuf>,
    pub mmio_address_ranges: Vec<RangeInclusive<u64>>,
    pub net_vq_pairs: Option<u16>,
    pub netmask: Option<net::Ipv4Addr>,
    pub no_legacy: bool,
    pub no_smt: bool,
    pub params: Vec<String>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub pci_low_start: Option<u64>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub pcie_ecam: Option<MemRegion>,
    #[cfg(feature = "direct")]
    pub pcie_rp: Vec<HostPcieRootPortParameters>,
    pub per_vm_core_scheduling: bool,
    pub plugin_gid_maps: Vec<GidMap>,
    pub plugin_mounts: Vec<BindMount>,
    pub plugin_root: Option<PathBuf>,
    pub pmem_devices: Vec<DiskOption>,
    pub privileged_vm: bool,
    pub protected_vm: ProtectionType,
    pub pstore: Option<Pstore>,
    /// Must be `Some` iff `protected_vm == ProtectionType::UnprotectedWithFirmware`.
    pub pvm_fw: Option<PathBuf>,
    pub rng: bool,
    pub rt_cpus: Vec<usize>,
    pub serial_parameters: BTreeMap<(SerialHardware, u8), SerialParameters>,
    pub shared_dirs: Vec<SharedDir>,
    pub socket_path: Option<PathBuf>,
    pub software_tpm: bool,
    #[cfg(feature = "audio")]
    pub sound: Option<PathBuf>,
    pub split_irqchip: bool,
    pub strict_balloon: bool,
    pub stub_pci_devices: Vec<StubPciParameters>,
    pub swiotlb: Option<u64>,
    pub syslog_tag: Option<String>,
    pub tap_fd: Vec<RawFd>,
    pub tap_name: Vec<String>,
    #[cfg(target_os = "android")]
    pub task_profiles: Vec<String>,
    pub usb: bool,
    pub userspace_msr: BTreeMap<u32, MsrConfig>,
    pub vcpu_affinity: Option<VcpuAffinity>,
    pub vcpu_cgroup_path: Option<PathBuf>,
    pub vcpu_count: Option<usize>,
    pub vfio: Vec<VfioCommand>,
    pub vhost_net: bool,
    pub vhost_net_device_path: PathBuf,
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
    pub vhost_vsock_device: Option<PathBuf>,
    #[cfg(feature = "video-decoder")]
    pub video_dec: Option<VideoBackendType>,
    #[cfg(feature = "video-encoder")]
    pub video_enc: Option<VideoBackendType>,
    pub virtio_input_evdevs: Vec<PathBuf>,
    pub virtio_keyboard: Vec<PathBuf>,
    pub virtio_mice: Vec<PathBuf>,
    pub virtio_multi_touch: Vec<TouchDeviceOption>,
    pub virtio_single_touch: Vec<TouchDeviceOption>,
    pub virtio_switches: Vec<PathBuf>,
    pub virtio_trackpad: Vec<TouchDeviceOption>,
    pub vvu_proxy: Vec<VvuOption>,
    pub wayland_socket_paths: BTreeMap<String, PathBuf>,
    pub x_display: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            #[cfg(feature = "audio")]
            ac97_parameters: Vec::new(),
            acpi_tables: Vec::new(),
            android_fstab: None,
            balloon: true,
            balloon_bias: 0,
            balloon_control: None,
            battery_type: None,
            cid: None,
            coiommu_param: None,
            #[cfg(feature = "audio_cras")]
            cras_snds: Vec::new(),
            cpu_capacity: BTreeMap::new(),
            cpu_clusters: Vec::new(),
            delay_rt: false,
            #[cfg(feature = "direct")]
            direct_edge_irq: Vec::new(),
            #[cfg(feature = "direct")]
            direct_gpe: Vec::new(),
            #[cfg(feature = "direct")]
            direct_level_irq: Vec::new(),
            #[cfg(feature = "direct")]
            direct_mmio: None,
            #[cfg(feature = "direct")]
            direct_pmio: None,
            disks: Vec::new(),
            display_window_keyboard: false,
            display_window_mouse: false,
            dmi_path: None,
            enable_pnp_data: false,
            executable_path: None,
            file_backed_mappings: Vec::new(),
            force_s2idle: false,
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            gdb: None,
            #[cfg(feature = "gpu")]
            gpu_parameters: None,
            #[cfg(feature = "gpu")]
            gpu_render_server_parameters: None,
            host_cpu_topology: false,
            host_ip: None,
            hugepages: false,
            init_memory: None,
            initrd_path: None,
            itmt: false,
            // We initialize the jail configuration with a default value so jail-related options can
            // apply irrespective of whether jail is enabled or not. `jail_config` will then be
            // assigned `None` if it turns out that `jail_enabled` is `false` after we parse all the
            // arguments.
            jail_config: Some(Default::default()),
            jail_enabled: !cfg!(feature = "default-no-sandbox"),
            kvm_device_path: PathBuf::from(KVM_PATH),
            mac_address: None,
            memory: None,
            memory_file: None,
            mmio_address_ranges: Vec::new(),
            net_vq_pairs: None,
            netmask: None,
            no_legacy: false,
            no_smt: false,
            params: Vec::new(),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            pci_low_start: None,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            pcie_ecam: None,
            #[cfg(feature = "direct")]
            pcie_rp: Vec::new(),
            per_vm_core_scheduling: false,
            plugin_gid_maps: Vec::new(),
            plugin_mounts: Vec::new(),
            plugin_root: None,
            pmem_devices: Vec::new(),
            privileged_vm: false,
            protected_vm: ProtectionType::Unprotected,
            pstore: None,
            pvm_fw: None,
            rng: true,
            rt_cpus: Vec::new(),
            serial_parameters: BTreeMap::new(),
            shared_dirs: Vec::new(),
            socket_path: None,
            software_tpm: false,
            #[cfg(feature = "audio")]
            sound: None,
            split_irqchip: false,
            strict_balloon: false,
            stub_pci_devices: Vec::new(),
            swiotlb: None,
            syslog_tag: None,
            tap_fd: Vec::new(),
            tap_name: Vec::new(),
            #[cfg(target_os = "android")]
            task_profiles: Vec::new(),
            usb: true,
            userspace_msr: BTreeMap::new(),
            vcpu_affinity: None,
            vcpu_cgroup_path: None,
            vcpu_count: None,
            vfio: Vec::new(),
            vhost_net: false,
            vhost_net_device_path: PathBuf::from(VHOST_NET_PATH),
            vhost_user_blk: Vec::new(),
            vhost_user_console: Vec::new(),
            vhost_user_fs: Vec::new(),
            vhost_user_gpu: Vec::new(),
            vhost_user_mac80211_hwsim: None,
            vhost_user_net: Vec::new(),
            #[cfg(feature = "audio")]
            vhost_user_snd: Vec::new(),
            vhost_user_vsock: Vec::new(),
            vhost_user_wl: Vec::new(),
            vhost_vsock_device: None,
            #[cfg(feature = "video-decoder")]
            video_dec: None,
            #[cfg(feature = "video-encoder")]
            video_enc: None,
            virtio_input_evdevs: Vec::new(),
            virtio_keyboard: Vec::new(),
            virtio_mice: Vec::new(),
            virtio_multi_touch: Vec::new(),
            virtio_single_touch: Vec::new(),
            virtio_switches: Vec::new(),
            virtio_trackpad: Vec::new(),
            vvu_proxy: Vec::new(),
            wayland_socket_paths: BTreeMap::new(),
            x_display: None,
        }
    }
}
