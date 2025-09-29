// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        use base::RawDescriptor;
        use devices::virtio::vhost::user::device::parse_wayland_sock;

        use crate::crosvm::sys::config::parse_pmem_ext2_option;
        use crate::crosvm::sys::config::VfioOption;
        use crate::crosvm::sys::config::SharedDir;
        use crate::crosvm::sys::config::PmemExt2Option;
    }
}

use std::collections::BTreeMap;
#[cfg(feature = "config-file")]
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use arch::CpuSet;
use arch::FdtPosition;
#[cfg(all(target_os = "android", target_arch = "aarch64"))]
use arch::FfaConfig;
#[cfg(target_arch = "x86_64")]
use arch::MemoryRegionConfig;
use arch::PciConfig;
use arch::Pstore;
#[cfg(target_arch = "x86_64")]
use arch::SmbiosOptions;
use arch::VcpuAffinity;
use argh::FromArgs;
use base::getpid;
use cros_async::ExecutorKind;
use devices::virtio::block::DiskOption;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
use devices::virtio::device_constants::video::VideoDeviceConfig;
use devices::virtio::scsi::ScsiOption;
#[cfg(feature = "audio")]
use devices::virtio::snd::parameters::Parameters as SndParameters;
use devices::virtio::vhost::user::device;
use devices::virtio::vsock::VsockConfig;
#[cfg(feature = "gpu")]
use devices::virtio::GpuDisplayParameters;
#[cfg(feature = "gpu")]
use devices::virtio::GpuMouseMode;
#[cfg(feature = "gpu")]
use devices::virtio::GpuParameters;
#[cfg(all(unix, feature = "net"))]
use devices::virtio::NetParameters;
#[cfg(all(unix, feature = "net"))]
use devices::virtio::NetParametersMode;
use devices::FwCfgParameters;
use devices::PflashParameters;
use devices::SerialHardware;
use devices::SerialParameters;
use devices::StubPciParameters;
#[cfg(target_arch = "x86_64")]
use hypervisor::CpuHybridType;
use hypervisor::ProtectionType;
use merge::vec::append;
use resources::AddressRange;
#[cfg(feature = "config-file")]
use serde::de::Error as SerdeError;
use serde::Deserialize;
#[cfg(feature = "config-file")]
use serde::Deserializer;
use serde::Serialize;
#[cfg(feature = "gpu")]
use serde_keyvalue::FromKeyValues;
use vm_memory::FileBackedMappingParameters;

use super::config::PmemOption;
#[cfg(feature = "gpu")]
use super::gpu_config::fixup_gpu_display_options;
#[cfg(feature = "gpu")]
use super::gpu_config::fixup_gpu_options;
#[cfg(all(unix, feature = "gpu"))]
use super::sys::GpuRenderServerParameters;
use crate::crosvm::config::from_key_values;
use crate::crosvm::config::parse_bus_id_addr;
use crate::crosvm::config::parse_cpu_affinity;
use crate::crosvm::config::parse_cpu_btreemap_u32;
#[cfg(all(
    any(target_arch = "arm", target_arch = "aarch64"),
    any(target_os = "android", target_os = "linux")
))]
use crate::crosvm::config::parse_cpu_frequencies;
use crate::crosvm::config::parse_mmio_address_range;
use crate::crosvm::config::parse_pflash_parameters;
use crate::crosvm::config::parse_serial_options;
use crate::crosvm::config::parse_touch_device_option;
use crate::crosvm::config::BatteryConfig;
use crate::crosvm::config::CpuOptions;
use crate::crosvm::config::DtboOption;
use crate::crosvm::config::Executable;
use crate::crosvm::config::HypervisorKind;
use crate::crosvm::config::InputDeviceOption;
use crate::crosvm::config::IrqChipKind;
use crate::crosvm::config::MemOptions;
use crate::crosvm::config::TouchDeviceOption;
use crate::crosvm::config::VhostUserFrontendOption;
#[cfg(feature = "plugin")]
use crate::crosvm::plugin::parse_plugin_mount_option;
#[cfg(feature = "plugin")]
use crate::crosvm::plugin::BindMount;
#[cfg(feature = "plugin")]
use crate::crosvm::plugin::GidMap;

#[derive(FromArgs)]
/// crosvm
pub struct CrosvmCmdlineArgs {
    #[argh(switch)]
    /// use extended exit status
    pub extended_status: bool,
    #[argh(option, default = r#"String::from("info")"#)]
    /// specify log level, eg "off", "error", "debug,disk=off", etc
    pub log_level: String,
    #[argh(option, arg_name = "TAG")]
    /// when logging to syslog, use the provided tag
    pub syslog_tag: Option<String>,
    #[argh(switch)]
    /// disable output to syslog
    pub no_syslog: bool,
    #[argh(subcommand)]
    pub command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(FromArgs)]
#[argh(subcommand)]
pub enum CrossPlatformCommands {
    #[cfg(feature = "balloon")]
    Balloon(BalloonCommand),
    #[cfg(feature = "balloon")]
    BalloonStats(BalloonStatsCommand),
    #[cfg(feature = "balloon")]
    BalloonWs(BalloonWsCommand),
    Battery(BatteryCommand),
    #[cfg(feature = "composite-disk")]
    CreateComposite(CreateCompositeCommand),
    #[cfg(feature = "qcow")]
    CreateQcow2(CreateQcow2Command),
    Device(DeviceCommand),
    Disk(DiskCommand),
    #[cfg(feature = "gpu")]
    Gpu(GpuCommand),
    #[cfg(feature = "audio")]
    Snd(SndCommand),
    MakeRT(MakeRTCommand),
    Resume(ResumeCommand),
    Run(RunCommand),
    Stop(StopCommand),
    Suspend(SuspendCommand),
    Swap(SwapCommand),
    Powerbtn(PowerbtnCommand),
    Sleepbtn(SleepCommand),
    Gpe(GpeCommand),
    Usb(UsbCommand),
    Version(VersionCommand),
    Vfio(VfioCrosvmCommand),
    #[cfg(feature = "pci-hotplug")]
    VirtioNet(VirtioNetCommand),
    Snapshot(SnapshotCommand),
}

#[allow(clippy::large_enum_variant)]
#[derive(argh_helpers::FlattenSubcommand)]
pub enum Command {
    CrossPlatform(CrossPlatformCommands),
    Sys(super::sys::cmdline::Commands),
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
    /// wait for response
    #[argh(switch)]
    pub wait: bool,
}

#[derive(argh::FromArgs)]
#[argh(subcommand, name = "balloon_stats")]
/// Prints virtio balloon statistics for a `VM_SOCKET`
pub struct BalloonStatsCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(argh::FromArgs)]
#[argh(subcommand, name = "balloon_ws")]
/// Prints virtio balloon working set for a `VM_SOCKET`
pub struct BalloonWsCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM control socket path.
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
    #[argh(positional, arg_name = "LABEL:PARTITION[:writable][:<GUID>]")]
    /// partitions
    pub partitions: Vec<String>,
}

#[cfg(feature = "qcow")]
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
    /// path to backing file; if specified, the image will be the same size as the backing file,
    /// and SIZE may not be specified
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
/// Resumes the crosvm instance. No-op if already running. When starting crosvm with `--restore`,
/// this command can be used to wait until the restore is complete
// Implementation note: All the restore work happens before crosvm becomes able to process incoming
// commands, so really all commands can be used to wait for restore to complete, but few are side
// effect free.
pub struct ResumeCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
    /// suspend VM VCPUs and Devices
    #[argh(switch)]
    pub full: bool,
}

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
    /// suspend VM VCPUs and Devices
    #[argh(switch)]
    pub full: bool,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "enable")]
/// Enable vmm-swap of a VM. The guest memory is moved to staging memory
pub struct SwapEnableCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "trim")]
/// Trim pages in the staging memory
pub struct SwapTrimCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "out")]
/// Swap out staging memory to swap file
pub struct SwapOutCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "disable")]
/// Disable vmm-swap of a VM
pub struct SwapDisableCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
    #[argh(switch)]
    /// clean up the swap file in the background.
    pub slow_file_cleanup: bool,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "status")]
/// Get vmm-swap status of a VM
pub struct SwapStatusCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

/// Vmm-swap commands
#[derive(FromArgs)]
#[argh(subcommand, name = "swap")]
pub struct SwapCommand {
    #[argh(subcommand)]
    pub nested: SwapSubcommands,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum SwapSubcommands {
    Enable(SwapEnableCommand),
    Trim(SwapTrimCommand),
    SwapOut(SwapOutCommand),
    Disable(SwapDisableCommand),
    Status(SwapStatusCommand),
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

#[cfg(feature = "gpu")]
#[derive(FromArgs)]
#[argh(subcommand, name = "gpu")]
/// Manage attached virtual GPU device.
pub struct GpuCommand {
    #[argh(subcommand)]
    pub command: GpuSubCommand,
}

#[cfg(feature = "audio")]
#[derive(FromArgs)]
/// Mute or unmute all snd devices.
#[argh(subcommand, name = "mute-all")]
pub struct MuteAllCommand {
    #[argh(positional)]
    /// muted state. true for mute, and false for unmute
    pub muted: bool,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[cfg(feature = "audio")]
#[derive(FromArgs)]
#[argh(subcommand)]
pub enum SndSubCommand {
    MuteAll(MuteAllCommand),
}

#[cfg(feature = "audio")]
#[derive(FromArgs)]
#[argh(subcommand, name = "snd")]
/// Manage virtio-snd device.
pub struct SndCommand {
    #[argh(subcommand)]
    pub command: SndSubCommand,
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

#[cfg(feature = "pci-hotplug")]
#[derive(FromArgs)]
#[argh(subcommand)]
pub enum VirtioNetSubCommand {
    AddTap(VirtioNetAddSubCommand),
    RemoveTap(VirtioNetRemoveSubCommand),
}

#[cfg(feature = "pci-hotplug")]
#[derive(FromArgs)]
#[argh(subcommand, name = "add")]
/// Add by Tap name.
pub struct VirtioNetAddSubCommand {
    #[argh(positional)]
    /// tap name
    pub tap_name: String,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[cfg(feature = "pci-hotplug")]
#[derive(FromArgs)]
#[argh(subcommand, name = "remove")]
/// Remove tap by bus number.
pub struct VirtioNetRemoveSubCommand {
    #[argh(positional)]
    /// bus number for device to remove
    pub bus: u8,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM socket path
    pub socket_path: String,
}

#[cfg(feature = "pci-hotplug")]
#[derive(FromArgs)]
#[argh(subcommand, name = "virtio-net")]
/// add network device as virtio into guest.
pub struct VirtioNetCommand {
    #[argh(subcommand)]
    pub command: VirtioNetSubCommand,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "device")]
/// Start a device process
pub struct DeviceCommand {
    /// configure async executor backend; "uring" or "epoll" on Linux, "handle" or "overlapped" on
    /// Windows. If this option is omitted on Linux, "epoll" is used by default.
    #[argh(option, arg_name = "EXECUTOR")]
    pub async_executor: Option<ExecutorKind>,

    #[argh(subcommand)]
    pub command: DeviceSubcommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
/// Cross-platform Devices
pub enum CrossPlatformDevicesCommands {
    Block(device::BlockOptions),
    #[cfg(feature = "gpu")]
    Gpu(device::GpuOptions),
    #[cfg(feature = "net")]
    Net(device::NetOptions),
    #[cfg(feature = "audio")]
    Snd(device::SndOptions),
}

#[derive(argh_helpers::FlattenSubcommand)]
pub enum DeviceSubcommand {
    CrossPlatform(CrossPlatformDevicesCommands),
    Sys(super::sys::cmdline::DeviceSubcommand),
}

#[cfg(feature = "gpu")]
#[derive(FromArgs)]
#[argh(subcommand)]
pub enum GpuSubCommand {
    AddDisplays(GpuAddDisplaysCommand),
    ListDisplays(GpuListDisplaysCommand),
    RemoveDisplays(GpuRemoveDisplaysCommand),
    SetDisplayMouseMode(GpuSetDisplayMouseModeCommand),
}

#[cfg(feature = "gpu")]
#[derive(FromArgs)]
/// Attach a new display to the GPU device.
#[argh(subcommand, name = "add-displays")]
pub struct GpuAddDisplaysCommand {
    #[argh(option)]
    /// displays
    pub gpu_display: Vec<GpuDisplayParameters>,

    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[cfg(feature = "gpu")]
#[derive(FromArgs)]
/// List the displays currently attached to the GPU device.
#[argh(subcommand, name = "list-displays")]
pub struct GpuListDisplaysCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[cfg(feature = "gpu")]
#[derive(FromArgs)]
/// Detach an existing display from the GPU device.
#[argh(subcommand, name = "remove-displays")]
pub struct GpuRemoveDisplaysCommand {
    #[argh(option)]
    /// display id
    pub display_id: Vec<u32>,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[cfg(feature = "gpu")]
#[derive(FromArgs)]
/// Sets the mouse mode of a display attached to the GPU device.
#[argh(subcommand, name = "set-mouse-mode")]
pub struct GpuSetDisplayMouseModeCommand {
    #[argh(option)]
    /// display id
    pub display_id: u32,
    #[argh(option)]
    /// display mouse mode
    pub mouse_mode: GpuMouseMode,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum UsbSubCommand {
    Attach(UsbAttachCommand),
    SecurityKeyAttach(UsbAttachKeyCommand),
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
    #[allow(dead_code)]
    pub addr: (u8, u8, u16, u16),
    #[argh(positional)]
    /// usb device path
    pub dev_path: String,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

#[derive(FromArgs)]
/// Attach security key device
#[argh(subcommand, name = "attach_key")]
pub struct UsbAttachKeyCommand {
    #[argh(positional)]
    /// security key hidraw device path
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
/// List currently attached USB devices
#[argh(subcommand, name = "list")]
pub struct UsbListCommand {
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
}

/// Structure containing the parameters for a single disk as well as a unique counter increasing
/// each time a new disk parameter is parsed.
///
/// This allows the letters assigned to each disk to reflect the order of their declaration, as
/// we have several options for specifying disks (rwroot, root, etc) and order can thus be lost
/// when they are aggregated.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields, from = "DiskOption", into = "DiskOption")]
struct DiskOptionWithId {
    disk_option: DiskOption,
    index: usize,
}

/// FromStr implementation for argh.
impl FromStr for DiskOptionWithId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let disk_option: DiskOption = from_key_values(s)?;
        Ok(Self::from(disk_option))
    }
}

/// Assign the next id to `disk_option`.
impl From<DiskOption> for DiskOptionWithId {
    fn from(disk_option: DiskOption) -> Self {
        static DISK_COUNTER: AtomicUsize = AtomicUsize::new(0);
        Self {
            disk_option,
            index: DISK_COUNTER.fetch_add(1, Ordering::Relaxed),
        }
    }
}

impl From<DiskOptionWithId> for DiskOption {
    fn from(disk_option_with_id: DiskOptionWithId) -> Self {
        disk_option_with_id.disk_option
    }
}

#[derive(FromArgs)]
#[argh(subcommand, name = "snapshot", description = "Snapshot commands")]
/// Snapshot commands
pub struct SnapshotCommand {
    #[argh(subcommand)]
    pub snapshot_command: SnapshotSubCommands,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "take")]
/// Take a snapshot of the VM
pub struct SnapshotTakeCommand {
    #[argh(positional, arg_name = "snapshot_path")]
    /// VM Image path
    pub snapshot_path: PathBuf,
    #[argh(positional, arg_name = "VM_SOCKET")]
    /// VM Socket path
    pub socket_path: String,
    #[argh(switch)]
    /// compress the ram snapshot.
    pub compress_memory: bool,
    #[argh(switch, arg_name = "encrypt")]
    /// whether the snapshot should be encrypted
    pub encrypt: bool,
}

#[derive(FromArgs)]
#[argh(subcommand)]
/// Snapshot commands
pub enum SnapshotSubCommands {
    Take(SnapshotTakeCommand),
}

/// Container for GpuParameters that have been fixed after parsing using serde.
///
/// This deserializes as a regular `GpuParameters` and applies validation.
#[cfg(feature = "gpu")]
#[derive(Debug, Deserialize, FromKeyValues)]
#[serde(try_from = "GpuParameters")]
pub struct FixedGpuParameters(pub GpuParameters);

#[cfg(feature = "gpu")]
impl TryFrom<GpuParameters> for FixedGpuParameters {
    type Error = String;

    fn try_from(gpu_params: GpuParameters) -> Result<Self, Self::Error> {
        fixup_gpu_options(gpu_params)
    }
}

/// Container for `GpuDisplayParameters` that have been fixed after parsing using serde.
///
/// This deserializes as a regular `GpuDisplayParameters` and applies validation.
/// TODO(b/260101753): Remove this once the old syntax for specifying DPI is deprecated.
#[cfg(feature = "gpu")]
#[derive(Debug, Deserialize, FromKeyValues)]
#[serde(try_from = "GpuDisplayParameters")]
pub struct FixedGpuDisplayParameters(pub GpuDisplayParameters);

#[cfg(feature = "gpu")]
impl TryFrom<GpuDisplayParameters> for FixedGpuDisplayParameters {
    type Error = String;

    fn try_from(gpu_display_params: GpuDisplayParameters) -> Result<Self, Self::Error> {
        fixup_gpu_display_options(gpu_display_params)
    }
}

/// Deserialize `config_file` into a `RunCommand`.
#[cfg(feature = "config-file")]
fn load_config_file<P: AsRef<Path>>(config_file: P) -> Result<RunCommand, String> {
    let config = std::fs::read_to_string(config_file).map_err(|e| e.to_string())?;

    serde_json::from_str(&config).map_err(|e| e.to_string())
}

/// Return a vector configuration loaded from the files pointed by strings in a sequence.
///
/// Used for including configuration files from another one.
#[cfg(feature = "config-file")]
fn include_config_file<'de, D>(deserializer: D) -> Result<Vec<RunCommand>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::SeqAccess;

    struct ConfigVisitor;

    impl<'de> serde::de::Visitor<'de> for ConfigVisitor {
        type Value = Vec<RunCommand>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an array of paths to configuration file to include")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let mut ret = Vec::new();

            while let Some(path) = seq.next_element::<&'de str>()? {
                let config =
                    load_config_file(path).map_err(<S as SeqAccess<'de>>::Error::custom)?;
                ret.push(config);
            }

            Ok(ret)
        }
    }

    deserializer.deserialize_seq(ConfigVisitor)
}

#[cfg(feature = "config-file")]
fn write_config_file(config_file: &Path, cmd: &RunCommand) -> Result<(), String> {
    use std::io::Write;

    let mut w =
        std::io::BufWriter::new(std::fs::File::create(config_file).map_err(|e| e.to_string())?);
    serde_json::to_writer_pretty(&mut w, cmd).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())?;
    Ok(())
}

/// Overwrite an `Option<T>` if the right member is set.
///
/// The default merge strategy for `Option<T>` is to merge `right` into `left` iff `left.is_none()`.
/// This doesn't play well with our need to overwrite options that have already been set.
///
/// `overwrite_option` merges `right` into `left` iff `right.is_some()`, which allows us to override
/// previously-set options.
fn overwrite_option<T>(left: &mut Option<T>, right: Option<T>) {
    if right.is_some() {
        *left = right;
    }
}

#[allow(dead_code)]
fn overwrite<T>(left: &mut T, right: T) {
    let _ = std::mem::replace(left, right);
}

fn bool_default_true() -> bool {
    true
}

/// User-specified configuration for the `crosvm run` command.
///
/// All fields of this structure MUST be either an `Option` or a `Vec` of their type. Arguments of
/// type `Option` can only be specified once, whereas `Vec` arguments can be specified several
/// times.
///
/// Each field of this structure has a dual use:
///
/// 1) As a command-line parameter, controlled by the `#[argh]` helper attribute.
/// 2) As a configuration file parameter, controlled by the `#[serde]` helper attribute.
///
/// For consistency, field names should be the same and use kebab-case for both uses, so please
/// refrain from using renaming directives and give the field the desired parameter name (it will
/// automatically be converted to kebab-case).
///
/// For consistency and convenience, all parameters should be deserializable by `serde_keyvalue`, as
/// this will automatically provide the same schema for both the command-line and configuration
/// file. This is particularly important for fields that are enums or structs, for which extra
/// parameters can be specified. Make sure to annotate your struct/enum with
/// `#[serde(deny_unknown_fields, rename_all = "kebab-case")]` so invalid fields are properly
/// rejected and all members are converted to kebab-case.
///
/// Each field should also have a `#[merge]` helper attribute, which defines the strategy to use
/// when merging two configurations into one. This happens when e.g. the user has specified extra
/// command-line arguments along with a configuration file. In this case, the `RunCommand` created
/// from the command-line arguments will be merged into the `RunCommand` deserialized from the
/// configuration file.
///
/// The rule of thumb for `#[merge]` attributes is that parameters that can only be specified once
/// (of `Option` type) should be overridden (`#[merge(strategy = overwrite_option)]`), while
/// parameters that can be specified several times (typically of `Vec` type) should be appended
/// (`#[merge(strategy = append)]`), but there might also be exceptions.
///
/// The command-line is the root configuration source, but one or more configuration files can be
/// specified for inclusion using the `--cfg` argument. Configuration files are applied in the
/// order they are mentioned, overriding (for `Option` fields) or augmenting (for `Vec` fields)
/// their fields, and the command-line options are finally applied last.
///
/// A configuration files can also include other configuration files by using `cfg` itself.
/// Included configuration files are applied first, with the parent configuration file applied
/// last.
///
/// The doccomment of the member will be displayed as its help message with `--help`.
///
/// Note that many parameters are marked with `#[serde(skip)]` and annotated with b/255223604. This
/// is because we only want to enable parameters in the config file after they undergo a proper
/// review to make sure they won't be obsoleted.
#[remain::sorted]
#[argh_helpers::pad_description_for_argh]
#[derive(FromArgs, Default, Deserialize, Serialize, merge::Merge)]
#[argh(subcommand, name = "run", description = "Start a new crosvm instance")]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RunCommand {
    #[cfg(all(target_arch = "x86_64", unix))]
    #[argh(switch)]
    #[serde(default)]
    #[merge(strategy = overwrite_option)]
    /// enable AC adapter device
    /// It purpose is to emulate ACPI ACPI0003 device, replicate and propagate the
    /// ac adapter status from the host to the guest.
    pub ac_adapter: Option<bool>,

    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// path to user provided ACPI table
    pub acpi_table: Vec<PathBuf>,

    #[cfg(feature = "android_display")]
    #[argh(option, arg_name = "NAME")]
    #[merge(strategy = overwrite_option)]
    /// name that the Android display backend will be registered to the service manager.
    pub android_display_service: Option<String>,

    #[argh(option)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// path to Android fstab
    pub android_fstab: Option<PathBuf>,

    /// configure async executor backend; "uring" or "epoll" on Linux, "handle" or "overlapped" on
    /// Windows. If this option is omitted on Linux, "epoll" is used by default.
    #[argh(option, arg_name = "EXECUTOR")]
    #[serde(skip)] // TODO(b/255223604)
    pub async_executor: Option<ExecutorKind>,

    #[cfg(feature = "balloon")]
    #[argh(option, arg_name = "N")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// amount to bias balance of memory between host and guest as the balloon inflates, in mib.
    pub balloon_bias_mib: Option<i64>,

    #[cfg(feature = "balloon")]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// path for balloon controller socket.
    pub balloon_control: Option<PathBuf>,

    #[cfg(feature = "balloon")]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// enable page reporting in balloon.
    pub balloon_page_reporting: Option<bool>,

    #[cfg(feature = "balloon")]
    #[argh(option)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// set number of WS bins to use (default = 4).
    pub balloon_ws_num_bins: Option<u8>,

    #[cfg(feature = "balloon")]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// enable working set reporting in balloon.
    pub balloon_ws_reporting: Option<bool>,

    #[argh(option)]
    /// comma separated key=value pairs for setting up battery
    /// device
    /// Possible key values:
    ///     type=goldfish - type of battery emulation, defaults to
    ///     goldfish
    #[merge(strategy = overwrite_option)]
    pub battery: Option<BatteryConfig>,

    #[argh(option)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// path to BIOS/firmware ROM
    pub bios: Option<PathBuf>,

    #[argh(option, short = 'b', arg_name = "PATH[,key=value[,key=value[,...]]]")]
    #[serde(default)]
    #[merge(strategy = append)]
    /// parameters for setting up a block device.
    /// Valid keys:
    ///     path=PATH - Path to the disk image. Can be specified
    ///         without the key as the first argument.
    ///     ro=BOOL - Whether the block should be read-only.
    ///         (default: false)
    ///     root=BOOL - Whether the block device should be mounted
    ///         as the root filesystem. This will add the required
    ///         parameters to the kernel command-line. Can only be
    ///         specified once. (default: false)
    ///     sparse=BOOL - Indicates whether the disk should support
    ///         the discard operation. (default: true)
    ///     block-size=BYTES - Set the reported block size of the
    ///         disk. (default: 512)
    ///     id=STRING - Set the block device identifier to an ASCII
    ///         string, up to 20 characters. (default: no ID)
    ///     direct=BOOL - Use O_DIRECT mode to bypass page cache.
    ///         (default: false)
    ///     async-executor=epoll|uring - set the async executor kind
    ///         to simulate the block device with. This takes
    ///         precedence over the global --async-executor option.
    ///     multiple-workers=BOOL - (Experimental) run multiple
    ///         worker threads in parallel. this option is not
    ///         effective for vhost-user blk device.
    ///         (default: false)
    ///     packed-queue=BOOL - Use packed virtqueue
    ///         in block device. If false, use split virtqueue.
    ///         (default: false)
    ///     bootindex=NUM - An index dictating the order that the
    ///         firmware will consider devices to boot from.
    ///         For example, if bootindex=2, then the BIOS
    ///         will attempt to boot from the current device
    ///         after failing to boot from the device with
    ///         bootindex=1.
    ///     pci-address=ADDR - Preferred PCI address, e.g. "00:01.0".
    block: Vec<DiskOptionWithId>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(switch)]
    #[serde(skip)]
    #[merge(strategy = overwrite_option)]
    /// set a minimum utilization for vCPU threads which will hint to the host scheduler
    /// to ramp up higher frequencies or place vCPU threads on larger cores.
    pub boost_uclamp: Option<bool>,

    #[cfg(target_arch = "x86_64")]
    #[argh(switch)]
    #[merge(strategy = overwrite_option)]
    /// break linux PCI configuration space io probing, to force the use of
    /// mmio access to PCIe ECAM.
    pub break_linux_pci_config_io: Option<bool>,

    /// ratelimit enforced on detected bus locks in guest.
    /// The default value of the bus_lock_ratelimit is 0 per second,
    /// which means no limitation on the guest's bus locks.
    #[cfg(target_arch = "x86_64")]
    #[argh(option)]
    pub bus_lock_ratelimit: Option<u64>,

    #[cfg(feature = "config-file")]
    #[argh(option, arg_name = "CONFIG_FILE", from_str_fn(load_config_file))]
    #[serde(default, deserialize_with = "include_config_file")]
    #[merge(skip)]
    /// path to a JSON configuration file to load.
    ///
    /// The options specified in the file can be overridden or augmented by subsequent uses of
    /// this argument, or other command-line parameters.
    cfg: Vec<Self>,

    #[argh(option, arg_name = "CID")]
    #[serde(skip)] // Deprecated - use `vsock` instead.
    #[merge(strategy = overwrite_option)]
    /// context ID for virtual sockets.
    pub cid: Option<u64>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(
        option,
        arg_name = "unpin_policy=POLICY,unpin_interval=NUM,unpin_limit=NUM,unpin_gen_threshold=NUM"
    )]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// comma separated key=value pairs for setting up coiommu
    /// devices.
    /// Possible key values:
    ///     unpin_policy=lru - LRU unpin policy.
    ///     unpin_interval=NUM - Unpin interval time in seconds.
    ///     unpin_limit=NUM - Unpin limit for each unpin cycle, in
    ///        unit of page count. 0 is invalid.
    ///     unpin_gen_threshold=NUM -  Number of unpin intervals a
    ///        pinned page must be busy for to be aged into the
    ///        older which is less frequently checked generation.
    pub coiommu: Option<devices::CoIommuParameters>,

    #[argh(option, default = "true")]
    #[merge(strategy = overwrite)]
    #[serde(default = "bool_default_true")]
    /// protect VM threads from hyperthreading-based attacks by scheduling them on different cores.
    /// Enabled by default, and required for per_vm_core_scheduling.
    pub core_scheduling: bool,

    #[argh(option, arg_name = "CPUSET", from_str_fn(parse_cpu_affinity))]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// comma-separated list of CPUs or CPU ranges to run VCPUs on (e.g. 0,1-3,5)
    /// or colon-separated list of assignments of guest to host CPU assignments (e.g. 0=0:1=1:2=2)
    /// (default: no mask)
    pub cpu_affinity: Option<VcpuAffinity>,

    #[argh(
        option,
        arg_name = "CPU=CAP[,CPU=CAP[,...]]",
        from_str_fn(parse_cpu_btreemap_u32)
    )]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// set the relative capacity of the given CPU (default: no capacity)
    pub cpu_capacity: Option<BTreeMap<usize, u32>>, // CPU index -> capacity

    #[argh(option, arg_name = "CPUSET")]
    #[serde(skip)] // Deprecated - use `cpu clusters=[...]` instead.
    #[merge(strategy = append)]
    /// group the given CPUs into a cluster (default: no clusters)
    pub cpu_cluster: Vec<CpuSet>,

    #[cfg(all(
        any(target_arch = "arm", target_arch = "aarch64"),
        any(target_os = "android", target_os = "linux")
    ))]
    #[argh(
        option,
        arg_name = "CPU=FREQS[,CPU=FREQS[,...]]",
        from_str_fn(parse_cpu_frequencies)
    )]
    #[serde(skip)]
    #[merge(strategy = overwrite_option)]
    /// set the list of frequencies in KHz for the given CPU (default: no frequencies).
    /// In the event that the user specifies a frequency (after normalizing for cpu_capacity)
    /// that results in a performance point that goes below the lowest frequency that the pCPU can
    /// support, the virtual cpufreq device will actively throttle the vCPU to deliberately slow
    /// its performance to match the guest's request.
    pub cpu_frequencies_khz: Option<BTreeMap<usize, Vec<u32>>>, // CPU index -> frequencies

    #[argh(
        option,
        arg_name = "CPU=RATIO[,CPU=RATIO[,...]]",
        from_str_fn(parse_cpu_btreemap_u32)
    )]
    #[serde(skip)]
    #[merge(strategy = overwrite_option)]
    /// set the instructions per cycle (IPC) performance of the vCPU relative to the pCPU it is
    /// affined to normalized to 1024. Defaults to 1024 which represents the baseline performance
    /// of the pCPU, setting the vCPU to 1024 means it will match the per cycle performance of the
    /// pCPU.  This ratio determines how quickly the same workload will complete on the vCPU
    /// compared to the pCPU. Ex. Setting the ratio to 512 will result in the task taking twice as
    /// long if it were set to 1024 given the same frequency. Conversely, using a value > 1024 will
    /// result in faster per cycle perf relative to the pCPU with some important limitations. In
    /// combination with virtual frequencies defined with "cpu_frequencies_khz", performance points
    /// with vCPU frequencies * vCPU IPC > pCPU@FMax * 1024 will not be properly supported.
    pub cpu_ipc_ratio: Option<BTreeMap<usize, u32>>, // CPU index -> ipc_ratio

    #[argh(option, short = 'c')]
    #[merge(strategy = overwrite_option)]
    /// cpu parameters.
    /// Possible key values:
    ///     num-cores=NUM - number of VCPUs. (default: 1)
    ///     clusters=[[CLUSTER],...] - CPU clusters (default: None)
    ///       Each CLUSTER is a set containing a list of CPUs
    ///       that should belong to the same cluster. Individual
    ///       CPU ids or ranges can be specified, comma-separated.
    ///       Examples:
    ///       clusters=[[0],[1],[2],[3]] - creates 4 clusters, one
    ///         for each specified core.
    ///       clusters=[[0-3]] - creates a cluster for cores 0 to 3
    ///         included.
    ///       clusters=[[0,2],[1,3],[4-7,12]] - creates one cluster
    ///         for cores 0 and 2, another one for cores 1 and 3,
    ///         and one last for cores 4, 5, 6, 7 and 12.
    ///     core-types=[atom=[CPUSET],core=[CPUSET]] - Hybrid core
    ///       types. (default: None)
    ///       Set the type of virtual hybrid CPUs. Currently
    ///       supports Intel Atom and Intel Core cpu types.
    ///       Examples:
    ///       core-types=[atom=[0,1],core=[2,3]] - set vCPU 0 and
    ///       vCPU 1 as intel Atom type, also set vCPU 2 and vCPU 3
    ///       as intel Core type.
    ///     boot-cpu=NUM - Select vCPU to boot from. (default: 0) (aarch64 only)
    ///     freq_domains=[[FREQ_DOMAIN],...] - CPU freq_domains (default: None) (aarch64 only)
    ///       Usage is identical to clusters, each FREQ_DOMAIN is a set containing a
    ///       list of CPUs that should belong to the same freq_domain. Individual
    ///       CPU ids or ranges can be specified, comma-separated.
    ///       Examples:
    ///       freq_domains=[[0],[1],[2],[3]] - creates 4 freq_domains, one
    ///         for each specified core.
    ///       freq_domains=[[0-3]] - creates a freq_domain for cores 0 to 3
    ///         included.
    ///       freq_domains=[[0,2],[1,3],[4-7,12]] - creates one freq_domain
    ///         for cores 0 and 2, another one for cores 1 and 3,
    ///         and one last for cores 4, 5, 6, 7 and 12.
    ///     sve=[enable=bool] - SVE Config. (aarch64 only)
    ///         Examples:
    ///         sve=[enable=true] - Enables SVE on device. Will fail is SVE unsupported.
    ///         default value = false.
    pub cpus: Option<CpuOptions>,

    #[cfg(feature = "crash-report")]
    #[argh(option, arg_name = "\\\\.\\pipe\\PIPE_NAME")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// the crash handler ipc pipe name.
    pub crash_pipe_name: Option<String>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// don't set VCPUs real-time until make-rt command is run
    pub delay_rt: Option<bool>,

    #[argh(option, arg_name = "PATH[,filter]")]
    #[serde(default)]
    #[merge(strategy = append)]
    /// path to device tree overlay binary which will be applied to the base guest device tree
    /// Parameters:
    ///    filter - only apply device tree nodes which belong to a VFIO device
    pub device_tree_overlay: Vec<DtboOption>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// run all devices in one, non-sandboxed process
    pub disable_sandbox: Option<bool>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// disable INTx in virtio devices
    pub disable_virtio_intx: Option<bool>,

    #[argh(option, short = 'd', arg_name = "PATH[,key=value[,key=value[,...]]]")]
    #[serde(skip)] // Deprecated - use `block` instead.
    #[merge(strategy = append)]
    // (DEPRECATED): Use `block` instead.
    /// path to a disk image followed by optional comma-separated
    /// options.
    /// Valid keys:
    ///    sparse=BOOL - Indicates whether the disk should support
    ///        the discard operation (default: true)
    ///    block_size=BYTES - Set the reported block size of the
    ///        disk (default: 512)
    ///    id=STRING - Set the block device identifier to an ASCII
    ///        string, up to 20 characters (default: no ID)
    ///    o_direct=BOOL - Use O_DIRECT mode to bypass page cache"
    disk: Vec<DiskOptionWithId>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// capture keyboard input from the display window
    pub display_window_keyboard: Option<bool>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// capture keyboard input from the display window
    pub display_window_mouse: Option<bool>,

    #[cfg(feature = "config-file")]
    #[argh(option, arg_name = "CONFIG_FILE")]
    #[serde(skip)]
    #[merge(skip)]
    /// path to a JSON configuration file to write the current configuration.
    dump_cfg: Option<PathBuf>,

    #[argh(option, long = "dump-device-tree-blob", arg_name = "FILE")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// dump generated device tree as a DTB file
    pub dump_device_tree_blob: Option<PathBuf>,

    #[argh(
        option,
        arg_name = "CPU=DYN_PWR[,CPU=DYN_PWR[,...]]",
        from_str_fn(parse_cpu_btreemap_u32)
    )]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// pass power modeling param from to guest OS; scalar coefficient used in conjuction with
    /// voltage and frequency for calculating power; in units of uW/MHz/^2
    pub dynamic_power_coefficient: Option<BTreeMap<usize, u32>>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// enable the fw_cfg device. If enabled, fw_cfg will automatically produce firmware
    /// configuration files containing such information as bootorder and the memory location of
    /// rsdp. If --fw-cfg is specified (see below), there is no need for this argument.
    pub enable_fw_cfg: Option<bool>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// expose HWP feature to the guest
    pub enable_hwp: Option<bool>,

    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// path to an event device node. The device will be grabbed (unusable from the host) and made
    /// available to the guest with the same configuration it shows on the host
    pub evdev: Vec<PathBuf>,

    #[cfg(windows)]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// gather and display statistics on Vm Exits and Bus Reads/Writes.
    pub exit_stats: Option<bool>,

    #[argh(option)]
    #[serde(skip)]
    #[merge(strategy = overwrite)]
    /// where the FDT is placed in memory.
    ///
    /// On x86_64, no effect.
    ///
    /// On aarch64, defaults to `end` for kernel payloads and to `start` for BIOS payloads.
    ///
    /// On riscv64, defaults to `after-payload`.
    pub fdt_position: Option<FdtPosition>,

    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    #[argh(option)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// allow FF-A protocol for this vm. Currently only supported option is --guest-ffa=auto
    pub ffa: Option<FfaConfig>,

    #[argh(
        option,
        arg_name = "addr=NUM,size=SIZE,path=PATH[,offset=NUM][,rw][,sync]"
    )]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// map the given file into guest memory at the specified
    /// address.
    /// Parameters (addr, size, path are required):
    ///     addr=NUM - guest physical address to map at
    ///     size=NUM - amount of memory to map
    ///     path=PATH - path to backing file/device to map
    ///     offset=NUM - offset in backing file (default 0)
    ///     rw - make the mapping writable (default readonly)
    ///     sync - open backing file with O_SYNC
    ///     align - whether to adjust addr and size to page
    ///        boundaries implicitly
    ///     ram - whether mapping to a RAM or MMIO region. defaults to MMIO
    pub file_backed_mapping: Vec<FileBackedMappingParameters>,

    #[cfg(target_arch = "x86_64")]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// force use of a calibrated TSC cpuid leaf (0x15) even if the hypervisor
    /// doesn't require one.
    pub force_calibrated_tsc_leaf: Option<bool>,

    #[argh(option, arg_name = "name=NAME,(path=PATH|string=STRING)")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// comma separated key=value pairs to specify data to pass to
    /// fw_cfg.
    /// Possible key values:
    ///     name - Name of the file in fw_cfg that will
    ///      be associated with provided data
    ///     path - Path to data that will be included in
    ///      fw_cfg under name
    ///     string - Alternative to path, data to be
    ///      included in fw_cfg under name
    pub fw_cfg: Vec<FwCfgParameters>,

    #[cfg(feature = "gdb")]
    #[argh(option, arg_name = "PORT")]
    #[merge(strategy = overwrite_option)]
    /// (EXPERIMENTAL) gdb on the given port
    pub gdb: Option<u32>,

    #[cfg(feature = "gpu")]
    #[argh(option)]
    // Although `gpu` is a vector, we are currently limited to a single GPU device due to the
    // resource bridge and interaction with other video devices. We do use a vector so the GPU
    // device can be specified like other device classes in the configuration file, and because we
    // hope to lift this limitation eventually.
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// (EXPERIMENTAL) Comma separated key=value pairs for setting
    /// up a virtio-gpu device
    /// Possible key values:
    ///     backend=(2d|virglrenderer|gfxstream) - Which backend to
    ///        use for virtio-gpu (determining rendering protocol)
    ///     max-num-displays=INT - The maximum number of concurrent
    ///        virtual displays in this VM. This must not exceed
    ///        VIRTIO_GPU_MAX_SCANOUTS (i.e. 16).
    ///     displays=[[GpuDisplayParameters]] - The list of virtual
    ///        displays to create when booting this VM. Displays may
    ///        be hotplugged after booting. See the possible key
    ///        values for GpuDisplayParameters in the section below.
    ///     context-types=LIST - The list of supported context
    ///       types, separated by ':' (default: no contexts enabled)
    ///     width=INT - The width of the virtual display connected
    ///        to the virtio-gpu.
    ///        Deprecated - use `displays` instead.
    ///     height=INT - The height of the virtual display
    ///        connected to the virtio-gpu.
    ///        Deprecated - use `displays` instead.
    ///     egl[=true|=false] - If the backend should use a EGL
    ///        context for rendering.
    ///     glx[=true|=false] - If the backend should use a GLX
    ///        context for rendering.
    ///     surfaceless[=true|=false] - If the backend should use a
    ///         surfaceless context for rendering.
    ///     vulkan[=true|=false] - If the backend should support
    ///        vulkan
    ///     wsi=vk - If the gfxstream backend should use the Vulkan
    ///        swapchain to draw on a window
    ///     cache-path=PATH - The path to the virtio-gpu device
    ///        shader cache.
    ///     cache-size=SIZE - The maximum size of the shader cache.
    ///     pci-address=ADDR - The PCI bus, device, and function
    ///        numbers, e.g. "00:01.0"
    ///     pci-bar-size=SIZE - The size for the PCI BAR in bytes
    ///        (default 8gb).
    ///     implicit-render-server[=true|=false] - If the render
    ///        server process should be allowed to autostart
    ///        (ignored when sandboxing is enabled)
    ///     fixed-blob-mapping[=true|=false] - if gpu memory blobs
    ///        should use fixed address mapping.
    ///
    /// Possible key values for GpuDisplayParameters:
    ///     mode=(borderless_full_screen|windowed[width,height]) -
    ///        Whether to show the window on the host in full
    ///        screen or windowed mode. If not specified, windowed
    ///        mode is used by default. "windowed" can also be
    ///        specified explicitly to use a window size different
    ///        from the default one.
    ///     hidden[=true|=false] - If the display window is
    ///        initially hidden (default: false).
    ///     refresh-rate=INT - Force a specific vsync generation
    ///        rate in hertz on the guest (default: 60)
    ///     dpi=[INT,INT] - The horizontal and vertical DPI of the
    ///        display (default: [320,320])
    ///     horizontal-dpi=INT - The horizontal DPI of the display
    ///        (default: 320)
    ///        Deprecated - use `dpi` instead.
    ///     vertical-dpi=INT - The vertical DPI of the display
    ///        (default: 320)
    ///        Deprecated - use `dpi` instead.
    pub gpu: Vec<FixedGpuParameters>,

    #[cfg(all(unix, feature = "gpu"))]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// move all vGPU threads to this Cgroup (default: nothing moves)
    pub gpu_cgroup_path: Option<PathBuf>,

    #[cfg(feature = "gpu")]
    #[argh(option)]
    #[serde(skip)] // TODO(b/255223604). Deprecated - use `gpu` instead.
    #[merge(strategy = append)]
    /// (EXPERIMENTAL) Comma separated key=value pairs for setting
    /// up a display on the virtio-gpu device. See comments for `gpu`
    /// for possible key values of GpuDisplayParameters.
    pub gpu_display: Vec<FixedGpuDisplayParameters>,

    #[cfg(all(unix, feature = "gpu"))]
    #[argh(option)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// (EXPERIMENTAL) Comma separated key=value pairs for setting
    /// up a render server for the virtio-gpu device
    /// Possible key values:
    ///     path=PATH - The path to the render server executable.
    ///     cache-path=PATH - The path to the render server shader
    ///         cache.
    ///     cache-size=SIZE - The maximum size of the shader cache
    ///     foz-db-list-path=PATH - The path to GPU foz db list
    ///         file for dynamically loading RO caches.
    pub gpu_render_server: Option<GpuRenderServerParameters>,

    #[cfg(all(unix, feature = "gpu"))]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// move all vGPU server threads to this Cgroup (default: nothing moves)
    pub gpu_server_cgroup_path: Option<PathBuf>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// use mirror cpu topology of Host for Guest VM, also copy some cpu feature to Guest VM
    pub host_cpu_topology: Option<bool>,

    #[cfg(windows)]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// string representation of the host guid in registry format, for namespacing vsock
    /// connections.
    pub host_guid: Option<String>,

    #[cfg(all(unix, feature = "net"))]
    #[argh(option, arg_name = "IP")]
    #[serde(skip)] // Deprecated - use `net` instead.
    #[merge(strategy = overwrite_option)]
    /// IP address to assign to host tap interface
    pub host_ip: Option<std::net::Ipv4Addr>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// advise the kernel to use Huge Pages for guest memory mappings
    pub hugepages: Option<bool>,

    /// hypervisor backend
    #[argh(option)]
    #[merge(strategy = overwrite_option)]
    pub hypervisor: Option<HypervisorKind>,

    #[cfg(feature = "balloon")]
    #[argh(option, arg_name = "N")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// amount of guest memory outside the balloon at boot in MiB. (default: --mem)
    pub init_mem: Option<u64>,

    #[argh(option, short = 'i', arg_name = "PATH")]
    #[merge(strategy = overwrite_option)]
    /// initial ramdisk to load
    pub initrd: Option<PathBuf>,

    #[argh(option, arg_name = "TYPE[OPTIONS]")]
    #[serde(default)]
    #[merge(strategy = append)]
    /// virtio-input device
    /// TYPE is an input device type, and OPTIONS are key=value
    /// pairs specific to the device type:
    ///     evdev[path=PATH]
    ///     keyboard[path=PATH]
    ///     mouse[path=PATH]
    ///     multi-touch[path=PATH,width=W,height=H,name=N]
    ///     rotary[path=PATH]
    ///     single-touch[path=PATH,width=W,height=H,name=N]
    ///     switches[path=PATH]
    ///     trackpad[path=PATH,width=W,height=H,name=N]
    ///     multi-touch-trackpad[path=PATH,width=W,height=H,name=N]
    /// See <https://crosvm.dev/book/devices/input.html> for more
    /// information.
    pub input: Vec<InputDeviceOption>,

    #[argh(option, arg_name = "kernel|split|userspace")]
    #[merge(strategy = overwrite_option)]
    /// type of interrupt controller emulation. "split" is only available for x86 KVM.
    pub irqchip: Option<IrqChipKind>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// allow to enable ITMT scheduling feature in VM. The success of enabling depends on HWP and
    /// ACPI CPPC support on hardware
    pub itmt: Option<bool>,

    #[argh(positional, arg_name = "KERNEL")]
    #[merge(strategy = overwrite_option)]
    /// bzImage of kernel to run
    pub kernel: Option<PathBuf>,

    #[cfg(windows)]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// forward hypervisor kernel driver logs for this VM to a file.
    pub kernel_log_file: Option<String>,

    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// path to a socket from where to read keyboard input events and write status updates to
    pub keyboard: Vec<PathBuf>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // Deprecated - use `hypervisor` instead.
    #[merge(strategy = overwrite_option)]
    /// path to the KVM device. (default /dev/kvm)
    pub kvm_device: Option<PathBuf>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// disable host swap on guest VM pages. use MADV_REMOVE to handle balloon. requires sandboxing
    pub lock_guest_memory: Option<bool>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// disable host swap on guest VM pages. use MADV_DONTNEED_LOCKED to handle balloon. requires
    /// 5.18+ kernel
    pub lock_guest_memory_dontneed: Option<bool>,

    #[cfg(windows)]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// redirect logs to the supplied log file at PATH rather than stderr. For multi-process mode,
    /// use --logs-directory instead
    pub log_file: Option<String>,

    #[cfg(windows)]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// path to the logs directory used for crosvm processes. Logs will be sent to stderr if unset,
    /// and stderr/stdout will be uncaptured
    pub logs_directory: Option<String>,

    #[cfg(all(unix, feature = "net"))]
    #[argh(option, arg_name = "MAC", long = "mac")]
    #[serde(skip)] // Deprecated - use `net` instead.
    #[merge(strategy = overwrite_option)]
    /// MAC address for VM
    pub mac_address: Option<net_util::MacAddress>,

    #[cfg(all(unix, feature = "media", feature = "video-decoder"))]
    #[argh(option, arg_name = "[backend]")]
    #[serde(default)]
    #[merge(strategy = append)]
    /// add a virtio-media adapter device.
    pub media_decoder: Vec<VideoDeviceConfig>,

    #[argh(option, short = 'm', arg_name = "N")]
    #[merge(strategy = overwrite_option)]
    /// memory parameters.
    /// Possible key values:
    ///     size=NUM - amount of guest memory in MiB. (default: 256)
    pub mem: Option<MemOptions>,

    #[argh(option, from_str_fn(parse_mmio_address_range))]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// MMIO address ranges
    pub mmio_address_range: Option<Vec<AddressRange>>,

    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// path to a socket from where to read mouse input events and write status updates to
    pub mouse: Vec<PathBuf>,

    #[cfg(target_arch = "aarch64")]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// enable the Memory Tagging Extension in the guest
    pub mte: Option<bool>,

    #[argh(
        option,
        arg_name = "[path=]PATH[,width=WIDTH][,height=HEIGHT][,name=NAME]",
        from_str_fn(parse_touch_device_option)
    )]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// path to a socket from where to read multi touch input events (such as those from a
    /// touchscreen) and write status updates to, optionally followed by width and height (defaults
    /// to 800x1280) and a name for the input device
    pub multi_touch: Vec<TouchDeviceOption>,

    #[argh(option)]
    #[merge(strategy = overwrite_option)]
    /// optional name for the VM. This is used as the name of the crosvm
    /// process which is helpful to distinguish multiple crosvm processes.
    /// A name longer than 15 bytes is truncated on Linux-like OSes. This
    /// is no-op on Windows and MacOS at the moment.
    pub name: Option<String>,

    #[cfg(all(unix, feature = "net"))]
    #[argh(
        option,
        arg_name = "(tap-name=TAP_NAME,mac=MAC_ADDRESS|tap-fd=TAP_FD,mac=MAC_ADDRESS|host-ip=IP,netmask=NETMASK,mac=MAC_ADDRESS),vhost-net=VHOST_NET,vq-pairs=N,pci-address=ADDR"
    )]
    #[serde(default)]
    #[merge(strategy = append)]
    /// comma separated key=value pairs for setting up a network
    /// device.
    /// Possible key values:
    ///   (
    ///      tap-name=STRING - name of a configured persistent TAP
    ///                          interface to use for networking.
    ///      mac=STRING      - MAC address for VM. [Optional]
    ///    OR
    ///      tap-fd=INT      - File descriptor for configured tap
    ///                          device.
    ///      mac=STRING      - MAC address for VM. [Optional]
    ///    OR
    ///      (
    ///         host-ip=STRING  - IP address to assign to host tap
    ///                             interface.
    ///       AND
    ///         netmask=STRING  - Netmask for VM subnet.
    ///       AND
    ///         mac=STRING      - MAC address for VM.
    ///      )
    ///   )
    /// AND
    ///   vhost-net
    ///   OR
    ///   vhost-net=[device=/vhost_net/device] - use vhost_net.
    ///                       If the device path is not the default
    ///                       /dev/vhost-net, it can also be
    ///                       specified.
    ///                       Default: false.  [Optional]
    ///   vq-pairs=N      - number of rx/tx queue pairs.
    ///                       Default: 1.      [Optional]
    ///   packed-queue    - use packed queue.
    ///                       If not set or set to false, it will
    ///                       use split virtqueue.
    ///                       Default: false.  [Optional]
    ///   pci-address     - preferred PCI address, e.g. "00:01.0"
    ///                       Default: automatic PCI address assignment. [Optional]
    ///   mrg_rxbuf       - enable VIRTIO_NET_F_MRG_RXBUF feature.
    ///                       If not set or set to false, it will disable this feature.
    ///                       Default: false.  [Optional]
    ///
    /// Either one tap_name, one tap_fd or a triplet of host_ip,
    /// netmask and mac must be specified.
    pub net: Vec<NetParameters>,

    #[cfg(all(unix, feature = "net"))]
    #[argh(option, arg_name = "N")]
    #[serde(skip)] // Deprecated - use `net` instead.
    #[merge(strategy = overwrite_option)]
    /// virtio net virtual queue pairs. (default: 1)
    pub net_vq_pairs: Option<u16>,

    #[cfg(all(unix, feature = "net"))]
    #[argh(option, arg_name = "NETMASK")]
    #[serde(skip)] // Deprecated - use `net` instead.
    #[merge(strategy = overwrite_option)]
    /// netmask for VM subnet
    pub netmask: Option<std::net::Ipv4Addr>,

    #[cfg(feature = "balloon")]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// don't use virtio-balloon device in the guest
    pub no_balloon: Option<bool>,

    #[cfg(target_arch = "x86_64")]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// don't use legacy KBD devices emulation
    pub no_i8042: Option<bool>,

    #[cfg(target_arch = "aarch64")]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// disable Performance Monitor Unit (PMU)
    pub no_pmu: Option<bool>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// don't create RNG device in the guest
    pub no_rng: Option<bool>,

    #[cfg(target_arch = "x86_64")]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// don't use legacy RTC devices emulation
    pub no_rtc: Option<bool>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// don't use SMT in the guest
    pub no_smt: Option<bool>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// don't use usb devices in the guest
    pub no_usb: Option<bool>,

    #[cfg(target_arch = "x86_64")]
    #[argh(option, arg_name = "OEM_STRING")]
    #[serde(skip)] // Deprecated - use `smbios` instead.
    #[merge(strategy = append)]
    /// SMBIOS OEM string values to add to the DMI tables
    pub oem_strings: Vec<String>,

    #[argh(option, short = 'p', arg_name = "PARAMS")]
    #[serde(default)]
    #[merge(strategy = append)]
    /// extra kernel or plugin command line arguments. Can be given more than once
    pub params: Vec<String>,

    #[argh(option)]
    #[serde(default)]
    #[merge(strategy = overwrite_option)]
    /// PCI parameters.
    ///
    /// Possible key values:
    ///     mem=[start=INT,size=INT] - region for non-prefetchable
    ///         PCI device memory below 4G
    ///
    /// Possible key values (aarch64 only):
    ///     cam=[start=INT,size=INT] - region for PCI Configuration
    ///         Access Mechanism
    ///
    /// Possible key values (x86_64 only):
    ///     ecam=[start=INT,size=INT] - region for PCIe Enhanced
    ///         Configuration Access Mechanism
    pub pci: Option<PciConfig>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(option, arg_name = "pci_hotplug_slots")]
    #[serde(default)]
    #[merge(strategy = overwrite_option)]
    /// number of hotplug slot count (default: None)
    pub pci_hotplug_slots: Option<u8>,

    #[cfg(target_arch = "x86_64")]
    #[argh(option, arg_name = "pci_low_mmio_start")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// the pci mmio start address below 4G
    pub pci_start: Option<u64>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// enable per-VM core scheduling intead of the default one (per-vCPU core scheduing) by
    /// making all vCPU threads share same cookie for core scheduling.
    /// This option is no-op on devices that have neither MDS nor L1TF vulnerability
    pub per_vm_core_scheduling: Option<bool>,

    #[argh(
        option,
        arg_name = "path=PATH,[block_size=SIZE]",
        from_str_fn(parse_pflash_parameters)
    )]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// comma-seperated key-value pair for setting up the pflash device, which provides space to
    /// store UEFI variables. block_size defaults to 4K.
    /// [--pflash <path=PATH,[block_size=SIZE]>]
    pub pflash: Option<PflashParameters>,

    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// path to empty directory to use for sandbox pivot root
    pub pivot_root: Option<PathBuf>,

    #[cfg(feature = "plugin")]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// absolute path to plugin process to run under crosvm
    pub plugin: Option<PathBuf>,

    #[cfg(feature = "plugin")]
    #[argh(option, arg_name = "GID:GID:INT")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// supplemental GIDs that should be mapped in plugin jail.  Can be given more than once
    pub plugin_gid_map: Vec<GidMap>,

    #[cfg(feature = "plugin")]
    #[argh(option)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// path to the file listing supplemental GIDs that should be mapped in plugin jail.  Can be
    /// given more than once
    pub plugin_gid_map_file: Option<PathBuf>,

    #[cfg(feature = "plugin")]
    #[argh(option, arg_name = "PATH:PATH:BOOL")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// path to be mounted into the plugin's root filesystem.  Can be given more than once
    pub plugin_mount: Vec<BindMount>,

    #[cfg(feature = "plugin")]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// path to the file listing paths be mounted into the plugin's root filesystem.  Can be given
    /// more than once
    pub plugin_mount_file: Option<PathBuf>,

    #[cfg(feature = "plugin")]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// absolute path to a directory that will become root filesystem for the plugin process.
    pub plugin_root: Option<PathBuf>,

    #[argh(option)]
    #[serde(default)]
    #[merge(strategy = append)]
    /// parameters for setting up a virtio-pmem device.
    /// Valid keys:
    ///     path=PATH - Path to the disk image. Can be specified
    ///         without the key as the first argument.
    ///     ro=BOOL - Whether the pmem device should be read-only.
    ///         (default: false)
    ///     vma-size=BYTES - (Experimental) Size in bytes
    ///        of an anonymous virtual memory area that is
    ///        created to back this device. When this
    ///        option is specified, the disk image path
    ///        is used to name the memory area
    ///     swap-interval-ms=NUM - (Experimental) Interval
    ///        in milliseconds for periodic swap out of
    ///        memory mapping created by this device. 0
    ///        means the memory mapping won't be swapped
    ///        out by crosvm
    pub pmem: Vec<PmemOption>,

    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// (DEPRECATED): Use --pmem instead.
    /// path to a disk image
    pmem_device: Vec<DiskOption>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(
        option,
        arg_name = "PATH[,key=value[,key=value[,...]]]",
        from_str_fn(parse_pmem_ext2_option)
    )]
    #[serde(default)]
    #[merge(strategy = append)]
    /// (EXPERIMENTAL): construct an ext2 file system on a pmem
    /// device from the given directory. The argument is the form of
    /// "PATH[,key=value[,key=value[,...]]]".
    /// Valid keys:
    ///     blocks_per_group=NUM - Number of blocks in a block
    ///       group. (default: 4096)
    ///     inodes_per_group=NUM - Number of inodes in a block
    ///       group. (default: 1024)
    ///     size=BYTES - Size of the memory region allocated by this
    ///       device. A file system will be built on the region. If
    ///       the filesystem doesn't fit within this size, crosvm
    ///       will fail to start with an error.
    ///       The number of block groups in the file system is
    ///       calculated from this value and other given parameters.
    ///       The value of `size` must be larger than (4096 *
    ///        blocks_per_group.) (default: 16777216)
    ///     uid=UID - uid of the mkfs process in the user
    ///       namespace created by minijail. (default: 0)
    ///     gid=GID - gid of the mkfs process in the user
    ///       namespace created by minijail. (default: 0)
    ///     uidmap=UIDMAP - a uid map in the format
    ///       "inner outer count[,inner outer count]". This format
    ///       is same as one for minijail.
    ///       (default: "0 <current euid> 1")
    ///     gidmap=GIDMAP - a gid map in the same format as uidmap
    ///       (default: "0 <current egid> 1")
    pub pmem_ext2: Vec<PmemExt2Option>,

    #[cfg(feature = "process-invariants")]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// shared read-only memory address for a serialized EmulatorProcessInvariants proto
    pub process_invariants_handle: Option<u64>,

    #[cfg(feature = "process-invariants")]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// size of the serialized EmulatorProcessInvariants proto pointed at by
    /// process-invariants-handle
    pub process_invariants_size: Option<usize>,

    #[cfg(windows)]
    #[argh(option)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// product channel
    pub product_channel: Option<String>,

    #[cfg(windows)]
    #[argh(option)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// the product name for file paths.
    pub product_name: Option<String>,

    #[cfg(windows)]
    #[argh(option)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// product version
    pub product_version: Option<String>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// prevent host access to guest memory
    pub protected_vm: Option<bool>,

    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// (EXPERIMENTAL/FOR DEBUGGING) Use custom VM firmware to run in protected mode
    pub protected_vm_with_firmware: Option<PathBuf>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// (EXPERIMENTAL) prevent host access to guest memory, but don't use protected VM firmware
    protected_vm_without_firmware: Option<bool>,

    #[argh(option, arg_name = "path=PATH,size=SIZE")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// path to pstore buffer backend file followed by size
    ///     [--pstore <path=PATH,size=SIZE>]
    pub pstore: Option<Pstore>,

    #[cfg(feature = "pvclock")]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// enable virtio-pvclock.
    /// Only available when crosvm is built with feature 'pvclock'.
    pub pvclock: Option<bool>,

    #[argh(option, long = "restore", arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// path of the snapshot that is used to restore the VM on startup.
    pub restore: Option<PathBuf>,

    #[argh(option, arg_name = "PATH[,key=value[,key=value[,...]]]", short = 'r')]
    #[serde(skip)] // Deprecated - use `block` instead.
    #[merge(strategy = overwrite_option)]
    // (DEPRECATED): Use `block` instead.
    /// path to a disk image followed by optional comma-separated
    /// options.
    /// Valid keys:
    ///     sparse=BOOL - Indicates whether the disk should support
    ///         the discard operation (default: true)
    ///     block_size=BYTES - Set the reported block size of the
    ///        disk (default: 512)
    ///     id=STRING - Set the block device identifier to an ASCII
    ///     string, up to 20 characters (default: no ID)
    ///     o_direct=BOOL - Use O_DIRECT mode to bypass page cache
    root: Option<DiskOptionWithId>,

    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// path to a socket from where to read rotary input events and write status updates to
    pub rotary: Vec<PathBuf>,

    #[argh(option, arg_name = "CPUSET")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// comma-separated list of CPUs or CPU ranges to run VCPUs on. (e.g. 0,1-3,5) (default: none)
    pub rt_cpus: Option<CpuSet>,

    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// (DEPRECATED): Use --pmem instead.
    /// path to a writable disk image
    rw_pmem_device: Vec<DiskOption>,

    #[argh(option, arg_name = "PATH[,key=value[,key=value[,...]]]")]
    #[serde(skip)] // Deprecated - use `block` instead.
    #[merge(strategy = append)]
    // (DEPRECATED): Use `block` instead.
    /// path to a read-write disk image followed by optional
    /// comma-separated options.
    /// Valid keys:
    ///     sparse=BOOL - Indicates whether the disk should support
    ///        the discard operation (default: true)
    ///     block_size=BYTES - Set the reported block size of the
    ///        disk (default: 512)
    ///     id=STRING - Set the block device identifier to an ASCII
    ///       string, up to 20 characters (default: no ID)
    ///     o_direct=BOOL - Use O_DIRECT mode to bypass page cache
    rwdisk: Vec<DiskOptionWithId>,

    #[argh(option, arg_name = "PATH[,key=value[,key=value[,...]]]")]
    #[serde(skip)] // Deprecated - use `block` instead.
    #[merge(strategy = overwrite_option)]
    // (DEPRECATED) Use `block` instead.
    /// path to a read-write root disk image followed by optional
    /// comma-separated options.
    /// Valid keys:
    ///     sparse=BOOL - Indicates whether the disk should support
    ///       the discard operation (default: true)
    ///     block_size=BYTES - Set the reported block size of the
    ///        disk (default: 512)
    ///     id=STRING - Set the block device identifier to an ASCII
    ///        string, up to 20 characters (default: no ID)
    ///     o_direct=BOOL - Use O_DIRECT mode to bypass page cache
    rwroot: Option<DiskOptionWithId>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// set Low Power S0 Idle Capable Flag for guest Fixed ACPI
    /// Description Table, additionally use enhanced crosvm suspend and resume
    /// routines to perform full guest suspension/resumption
    pub s2idle: Option<bool>,

    #[argh(option, arg_name = "PATH[,key=value[,key=value[,...]]]")]
    #[serde(default)]
    #[merge(strategy = append)]
    /// (EXPERIMENTAL) parameters for setting up a SCSI disk.
    /// Valid keys:
    ///     path=PATH - Path to the disk image. Can be specified
    ///         without the key as the first argument.
    ///     block_size=BYTES - Set the reported block size of the
    ///        disk (default: 512)
    ///     ro=BOOL - Whether the block should be read-only.
    ///         (default: false)
    ///     root=BOOL - Whether the scsi device should be mounted
    ///         as the root filesystem. This will add the required
    ///         parameters to the kernel command-line. Can only be
    ///         specified once. (default: false)
    // TODO(b/300580119): Add O_DIRECT and sparse file support.
    scsi_block: Vec<ScsiOption>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// instead of seccomp filter failures being fatal, they will be logged instead
    pub seccomp_log_failures: Option<bool>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// path to seccomp .policy files
    pub seccomp_policy_dir: Option<PathBuf>,

    #[argh(
        option,
        arg_name = "type=TYPE,[hardware=HW,name=NAME,num=NUM,path=PATH,input=PATH,console,earlycon,stdin,pci-address=ADDR]",
        from_str_fn(parse_serial_options)
    )]
    #[serde(default)]
    #[merge(strategy = append)]
    /// comma separated key=value pairs for setting up serial
    /// devices. Can be given more than once.
    /// Possible key values:
    ///     type=(stdout,syslog,sink,file) - Where to route the
    ///        serial device.
    ///        Platform-specific options:
    ///        On Unix: 'unix' (datagram) and 'unix-stream' (stream)
    ///        On Windows: 'namedpipe'
    ///     hardware=(serial,virtio-console,debugcon) - Which type of
    ///        serial hardware to emulate. Defaults to 8250 UART
    ///        (serial).
    ///     name=NAME - Console Port Name, used for virtio-console
    ///        as a tag for identification within the guest.
    ///     num=(1,2,3,4) - Serial Device Number. If not provided,
    ///        num will default to 1.
    ///     debugcon_port=PORT - Port for the debugcon device to
    ///        listen to. Defaults to 0x402, which is what OVMF
    ///        expects.
    ///     path=PATH - The path to the file to write to when
    ///        type=file
    ///     input=PATH - The path to the file to read from when not
    ///        stdin
    ///     input-unix-stream - (Unix-only) Whether to use the given
    ///        Unix stream socket for input as well as output.
    ///        This flag is only valid when type=unix-stream and
    ///        the socket path is specified with path=.
    ///        Can't be passed when input is specified.
    ///     console - Use this serial device as the guest console.
    ///        Will default to first serial port if not provided.
    ///     earlycon - Use this serial device as the early console.
    ///        Can only be given once.
    ///     stdin - Direct standard input to this serial device.
    ///        Can only be given once. Will default to first serial
    ///        port if not provided.
    ///     pci-address - Preferred PCI address, e.g. "00:01.0".
    ///     max-queue-sizes=[uint,uint] - Max size of each virtio
    ///        queue. Only applicable when hardware=virtio-console.
    pub serial: Vec<SerialParameters>,

    #[cfg(windows)]
    #[argh(option, arg_name = "PIPE_NAME")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// the service ipc pipe name. (Prefix \\\\.\\pipe\\ not needed.
    pub service_pipe_name: Option<String>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(
        option,
        arg_name = "PATH:TAG[:type=TYPE:writeback=BOOL:timeout=SECONDS:uidmap=UIDMAP:gidmap=GIDMAP:cache=CACHE:dax=BOOL,posix_acl=BOOL]"
    )]
    // TODO(b/218223240) add Deserialize implementation for SharedDir so it can be supported by the
    // config file.
    #[serde(skip)]
    #[merge(strategy = append)]
    /// colon-separated options for configuring a directory to be
    /// shared with the VM. The first field is the directory to be
    /// shared and the second field is the tag that the VM can use
    /// to identify the device. The remaining fields are key=value
    /// pairs that may appear in any order.
    ///  Valid keys are:
    ///     type=(p9, fs) - Indicates whether the directory should
    ///        be shared via virtio-9p or virtio-fs (default: p9).
    ///     uidmap=UIDMAP - The uid map to use for the device's
    ///        jail in the format "inner outer
    ///        count[,inner outer count]"
    ///        (default: 0 <current euid> 1).
    ///     gidmap=GIDMAP - The gid map to use for the device's
    ///        jail in the format "inner outer
    ///        count[,inner outer count]"
    ///        (default: 0 <current egid> 1).
    ///     cache=(never, auto, always) - Indicates whether the VM
    ///        can cache the contents of the shared directory
    ///        (default: auto).  When set to "auto" and the type
    ///        is "fs", the VM will use close-to-open consistency
    ///        for file contents.
    ///     timeout=SECONDS - How long the VM should consider file
    ///        attributes and directory entries to be valid
    ///        (default: 5).  If the VM has exclusive access to the
    ///        directory, then this should be a large value.  If
    ///        the directory can be modified by other processes,
    ///        then this should be 0.
    ///     writeback=BOOL - Enables writeback caching
    ///        (default: false).  This is only safe to do when the
    ///        VM has exclusive access to the files in a directory.
    ///        Additionally, the server should have read
    ///        permission for all files as the VM may issue read
    ///        requests even for files that are opened write-only.
    ///     dax=BOOL - Enables DAX support.  Enabling DAX can
    ///        improve performance for frequently accessed files
    ///        by mapping regions of the file directly into the
    ///        VM's memory. There is a cost of slightly increased
    ///        latency the first time the file is accessed.  Since
    ///        the mapping is shared directly from the host kernel's
    ///        file cache, enabling DAX can improve performance even
    ///         when the guest cache policy is "Never".  The default
    ///         value for this option is "false".
    ///     posix_acl=BOOL - Indicates whether the shared directory
    ///        supports POSIX ACLs.  This should only be enabled
    ///        when the underlying file system supports POSIX ACLs.
    ///        The default value for this option is "true".
    ///     uid=UID - uid of the device process in the user
    ///        namespace created by minijail. (default: 0)
    ///     gid=GID - gid of the device process in the user
    ///        namespace created by minijail. (default: 0)
    ///     max_dynamic_perm=uint - Indicates maximum number of
    ///        dynamic permissions that the shared directory allows.
    ///         (default: 0). The fuse server will return EPERM
    ///         Error when FS_IOC_SETPERMISSION ioctl is called
    ///         in the device if current dyamic permission path is
    ///         lager or equal to this value.
    ///     max_dynamic_xattr=uint - Indicates maximum number of
    ///        dynamic xattrs that the shared directory allows.
    ///         (default: 0). The fuse server will return EPERM
    ///         Error when FS_IOC_SETPATHXATTR ioctl is called
    ///         in the device if current dyamic permission path is
    ///         lager or equal to this value.
    ///     security_ctx=BOOL - Enables FUSE_SECURITY_CONTEXT
    ///        feature(default: true). This should be set to false
    ///        in case the when the host not allowing write to
    ///        /proc/<pid>/attr/fscreate, or guest directory does
    ///        not care about the security context.
    ///     Options uid and gid are useful when the crosvm process
    ///     has no CAP_SETGID/CAP_SETUID but an identity mapping of
    ///     the current user/group between the VM and the host is
    ///     required. Say the current user and the crosvm process
    ///     has uid 5000, a user can use "uid=5000" and
    ///     "uidmap=5000 5000 1" such that files owned by user
    ///     5000 still appear to be owned by user 5000 in the VM.
    ///     These 2 options are useful only when there is 1 user
    ///     in the VM accessing shared files. If multiple users
    ///     want to access the shared file, gid/uid options are
    ///     useless. It'd be better to create a new user namespace
    ///     and give CAP_SETUID/CAP_SETGID to the crosvm.
    pub shared_dir: Vec<SharedDir>,

    #[cfg(all(unix, feature = "media"))]
    #[argh(switch)]
    #[serde(default)]
    #[merge(strategy = overwrite_option)]
    /// enable the simple virtio-media device, a virtual capture device generating a fixed pattern
    /// for testing purposes.
    pub simple_media_device: Option<bool>,

    #[argh(
        option,
        arg_name = "[path=]PATH[,width=WIDTH][,height=HEIGHT][,name=NAME]",
        from_str_fn(parse_touch_device_option)
    )]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// path to a socket from where to read single touch input events (such as those from a
    /// touchscreen) and write status updates to, optionally followed by width and height (defaults
    /// to 800x1280) and a name for the input device
    pub single_touch: Vec<TouchDeviceOption>,

    #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// redirects slirp network packets to the supplied log file rather than the current directory
    /// as `slirp_capture_packets.pcap`
    pub slirp_capture_file: Option<String>,

    #[cfg(target_arch = "x86_64")]
    #[argh(option, arg_name = "key=val,...")]
    #[serde(default)]
    #[merge(strategy = overwrite_option)]
    /// SMBIOS table configuration (DMI)
    /// The fields are key=value pairs.
    ///  Valid keys are:
    ///     bios-vendor=STRING - BIOS vendor name.
    ///     bios-version=STRING - BIOS version number (free-form string).
    ///     manufacturer=STRING - System manufacturer name.
    ///     product-name=STRING - System product name.
    ///     serial-number=STRING - System serial number.
    ///     uuid=UUID - System UUID.
    ///     oem-strings=[...] - Free-form OEM strings (SMBIOS type 11).
    pub smbios: Option<SmbiosOptions>,

    #[argh(option, short = 's', arg_name = "PATH")]
    #[merge(strategy = overwrite_option)]
    /// path to put the control socket. If PATH is a directory, a name will be generated
    pub socket: Option<PathBuf>,

    #[cfg(feature = "audio")]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// path to the VioS server socket for setting up virtio-snd devices
    pub sound: Option<PathBuf>,

    #[cfg(target_arch = "x86_64")]
    #[argh(switch)]
    #[serde(skip)] // Deprecated - use `irq_chip` instead.
    #[merge(strategy = overwrite_option)]
    /// (EXPERIMENTAL) enable split-irqchip support
    pub split_irqchip: Option<bool>,

    #[argh(
        option,
        arg_name = "DOMAIN:BUS:DEVICE.FUNCTION[,vendor=NUM][,device=NUM][,class=NUM][,subsystem_vendor=NUM][,subsystem_device=NUM][,revision=NUM]"
    )]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// comma-separated key=value pairs for setting up a stub PCI
    /// device that just enumerates. The first option in the list
    /// must specify a PCI address to claim.
    /// Optional further parameters
    ///     vendor=NUM - PCI vendor ID
    ///     device=NUM - PCI device ID
    ///     class=NUM - PCI class (including class code, subclass,
    ///        and programming interface)
    ///     subsystem_vendor=NUM - PCI subsystem vendor ID
    ///     subsystem_device=NUM - PCI subsystem device ID
    ///     revision=NUM - revision
    pub stub_pci_device: Vec<StubPciParameters>,

    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// start a VM with vCPUs and devices suspended
    pub suspended: Option<bool>,

    #[argh(option, long = "swap", arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// enable vmm-swap via an unnamed temporary file on the filesystem which contains the
    /// specified directory.
    pub swap_dir: Option<PathBuf>,

    #[argh(option, arg_name = "N")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// (EXPERIMENTAL) Size of virtio swiotlb buffer in MiB (default: 64 if `--protected-vm` or
    /// `--protected-vm-without-firmware` is present)
    pub swiotlb: Option<u64>,

    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// path to a socket from where to read switch input events and write status updates to
    pub switches: Vec<PathBuf>,

    #[argh(option, arg_name = "TAG")]
    #[serde(skip)] // Deprecated - use `CrosvmCmdlineArgs::syslog_tag` instead.
    #[merge(strategy = overwrite_option)]
    /// when logging to syslog, use the provided tag
    pub syslog_tag: Option<String>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(option)]
    #[serde(skip)] // Deprecated - use `net` instead.
    #[merge(strategy = append)]
    /// file descriptor for configured tap device. A different virtual network card will be added
    /// each time this argument is given
    pub tap_fd: Vec<RawDescriptor>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(option)]
    #[serde(skip)] // Deprecated - use `net` instead.
    #[merge(strategy = append)]
    /// name of a configured persistent TAP interface to use for networking. A different virtual
    /// network card will be added each time this argument is given
    pub tap_name: Vec<String>,

    #[cfg(target_os = "android")]
    #[argh(option, arg_name = "NAME[,...]")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// comma-separated names of the task profiles to apply to all threads in crosvm including the
    /// vCPU threads
    pub task_profiles: Vec<String>,

    #[argh(
        option,
        arg_name = "[path=]PATH[,width=WIDTH][,height=HEIGHT][,name=NAME]",
        from_str_fn(parse_touch_device_option)
    )]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// path to a socket from where to read trackpad input events and write status updates to,
    /// optionally followed by screen width and height (defaults to 800x1280) and a name for the
    /// input device
    pub trackpad: Vec<TouchDeviceOption>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// set MADV_DONTFORK on guest memory
    ///
    /// Intended for use in combination with --protected-vm, where the guest memory can be
    /// dangerous to access. Some systems, e.g. Android, have tools that fork processes and examine
    /// their memory. This flag effectively hides the guest memory from those tools.
    ///
    /// Not compatible with sandboxing.
    pub unmap_guest_memory_on_fork: Option<bool>,

    // Must be `Some` iff `protection_type == ProtectionType::UnprotectedWithFirmware`.
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// (EXPERIMENTAL/FOR DEBUGGING) Use VM firmware, but allow host access to guest memory
    pub unprotected_vm_with_firmware: Option<PathBuf>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(all(unix, feature = "media"))]
    #[argh(option, arg_name = "[device]")]
    #[serde(default)]
    #[merge(strategy = append)]
    /// path to a V4L2 device to expose to the guest using the virtio-media protocol.
    pub v4l2_proxy: Vec<PathBuf>,

    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// move all vCPU threads to this CGroup (default: nothing moves)
    pub vcpu_cgroup_path: Option<PathBuf>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(
        option,
        arg_name = "PATH[,guest-address=<BUS:DEVICE.FUNCTION>][,iommu=viommu|coiommu|pkvm-iommu|off][,dt-symbol=<SYMBOL>]"
    )]
    #[serde(default)]
    #[merge(strategy = append)]
    /// path to sysfs of VFIO device.
    ///     guest-address=<BUS:DEVICE.FUNCTION> - PCI address
    ///        that the device will be assigned in the guest.
    ///        If not specified, the device will be assigned an
    ///        address that mirrors its address in the host.
    ///        Only valid for PCI devices.
    ///     iommu=viommu|coiommu|pkvm-iommu|off - indicates which type of IOMMU
    ///        to use for this device.
    ///     dt-symbol=<SYMBOL> - the symbol that labels the device tree
    ///        node in the device tree overlay file.
    pub vfio: Vec<VfioOption>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// isolate all hotplugged passthrough vfio device behind virtio-iommu
    pub vfio_isolate_hotplug: Option<bool>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // Deprecated - use `vfio` instead.
    #[merge(strategy = append)]
    /// path to sysfs of platform pass through
    pub vfio_platform: Vec<VfioOption>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(switch)]
    #[serde(skip)] // Deprecated - use `net` instead.
    #[merge(strategy = overwrite_option)]
    /// use vhost for networking
    pub vhost_net: Option<bool>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(option, arg_name = "PATH")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// path to the vhost-net device. (default /dev/vhost-net)
    pub vhost_net_device: Option<PathBuf>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    #[argh(switch)]
    #[merge(strategy = overwrite_option)]
    /// use vhost for scmi
    pub vhost_scmi: Option<bool>,

    #[argh(
        option,
        arg_name = "[type=]TYPE,socket=SOCKET_PATH[,max-queue-size=NUM][,pci-address=ADDR]"
    )]
    #[serde(default)]
    #[merge(strategy = append)]
    /// comma separated key=value pairs for connecting to a
    /// vhost-user backend.
    /// Possible key values:
    ///     type=TYPE - Virtio device type (net, block, etc.)
    ///     socket=SOCKET_PATH - Path to vhost-user socket.
    ///     max-queue-size=NUM - Limit maximum queue size (must be a power of two).
    ///     pci-address=ADDR - Preferred PCI address, e.g. "00:01.0".
    pub vhost_user: Vec<VhostUserFrontendOption>,

    #[argh(option)]
    #[serde(skip)]
    #[merge(strategy = overwrite_option)]
    /// number of milliseconds to retry if the socket path is missing or has no listener. Defaults
    /// to no retries.
    pub vhost_user_connect_timeout_ms: Option<u64>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(option, arg_name = "SOCKET_PATH")]
    #[serde(skip)] // Deprecated - use `vsock` instead.
    #[merge(strategy = overwrite_option)]
    /// path to the vhost-vsock device. (default /dev/vhost-vsock)
    pub vhost_vsock_device: Option<PathBuf>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(option, arg_name = "FD")]
    #[serde(skip)] // Deprecated - use `vsock` instead.
    #[merge(strategy = overwrite_option)]
    /// open FD to the vhost-vsock device, mutually exclusive with vhost-vsock-device
    pub vhost_vsock_fd: Option<RawDescriptor>,

    #[cfg(feature = "video-decoder")]
    #[argh(option, arg_name = "[backend]")]
    #[serde(default)]
    #[merge(strategy = append)]
    /// (EXPERIMENTAL) enable virtio-video decoder device
    /// Possible backend values: libvda, ffmpeg, vaapi
    pub video_decoder: Vec<VideoDeviceConfig>,

    #[cfg(feature = "video-encoder")]
    #[argh(option, arg_name = "[backend]")]
    #[serde(default)]
    #[merge(strategy = append)]
    /// (EXPERIMENTAL) enable virtio-video encoder device
    /// Possible backend values: libvda
    pub video_encoder: Vec<VideoDeviceConfig>,

    #[cfg(all(
        any(target_arch = "arm", target_arch = "aarch64"),
        any(target_os = "android", target_os = "linux")
    ))]
    #[argh(switch)]
    #[serde(skip)]
    #[merge(strategy = overwrite_option)]
    /// enable a virtual cpu freq device
    pub virt_cpufreq: Option<bool>,

    #[cfg(all(
        any(target_arch = "arm", target_arch = "aarch64"),
        any(target_os = "android", target_os = "linux")
    ))]
    #[argh(switch)]
    #[serde(skip)]
    #[merge(strategy = overwrite_option)]
    /// enable version of the virtual cpu freq device compatible
    /// with the driver in upstream linux
    pub virt_cpufreq_upstream: Option<bool>,

    #[cfg(feature = "audio")]
    #[argh(
        option,
        arg_name = "[capture=true,backend=BACKEND,num_output_devices=1,\
        num_input_devices=1,num_output_streams=1,num_input_streams=1]"
    )]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// comma separated key=value pairs for setting up virtio snd
    /// devices.
    /// Possible key values:
    ///     capture=(false,true) - Disable/enable audio capture.
    ///         Default is false.
    ///     backend=(null,file,[cras]) - Which backend to use for
    ///         virtio-snd.
    ///     client_type=(crosvm,arcvm,borealis) - Set specific
    ///         client type for cras backend. Default is crosvm.
    ///     socket_type=(legacy,unified) Set specific socket type
    ///         for cras backend. Default is unified.
    ///     playback_path=STR - Set directory of output streams
    ///         for file backend.
    ///     playback_size=INT - Set size of the output streams
    ///         from file backend.
    ///     num_output_devices=INT - Set number of output PCM
    ///         devices.
    ///     num_input_devices=INT - Set number of input PCM devices.
    ///     num_output_streams=INT - Set number of output PCM
    ///         streams per device.
    ///     num_input_streams=INT - Set number of input PCM streams
    ///         per device.
    pub virtio_snd: Vec<SndParameters>,

    #[argh(option, arg_name = "cid=CID[,device=VHOST_DEVICE]")]
    #[serde(default)]
    #[merge(strategy = overwrite_option)]
    /// add a vsock device. Since a guest can only have one CID,
    /// this option can only be specified once.
    ///     cid=CID - CID to use for the device.
    ///     device=VHOST_DEVICE - path to the vhost-vsock device to
    ///         use (Linux only). Defaults to /dev/vhost-vsock.
    ///     max-queue-sizes=[uint,uint,uint] - Max size of each
    ///         virtio queue.
    pub vsock: Option<VsockConfig>,

    #[cfg(feature = "vtpm")]
    #[argh(switch)]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// enable the virtio-tpm connection to vtpm daemon
    pub vtpm_proxy: Option<bool>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(option, arg_name = "PATH[,name=NAME]", from_str_fn(parse_wayland_sock))]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = append)]
    /// path to the Wayland socket to use. The unnamed one is used for displaying virtual screens.
    /// Named ones are only for IPC
    pub wayland_sock: Vec<(String, PathBuf)>,

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[argh(option, arg_name = "DISPLAY")]
    #[serde(skip)] // TODO(b/255223604)
    #[merge(strategy = overwrite_option)]
    /// X11 display name to use
    pub x_display: Option<String>,
}

#[cfg(feature = "config-file")]
impl RunCommand {
    /// Merge the content of `self` into `self.cfg` if it exists, and return the merged
    /// configuration in which `self.cfg` is empty.
    pub fn squash(mut self) -> Self {
        use merge::Merge;

        std::mem::take(&mut self.cfg)
            .into_iter()
            .map(|c| c.squash())
            .chain(std::iter::once(self))
            .reduce(|mut acc: Self, cfg| {
                acc.merge(cfg);
                acc
            })
            .unwrap()
    }
}

impl TryFrom<RunCommand> for super::config::Config {
    type Error = String;

    fn try_from(cmd: RunCommand) -> Result<Self, Self::Error> {
        // Squash the configuration file (if any) and command-line arguments together.
        #[cfg(feature = "config-file")]
        let cmd = {
            if !cmd.cfg.is_empty() {
                log::warn!(
                    "`--cfg` is still experimental and the configuration file format may change"
                );
            }
            cmd.squash()
        };

        #[cfg(feature = "config-file")]
        if let Some(cfg_path) = &cmd.dump_cfg {
            write_config_file(cfg_path, &cmd)?;
        }

        let mut cfg = Self::default();
        // TODO: we need to factor out some(?) of the checks into config::validate_config

        // Process arguments
        if let Some(p) = cmd.kernel {
            cfg.executable_path = Some(Executable::Kernel(p));
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        if let Some(p) = cmd.kvm_device {
            log::warn!(
                "`--kvm-device <PATH>` is deprecated; use `--hypervisor kvm[device=<PATH>]` instead"
            );

            if cmd.hypervisor.is_some() {
                return Err("cannot specify both --hypervisor and --kvm-device".to_string());
            }

            cfg.hypervisor = Some(crate::crosvm::config::HypervisorKind::Kvm { device: Some(p) });
        }

        cfg.android_fstab = cmd.android_fstab;

        cfg.async_executor = cmd.async_executor;

        #[cfg(target_arch = "x86_64")]
        if let Some(p) = cmd.bus_lock_ratelimit {
            cfg.bus_lock_ratelimit = p;
        }

        cfg.params.extend(cmd.params);

        cfg.core_scheduling = cmd.core_scheduling;
        cfg.per_vm_core_scheduling = cmd.per_vm_core_scheduling.unwrap_or_default();

        // `--cpu` parameters.
        {
            let cpus = cmd.cpus.unwrap_or_default();
            cfg.vcpu_count = cpus.num_cores;
            cfg.boot_cpu = cpus.boot_cpu.unwrap_or_default();
            cfg.cpu_freq_domains = cpus.freq_domains;

            // Only allow deprecated `--cpu-cluster` option only if `--cpu clusters=[...]` is not
            // used.
            cfg.cpu_clusters = match (&cpus.clusters.is_empty(), &cmd.cpu_cluster.is_empty()) {
                (_, true) => cpus.clusters,
                (true, false) => cmd.cpu_cluster,
                (false, false) => {
                    return Err(
                        "cannot specify both --cpu clusters=[...] and --cpu_cluster".to_string()
                    )
                }
            };

            #[cfg(target_arch = "x86_64")]
            if let Some(cpu_types) = cpus.core_types {
                for cpu in cpu_types.atom {
                    if cfg
                        .vcpu_hybrid_type
                        .insert(cpu, CpuHybridType::Atom)
                        .is_some()
                    {
                        return Err(format!("vCPU index must be unique {}", cpu));
                    }
                }
                for cpu in cpu_types.core {
                    if cfg
                        .vcpu_hybrid_type
                        .insert(cpu, CpuHybridType::Core)
                        .is_some()
                    {
                        return Err(format!("vCPU index must be unique {}", cpu));
                    }
                }
            }
            #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
            {
                cfg.sve = cpus.sve;
            }
        }

        cfg.vcpu_affinity = cmd.cpu_affinity;

        if let Some(dynamic_power_coefficient) = cmd.dynamic_power_coefficient {
            cfg.dynamic_power_coefficient = dynamic_power_coefficient;
        }

        if let Some(capacity) = cmd.cpu_capacity {
            cfg.cpu_capacity = capacity;
        }

        #[cfg(all(
            any(target_arch = "arm", target_arch = "aarch64"),
            any(target_os = "android", target_os = "linux")
        ))]
        {
            cfg.virt_cpufreq = cmd.virt_cpufreq.unwrap_or_default();
            cfg.virt_cpufreq_v2 = cmd.virt_cpufreq_upstream.unwrap_or_default();
            if cfg.virt_cpufreq && cfg.virt_cpufreq_v2 {
                return Err("Only one version of virt-cpufreq can be used!".to_string());
            }
            if let Some(frequencies) = cmd.cpu_frequencies_khz {
                cfg.cpu_frequencies_khz = frequencies;
            }
            if let Some(ipc_ratio) = cmd.cpu_ipc_ratio {
                cfg.cpu_ipc_ratio = ipc_ratio;
            }
        }

        cfg.vcpu_cgroup_path = cmd.vcpu_cgroup_path;

        cfg.no_smt = cmd.no_smt.unwrap_or_default();

        if let Some(rt_cpus) = cmd.rt_cpus {
            cfg.rt_cpus = rt_cpus;
        }

        cfg.delay_rt = cmd.delay_rt.unwrap_or_default();

        let mem = cmd.mem.unwrap_or_default();
        cfg.memory = mem.size;

        #[cfg(target_arch = "aarch64")]
        {
            if cmd.mte.unwrap_or_default()
                && !(cmd.pmem.is_empty()
                    && cmd.pmem_device.is_empty()
                    && cmd.pstore.is_none()
                    && cmd.rw_pmem_device.is_empty())
            {
                return Err(
                    "--mte cannot be specified together with --pstore or pmem flags".to_string(),
                );
            }
            cfg.mte = cmd.mte.unwrap_or_default();
            cfg.no_pmu = cmd.no_pmu.unwrap_or_default();
            cfg.swiotlb = cmd.swiotlb;
        }

        #[cfg(all(target_os = "android", target_arch = "aarch64"))]
        {
            cfg.ffa = cmd.ffa;
        }

        cfg.hugepages = cmd.hugepages.unwrap_or_default();

        // `cfg.hypervisor` may have been set by the deprecated `--kvm-device` option above.
        // TODO(b/274817652): remove this workaround when `--kvm-device` is removed.
        if cfg.hypervisor.is_none() {
            cfg.hypervisor = cmd.hypervisor;
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            cfg.lock_guest_memory = cmd.lock_guest_memory.unwrap_or_default();
            cfg.lock_guest_memory_dontneed = cmd.lock_guest_memory_dontneed.unwrap_or_default();
            cfg.boost_uclamp = cmd.boost_uclamp.unwrap_or_default();
        }

        #[cfg(feature = "audio")]
        {
            cfg.sound = cmd.sound;
        }

        for serial_params in cmd.serial {
            super::sys::config::check_serial_params(&serial_params)?;

            let num = serial_params.num;
            let key = (serial_params.hardware, num);

            if cfg.serial_parameters.contains_key(&key) {
                return Err(format!(
                    "serial hardware {} num {}",
                    serial_params.hardware, num,
                ));
            }

            if serial_params.earlycon {
                // Only SerialHardware::Serial supports earlycon= currently.
                match serial_params.hardware {
                    SerialHardware::Serial => {}
                    _ => {
                        return Err(super::config::invalid_value_err(
                            serial_params.hardware.to_string(),
                            String::from("earlycon not supported for hardware"),
                        ));
                    }
                }
                for params in cfg.serial_parameters.values() {
                    if params.earlycon {
                        return Err(format!(
                            "{} device {} already set as earlycon",
                            params.hardware, params.num,
                        ));
                    }
                }
            }

            if serial_params.stdin {
                if let Some(previous_stdin) = cfg.serial_parameters.values().find(|sp| sp.stdin) {
                    return Err(format!(
                        "{} device {} already connected to standard input",
                        previous_stdin.hardware, previous_stdin.num,
                    ));
                }
            }

            cfg.serial_parameters.insert(key, serial_params);
        }

        if !(cmd.root.is_none()
            && cmd.rwroot.is_none()
            && cmd.disk.is_empty()
            && cmd.rwdisk.is_empty())
        {
            log::warn!("Deprecated disk flags such as --[rw]disk or --[rw]root are passed. Use --block instead.");
        }
        // Aggregate all the disks with the expected read-only and root values according to the
        // option they have been passed with.
        let mut disks = cmd
            .root
            .into_iter()
            .map(|mut d| {
                d.disk_option.read_only = true;
                d.disk_option.root = true;
                d
            })
            .chain(cmd.rwroot.into_iter().map(|mut d| {
                d.disk_option.read_only = false;
                d.disk_option.root = true;
                d
            }))
            .chain(cmd.disk.into_iter().map(|mut d| {
                d.disk_option.read_only = true;
                d.disk_option.root = false;
                d
            }))
            .chain(cmd.rwdisk.into_iter().map(|mut d| {
                d.disk_option.read_only = false;
                d.disk_option.root = false;
                d
            }))
            .chain(cmd.block)
            .collect::<Vec<_>>();

        // Sort all our disks by index.
        disks.sort_by_key(|d| d.index);
        cfg.disks = disks.into_iter().map(|d| d.disk_option).collect();

        cfg.scsis = cmd.scsi_block;

        cfg.pmems = cmd.pmem;

        if !cmd.pmem_device.is_empty() || !cmd.rw_pmem_device.is_empty() {
            log::warn!(
                "--pmem-device and --rw-pmem-device are deprecated. Please use --pmem instead."
            );
        }

        // Convert the deprecated `pmem_device` and `rw_pmem_device` into `pmem_devices`.
        for disk_option in cmd.pmem_device.into_iter() {
            cfg.pmems.push(PmemOption {
                path: disk_option.path,
                ro: true, // read-only
                ..PmemOption::default()
            });
        }
        for disk_option in cmd.rw_pmem_device.into_iter() {
            cfg.pmems.push(PmemOption {
                path: disk_option.path,
                ro: false, // writable
                ..PmemOption::default()
            });
        }

        // Find the device to use as the kernel `root=` parameter. There can only be one.
        let virtio_blk_root_devs = cfg
            .disks
            .iter()
            .enumerate()
            .filter(|(_, d)| d.root)
            .map(|(i, d)| (format_disk_letter("/dev/vd", i), d.read_only));

        let virtio_scsi_root_devs = cfg
            .scsis
            .iter()
            .enumerate()
            .filter(|(_, s)| s.root)
            .map(|(i, s)| (format_disk_letter("/dev/sd", i), s.read_only));

        let virtio_pmem_root_devs = cfg
            .pmems
            .iter()
            .enumerate()
            .filter(|(_, p)| p.root)
            .map(|(i, p)| (format!("/dev/pmem{}", i), p.ro));

        let mut root_devs = virtio_blk_root_devs
            .chain(virtio_scsi_root_devs)
            .chain(virtio_pmem_root_devs);
        if let Some((root_dev, read_only)) = root_devs.next() {
            cfg.params.push(format!(
                "root={} {}",
                root_dev,
                if read_only { "ro" } else { "rw" }
            ));

            // If the iterator is not exhausted, the user specified `root=true` on more than one
            // device, which is an error.
            if root_devs.next().is_some() {
                return Err("only one root disk can be specified".to_string());
            }
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            cfg.pmem_ext2 = cmd.pmem_ext2;
        }

        #[cfg(feature = "pvclock")]
        {
            cfg.pvclock = cmd.pvclock.unwrap_or_default();
        }

        #[cfg(windows)]
        {
            #[cfg(feature = "crash-report")]
            {
                cfg.crash_pipe_name = cmd.crash_pipe_name;
            }
            cfg.product_name = cmd.product_name;
            cfg.exit_stats = cmd.exit_stats.unwrap_or_default();
            cfg.host_guid = cmd.host_guid;
            cfg.kernel_log_file = cmd.kernel_log_file;
            cfg.log_file = cmd.log_file;
            cfg.logs_directory = cmd.logs_directory;
            #[cfg(feature = "process-invariants")]
            {
                cfg.process_invariants_data_handle = cmd.process_invariants_handle;

                cfg.process_invariants_data_size = cmd.process_invariants_size;
            }
            #[cfg(windows)]
            {
                cfg.service_pipe_name = cmd.service_pipe_name;
            }
            #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
            {
                cfg.slirp_capture_file = cmd.slirp_capture_file;
            }
            cfg.product_channel = cmd.product_channel;
            cfg.product_version = cmd.product_version;
        }
        cfg.pstore = cmd.pstore;

        cfg.enable_fw_cfg = cmd.enable_fw_cfg.unwrap_or_default();
        cfg.fw_cfg_parameters = cmd.fw_cfg;

        #[cfg(any(target_os = "android", target_os = "linux"))]
        for (name, params) in cmd.wayland_sock {
            if cfg.wayland_socket_paths.contains_key(&name) {
                return Err(format!("wayland socket name already used: '{}'", name));
            }
            cfg.wayland_socket_paths.insert(name, params);
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            cfg.x_display = cmd.x_display;
        }

        cfg.display_window_keyboard = cmd.display_window_keyboard.unwrap_or_default();
        cfg.display_window_mouse = cmd.display_window_mouse.unwrap_or_default();

        cfg.swap_dir = cmd.swap_dir;
        cfg.restore_path = cmd.restore;
        cfg.suspended = cmd.suspended.unwrap_or_default();

        if let Some(mut socket_path) = cmd.socket {
            if socket_path.is_dir() {
                socket_path.push(format!("crosvm-{}.sock", getpid()));
            }
            cfg.socket_path = Some(socket_path);
        }

        cfg.vsock = cmd.vsock;

        // Legacy vsock options.
        if let Some(cid) = cmd.cid {
            if cfg.vsock.is_some() {
                return Err(
                    "`cid` and `vsock` cannot be specified together. Use `vsock` only.".to_string(),
                );
            }

            let legacy_vsock_config = VsockConfig::new(
                cid,
                #[cfg(any(target_os = "android", target_os = "linux"))]
                match (cmd.vhost_vsock_device, cmd.vhost_vsock_fd) {
                    (Some(_), Some(_)) => {
                        return Err(
                            "Only one of vhost-vsock-device vhost-vsock-fd has to be specified"
                                .to_string(),
                        )
                    }
                    (Some(path), None) => Some(path),
                    (None, Some(fd)) => Some(PathBuf::from(format!("/proc/self/fd/{}", fd))),
                    (None, None) => None,
                },
            );

            cfg.vsock = Some(legacy_vsock_config);
        }

        #[cfg(feature = "plugin")]
        {
            use std::fs::File;
            use std::io::BufRead;
            use std::io::BufReader;

            if let Some(p) = cmd.plugin {
                if cfg.executable_path.is_some() {
                    return Err(format!(
                        "A VM executable was already specified: {:?}",
                        cfg.executable_path
                    ));
                }
                cfg.executable_path = Some(Executable::Plugin(p));
            }
            cfg.plugin_root = cmd.plugin_root;
            cfg.plugin_mounts = cmd.plugin_mount;

            if let Some(path) = cmd.plugin_mount_file {
                let file = File::open(path)
                    .map_err(|_| String::from("unable to open `plugin-mount-file` file"))?;
                let reader = BufReader::new(file);
                for l in reader.lines() {
                    let line = l.unwrap();
                    let trimmed_line = line.split_once('#').map_or(&*line, |x| x.0).trim();
                    if !trimmed_line.is_empty() {
                        let mount = parse_plugin_mount_option(trimmed_line)?;
                        cfg.plugin_mounts.push(mount);
                    }
                }
            }

            cfg.plugin_gid_maps = cmd.plugin_gid_map;

            if let Some(path) = cmd.plugin_gid_map_file {
                let file = File::open(path)
                    .map_err(|_| String::from("unable to open `plugin-gid-map-file` file"))?;
                let reader = BufReader::new(file);
                for l in reader.lines() {
                    let line = l.unwrap();
                    let trimmed_line = line.split_once('#').map_or(&*line, |x| x.0).trim();
                    if !trimmed_line.is_empty() {
                        let map = trimmed_line.parse()?;
                        cfg.plugin_gid_maps.push(map);
                    }
                }
            }
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        {
            cfg.vhost_scmi = cmd.vhost_scmi.unwrap_or_default();
        }

        #[cfg(feature = "vtpm")]
        {
            cfg.vtpm_proxy = cmd.vtpm_proxy.unwrap_or_default();
        }

        cfg.virtio_input = cmd.input;

        if !cmd.single_touch.is_empty() {
            log::warn!("`--single-touch` is deprecated; please use `--input single-touch[...]`");
            cfg.virtio_input
                .extend(
                    cmd.single_touch
                        .into_iter()
                        .map(|touch| InputDeviceOption::SingleTouch {
                            path: touch.path,
                            width: touch.width,
                            height: touch.height,
                            name: touch.name,
                        }),
                );
        }

        if !cmd.multi_touch.is_empty() {
            log::warn!("`--multi-touch` is deprecated; please use `--input multi-touch[...]`");
            cfg.virtio_input
                .extend(
                    cmd.multi_touch
                        .into_iter()
                        .map(|touch| InputDeviceOption::MultiTouch {
                            path: touch.path,
                            width: touch.width,
                            height: touch.height,
                            name: touch.name,
                        }),
                );
        }

        if !cmd.trackpad.is_empty() {
            log::warn!("`--trackpad` is deprecated; please use `--input trackpad[...]`");
            cfg.virtio_input
                .extend(
                    cmd.trackpad
                        .into_iter()
                        .map(|trackpad| InputDeviceOption::Trackpad {
                            path: trackpad.path,
                            width: trackpad.width,
                            height: trackpad.height,
                            name: trackpad.name,
                        }),
                );
        }

        if !cmd.mouse.is_empty() {
            log::warn!("`--mouse` is deprecated; please use `--input mouse[...]`");
            cfg.virtio_input.extend(
                cmd.mouse
                    .into_iter()
                    .map(|path| InputDeviceOption::Mouse { path }),
            );
        }

        if !cmd.keyboard.is_empty() {
            log::warn!("`--keyboard` is deprecated; please use `--input keyboard[...]`");
            cfg.virtio_input.extend(
                cmd.keyboard
                    .into_iter()
                    .map(|path| InputDeviceOption::Keyboard { path }),
            )
        }

        if !cmd.switches.is_empty() {
            log::warn!("`--switches` is deprecated; please use `--input switches[...]`");
            cfg.virtio_input.extend(
                cmd.switches
                    .into_iter()
                    .map(|path| InputDeviceOption::Switches { path }),
            );
        }

        if !cmd.rotary.is_empty() {
            log::warn!("`--rotary` is deprecated; please use `--input rotary[...]`");
            cfg.virtio_input.extend(
                cmd.rotary
                    .into_iter()
                    .map(|path| InputDeviceOption::Rotary { path }),
            );
        }

        if !cmd.evdev.is_empty() {
            log::warn!("`--evdev` is deprecated; please use `--input evdev[...]`");
            cfg.virtio_input.extend(
                cmd.evdev
                    .into_iter()
                    .map(|path| InputDeviceOption::Evdev { path }),
            );
        }

        cfg.irq_chip = cmd.irqchip;

        #[cfg(target_arch = "x86_64")]
        if cmd.split_irqchip.unwrap_or_default() {
            if cmd.irqchip.is_some() {
                return Err("cannot use `--irqchip` and `--split-irqchip` together".to_string());
            }

            log::warn!("`--split-irqchip` is deprecated; please use `--irqchip=split`");
            cfg.irq_chip = Some(IrqChipKind::Split);
        }

        cfg.initrd_path = cmd.initrd;

        if let Some(p) = cmd.bios {
            if cfg.executable_path.is_some() {
                return Err(format!(
                    "A VM executable was already specified: {:?}",
                    cfg.executable_path
                ));
            }
            cfg.executable_path = Some(Executable::Bios(p));
        }
        cfg.pflash_parameters = cmd.pflash;

        #[cfg(feature = "video-decoder")]
        {
            cfg.video_dec = cmd.video_decoder;
        }
        #[cfg(feature = "video-encoder")]
        {
            cfg.video_enc = cmd.video_encoder;
        }

        cfg.acpi_tables = cmd.acpi_table;

        cfg.usb = !cmd.no_usb.unwrap_or_default();
        cfg.rng = !cmd.no_rng.unwrap_or_default();

        #[cfg(feature = "balloon")]
        {
            cfg.balloon = !cmd.no_balloon.unwrap_or_default();

            // cfg.balloon_bias is in bytes.
            if let Some(b) = cmd.balloon_bias_mib {
                cfg.balloon_bias = b * 1024 * 1024;
            }

            cfg.balloon_control = cmd.balloon_control;
            cfg.balloon_page_reporting = cmd.balloon_page_reporting.unwrap_or_default();
            cfg.balloon_ws_num_bins = cmd.balloon_ws_num_bins.unwrap_or(4);
            cfg.balloon_ws_reporting = cmd.balloon_ws_reporting.unwrap_or_default();
            cfg.init_memory = cmd.init_mem;
        }

        #[cfg(feature = "audio")]
        {
            cfg.virtio_snds = cmd.virtio_snd;
        }

        #[cfg(feature = "gpu")]
        {
            // Due to the resource bridge, we can only create a single GPU device at the moment.
            if cmd.gpu.len() > 1 {
                return Err("at most one GPU device can currently be created".to_string());
            }
            cfg.gpu_parameters = cmd.gpu.into_iter().map(|p| p.0).take(1).next();
            if !cmd.gpu_display.is_empty() {
                log::warn!("'--gpu-display' is deprecated; please use `--gpu displays=[...]`");
                cfg.gpu_parameters
                    .get_or_insert_with(Default::default)
                    .display_params
                    .extend(cmd.gpu_display.into_iter().map(|p| p.0));
            }

            #[cfg(feature = "android_display")]
            {
                if let Some(gpu_parameters) = &cfg.gpu_parameters {
                    if !gpu_parameters.display_params.is_empty() {
                        cfg.android_display_service = cmd.android_display_service;
                    }
                }
            }

            #[cfg(windows)]
            if let Some(gpu_parameters) = &cfg.gpu_parameters {
                let num_displays = gpu_parameters.display_params.len();
                if num_displays > 1 {
                    return Err(format!(
                        "Only one display is supported (supplied {})",
                        num_displays
                    ));
                }
            }

            #[cfg(any(target_os = "android", target_os = "linux"))]
            {
                cfg.gpu_cgroup_path = cmd.gpu_cgroup_path;
                cfg.gpu_server_cgroup_path = cmd.gpu_server_cgroup_path;
            }
        }

        #[cfg(all(unix, feature = "net"))]
        {
            use devices::virtio::VhostNetParameters;
            use devices::virtio::VHOST_NET_DEFAULT_PATH;

            cfg.net = cmd.net;

            if let Some(vhost_net_device) = &cmd.vhost_net_device {
                let vhost_net_path = vhost_net_device.to_string_lossy();
                log::warn!(
                    "`--vhost-net-device` is deprecated; please use \
                    `--net ...,vhost-net=[device={vhost_net_path}]`"
                );
            }

            let vhost_net_config = if cmd.vhost_net.unwrap_or_default() {
                Some(VhostNetParameters {
                    device: cmd
                        .vhost_net_device
                        .unwrap_or_else(|| PathBuf::from(VHOST_NET_DEFAULT_PATH)),
                })
            } else {
                None
            };

            let vhost_net_msg = match cmd.vhost_net.unwrap_or_default() {
                true => ",vhost-net=true",
                false => "",
            };
            let vq_pairs_msg = match cmd.net_vq_pairs {
                Some(n) => format!(",vq-pairs={}", n),
                None => "".to_string(),
            };

            for tap_name in cmd.tap_name {
                log::warn!(
                    "`--tap-name` is deprecated; please use \
                    `--net tap-name={tap_name}{vhost_net_msg}{vq_pairs_msg}`"
                );
                cfg.net.push(NetParameters {
                    mode: NetParametersMode::TapName {
                        tap_name,
                        mac: None,
                    },
                    vhost_net: vhost_net_config.clone(),
                    vq_pairs: cmd.net_vq_pairs,
                    packed_queue: false,
                    pci_address: None,
                    mrg_rxbuf: false,
                });
            }

            for tap_fd in cmd.tap_fd {
                log::warn!(
                    "`--tap-fd` is deprecated; please use \
                    `--net tap-fd={tap_fd}{vhost_net_msg}{vq_pairs_msg}`"
                );
                cfg.net.push(NetParameters {
                    mode: NetParametersMode::TapFd { tap_fd, mac: None },
                    vhost_net: vhost_net_config.clone(),
                    vq_pairs: cmd.net_vq_pairs,
                    packed_queue: false,
                    pci_address: None,
                    mrg_rxbuf: false,
                });
            }

            if cmd.host_ip.is_some() || cmd.netmask.is_some() || cmd.mac_address.is_some() {
                let host_ip = match cmd.host_ip {
                    Some(host_ip) => host_ip,
                    None => return Err("`host-ip` missing from network config".to_string()),
                };
                let netmask = match cmd.netmask {
                    Some(netmask) => netmask,
                    None => return Err("`netmask` missing from network config".to_string()),
                };
                let mac = match cmd.mac_address {
                    Some(mac) => mac,
                    None => return Err("`mac` missing from network config".to_string()),
                };

                log::warn!(
                    "`--host-ip`, `--netmask`, and `--mac` are deprecated; please use \
                    `--net host-ip={host_ip},netmask={netmask},mac={mac}{vhost_net_msg}{vq_pairs_msg}`"
                );

                cfg.net.push(NetParameters {
                    mode: NetParametersMode::RawConfig {
                        host_ip,
                        netmask,
                        mac,
                    },
                    vhost_net: vhost_net_config,
                    vq_pairs: cmd.net_vq_pairs,
                    packed_queue: false,
                    pci_address: None,
                    mrg_rxbuf: false,
                });
            }

            // The number of vq pairs on a network device shall never exceed the number of vcpu
            // cores. Fix that up if needed.
            for net in &mut cfg.net {
                if let Some(vq_pairs) = net.vq_pairs {
                    if vq_pairs as usize > cfg.vcpu_count.unwrap_or(1) {
                        log::warn!("the number of net vq pairs must not exceed the vcpu count, falling back to single queue mode");
                        net.vq_pairs = None;
                    }
                }
                if net.mrg_rxbuf && net.packed_queue {
                    return Err("mrg_rxbuf and packed_queue together is unsupported".to_string());
                }
            }
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            cfg.shared_dirs = cmd.shared_dir;

            cfg.coiommu_param = cmd.coiommu;

            #[cfg(feature = "gpu")]
            {
                cfg.gpu_render_server_parameters = cmd.gpu_render_server;
            }

            if let Some(d) = cmd.seccomp_policy_dir {
                cfg.jail_config
                    .get_or_insert_with(Default::default)
                    .seccomp_policy_dir = Some(d);
            }

            if cmd.seccomp_log_failures.unwrap_or_default() {
                cfg.jail_config
                    .get_or_insert_with(Default::default)
                    .seccomp_log_failures = true;
            }

            if let Some(p) = cmd.pivot_root {
                cfg.jail_config
                    .get_or_insert_with(Default::default)
                    .pivot_root = p;
            }
        }

        let protection_flags = [
            cmd.protected_vm.unwrap_or_default(),
            cmd.protected_vm_with_firmware.is_some(),
            cmd.protected_vm_without_firmware.unwrap_or_default(),
            cmd.unprotected_vm_with_firmware.is_some(),
        ];

        if protection_flags.into_iter().filter(|b| *b).count() > 1 {
            return Err("Only one protection mode has to be specified".to_string());
        }

        cfg.protection_type = if cmd.protected_vm.unwrap_or_default() {
            ProtectionType::Protected
        } else if cmd.protected_vm_without_firmware.unwrap_or_default() {
            ProtectionType::ProtectedWithoutFirmware
        } else if let Some(p) = cmd.protected_vm_with_firmware {
            if !p.exists() || !p.is_file() {
                return Err(
                    "protected-vm-with-firmware path should be an existing file".to_string()
                );
            }
            cfg.pvm_fw = Some(p);
            ProtectionType::ProtectedWithCustomFirmware
        } else if let Some(p) = cmd.unprotected_vm_with_firmware {
            if !p.exists() || !p.is_file() {
                return Err(
                    "unprotected-vm-with-firmware path should be an existing file".to_string(),
                );
            }
            cfg.pvm_fw = Some(p);
            ProtectionType::UnprotectedWithFirmware
        } else {
            ProtectionType::Unprotected
        };

        if !matches!(cfg.protection_type, ProtectionType::Unprotected) {
            // USB devices only work for unprotected VMs.
            cfg.usb = false;
            // Protected VMs can't trust the RNG device, so don't provide it.
            cfg.rng = false;

            // Balloon is not supported for protected VMs on x86 yet.
            #[cfg(all(feature = "balloon", target_arch = "x86_64"))]
            {
                if cfg.balloon {
                    log::warn!(
                        "Disabling balloon, it is not supported for protected VMs on x86 yet."
                    );
                    cfg.balloon = false;
                    cfg.balloon_control = None;
                    cfg.balloon_page_reporting = false;
                    cfg.balloon_ws_reporting = false;
                }
            }
        }

        cfg.battery_config = cmd.battery;
        #[cfg(all(target_arch = "x86_64", unix))]
        {
            cfg.ac_adapter = cmd.ac_adapter.unwrap_or_default();
        }

        #[cfg(feature = "gdb")]
        {
            if cfg.suspended && cmd.gdb.is_some() {
                return Err("suspended mode not supported with GDB".to_string());
            }
            cfg.gdb = cmd.gdb;
        }

        cfg.host_cpu_topology = cmd.host_cpu_topology.unwrap_or_default();

        cfg.pci_config = cmd.pci.unwrap_or_default();

        #[cfg(target_arch = "x86_64")]
        {
            cfg.break_linux_pci_config_io = cmd.break_linux_pci_config_io.unwrap_or_default();
            cfg.enable_hwp = cmd.enable_hwp.unwrap_or_default();
            cfg.force_s2idle = cmd.s2idle.unwrap_or_default();
            cfg.no_i8042 = cmd.no_i8042.unwrap_or_default();
            cfg.no_rtc = cmd.no_rtc.unwrap_or_default();
            cfg.smbios = cmd.smbios.unwrap_or_default();

            if let Some(pci_start) = cmd.pci_start {
                if cfg.pci_config.mem.is_some() {
                    return Err("--pci-start cannot be used with --pci mem=[...]".to_string());
                }
                log::warn!("`--pci-start` is deprecated; use `--pci mem=[start={pci_start:#?}]");
                cfg.pci_config.mem = Some(MemoryRegionConfig {
                    start: pci_start,
                    size: None,
                });
            }

            if !cmd.oem_strings.is_empty() {
                log::warn!(
                    "`--oem-strings` is deprecated; use `--smbios oem-strings=[...]` instead."
                );
                cfg.smbios.oem_strings.extend_from_slice(&cmd.oem_strings);
            }
        }

        #[cfg(feature = "pci-hotplug")]
        {
            cfg.pci_hotplug_slots = cmd.pci_hotplug_slots;
        }

        cfg.vhost_user = cmd.vhost_user;

        cfg.vhost_user_connect_timeout_ms = cmd.vhost_user_connect_timeout_ms;

        cfg.disable_virtio_intx = cmd.disable_virtio_intx.unwrap_or_default();

        cfg.dump_device_tree_blob = cmd.dump_device_tree_blob;

        cfg.itmt = cmd.itmt.unwrap_or_default();

        #[cfg(target_arch = "x86_64")]
        {
            cfg.force_calibrated_tsc_leaf = cmd.force_calibrated_tsc_leaf.unwrap_or_default();
        }

        cfg.stub_pci_devices = cmd.stub_pci_device;

        cfg.fdt_position = cmd.fdt_position;

        #[cfg(any(target_os = "android", target_os = "linux"))]
        #[cfg(all(unix, feature = "media"))]
        {
            cfg.v4l2_proxy = cmd.v4l2_proxy;
            cfg.simple_media_device = cmd.simple_media_device.unwrap_or_default();
        }

        #[cfg(all(unix, feature = "media", feature = "video-decoder"))]
        {
            cfg.media_decoder = cmd.media_decoder;
        }

        (cfg.file_backed_mappings_ram, cfg.file_backed_mappings_mmio) =
            cmd.file_backed_mapping.into_iter().partition(|x| x.ram);

        #[cfg(target_os = "android")]
        {
            cfg.task_profiles = cmd.task_profiles;
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            if cmd.unmap_guest_memory_on_fork.unwrap_or_default()
                && !cmd.disable_sandbox.unwrap_or_default()
            {
                return Err("--unmap-guest-memory-on-fork requires --disable-sandbox".to_string());
            }
            cfg.unmap_guest_memory_on_fork = cmd.unmap_guest_memory_on_fork.unwrap_or_default();
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            cfg.vfio.extend(cmd.vfio);
            cfg.vfio.extend(cmd.vfio_platform);
            cfg.vfio_isolate_hotplug = cmd.vfio_isolate_hotplug.unwrap_or_default();
        }

        cfg.device_tree_overlay = cmd.device_tree_overlay;
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            if cfg.device_tree_overlay.iter().any(|o| o.filter_devs)
                && cfg.vfio.iter().all(|o| o.dt_symbol.is_none())
            {
                return Err("expected at least one VFIO device with a defined dt_symbol".into());
            }
        }

        // `--disable-sandbox` has the effect of disabling sandboxing altogether, so make sure
        // to handle it after other sandboxing options since they implicitly enable it.
        if cmd.disable_sandbox.unwrap_or_default() {
            cfg.jail_config = None;
        }

        cfg.name = cmd.name;

        // Now do validation of constructed config
        super::config::validate_config(&mut cfg)?;

        Ok(cfg)
    }
}

// Produce a block device path as used by Linux block devices.
//
// Examples for "/dev/vdX":
// /dev/vda, /dev/vdb, ..., /dev/vdz, /dev/vdaa, /dev/vdab, ...
fn format_disk_letter(dev_prefix: &str, mut i: usize) -> String {
    const ALPHABET_LEN: usize = 26; // a to z
    let mut s = dev_prefix.to_string();
    let insert_idx = dev_prefix.len();
    loop {
        s.insert(insert_idx, char::from(b'a' + (i % ALPHABET_LEN) as u8));
        i /= ALPHABET_LEN;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "config-file")]
    fn merge_runcommands() {
        let cmd2 = RunCommand {
            mem: Some(MemOptions { size: Some(4096) }),
            kernel: Some("/path/to/kernel".into()),
            params: vec!["firstparam".into()],
            ..Default::default()
        };

        let cmd3 = RunCommand {
            mem: Some(MemOptions { size: Some(8192) }),
            params: vec!["secondparam".into()],
            ..Default::default()
        };

        let cmd1 = RunCommand {
            mem: Some(MemOptions { size: Some(2048) }),
            params: vec!["thirdparam".into(), "fourthparam".into()],
            cfg: vec![cmd2, cmd3],
            ..Default::default()
        };

        let merged_cmd = cmd1.squash();

        assert_eq!(merged_cmd.mem, Some(MemOptions { size: Some(2048) }));
        assert_eq!(merged_cmd.kernel, Some("/path/to/kernel".into()));
        assert_eq!(
            merged_cmd.params,
            vec![
                String::from("firstparam"),
                String::from("secondparam"),
                String::from("thirdparam"),
                String::from("fourthparam"),
            ]
        );
    }

    #[test]
    fn disk_letter() {
        assert_eq!(format_disk_letter("/dev/sd", 0), "/dev/sda");
        assert_eq!(format_disk_letter("/dev/sd", 1), "/dev/sdb");
        assert_eq!(format_disk_letter("/dev/sd", 25), "/dev/sdz");
        assert_eq!(format_disk_letter("/dev/sd", 26), "/dev/sdaa");
        assert_eq!(format_disk_letter("/dev/sd", 27), "/dev/sdab");
        assert_eq!(format_disk_letter("/dev/sd", 51), "/dev/sdaz");
        assert_eq!(format_disk_letter("/dev/sd", 52), "/dev/sdba");
        assert_eq!(format_disk_letter("/dev/sd", 53), "/dev/sdbb");
        assert_eq!(format_disk_letter("/dev/sd", 78), "/dev/sdca");
        assert_eq!(format_disk_letter("/dev/sd", 701), "/dev/sdzz");
        assert_eq!(format_disk_letter("/dev/sd", 702), "/dev/sdaaa");
        assert_eq!(format_disk_letter("/dev/sd", 703), "/dev/sdaab");
    }
}
