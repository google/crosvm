// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__cpuid;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__cpuid_count;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use arch::set_default_serial_parameters;
use arch::CpuSet;
use arch::Pstore;
#[cfg(target_arch = "x86_64")]
use arch::SmbiosOptions;
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
use devices::virtio::scsi::ScsiOption;
#[cfg(feature = "audio")]
use devices::virtio::snd::parameters::Parameters as SndParameters;
#[cfg(all(windows, feature = "gpu"))]
use devices::virtio::vhost::user::device::gpu::sys::windows::GpuBackendConfig;
#[cfg(all(windows, feature = "gpu"))]
use devices::virtio::vhost::user::device::gpu::sys::windows::GpuVmmConfig;
#[cfg(all(windows, feature = "gpu"))]
use devices::virtio::vhost::user::device::gpu::sys::windows::InputEventSplitConfig;
#[cfg(all(windows, feature = "gpu"))]
use devices::virtio::vhost::user::device::gpu::sys::windows::WindowProcedureThreadSplitConfig;
#[cfg(all(windows, feature = "audio"))]
use devices::virtio::vhost::user::device::snd::sys::windows::SndSplitConfig;
use devices::virtio::vsock::VsockConfig;
use devices::virtio::DeviceType;
#[cfg(feature = "net")]
use devices::virtio::NetParameters;
use devices::FwCfgParameters;
use devices::PciAddress;
use devices::PflashParameters;
use devices::StubPciParameters;
#[cfg(target_arch = "x86_64")]
use hypervisor::CpuHybridType;
use hypervisor::ProtectionType;
use jail::JailConfig;
use resources::AddressRange;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;
use vm_control::BatteryType;
#[cfg(target_arch = "x86_64")]
use x86_64::check_host_hybrid_support;
#[cfg(target_arch = "x86_64")]
use x86_64::CpuIdCall;

pub(crate) use super::sys::HypervisorKind;
#[cfg(any(target_os = "android", target_os = "linux"))]
use crate::crosvm::sys::config::SharedDir;

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        #[cfg(feature = "gpu")]
        use crate::crosvm::sys::GpuRenderServerParameters;

        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        static VHOST_SCMI_PATH: &str = "/dev/vhost-scmi";
    } else if #[cfg(windows)] {
        use base::{Event, Tube};
    }
}

#[cfg(target_arch = "x86_64")]
const ONE_MB: u64 = 1 << 20;
#[cfg(target_arch = "x86_64")]
const MB_ALIGNED: u64 = ONE_MB - 1;
// the max bus number is 256 and each bus occupy 1MB, so the max pcie cfg mmio size = 256M
#[cfg(target_arch = "x86_64")]
const MAX_PCIE_ECAM_SIZE: u64 = ONE_MB * 256;

// by default, if enabled, the balloon WS features will use 4 bins.
#[cfg(feature = "balloon")]
const VIRTIO_BALLOON_WS_DEFAULT_NUM_BINS: u8 = 4;

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
#[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "x86_64")]
    pub core_types: Option<CpuCoreType>,
    /// Select which CPU to boot from.
    #[serde(default)]
    pub boot_cpu: Option<usize>,
}

/// Device tree overlay configuration.
#[derive(Debug, Default, Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DtboOption {
    /// Overlay file to apply to the base device tree.
    pub path: PathBuf,
    /// Whether to only apply device tree nodes which belong to a VFIO device.
    #[serde(rename = "filter", default)]
    pub filter_devs: bool,
}

#[derive(Debug, Default, Deserialize, Serialize, FromKeyValues, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct MemOptions {
    /// Amount of guest memory in MiB.
    #[serde(default)]
    pub size: Option<u64>,
}

fn deserialize_swap_interval<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Duration>, D::Error> {
    let ms = Option::<u64>::deserialize(deserializer)?;
    match ms {
        None => Ok(None),
        Some(ms) => Ok(Some(Duration::from_millis(ms))),
    }
}

#[derive(
    Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, serde_keyvalue::FromKeyValues,
)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PmemOption {
    /// Path to the diks image.
    pub path: PathBuf,
    /// Whether the disk is read-only.
    #[serde(default)]
    pub ro: bool,
    /// If set, add a kernel command line option making this the root device. Can only be set once.
    #[serde(default)]
    pub root: bool,
    /// Experimental option to specify the size in bytes of an anonymous virtual memory area that
    /// will be created to back this device.
    #[serde(default)]
    pub vma_size: Option<u64>,
    /// Experimental option to specify interval for periodic swap out of memory mapping
    #[serde(
        default,
        deserialize_with = "deserialize_swap_interval",
        rename = "swap-interval-ms"
    )]
    pub swap_interval: Option<Duration>,
}

#[derive(Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct VhostUserOption {
    pub socket: PathBuf,

    /// Maximum number of entries per queue (default: 32768)
    pub max_queue_size: Option<u16>,
}

#[derive(Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct VhostUserFrontendOption {
    /// Device type
    #[serde(rename = "type")]
    pub type_: devices::virtio::DeviceType,

    /// Path to the vhost-user backend socket to connect to
    pub socket: PathBuf,

    /// Maximum number of entries per queue (default: 32768)
    pub max_queue_size: Option<u16>,

    /// Preferred PCI address
    pub pci_address: Option<PciAddress>,
}

#[derive(Serialize, Deserialize, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct VhostUserFsOption {
    pub socket: PathBuf,
    pub tag: Option<String>,

    /// Maximum number of entries per queue (default: 32768)
    pub max_queue_size: Option<u16>,
}

pub fn parse_vhost_user_fs_option(param: &str) -> Result<VhostUserFsOption, String> {
    // Allow the previous `--vhost-user-fs /path/to/socket:fs-tag` format for compatibility.
    // This will unfortunately prevent parsing of valid comma-separated FromKeyValues options that
    // contain a ":" character (e.g. in a socket filename), but those were not supported in the old
    // format either, so we can live with it until the deprecated format is removed.
    // TODO(b/218223240): Remove support for the deprecated format (and use `FromKeyValues`
    // directly instead of `from_str_fn`) once enough time has passed.
    if param.contains(':') {
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

        log::warn!(
            "`--vhost-user-fs` with colon-separated options is deprecated; \
            please use `--vhost-user-fs {},tag={}` instead",
            socket.display(),
            tag,
        );

        Ok(VhostUserFsOption {
            socket,
            tag: Some(tag),
            max_queue_size: None,
        })
    } else {
        from_key_values::<VhostUserFsOption>(param)
    }
}

pub const DEFAULT_TOUCH_DEVICE_HEIGHT: u32 = 1024;
pub const DEFAULT_TOUCH_DEVICE_WIDTH: u32 = 1280;

#[derive(Serialize, Deserialize, Debug, FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct TouchDeviceOption {
    pub path: PathBuf,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub name: Option<String>,
}

/// Try to parse a colon-separated touch device option.
///
/// The expected format is "PATH:WIDTH:HEIGHT:NAME", with all fields except PATH being optional.
fn parse_touch_device_option_legacy(s: &str) -> Option<TouchDeviceOption> {
    let mut it = s.split(':');
    let path = PathBuf::from(it.next()?.to_owned());
    let width = if let Some(width) = it.next() {
        Some(width.trim().parse().ok()?)
    } else {
        None
    };
    let height = if let Some(height) = it.next() {
        Some(height.trim().parse().ok()?)
    } else {
        None
    };
    let name = it.next().map(|name| name.trim().to_string());
    if it.next().is_some() {
        return None;
    }

    Some(TouchDeviceOption {
        path,
        width,
        height,
        name,
    })
}

/// Parse virtio-input touch device options from a string.
///
/// This function only exists to enable the use of the deprecated colon-separated form
/// ("PATH:WIDTH:HEIGHT:NAME"); once the deprecation period is over, this function should be removed
/// in favor of using the derived `FromKeyValues` function directly.
pub fn parse_touch_device_option(s: &str) -> Result<TouchDeviceOption, String> {
    if s.contains(':') {
        if let Some(touch_spec) = parse_touch_device_option_legacy(s) {
            log::warn!(
                "colon-separated touch device options are deprecated; \
                please use --input instead"
            );
            return Ok(touch_spec);
        }
    }

    from_key_values::<TouchDeviceOption>(s)
}

/// virtio-input device configuration
#[derive(Serialize, Deserialize, Debug, FromKeyValues, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum InputDeviceOption {
    Evdev {
        path: PathBuf,
    },
    Keyboard {
        path: PathBuf,
    },
    Mouse {
        path: PathBuf,
    },
    MultiTouch {
        path: PathBuf,
        width: Option<u32>,
        height: Option<u32>,
        name: Option<String>,
    },
    Rotary {
        path: PathBuf,
    },
    SingleTouch {
        path: PathBuf,
        width: Option<u32>,
        height: Option<u32>,
        name: Option<String>,
    },
    Switches {
        path: PathBuf,
    },
    Trackpad {
        path: PathBuf,
        width: Option<u32>,
        height: Option<u32>,
        name: Option<String>,
    },
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

    if params.pci_address.is_some()
        && params.hardware != SerialHardware::VirtioConsole
        && params.hardware != SerialHardware::LegacyVirtioConsole
    {
        return Err(invalid_value_err(
            params.pci_address.unwrap().to_string(),
            "Providing serial PCI address is only supported for virtio-console hardware type",
        ));
    }

    Ok(())
}

pub fn parse_serial_options(s: &str) -> Result<SerialParameters, String> {
    let params: SerialParameters = from_key_values(s)?;

    validate_serial_parameters(&params)?;

    Ok(params)
}

#[cfg(target_arch = "x86_64")]
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
        Ok(BTreeMap::from_iter(params))
    }
}

/// Aggregate of all configurable options for a running VM.
#[derive(Serialize, Deserialize)]
#[remain::sorted]
pub struct Config {
    #[cfg(all(target_arch = "x86_64", unix))]
    pub ac_adapter: bool,
    pub acpi_tables: Vec<PathBuf>,
    #[cfg(feature = "android_display")]
    pub android_display_service: Option<String>,
    pub android_fstab: Option<PathBuf>,
    pub async_executor: Option<ExecutorKind>,
    #[cfg(feature = "balloon")]
    pub balloon: bool,
    #[cfg(feature = "balloon")]
    pub balloon_bias: i64,
    #[cfg(feature = "balloon")]
    pub balloon_control: Option<PathBuf>,
    #[cfg(feature = "balloon")]
    pub balloon_page_reporting: bool,
    #[cfg(feature = "balloon")]
    pub balloon_ws_num_bins: u8,
    #[cfg(feature = "balloon")]
    pub balloon_ws_reporting: bool,
    pub battery_config: Option<BatteryConfig>,
    #[cfg(windows)]
    pub block_control_tube: Vec<Tube>,
    #[cfg(windows)]
    pub block_vhost_user_tube: Vec<Tube>,
    pub boot_cpu: usize,
    #[cfg(target_arch = "x86_64")]
    pub break_linux_pci_config_io: bool,
    #[cfg(windows)]
    pub broker_shutdown_event: Option<Event>,
    #[cfg(target_arch = "x86_64")]
    pub bus_lock_ratelimit: u64,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub coiommu_param: Option<devices::CoIommuParameters>,
    pub core_scheduling: bool,
    pub cpu_capacity: BTreeMap<usize, u32>, // CPU index -> capacity
    pub cpu_clusters: Vec<CpuSet>,
    #[cfg(feature = "crash-report")]
    pub crash_pipe_name: Option<String>,
    #[cfg(feature = "crash-report")]
    pub crash_report_uuid: Option<String>,
    pub delay_rt: bool,
    pub device_tree_overlay: Vec<DtboOption>,
    pub disable_virtio_intx: bool,
    pub disks: Vec<DiskOption>,
    pub display_input_height: Option<u32>,
    pub display_input_width: Option<u32>,
    pub display_window_keyboard: bool,
    pub display_window_mouse: bool,
    pub dump_device_tree_blob: Option<PathBuf>,
    pub dynamic_power_coefficient: BTreeMap<usize, u32>,
    pub enable_fw_cfg: bool,
    pub enable_hwp: bool,
    pub executable_path: Option<Executable>,
    #[cfg(windows)]
    pub exit_stats: bool,
    pub file_backed_mappings: Vec<FileBackedMappingParameters>,
    pub force_calibrated_tsc_leaf: bool,
    pub force_s2idle: bool,
    pub fw_cfg_parameters: Vec<FwCfgParameters>,
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
    #[cfg(feature = "balloon")]
    pub init_memory: Option<u64>,
    pub initrd_path: Option<PathBuf>,
    #[cfg(all(windows, feature = "gpu"))]
    pub input_event_split_config: Option<InputEventSplitConfig>,
    pub irq_chip: Option<IrqChipKind>,
    pub itmt: bool,
    pub jail_config: Option<JailConfig>,
    #[cfg(windows)]
    pub kernel_log_file: Option<String>,
    #[cfg(any(target_os = "android", target_os = "linux"))]
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
    #[cfg(feature = "net")]
    pub net: Vec<NetParameters>,
    #[cfg(windows)]
    pub net_vhost_user_tube: Option<Tube>,
    pub no_i8042: bool,
    pub no_rtc: bool,
    pub no_smt: bool,
    pub params: Vec<String>,
    #[cfg(feature = "pci-hotplug")]
    pub pci_hotplug_slots: Option<u8>,
    #[cfg(target_arch = "x86_64")]
    pub pci_low_start: Option<u64>,
    #[cfg(target_arch = "x86_64")]
    pub pcie_ecam: Option<AddressRange>,
    pub per_vm_core_scheduling: bool,
    pub pflash_parameters: Option<PflashParameters>,
    #[cfg(feature = "plugin")]
    pub plugin_gid_maps: Vec<crate::crosvm::plugin::GidMap>,
    #[cfg(feature = "plugin")]
    pub plugin_mounts: Vec<crate::crosvm::plugin::BindMount>,
    pub plugin_root: Option<PathBuf>,
    pub pmems: Vec<PmemOption>,
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
    #[cfg(feature = "pvclock")]
    pub pvclock: bool,
    /// Must be `Some` iff `protection_type == ProtectionType::UnprotectedWithFirmware`.
    pub pvm_fw: Option<PathBuf>,
    pub restore_path: Option<PathBuf>,
    pub rng: bool,
    pub rt_cpus: CpuSet,
    pub scsis: Vec<ScsiOption>,
    #[serde(with = "serde_serial_params")]
    pub serial_parameters: BTreeMap<(SerialHardware, u8), SerialParameters>,
    #[cfg(windows)]
    pub service_pipe_name: Option<String>,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[serde(skip)]
    pub shared_dirs: Vec<SharedDir>,
    #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
    pub slirp_capture_file: Option<String>,
    #[cfg(target_arch = "x86_64")]
    pub smbios: SmbiosOptions,
    #[cfg(all(windows, feature = "audio"))]
    pub snd_split_configs: Vec<SndSplitConfig>,
    pub socket_path: Option<PathBuf>,
    #[cfg(feature = "audio")]
    pub sound: Option<PathBuf>,
    #[cfg(feature = "balloon")]
    pub strict_balloon: bool,
    pub stub_pci_devices: Vec<StubPciParameters>,
    pub suspended: bool,
    pub swap_dir: Option<PathBuf>,
    pub swiotlb: Option<u64>,
    #[cfg(target_os = "android")]
    pub task_profiles: Vec<String>,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub unmap_guest_memory_on_fork: bool,
    pub usb: bool,
    pub vcpu_affinity: Option<VcpuAffinity>,
    pub vcpu_cgroup_path: Option<PathBuf>,
    pub vcpu_count: Option<usize>,
    #[cfg(target_arch = "x86_64")]
    pub vcpu_hybrid_type: BTreeMap<usize, CpuHybridType>, // CPU index -> hybrid type
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub vfio: Vec<super::sys::config::VfioOption>,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub vfio_isolate_hotplug: bool,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub vhost_scmi: bool,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub vhost_scmi_device: PathBuf,
    pub vhost_user: Vec<VhostUserFrontendOption>,
    pub vhost_user_fs: Vec<VhostUserFsOption>,
    #[cfg(feature = "video-decoder")]
    pub video_dec: Vec<VideoDeviceConfig>,
    #[cfg(feature = "video-encoder")]
    pub video_enc: Vec<VideoDeviceConfig>,
    #[cfg(all(
        any(target_arch = "arm", target_arch = "aarch64"),
        any(target_os = "android", target_os = "linux")
    ))]
    pub virt_cpufreq: bool,
    pub virt_cpufreq_socket: Option<PathBuf>,
    pub virtio_input: Vec<InputDeviceOption>,
    #[cfg(feature = "audio")]
    #[serde(skip)]
    pub virtio_snds: Vec<SndParameters>,
    pub vsock: Option<VsockConfig>,
    #[cfg(feature = "vtpm")]
    pub vtpm_proxy: bool,
    pub wayland_socket_paths: BTreeMap<String, PathBuf>,
    #[cfg(all(windows, feature = "gpu"))]
    pub window_procedure_thread_split_config: Option<WindowProcedureThreadSplitConfig>,
    pub x_display: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            #[cfg(all(target_arch = "x86_64", unix))]
            ac_adapter: false,
            acpi_tables: Vec::new(),
            #[cfg(feature = "android_display")]
            android_display_service: None,
            android_fstab: None,
            async_executor: None,
            #[cfg(feature = "balloon")]
            balloon: true,
            #[cfg(feature = "balloon")]
            balloon_bias: 0,
            #[cfg(feature = "balloon")]
            balloon_control: None,
            #[cfg(feature = "balloon")]
            balloon_page_reporting: false,
            #[cfg(feature = "balloon")]
            balloon_ws_num_bins: VIRTIO_BALLOON_WS_DEFAULT_NUM_BINS,
            #[cfg(feature = "balloon")]
            balloon_ws_reporting: false,
            battery_config: None,
            boot_cpu: 0,
            #[cfg(windows)]
            block_control_tube: Vec::new(),
            #[cfg(windows)]
            block_vhost_user_tube: Vec::new(),
            #[cfg(target_arch = "x86_64")]
            break_linux_pci_config_io: false,
            #[cfg(windows)]
            broker_shutdown_event: None,
            #[cfg(target_arch = "x86_64")]
            bus_lock_ratelimit: 0,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            coiommu_param: None,
            core_scheduling: true,
            #[cfg(feature = "crash-report")]
            crash_pipe_name: None,
            #[cfg(feature = "crash-report")]
            crash_report_uuid: None,
            cpu_capacity: BTreeMap::new(),
            cpu_clusters: Vec::new(),
            delay_rt: false,
            device_tree_overlay: Vec::new(),
            disks: Vec::new(),
            disable_virtio_intx: false,
            display_input_height: None,
            display_input_width: None,
            display_window_keyboard: false,
            display_window_mouse: false,
            dump_device_tree_blob: None,
            dynamic_power_coefficient: BTreeMap::new(),
            enable_fw_cfg: false,
            enable_hwp: false,
            executable_path: None,
            #[cfg(windows)]
            exit_stats: false,
            file_backed_mappings: Vec::new(),
            force_calibrated_tsc_leaf: false,
            force_s2idle: false,
            fw_cfg_parameters: Vec::new(),
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
            #[cfg(feature = "balloon")]
            init_memory: None,
            initrd_path: None,
            #[cfg(all(windows, feature = "gpu"))]
            input_event_split_config: None,
            irq_chip: None,
            itmt: false,
            jail_config: if !cfg!(feature = "default-no-sandbox") {
                Some(Default::default())
            } else {
                None
            },
            #[cfg(windows)]
            kernel_log_file: None,
            #[cfg(any(target_os = "android", target_os = "linux"))]
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
            #[cfg(feature = "net")]
            net: Vec::new(),
            #[cfg(windows)]
            net_vhost_user_tube: None,
            no_i8042: false,
            no_rtc: false,
            no_smt: false,
            params: Vec::new(),
            #[cfg(feature = "pci-hotplug")]
            pci_hotplug_slots: None,
            #[cfg(target_arch = "x86_64")]
            pci_low_start: None,
            #[cfg(target_arch = "x86_64")]
            pcie_ecam: None,
            per_vm_core_scheduling: false,
            pflash_parameters: None,
            #[cfg(feature = "plugin")]
            plugin_gid_maps: Vec::new(),
            #[cfg(feature = "plugin")]
            plugin_mounts: Vec::new(),
            plugin_root: None,
            pmems: Vec::new(),
            #[cfg(feature = "process-invariants")]
            process_invariants_data_handle: None,
            #[cfg(feature = "process-invariants")]
            process_invariants_data_size: None,
            #[cfg(windows)]
            product_name: None,
            protection_type: ProtectionType::Unprotected,
            pstore: None,
            #[cfg(feature = "pvclock")]
            pvclock: false,
            pvm_fw: None,
            restore_path: None,
            rng: true,
            rt_cpus: Default::default(),
            serial_parameters: BTreeMap::new(),
            scsis: Vec::new(),
            #[cfg(windows)]
            service_pipe_name: None,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            shared_dirs: Vec::new(),
            #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
            slirp_capture_file: None,
            #[cfg(target_arch = "x86_64")]
            smbios: SmbiosOptions::default(),
            #[cfg(all(windows, feature = "audio"))]
            snd_split_configs: Vec::new(),
            socket_path: None,
            #[cfg(feature = "audio")]
            sound: None,
            #[cfg(feature = "balloon")]
            strict_balloon: false,
            stub_pci_devices: Vec::new(),
            suspended: false,
            swap_dir: None,
            swiotlb: None,
            #[cfg(target_os = "android")]
            task_profiles: Vec::new(),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            unmap_guest_memory_on_fork: false,
            usb: true,
            vcpu_affinity: None,
            vcpu_cgroup_path: None,
            vcpu_count: None,
            #[cfg(target_arch = "x86_64")]
            vcpu_hybrid_type: BTreeMap::new(),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            vfio: Vec::new(),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            vfio_isolate_hotplug: false,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
            vhost_scmi: false,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
            vhost_scmi_device: PathBuf::from(VHOST_SCMI_PATH),
            vhost_user: Vec::new(),
            vhost_user_fs: Vec::new(),
            vsock: None,
            #[cfg(feature = "video-decoder")]
            video_dec: Vec::new(),
            #[cfg(feature = "video-encoder")]
            video_enc: Vec::new(),
            #[cfg(all(
                any(target_arch = "arm", target_arch = "aarch64"),
                any(target_os = "android", target_os = "linux")
            ))]
            virt_cpufreq: false,
            virt_cpufreq_socket: None,
            virtio_input: Vec::new(),
            #[cfg(feature = "audio")]
            virtio_snds: Vec::new(),
            #[cfg(feature = "vtpm")]
            vtpm_proxy: false,
            wayland_socket_paths: BTreeMap::new(),
            #[cfg(windows)]
            window_procedure_thread_split_config: None,
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

        if !cfg.cpu_capacity.is_empty() {
            return Err(
                "`host-cpu-topology` requires not to set `cpu-capacity` at the same time"
                    .to_string(),
            );
        }

        if !cfg.cpu_clusters.is_empty() {
            return Err(
                "`host-cpu-topology` requires not to set `cpu clusters` at the same time"
                    .to_string(),
            );
        }
    }

    if cfg.boot_cpu >= cfg.vcpu_count.unwrap_or(1) {
        log::warn!("boot_cpu selection cannot be higher than vCPUs available, defaulting to 0");
        cfg.boot_cpu = 0;
    }

    #[cfg(all(
        any(target_arch = "arm", target_arch = "aarch64"),
        any(target_os = "android", target_os = "linux")
    ))]
    if cfg.virt_cpufreq {
        if !cfg.host_cpu_topology && (cfg.vcpu_affinity.is_none() || cfg.cpu_capacity.is_empty()) {
            return Err("`virt-cpufreq` requires 'host-cpu-topology' enabled or \
                       have vcpu_affinity and cpu_capacity configured"
                .to_string());
        }
    }
    #[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "x86_64")]
    if cfg.enable_hwp && !cfg.host_cpu_topology {
        return Err("setting `enable-hwp` requires `host-cpu-topology` is set.".to_string());
    }
    #[cfg(target_arch = "x86_64")]
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

    #[cfg(feature = "balloon")]
    {
        if !cfg.balloon && cfg.balloon_control.is_some() {
            return Err("'balloon-control' requires enabled balloon".to_string());
        }

        if !cfg.balloon && cfg.balloon_page_reporting {
            return Err("'balloon_page_reporting' requires enabled balloon".to_string());
        }
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
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
        cfg.vhost_user
            .iter()
            .any(|opt| opt.type_ == DeviceType::Console),
    );

    for mapping in cfg.file_backed_mappings.iter_mut() {
        validate_file_backed_mapping(mapping)?;
    }

    for pmem in cfg.pmems.iter() {
        validate_pmem(pmem)?;
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

fn validate_pmem(pmem: &PmemOption) -> Result<(), String> {
    if (pmem.swap_interval.is_some() && pmem.vma_size.is_none())
        || (pmem.swap_interval.is_none() && pmem.vma_size.is_some())
    {
        return Err(
            "--pmem vma-size and swap-interval parameters must be specified together".to_string(),
        );
    }

    if pmem.ro && pmem.swap_interval.is_some() {
        return Err(
            "--pmem swap-interval parameter can only be set for writable pmem device".to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::needless_update)]
mod tests {
    use argh::FromArgs;
    use devices::PciClassCode;
    use devices::StubPciParameters;
    #[cfg(target_arch = "x86_64")]
    use uuid::uuid;

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

        #[cfg(target_arch = "x86_64")]
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
        // For now, allow duplicates - they will be handled gracefully by the vec to cpu_set_t
        // conversion.
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
    fn parse_serial_pci_address_valid_for_virtio() {
        let parsed =
            parse_serial_options("type=syslog,hardware=virtio-console,pci-address=00:0e.0")
                .expect("parse should have succeded");
        assert_eq!(
            parsed.pci_address,
            Some(PciAddress {
                bus: 0,
                dev: 14,
                func: 0
            })
        );
    }

    #[test]
    fn parse_serial_pci_address_valid_for_legacy_virtio() {
        let parsed =
            parse_serial_options("type=syslog,hardware=legacy-virtio-console,pci-address=00:0e.0")
                .expect("parse should have succeded");
        assert_eq!(
            parsed.pci_address,
            Some(PciAddress {
                bus: 0,
                dev: 14,
                func: 0
            })
        );
    }

    #[test]
    fn parse_serial_pci_address_failed_for_serial() {
        parse_serial_options("type=syslog,hardware=serial,pci-address=00:0e.0")
            .expect_err("expected pci-address error for serial hardware");
    }

    #[test]
    fn parse_serial_pci_address_failed_for_debugcon() {
        parse_serial_options("type=syslog,hardware=debugcon,pci-address=00:0e.0")
            .expect_err("expected pci-address error for debugcon hardware");
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
        let addr = pagesize() as u64 * 3 + 42;
        let size = pagesize() as u64 - 0xf;
        let mut params = from_key_values::<FileBackedMappingParameters>(&format!(
            "addr={addr},size={size},path=/dev/mem,align",
        ))
        .unwrap();
        assert_eq!(params.address, addr);
        assert_eq!(params.size, size);
        validate_file_backed_mapping(&mut params).unwrap();
        assert_eq!(params.address, pagesize() as u64 * 3);
        assert_eq!(params.size, pagesize() as u64 * 2);
    }

    #[test]
    fn parse_fw_cfg_valid_path() {
        let cfg = TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &["--fw-cfg", "name=bar,path=data.bin", "/dev/null"],
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(cfg.fw_cfg_parameters.len(), 1);
        assert_eq!(cfg.fw_cfg_parameters[0].name, "bar".to_string());
        assert_eq!(cfg.fw_cfg_parameters[0].string, None);
        assert_eq!(cfg.fw_cfg_parameters[0].path, Some("data.bin".into()));
    }

    #[test]
    fn parse_fw_cfg_valid_string() {
        let cfg = TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &["--fw-cfg", "name=bar,string=foo", "/dev/null"],
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(cfg.fw_cfg_parameters.len(), 1);
        assert_eq!(cfg.fw_cfg_parameters[0].name, "bar".to_string());
        assert_eq!(cfg.fw_cfg_parameters[0].string, Some("foo".to_string()));
        assert_eq!(cfg.fw_cfg_parameters[0].path, None);
    }

    #[test]
    fn parse_dtbo() {
        let cfg: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--device-tree-overlay",
                "/path/to/dtbo1",
                "--device-tree-overlay",
                "/path/to/dtbo2",
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(cfg.device_tree_overlay.len(), 2);
        for (opt, p) in cfg
            .device_tree_overlay
            .into_iter()
            .zip(["/path/to/dtbo1", "/path/to/dtbo2"])
        {
            assert_eq!(opt.path, PathBuf::from(p));
            assert!(!opt.filter_devs);
        }
    }

    #[test]
    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn parse_dtbo_filtered() {
        let cfg: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--vfio",
                "/path/to/dev,dt-symbol=mydev",
                "--device-tree-overlay",
                "/path/to/dtbo1,filter",
                "--device-tree-overlay",
                "/path/to/dtbo2,filter",
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(cfg.device_tree_overlay.len(), 2);
        for (opt, p) in cfg
            .device_tree_overlay
            .into_iter()
            .zip(["/path/to/dtbo1", "/path/to/dtbo2"])
        {
            assert_eq!(opt.path, PathBuf::from(p));
            assert!(opt.filter_devs);
        }

        assert!(TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &["--device-tree-overlay", "/path/to/dtbo,filter", "/dev/null"],
            )
            .unwrap(),
        )
        .is_err());
    }

    #[test]
    fn parse_fw_cfg_invalid_no_name() {
        assert!(
            crate::crosvm::cmdline::RunCommand::from_args(&[], &["--fw-cfg", "string=foo",])
                .is_err()
        );
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
    fn parse_vhost_user_option() {
        let opt: VhostUserOption = from_key_values("/10mm").unwrap();
        assert_eq!(opt.socket.to_str(), Some("/10mm"));
        assert_eq!(opt.max_queue_size, None);

        let opt: VhostUserOption = from_key_values("/10mm,max-queue-size=256").unwrap();
        assert_eq!(opt.socket.to_str(), Some("/10mm"));
        assert_eq!(opt.max_queue_size, Some(256));
    }

    #[test]
    fn parse_vhost_user_option_all_device_types() {
        fn test_device_type(type_string: &str, type_: DeviceType) {
            let vhost_user_arg = format!("{},socket=sock", type_string);

            let cfg = TryInto::<Config>::try_into(
                crate::crosvm::cmdline::RunCommand::from_args(
                    &[],
                    &["--vhost-user", &vhost_user_arg, "/dev/null"],
                )
                .unwrap(),
            )
            .unwrap();

            assert_eq!(cfg.vhost_user.len(), 1);
            let vu = &cfg.vhost_user[0];
            assert_eq!(vu.type_, type_);
        }

        test_device_type("net", DeviceType::Net);
        test_device_type("block", DeviceType::Block);
        test_device_type("console", DeviceType::Console);
        test_device_type("rng", DeviceType::Rng);
        test_device_type("balloon", DeviceType::Balloon);
        test_device_type("scsi", DeviceType::Scsi);
        test_device_type("9p", DeviceType::P9);
        test_device_type("gpu", DeviceType::Gpu);
        test_device_type("input", DeviceType::Input);
        test_device_type("vsock", DeviceType::Vsock);
        test_device_type("iommu", DeviceType::Iommu);
        test_device_type("sound", DeviceType::Sound);
        test_device_type("fs", DeviceType::Fs);
        test_device_type("pmem", DeviceType::Pmem);
        test_device_type("mac80211-hwsim", DeviceType::Mac80211HwSim);
        test_device_type("video-encoder", DeviceType::VideoEncoder);
        test_device_type("video-decoder", DeviceType::VideoDecoder);
        test_device_type("scmi", DeviceType::Scmi);
        test_device_type("wl", DeviceType::Wl);
        test_device_type("tpm", DeviceType::Tpm);
        test_device_type("pvclock", DeviceType::Pvclock);
    }

    #[test]
    fn parse_vhost_user_fs_deprecated() {
        let cfg = TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &["--vhost-user-fs", "my_socket:my_tag", "/dev/null"],
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(cfg.vhost_user_fs.len(), 1);
        let fs = &cfg.vhost_user_fs[0];
        assert_eq!(fs.socket.to_str(), Some("my_socket"));
        assert_eq!(fs.tag, Some("my_tag".to_string()));
        assert_eq!(fs.max_queue_size, None);
    }

    #[test]
    fn parse_vhost_user_fs() {
        let cfg = TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &["--vhost-user-fs", "my_socket,tag=my_tag", "/dev/null"],
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(cfg.vhost_user_fs.len(), 1);
        let fs = &cfg.vhost_user_fs[0];
        assert_eq!(fs.socket.to_str(), Some("my_socket"));
        assert_eq!(fs.tag, Some("my_tag".to_string()));
        assert_eq!(fs.max_queue_size, None);
    }

    #[test]
    fn parse_vhost_user_fs_max_queue_size() {
        let cfg = TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &[
                    "--vhost-user-fs",
                    "my_socket,tag=my_tag,max-queue-size=256",
                    "/dev/null",
                ],
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(cfg.vhost_user_fs.len(), 1);
        let fs = &cfg.vhost_user_fs[0];
        assert_eq!(fs.socket.to_str(), Some("my_socket"));
        assert_eq!(fs.tag, Some("my_tag".to_string()));
        assert_eq!(fs.max_queue_size, Some(256));
    }

    #[test]
    fn parse_vhost_user_fs_no_tag() {
        let cfg = TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &["--vhost-user-fs", "my_socket", "/dev/null"],
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(cfg.vhost_user_fs.len(), 1);
        let fs = &cfg.vhost_user_fs[0];
        assert_eq!(fs.socket.to_str(), Some("my_socket"));
        assert_eq!(fs.tag, None);
        assert_eq!(fs.max_queue_size, None);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn parse_smbios_uuid() {
        let opt: SmbiosOptions =
            from_key_values("uuid=12e474af-2cc1-49d1-b0e5-d03a3e03ca03").unwrap();
        assert_eq!(
            opt.uuid,
            Some(uuid!("12e474af-2cc1-49d1-b0e5-d03a3e03ca03"))
        );

        from_key_values::<SmbiosOptions>("uuid=zzzz").expect_err("expected error parsing uuid");
    }

    #[test]
    fn parse_touch_legacy() {
        let cfg = TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &["--multi-touch", "my_socket:867:5309", "bzImage"],
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(cfg.virtio_input.len(), 1);
        let multi_touch = cfg
            .virtio_input
            .iter()
            .find(|input| matches!(input, InputDeviceOption::MultiTouch { .. }))
            .unwrap();
        assert_eq!(
            *multi_touch,
            InputDeviceOption::MultiTouch {
                path: PathBuf::from("my_socket"),
                width: Some(867),
                height: Some(5309),
                name: None
            }
        );
    }

    #[test]
    fn parse_touch() {
        let cfg = TryInto::<Config>::try_into(
            crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &["--multi-touch", r"C:\path,width=867,height=5309", "bzImage"],
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(cfg.virtio_input.len(), 1);
        let multi_touch = cfg
            .virtio_input
            .iter()
            .find(|input| matches!(input, InputDeviceOption::MultiTouch { .. }))
            .unwrap();
        assert_eq!(
            *multi_touch,
            InputDeviceOption::MultiTouch {
                path: PathBuf::from(r"C:\path"),
                width: Some(867),
                height: Some(5309),
                name: None
            }
        );
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

        let single_touch = config
            .virtio_input
            .iter()
            .find(|input| matches!(input, InputDeviceOption::SingleTouch { .. }))
            .unwrap();
        let trackpad = config
            .virtio_input
            .iter()
            .find(|input| matches!(input, InputDeviceOption::Trackpad { .. }))
            .unwrap();

        assert_eq!(
            *single_touch,
            InputDeviceOption::SingleTouch {
                path: PathBuf::from("/dev/single-touch-test"),
                width: None,
                height: None,
                name: None
            }
        );
        assert_eq!(
            *trackpad,
            InputDeviceOption::Trackpad {
                path: PathBuf::from("/dev/single-touch-test"),
                width: None,
                height: None,
                name: None
            }
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn single_touch_spec_default_size_from_gpu() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--single-touch",
                "/dev/single-touch-test",
                "--gpu",
                "width=1024,height=768",
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let single_touch = config
            .virtio_input
            .iter()
            .find(|input| matches!(input, InputDeviceOption::SingleTouch { .. }))
            .unwrap();
        assert_eq!(
            *single_touch,
            InputDeviceOption::SingleTouch {
                path: PathBuf::from("/dev/single-touch-test"),
                width: None,
                height: None,
                name: None
            }
        );

        assert_eq!(config.display_input_width, Some(1024));
        assert_eq!(config.display_input_height, Some(768));
    }

    #[test]
    fn single_touch_spec_and_track_pad_spec_with_size() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--single-touch",
                "/dev/single-touch-test:12345:54321",
                "--trackpad",
                "/dev/single-touch-test:5678:9876",
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let single_touch = config
            .virtio_input
            .iter()
            .find(|input| matches!(input, InputDeviceOption::SingleTouch { .. }))
            .unwrap();
        let trackpad = config
            .virtio_input
            .iter()
            .find(|input| matches!(input, InputDeviceOption::Trackpad { .. }))
            .unwrap();

        assert_eq!(
            *single_touch,
            InputDeviceOption::SingleTouch {
                path: PathBuf::from("/dev/single-touch-test"),
                width: Some(12345),
                height: Some(54321),
                name: None
            }
        );
        assert_eq!(
            *trackpad,
            InputDeviceOption::Trackpad {
                path: PathBuf::from("/dev/single-touch-test"),
                width: Some(5678),
                height: Some(9876),
                name: None
            }
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn single_touch_spec_with_size_independent_from_gpu() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--single-touch",
                "/dev/single-touch-test:12345:54321",
                "--gpu",
                "width=1024,height=768",
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let single_touch = config
            .virtio_input
            .iter()
            .find(|input| matches!(input, InputDeviceOption::SingleTouch { .. }))
            .unwrap();

        assert_eq!(
            *single_touch,
            InputDeviceOption::SingleTouch {
                path: PathBuf::from("/dev/single-touch-test"),
                width: Some(12345),
                height: Some(54321),
                name: None
            }
        );

        assert_eq!(config.display_input_width, Some(1024));
        assert_eq!(config.display_input_height, Some(768));
    }

    #[test]
    fn virtio_switches() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--switches", "/dev/switches-test", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let switches = config
            .virtio_input
            .iter()
            .find(|input| matches!(input, InputDeviceOption::Switches { .. }))
            .unwrap();

        assert_eq!(
            *switches,
            InputDeviceOption::Switches {
                path: PathBuf::from("/dev/switches-test")
            }
        );
    }

    #[test]
    fn virtio_rotary() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--rotary", "/dev/rotary-test", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let rotary = config
            .virtio_input
            .iter()
            .find(|input| matches!(input, InputDeviceOption::Rotary { .. }))
            .unwrap();

        assert_eq!(
            *rotary,
            InputDeviceOption::Rotary {
                path: PathBuf::from("/dev/rotary-test")
            }
        );
    }

    #[test]
    fn parse_pmem_options_missing_path() {
        assert!(from_key_values::<PmemOption>("")
            .unwrap_err()
            .contains("missing field `path`"));
    }

    #[test]
    fn parse_pmem_options_default_values() {
        let pmem = from_key_values::<PmemOption>("/path/to/disk.img").unwrap();
        assert_eq!(
            pmem,
            PmemOption {
                path: "/path/to/disk.img".into(),
                ro: false,
                root: false,
                vma_size: None,
                swap_interval: None,
            }
        );
    }

    #[test]
    fn parse_pmem_options_virtual_swap() {
        let pmem =
            from_key_values::<PmemOption>("virtual_path,vma-size=12345,swap-interval-ms=1000")
                .unwrap();
        assert_eq!(
            pmem,
            PmemOption {
                path: "virtual_path".into(),
                ro: false,
                root: false,
                vma_size: Some(12345),
                swap_interval: Some(Duration::new(1, 0)),
            }
        );
    }

    #[test]
    fn validate_pmem_missing_virtual_swap_param() {
        let pmem = from_key_values::<PmemOption>("virtual_path,swap-interval-ms=1000").unwrap();
        assert!(validate_pmem(&pmem)
            .unwrap_err()
            .contains("vma-size and swap-interval parameters must be specified together"));
    }

    #[test]
    fn validate_pmem_read_only_virtual_swap() {
        let pmem = from_key_values::<PmemOption>(
            "virtual_path,ro=true,vma-size=12345,swap-interval-ms=1000",
        )
        .unwrap();
        assert!(validate_pmem(&pmem)
            .unwrap_err()
            .contains("swap-interval parameter can only be set for writable pmem device"));
    }
}
