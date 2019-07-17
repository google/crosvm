// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The root level module that includes the config and aggregate of the submodules for running said
//! configs.

pub mod argument;
pub mod linux;
#[cfg(feature = "plugin")]
pub mod plugin;

use std::collections::BTreeMap;
use std::net;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::str::FromStr;

use devices::virtio::fs::passthrough;
use devices::SerialParameters;
use libc::{getegid, geteuid};

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

pub struct DiskOption {
    pub path: PathBuf,
    pub read_only: bool,
    pub sparse: bool,
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

const DEFAULT_TOUCH_DEVICE_WIDTH: u32 = 800;
const DEFAULT_TOUCH_DEVICE_HEIGHT: u32 = 1280;

pub struct TouchDeviceOption {
    pub path: PathBuf,
    pub width: u32,
    pub height: u32,
}

impl TouchDeviceOption {
    pub fn new(path: PathBuf) -> TouchDeviceOption {
        TouchDeviceOption {
            path,
            width: DEFAULT_TOUCH_DEVICE_WIDTH,
            height: DEFAULT_TOUCH_DEVICE_HEIGHT,
        }
    }
}

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
    pub cfg: passthrough::Config,
}

impl Default for SharedDir {
    fn default() -> SharedDir {
        SharedDir {
            src: Default::default(),
            tag: Default::default(),
            kind: Default::default(),
            uid_map: format!("0 {} 1", unsafe { geteuid() }),
            gid_map: format!("0 {} 1", unsafe { getegid() }),
            cfg: Default::default(),
        }
    }
}

/// Aggregate of all configurable options for a running VM.
pub struct Config {
    pub vcpu_count: Option<u32>,
    pub vcpu_affinity: Vec<usize>,
    pub memory: Option<usize>,
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
    pub host_ip: Option<net::Ipv4Addr>,
    pub netmask: Option<net::Ipv4Addr>,
    pub mac_address: Option<net_util::MacAddress>,
    pub vhost_net: bool,
    pub tap_fd: Vec<RawFd>,
    pub cid: Option<u64>,
    pub wayland_socket_path: Option<PathBuf>,
    pub wayland_dmabuf: bool,
    pub x_display: Option<String>,
    pub shared_dirs: Vec<SharedDir>,
    pub sandbox: bool,
    pub seccomp_policy_dir: PathBuf,
    pub seccomp_log_failures: bool,
    pub gpu: bool,
    pub software_tpm: bool,
    pub cras_audio: bool,
    pub cras_capture: bool,
    pub null_audio: bool,
    pub serial_parameters: BTreeMap<u8, SerialParameters>,
    pub syslog_tag: Option<String>,
    pub virtio_single_touch: Option<TouchDeviceOption>,
    pub virtio_trackpad: Option<TouchDeviceOption>,
    pub virtio_mouse: Option<PathBuf>,
    pub virtio_keyboard: Option<PathBuf>,
    pub virtio_input_evdevs: Vec<PathBuf>,
    pub split_irqchip: bool,
    pub vfio: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            vcpu_count: None,
            vcpu_affinity: Vec::new(),
            memory: None,
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
            host_ip: None,
            netmask: None,
            mac_address: None,
            vhost_net: false,
            tap_fd: Vec::new(),
            cid: None,
            gpu: false,
            software_tpm: false,
            wayland_socket_path: None,
            wayland_dmabuf: false,
            x_display: None,
            shared_dirs: Vec::new(),
            sandbox: !cfg!(feature = "default-no-sandbox"),
            seccomp_policy_dir: PathBuf::from(SECCOMP_POLICY_DIR),
            seccomp_log_failures: false,
            cras_audio: false,
            cras_capture: false,
            null_audio: false,
            serial_parameters: BTreeMap::new(),
            syslog_tag: None,
            virtio_single_touch: None,
            virtio_trackpad: None,
            virtio_mouse: None,
            virtio_keyboard: None,
            virtio_input_evdevs: Vec::new(),
            split_irqchip: false,
            vfio: None,
        }
    }
}
