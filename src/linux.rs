// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::cmp::min;
use std::convert::TryFrom;
use std::error::Error as StdError;
use std::ffi::CStr;
use std::fmt::{self, Display};
use std::fs::{File, OpenOptions};
use std::io::{self, stdin, Read};
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::{Arc, Barrier};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libc::{self, c_int, gid_t, uid_t};

use audio_streams::DummyStreamSource;
use devices::virtio::{self, VirtioDevice};
use devices::{self, HostBackendDeviceProvider, PciDevice, VirtioPciDevice, XhciController};
use io_jail::{self, Minijail};
use kvm::*;
use libcras::CrasClient;
use msg_socket::{MsgError, MsgReceiver, MsgSender, MsgSocket};
use net_util::{Error as NetError, MacAddress, Tap};
use qcow::{self, ImageType, QcowFile};
use rand_ish::SimpleRng;
use remain::sorted;
use resources::{Alloc, SystemAllocator};
use sync::{Condvar, Mutex};
use sys_util::net::{UnixSeqpacket, UnixSeqpacketListener, UnlinkUnixSeqpacketListener};

use sys_util::{
    self, block_signal, clear_signal, drop_capabilities, error, flock, get_blocked_signals,
    get_group_id, get_user_id, getegid, geteuid, info, register_signal_handler, set_cpu_affinity,
    validate_raw_fd, warn, EventFd, FlockOperation, GuestAddress, GuestMemory, Killable,
    MemoryMapping, PollContext, PollToken, Protection, SignalFd, Terminal, TimerFd, WatchingEvents,
    SIGRTMIN,
};
use vhost;
use vm_control::{
    BalloonControlCommand, BalloonControlRequestSocket, BalloonControlResponseSocket,
    DiskControlCommand, DiskControlRequestSocket, DiskControlResponseSocket, DiskControlResult,
    UsbControlSocket, VmControlResponseSocket, VmMemoryControlRequestSocket,
    VmMemoryControlResponseSocket, VmMemoryRequest, VmMemoryResponse, VmRunMode,
};

use crate::{Config, DiskOption, Executable, TouchDeviceOption};

use arch::{self, LinuxArch, RunnableLinuxVm, VirtioDeviceStub, VmComponents, VmImage};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use aarch64::AArch64 as Arch;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::X8664arch as Arch;

#[cfg(feature = "gpu-forward")]
use render_node_forward::*;
#[cfg(not(feature = "gpu-forward"))]
type RenderNodeHost = ();

#[sorted]
#[derive(Debug)]
pub enum Error {
    AddGpuDeviceMemory(sys_util::Error),
    AddPmemDeviceMemory(sys_util::Error),
    AllocateGpuDeviceAddress,
    AllocatePmemDeviceAddress(resources::Error),
    BalloonDeviceNew(virtio::BalloonError),
    BlockDeviceNew(sys_util::Error),
    BlockSignal(sys_util::signal::Error),
    BuildVm(<Arch as LinuxArch>::Error),
    ChownTpmStorage(sys_util::Error),
    CloneEventFd(sys_util::Error),
    CreateCrasClient(libcras::Error),
    CreateEventFd(sys_util::Error),
    CreatePollContext(sys_util::Error),
    CreateSignalFd(sys_util::SignalFdError),
    CreateSocket(io::Error),
    CreateTapDevice(NetError),
    CreateTimerFd(sys_util::Error),
    CreateTpmStorage(PathBuf, io::Error),
    CreateUsbProvider(devices::usb::host_backend::error::Error),
    DetectImageType(qcow::Error),
    DeviceJail(io_jail::Error),
    DevicePivotRoot(io_jail::Error),
    Disk(io::Error),
    DiskImageLock(sys_util::Error),
    DropCapabilities(sys_util::Error),
    InputDeviceNew(virtio::InputError),
    InputEventsOpen(std::io::Error),
    InvalidFdPath,
    InvalidWaylandPath,
    IoJail(io_jail::Error),
    LoadKernel(Box<dyn StdError>),
    NetDeviceNew(virtio::NetError),
    OpenAndroidFstab(PathBuf, io::Error),
    OpenBios(PathBuf, io::Error),
    OpenInitrd(PathBuf, io::Error),
    OpenKernel(PathBuf, io::Error),
    OpenVinput(PathBuf, io::Error),
    P9DeviceNew(virtio::P9Error),
    PivotRootDoesntExist(&'static str),
    PmemDeviceImageTooBig,
    PmemDeviceNew(sys_util::Error),
    PollContextAdd(sys_util::Error),
    PollContextDelete(sys_util::Error),
    QcowDeviceCreate(qcow::Error),
    ReadLowmemAvailable(io::Error),
    ReadLowmemMargin(io::Error),
    RegisterBalloon(arch::DeviceRegistrationError),
    RegisterBlock(arch::DeviceRegistrationError),
    RegisterGpu(arch::DeviceRegistrationError),
    RegisterNet(arch::DeviceRegistrationError),
    RegisterP9(arch::DeviceRegistrationError),
    RegisterRng(arch::DeviceRegistrationError),
    RegisterSignalHandler(sys_util::Error),
    RegisterWayland(arch::DeviceRegistrationError),
    ReserveGpuMemory(sys_util::MmapError),
    ReserveMemory(sys_util::Error),
    ReservePmemMemory(sys_util::MmapError),
    ResetTimerFd(sys_util::Error),
    RngDeviceNew(virtio::RngError),
    SettingGidMap(io_jail::Error),
    SettingUidMap(io_jail::Error),
    SignalFd(sys_util::SignalFdError),
    SpawnVcpu(io::Error),
    TimerFd(sys_util::Error),
    ValidateRawFd(sys_util::Error),
    VhostNetDeviceNew(virtio::vhost::Error),
    VhostVsockDeviceNew(virtio::vhost::Error),
    VirtioPciDev(sys_util::Error),
    WaylandDeviceNew(sys_util::Error),
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            AddGpuDeviceMemory(e) => write!(f, "failed to add gpu device memory: {}", e),
            AddPmemDeviceMemory(e) => write!(f, "failed to add pmem device memory: {}", e),
            AllocateGpuDeviceAddress => write!(f, "failed to allocate gpu device guest address"),
            AllocatePmemDeviceAddress(e) => {
                write!(f, "failed to allocate memory for pmem device: {}", e)
            }
            BalloonDeviceNew(e) => write!(f, "failed to create balloon: {}", e),
            BlockDeviceNew(e) => write!(f, "failed to create block device: {}", e),
            BlockSignal(e) => write!(f, "failed to block signal: {}", e),
            BuildVm(e) => write!(f, "The architecture failed to build the vm: {}", e),
            ChownTpmStorage(e) => write!(f, "failed to chown tpm storage: {}", e),
            CloneEventFd(e) => write!(f, "failed to clone eventfd: {}", e),
            CreateCrasClient(e) => write!(f, "failed to create cras client: {}", e),
            CreateEventFd(e) => write!(f, "failed to create eventfd: {}", e),
            CreatePollContext(e) => write!(f, "failed to create poll context: {}", e),
            CreateSignalFd(e) => write!(f, "failed to create signalfd: {}", e),
            CreateSocket(e) => write!(f, "failed to create socket: {}", e),
            CreateTapDevice(e) => write!(f, "failed to create tap device: {}", e),
            CreateTimerFd(e) => write!(f, "failed to create timerfd: {}", e),
            CreateTpmStorage(p, e) => {
                write!(f, "failed to create tpm storage dir {}: {}", p.display(), e)
            }
            CreateUsbProvider(e) => write!(f, "failed to create usb provider: {}", e),
            DetectImageType(e) => write!(f, "failed to detect disk image type: {}", e),
            DeviceJail(e) => write!(f, "failed to jail device: {}", e),
            DevicePivotRoot(e) => write!(f, "failed to pivot root device: {}", e),
            Disk(e) => write!(f, "failed to load disk image: {}", e),
            DiskImageLock(e) => write!(f, "failed to lock disk image: {}", e),
            DropCapabilities(e) => write!(f, "failed to drop process capabilities: {}", e),
            InputDeviceNew(e) => write!(f, "failed to set up input device: {}", e),
            InputEventsOpen(e) => write!(f, "failed to open event device: {}", e),
            InvalidFdPath => write!(f, "failed parsing a /proc/self/fd/*"),
            InvalidWaylandPath => write!(f, "wayland socket path has no parent or file name"),
            IoJail(e) => write!(f, "{}", e),
            LoadKernel(e) => write!(f, "failed to load kernel: {}", e),
            NetDeviceNew(e) => write!(f, "failed to set up virtio networking: {}", e),
            OpenAndroidFstab(p, e) => write!(
                f,
                "failed to open android fstab file {}: {}",
                p.display(),
                e
            ),
            OpenBios(p, e) => write!(f, "failed to open bios {}: {}", p.display(), e),
            OpenInitrd(p, e) => write!(f, "failed to open initrd {}: {}", p.display(), e),
            OpenKernel(p, e) => write!(f, "failed to open kernel image {}: {}", p.display(), e),
            OpenVinput(p, e) => write!(f, "failed to open vinput device {}: {}", p.display(), e),
            P9DeviceNew(e) => write!(f, "failed to create 9p device: {}", e),
            PivotRootDoesntExist(p) => write!(f, "{} doesn't exist, can't jail devices.", p),
            PmemDeviceImageTooBig => {
                write!(f, "failed to create pmem device: pmem device image too big")
            }
            PmemDeviceNew(e) => write!(f, "failed to create pmem device: {}", e),
            PollContextAdd(e) => write!(f, "failed to add fd to poll context: {}", e),
            PollContextDelete(e) => write!(f, "failed to remove fd from poll context: {}", e),
            QcowDeviceCreate(e) => write!(f, "failed to read qcow formatted file {}", e),
            ReadLowmemAvailable(e) => write!(
                f,
                "failed to read /sys/kernel/mm/chromeos-low_mem/available: {}",
                e
            ),
            ReadLowmemMargin(e) => write!(
                f,
                "failed to read /sys/kernel/mm/chromeos-low_mem/margin: {}",
                e
            ),
            RegisterBalloon(e) => write!(f, "error registering balloon device: {}", e),
            RegisterBlock(e) => write!(f, "error registering block device: {}", e),
            RegisterGpu(e) => write!(f, "error registering gpu device: {}", e),
            RegisterNet(e) => write!(f, "error registering net device: {}", e),
            RegisterP9(e) => write!(f, "error registering 9p device: {}", e),
            RegisterRng(e) => write!(f, "error registering rng device: {}", e),
            RegisterSignalHandler(e) => write!(f, "error registering signal handler: {}", e),
            RegisterWayland(e) => write!(f, "error registering wayland device: {}", e),
            ReserveGpuMemory(e) => write!(f, "failed to reserve gpu memory: {}", e),
            ReserveMemory(e) => write!(f, "failed to reserve memory: {}", e),
            ReservePmemMemory(e) => write!(f, "failed to reserve pmem memory: {}", e),
            ResetTimerFd(e) => write!(f, "failed to reset timerfd: {}", e),
            RngDeviceNew(e) => write!(f, "failed to set up rng: {}", e),
            SettingGidMap(e) => write!(f, "error setting GID map: {}", e),
            SettingUidMap(e) => write!(f, "error setting UID map: {}", e),
            SignalFd(e) => write!(f, "failed to read signal fd: {}", e),
            SpawnVcpu(e) => write!(f, "failed to spawn VCPU thread: {}", e),
            TimerFd(e) => write!(f, "failed to read timer fd: {}", e),
            ValidateRawFd(e) => write!(f, "failed to validate raw fd: {}", e),
            VhostNetDeviceNew(e) => write!(f, "failed to set up vhost networking: {}", e),
            VhostVsockDeviceNew(e) => write!(f, "failed to set up virtual socket device: {}", e),
            VirtioPciDev(e) => write!(f, "failed to create virtio pci dev: {}", e),
            WaylandDeviceNew(e) => write!(f, "failed to create wayland device: {}", e),
        }
    }
}

impl From<io_jail::Error> for Error {
    fn from(err: io_jail::Error) -> Self {
        Error::IoJail(err)
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

enum TaggedControlSocket {
    Vm(VmControlResponseSocket),
    VmMemory(VmMemoryControlResponseSocket),
}

impl AsRef<UnixSeqpacket> for TaggedControlSocket {
    fn as_ref(&self) -> &UnixSeqpacket {
        use self::TaggedControlSocket::*;
        match &self {
            Vm(ref socket) => socket,
            VmMemory(ref socket) => socket,
        }
    }
}

impl AsRawFd for TaggedControlSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.as_ref().as_raw_fd()
    }
}

fn create_base_minijail(root: &Path, seccomp_policy: &Path) -> Result<Minijail> {
    // All child jails run in a new user namespace without any users mapped,
    // they run as nobody unless otherwise configured.
    let mut j = Minijail::new().map_err(Error::DeviceJail)?;
    j.namespace_pids();
    j.namespace_user();
    j.namespace_user_disable_setgroups();
    // Don't need any capabilities.
    j.use_caps(0);
    // Create a new mount namespace with an empty root FS.
    j.namespace_vfs();
    j.enter_pivot_root(root).map_err(Error::DevicePivotRoot)?;
    // Run in an empty network namespace.
    j.namespace_net();
    // Apply the block device seccomp policy.
    j.no_new_privs();
    // Use TSYNC only for the side effect of it using SECCOMP_RET_TRAP, which will correctly kill
    // the entire device process if a worker thread commits a seccomp violation.
    j.set_seccomp_filter_tsync();
    #[cfg(debug_assertions)]
    j.log_seccomp_filter_failures();
    j.parse_seccomp_filters(seccomp_policy)
        .map_err(Error::DeviceJail)?;
    j.use_seccomp_filter();
    // Don't do init setup.
    j.run_as_init();
    Ok(j)
}

fn simple_jail(cfg: &Config, policy: &str) -> Result<Option<Minijail>> {
    if cfg.sandbox {
        let pivot_root: &str = option_env!("DEFAULT_PIVOT_ROOT").unwrap_or("/var/empty");
        // A directory for a jailed device's pivot root.
        let root_path = Path::new(pivot_root);
        if !root_path.exists() {
            return Err(Error::PivotRootDoesntExist(pivot_root));
        }
        let policy_path: PathBuf = cfg.seccomp_policy_dir.join(policy);
        Ok(Some(create_base_minijail(root_path, &policy_path)?))
    } else {
        Ok(None)
    }
}

type DeviceResult<T = VirtioDeviceStub> = std::result::Result<T, Error>;

fn create_block_device(
    cfg: &Config,
    disk: &DiskOption,
    disk_device_socket: DiskControlResponseSocket,
) -> DeviceResult {
    // Special case '/proc/self/fd/*' paths. The FD is already open, just use it.
    let raw_image: File = if disk.path.parent() == Some(Path::new("/proc/self/fd")) {
        // Safe because we will validate |raw_fd|.
        unsafe { File::from_raw_fd(raw_fd_from_path(&disk.path)?) }
    } else {
        OpenOptions::new()
            .read(true)
            .write(!disk.read_only)
            .open(&disk.path)
            .map_err(Error::Disk)?
    };
    // Lock the disk image to prevent other crosvm instances from using it.
    let lock_op = if disk.read_only {
        FlockOperation::LockShared
    } else {
        FlockOperation::LockExclusive
    };
    flock(&raw_image, lock_op, true).map_err(Error::DiskImageLock)?;

    let image_type = qcow::detect_image_type(&raw_image).map_err(Error::DetectImageType)?;
    let dev = match image_type {
        ImageType::Raw => {
            // Access as a raw block device.
            let dev = virtio::Block::new(raw_image, disk.read_only, Some(disk_device_socket))
                .map_err(Error::BlockDeviceNew)?;
            Box::new(dev) as Box<dyn VirtioDevice>
        }
        ImageType::Qcow2 => {
            // Valid qcow header present
            let qcow_image = QcowFile::from(raw_image).map_err(Error::QcowDeviceCreate)?;
            let dev = virtio::Block::new(qcow_image, disk.read_only, Some(disk_device_socket))
                .map_err(Error::BlockDeviceNew)?;
            Box::new(dev) as Box<dyn VirtioDevice>
        }
    };

    Ok(VirtioDeviceStub {
        dev,
        jail: simple_jail(&cfg, "block_device.policy")?,
    })
}

fn create_rng_device(cfg: &Config) -> DeviceResult {
    let dev = virtio::Rng::new().map_err(Error::RngDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "rng_device.policy")?,
    })
}

#[cfg(feature = "tpm")]
fn create_tpm_device(cfg: &Config) -> DeviceResult {
    use std::ffi::CString;
    use std::fs;
    use std::process;
    use sys_util::chown;

    let tpm_storage: PathBuf;
    let mut tpm_jail = simple_jail(&cfg, "tpm_device.policy")?;

    match &mut tpm_jail {
        Some(jail) => {
            // Create a tmpfs in the device's root directory for tpm
            // simulator storage. The size is 20*1024, or 20 KB.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=20480",
            )?;

            let crosvm_ids = add_crosvm_user_to_jail(jail, "tpm")?;

            let pid = process::id();
            let tpm_pid_dir = format!("/run/vm/tpm.{}", pid);
            tpm_storage = Path::new(&tpm_pid_dir).to_owned();
            fs::create_dir_all(&tpm_storage)
                .map_err(|e| Error::CreateTpmStorage(tpm_storage.to_owned(), e))?;
            let tpm_pid_dir_c = CString::new(tpm_pid_dir).expect("no nul bytes");
            chown(&tpm_pid_dir_c, crosvm_ids.uid, crosvm_ids.gid)
                .map_err(Error::ChownTpmStorage)?;

            jail.mount_bind(&tpm_storage, &tpm_storage, true)?;
        }
        None => {
            // Path used inside cros_sdk which does not have /run/vm.
            tpm_storage = Path::new("/tmp/tpm-simulator").to_owned();
        }
    }

    let dev = virtio::Tpm::new(tpm_storage);

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: tpm_jail,
    })
}

fn create_single_touch_device(cfg: &Config, single_touch_spec: &TouchDeviceOption) -> DeviceResult {
    let socket = create_input_socket(&single_touch_spec.path).map_err(|e| {
        error!("failed configuring virtio single touch: {:?}", e);
        e
    })?;

    let dev = virtio::new_single_touch(socket, single_touch_spec.width, single_touch_spec.height)
        .map_err(Error::InputDeviceNew)?;
    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device.policy")?,
    })
}

fn create_trackpad_device(cfg: &Config, trackpad_spec: &TouchDeviceOption) -> DeviceResult {
    let socket = create_input_socket(&trackpad_spec.path).map_err(|e| {
        error!("failed configuring virtio trackpad: {}", e);
        e
    })?;

    let dev = virtio::new_trackpad(socket, trackpad_spec.width, trackpad_spec.height)
        .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device.policy")?,
    })
}

fn create_mouse_device(cfg: &Config, mouse_socket: &Path) -> DeviceResult {
    let socket = create_input_socket(&mouse_socket).map_err(|e| {
        error!("failed configuring virtio mouse: {}", e);
        e
    })?;

    let dev = virtio::new_mouse(socket).map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device.policy")?,
    })
}

fn create_keyboard_device(cfg: &Config, keyboard_socket: &Path) -> DeviceResult {
    let socket = create_input_socket(&keyboard_socket).map_err(|e| {
        error!("failed configuring virtio keyboard: {}", e);
        e
    })?;

    let dev = virtio::new_keyboard(socket).map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device.policy")?,
    })
}

fn create_vinput_device(cfg: &Config, dev_path: &Path) -> DeviceResult {
    let dev_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .map_err(|e| Error::OpenVinput(dev_path.to_owned(), e))?;

    let dev = virtio::new_evdev(dev_file).map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device.policy")?,
    })
}

fn create_balloon_device(cfg: &Config, socket: BalloonControlResponseSocket) -> DeviceResult {
    let dev = virtio::Balloon::new(socket).map_err(Error::BalloonDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "balloon_device.policy")?,
    })
}

fn create_tap_net_device(cfg: &Config, tap_fd: RawFd) -> DeviceResult {
    // Safe because we ensure that we get a unique handle to the fd.
    let tap = unsafe {
        Tap::from_raw_fd(validate_raw_fd(tap_fd).map_err(Error::ValidateRawFd)?)
            .map_err(Error::CreateTapDevice)?
    };

    let dev = virtio::Net::from(tap).map_err(Error::NetDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "net_device.policy")?,
    })
}

fn create_net_device(
    cfg: &Config,
    host_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mac_address: MacAddress,
    mem: &GuestMemory,
) -> DeviceResult {
    let dev = if cfg.vhost_net {
        let dev =
            virtio::vhost::Net::<Tap, vhost::Net<Tap>>::new(host_ip, netmask, mac_address, mem)
                .map_err(Error::VhostNetDeviceNew)?;
        Box::new(dev) as Box<dyn VirtioDevice>
    } else {
        let dev =
            virtio::Net::<Tap>::new(host_ip, netmask, mac_address).map_err(Error::NetDeviceNew)?;
        Box::new(dev) as Box<dyn VirtioDevice>
    };

    let policy = if cfg.vhost_net {
        "vhost_net_device.policy"
    } else {
        "net_device.policy"
    };

    Ok(VirtioDeviceStub {
        dev,
        jail: simple_jail(&cfg, policy)?,
    })
}

#[cfg(feature = "gpu")]
fn create_gpu_device(
    cfg: &Config,
    exit_evt: &EventFd,
    gpu_device_socket: VmMemoryControlRequestSocket,
    gpu_socket: virtio::resource_bridge::ResourceResponseSocket,
    wayland_socket_path: &Path,
) -> DeviceResult {
    let jailed_wayland_path = Path::new("/wayland-0");

    let dev = virtio::Gpu::new(
        exit_evt.try_clone().map_err(Error::CloneEventFd)?,
        Some(gpu_device_socket),
        Some(gpu_socket),
        if cfg.sandbox {
            &jailed_wayland_path
        } else {
            wayland_socket_path
        },
    );

    let jail = match simple_jail(&cfg, "gpu_device.policy")? {
        Some(mut jail) => {
            // Create a tmpfs in the device's root directory so that we can bind mount the
            // dri directory into it.  The size=67108864 is size=64*1024*1024 or size=64MB.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=67108864",
            )?;

            // Device nodes required for DRM.
            let sys_dev_char_path = Path::new("/sys/dev/char");
            jail.mount_bind(sys_dev_char_path, sys_dev_char_path, false)?;
            let sys_devices_path = Path::new("/sys/devices");
            jail.mount_bind(sys_devices_path, sys_devices_path, false)?;
            let drm_dri_path = Path::new("/dev/dri");
            jail.mount_bind(drm_dri_path, drm_dri_path, false)?;

            // Libraries that are required when mesa drivers are dynamically loaded.
            let lib_path = Path::new("/lib64");
            jail.mount_bind(lib_path, lib_path, false)?;
            let usr_lib_path = Path::new("/usr/lib64");
            jail.mount_bind(usr_lib_path, usr_lib_path, false)?;

            // Bind mount the wayland socket into jail's root. This is necessary since each
            // new wayland context must open() the socket.
            jail.mount_bind(wayland_socket_path, jailed_wayland_path, true)?;

            add_crosvm_user_to_jail(&mut jail, "gpu")?;

            Some(jail)
        }
        None => None,
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

fn create_wayland_device(
    cfg: &Config,
    socket_path: &Path,
    socket: VmMemoryControlRequestSocket,
    resource_bridge: Option<virtio::resource_bridge::ResourceRequestSocket>,
) -> DeviceResult {
    let wayland_socket_dir = socket_path.parent().ok_or(Error::InvalidWaylandPath)?;
    let wayland_socket_name = socket_path.file_name().ok_or(Error::InvalidWaylandPath)?;
    let jailed_wayland_dir = Path::new("/wayland");
    let jailed_wayland_path = jailed_wayland_dir.join(wayland_socket_name);

    let dev = virtio::Wl::new(
        if cfg.sandbox {
            &jailed_wayland_path
        } else {
            socket_path
        },
        socket,
        resource_bridge,
    )
    .map_err(Error::WaylandDeviceNew)?;

    let jail = match simple_jail(&cfg, "wl_device.policy")? {
        Some(mut jail) => {
            // Create a tmpfs in the device's root directory so that we can bind mount the wayland
            // socket directory into it. The size=67108864 is size=64*1024*1024 or size=64MB.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=67108864",
            )?;

            // Bind mount the wayland socket's directory into jail's root. This is necessary since
            // each new wayland context must open() the socket. If the wayland socket is ever
            // destroyed and remade in the same host directory, new connections will be possible
            // without restarting the wayland device.
            jail.mount_bind(wayland_socket_dir, jailed_wayland_dir, true)?;

            add_crosvm_user_to_jail(&mut jail, "Wayland")?;

            Some(jail)
        }
        None => None,
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

fn create_vhost_vsock_device(cfg: &Config, cid: u64, mem: &GuestMemory) -> DeviceResult {
    let dev = virtio::vhost::Vsock::new(cid, mem).map_err(Error::VhostVsockDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "vhost_vsock_device.policy")?,
    })
}

fn create_9p_device(cfg: &Config, chronos: Ids, src: &Path, tag: &str) -> DeviceResult {
    let (jail, root) = match simple_jail(&cfg, "9p_device.policy")? {
        Some(mut jail) => {
            //  The shared directory becomes the root of the device's file system.
            let root = Path::new("/");
            jail.mount_bind(src, root, true)?;

            // Set the uid/gid for the jailed process, and give a basic id map. This
            // is required for the above bind mount to work.
            jail.change_uid(chronos.uid);
            jail.change_gid(chronos.gid);
            jail.uidmap(&format!("{0} {0} 1", chronos.uid))
                .map_err(Error::SettingUidMap)?;
            jail.gidmap(&format!("{0} {0} 1", chronos.gid))
                .map_err(Error::SettingGidMap)?;

            (Some(jail), root)
        }
        None => {
            // There's no bind mount so we tell the server to treat the source directory as the
            // root.
            (None, src)
        }
    };

    let dev = virtio::P9::new(root, tag).map_err(Error::P9DeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

fn create_pmem_device(
    cfg: &Config,
    vm: &mut Vm,
    resources: &mut SystemAllocator,
    disk: &DiskOption,
    index: usize,
) -> DeviceResult {
    let fd = OpenOptions::new()
        .read(true)
        .write(!disk.read_only)
        .open(&disk.path)
        .map_err(Error::Disk)?;

    let image_size = {
        let metadata = std::fs::metadata(&disk.path).map_err(Error::Disk)?;
        metadata.len()
    };

    let protection = {
        if disk.read_only {
            Protection::read()
        } else {
            Protection::read_write()
        }
    };

    let memory_mapping = {
        // Conversion from u64 to usize may fail on 32bit system.
        let image_size = usize::try_from(image_size).map_err(|_| Error::PmemDeviceImageTooBig)?;

        MemoryMapping::from_fd_offset_protection(&fd, image_size, 0, protection)
            .map_err(Error::ReservePmemMemory)?
    };

    let mapping_address = resources
        .device_allocator()
        .allocate_with_align(
            image_size,
            Alloc::PmemDevice(index),
            format!("pmem_disk_image_{}", index),
            // Linux kernel requires pmem namespaces to be 128 MiB aligned.
            128 * 1024 * 1024, /* 128 MiB */
        )
        .map_err(Error::AllocatePmemDeviceAddress)?;

    vm.add_device_memory(
        GuestAddress(mapping_address),
        memory_mapping,
        /* read_only = */ disk.read_only,
        /* log_dirty_pages = */ false,
    )
    .map_err(Error::AddPmemDeviceMemory)?;

    let dev = virtio::Pmem::new(fd, GuestAddress(mapping_address), image_size)
        .map_err(Error::PmemDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev) as Box<dyn VirtioDevice>,
        /// TODO(jstaron) Create separate device policy for pmem_device.
        jail: simple_jail(&cfg, "block_device.policy")?,
    })
}

// gpu_device_socket is not used when GPU support is disabled.
#[cfg_attr(not(feature = "gpu"), allow(unused_variables))]
fn create_virtio_devices(
    cfg: &Config,
    mem: &GuestMemory,
    vm: &mut Vm,
    resources: &mut SystemAllocator,
    _exit_evt: &EventFd,
    wayland_device_socket: VmMemoryControlRequestSocket,
    gpu_device_socket: VmMemoryControlRequestSocket,
    balloon_device_socket: BalloonControlResponseSocket,
    disk_device_sockets: &mut Vec<DiskControlResponseSocket>,
) -> DeviceResult<Vec<VirtioDeviceStub>> {
    let mut devs = Vec::new();

    for disk in &cfg.disks {
        let disk_device_socket = disk_device_sockets.remove(0);
        devs.push(create_block_device(cfg, disk, disk_device_socket)?);
    }

    for (index, pmem_disk) in cfg.pmem_devices.iter().enumerate() {
        devs.push(create_pmem_device(cfg, vm, resources, pmem_disk, index)?);
    }

    devs.push(create_rng_device(cfg)?);

    #[cfg(feature = "tpm")]
    {
        if cfg.software_tpm {
            devs.push(create_tpm_device(cfg)?);
        }
    }

    if let Some(single_touch_spec) = &cfg.virtio_single_touch {
        devs.push(create_single_touch_device(cfg, single_touch_spec)?);
    }

    if let Some(trackpad_spec) = &cfg.virtio_trackpad {
        devs.push(create_trackpad_device(cfg, trackpad_spec)?);
    }

    if let Some(mouse_socket) = &cfg.virtio_mouse {
        devs.push(create_mouse_device(cfg, mouse_socket)?);
    }

    if let Some(keyboard_socket) = &cfg.virtio_keyboard {
        devs.push(create_keyboard_device(cfg, keyboard_socket)?);
    }

    for dev_path in &cfg.virtio_input_evdevs {
        devs.push(create_vinput_device(cfg, dev_path)?);
    }

    devs.push(create_balloon_device(cfg, balloon_device_socket)?);

    // We checked above that if the IP is defined, then the netmask is, too.
    for tap_fd in &cfg.tap_fd {
        devs.push(create_tap_net_device(cfg, *tap_fd)?);
    }

    if let (Some(host_ip), Some(netmask), Some(mac_address)) =
        (cfg.host_ip, cfg.netmask, cfg.mac_address)
    {
        devs.push(create_net_device(cfg, host_ip, netmask, mac_address, mem)?);
    }

    #[cfg_attr(not(feature = "gpu"), allow(unused_mut))]
    let mut resource_bridge_wl_socket = None::<virtio::resource_bridge::ResourceRequestSocket>;

    #[cfg(feature = "gpu")]
    {
        if cfg.gpu {
            if let Some(wayland_socket_path) = &cfg.wayland_socket_path {
                let (wl_socket, gpu_socket) =
                    virtio::resource_bridge::pair().map_err(Error::CreateSocket)?;
                resource_bridge_wl_socket = Some(wl_socket);

                devs.push(create_gpu_device(
                    cfg,
                    _exit_evt,
                    gpu_device_socket,
                    gpu_socket,
                    wayland_socket_path,
                )?);
            }
        }
    }

    if let Some(wayland_socket_path) = cfg.wayland_socket_path.as_ref() {
        devs.push(create_wayland_device(
            cfg,
            wayland_socket_path,
            wayland_device_socket,
            resource_bridge_wl_socket,
        )?);
    }

    if let Some(cid) = cfg.cid {
        devs.push(create_vhost_vsock_device(cfg, cid, mem)?);
    }

    let chronos = get_chronos_ids();

    for (src, tag) in &cfg.shared_dirs {
        devs.push(create_9p_device(cfg, chronos, src, tag)?);
    }

    Ok(devs)
}

fn create_devices(
    cfg: &Config,
    mem: &GuestMemory,
    vm: &mut Vm,
    resources: &mut SystemAllocator,
    exit_evt: &EventFd,
    wayland_device_socket: VmMemoryControlRequestSocket,
    gpu_device_socket: VmMemoryControlRequestSocket,
    balloon_device_socket: BalloonControlResponseSocket,
    disk_device_sockets: &mut Vec<DiskControlResponseSocket>,
    usb_provider: HostBackendDeviceProvider,
) -> DeviceResult<Vec<(Box<dyn PciDevice>, Option<Minijail>)>> {
    let stubs = create_virtio_devices(
        &cfg,
        mem,
        vm,
        resources,
        exit_evt,
        wayland_device_socket,
        gpu_device_socket,
        balloon_device_socket,
        disk_device_sockets,
    )?;

    let mut pci_devices = Vec::new();

    for stub in stubs {
        let dev = VirtioPciDevice::new(mem.clone(), stub.dev).map_err(Error::VirtioPciDev)?;
        let dev = Box::new(dev) as Box<dyn PciDevice>;
        pci_devices.push((dev, stub.jail));
    }

    if cfg.cras_audio {
        let mut server = Box::new(CrasClient::new().map_err(Error::CreateCrasClient)?);
        if cfg.cras_capture {
            server.enable_cras_capture();
        }
        let cras_audio = devices::Ac97Dev::new(mem.clone(), server);

        pci_devices.push((
            Box::new(cras_audio),
            simple_jail(&cfg, "cras_audio_device.policy")?,
        ));
    }

    if cfg.null_audio {
        let server = Box::new(DummyStreamSource::new());
        let null_audio = devices::Ac97Dev::new(mem.clone(), server);

        pci_devices.push((
            Box::new(null_audio),
            simple_jail(&cfg, "null_audio_device.policy")?,
        ));
    }
    // Create xhci controller.
    let usb_controller = Box::new(XhciController::new(mem.clone(), usb_provider));
    pci_devices.push((usb_controller, simple_jail(&cfg, "xhci.policy")?));

    Ok(pci_devices)
}

#[derive(Copy, Clone)]
struct Ids {
    uid: uid_t,
    gid: gid_t,
}

fn get_chronos_ids() -> Ids {
    let chronos_user_group = CStr::from_bytes_with_nul(b"chronos\0").unwrap();

    let chronos_uid = match get_user_id(&chronos_user_group) {
        Ok(u) => u,
        Err(e) => {
            warn!("falling back to current user id for 9p: {}", e);
            geteuid()
        }
    };

    let chronos_gid = match get_group_id(&chronos_user_group) {
        Ok(u) => u,
        Err(e) => {
            warn!("falling back to current group id for 9p: {}", e);
            getegid()
        }
    };

    Ids {
        uid: chronos_uid,
        gid: chronos_gid,
    }
}

// Set the uid/gid for the jailed process and give a basic id map. This is
// required for bind mounts to work.
fn add_crosvm_user_to_jail(jail: &mut Minijail, feature: &str) -> Result<Ids> {
    let crosvm_user_group = CStr::from_bytes_with_nul(b"crosvm\0").unwrap();

    let crosvm_uid = match get_user_id(&crosvm_user_group) {
        Ok(u) => u,
        Err(e) => {
            warn!("falling back to current user id for {}: {}", feature, e);
            geteuid()
        }
    };

    let crosvm_gid = match get_group_id(&crosvm_user_group) {
        Ok(u) => u,
        Err(e) => {
            warn!("falling back to current group id for {}: {}", feature, e);
            getegid()
        }
    };

    jail.change_uid(crosvm_uid);
    jail.change_gid(crosvm_gid);
    jail.uidmap(&format!("{0} {0} 1", crosvm_uid))
        .map_err(Error::SettingUidMap)?;
    jail.gidmap(&format!("{0} {0} 1", crosvm_gid))
        .map_err(Error::SettingGidMap)?;

    Ok(Ids {
        uid: crosvm_uid,
        gid: crosvm_gid,
    })
}

fn raw_fd_from_path(path: &Path) -> Result<RawFd> {
    if !path.is_file() {
        return Err(Error::InvalidFdPath);
    }
    let raw_fd = path
        .file_name()
        .and_then(|fd_osstr| fd_osstr.to_str())
        .and_then(|fd_str| fd_str.parse::<c_int>().ok())
        .ok_or(Error::InvalidFdPath)?;
    validate_raw_fd(raw_fd).map_err(Error::ValidateRawFd)
}

fn create_input_socket(path: &Path) -> Result<UnixStream> {
    if path.parent() == Some(Path::new("/proc/self/fd")) {
        // Safe because we will validate |raw_fd|.
        unsafe { Ok(UnixStream::from_raw_fd(raw_fd_from_path(path)?)) }
    } else {
        UnixStream::connect(path).map_err(Error::InputEventsOpen)
    }
}

fn setup_vcpu_signal_handler() -> Result<()> {
    unsafe {
        extern "C" fn handle_signal() {}
        // Our signal handler does nothing and is trivially async signal safe.
        register_signal_handler(SIGRTMIN() + 0, handle_signal)
            .map_err(Error::RegisterSignalHandler)?;
    }
    block_signal(SIGRTMIN() + 0).map_err(Error::BlockSignal)?;
    Ok(())
}

#[derive(Default)]
struct VcpuRunMode {
    mtx: Mutex<VmRunMode>,
    cvar: Condvar,
}

impl VcpuRunMode {
    fn set_and_notify(&self, new_mode: VmRunMode) {
        *self.mtx.lock() = new_mode;
        self.cvar.notify_all();
    }
}

fn run_vcpu(
    vcpu: Vcpu,
    cpu_id: u32,
    vcpu_affinity: Vec<usize>,
    start_barrier: Arc<Barrier>,
    io_bus: devices::Bus,
    mmio_bus: devices::Bus,
    exit_evt: EventFd,
    requires_kvmclock_ctrl: bool,
    run_mode_arc: Arc<VcpuRunMode>,
) -> Result<JoinHandle<()>> {
    thread::Builder::new()
        .name(format!("crosvm_vcpu{}", cpu_id))
        .spawn(move || {
            if vcpu_affinity.len() != 0 {
                if let Err(e) = set_cpu_affinity(vcpu_affinity) {
                    error!("Failed to set CPU affinity: {}", e);
                }
            }

            let mut sig_ok = true;
            match get_blocked_signals() {
                Ok(mut v) => {
                    v.retain(|&x| x != SIGRTMIN() + 0);
                    if let Err(e) = vcpu.set_signal_mask(&v) {
                        error!(
                            "Failed to set the KVM_SIGNAL_MASK for vcpu {} : {}",
                            cpu_id, e
                        );
                        sig_ok = false;
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to retrieve signal mask for vcpu {} : {}",
                        cpu_id, e
                    );
                    sig_ok = false;
                }
            };

            start_barrier.wait();

            if sig_ok {
                'vcpu_loop: loop {
                    let mut interrupted_by_signal = false;
                    match vcpu.run() {
                        Ok(VcpuExit::IoIn { port, mut size }) => {
                            let mut data = [0; 8];
                            if size > data.len() {
                                error!("unsupported IoIn size of {} bytes", size);
                                size = data.len();
                            }
                            io_bus.read(port as u64, &mut data[..size]);
                            if let Err(e) = vcpu.set_data(&data[..size]) {
                                error!("failed to set return data for IoIn: {}", e);
                            }
                        }
                        Ok(VcpuExit::IoOut {
                            port,
                            mut size,
                            data,
                        }) => {
                            if size > data.len() {
                                error!("unsupported IoOut size of {} bytes", size);
                                size = data.len();
                            }
                            io_bus.write(port as u64, &data[..size]);
                        }
                        Ok(VcpuExit::MmioRead { address, size }) => {
                            let mut data = [0; 8];
                            mmio_bus.read(address, &mut data[..size]);
                            // Setting data for mmio can not fail.
                            let _ = vcpu.set_data(&data[..size]);
                        }
                        Ok(VcpuExit::MmioWrite {
                            address,
                            size,
                            data,
                        }) => {
                            mmio_bus.write(address, &data[..size]);
                        }
                        Ok(VcpuExit::Hlt) => break,
                        Ok(VcpuExit::Shutdown) => break,
                        Ok(VcpuExit::SystemEvent(_, _)) => break,
                        Ok(r) => warn!("unexpected vcpu exit: {:?}", r),
                        Err(e) => match e.errno() {
                            libc::EINTR => interrupted_by_signal = true,
                            libc::EAGAIN => {}
                            _ => {
                                error!("vcpu hit unknown error: {}", e);
                                break;
                            }
                        },
                    }

                    if interrupted_by_signal {
                        // Try to clear the signal that we use to kick VCPU if it is pending before
                        // attempting to handle pause requests.
                        if let Err(e) = clear_signal(SIGRTMIN() + 0) {
                            error!("failed to clear pending signal: {}", e);
                            break;
                        }
                        let mut run_mode_lock = run_mode_arc.mtx.lock();
                        loop {
                            match *run_mode_lock {
                                VmRunMode::Running => break,
                                VmRunMode::Suspending => {
                                    // On KVM implementations that use a paravirtualized clock (e.g.
                                    // x86), a flag must be set to indicate to the guest kernel that
                                    // a VCPU was suspended. The guest kernel will use this flag to
                                    // prevent the soft lockup detection from triggering when this
                                    // VCPU resumes, which could happen days later in realtime.
                                    if requires_kvmclock_ctrl {
                                        if let Err(e) = vcpu.kvmclock_ctrl() {
                                            error!("failed to signal to kvm that vcpu {} is being suspended: {}", cpu_id, e);
                                        }
                                    }
                                }
                                VmRunMode::Exiting => break 'vcpu_loop,
                            }
                            // Give ownership of our exclusive lock to the condition variable that
                            // will block. When the condition variable is notified, `wait` will
                            // unblock and return a new exclusive lock.
                            run_mode_lock = run_mode_arc.cvar.wait(run_mode_lock);
                        }
                    }
                }
            }
            exit_evt
                .write(1)
                .expect("failed to signal vcpu exit eventfd");
        })
        .map_err(Error::SpawnVcpu)
}

// Reads the contents of a file and converts the space-separated fields into a Vec of u64s.
// Returns an error if any of the fields fail to parse.
fn file_fields_to_u64<P: AsRef<Path>>(path: P) -> io::Result<Vec<u64>> {
    let mut file = File::open(path)?;

    let mut buf = [0u8; 32];
    let count = file.read(&mut buf)?;

    let content =
        str::from_utf8(&buf[..count]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    content
        .trim()
        .split_whitespace()
        .map(|x| {
            x.parse::<u64>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
        .collect()
}

// Reads the contents of a file and converts them into a u64, and if there
// are multiple fields it only returns the first one.
fn file_to_u64<P: AsRef<Path>>(path: P) -> io::Result<u64> {
    file_fields_to_u64(path)?
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty file"))
}

pub fn run_config(cfg: Config) -> Result<()> {
    if cfg.sandbox {
        // Printing something to the syslog before entering minijail so that libc's syslogger has a
        // chance to open files necessary for its operation, like `/etc/localtime`. After jailing,
        // access to those files will not be possible.
        info!("crosvm entering multiprocess mode");
    }

    let (usb_control_socket, usb_provider) =
        HostBackendDeviceProvider::new().map_err(Error::CreateUsbProvider)?;
    // Masking signals is inherently dangerous, since this can persist across clones/execs. Do this
    // before any jailed devices have been spawned, so that we can catch any of them that fail very
    // quickly.
    let sigchld_fd = SignalFd::new(libc::SIGCHLD).map_err(Error::CreateSignalFd)?;

    let initrd_image = if let Some(initrd_path) = &cfg.initrd_path {
        Some(File::open(initrd_path).map_err(|e| Error::OpenInitrd(initrd_path.clone(), e))?)
    } else {
        None
    };

    let vm_image = match cfg.executable_path {
        Some(Executable::Kernel(ref kernel_path)) => VmImage::Kernel(
            File::open(kernel_path).map_err(|e| Error::OpenKernel(kernel_path.to_path_buf(), e))?,
        ),
        Some(Executable::Bios(ref bios_path)) => VmImage::Bios(
            File::open(bios_path).map_err(|e| Error::OpenBios(bios_path.to_path_buf(), e))?,
        ),
        _ => panic!("Did not receive a bios or kernel, should be impossible."),
    };

    let components = VmComponents {
        memory_size: (cfg.memory.unwrap_or(256) << 20) as u64,
        vcpu_count: cfg.vcpu_count.unwrap_or(1),
        vcpu_affinity: cfg.vcpu_affinity.clone(),
        vm_image,
        android_fstab: cfg
            .android_fstab
            .as_ref()
            .map(|x| File::open(x).map_err(|e| Error::OpenAndroidFstab(x.to_path_buf(), e)))
            .map_or(Ok(None), |v| v.map(Some))?,
        initrd_image,
        extra_kernel_params: cfg.params.clone(),
        wayland_dmabuf: cfg.wayland_dmabuf,
    };

    let control_server_socket = match &cfg.socket_path {
        Some(path) => Some(UnlinkUnixSeqpacketListener(
            UnixSeqpacketListener::bind(path).map_err(Error::CreateSocket)?,
        )),
        None => None,
    };

    let mut control_sockets = Vec::new();
    let (wayland_host_socket, wayland_device_socket) =
        msg_socket::pair::<VmMemoryResponse, VmMemoryRequest>().map_err(Error::CreateSocket)?;
    control_sockets.push(TaggedControlSocket::VmMemory(wayland_host_socket));
    // Balloon gets a special socket so balloon requests can be forwarded from the main process.
    let (balloon_host_socket, balloon_device_socket) =
        msg_socket::pair::<BalloonControlCommand, ()>().map_err(Error::CreateSocket)?;

    // Create one control socket per disk.
    let mut disk_device_sockets = Vec::new();
    let mut disk_host_sockets = Vec::new();
    let disk_count = cfg.disks.len();
    for _ in 0..disk_count {
        let (disk_host_socket, disk_device_socket) =
            msg_socket::pair::<DiskControlCommand, DiskControlResult>()
                .map_err(Error::CreateSocket)?;
        disk_host_sockets.push(disk_host_socket);
        disk_device_sockets.push(disk_device_socket);
    }

    let (gpu_host_socket, gpu_device_socket) =
        msg_socket::pair::<VmMemoryResponse, VmMemoryRequest>().map_err(Error::CreateSocket)?;
    control_sockets.push(TaggedControlSocket::VmMemory(gpu_host_socket));

    let sandbox = cfg.sandbox;
    let linux = Arch::build_vm(
        components,
        cfg.split_irqchip,
        &cfg.serial_parameters,
        |mem, vm, sys_allocator, exit_evt| {
            create_devices(
                &cfg,
                mem,
                vm,
                sys_allocator,
                exit_evt,
                wayland_device_socket,
                gpu_device_socket,
                balloon_device_socket,
                &mut disk_device_sockets,
                usb_provider,
            )
        },
    )
    .map_err(Error::BuildVm)?;

    let _render_node_host = ();
    #[cfg(feature = "gpu-forward")]
    let (_render_node_host, linux) = {
        // Rebinds linux as mutable.
        let mut linux = linux;

        // Reserve memory range for GPU buffer allocation in advance to bypass region count
        // limitation. We use mremap/MAP_FIXED later to make sure GPU buffers fall into this range.
        let gpu_mmap =
            MemoryMapping::new_protection(RENDER_NODE_HOST_SIZE as usize, Protection::none())
                .map_err(Error::ReserveGpuMemory)?;

        // Put the non-accessible memory map into device memory so that no other devices use that
        // guest address space.
        let gpu_addr = linux
            .resources
            .device_allocator()
            .allocate(
                RENDER_NODE_HOST_SIZE,
                Alloc::GpuRenderNode,
                "gpu_render_node".to_string(),
            )
            .map_err(|_| Error::AllocateGpuDeviceAddress)?;

        let host = RenderNodeHost::start(&gpu_mmap, gpu_addr, linux.vm.get_memory().clone());

        // Makes the gpu memory accessible at allocated address.
        linux
            .vm
            .add_device_memory(
                GuestAddress(gpu_addr),
                gpu_mmap,
                /* read_only = */ false,
                /* log_dirty_pages = */ false,
            )
            .map_err(Error::AddGpuDeviceMemory)?;
        (host, linux)
    };

    run_control(
        linux,
        control_server_socket,
        control_sockets,
        balloon_host_socket,
        &disk_host_sockets,
        usb_control_socket,
        sigchld_fd,
        _render_node_host,
        sandbox,
    )
}

fn run_control(
    mut linux: RunnableLinuxVm,
    control_server_socket: Option<UnlinkUnixSeqpacketListener>,
    mut control_sockets: Vec<TaggedControlSocket>,
    balloon_host_socket: BalloonControlRequestSocket,
    disk_host_sockets: &[DiskControlRequestSocket],
    usb_control_socket: UsbControlSocket,
    sigchld_fd: SignalFd,
    _render_node_host: RenderNodeHost,
    sandbox: bool,
) -> Result<()> {
    // Paths to get the currently available memory and the low memory threshold.
    const LOWMEM_MARGIN: &str = "/sys/kernel/mm/chromeos-low_mem/margin";
    const LOWMEM_AVAILABLE: &str = "/sys/kernel/mm/chromeos-low_mem/available";

    // The amount of additional memory to claim back from the VM whenever the system is
    // low on memory.
    const ONE_GB: u64 = (1 << 30);

    let max_balloon_memory = match linux.vm.get_memory().memory_size() {
        // If the VM has at least 1.5 GB, the balloon driver can consume all but the last 1 GB.
        n if n >= (ONE_GB / 2) * 3 => n - ONE_GB,
        // Otherwise, if the VM has at least 500MB the balloon driver will consume at most
        // half of it.
        n if n >= (ONE_GB / 2) => n / 2,
        // Otherwise, the VM is too small for us to take memory away from it.
        _ => 0,
    };
    let mut current_balloon_memory: u64 = 0;
    let balloon_memory_increment: u64 = max_balloon_memory / 16;

    #[derive(PollToken)]
    enum Token {
        Exit,
        Stdin,
        ChildSignal,
        CheckAvailableMemory,
        LowMemory,
        LowmemTimer,
        VmControlServer,
        VmControl { index: usize },
    }

    let stdin_handle = stdin();
    let stdin_lock = stdin_handle.lock();
    stdin_lock
        .set_raw_mode()
        .expect("failed to set terminal raw mode");

    let poll_ctx = PollContext::new().map_err(Error::CreatePollContext)?;
    poll_ctx
        .add(&linux.exit_evt, Token::Exit)
        .map_err(Error::PollContextAdd)?;
    if let Err(e) = poll_ctx.add(&stdin_handle, Token::Stdin) {
        warn!("failed to add stdin to poll context: {}", e);
    }
    poll_ctx
        .add(&sigchld_fd, Token::ChildSignal)
        .map_err(Error::PollContextAdd)?;

    if let Some(socket_server) = &control_server_socket {
        poll_ctx
            .add(socket_server, Token::VmControlServer)
            .map_err(Error::PollContextAdd)?;
    }
    for (index, socket) in control_sockets.iter().enumerate() {
        poll_ctx
            .add(socket.as_ref(), Token::VmControl { index })
            .map_err(Error::PollContextAdd)?;
    }

    // Watch for low memory notifications and take memory back from the VM.
    let low_mem = File::open("/dev/chromeos-low-mem").ok();
    if let Some(low_mem) = &low_mem {
        poll_ctx
            .add(low_mem, Token::LowMemory)
            .map_err(Error::PollContextAdd)?;
    } else {
        warn!("Unable to open low mem indicator, maybe not a chrome os kernel");
    }

    // Used to rate limit balloon requests.
    let mut lowmem_timer = TimerFd::new().map_err(Error::CreateTimerFd)?;
    poll_ctx
        .add(&lowmem_timer, Token::LowmemTimer)
        .map_err(Error::PollContextAdd)?;

    // Used to check whether it's ok to start giving memory back to the VM.
    let mut freemem_timer = TimerFd::new().map_err(Error::CreateTimerFd)?;
    poll_ctx
        .add(&freemem_timer, Token::CheckAvailableMemory)
        .map_err(Error::PollContextAdd)?;

    // Used to add jitter to timer values so that we don't have a thundering herd problem when
    // multiple VMs are running.
    let mut simple_rng = SimpleRng::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .subsec_nanos() as u64,
    );

    if sandbox {
        // Before starting VCPUs, in case we started with some capabilities, drop them all.
        drop_capabilities().map_err(Error::DropCapabilities)?;
    }

    let mut vcpu_handles = Vec::with_capacity(linux.vcpus.len());
    let vcpu_thread_barrier = Arc::new(Barrier::new(linux.vcpus.len() + 1));
    let run_mode_arc = Arc::new(VcpuRunMode::default());
    setup_vcpu_signal_handler()?;
    for (cpu_id, vcpu) in linux.vcpus.into_iter().enumerate() {
        let handle = run_vcpu(
            vcpu,
            cpu_id as u32,
            linux.vcpu_affinity.clone(),
            vcpu_thread_barrier.clone(),
            linux.io_bus.clone(),
            linux.mmio_bus.clone(),
            linux.exit_evt.try_clone().map_err(Error::CloneEventFd)?,
            linux.vm.check_extension(Cap::KvmclockCtrl),
            run_mode_arc.clone(),
        )?;
        vcpu_handles.push(handle);
    }
    vcpu_thread_barrier.wait();

    'poll: loop {
        let events = {
            match poll_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to poll: {}", e);
                    break;
                }
            }
        };

        let mut vm_control_indices_to_remove = Vec::new();
        for event in events.iter_readable() {
            match event.token() {
                Token::Exit => {
                    info!("vcpu requested shutdown");
                    break 'poll;
                }
                Token::Stdin => {
                    let mut out = [0u8; 64];
                    match stdin_lock.read_raw(&mut out[..]) {
                        Ok(0) => {
                            // Zero-length read indicates EOF. Remove from pollables.
                            let _ = poll_ctx.delete(&stdin_handle);
                        }
                        Err(e) => {
                            warn!("error while reading stdin: {}", e);
                            let _ = poll_ctx.delete(&stdin_handle);
                        }
                        Ok(count) => {
                            if let Some(ref stdio_serial) = linux.stdio_serial {
                                stdio_serial
                                    .lock()
                                    .queue_input_bytes(&out[..count])
                                    .expect("failed to queue bytes into serial port");
                            }
                        }
                    }
                }
                Token::ChildSignal => {
                    // Print all available siginfo structs, then exit the loop.
                    while let Some(siginfo) = sigchld_fd.read().map_err(Error::SignalFd)? {
                        let pid = siginfo.ssi_pid;
                        let pid_label = match linux.pid_debug_label_map.get(&pid) {
                            Some(label) => format!("{} (pid {})", label, pid),
                            None => format!("pid {}", pid),
                        };
                        error!(
                            "child {} died: signo {}, status {}, code {}",
                            pid_label, siginfo.ssi_signo, siginfo.ssi_status, siginfo.ssi_code
                        );
                    }
                    break 'poll;
                }
                Token::CheckAvailableMemory => {
                    // Acknowledge the timer.
                    freemem_timer.wait().map_err(Error::TimerFd)?;
                    if current_balloon_memory == 0 {
                        // Nothing to see here.
                        if let Err(e) = freemem_timer.clear() {
                            warn!("unable to clear available memory check timer: {}", e);
                        }
                        continue;
                    }

                    // Otherwise see if we can free up some memory.
                    let margin = file_to_u64(LOWMEM_MARGIN).map_err(Error::ReadLowmemMargin)?;
                    let available =
                        file_to_u64(LOWMEM_AVAILABLE).map_err(Error::ReadLowmemAvailable)?;

                    // `available` and `margin` are specified in MB while `balloon_memory_increment` is in
                    // bytes.  So to correctly compare them we need to turn the increment value into MB.
                    if available >= margin + 2 * (balloon_memory_increment >> 20) {
                        current_balloon_memory =
                            if current_balloon_memory >= balloon_memory_increment {
                                current_balloon_memory - balloon_memory_increment
                            } else {
                                0
                            };
                        let command = BalloonControlCommand::Adjust {
                            num_bytes: current_balloon_memory,
                        };
                        if let Err(e) = balloon_host_socket.send(&command) {
                            warn!("failed to send memory value to balloon device: {}", e);
                        }
                    }
                }
                Token::LowMemory => {
                    if let Some(low_mem) = &low_mem {
                        let old_balloon_memory = current_balloon_memory;
                        current_balloon_memory = min(
                            current_balloon_memory + balloon_memory_increment,
                            max_balloon_memory,
                        );
                        if current_balloon_memory != old_balloon_memory {
                            let command = BalloonControlCommand::Adjust {
                                num_bytes: current_balloon_memory,
                            };
                            if let Err(e) = balloon_host_socket.send(&command) {
                                warn!("failed to send memory value to balloon device: {}", e);
                            }
                        }

                        // Stop polling the lowmem device until the timer fires.
                        poll_ctx.delete(low_mem).map_err(Error::PollContextDelete)?;

                        // Add some jitter to the timer so that if there are multiple VMs running
                        // they don't all start ballooning at exactly the same time.
                        let lowmem_dur = Duration::from_millis(1000 + simple_rng.rng() % 200);
                        lowmem_timer
                            .reset(lowmem_dur, None)
                            .map_err(Error::ResetTimerFd)?;

                        // Also start a timer to check when we can start giving memory back.  Do the
                        // first check after a minute (with jitter) and subsequent checks after
                        // every 30 seconds (with jitter).
                        let freemem_dur = Duration::from_secs(60 + simple_rng.rng() % 12);
                        let freemem_int = Duration::from_secs(30 + simple_rng.rng() % 6);
                        freemem_timer
                            .reset(freemem_dur, Some(freemem_int))
                            .map_err(Error::ResetTimerFd)?;
                    }
                }
                Token::LowmemTimer => {
                    // Acknowledge the timer.
                    lowmem_timer.wait().map_err(Error::TimerFd)?;

                    if let Some(low_mem) = &low_mem {
                        // Start polling the lowmem device again.
                        poll_ctx
                            .add(low_mem, Token::LowMemory)
                            .map_err(Error::PollContextAdd)?;
                    }
                }
                Token::VmControlServer => {
                    if let Some(socket_server) = &control_server_socket {
                        match socket_server.accept() {
                            Ok(socket) => {
                                poll_ctx
                                    .add(
                                        &socket,
                                        Token::VmControl {
                                            index: control_sockets.len(),
                                        },
                                    )
                                    .map_err(Error::PollContextAdd)?;
                                control_sockets
                                    .push(TaggedControlSocket::Vm(MsgSocket::new(socket)));
                            }
                            Err(e) => error!("failed to accept socket: {}", e),
                        }
                    }
                }
                Token::VmControl { index } => {
                    if let Some(socket) = control_sockets.get(index) {
                        match socket {
                            TaggedControlSocket::Vm(socket) => match socket.recv() {
                                Ok(request) => {
                                    let mut run_mode_opt = None;
                                    let response = request.execute(
                                        &mut run_mode_opt,
                                        &balloon_host_socket,
                                        disk_host_sockets,
                                        &usb_control_socket,
                                    );
                                    if let Err(e) = socket.send(&response) {
                                        error!("failed to send VmResponse: {}", e);
                                    }
                                    if let Some(run_mode) = run_mode_opt {
                                        info!("control socket changed run mode to {}", run_mode);
                                        match run_mode {
                                            VmRunMode::Exiting => {
                                                break 'poll;
                                            }
                                            other => {
                                                run_mode_arc.set_and_notify(other);
                                                for handle in &vcpu_handles {
                                                    let _ = handle.kill(SIGRTMIN() + 0);
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    if let MsgError::BadRecvSize { actual: 0, .. } = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmRequest: {}", e);
                                    }
                                }
                            },
                            TaggedControlSocket::VmMemory(socket) => match socket.recv() {
                                Ok(request) => {
                                    let response =
                                        request.execute(&mut linux.vm, &mut linux.resources);
                                    if let Err(e) = socket.send(&response) {
                                        error!("failed to send VmMemoryControlResponse: {}", e);
                                    }
                                }
                                Err(e) => {
                                    if let MsgError::BadRecvSize { actual: 0, .. } = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmMemoryControlRequest: {}", e);
                                    }
                                }
                            },
                        }
                    }
                }
            }
        }

        for event in events.iter_hungup() {
            match event.token() {
                Token::Exit => {}
                Token::Stdin => {
                    let _ = poll_ctx.delete(&stdin_handle);
                }
                Token::ChildSignal => {}
                Token::CheckAvailableMemory => {}
                Token::LowMemory => {}
                Token::LowmemTimer => {}
                Token::VmControlServer => {}
                Token::VmControl { index } => {
                    // It's possible more data is readable and buffered while the socket is hungup,
                    // so don't delete the socket from the poll context until we're sure all the
                    // data is read.
                    match control_sockets
                        .get(index)
                        .map(|s| s.as_ref().get_readable_bytes())
                    {
                        Some(Ok(0)) | Some(Err(_)) => vm_control_indices_to_remove.push(index),
                        Some(Ok(x)) => info!("control index {} has {} bytes readable", index, x),
                        _ => {}
                    }
                }
            }
        }

        // Sort in reverse so the highest indexes are removed first. This removal algorithm
        // preserved correct indexes as each element is removed.
        vm_control_indices_to_remove.sort_unstable_by(|a, b| b.cmp(a));
        vm_control_indices_to_remove.dedup();
        for index in vm_control_indices_to_remove {
            control_sockets.swap_remove(index);
            if let Some(socket) = control_sockets.get(index) {
                poll_ctx
                    .modify(
                        socket,
                        WatchingEvents::empty().set_read(),
                        Token::VmControl { index },
                    )
                    .map_err(Error::PollContextAdd)?;
            }
        }
    }

    // VCPU threads MUST see the VmRunMode flag, otherwise they may re-enter the VM.
    run_mode_arc.set_and_notify(VmRunMode::Exiting);
    for handle in vcpu_handles {
        match handle.kill(SIGRTMIN() + 0) {
            Ok(_) => {
                if let Err(e) = handle.join() {
                    error!("failed to join vcpu thread: {:?}", e);
                }
            }
            Err(e) => error!("failed to kill vcpu thread: {}", e),
        }
    }

    stdin_lock
        .set_canon_mode()
        .expect("failed to restore canonical mode for terminal");

    Ok(())
}
