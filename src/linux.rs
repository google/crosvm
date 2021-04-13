// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::{max, min, Reverse};
use std::convert::TryFrom;
#[cfg(feature = "gpu")]
use std::env;
use std::error::Error as StdError;
use std::ffi::CStr;
use std::fmt::{self, Display};
use std::fs::{File, OpenOptions};
use std::io::{self, stdin, Read};
use std::iter;
use std::mem;
use std::net::Ipv4Addr;
#[cfg(feature = "gpu")]
use std::num::NonZeroU8;
use std::num::ParseIntError;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::ptr;
use std::str;
use std::sync::{mpsc, Arc, Barrier};

use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use libc::{self, c_int, gid_t, uid_t};

use acpi_tables::sdt::SDT;

use base::net::{UnixSeqpacketListener, UnlinkUnixSeqpacketListener};
use base::*;
use devices::virtio::vhost::user::{
    Block as VhostUserBlock, Error as VhostUserError, Fs as VhostUserFs, Net as VhostUserNet,
};
#[cfg(feature = "gpu")]
use devices::virtio::EventDevice;
use devices::virtio::{self, Console, VirtioDevice};
#[cfg(feature = "audio")]
use devices::Ac97Dev;
use devices::{
    self, HostBackendDeviceProvider, IrqChip, IrqEventIndex, KvmKernelIrqChip, PciDevice,
    VcpuRunState, VfioContainer, VfioDevice, VfioPciDevice, VirtioPciDevice, XhciController,
};
use hypervisor::kvm::{Kvm, KvmVcpu, KvmVm};
use hypervisor::{HypervisorCap, Vcpu, VcpuExit, VcpuRunHandle, Vm, VmCap};
use minijail::{self, Minijail};
use net_util::{Error as NetError, MacAddress, Tap};
use remain::sorted;
use resources::{Alloc, MmioType, SystemAllocator};
use rutabaga_gfx::RutabagaGralloc;
use sync::Mutex;
use vm_control::*;
use vm_memory::{GuestAddress, GuestMemory, MemoryPolicy};

#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
use crate::gdb::{gdb_thread, GdbStub};
use crate::{
    Config, DiskOption, Executable, SharedDir, SharedDirKind, TouchDeviceOption, VhostUserFsOption,
    VhostUserOption,
};
use arch::{
    self, LinuxArch, RunnableLinuxVm, SerialHardware, SerialParameters, VcpuAffinity,
    VirtioDeviceStub, VmComponents, VmImage,
};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use {
    aarch64::AArch64 as Arch,
    devices::IrqChipAArch64 as IrqChipArch,
    hypervisor::{VcpuAArch64 as VcpuArch, VmAArch64 as VmArch},
};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use {
    devices::{IrqChipX86_64 as IrqChipArch, KvmSplitIrqChip},
    hypervisor::{VcpuX86_64 as VcpuArch, VmX86_64 as VmArch},
    x86_64::X8664arch as Arch,
};

#[sorted]
#[derive(Debug)]
pub enum Error {
    AddGpuDeviceMemory(base::Error),
    AddIrqChipVcpu(base::Error),
    AddPmemDeviceMemory(base::Error),
    AllocateGpuDeviceAddress,
    AllocatePmemDeviceAddress(resources::Error),
    BalloonActualTooLarge,
    BalloonDeviceNew(virtio::BalloonError),
    BlockDeviceNew(base::Error),
    BlockSignal(base::signal::Error),
    BuildVm(<Arch as LinuxArch>::Error),
    ChownTpmStorage(base::Error),
    CloneEvent(base::Error),
    CloneVcpu(base::Error),
    ConfigureVcpu(<Arch as LinuxArch>::Error),
    #[cfg(feature = "audio")]
    CreateAc97(devices::PciDeviceError),
    CreateConsole(arch::serial::Error),
    CreateControlServer(io::Error),
    CreateDiskError(disk::Error),
    CreateEvent(base::Error),
    CreateGrallocError(rutabaga_gfx::RutabagaError),
    CreateKvm(base::Error),
    CreateSignalFd(base::SignalFdError),
    CreateSocket(io::Error),
    CreateTapDevice(NetError),
    CreateTimer(base::Error),
    CreateTpmStorage(PathBuf, io::Error),
    CreateTube(TubeError),
    CreateUsbProvider(devices::usb::host_backend::error::Error),
    CreateVcpu(base::Error),
    CreateVfioDevice(devices::vfio::VfioError),
    CreateVm(base::Error),
    CreateWaitContext(base::Error),
    DeviceJail(minijail::Error),
    DevicePivotRoot(minijail::Error),
    #[cfg(feature = "direct")]
    DirectIo(io::Error),
    #[cfg(feature = "direct")]
    DirectIrq(devices::DirectIrqError),
    Disk(PathBuf, io::Error),
    DiskImageLock(base::Error),
    DropCapabilities(base::Error),
    FsDeviceNew(virtio::fs::Error),
    GetMaxOpenFiles(io::Error),
    GetSignalMask(signal::Error),
    GuestCachedMissing(),
    GuestCachedTooLarge(std::num::TryFromIntError),
    GuestFreeMissing(),
    GuestFreeTooLarge(std::num::TryFromIntError),
    GuestMemoryLayout(<Arch as LinuxArch>::Error),
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    HandleDebugCommand(<Arch as LinuxArch>::Error),
    InputDeviceNew(virtio::InputError),
    InputEventsOpen(std::io::Error),
    InvalidFdPath,
    InvalidWaylandPath,
    IoJail(minijail::Error),
    LoadKernel(Box<dyn StdError>),
    MemoryTooLarge,
    NetDeviceNew(virtio::NetError),
    OpenAcpiTable(PathBuf, io::Error),
    OpenAndroidFstab(PathBuf, io::Error),
    OpenBios(PathBuf, io::Error),
    OpenInitrd(PathBuf, io::Error),
    OpenKernel(PathBuf, io::Error),
    OpenVinput(PathBuf, io::Error),
    P9DeviceNew(virtio::P9Error),
    ParseMaxOpenFiles(ParseIntError),
    PivotRootDoesntExist(&'static str),
    PmemDeviceImageTooBig,
    PmemDeviceNew(base::Error),
    ReadMemAvailable(io::Error),
    ReadStatm(io::Error),
    RegisterBalloon(arch::DeviceRegistrationError),
    RegisterBlock(arch::DeviceRegistrationError),
    RegisterGpu(arch::DeviceRegistrationError),
    RegisterNet(arch::DeviceRegistrationError),
    RegisterP9(arch::DeviceRegistrationError),
    RegisterRng(arch::DeviceRegistrationError),
    RegisterSignalHandler(base::Error),
    RegisterWayland(arch::DeviceRegistrationError),
    ReserveGpuMemory(base::MmapError),
    ReserveMemory(base::Error),
    ReservePmemMemory(base::MmapError),
    ResetTimer(base::Error),
    RngDeviceNew(virtio::RngError),
    RunnableVcpu(base::Error),
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    SendDebugStatus(Box<mpsc::SendError<VcpuDebugStatusMessage>>),
    SettingGidMap(minijail::Error),
    SettingMaxOpenFiles(minijail::Error),
    SettingSignalMask(base::Error),
    SettingUidMap(minijail::Error),
    SignalFd(base::SignalFdError),
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    SpawnGdbServer(io::Error),
    SpawnVcpu(io::Error),
    Timer(base::Error),
    ValidateRawDescriptor(base::Error),
    VhostNetDeviceNew(virtio::vhost::Error),
    VhostUserBlockDeviceNew(VhostUserError),
    VhostUserFsDeviceNew(VhostUserError),
    VhostUserNetDeviceNew(VhostUserError),
    VhostUserNetWithNetArgs,
    VhostVsockDeviceNew(virtio::vhost::Error),
    VirtioPciDev(base::Error),
    WaitContextAdd(base::Error),
    WaitContextDelete(base::Error),
    WaylandDeviceNew(base::Error),
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            AddGpuDeviceMemory(e) => write!(f, "failed to add gpu device memory: {}", e),
            AddIrqChipVcpu(e) => write!(f, "failed to add vcpu to irq chip: {}", e),
            AddPmemDeviceMemory(e) => write!(f, "failed to add pmem device memory: {}", e),
            AllocateGpuDeviceAddress => write!(f, "failed to allocate gpu device guest address"),
            AllocatePmemDeviceAddress(e) => {
                write!(f, "failed to allocate memory for pmem device: {}", e)
            }
            BalloonActualTooLarge => write!(f, "balloon actual size is too large"),
            BalloonDeviceNew(e) => write!(f, "failed to create balloon: {}", e),
            BlockDeviceNew(e) => write!(f, "failed to create block device: {}", e),
            BlockSignal(e) => write!(f, "failed to block signal: {}", e),
            BuildVm(e) => write!(f, "The architecture failed to build the vm: {}", e),
            ChownTpmStorage(e) => write!(f, "failed to chown tpm storage: {}", e),
            CloneEvent(e) => write!(f, "failed to clone event: {}", e),
            CloneVcpu(e) => write!(f, "failed to clone vcpu: {}", e),
            ConfigureVcpu(e) => write!(f, "failed to configure vcpu: {}", e),
            #[cfg(feature = "audio")]
            CreateAc97(e) => write!(f, "failed to create ac97 device: {}", e),
            CreateConsole(e) => write!(f, "failed to create console device: {}", e),
            CreateControlServer(e) => write!(f, "failed to create control server: {}", e),
            CreateDiskError(e) => write!(f, "failed to create virtual disk: {}", e),
            CreateEvent(e) => write!(f, "failed to create event: {}", e),
            CreateGrallocError(e) => write!(f, "failed to create gralloc: {}", e),
            CreateKvm(e) => write!(f, "failed to create kvm: {}", e),
            CreateSignalFd(e) => write!(f, "failed to create signalfd: {}", e),
            CreateSocket(e) => write!(f, "failed to create socket: {}", e),
            CreateTapDevice(e) => write!(f, "failed to create tap device: {}", e),
            CreateTimer(e) => write!(f, "failed to create Timer: {}", e),
            CreateTpmStorage(p, e) => {
                write!(f, "failed to create tpm storage dir {}: {}", p.display(), e)
            }
            CreateTube(e) => write!(f, "failed to create tube: {}", e),
            CreateUsbProvider(e) => write!(f, "failed to create usb provider: {}", e),
            CreateVcpu(e) => write!(f, "failed to create vcpu: {}", e),
            CreateVfioDevice(e) => write!(f, "Failed to create vfio device {}", e),
            CreateVm(e) => write!(f, "failed to create vm: {}", e),
            CreateWaitContext(e) => write!(f, "failed to create wait context: {}", e),
            DeviceJail(e) => write!(f, "failed to jail device: {}", e),
            DevicePivotRoot(e) => write!(f, "failed to pivot root device: {}", e),
            #[cfg(feature = "direct")]
            DirectIo(e) => write!(f, "failed to open direct io device: {}", e),
            #[cfg(feature = "direct")]
            DirectIrq(e) => write!(f, "failed to enable interrupt forwarding: {}", e),
            Disk(p, e) => write!(f, "failed to load disk image {}: {}", p.display(), e),
            DiskImageLock(e) => write!(f, "failed to lock disk image: {}", e),
            DropCapabilities(e) => write!(f, "failed to drop process capabilities: {}", e),
            FsDeviceNew(e) => write!(f, "failed to create fs device: {}", e),
            GetMaxOpenFiles(e) => write!(f, "failed to get max number of open files: {}", e),
            GetSignalMask(e) => write!(f, "failed to retrieve signal mask for vcpu: {}", e),
            GuestCachedMissing() => write!(f, "guest cached is missing from balloon stats"),
            GuestCachedTooLarge(e) => write!(f, "guest cached is too large: {}", e),
            GuestFreeMissing() => write!(f, "guest free is missing from balloon stats"),
            GuestFreeTooLarge(e) => write!(f, "guest free is too large: {}", e),
            GuestMemoryLayout(e) => write!(f, "failed to create guest memory layout: {}", e),
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            HandleDebugCommand(e) => write!(f, "failed to handle a gdb command: {}", e),
            InputDeviceNew(e) => write!(f, "failed to set up input device: {}", e),
            InputEventsOpen(e) => write!(f, "failed to open event device: {}", e),
            InvalidFdPath => write!(f, "failed parsing a /proc/self/fd/*"),
            InvalidWaylandPath => write!(f, "wayland socket path has no parent or file name"),
            IoJail(e) => write!(f, "{}", e),
            LoadKernel(e) => write!(f, "failed to load kernel: {}", e),
            MemoryTooLarge => write!(f, "requested memory size too large"),
            NetDeviceNew(e) => write!(f, "failed to set up virtio networking: {}", e),
            OpenAcpiTable(p, e) => write!(f, "failed to open ACPI file {}: {}", p.display(), e),
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
            ParseMaxOpenFiles(e) => write!(f, "failed to parse max number of open files: {}", e),
            PivotRootDoesntExist(p) => write!(f, "{} doesn't exist, can't jail devices.", p),
            PmemDeviceImageTooBig => {
                write!(f, "failed to create pmem device: pmem device image too big")
            }
            PmemDeviceNew(e) => write!(f, "failed to create pmem device: {}", e),
            ReadMemAvailable(e) => write!(
                f,
                "failed to read /sys/kernel/mm/chromeos-low_mem/available: {}",
                e
            ),
            ReadStatm(e) => write!(f, "failed to read /proc/self/statm: {}", e),
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
            ResetTimer(e) => write!(f, "failed to reset Timer: {}", e),
            RngDeviceNew(e) => write!(f, "failed to set up rng: {}", e),
            RunnableVcpu(e) => write!(f, "failed to set thread id for vcpu: {}", e),
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            SendDebugStatus(e) => write!(f, "failed to send a debug status to GDB thread: {}", e),
            SettingGidMap(e) => write!(f, "error setting GID map: {}", e),
            SettingMaxOpenFiles(e) => write!(f, "error setting max open files: {}", e),
            SettingSignalMask(e) => write!(f, "failed to set the signal mask for vcpu: {}", e),
            SettingUidMap(e) => write!(f, "error setting UID map: {}", e),
            SignalFd(e) => write!(f, "failed to read signal fd: {}", e),
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            SpawnGdbServer(e) => write!(f, "failed to spawn GDB thread: {}", e),
            SpawnVcpu(e) => write!(f, "failed to spawn VCPU thread: {}", e),
            Timer(e) => write!(f, "failed to read timer fd: {}", e),
            ValidateRawDescriptor(e) => write!(f, "failed to validate raw descriptor: {}", e),
            VhostNetDeviceNew(e) => write!(f, "failed to set up vhost networking: {}", e),
            VhostUserBlockDeviceNew(e) => {
                write!(f, "failed to set up vhost-user block device: {}", e)
            }
            VhostUserFsDeviceNew(e) => write!(f, "failed to set up vhost-user fs device: {}", e),
            VhostUserNetDeviceNew(e) => write!(f, "failed to set up vhost-user net device: {}", e),
            VhostUserNetWithNetArgs => write!(
                f,
                "vhost-user-net cannot be used with any of --host_ip, --netmask or --mac"
            ),
            VhostVsockDeviceNew(e) => write!(f, "failed to set up virtual socket device: {}", e),
            VirtioPciDev(e) => write!(f, "failed to create virtio pci dev: {}", e),
            WaitContextAdd(e) => write!(f, "failed to add descriptor to wait context: {}", e),
            WaitContextDelete(e) => {
                write!(f, "failed to remove descriptor from wait context: {}", e)
            }
            WaylandDeviceNew(e) => write!(f, "failed to create wayland device: {}", e),
        }
    }
}

impl From<minijail::Error> for Error {
    fn from(err: minijail::Error) -> Self {
        Error::IoJail(err)
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

enum TaggedControlTube {
    Fs(Tube),
    Vm(Tube),
    VmMemory(Tube),
    VmIrq(Tube),
    VmMsync(Tube),
}

impl AsRef<Tube> for TaggedControlTube {
    fn as_ref(&self) -> &Tube {
        use self::TaggedControlTube::*;
        match &self {
            Fs(tube) | Vm(tube) | VmMemory(tube) | VmIrq(tube) | VmMsync(tube) => tube,
        }
    }
}

impl AsRawDescriptor for TaggedControlTube {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.as_ref().as_raw_descriptor()
    }
}

fn get_max_open_files() -> Result<u64> {
    let mut buf = mem::MaybeUninit::<libc::rlimit64>::zeroed();

    // Safe because this will only modify `buf` and we check the return value.
    let res = unsafe { libc::prlimit64(0, libc::RLIMIT_NOFILE, ptr::null(), buf.as_mut_ptr()) };
    if res == 0 {
        // Safe because the kernel guarantees that the struct is fully initialized.
        let limit = unsafe { buf.assume_init() };
        Ok(limit.rlim_max)
    } else {
        Err(Error::GetMaxOpenFiles(io::Error::last_os_error()))
    }
}

struct SandboxConfig<'a> {
    limit_caps: bool,
    log_failures: bool,
    seccomp_policy: &'a Path,
    uid_map: Option<&'a str>,
    gid_map: Option<&'a str>,
}

fn create_base_minijail(
    root: &Path,
    r_limit: Option<u64>,
    config: Option<&SandboxConfig>,
) -> Result<Minijail> {
    // All child jails run in a new user namespace without any users mapped,
    // they run as nobody unless otherwise configured.
    let mut j = Minijail::new().map_err(Error::DeviceJail)?;

    if let Some(config) = config {
        j.namespace_pids();
        j.namespace_user();
        j.namespace_user_disable_setgroups();
        if config.limit_caps {
            // Don't need any capabilities.
            j.use_caps(0);
        }
        if let Some(uid_map) = config.uid_map {
            j.uidmap(uid_map).map_err(Error::SettingUidMap)?;
        }
        if let Some(gid_map) = config.gid_map {
            j.gidmap(gid_map).map_err(Error::SettingGidMap)?;
        }
        // Run in a new mount namespace.
        j.namespace_vfs();

        // Run in an empty network namespace.
        j.namespace_net();

        // Don't allow the device to gain new privileges.
        j.no_new_privs();

        // By default we'll prioritize using the pre-compiled .bpf over the .policy
        // file (the .bpf is expected to be compiled using "trap" as the failure
        // behavior instead of the default "kill" behavior).
        // Refer to the code comment for the "seccomp-log-failures"
        // command-line parameter for an explanation about why the |log_failures|
        // flag forces the use of .policy files (and the build-time alternative to
        // this run-time flag).
        let bpf_policy_file = config.seccomp_policy.with_extension("bpf");
        if bpf_policy_file.exists() && !config.log_failures {
            j.parse_seccomp_program(&bpf_policy_file)
                .map_err(Error::DeviceJail)?;
        } else {
            // Use TSYNC only for the side effect of it using SECCOMP_RET_TRAP,
            // which will correctly kill the entire device process if a worker
            // thread commits a seccomp violation.
            j.set_seccomp_filter_tsync();
            if config.log_failures {
                j.log_seccomp_filter_failures();
            }
            j.parse_seccomp_filters(&config.seccomp_policy.with_extension("policy"))
                .map_err(Error::DeviceJail)?;
        }
        j.use_seccomp_filter();
        // Don't do init setup.
        j.run_as_init();
    }

    // Only pivot_root if we are not re-using the current root directory.
    if root != Path::new("/") {
        // It's safe to call `namespace_vfs` multiple times.
        j.namespace_vfs();
        j.enter_pivot_root(root).map_err(Error::DevicePivotRoot)?;
    }

    // Most devices don't need to open many fds.
    let limit = if let Some(r) = r_limit { r } else { 1024u64 };
    j.set_rlimit(libc::RLIMIT_NOFILE as i32, limit, limit)
        .map_err(Error::SettingMaxOpenFiles)?;

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
        let config = SandboxConfig {
            limit_caps: true,
            log_failures: cfg.seccomp_log_failures,
            seccomp_policy: &policy_path,
            uid_map: None,
            gid_map: None,
        };
        Ok(Some(create_base_minijail(root_path, None, Some(&config))?))
    } else {
        Ok(None)
    }
}

type DeviceResult<T = VirtioDeviceStub> = std::result::Result<T, Error>;

fn create_block_device(cfg: &Config, disk: &DiskOption, disk_device_tube: Tube) -> DeviceResult {
    // Special case '/proc/self/fd/*' paths. The FD is already open, just use it.
    let raw_image: File = if disk.path.parent() == Some(Path::new("/proc/self/fd")) {
        // Safe because we will validate |raw_fd|.
        unsafe { File::from_raw_descriptor(raw_descriptor_from_path(&disk.path)?) }
    } else {
        OpenOptions::new()
            .read(true)
            .write(!disk.read_only)
            .open(&disk.path)
            .map_err(|e| Error::Disk(disk.path.to_path_buf(), e))?
    };
    // Lock the disk image to prevent other crosvm instances from using it.
    let lock_op = if disk.read_only {
        FlockOperation::LockShared
    } else {
        FlockOperation::LockExclusive
    };
    flock(&raw_image, lock_op, true).map_err(Error::DiskImageLock)?;

    let dev = if disk::async_ok(&raw_image).map_err(Error::CreateDiskError)? {
        let async_file = disk::create_async_disk_file(raw_image).map_err(Error::CreateDiskError)?;
        Box::new(
            virtio::BlockAsync::new(
                virtio::base_features(cfg.protected_vm),
                async_file,
                disk.read_only,
                disk.sparse,
                disk.block_size,
                disk.id,
                Some(disk_device_tube),
            )
            .map_err(Error::BlockDeviceNew)?,
        ) as Box<dyn VirtioDevice>
    } else {
        let disk_file = disk::create_disk_file(raw_image).map_err(Error::CreateDiskError)?;
        Box::new(
            virtio::Block::new(
                virtio::base_features(cfg.protected_vm),
                disk_file,
                disk.read_only,
                disk.sparse,
                disk.block_size,
                disk.id,
                Some(disk_device_tube),
            )
            .map_err(Error::BlockDeviceNew)?,
        ) as Box<dyn VirtioDevice>
    };

    Ok(VirtioDeviceStub {
        dev,
        jail: simple_jail(&cfg, "block_device")?,
    })
}

fn create_vhost_user_block_device(cfg: &Config, opt: &VhostUserOption) -> DeviceResult {
    let dev = VhostUserBlock::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .map_err(Error::VhostUserBlockDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

fn create_vhost_user_fs_device(cfg: &Config, option: &VhostUserFsOption) -> DeviceResult {
    let dev = VhostUserFs::new(
        virtio::base_features(cfg.protected_vm),
        &option.socket,
        &option.tag,
    )
    .map_err(Error::VhostUserFsDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

fn create_rng_device(cfg: &Config) -> DeviceResult {
    let dev =
        virtio::Rng::new(virtio::base_features(cfg.protected_vm)).map_err(Error::RngDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "rng_device")?,
    })
}

#[cfg(feature = "tpm")]
fn create_tpm_device(cfg: &Config) -> DeviceResult {
    use std::ffi::CString;
    use std::fs;
    use std::process;

    let tpm_storage: PathBuf;
    let mut tpm_jail = simple_jail(&cfg, "tpm_device")?;

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
    let socket = single_touch_spec
        .get_path()
        .into_unix_stream()
        .map_err(|e| {
            error!("failed configuring virtio single touch: {:?}", e);
            e
        })?;

    let (width, height) = single_touch_spec.get_size();
    let dev = virtio::new_single_touch(
        socket,
        width,
        height,
        virtio::base_features(cfg.protected_vm),
    )
    .map_err(Error::InputDeviceNew)?;
    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_multi_touch_device(cfg: &Config, multi_touch_spec: &TouchDeviceOption) -> DeviceResult {
    let socket = multi_touch_spec
        .get_path()
        .into_unix_stream()
        .map_err(|e| {
            error!("failed configuring virtio multi touch: {:?}", e);
            e
        })?;

    let (width, height) = multi_touch_spec.get_size();
    let dev = virtio::new_multi_touch(
        socket,
        width,
        height,
        virtio::base_features(cfg.protected_vm),
    )
    .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_trackpad_device(cfg: &Config, trackpad_spec: &TouchDeviceOption) -> DeviceResult {
    let socket = trackpad_spec.get_path().into_unix_stream().map_err(|e| {
        error!("failed configuring virtio trackpad: {}", e);
        e
    })?;

    let (width, height) = trackpad_spec.get_size();
    let dev = virtio::new_trackpad(
        socket,
        width,
        height,
        virtio::base_features(cfg.protected_vm),
    )
    .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_mouse_device<T: IntoUnixStream>(cfg: &Config, mouse_socket: T) -> DeviceResult {
    let socket = mouse_socket.into_unix_stream().map_err(|e| {
        error!("failed configuring virtio mouse: {}", e);
        e
    })?;

    let dev = virtio::new_mouse(socket, virtio::base_features(cfg.protected_vm))
        .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_keyboard_device<T: IntoUnixStream>(cfg: &Config, keyboard_socket: T) -> DeviceResult {
    let socket = keyboard_socket.into_unix_stream().map_err(|e| {
        error!("failed configuring virtio keyboard: {}", e);
        e
    })?;

    let dev = virtio::new_keyboard(socket, virtio::base_features(cfg.protected_vm))
        .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_switches_device<T: IntoUnixStream>(cfg: &Config, switches_socket: T) -> DeviceResult {
    let socket = switches_socket.into_unix_stream().map_err(|e| {
        error!("failed configuring virtio switches: {}", e);
        e
    })?;

    let dev = virtio::new_switches(socket, virtio::base_features(cfg.protected_vm))
        .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_vinput_device(cfg: &Config, dev_path: &Path) -> DeviceResult {
    let dev_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .map_err(|e| Error::OpenVinput(dev_path.to_owned(), e))?;

    let dev = virtio::new_evdev(dev_file, virtio::base_features(cfg.protected_vm))
        .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "input_device")?,
    })
}

fn create_balloon_device(cfg: &Config, tube: Tube) -> DeviceResult {
    let dev = virtio::Balloon::new(virtio::base_features(cfg.protected_vm), tube)
        .map_err(Error::BalloonDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "balloon_device")?,
    })
}

fn create_tap_net_device(cfg: &Config, tap_fd: RawDescriptor) -> DeviceResult {
    // Safe because we ensure that we get a unique handle to the fd.
    let tap = unsafe {
        Tap::from_raw_descriptor(
            validate_raw_descriptor(tap_fd).map_err(Error::ValidateRawDescriptor)?,
        )
        .map_err(Error::CreateTapDevice)?
    };

    let mut vq_pairs = cfg.net_vq_pairs.unwrap_or(1);
    let vcpu_count = cfg.vcpu_count.unwrap_or(1);
    if vcpu_count < vq_pairs as usize {
        error!("net vq pairs must be smaller than vcpu count, fall back to single queue mode");
        vq_pairs = 1;
    }
    let features = virtio::base_features(cfg.protected_vm);
    let dev = virtio::Net::from(features, tap, vq_pairs).map_err(Error::NetDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "net_device")?,
    })
}

fn create_net_device(
    cfg: &Config,
    host_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mac_address: MacAddress,
    mem: &GuestMemory,
) -> DeviceResult {
    let mut vq_pairs = cfg.net_vq_pairs.unwrap_or(1);
    let vcpu_count = cfg.vcpu_count.unwrap_or(1);
    if vcpu_count < vq_pairs as usize {
        error!("net vq pairs must be smaller than vcpu count, fall back to single queue mode");
        vq_pairs = 1;
    }

    let features = virtio::base_features(cfg.protected_vm);
    let dev = if cfg.vhost_net {
        let dev = virtio::vhost::Net::<Tap, vhost::Net<Tap>>::new(
            &cfg.vhost_net_device_path,
            features,
            host_ip,
            netmask,
            mac_address,
            mem,
        )
        .map_err(Error::VhostNetDeviceNew)?;
        Box::new(dev) as Box<dyn VirtioDevice>
    } else {
        let dev = virtio::Net::<Tap>::new(features, host_ip, netmask, mac_address, vq_pairs)
            .map_err(Error::NetDeviceNew)?;
        Box::new(dev) as Box<dyn VirtioDevice>
    };

    let policy = if cfg.vhost_net {
        "vhost_net_device"
    } else {
        "net_device"
    };

    Ok(VirtioDeviceStub {
        dev,
        jail: simple_jail(&cfg, policy)?,
    })
}

fn create_vhost_user_net_device(cfg: &Config, opt: &VhostUserOption) -> DeviceResult {
    let dev = VhostUserNet::new(virtio::base_features(cfg.protected_vm), &opt.socket)
        .map_err(Error::VhostUserNetDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

#[cfg(feature = "gpu")]
fn create_gpu_device(
    cfg: &Config,
    exit_evt: &Event,
    gpu_device_tube: Tube,
    resource_bridges: Vec<Tube>,
    wayland_socket_path: Option<&PathBuf>,
    x_display: Option<String>,
    event_devices: Vec<EventDevice>,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
    mem: &GuestMemory,
) -> DeviceResult {
    let jailed_wayland_path = Path::new("/wayland-0");

    let mut display_backends = vec![
        virtio::DisplayBackend::X(x_display),
        virtio::DisplayBackend::Stub,
    ];

    if let Some(socket_path) = wayland_socket_path {
        display_backends.insert(
            0,
            virtio::DisplayBackend::Wayland(if cfg.sandbox {
                Some(jailed_wayland_path.to_owned())
            } else {
                Some(socket_path.to_owned())
            }),
        );
    }

    let dev = virtio::Gpu::new(
        exit_evt.try_clone().map_err(Error::CloneEvent)?,
        Some(gpu_device_tube),
        NonZeroU8::new(1).unwrap(), // number of scanouts
        resource_bridges,
        display_backends,
        cfg.gpu_parameters.as_ref().unwrap(),
        event_devices,
        map_request,
        cfg.sandbox,
        virtio::base_features(cfg.protected_vm),
        cfg.wayland_socket_paths.clone(),
        mem.clone(),
    );

    let jail = match simple_jail(&cfg, "gpu_device")? {
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
            if drm_dri_path.exists() {
                jail.mount_bind(drm_dri_path, drm_dri_path, false)?;
            }

            // Prepare GPU shader disk cache directory.
            if let Some(cache_dir) = cfg
                .gpu_parameters
                .as_ref()
                .and_then(|params| params.cache_path.as_ref())
            {
                if cfg!(any(target_arch = "arm", target_arch = "aarch64")) && cfg.sandbox {
                    warn!("shader caching not yet supported on ARM with sandbox enabled");
                    env::set_var("MESA_GLSL_CACHE_DISABLE", "true");
                } else {
                    env::set_var("MESA_GLSL_CACHE_DISABLE", "false");
                    env::set_var("MESA_GLSL_CACHE_DIR", cache_dir);
                    if let Some(cache_size) = cfg
                        .gpu_parameters
                        .as_ref()
                        .and_then(|params| params.cache_size.as_ref())
                    {
                        env::set_var("MESA_GLSL_CACHE_MAX_SIZE", cache_size);
                    }
                    let shadercache_path = Path::new(cache_dir);
                    jail.mount_bind(shadercache_path, shadercache_path, true)?;
                }
            }

            // If the ARM specific devices exist on the host, bind mount them in.
            let mali0_path = Path::new("/dev/mali0");
            if mali0_path.exists() {
                jail.mount_bind(mali0_path, mali0_path, true)?;
            }

            let pvr_sync_path = Path::new("/dev/pvr_sync");
            if pvr_sync_path.exists() {
                jail.mount_bind(pvr_sync_path, pvr_sync_path, true)?;
            }

            // If the udmabuf driver exists on the host, bind mount it in.
            let udmabuf_path = Path::new("/dev/udmabuf");
            if udmabuf_path.exists() {
                jail.mount_bind(udmabuf_path, udmabuf_path, true)?;
            }

            // Libraries that are required when mesa drivers are dynamically loaded.
            let lib_dirs = &[
                "/usr/lib",
                "/usr/lib64",
                "/lib",
                "/lib64",
                "/usr/share/vulkan",
            ];
            for dir in lib_dirs {
                let dir_path = Path::new(dir);
                if dir_path.exists() {
                    jail.mount_bind(dir_path, dir_path, false)?;
                }
            }

            // Bind mount the wayland socket into jail's root. This is necessary since each
            // new wayland context must open() the socket.  Don't bind mount the camera socket
            // since it seems to cause problems on ARCVM (b/180126126) + Mali.  It's unclear if
            // camera team will opt for virtio-camera or continue using virtio-wl, so this should
            // be fine for now.
            if let Some(path) = wayland_socket_path {
                jail.mount_bind(path, jailed_wayland_path, true)?;
            }

            add_crosvm_user_to_jail(&mut jail, "gpu")?;

            // pvr driver requires read access to /proc/self/task/*/comm.
            let proc_path = Path::new("/proc");
            jail.mount(
                proc_path,
                proc_path,
                "proc",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY) as usize,
            )?;

            // To enable perfetto tracing, we need to give access to the perfetto service IPC
            // endpoints.
            let perfetto_path = Path::new("/run/perfetto");
            if perfetto_path.exists() {
                jail.mount_bind(perfetto_path, perfetto_path, true)?;
            }

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
    control_tube: Tube,
    resource_bridge: Option<Tube>,
) -> DeviceResult {
    let wayland_socket_dirs = cfg
        .wayland_socket_paths
        .iter()
        .map(|(_name, path)| path.parent())
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::InvalidWaylandPath)?;

    let features = virtio::base_features(cfg.protected_vm);
    let dev = virtio::Wl::new(
        features,
        cfg.wayland_socket_paths.clone(),
        control_tube,
        resource_bridge,
    )
    .map_err(Error::WaylandDeviceNew)?;

    let jail = match simple_jail(&cfg, "wl_device")? {
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
            for dir in &wayland_socket_dirs {
                jail.mount_bind(dir, dir, true)?;
            }
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

#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
fn create_video_device(
    cfg: &Config,
    typ: devices::virtio::VideoDeviceType,
    resource_bridge: Tube,
) -> DeviceResult {
    let jail = match simple_jail(&cfg, "video_device")? {
        Some(mut jail) => {
            match typ {
                devices::virtio::VideoDeviceType::Decoder => {
                    add_crosvm_user_to_jail(&mut jail, "video-decoder")?
                }
                devices::virtio::VideoDeviceType::Encoder => {
                    add_crosvm_user_to_jail(&mut jail, "video-encoder")?
                }
            };

            // Create a tmpfs in the device's root directory so that we can bind mount files.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=67108864",
            )?;

            // Render node for libvda.
            let dev_dri_path = Path::new("/dev/dri/renderD128");
            jail.mount_bind(dev_dri_path, dev_dri_path, false)?;

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                // Device nodes used by libdrm through minigbm in libvda on AMD devices.
                let sys_dev_char_path = Path::new("/sys/dev/char");
                jail.mount_bind(sys_dev_char_path, sys_dev_char_path, false)?;
                let sys_devices_path = Path::new("/sys/devices");
                jail.mount_bind(sys_devices_path, sys_devices_path, false)?;

                // Required for loading dri libraries loaded by minigbm on AMD devices.
                let lib_dir = Path::new("/usr/lib64");
                jail.mount_bind(lib_dir, lib_dir, false)?;
            }

            // Device nodes required by libchrome which establishes Mojo connection in libvda.
            let dev_urandom_path = Path::new("/dev/urandom");
            jail.mount_bind(dev_urandom_path, dev_urandom_path, false)?;
            let system_bus_socket_path = Path::new("/run/dbus/system_bus_socket");
            jail.mount_bind(system_bus_socket_path, system_bus_socket_path, true)?;

            Some(jail)
        }
        None => None,
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(devices::virtio::VideoDevice::new(
            virtio::base_features(cfg.protected_vm),
            typ,
            Some(resource_bridge),
        )),
        jail,
    })
}

#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
fn register_video_device(
    devs: &mut Vec<VirtioDeviceStub>,
    video_tube: Tube,
    cfg: &Config,
    typ: devices::virtio::VideoDeviceType,
) -> std::result::Result<(), Error> {
    devs.push(create_video_device(cfg, typ, video_tube)?);
    Ok(())
}

fn create_vhost_vsock_device(cfg: &Config, cid: u64, mem: &GuestMemory) -> DeviceResult {
    let features = virtio::base_features(cfg.protected_vm);
    let dev = virtio::vhost::Vsock::new(&cfg.vhost_vsock_device_path, features, cid, mem)
        .map_err(Error::VhostVsockDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: simple_jail(&cfg, "vhost_vsock_device")?,
    })
}

fn create_fs_device(
    cfg: &Config,
    uid_map: &str,
    gid_map: &str,
    src: &Path,
    tag: &str,
    fs_cfg: virtio::fs::passthrough::Config,
    device_tube: Tube,
) -> DeviceResult {
    let max_open_files = get_max_open_files()?;
    let j = if cfg.sandbox {
        let seccomp_policy = cfg.seccomp_policy_dir.join("fs_device");
        let config = SandboxConfig {
            limit_caps: false,
            uid_map: Some(uid_map),
            gid_map: Some(gid_map),
            log_failures: cfg.seccomp_log_failures,
            seccomp_policy: &seccomp_policy,
        };
        let mut jail = create_base_minijail(src, Some(max_open_files), Some(&config))?;
        // We want bind mounts from the parent namespaces to propagate into the fs device's
        // namespace.
        jail.set_remount_mode(libc::MS_SLAVE);

        jail
    } else {
        create_base_minijail(src, Some(max_open_files), None)?
    };

    let features = virtio::base_features(cfg.protected_vm);
    // TODO(chirantan): Use more than one worker once the kernel driver has been fixed to not panic
    // when num_queues > 1.
    let dev =
        virtio::fs::Fs::new(features, tag, 1, fs_cfg, device_tube).map_err(Error::FsDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail: Some(j),
    })
}

fn create_9p_device(
    cfg: &Config,
    uid_map: &str,
    gid_map: &str,
    src: &Path,
    tag: &str,
    mut p9_cfg: p9::Config,
) -> DeviceResult {
    let max_open_files = get_max_open_files()?;
    let (jail, root) = if cfg.sandbox {
        let seccomp_policy = cfg.seccomp_policy_dir.join("9p_device");
        let config = SandboxConfig {
            limit_caps: false,
            uid_map: Some(uid_map),
            gid_map: Some(gid_map),
            log_failures: cfg.seccomp_log_failures,
            seccomp_policy: &seccomp_policy,
        };

        let mut jail = create_base_minijail(src, Some(max_open_files), Some(&config))?;
        // We want bind mounts from the parent namespaces to propagate into the 9p server's
        // namespace.
        jail.set_remount_mode(libc::MS_SLAVE);

        //  The shared directory becomes the root of the device's file system.
        let root = Path::new("/");
        (Some(jail), root)
    } else {
        // There's no mount namespace so we tell the server to treat the source directory as the
        // root.
        (None, src)
    };

    let features = virtio::base_features(cfg.protected_vm);
    p9_cfg.root = root.into();
    let dev = virtio::P9::new(features, tag, p9_cfg).map_err(Error::P9DeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

fn create_pmem_device(
    cfg: &Config,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    disk: &DiskOption,
    index: usize,
    pmem_device_tube: Tube,
) -> DeviceResult {
    // Special case '/proc/self/fd/*' paths. The FD is already open, just use it.
    let fd: File = if disk.path.parent() == Some(Path::new("/proc/self/fd")) {
        // Safe because we will validate |raw_fd|.
        unsafe { File::from_raw_descriptor(raw_descriptor_from_path(&disk.path)?) }
    } else {
        OpenOptions::new()
            .read(true)
            .write(!disk.read_only)
            .open(&disk.path)
            .map_err(|e| Error::Disk(disk.path.to_path_buf(), e))?
    };

    let arena_size = {
        let metadata =
            std::fs::metadata(&disk.path).map_err(|e| Error::Disk(disk.path.to_path_buf(), e))?;
        let disk_len = metadata.len();
        // Linux requires pmem region sizes to be 2 MiB aligned. Linux will fill any partial page
        // at the end of an mmap'd file and won't write back beyond the actual file length, but if
        // we just align the size of the file to 2 MiB then access beyond the last page of the
        // mapped file will generate SIGBUS. So use a memory mapping arena that will provide
        // padding up to 2 MiB.
        let alignment = 2 * 1024 * 1024;
        let align_adjust = if disk_len % alignment != 0 {
            alignment - (disk_len % alignment)
        } else {
            0
        };
        disk_len
            .checked_add(align_adjust)
            .ok_or(Error::PmemDeviceImageTooBig)?
    };

    let protection = {
        if disk.read_only {
            Protection::read()
        } else {
            Protection::read_write()
        }
    };

    let arena = {
        // Conversion from u64 to usize may fail on 32bit system.
        let arena_size = usize::try_from(arena_size).map_err(|_| Error::PmemDeviceImageTooBig)?;

        let mut arena = MemoryMappingArena::new(arena_size).map_err(Error::ReservePmemMemory)?;
        arena
            .add_fd_offset_protection(0, arena_size, &fd, 0, protection)
            .map_err(Error::ReservePmemMemory)?;
        arena
    };

    let mapping_address = resources
        .mmio_allocator(MmioType::High)
        .allocate_with_align(
            arena_size,
            Alloc::PmemDevice(index),
            format!("pmem_disk_image_{}", index),
            // Linux kernel requires pmem namespaces to be 128 MiB aligned.
            128 * 1024 * 1024, /* 128 MiB */
        )
        .map_err(Error::AllocatePmemDeviceAddress)?;

    let slot = vm
        .add_memory_region(
            GuestAddress(mapping_address),
            Box::new(arena),
            /* read_only = */ disk.read_only,
            /* log_dirty_pages = */ false,
        )
        .map_err(Error::AddPmemDeviceMemory)?;

    let dev = virtio::Pmem::new(
        virtio::base_features(cfg.protected_vm),
        fd,
        GuestAddress(mapping_address),
        slot,
        arena_size,
        Some(pmem_device_tube),
    )
    .map_err(Error::PmemDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev) as Box<dyn VirtioDevice>,
        jail: simple_jail(&cfg, "pmem_device")?,
    })
}

fn create_console_device(cfg: &Config, param: &SerialParameters) -> DeviceResult {
    let mut keep_rds = Vec::new();
    let evt = Event::new().map_err(Error::CreateEvent)?;
    let dev = param
        .create_serial_device::<Console>(cfg.protected_vm, &evt, &mut keep_rds)
        .map_err(Error::CreateConsole)?;

    let jail = match simple_jail(&cfg, "serial")? {
        Some(mut jail) => {
            // Create a tmpfs in the device's root directory so that we can bind mount the
            // log socket directory into it.
            // The size=67108864 is size=64*1024*1024 or size=64MB.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID) as usize,
                "size=67108864",
            )?;
            add_crosvm_user_to_jail(&mut jail, "serial")?;
            let res = param.add_bind_mounts(&mut jail);
            if res.is_err() {
                error!("failed to add bind mounts for console device");
            }
            Some(jail)
        }
        None => None,
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail, // TODO(dverkamp): use a separate policy for console?
    })
}

// gpu_device_tube is not used when GPU support is disabled.
#[cfg_attr(not(feature = "gpu"), allow(unused_variables))]
fn create_virtio_devices(
    cfg: &Config,
    mem: &GuestMemory,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    _exit_evt: &Event,
    wayland_device_tube: Tube,
    gpu_device_tube: Tube,
    balloon_device_tube: Tube,
    disk_device_tubes: &mut Vec<Tube>,
    pmem_device_tubes: &mut Vec<Tube>,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
    fs_device_tubes: &mut Vec<Tube>,
) -> DeviceResult<Vec<VirtioDeviceStub>> {
    let mut devs = Vec::new();

    for (_, param) in cfg
        .serial_parameters
        .iter()
        .filter(|(_k, v)| v.hardware == SerialHardware::VirtioConsole)
    {
        let dev = create_console_device(cfg, param)?;
        devs.push(dev);
    }

    for disk in &cfg.disks {
        let disk_device_tube = disk_device_tubes.remove(0);
        devs.push(create_block_device(cfg, disk, disk_device_tube)?);
    }

    for blk in &cfg.vhost_user_blk {
        devs.push(create_vhost_user_block_device(cfg, blk)?);
    }

    for (index, pmem_disk) in cfg.pmem_devices.iter().enumerate() {
        let pmem_device_tube = pmem_device_tubes.remove(0);
        devs.push(create_pmem_device(
            cfg,
            vm,
            resources,
            pmem_disk,
            index,
            pmem_device_tube,
        )?);
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

    if let Some(multi_touch_spec) = &cfg.virtio_multi_touch {
        devs.push(create_multi_touch_device(cfg, multi_touch_spec)?);
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

    if let Some(switches_socket) = &cfg.virtio_switches {
        devs.push(create_switches_device(cfg, switches_socket)?);
    }

    for dev_path in &cfg.virtio_input_evdevs {
        devs.push(create_vinput_device(cfg, dev_path)?);
    }

    devs.push(create_balloon_device(cfg, balloon_device_tube)?);

    // We checked above that if the IP is defined, then the netmask is, too.
    for tap_fd in &cfg.tap_fd {
        devs.push(create_tap_net_device(cfg, *tap_fd)?);
    }

    if let (Some(host_ip), Some(netmask), Some(mac_address)) =
        (cfg.host_ip, cfg.netmask, cfg.mac_address)
    {
        if !cfg.vhost_user_net.is_empty() {
            return Err(Error::VhostUserNetWithNetArgs);
        }
        devs.push(create_net_device(cfg, host_ip, netmask, mac_address, mem)?);
    }

    for net in &cfg.vhost_user_net {
        devs.push(create_vhost_user_net_device(cfg, net)?);
    }

    #[cfg_attr(not(feature = "gpu"), allow(unused_mut))]
    let mut resource_bridges = Vec::<Tube>::new();

    if !cfg.wayland_socket_paths.is_empty() {
        #[cfg_attr(not(feature = "gpu"), allow(unused_mut))]
        let mut wl_resource_bridge = None::<Tube>;

        #[cfg(feature = "gpu")]
        {
            if cfg.gpu_parameters.is_some() {
                let (wl_socket, gpu_socket) = Tube::pair().map_err(Error::CreateTube)?;
                resource_bridges.push(gpu_socket);
                wl_resource_bridge = Some(wl_socket);
            }
        }

        devs.push(create_wayland_device(
            cfg,
            wayland_device_tube,
            wl_resource_bridge,
        )?);
    }

    #[cfg(feature = "video-decoder")]
    let video_dec_tube = if cfg.video_dec {
        let (video_tube, gpu_tube) = Tube::pair().map_err(Error::CreateTube)?;
        resource_bridges.push(gpu_tube);
        Some(video_tube)
    } else {
        None
    };

    #[cfg(feature = "video-encoder")]
    let video_enc_tube = if cfg.video_enc {
        let (video_tube, gpu_tube) = Tube::pair().map_err(Error::CreateTube)?;
        resource_bridges.push(gpu_tube);
        Some(video_tube)
    } else {
        None
    };

    #[cfg(feature = "gpu")]
    {
        if let Some(gpu_parameters) = &cfg.gpu_parameters {
            let mut event_devices = Vec::new();
            if cfg.display_window_mouse {
                let (event_device_socket, virtio_dev_socket) =
                    UnixStream::pair().map_err(Error::CreateSocket)?;
                let (multi_touch_width, multi_touch_height) = cfg
                    .virtio_multi_touch
                    .as_ref()
                    .map(|multi_touch_spec| multi_touch_spec.get_size())
                    .unwrap_or((gpu_parameters.display_width, gpu_parameters.display_height));
                let dev = virtio::new_multi_touch(
                    virtio_dev_socket,
                    multi_touch_width,
                    multi_touch_height,
                    virtio::base_features(cfg.protected_vm),
                )
                .map_err(Error::InputDeviceNew)?;
                devs.push(VirtioDeviceStub {
                    dev: Box::new(dev),
                    jail: simple_jail(&cfg, "input_device")?,
                });
                event_devices.push(EventDevice::touchscreen(event_device_socket));
            }
            if cfg.display_window_keyboard {
                let (event_device_socket, virtio_dev_socket) =
                    UnixStream::pair().map_err(Error::CreateSocket)?;
                let dev = virtio::new_keyboard(
                    virtio_dev_socket,
                    virtio::base_features(cfg.protected_vm),
                )
                .map_err(Error::InputDeviceNew)?;
                devs.push(VirtioDeviceStub {
                    dev: Box::new(dev),
                    jail: simple_jail(&cfg, "input_device")?,
                });
                event_devices.push(EventDevice::keyboard(event_device_socket));
            }
            devs.push(create_gpu_device(
                cfg,
                _exit_evt,
                gpu_device_tube,
                resource_bridges,
                // Use the unnamed socket for GPU display screens.
                cfg.wayland_socket_paths.get(""),
                cfg.x_display.clone(),
                event_devices,
                map_request,
                mem,
            )?);
        }
    }

    #[cfg(feature = "video-decoder")]
    {
        if let Some(video_dec_tube) = video_dec_tube {
            register_video_device(
                &mut devs,
                video_dec_tube,
                cfg,
                devices::virtio::VideoDeviceType::Decoder,
            )?;
        }
    }

    #[cfg(feature = "video-encoder")]
    {
        if let Some(video_enc_tube) = video_enc_tube {
            register_video_device(
                &mut devs,
                video_enc_tube,
                cfg,
                devices::virtio::VideoDeviceType::Encoder,
            )?;
        }
    }

    if let Some(cid) = cfg.cid {
        devs.push(create_vhost_vsock_device(cfg, cid, mem)?);
    }

    for vhost_user_fs in &cfg.vhost_user_fs {
        devs.push(create_vhost_user_fs_device(cfg, &vhost_user_fs)?);
    }

    for shared_dir in &cfg.shared_dirs {
        let SharedDir {
            src,
            tag,
            kind,
            uid_map,
            gid_map,
            fs_cfg,
            p9_cfg,
        } = shared_dir;

        let dev = match kind {
            SharedDirKind::FS => {
                let device_tube = fs_device_tubes.remove(0);
                create_fs_device(cfg, uid_map, gid_map, src, tag, fs_cfg.clone(), device_tube)?
            }
            SharedDirKind::P9 => create_9p_device(cfg, uid_map, gid_map, src, tag, p9_cfg.clone())?,
        };
        devs.push(dev);
    }

    Ok(devs)
}

fn create_devices(
    cfg: &Config,
    mem: &GuestMemory,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    exit_evt: &Event,
    control_tubes: &mut Vec<TaggedControlTube>,
    wayland_device_tube: Tube,
    gpu_device_tube: Tube,
    balloon_device_tube: Tube,
    disk_device_tubes: &mut Vec<Tube>,
    pmem_device_tubes: &mut Vec<Tube>,
    fs_device_tubes: &mut Vec<Tube>,
    usb_provider: HostBackendDeviceProvider,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
) -> DeviceResult<Vec<(Box<dyn PciDevice>, Option<Minijail>)>> {
    let stubs = create_virtio_devices(
        &cfg,
        mem,
        vm,
        resources,
        exit_evt,
        wayland_device_tube,
        gpu_device_tube,
        balloon_device_tube,
        disk_device_tubes,
        pmem_device_tubes,
        map_request,
        fs_device_tubes,
    )?;

    let mut pci_devices = Vec::new();

    for stub in stubs {
        let (msi_host_tube, msi_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
        control_tubes.push(TaggedControlTube::VmIrq(msi_host_tube));
        let dev = VirtioPciDevice::new(mem.clone(), stub.dev, msi_device_tube)
            .map_err(Error::VirtioPciDev)?;
        let dev = Box::new(dev) as Box<dyn PciDevice>;
        pci_devices.push((dev, stub.jail));
    }

    #[cfg(feature = "audio")]
    for ac97_param in &cfg.ac97_parameters {
        let dev = Ac97Dev::try_new(mem.clone(), ac97_param.clone()).map_err(Error::CreateAc97)?;
        let jail = simple_jail(&cfg, dev.minijail_policy())?;
        pci_devices.push((Box::new(dev), jail));
    }

    // Create xhci controller.
    let usb_controller = Box::new(XhciController::new(mem.clone(), usb_provider));
    pci_devices.push((usb_controller, simple_jail(&cfg, "xhci")?));

    if !cfg.vfio.is_empty() {
        let vfio_container = Arc::new(Mutex::new(
            VfioContainer::new().map_err(Error::CreateVfioDevice)?,
        ));

        for vfio_path in &cfg.vfio {
            // create MSI, MSI-X, and Mem request sockets for each vfio device
            let (vfio_host_tube_msi, vfio_device_tube_msi) =
                Tube::pair().map_err(Error::CreateTube)?;
            control_tubes.push(TaggedControlTube::VmIrq(vfio_host_tube_msi));

            let (vfio_host_tube_msix, vfio_device_tube_msix) =
                Tube::pair().map_err(Error::CreateTube)?;
            control_tubes.push(TaggedControlTube::VmIrq(vfio_host_tube_msix));

            let (vfio_host_tube_mem, vfio_device_tube_mem) =
                Tube::pair().map_err(Error::CreateTube)?;
            control_tubes.push(TaggedControlTube::VmMemory(vfio_host_tube_mem));

            let vfiodevice = VfioDevice::new(vfio_path.as_path(), vm, mem, vfio_container.clone())
                .map_err(Error::CreateVfioDevice)?;
            let mut vfiopcidevice = Box::new(VfioPciDevice::new(
                vfiodevice,
                vfio_device_tube_msi,
                vfio_device_tube_msix,
                vfio_device_tube_mem,
            ));
            // early reservation for pass-through PCI devices.
            if vfiopcidevice.allocate_address(resources).is_err() {
                warn!(
                    "address reservation failed for vfio {}",
                    vfiopcidevice.debug_label()
                );
            }
            pci_devices.push((vfiopcidevice, simple_jail(&cfg, "vfio_device")?));
        }
    }

    Ok(pci_devices)
}

#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "tpm"), allow(dead_code))]
struct Ids {
    uid: uid_t,
    gid: gid_t,
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

fn raw_descriptor_from_path(path: &Path) -> Result<RawDescriptor> {
    if !path.is_file() {
        return Err(Error::InvalidFdPath);
    }
    let raw_descriptor = path
        .file_name()
        .and_then(|fd_osstr| fd_osstr.to_str())
        .and_then(|fd_str| fd_str.parse::<c_int>().ok())
        .ok_or(Error::InvalidFdPath)?;
    validate_raw_descriptor(raw_descriptor).map_err(Error::ValidateRawDescriptor)
}

trait IntoUnixStream {
    fn into_unix_stream(self) -> Result<UnixStream>;
}

impl<'a> IntoUnixStream for &'a Path {
    fn into_unix_stream(self) -> Result<UnixStream> {
        if self.parent() == Some(Path::new("/proc/self/fd")) {
            // Safe because we will validate |raw_fd|.
            unsafe { Ok(UnixStream::from_raw_fd(raw_descriptor_from_path(self)?)) }
        } else {
            UnixStream::connect(self).map_err(Error::InputEventsOpen)
        }
    }
}
impl<'a> IntoUnixStream for &'a PathBuf {
    fn into_unix_stream(self) -> Result<UnixStream> {
        self.as_path().into_unix_stream()
    }
}

impl IntoUnixStream for UnixStream {
    fn into_unix_stream(self) -> Result<UnixStream> {
        Ok(self)
    }
}

fn setup_vcpu_signal_handler<T: Vcpu>(use_hypervisor_signals: bool) -> Result<()> {
    if use_hypervisor_signals {
        unsafe {
            extern "C" fn handle_signal(_: c_int) {}
            // Our signal handler does nothing and is trivially async signal safe.
            register_rt_signal_handler(SIGRTMIN() + 0, handle_signal)
                .map_err(Error::RegisterSignalHandler)?;
        }
        block_signal(SIGRTMIN() + 0).map_err(Error::BlockSignal)?;
    } else {
        unsafe {
            extern "C" fn handle_signal<T: Vcpu>(_: c_int) {
                T::set_local_immediate_exit(true);
            }
            register_rt_signal_handler(SIGRTMIN() + 0, handle_signal::<T>)
                .map_err(Error::RegisterSignalHandler)?;
        }
    }
    Ok(())
}

// Sets up a vcpu and converts it into a runnable vcpu.
fn runnable_vcpu<V>(
    cpu_id: usize,
    vcpu: Option<V>,
    vm: impl VmArch,
    irq_chip: &mut impl IrqChipArch,
    vcpu_count: usize,
    run_rt: bool,
    vcpu_affinity: Vec<usize>,
    no_smt: bool,
    has_bios: bool,
    use_hypervisor_signals: bool,
) -> Result<(V, VcpuRunHandle)>
where
    V: VcpuArch,
{
    let mut vcpu = match vcpu {
        Some(v) => v,
        None => {
            // If vcpu is None, it means this arch/hypervisor requires create_vcpu to be called from
            // the vcpu thread.
            match vm
                .create_vcpu(cpu_id)
                .map_err(Error::CreateVcpu)?
                .downcast::<V>()
            {
                Ok(v) => *v,
                Err(_) => panic!("VM created wrong type of VCPU"),
            }
        }
    };

    irq_chip
        .add_vcpu(cpu_id, &vcpu)
        .map_err(Error::AddIrqChipVcpu)?;

    if !vcpu_affinity.is_empty() {
        if let Err(e) = set_cpu_affinity(vcpu_affinity) {
            error!("Failed to set CPU affinity: {}", e);
        }
    }

    Arch::configure_vcpu(
        vm.get_memory(),
        vm.get_hypervisor(),
        irq_chip,
        &mut vcpu,
        cpu_id,
        vcpu_count,
        has_bios,
        no_smt,
    )
    .map_err(Error::ConfigureVcpu)?;

    #[cfg(feature = "chromeos")]
    if let Err(e) = base::sched::enable_core_scheduling() {
        error!("Failed to enable core scheduling: {}", e);
    }

    if run_rt {
        const DEFAULT_VCPU_RT_LEVEL: u16 = 6;
        if let Err(e) = set_rt_prio_limit(u64::from(DEFAULT_VCPU_RT_LEVEL))
            .and_then(|_| set_rt_round_robin(i32::from(DEFAULT_VCPU_RT_LEVEL)))
        {
            warn!("Failed to set vcpu to real time: {}", e);
        }
    }

    if use_hypervisor_signals {
        let mut v = get_blocked_signals().map_err(Error::GetSignalMask)?;
        v.retain(|&x| x != SIGRTMIN() + 0);
        vcpu.set_signal_mask(&v).map_err(Error::SettingSignalMask)?;
    }

    let vcpu_run_handle = vcpu
        .take_run_handle(Some(SIGRTMIN() + 0))
        .map_err(Error::RunnableVcpu)?;

    Ok((vcpu, vcpu_run_handle))
}

#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
fn handle_debug_msg<V>(
    cpu_id: usize,
    vcpu: &V,
    guest_mem: &GuestMemory,
    d: VcpuDebug,
    reply_tube: &mpsc::Sender<VcpuDebugStatusMessage>,
) -> Result<()>
where
    V: VcpuArch + 'static,
{
    match d {
        VcpuDebug::ReadRegs => {
            let msg = VcpuDebugStatusMessage {
                cpu: cpu_id as usize,
                msg: VcpuDebugStatus::RegValues(
                    Arch::debug_read_registers(vcpu as &V).map_err(Error::HandleDebugCommand)?,
                ),
            };
            reply_tube
                .send(msg)
                .map_err(|e| Error::SendDebugStatus(Box::new(e)))
        }
        VcpuDebug::WriteRegs(regs) => {
            Arch::debug_write_registers(vcpu as &V, &regs).map_err(Error::HandleDebugCommand)?;
            reply_tube
                .send(VcpuDebugStatusMessage {
                    cpu: cpu_id as usize,
                    msg: VcpuDebugStatus::CommandComplete,
                })
                .map_err(|e| Error::SendDebugStatus(Box::new(e)))
        }
        VcpuDebug::ReadMem(vaddr, len) => {
            let msg = VcpuDebugStatusMessage {
                cpu: cpu_id as usize,
                msg: VcpuDebugStatus::MemoryRegion(
                    Arch::debug_read_memory(vcpu as &V, guest_mem, vaddr, len)
                        .unwrap_or(Vec::new()),
                ),
            };
            reply_tube
                .send(msg)
                .map_err(|e| Error::SendDebugStatus(Box::new(e)))
        }
        VcpuDebug::WriteMem(vaddr, buf) => {
            Arch::debug_write_memory(vcpu as &V, guest_mem, vaddr, &buf)
                .map_err(Error::HandleDebugCommand)?;
            reply_tube
                .send(VcpuDebugStatusMessage {
                    cpu: cpu_id as usize,
                    msg: VcpuDebugStatus::CommandComplete,
                })
                .map_err(|e| Error::SendDebugStatus(Box::new(e)))
        }
        VcpuDebug::EnableSinglestep => {
            Arch::debug_enable_singlestep(vcpu as &V).map_err(Error::HandleDebugCommand)?;
            reply_tube
                .send(VcpuDebugStatusMessage {
                    cpu: cpu_id as usize,
                    msg: VcpuDebugStatus::CommandComplete,
                })
                .map_err(|e| Error::SendDebugStatus(Box::new(e)))
        }
        VcpuDebug::SetHwBreakPoint(addrs) => {
            Arch::debug_set_hw_breakpoints(vcpu as &V, &addrs)
                .map_err(Error::HandleDebugCommand)?;
            reply_tube
                .send(VcpuDebugStatusMessage {
                    cpu: cpu_id as usize,
                    msg: VcpuDebugStatus::CommandComplete,
                })
                .map_err(|e| Error::SendDebugStatus(Box::new(e)))
        }
    }
}

fn run_vcpu<V>(
    cpu_id: usize,
    vcpu: Option<V>,
    vm: impl VmArch + 'static,
    mut irq_chip: impl IrqChipArch + 'static,
    vcpu_count: usize,
    run_rt: bool,
    vcpu_affinity: Vec<usize>,
    no_smt: bool,
    start_barrier: Arc<Barrier>,
    has_bios: bool,
    io_bus: devices::Bus,
    mmio_bus: devices::Bus,
    exit_evt: Event,
    requires_pvclock_ctrl: bool,
    from_main_tube: mpsc::Receiver<VcpuControl>,
    use_hypervisor_signals: bool,
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))] to_gdb_tube: Option<
        mpsc::Sender<VcpuDebugStatusMessage>,
    >,
) -> Result<JoinHandle<()>>
where
    V: VcpuArch + 'static,
{
    thread::Builder::new()
        .name(format!("crosvm_vcpu{}", cpu_id))
        .spawn(move || {
            // The VCPU thread must trigger the `exit_evt` in all paths, and a `ScopedEvent`'s Drop
            // implementation accomplishes that.
            let _scoped_exit_evt = ScopedEvent::from(exit_evt);

            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            let guest_mem = vm.get_memory().clone();
            let runnable_vcpu = runnable_vcpu(
                cpu_id,
                vcpu,
                vm,
                &mut irq_chip,
                vcpu_count,
                run_rt,
                vcpu_affinity,
                no_smt,
                has_bios,
                use_hypervisor_signals,
            );

            start_barrier.wait();

            let (vcpu, vcpu_run_handle) = match runnable_vcpu {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to start vcpu {}: {}", cpu_id, e);
                    return;
                }
            };

            let mut run_mode = VmRunMode::Running;
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            if to_gdb_tube.is_some() {
                // Wait until a GDB client attaches
                run_mode = VmRunMode::Breakpoint;
            }

            let mut interrupted_by_signal = false;

            'vcpu_loop: loop {
                // Start by checking for messages to process and the run state of the CPU.
                // An extra check here for Running so there isn't a need to call recv unless a
                // message is likely to be ready because a signal was sent.
                if interrupted_by_signal || run_mode != VmRunMode::Running {
                    'state_loop: loop {
                        // Tries to get a pending message without blocking first.
                        let msg = match from_main_tube.try_recv() {
                            Ok(m) => m,
                            Err(mpsc::TryRecvError::Empty) if run_mode == VmRunMode::Running => {
                                // If the VM is running and no message is pending, the state won't
                                // change.
                                break 'state_loop;
                            }
                            Err(mpsc::TryRecvError::Empty) => {
                                // If the VM is not running, wait until a message is ready.
                                match from_main_tube.recv() {
                                    Ok(m) => m,
                                    Err(mpsc::RecvError) => {
                                        error!("Failed to read from main tube in vcpu");
                                        break 'vcpu_loop;
                                    }
                                }
                            }
                            Err(mpsc::TryRecvError::Disconnected) => {
                                error!("Failed to read from main tube in vcpu");
                                break 'vcpu_loop;
                            }
                        };

                        // Collect all pending messages.
                        let mut messages = vec![msg];
                        messages.append(&mut from_main_tube.try_iter().collect());

                        for msg in messages {
                            match msg {
                                VcpuControl::RunState(new_mode) => {
                                    run_mode = new_mode;
                                    match run_mode {
                                        VmRunMode::Running => break 'state_loop,
                                        VmRunMode::Suspending => {
                                            // On KVM implementations that use a paravirtualized
                                            // clock (e.g. x86), a flag must be set to indicate to
                                            // the guest kernel that a vCPU was suspended. The guest
                                            // kernel will use this flag to prevent the soft lockup
                                            // detection from triggering when this vCPU resumes,
                                            // which could happen days later in realtime.
                                            if requires_pvclock_ctrl {
                                                if let Err(e) = vcpu.pvclock_ctrl() {
                                                    error!(
                                                        "failed to tell hypervisor vcpu {} is suspending: {}",
                                                        cpu_id, e
                                                    );
                                                }
                                            }
                                        }
                                        VmRunMode::Breakpoint => {}
                                        VmRunMode::Exiting => break 'vcpu_loop,
                                    }
                                }
                                #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
                                VcpuControl::Debug(d) => {
                                    match &to_gdb_tube {
                                        Some(ref ch) => {
                                            if let Err(e) = handle_debug_msg(
                                                cpu_id, &vcpu, &guest_mem, d, &ch,
                                            ) {
                                                error!("Failed to handle gdb message: {}", e);
                                            }
                                        },
                                        None => {
                                            error!("VcpuControl::Debug received while GDB feature is disabled: {:?}", d);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                interrupted_by_signal = false;

                // Vcpus may have run a HLT instruction, which puts them into a state other than
                // VcpuRunState::Runnable. In that case, this call to wait_until_runnable blocks
                // until either the irqchip receives an interrupt for this vcpu, or until the main
                // thread kicks this vcpu as a result of some VmControl operation. In most IrqChip
                // implementations HLT instructions do not make it to crosvm, and thus this is a
                // no-op that always returns VcpuRunState::Runnable.
                match irq_chip.wait_until_runnable(&vcpu) {
                    Ok(VcpuRunState::Runnable) => {}
                    Ok(VcpuRunState::Interrupted) => interrupted_by_signal = true,
                    Err(e) => error!(
                        "error waiting for vcpu {} to become runnable: {}",
                        cpu_id, e
                    ),
                }

                if !interrupted_by_signal {
                    match vcpu.run(&vcpu_run_handle) {
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
                        Ok(VcpuExit::IoapicEoi { vector }) => {
                            if let Err(e) = irq_chip.broadcast_eoi(vector) {
                                error!(
                                    "failed to broadcast eoi {} on vcpu {}: {}",
                                    vector, cpu_id, e
                                );
                            }
                        }
                        Ok(VcpuExit::IrqWindowOpen) => {}
                        Ok(VcpuExit::Hlt) => irq_chip.halted(cpu_id),
                        Ok(VcpuExit::Shutdown) => break,
                        Ok(VcpuExit::FailEntry {
                            hardware_entry_failure_reason,
                        }) => {
                            error!("vcpu hw run failure: {:#x}", hardware_entry_failure_reason);
                            break;
                        }
                        Ok(VcpuExit::SystemEvent(_, _)) => break,
                        Ok(VcpuExit::Debug { .. }) => {
                            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
                            {
                                let msg = VcpuDebugStatusMessage {
                                    cpu: cpu_id as usize,
                                    msg: VcpuDebugStatus::HitBreakPoint,
                                };
                                if let Some(ref ch) = to_gdb_tube {
                                    if let Err(e) = ch.send(msg) {
                                        error!("failed to notify breakpoint to GDB thread: {}", e);
                                        break;
                                    }
                                }
                                run_mode = VmRunMode::Breakpoint;
                            }
                        }
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
                }

                if interrupted_by_signal {
                    if use_hypervisor_signals {
                        // Try to clear the signal that we use to kick VCPU if it is pending before
                        // attempting to handle pause requests.
                        if let Err(e) = clear_signal(SIGRTMIN() + 0) {
                            error!("failed to clear pending signal: {}", e);
                            break;
                        }
                    } else {
                        vcpu.set_immediate_exit(false);
                    }
                }

                if let Err(e) = irq_chip.inject_interrupts(&vcpu) {
                    error!("failed to inject interrupts for vcpu {}: {}", cpu_id, e);
                }
            }
        })
        .map_err(Error::SpawnVcpu)
}

// Reads the contents of a file and converts the space-separated fields into a Vec of i64s.
// Returns an error if any of the fields fail to parse.
fn file_fields_to_i64<P: AsRef<Path>>(path: P) -> io::Result<Vec<i64>> {
    let mut file = File::open(path)?;

    let mut buf = [0u8; 32];
    let count = file.read(&mut buf)?;

    let content =
        str::from_utf8(&buf[..count]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    content
        .trim()
        .split_whitespace()
        .map(|x| {
            x.parse::<i64>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
        .collect()
}

// Reads the contents of a file and converts them into a u64, and if there
// are multiple fields it only returns the first one.
fn file_to_i64<P: AsRef<Path>>(path: P, nth: usize) -> io::Result<i64> {
    file_fields_to_i64(path)?
        .into_iter()
        .nth(nth)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty file"))
}

fn create_kvm_kernel_irq_chip(
    vm: &KvmVm,
    vcpu_count: usize,
    _ioapic_device_tube: Tube,
) -> base::Result<impl IrqChipArch> {
    let irq_chip = KvmKernelIrqChip::new(vm.try_clone()?, vcpu_count)?;
    Ok(irq_chip)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn create_kvm_split_irq_chip(
    vm: &KvmVm,
    vcpu_count: usize,
    ioapic_device_tube: Tube,
) -> base::Result<impl IrqChipArch> {
    let irq_chip =
        KvmSplitIrqChip::new(vm.try_clone()?, vcpu_count, ioapic_device_tube, Some(120))?;
    Ok(irq_chip)
}

pub fn run_config(cfg: Config) -> Result<()> {
    let components = setup_vm_components(&cfg)?;

    let guest_mem_layout =
        Arch::guest_memory_layout(&components).map_err(Error::GuestMemoryLayout)?;
    let guest_mem = GuestMemory::new(&guest_mem_layout).unwrap();
    let mut mem_policy = MemoryPolicy::empty();
    if components.hugepages {
        mem_policy |= MemoryPolicy::USE_HUGEPAGES;
    }
    guest_mem.set_memory_policy(mem_policy);
    let kvm = Kvm::new_with_path(&cfg.kvm_device_path).map_err(Error::CreateKvm)?;
    let vm = KvmVm::new(&kvm, guest_mem).map_err(Error::CreateVm)?;

    if cfg.split_irqchip {
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        {
            unimplemented!("KVM split irqchip mode only supported on x86 processors")
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            run_vm::<KvmVcpu, _, _, _>(cfg, components, vm, create_kvm_split_irq_chip)
        }
    } else {
        run_vm::<KvmVcpu, _, _, _>(cfg, components, vm, create_kvm_kernel_irq_chip)
    }
}

fn setup_vm_components(cfg: &Config) -> Result<VmComponents> {
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

    Ok(VmComponents {
        memory_size: cfg
            .memory
            .unwrap_or(256)
            .checked_mul(1024 * 1024)
            .ok_or(Error::MemoryTooLarge)?,
        vcpu_count: cfg.vcpu_count.unwrap_or(1),
        vcpu_affinity: cfg.vcpu_affinity.clone(),
        no_smt: cfg.no_smt,
        hugepages: cfg.hugepages,
        vm_image,
        android_fstab: cfg
            .android_fstab
            .as_ref()
            .map(|x| File::open(x).map_err(|e| Error::OpenAndroidFstab(x.to_path_buf(), e)))
            .map_or(Ok(None), |v| v.map(Some))?,
        pstore: cfg.pstore.clone(),
        initrd_image,
        extra_kernel_params: cfg.params.clone(),
        wayland_dmabuf: cfg.wayland_dmabuf,
        acpi_sdts: cfg
            .acpi_tables
            .iter()
            .map(|path| SDT::from_file(path).map_err(|e| Error::OpenAcpiTable(path.clone(), e)))
            .collect::<Result<Vec<SDT>>>()?,
        rt_cpus: cfg.rt_cpus.clone(),
        protected_vm: cfg.protected_vm,
        #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
        gdb: None,
        dmi_path: cfg.dmi_path.clone(),
    })
}

fn run_vm<Vcpu, V, I, FI>(
    cfg: Config,
    #[allow(unused_mut)] mut components: VmComponents,
    vm: V,
    create_irq_chip: FI,
) -> Result<()>
where
    Vcpu: VcpuArch + 'static,
    V: VmArch + 'static,
    I: IrqChipArch + 'static,
    FI: FnOnce(
        &V,
        usize, // vcpu_count
        Tube,  // ioapic_device_tube
    ) -> base::Result<I>,
{
    if cfg.sandbox {
        // Printing something to the syslog before entering minijail so that libc's syslogger has a
        // chance to open files necessary for its operation, like `/etc/localtime`. After jailing,
        // access to those files will not be possible.
        info!("crosvm entering multiprocess mode");
    }

    let (usb_control_tube, usb_provider) =
        HostBackendDeviceProvider::new().map_err(Error::CreateUsbProvider)?;
    // Masking signals is inherently dangerous, since this can persist across clones/execs. Do this
    // before any jailed devices have been spawned, so that we can catch any of them that fail very
    // quickly.
    let sigchld_fd = SignalFd::new(libc::SIGCHLD).map_err(Error::CreateSignalFd)?;

    let control_server_socket = match &cfg.socket_path {
        Some(path) => Some(UnlinkUnixSeqpacketListener(
            UnixSeqpacketListener::bind(path).map_err(Error::CreateControlServer)?,
        )),
        None => None,
    };

    let mut control_tubes = Vec::new();

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    if let Some(port) = cfg.gdb {
        // GDB needs a control socket to interrupt vcpus.
        let (gdb_host_tube, gdb_control_tube) = Tube::pair().map_err(Error::CreateTube)?;
        control_tubes.push(TaggedControlTube::Vm(gdb_host_tube));
        components.gdb = Some((port, gdb_control_tube));
    }

    let (wayland_host_tube, wayland_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
    control_tubes.push(TaggedControlTube::VmMemory(wayland_host_tube));
    // Balloon gets a special socket so balloon requests can be forwarded from the main process.
    let (balloon_host_tube, balloon_device_tube) = Tube::pair().map_err(Error::CreateTube)?;

    // Create one control socket per disk.
    let mut disk_device_tubes = Vec::new();
    let mut disk_host_tubes = Vec::new();
    let disk_count = cfg.disks.len();
    for _ in 0..disk_count {
        let (disk_host_tub, disk_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
        disk_host_tubes.push(disk_host_tub);
        disk_device_tubes.push(disk_device_tube);
    }

    let mut pmem_device_tubes = Vec::new();
    let pmem_count = cfg.pmem_devices.len();
    for _ in 0..pmem_count {
        let (pmem_host_tube, pmem_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
        pmem_device_tubes.push(pmem_device_tube);
        control_tubes.push(TaggedControlTube::VmMsync(pmem_host_tube));
    }

    let (gpu_host_tube, gpu_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
    control_tubes.push(TaggedControlTube::VmMemory(gpu_host_tube));

    let (ioapic_host_tube, ioapic_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
    control_tubes.push(TaggedControlTube::VmIrq(ioapic_host_tube));

    let battery = if cfg.battery_type.is_some() {
        let jail = match simple_jail(&cfg, "battery")? {
            #[cfg_attr(not(feature = "powerd-monitor-powerd"), allow(unused_mut))]
            Some(mut jail) => {
                // Setup a bind mount to the system D-Bus socket if the powerd monitor is used.
                #[cfg(feature = "power-monitor-powerd")]
                {
                    add_crosvm_user_to_jail(&mut jail, "battery")?;

                    // Create a tmpfs in the device's root directory so that we can bind mount files.
                    jail.mount_with_data(
                        Path::new("none"),
                        Path::new("/"),
                        "tmpfs",
                        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                        "size=67108864",
                    )?;

                    let system_bus_socket_path = Path::new("/run/dbus/system_bus_socket");
                    jail.mount_bind(system_bus_socket_path, system_bus_socket_path, true)?;
                }
                Some(jail)
            }
            None => None,
        };
        (&cfg.battery_type, jail)
    } else {
        (&cfg.battery_type, None)
    };

    let gralloc = RutabagaGralloc::new().map_err(Error::CreateGrallocError)?;
    let map_request: Arc<Mutex<Option<ExternalMapping>>> = Arc::new(Mutex::new(None));

    let fs_count = cfg
        .shared_dirs
        .iter()
        .filter(|sd| sd.kind == SharedDirKind::FS)
        .count();
    let mut fs_device_tubes = Vec::with_capacity(fs_count);
    for _ in 0..fs_count {
        let (fs_host_tube, fs_device_tube) = Tube::pair().map_err(Error::CreateTube)?;
        control_tubes.push(TaggedControlTube::Fs(fs_host_tube));
        fs_device_tubes.push(fs_device_tube);
    }

    #[cfg_attr(not(feature = "direct"), allow(unused_mut))]
    let mut linux: RunnableLinuxVm<_, Vcpu, _> = Arch::build_vm(
        components,
        &cfg.serial_parameters,
        simple_jail(&cfg, "serial")?,
        battery,
        vm,
        |mem, vm, sys_allocator, exit_evt| {
            create_devices(
                &cfg,
                mem,
                vm,
                sys_allocator,
                exit_evt,
                &mut control_tubes,
                wayland_device_tube,
                gpu_device_tube,
                balloon_device_tube,
                &mut disk_device_tubes,
                &mut pmem_device_tubes,
                &mut fs_device_tubes,
                usb_provider,
                Arc::clone(&map_request),
            )
        },
        |vm, vcpu_count| create_irq_chip(vm, vcpu_count, ioapic_device_tube),
    )
    .map_err(Error::BuildVm)?;

    #[cfg(feature = "direct")]
    if let Some(pmio) = &cfg.direct_pmio {
        let direct_io =
            Arc::new(devices::DirectIo::new(&pmio.path, false).map_err(Error::DirectIo)?);
        for range in pmio.ranges.iter() {
            linux
                .io_bus
                .insert_sync(direct_io.clone(), range.0, range.1)
                .unwrap();
        }
    };

    #[cfg(feature = "direct")]
    let mut irqs = Vec::new();

    #[cfg(feature = "direct")]
    for irq in &cfg.direct_level_irq {
        if !linux.resources.reserve_irq(*irq) {
            warn!("irq {} already reserved.", irq);
        }
        let trigger = Event::new().map_err(Error::CreateEvent)?;
        let resample = Event::new().map_err(Error::CreateEvent)?;
        linux
            .irq_chip
            .register_irq_event(*irq, &trigger, Some(&resample))
            .unwrap();
        let direct_irq =
            devices::DirectIrq::new(trigger, Some(resample)).map_err(Error::DirectIrq)?;
        direct_irq.irq_enable(*irq).map_err(Error::DirectIrq)?;
        irqs.push(direct_irq);
    }

    #[cfg(feature = "direct")]
    for irq in &cfg.direct_edge_irq {
        if !linux.resources.reserve_irq(*irq) {
            warn!("irq {} already reserved.", irq);
        }
        let trigger = Event::new().map_err(Error::CreateEvent)?;
        linux
            .irq_chip
            .register_irq_event(*irq, &trigger, None)
            .unwrap();
        let direct_irq = devices::DirectIrq::new(trigger, None).map_err(Error::DirectIrq)?;
        direct_irq.irq_enable(*irq).map_err(Error::DirectIrq)?;
        irqs.push(direct_irq);
    }

    run_control(
        linux,
        control_server_socket,
        control_tubes,
        balloon_host_tube,
        &disk_host_tubes,
        usb_control_tube,
        sigchld_fd,
        cfg.sandbox,
        Arc::clone(&map_request),
        cfg.balloon_bias,
        gralloc,
    )
}

/// Signals all running VCPUs to vmexit, sends VmRunMode message to each VCPU tube, and tells
/// `irq_chip` to stop blocking halted VCPUs. The tube message is set first because both the
/// signal and the irq_chip kick could cause the VCPU thread to continue through the VCPU run
/// loop.
fn kick_all_vcpus(
    vcpu_handles: &[(JoinHandle<()>, mpsc::Sender<vm_control::VcpuControl>)],
    irq_chip: &impl IrqChip,
    run_mode: &VmRunMode,
) {
    for (handle, tube) in vcpu_handles {
        if let Err(e) = tube.send(VcpuControl::RunState(run_mode.clone())) {
            error!("failed to send VmRunMode: {}", e);
        }
        let _ = handle.kill(SIGRTMIN() + 0);
    }
    irq_chip.kick_halted_vcpus();
}

// BalloonPolicy determines the size to set the balloon.
struct BalloonPolicy {
    // Estimate for when the guest starts aggressivly freeing memory.
    critical_guest_available: i64,
    critical_host_available: i64, // ChromeOS critical margin.
    guest_available_bias: i64,
    max_balloon_actual: i64, // The largest the balloon has ever been observed.
    prev_balloon_full_percent: i64, // How full was the balloon at the previous timestep.
    prev_guest_available: i64, // Available memory in the guest at the previous timestep.
}

const ONE_KB: i64 = 1024;
const ONE_MB: i64 = 1024 * ONE_KB;

const LOWMEM_AVAILABLE: &str = "/sys/kernel/mm/chromeos-low_mem/available";
const LOWMEM_MARGIN: &str = "/sys/kernel/mm/chromeos-low_mem/margin";

// BalloonPolicy implements the virtio balloon sizing logic.
// The balloon is sized with the following heuristics:
//   Balance Available
//     The balloon is sized to balance the amount of available memory above a
//     critical margin. The critical margin is the level at which memory is
//     freed. In the host, this is the ChromeOS available critical margin, which
//     is the trigger to kill tabs. In the guest, we estimate this level by
//     tracking the minimum amount of available memory, discounting sharp
//     'valleys'. If the guest manages to keep available memory above a given
//     level even with some pressure, then we determine that this is the
//     'critical' level for the guest. We don't update this critical value if
//     the balloon is fully inflated because in that case, the guest may be out
//     of memory to free.
//   guest_available_bias
//     Even if available memory is perfectly balanced between host and guest,
//     The size of the balloon will still drift randomly depending on whether
//     those host or guest reclaims memory first/faster every time memory is
//     low. To encourage large balloons to shrink and small balloons to grow,
//     the following bias is added to the guest critical margin:
//         (guest_available_bias * balloon_full_percent) / 100
//     This give the guest more memory when the balloon is full.
impl BalloonPolicy {
    fn new(
        memory_size: i64,
        critical_host_available: i64,
        guest_available_bias: i64,
    ) -> BalloonPolicy {
        // Estimate some reasonable initial maximum for balloon size.
        let max_balloon_actual = (memory_size * 3) / 4;
        // 400MB is above the zone min margin even for Crostini VMs on 16GB
        // devices (~85MB), and is above when Android Low Memory Killer kills
        // apps (~250MB).
        let critical_guest_available = 400 * ONE_MB;

        BalloonPolicy {
            critical_guest_available,
            critical_host_available,
            guest_available_bias,
            max_balloon_actual,
            prev_balloon_full_percent: 0,
            prev_guest_available: 0,
        }
    }
    fn delta(&mut self, stats: BalloonStats, balloon_actual_u: u64) -> Result<i64> {
        let guest_free = stats
            .free_memory
            .map(i64::try_from)
            .ok_or(Error::GuestFreeMissing())?
            .map_err(Error::GuestFreeTooLarge)?;
        let guest_cached = stats
            .disk_caches
            .map(i64::try_from)
            .ok_or(Error::GuestFreeMissing())?
            .map_err(Error::GuestFreeTooLarge)?;
        let balloon_actual = match balloon_actual_u {
            size if size < i64::max_value() as u64 => size as i64,
            _ => return Err(Error::BalloonActualTooLarge),
        };
        let guest_available = guest_free + guest_cached;
        // Available memory is reported in MB, and we need bytes.
        let host_available =
            file_to_i64(LOWMEM_AVAILABLE, 0).map_err(Error::ReadMemAvailable)? * ONE_MB;
        if self.max_balloon_actual < balloon_actual {
            self.max_balloon_actual = balloon_actual;
            info!(
                "balloon updated max_balloon_actual to {} MiB",
                self.max_balloon_actual / ONE_MB,
            );
        }
        let balloon_full_percent = balloon_actual * 100 / self.max_balloon_actual;
        // Update critical_guest_available if we see a lower available with the
        // balloon not fully inflated. If the balloon is completely inflated
        // there is a risk that the low available level we see comes at the cost
        // of stability. The Linux OOM Killer might have been forced to kill
        // something important, or page reclaim was so aggressive that there are
        // long UI hangs.
        if guest_available < self.critical_guest_available && balloon_full_percent < 95 {
            // To ignore temporary low memory states, we require that two guest
            // available measurements in a row are low.
            if self.prev_guest_available < self.critical_guest_available
                && self.prev_balloon_full_percent < 95
            {
                self.critical_guest_available = self.prev_guest_available;
                info!(
                    "balloon updated critical_guest_available to {} MiB",
                    self.critical_guest_available / ONE_MB,
                );
            }
        }

        // Compute the difference in available memory above the host and guest
        // critical thresholds.
        let bias = (self.guest_available_bias * balloon_full_percent) / 100;
        let guest_above_critical = guest_available - self.critical_guest_available - bias;
        let host_above_critical = host_available - self.critical_host_available;
        let balloon_delta = guest_above_critical - host_above_critical;
        // Only let the balloon take up MAX_CRITICAL_DELTA of available memory
        // below the critical level in host or guest.
        const MAX_CRITICAL_DELTA: i64 = 10 * ONE_MB;
        let balloon_delta_capped = if balloon_delta < 0 {
            // The balloon is deflating, taking memory from the host. Don't let
            // it take more than the amount of available memory above the
            // critical margin, plus MAX_CRITICAL_DELTA.
            max(
                balloon_delta,
                -(host_available - self.critical_host_available + MAX_CRITICAL_DELTA),
            )
        } else {
            // The balloon is inflating, taking memory from the guest. Don't let
            // it take more than the amount of available memory above the
            // critical margin, plus MAX_CRITICAL_DELTA.
            min(
                balloon_delta,
                guest_available - self.critical_guest_available + MAX_CRITICAL_DELTA,
            )
        };

        self.prev_balloon_full_percent = balloon_full_percent;
        self.prev_guest_available = guest_available;

        // Only return a value if target would change available above critical
        // by more than 1%, or we are within 1 MB of critical in host or guest.
        if guest_above_critical < ONE_MB
            || host_above_critical < ONE_MB
            || (balloon_delta.abs() * 100) / guest_above_critical > 1
            || (balloon_delta.abs() * 100) / host_above_critical > 1
        {
            // Finally, make sure the balloon delta won't cause a negative size.
            let result = max(balloon_delta_capped, -balloon_actual);
            if result != 0 {
                info!(
                    "balloon delta={:<6} ha={:<6} hc={:<6} ga={:<6} gc={:<6} bias={:<6} full={:>3}%",
                    result / ONE_MB,
                    host_available / ONE_MB,
                    self.critical_host_available / ONE_MB,
                    guest_available / ONE_MB,
                    self.critical_guest_available / ONE_MB,
                    bias / ONE_MB,
                    balloon_full_percent,
                );
            }
            return Ok(result);
        }
        Ok(0)
    }
}

fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static, I: IrqChipArch + 'static>(
    mut linux: RunnableLinuxVm<V, Vcpu, I>,
    control_server_socket: Option<UnlinkUnixSeqpacketListener>,
    mut control_tubes: Vec<TaggedControlTube>,
    balloon_host_tube: Tube,
    disk_host_tubes: &[Tube],
    usb_control_tube: Tube,
    sigchld_fd: SignalFd,
    sandbox: bool,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
    balloon_bias: i64,
    mut gralloc: RutabagaGralloc,
) -> Result<()> {
    #[derive(PollToken)]
    enum Token {
        Exit,
        Suspend,
        ChildSignal,
        IrqFd { index: IrqEventIndex },
        BalanceMemory,
        BalloonResult,
        VmControlServer,
        VmControl { index: usize },
    }

    stdin()
        .set_raw_mode()
        .expect("failed to set terminal raw mode");

    let wait_ctx = WaitContext::build_with(&[
        (&linux.exit_evt, Token::Exit),
        (&linux.suspend_evt, Token::Suspend),
        (&sigchld_fd, Token::ChildSignal),
    ])
    .map_err(Error::WaitContextAdd)?;

    if let Some(socket_server) = &control_server_socket {
        wait_ctx
            .add(socket_server, Token::VmControlServer)
            .map_err(Error::WaitContextAdd)?;
    }
    for (index, socket) in control_tubes.iter().enumerate() {
        wait_ctx
            .add(socket.as_ref(), Token::VmControl { index })
            .map_err(Error::WaitContextAdd)?;
    }

    let events = linux
        .irq_chip
        .irq_event_tokens()
        .map_err(Error::WaitContextAdd)?;

    for (index, _gsi, evt) in events {
        wait_ctx
            .add(&evt, Token::IrqFd { index })
            .map_err(Error::WaitContextAdd)?;
    }

    // Balance available memory between guest and host every second.
    let mut balancemem_timer = Timer::new().map_err(Error::CreateTimer)?;
    let mut balloon_policy = if let Ok(critical_margin) = file_to_i64(LOWMEM_MARGIN, 0) {
        // Create timer request balloon stats every 1s.
        wait_ctx
            .add(&balancemem_timer, Token::BalanceMemory)
            .map_err(Error::WaitContextAdd)?;
        let balancemem_dur = Duration::from_secs(1);
        let balancemem_int = Duration::from_secs(1);
        balancemem_timer
            .reset(balancemem_dur, Some(balancemem_int))
            .map_err(Error::ResetTimer)?;

        // Listen for balloon statistics from the guest so we can balance.
        wait_ctx
            .add(&balloon_host_tube, Token::BalloonResult)
            .map_err(Error::WaitContextAdd)?;
        Some(BalloonPolicy::new(
            linux.vm.get_memory().memory_size() as i64,
            critical_margin * ONE_MB,
            balloon_bias,
        ))
    } else {
        warn!("Unable to open low mem margin, maybe not a chrome os kernel");
        None
    };

    if sandbox {
        // Before starting VCPUs, in case we started with some capabilities, drop them all.
        drop_capabilities().map_err(Error::DropCapabilities)?;
    }

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    // Create a channel for GDB thread.
    let (to_gdb_channel, from_vcpu_channel) = if linux.gdb.is_some() {
        let (s, r) = mpsc::channel();
        (Some(s), Some(r))
    } else {
        (None, None)
    };

    let mut vcpu_handles = Vec::with_capacity(linux.vcpu_count);
    let vcpu_thread_barrier = Arc::new(Barrier::new(linux.vcpu_count + 1));
    let use_hypervisor_signals = !linux
        .vm
        .get_hypervisor()
        .check_capability(&HypervisorCap::ImmediateExit);
    setup_vcpu_signal_handler::<Vcpu>(use_hypervisor_signals)?;

    let vcpus: Vec<Option<_>> = match linux.vcpus.take() {
        Some(vec) => vec.into_iter().map(Some).collect(),
        None => iter::repeat_with(|| None).take(linux.vcpu_count).collect(),
    };
    for (cpu_id, vcpu) in vcpus.into_iter().enumerate() {
        let (to_vcpu_channel, from_main_channel) = mpsc::channel();
        let vcpu_affinity = match linux.vcpu_affinity.clone() {
            Some(VcpuAffinity::Global(v)) => v,
            Some(VcpuAffinity::PerVcpu(mut m)) => m.remove(&cpu_id).unwrap_or_default(),
            None => Default::default(),
        };
        let handle = run_vcpu(
            cpu_id,
            vcpu,
            linux.vm.try_clone().map_err(Error::CloneEvent)?,
            linux.irq_chip.try_clone().map_err(Error::CloneEvent)?,
            linux.vcpu_count,
            linux.rt_cpus.contains(&cpu_id),
            vcpu_affinity,
            linux.no_smt,
            vcpu_thread_barrier.clone(),
            linux.has_bios,
            linux.io_bus.clone(),
            linux.mmio_bus.clone(),
            linux.exit_evt.try_clone().map_err(Error::CloneEvent)?,
            linux.vm.check_capability(VmCap::PvClockSuspend),
            from_main_channel,
            use_hypervisor_signals,
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            to_gdb_channel.clone(),
        )?;
        vcpu_handles.push((handle, to_vcpu_channel));
    }

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    // Spawn GDB thread.
    if let Some((gdb_port_num, gdb_control_tube)) = linux.gdb.take() {
        let to_vcpu_channels = vcpu_handles
            .iter()
            .map(|(_handle, channel)| channel.clone())
            .collect();
        let target = GdbStub::new(
            gdb_control_tube,
            to_vcpu_channels,
            from_vcpu_channel.unwrap(), // Must succeed to unwrap()
        );
        thread::Builder::new()
            .name("gdb".to_owned())
            .spawn(move || gdb_thread(target, gdb_port_num))
            .map_err(Error::SpawnGdbServer)?;
    };

    vcpu_thread_barrier.wait();

    'wait: loop {
        let events = {
            match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to poll: {}", e);
                    break;
                }
            }
        };

        if let Err(e) = linux.irq_chip.process_delayed_irq_events() {
            warn!("can't deliver delayed irqs: {}", e);
        }

        let mut vm_control_indices_to_remove = Vec::new();
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::Exit => {
                    info!("vcpu requested shutdown");
                    break 'wait;
                }
                Token::Suspend => {
                    info!("VM requested suspend");
                    linux.suspend_evt.read().unwrap();
                    kick_all_vcpus(&vcpu_handles, &linux.irq_chip, &VmRunMode::Suspending);
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
                    break 'wait;
                }
                Token::IrqFd { index } => {
                    if let Err(e) = linux.irq_chip.service_irq_event(index) {
                        error!("failed to signal irq {}: {}", index, e);
                    }
                }
                Token::BalanceMemory => {
                    balancemem_timer.wait().map_err(Error::Timer)?;
                    let command = BalloonControlCommand::Stats {};
                    if let Err(e) = balloon_host_tube.send(&command) {
                        warn!("failed to send stats request to balloon device: {}", e);
                    }
                }
                Token::BalloonResult => {
                    match balloon_host_tube.recv() {
                        Ok(BalloonControlResult::Stats {
                            stats,
                            balloon_actual: balloon_actual_u,
                        }) => {
                            match balloon_policy
                                .as_mut()
                                .map(|p| p.delta(stats, balloon_actual_u))
                            {
                                None => {
                                    error!(
                                        "got result from balloon stats, but no policy is running"
                                    );
                                }
                                Some(Err(e)) => {
                                    warn!("failed to run balloon policy {}", e);
                                }
                                Some(Ok(delta)) if delta != 0 => {
                                    let target = max((balloon_actual_u as i64) + delta, 0) as u64;
                                    let command =
                                        BalloonControlCommand::Adjust { num_bytes: target };
                                    if let Err(e) = balloon_host_tube.send(&command) {
                                        warn!(
                                            "failed to send memory value to balloon device: {}",
                                            e
                                        );
                                    }
                                }
                                Some(Ok(_)) => {}
                            }
                        }
                        Err(e) => {
                            error!("failed to recv BalloonControlResult: {}", e);
                        }
                    };
                }
                Token::VmControlServer => {
                    if let Some(socket_server) = &control_server_socket {
                        match socket_server.accept() {
                            Ok(socket) => {
                                wait_ctx
                                    .add(
                                        &socket,
                                        Token::VmControl {
                                            index: control_tubes.len(),
                                        },
                                    )
                                    .map_err(Error::WaitContextAdd)?;
                                control_tubes.push(TaggedControlTube::Vm(Tube::new(socket)));
                            }
                            Err(e) => error!("failed to accept socket: {}", e),
                        }
                    }
                }
                Token::VmControl { index } => {
                    if let Some(socket) = control_tubes.get(index) {
                        match socket {
                            TaggedControlTube::Vm(tube) => match tube.recv::<VmRequest>() {
                                Ok(request) => {
                                    let mut run_mode_opt = None;
                                    let response = request.execute(
                                        &mut run_mode_opt,
                                        &balloon_host_tube,
                                        disk_host_tubes,
                                        &usb_control_tube,
                                        &mut linux.bat_control,
                                    );
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmResponse: {}", e);
                                    }
                                    if let Some(run_mode) = run_mode_opt {
                                        info!("control socket changed run mode to {}", run_mode);
                                        match run_mode {
                                            VmRunMode::Exiting => {
                                                break 'wait;
                                            }
                                            other => {
                                                if other == VmRunMode::Running {
                                                    linux.io_bus.notify_resume();
                                                }
                                                kick_all_vcpus(
                                                    &vcpu_handles,
                                                    &linux.irq_chip,
                                                    &other,
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    if let TubeError::Disconnected = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmRequest: {}", e);
                                    }
                                }
                            },
                            TaggedControlTube::VmMemory(tube) => {
                                match tube.recv::<VmMemoryRequest>() {
                                    Ok(request) => {
                                        let response = request.execute(
                                            &mut linux.vm,
                                            &mut linux.resources,
                                            Arc::clone(&map_request),
                                            &mut gralloc,
                                        );
                                        if let Err(e) = tube.send(&response) {
                                            error!("failed to send VmMemoryControlResponse: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        if let TubeError::Disconnected = e {
                                            vm_control_indices_to_remove.push(index);
                                        } else {
                                            error!("failed to recv VmMemoryControlRequest: {}", e);
                                        }
                                    }
                                }
                            }
                            TaggedControlTube::VmIrq(tube) => match tube.recv::<VmIrqRequest>() {
                                Ok(request) => {
                                    let response = {
                                        let irq_chip = &mut linux.irq_chip;
                                        request.execute(
                                            |setup| match setup {
                                                IrqSetup::Event(irq, ev) => {
                                                    if let Some(event_index) = irq_chip
                                                        .register_irq_event(irq, ev, None)?
                                                    {
                                                        match wait_ctx.add(
                                                            ev,
                                                            Token::IrqFd {
                                                                index: event_index
                                                            },
                                                        ) {
                                                            Err(e) => {
                                                                warn!("failed to add IrqFd to poll context: {}", e);
                                                                Err(e)
                                                            },
                                                            Ok(_) => {
                                                                Ok(())
                                                            }
                                                        }
                                                    } else {
                                                        Ok(())
                                                    }
                                                }
                                                IrqSetup::Route(route) => irq_chip.route_irq(route),
                                            },
                                            &mut linux.resources,
                                        )
                                    };
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmIrqResponse: {}", e);
                                    }
                                }
                                Err(e) => {
                                    if let TubeError::Disconnected = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmIrqRequest: {}", e);
                                    }
                                }
                            },
                            TaggedControlTube::VmMsync(tube) => {
                                match tube.recv::<VmMsyncRequest>() {
                                    Ok(request) => {
                                        let response = request.execute(&mut linux.vm);
                                        if let Err(e) = tube.send(&response) {
                                            error!("failed to send VmMsyncResponse: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        if let TubeError::Disconnected = e {
                                            vm_control_indices_to_remove.push(index);
                                        } else {
                                            error!("failed to recv VmMsyncRequest: {}", e);
                                        }
                                    }
                                }
                            }
                            TaggedControlTube::Fs(tube) => match tube.recv::<FsMappingRequest>() {
                                Ok(request) => {
                                    let response =
                                        request.execute(&mut linux.vm, &mut linux.resources);
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmResponse: {}", e);
                                    }
                                }
                                Err(e) => {
                                    if let TubeError::Disconnected = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmResponse: {}", e);
                                    }
                                }
                            },
                        }
                    }
                }
            }
        }

        for event in events.iter().filter(|e| e.is_hungup) {
            match event.token {
                Token::Exit => {}
                Token::Suspend => {}
                Token::ChildSignal => {}
                Token::IrqFd { index: _ } => {}
                Token::BalanceMemory => {}
                Token::BalloonResult => {}
                Token::VmControlServer => {}
                Token::VmControl { index } => {
                    // It's possible more data is readable and buffered while the socket is hungup,
                    // so don't delete the tube from the poll context until we're sure all the
                    // data is read.
                    if control_tubes
                        .get(index)
                        .map(|s| !s.as_ref().is_packet_ready())
                        .unwrap_or(false)
                    {
                        vm_control_indices_to_remove.push(index);
                    }
                }
            }
        }

        // Sort in reverse so the highest indexes are removed first. This removal algorithm
        // preserves correct indexes as each element is removed.
        vm_control_indices_to_remove.sort_unstable_by_key(|&k| Reverse(k));
        vm_control_indices_to_remove.dedup();
        for index in vm_control_indices_to_remove {
            // Delete the socket from the `wait_ctx` synchronously. Otherwise, the kernel will do
            // this automatically when the FD inserted into the `wait_ctx` is closed after this
            // if-block, but this removal can be deferred unpredictably. In some instances where the
            // system is under heavy load, we can even get events returned by `wait_ctx` for an FD
            // that has already been closed. Because the token associated with that spurious event
            // now belongs to a different socket, the control loop will start to interact with
            // sockets that might not be ready to use. This can cause incorrect hangup detection or
            // blocking on a socket that will never be ready. See also: crbug.com/1019986
            if let Some(socket) = control_tubes.get(index) {
                wait_ctx.delete(socket).map_err(Error::WaitContextDelete)?;
            }

            // This line implicitly drops the socket at `index` when it gets returned by
            // `swap_remove`. After this line, the socket at `index` is not the one from
            // `vm_control_indices_to_remove`. Because of this socket's change in index, we need to
            // use `wait_ctx.modify` to change the associated index in its `Token::VmControl`.
            control_tubes.swap_remove(index);
            if let Some(tube) = control_tubes.get(index) {
                wait_ctx
                    .modify(tube, EventType::Read, Token::VmControl { index })
                    .map_err(Error::WaitContextAdd)?;
            }
        }
    }

    kick_all_vcpus(&vcpu_handles, &linux.irq_chip, &VmRunMode::Exiting);
    for (handle, _) in vcpu_handles {
        if let Err(e) = handle.join() {
            error!("failed to join vcpu thread: {:?}", e);
        }
    }

    // Explicitly drop the VM structure here to allow the devices to clean up before the
    // control sockets are closed when this function exits.
    mem::drop(linux);

    stdin()
        .set_canon_mode()
        .expect("failed to restore canonical mode for terminal");

    Ok(())
}
