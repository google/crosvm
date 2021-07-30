// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use arch::{self, LinuxArch};
use base::TubeError;
use devices::virtio;
use devices::virtio::vhost::user::Error as VhostUserError;
use std::error::Error as StdError;
use std::fmt::{self, Display};
use std::io;
use std::num::ParseIntError;
use std::path::PathBuf;
#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
use std::sync::mpsc;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::X8664arch as Arch;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use {
    aarch64::AArch64 as Arch,
    devices::IrqChipAArch64 as IrqChipArch,
    hypervisor::{VcpuAArch64 as VcpuArch, VmAArch64 as VmArch},
};

use net_util::Error as NetError;
use remain::sorted;
#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
use vm_control::VcpuDebugStatusMessage;

#[sorted]
#[derive(Debug)]
pub enum Error {
    AddGpuDeviceMemory(base::Error),
    AddIrqChipVcpu(base::Error),
    AddPmemDeviceMemory(base::Error),
    AllocateGpuDeviceAddress,
    AllocatePmemDeviceAddress(resources::Error),
    BalloonDeviceNew(virtio::BalloonError),
    BlockDeviceNew(base::Error),
    BlockSignal(base::signal::Error),
    BuildVm(<Arch as LinuxArch>::Error),
    ChownTpmStorage(base::Error),
    CloneEvent(base::Error),
    CloneVcpu(base::Error),
    ConfigureVcpu(<Arch as LinuxArch>::Error),
    ConnectTube(io::Error),
    #[cfg(feature = "audio")]
    CreateAc97(devices::PciDeviceError),
    CreateConsole(arch::serial::Error),
    CreateControlServer(io::Error),
    CreateDiskError(disk::Error),
    CreateEvent(base::Error),
    CreateGrallocError(rutabaga_gfx::RutabagaError),
    CreateGuestMemory(vm_memory::GuestMemoryError),
    CreateIrqChip(base::Error),
    CreateKvm(base::Error),
    CreateSignalFd(base::SignalFdError),
    CreateSocket(io::Error),
    CreateTapDevice(NetError),
    CreateTimer(base::Error),
    CreateTpmStorage(PathBuf, io::Error),
    CreateTube(TubeError),
    #[cfg(feature = "usb")]
    CreateUsbProvider(devices::usb::host_backend::error::Error),
    CreateVcpu(base::Error),
    CreateVfioDevice(devices::vfio::VfioError),
    CreateVfioKvmDevice(base::Error),
    CreateVirtioIommu(base::Error),
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
    GenerateAcpi,
    GetMaxOpenFiles(io::Error),
    GetSignalMask(base::signal::Error),
    GuestMemoryLayout(<Arch as LinuxArch>::Error),
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    HandleDebugCommand(<Arch as LinuxArch>::Error),
    InputDeviceNew(virtio::InputError),
    InputEventsOpen(io::Error),
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
    #[cfg(feature = "audio")]
    SoundDeviceNew(virtio::SoundError),
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    SpawnGdbServer(io::Error),
    SpawnVcpu(io::Error),
    SwiotlbTooLarge,
    Timer(base::Error),
    ValidateRawDescriptor(base::Error),
    VhostNetDeviceNew(virtio::vhost::Error),
    VhostUserBlockDeviceNew(VhostUserError),
    VhostUserConsoleDeviceNew(VhostUserError),
    VhostUserFsDeviceNew(VhostUserError),
    VhostUserMac80211HwsimNew(VhostUserError),
    VhostUserNetDeviceNew(VhostUserError),
    VhostUserNetWithNetArgs,
    VhostUserWlDeviceNew(VhostUserError),
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
            BalloonDeviceNew(e) => write!(f, "failed to create balloon: {}", e),
            BlockDeviceNew(e) => write!(f, "failed to create block device: {}", e),
            BlockSignal(e) => write!(f, "failed to block signal: {}", e),
            BuildVm(e) => write!(f, "The architecture failed to build the vm: {}", e),
            ChownTpmStorage(e) => write!(f, "failed to chown tpm storage: {}", e),
            CloneEvent(e) => write!(f, "failed to clone event: {}", e),
            CloneVcpu(e) => write!(f, "failed to clone vcpu: {}", e),
            ConfigureVcpu(e) => write!(f, "failed to configure vcpu: {}", e),
            ConnectTube(e) => write!(f, "failed to connect to tube: {}", e),
            #[cfg(feature = "audio")]
            CreateAc97(e) => write!(f, "failed to create ac97 device: {}", e),
            CreateConsole(e) => write!(f, "failed to create console device: {}", e),
            CreateControlServer(e) => write!(f, "failed to create control server: {}", e),
            CreateDiskError(e) => write!(f, "failed to create virtual disk: {}", e),
            CreateEvent(e) => write!(f, "failed to create event: {}", e),
            CreateGrallocError(e) => write!(f, "failed to create gralloc: {}", e),
            CreateGuestMemory(e) => write!(f, "failed to create guest memory: {}", e),
            CreateIrqChip(e) => write!(f, "failed to create IRQ chip: {}", e),
            CreateKvm(e) => write!(f, "failed to create kvm: {}", e),
            CreateSignalFd(e) => write!(f, "failed to create signalfd: {}", e),
            CreateSocket(e) => write!(f, "failed to create socket: {}", e),
            CreateTapDevice(e) => write!(f, "failed to create tap device: {}", e),
            CreateTimer(e) => write!(f, "failed to create Timer: {}", e),
            CreateTpmStorage(p, e) => {
                write!(f, "failed to create tpm storage dir {}: {}", p.display(), e)
            }
            CreateTube(e) => write!(f, "failed to create tube: {}", e),
            #[cfg(feature = "usb")]
            CreateUsbProvider(e) => write!(f, "failed to create usb provider: {}", e),
            CreateVcpu(e) => write!(f, "failed to create vcpu: {}", e),
            CreateVfioDevice(e) => write!(f, "Failed to create vfio device {}", e),
            CreateVfioKvmDevice(e) => write!(f, "failed to create KVM vfio device: {}", e),
            CreateVirtioIommu(e) => write!(f, "Failed to create IOMMU device {}", e),
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
            GenerateAcpi => write!(f, "failed to generate ACPI table"),
            GetMaxOpenFiles(e) => write!(f, "failed to get max number of open files: {}", e),
            GetSignalMask(e) => write!(f, "failed to retrieve signal mask for vcpu: {}", e),
            GuestMemoryLayout(e) => write!(f, "failed to create guest memory layout: {}", e),
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            HandleDebugCommand(e) => write!(f, "failed to handle a gdb command: {}", e),
            InputDeviceNew(e) => write!(f, "failed to set up input device: {}", e),
            InputEventsOpen(e) => write!(f, "failed to open event device: {}", e),
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
            #[cfg(feature = "audio")]
            SoundDeviceNew(e) => write!(f, "failed to create sound device: {}", e),
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            SpawnGdbServer(e) => write!(f, "failed to spawn GDB thread: {}", e),
            SpawnVcpu(e) => write!(f, "failed to spawn VCPU thread: {}", e),
            SwiotlbTooLarge => write!(f, "requested swiotlb size too large"),
            Timer(e) => write!(f, "failed to read timer fd: {}", e),
            ValidateRawDescriptor(e) => write!(f, "failed to validate raw descriptor: {}", e),
            VhostNetDeviceNew(e) => write!(f, "failed to set up vhost networking: {}", e),
            VhostUserBlockDeviceNew(e) => {
                write!(f, "failed to set up vhost-user block device: {}", e)
            }
            VhostUserConsoleDeviceNew(e) => {
                write!(f, "failed to set up vhost-user console device: {}", e)
            }
            VhostUserFsDeviceNew(e) => write!(f, "failed to set up vhost-user fs device: {}", e),
            VhostUserMac80211HwsimNew(e) => {
                write!(f, "failed to set up vhost-user mac80211_hwsim device {}", e)
            }
            VhostUserNetDeviceNew(e) => write!(f, "failed to set up vhost-user net device: {}", e),
            VhostUserNetWithNetArgs => write!(
                f,
                "vhost-user-net cannot be used with any of --host_ip, --netmask or --mac"
            ),
            VhostUserWlDeviceNew(e) => {
                write!(f, "failed to set up vhost-user wl device: {}", e)
            }
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

pub type Result<T> = std::result::Result<T, Error>;
