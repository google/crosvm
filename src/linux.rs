// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::ffi::{CString, CStr};
use std::fmt;
use std::fs::{File, OpenOptions, remove_file};
use std::io::{self, stdin, stdout};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Barrier};
use std::thread;
use std::thread::JoinHandle;

use libc;

use device_manager;
use devices;
use io_jail::{self, Minijail};
use kernel_cmdline;
use kernel_loader;
use kvm::*;
use qcow::{self, QcowFile};
use sys_util::*;
use sys_util;
use vm_control::VmRequest;

use Config;
use DiskType;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64;

pub enum Error {
    BalloonDeviceNew(devices::virtio::BalloonError),
    BlockDeviceNew(sys_util::Error),
    ChownWaylandRoot(sys_util::Error),
    CloneEventFd(sys_util::Error),
    Cmdline(kernel_cmdline::Error),
    CreateEventFd(sys_util::Error),
    CreateGuestMemory(sys_util::GuestMemoryError),
    CreateIrqChip(sys_util::Error),
    CreateKvm(sys_util::Error),
    CreatePit(sys_util::Error),
    CreateSignalFd(sys_util::SignalFdError),
    CreateSocket(io::Error),
    CreateVcpu(sys_util::Error),
    CreateVm(sys_util::Error),
    DeviceJail(io_jail::Error),
    DevicePivotRoot(io_jail::Error),
    Disk(io::Error),
    GetWaylandGroup(sys_util::Error),
    LoadCmdline(kernel_loader::Error),
    LoadKernel(kernel_loader::Error),
    NetDeviceNew(devices::virtio::NetError),
    NoVarEmpty,
    OpenKernel(PathBuf, io::Error),
    QcowDeviceCreate(qcow::Error),
    RegisterBalloon(device_manager::Error),
    RegisterBlock(device_manager::Error),
    RegisterIrqfd(sys_util::Error),
    RegisterNet(device_manager::Error),
    RegisterRng(device_manager::Error),
    RegisterVsock(device_manager::Error),
    RegisterWayland(device_manager::Error),
    RngDeviceNew(devices::virtio::RngError),
    SettingGidMap(io_jail::Error),
    SettingUidMap(io_jail::Error),
    SetTssAddr(sys_util::Error),
    SignalFd(sys_util::SignalFdError),
    SpawnVcpu(io::Error),
    VhostNetDeviceNew(devices::virtio::vhost::Error),
    VhostVsockDeviceNew(devices::virtio::vhost::Error),
    WaylandDeviceNew(sys_util::Error),
    WaylandTempDir(sys_util::Error),
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ConfigureSystem(x86_64::Error),
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ConfigureVcpu(x86_64::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::BalloonDeviceNew(ref e) => write!(f, "failed to create balloon: {:?}", e),
            &Error::BlockDeviceNew(ref e) => write!(f, "failed to create block device: {:?}", e),
            &Error::ChownWaylandRoot(ref e) => {
                write!(f, "error chowning wayland root directory: {:?}", e)
            }
            &Error::CloneEventFd(ref e) => write!(f, "failed to clone eventfd: {:?}", e),
            &Error::Cmdline(ref e) => write!(f, "the given kernel command line was invalid: {}", e),
            &Error::CreateEventFd(ref e) => write!(f, "failed to create eventfd: {:?}", e),
            &Error::CreateGuestMemory(ref e) => write!(f, "failed to create guest memory: {:?}", e),
            &Error::CreateIrqChip(ref e) => {
                write!(f, "failed to create in-kernel IRQ chip: {:?}", e)
            }
            &Error::CreateKvm(ref e) => write!(f, "failed to open /dev/kvm: {:?}", e),
            &Error::CreatePit(ref e) => write!(f, "failed to create in-kernel PIT: {:?}", e),
            &Error::CreateSignalFd(ref e) => write!(f, "failed to create signalfd: {:?}", e),
            &Error::CreateSocket(ref e) => write!(f, "failed to create socket: {}", e),
            &Error::CreateVcpu(ref e) => write!(f, "failed to create VCPU: {:?}", e),
            &Error::CreateVm(ref e) => write!(f, "failed to create KVM VM object: {:?}", e),
            &Error::DeviceJail(ref e) => write!(f, "failed to jail device: {}", e),
            &Error::DevicePivotRoot(ref e) => write!(f, "failed to pivot root device: {}", e),
            &Error::Disk(ref e) => write!(f, "failed to load disk image: {}", e),
            &Error::GetWaylandGroup(ref e) => {
                write!(f, "could not find gid for wayland group: {:?}", e)
            }
            &Error::LoadCmdline(ref e) => write!(f, "error loading kernel command line: {:?}", e),
            &Error::LoadKernel(ref e) => write!(f, "error loading kernel: {:?}", e),
            &Error::NetDeviceNew(ref e) => write!(f, "failed to set up virtio networking: {:?}", e),
            &Error::NoVarEmpty => write!(f, "/var/empty doesn't exist, can't jail devices."),
            &Error::OpenKernel(ref p, ref e) => {
                write!(f, "failed to open kernel image {:?}: {}", p, e)
            }
            &Error::QcowDeviceCreate(ref e) => {
                write!(f, "failed to read qcow formatted file {:?}", e)
            }
            &Error::RegisterBalloon(ref e) => {
                write!(f, "error registering balloon device: {:?}", e)
            },
            &Error::RegisterBlock(ref e) => write!(f, "error registering block device: {:?}", e),
            &Error::RegisterIrqfd(ref e) => write!(f, "error registering irqfd: {:?}", e),
            &Error::RegisterNet(ref e) => write!(f, "error registering net device: {:?}", e),
            &Error::RegisterRng(ref e) => write!(f, "error registering rng device: {:?}", e),
            &Error::RegisterVsock(ref e) => {
                write!(f, "error registering virtual socket device: {:?}", e)
            }
            &Error::RegisterWayland(ref e) => write!(f, "error registering wayland device: {}", e),
            &Error::RngDeviceNew(ref e) => write!(f, "failed to set up rng: {:?}", e),
            &Error::SettingGidMap(ref e) => write!(f, "error setting GID map: {}", e),
            &Error::SettingUidMap(ref e) => write!(f, "error setting UID map: {}", e),
            &Error::SetTssAddr(ref e) => write!(f, "failed to set TSS address: {:?}", e),
            &Error::SignalFd(ref e) => write!(f, "failed to read signal fd: {:?}", e),
            &Error::SpawnVcpu(ref e) => write!(f, "failed to spawn VCPU thread: {:?}", e),
            &Error::VhostNetDeviceNew(ref e) => {
                write!(f, "failed to set up vhost networking: {:?}", e)
            }
            &Error::VhostVsockDeviceNew(ref e) => {
                write!(f, "failed to set up virtual socket device: {:?}", e)
            }
            &Error::WaylandDeviceNew(ref e) => {
                write!(f, "failed to create wayland device: {:?}", e)
            }
            &Error::WaylandTempDir(ref e) => {
                write!(f, "failed to create wayland device jail directroy: {:?}", e)
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            &Error::ConfigureSystem(ref e) => write!(f, "error configuring system: {:?}", e),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            &Error::ConfigureVcpu(ref e) => write!(f, "failed to configure vcpu: {:?}", e),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

struct UnlinkUnixDatagram(UnixDatagram);
impl AsRef<UnixDatagram> for UnlinkUnixDatagram {
    fn as_ref(&self) -> &UnixDatagram{
        &self.0
    }
}
impl Drop for UnlinkUnixDatagram {
    fn drop(&mut self) {
        if let Ok(addr) = self.0.local_addr() {
            if let Some(path) = addr.as_pathname() {
                if let Err(e) = remove_file(path) {
                    warn!("failed to remove control socket file: {:?}", e);
                }
            }
        }
    }
}

const KERNEL_START_OFFSET: usize = 0x200000;
const CMDLINE_OFFSET: usize = 0x20000;
const CMDLINE_MAX_SIZE: usize = KERNEL_START_OFFSET - CMDLINE_OFFSET;
const BASE_DEV_MEMORY_PFN: u64 = 1u64 << 26;

fn create_base_minijail(root: &Path, seccomp_policy: &Path) -> Result<Minijail> {
    // All child jails run in a new user namespace without any users mapped,
    // they run as nobody unless otherwise configured.
    let mut j = Minijail::new().map_err(|e| Error::DeviceJail(e))?;
    j.namespace_pids();
    j.namespace_user();
    j.namespace_user_disable_setgroups();
    // Don't need any capabilities.
    j.use_caps(0);
    // Create a new mount namespace with an empty root FS.
    j.namespace_vfs();
    j.enter_pivot_root(root)
        .map_err(|e| Error::DevicePivotRoot(e))?;
    // Run in an empty network namespace.
    j.namespace_net();
    // Apply the block device seccomp policy.
    j.no_new_privs();
    // Use TSYNC only for the side effect of it using SECCOMP_RET_TRAP, which will correctly kill
    // the entire device process if a worker thread commits a seccomp violation.
    j.set_seccomp_filter_tsync();
    j.parse_seccomp_filters(seccomp_policy)
        .map_err(|e| Error::DeviceJail(e))?;
    j.use_seccomp_filter();
    // Don't do init setup.
    j.run_as_init();
    Ok(j)
}

fn setup_memory(memory: Option<usize>) -> Result<GuestMemory> {
    let mem_size = memory.unwrap_or(256) << 20;
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    let arch_mem_regions = vec![(GuestAddress(0), mem_size)];
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let arch_mem_regions = x86_64::arch_memory_regions(mem_size);
    GuestMemory::new(&arch_mem_regions).map_err(Error::CreateGuestMemory)
}

fn setup_io_bus(vm: &mut Vm,
                exit_evt: EventFd)
                -> Result<(devices::Bus, Arc<Mutex<devices::Serial>>)> {
    struct NoDevice;
    impl devices::BusDevice for NoDevice {}

    let mut io_bus = devices::Bus::new();

    let com_evt_1_3 = EventFd::new().map_err(Error::CreateEventFd)?;
    let com_evt_2_4 = EventFd::new().map_err(Error::CreateEventFd)?;
    let stdio_serial =
        Arc::new(Mutex::new(devices::Serial::new_out(com_evt_1_3
                                                         .try_clone()
                                                         .map_err(Error::CloneEventFd)?,
                                                     Box::new(stdout()))));
    let nul_device = Arc::new(Mutex::new(NoDevice));
    io_bus.insert(stdio_serial.clone(), 0x3f8, 0x8).unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(devices::Serial::new_sink(com_evt_2_4
                                                                  .try_clone()
                                                                  .map_err(Error::CloneEventFd)?))),
                0x2f8,
                0x8)
        .unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(devices::Serial::new_sink(com_evt_1_3
                                                                  .try_clone()
                                                                  .map_err(Error::CloneEventFd)?))),
                0x3e8,
                0x8)
        .unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(devices::Serial::new_sink(com_evt_2_4
                                                                  .try_clone()
                                                                  .map_err(Error::CloneEventFd)?))),
                0x2e8,
                0x8)
        .unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(devices::Cmos::new())), 0x70, 0x2)
        .unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(devices::I8042Device::new(exit_evt
                                                                  .try_clone()
                                                                  .map_err(Error::CloneEventFd)?))),
                0x061,
                0x4)
        .unwrap();
    io_bus.insert(nul_device.clone(), 0x040, 0x8).unwrap(); // ignore pit
    io_bus.insert(nul_device.clone(), 0x0ed, 0x1).unwrap(); // most likely this one does nothing
    io_bus.insert(nul_device.clone(), 0x0f0, 0x2).unwrap(); // ignore fpu
    io_bus.insert(nul_device.clone(), 0xcf8, 0x8).unwrap(); // ignore pci

    vm.register_irqfd(&com_evt_1_3, 4)
        .map_err(Error::RegisterIrqfd)?;
    vm.register_irqfd(&com_evt_2_4, 3)
        .map_err(Error::RegisterIrqfd)?;

    Ok((io_bus, stdio_serial))
}

fn setup_mmio_bus(cfg: &Config,
                  vm: &mut Vm,
                  mem: &GuestMemory,
                  cmdline: &mut kernel_cmdline::Cmdline,
                  control_sockets: &mut Vec<UnlinkUnixDatagram>,
                  balloon_device_socket: UnixDatagram)
                  -> Result<devices::Bus> {
    static DEFAULT_PIVOT_ROOT: &'static str = "/var/empty";
    let mut device_manager =
        device_manager::DeviceManager::new(vm, mem.clone(), 0x1000, 0xd0000000, 5);

    // An empty directory for jailed device's pivot root.
    let empty_root_path = Path::new(DEFAULT_PIVOT_ROOT);
    if cfg.multiprocess && !empty_root_path.exists() {
        return Err(Error::NoVarEmpty);
    }

    for disk in &cfg.disks {
        let mut raw_image = OpenOptions::new()
                            .read(true)
                            .write(disk.writable)
                            .open(&disk.path)
                            .map_err(|e| Error::Disk(e))?;
        let block_box: Box<devices::virtio::VirtioDevice> = match disk.disk_type {
            DiskType::FlatFile => { // Access as a raw block device.
                Box::new(devices::virtio::Block::new(raw_image)
                    .map_err(|e| Error::BlockDeviceNew(e))?)
            }
            DiskType::Qcow => { // Valid qcow header present
                let qcow_image = QcowFile::from(raw_image)
                    .map_err(|e| Error::QcowDeviceCreate(e))?;
                Box::new(devices::virtio::Block::new(qcow_image)
                    .map_err(|e| Error::BlockDeviceNew(e))?)
            }
        };
        let jail = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("block_device.policy");
            Some(create_base_minijail(empty_root_path, &policy_path)?)
        }
        else {
            None
        };

        device_manager
            .register_mmio(block_box, jail, cmdline)
            .map_err(Error::RegisterBlock)?;
    }

    let rng_box = Box::new(devices::virtio::Rng::new().map_err(Error::RngDeviceNew)?);
    let rng_jail = if cfg.multiprocess {
        let policy_path: PathBuf = cfg.seccomp_policy_dir.join("rng_device.policy");
        Some(create_base_minijail(empty_root_path, &policy_path)?)
    } else {
        None
    };
    device_manager
        .register_mmio(rng_box, rng_jail, cmdline)
        .map_err(Error::RegisterRng)?;

    let balloon_box = Box::new(devices::virtio::Balloon::new(balloon_device_socket)
                                   .map_err(Error::BalloonDeviceNew)?);
    let balloon_jail = if cfg.multiprocess {
        let policy_path: PathBuf = cfg.seccomp_policy_dir.join("balloon_device.policy");
        Some(create_base_minijail(empty_root_path, &policy_path)?)
    } else {
        None
    };
    device_manager.register_mmio(balloon_box, balloon_jail, cmdline)
        .map_err(Error::RegisterBalloon)?;

    // We checked above that if the IP is defined, then the netmask is, too.
    if let Some(host_ip) = cfg.host_ip {
        if let Some(netmask) = cfg.netmask {
            let net_box: Box<devices::virtio::VirtioDevice> = if cfg.vhost_net {
                Box::new(devices::virtio::vhost::Net::new(host_ip, netmask, &mem)
                             .map_err(Error::VhostNetDeviceNew)?)
            } else {
                Box::new(devices::virtio::Net::new(host_ip, netmask)
                                   .map_err(|e| Error::NetDeviceNew(e))?)
            };

            let jail = if cfg.multiprocess {
                let policy_path: PathBuf = if cfg.vhost_net {
                    cfg.seccomp_policy_dir.join("vhost_net_device.policy")
                } else {
                    cfg.seccomp_policy_dir.join("net_device.policy")
                };

                Some(create_base_minijail(empty_root_path, &policy_path)?)
            }
            else {
                None
            };

            device_manager
                .register_mmio(net_box, jail, cmdline)
                .map_err(Error::RegisterNet)?;
        }
    }

    if let Some(wayland_socket_path) = cfg.wayland_socket_path.as_ref() {
        let jailed_wayland_path = Path::new("/wayland-0");

        let (host_socket, device_socket) = UnixDatagram::pair().map_err(Error::CreateSocket)?;
        control_sockets.push(UnlinkUnixDatagram(host_socket));
        let wl_box = Box::new(devices::virtio::Wl::new(if cfg.multiprocess {
                                                           &jailed_wayland_path
                                                       } else {
                                                           wayland_socket_path.as_path()
                                                       },
                                                       device_socket)
                                      .map_err(Error::WaylandDeviceNew)?);

        let jail = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("wl_device.policy");
            let mut jail = create_base_minijail(empty_root_path, &policy_path)?;

            // Create a tmpfs in the device's root directory so that we can bind mount the
            // wayland socket into it.  The size=67108864 is size=64*1024*1024 or size=64MB.
            jail.mount_with_data(Path::new("none"), Path::new("/"), "tmpfs",
                                 (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                                 "size=67108864")
                .unwrap();

            // Bind mount the wayland socket into jail's root. This is necessary since each
            // new wayland context must open() the socket.
            jail.mount_bind(wayland_socket_path.as_path(), jailed_wayland_path, true)
                .unwrap();

            // Set the uid/gid for the jailed process, and give a basic id map. This
            // is required for the above bind mount to work.
            let wayland_group = cfg.wayland_group.as_ref().map(|s| s.as_str()).unwrap_or("wayland");
            let wayland_cstr = CString::new(wayland_group).unwrap();
            let wayland_gid = get_group_id(&wayland_cstr)
                .map_err(Error::GetWaylandGroup)?;

            let crosvm_user_group = CStr::from_bytes_with_nul(b"crosvm\0").unwrap();
            let crosvm_uid = match get_user_id(&crosvm_user_group) {
                Ok(u) => u,
                Err(e) => {
                    warn!("falling back to current user id for Wayland: {:?}", e);
                    geteuid()
                }
            };
            jail.change_uid(crosvm_uid);
            jail.change_gid(wayland_gid);
            jail.uidmap(&format!("{0} {0} 1", crosvm_uid))
                .map_err(Error::SettingUidMap)?;
            jail.gidmap(&format!("{0} {0} 1", wayland_gid))
                .map_err(Error::SettingGidMap)?;

            Some(jail)
        } else {
            None
        };
        device_manager
            .register_mmio(wl_box, jail, cmdline)
            .map_err(Error::RegisterWayland)?;
    }

    if let Some(cid) = cfg.cid {
        let vsock_box = Box::new(devices::virtio::vhost::Vsock::new(cid, &mem)
                                     .map_err(Error::VhostVsockDeviceNew)?);

        let jail = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("vhost_vsock_device.policy");

            Some(create_base_minijail(empty_root_path, &policy_path)?)
        } else {
            None
        };

        device_manager
            .register_mmio(vsock_box, jail, cmdline)
            .map_err(Error::RegisterVsock)?;
    }

    Ok(device_manager.bus)
}

fn setup_system_memory(mem: &GuestMemory,
                       vcpu_count: u32,
                       mut kernel_image: File,
                       cmdline: &CStr)
                       -> Result<()> {
    let kernel_start_addr = GuestAddress(KERNEL_START_OFFSET);
    let cmdline_addr = GuestAddress(CMDLINE_OFFSET);
    kernel_loader::load_kernel(mem, kernel_start_addr, &mut kernel_image)
        .map_err(Error::LoadKernel)?;
    kernel_loader::load_cmdline(mem, cmdline_addr, cmdline)
        .map_err(Error::LoadCmdline)?;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    x86_64::configure_system(mem,
                             kernel_start_addr,
                             cmdline_addr,
                             cmdline.to_bytes().len() + 1,
                             vcpu_count as u8)
            .map_err(Error::ConfigureSystem)?;
    Ok(())
}

fn setup_vm(kvm: &Kvm, mem: GuestMemory) -> Result<Vm> {
    let vm = Vm::new(&kvm, mem).map_err(Error::CreateVm)?;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let tss_addr = GuestAddress(0xfffbd000);
        vm.set_tss_addr(tss_addr).expect("set tss addr failed");
        vm.create_pit().expect("create pit failed");
    }
    vm.create_irq_chip().map_err(Error::CreateIrqChip)?;
    Ok(vm)
}

fn setup_vcpu(kvm: &Kvm,
              vm: &Vm,
              cpu_id: u32,
              vcpu_count: u32,
              start_barrier: Arc<Barrier>,
              exit_evt: EventFd,
              kill_signaled: Arc<AtomicBool>,
              io_bus: devices::Bus,
              mmio_bus: devices::Bus)
              -> Result<JoinHandle<()>> {
    let kernel_start_addr = GuestAddress(KERNEL_START_OFFSET);
    let vcpu = Vcpu::new(cpu_id as libc::c_ulong, &kvm, &vm)
        .map_err(Error::CreateVcpu)?;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    x86_64::configure_vcpu(vm.get_memory(),
                           kernel_start_addr,
                           &kvm,
                           &vcpu,
                           cpu_id as u64,
                           vcpu_count as u64)
            .map_err(Error::ConfigureVcpu)?;
    thread::Builder::new()
        .name(format!("crosvm_vcpu{}", cpu_id))
        .spawn(move || {
            unsafe {
                extern "C" fn handle_signal() {}
                // Our signal handler does nothing and is trivially async signal safe.
                register_signal_handler(0, handle_signal)
                    .expect("failed to register vcpu signal handler");
            }

            start_barrier.wait();
            loop {
                let run_res = vcpu.run();
                match run_res {
                    Ok(run) => {
                        match run {
                            VcpuExit::IoIn(addr, data) => {
                                io_bus.read(addr as u64, data);
                            }
                            VcpuExit::IoOut(addr, data) => {
                                io_bus.write(addr as u64, data);
                            }
                            VcpuExit::MmioRead(addr, data) => {
                                mmio_bus.read(addr, data);
                            }
                            VcpuExit::MmioWrite(addr, data) => {
                                mmio_bus.write(addr, data);
                            }
                            VcpuExit::Hlt => break,
                            VcpuExit::Shutdown => break,
                            r => warn!("unexpected vcpu exit: {:?}", r),
                        }
                    }
                    Err(e) => {
                        match e.errno() {
                            libc::EAGAIN | libc::EINTR => {},
                            _ => {
                                error!("vcpu hit unknown error: {:?}", e);
                                break;
                            }
                        }
                    }
                }
                if kill_signaled.load(Ordering::SeqCst) {
                    break;
                }
            }
            exit_evt
                .write(1)
                .expect("failed to signal vcpu exit eventfd");
        })
        .map_err(Error::SpawnVcpu)
}

fn run_control(vm: &mut Vm,
               control_sockets: Vec<UnlinkUnixDatagram>,
               next_dev_pfn: &mut u64,
               stdio_serial: Arc<Mutex<devices::Serial>>,
               exit_evt: EventFd,
               sigchld_fd: SignalFd,
               kill_signaled: Arc<AtomicBool>,
               vcpu_handles: Vec<JoinHandle<()>>,
               balloon_host_socket: UnixDatagram)
               -> Result<()> {
    const MAX_VM_FD_RECV: usize = 1;

    const EXIT: u32 = 0;
    const STDIN: u32 = 1;
    const CHILD_SIGNAL: u32 = 2;
    const VM_BASE: u32 = 3;

    let stdin_handle = stdin();
    let stdin_lock = stdin_handle.lock();
    stdin_lock
        .set_raw_mode()
        .expect("failed to set terminal raw mode");

    let mut pollables = Vec::new();
    pollables.push((EXIT, &exit_evt as &Pollable));
    pollables.push((STDIN, &stdin_lock as &Pollable));
    pollables.push((CHILD_SIGNAL, &sigchld_fd as &Pollable));
    for (i, socket) in control_sockets.iter().enumerate() {
        pollables.push((VM_BASE + i as u32, socket.as_ref() as &Pollable));
    }

    let mut poller = Poller::new(pollables.len());
    let mut scm = Scm::new(MAX_VM_FD_RECV);

    'poll: loop {
        let tokens = {
            match poller.poll(&pollables[..]) {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to poll: {:?}", e);
                    break;
                }
            }
        };
        for &token in tokens {
            match token {
                EXIT => {
                    info!("vcpu requested shutdown");
                    break 'poll;
                }
                STDIN => {
                    let mut out = [0u8; 64];
                    match stdin_lock.read_raw(&mut out[..]) {
                        Ok(0) => {
                            // Zero-length read indicates EOF. Remove from pollables.
                            pollables.retain(|&pollable| pollable.0 != STDIN);
                        },
                        Err(e) => {
                            warn!("error while reading stdin: {:?}", e);
                            pollables.retain(|&pollable| pollable.0 != STDIN);
                        },
                        Ok(count) => {
                            stdio_serial
                                .lock()
                                .unwrap()
                                .queue_input_bytes(&out[..count])
                                .expect("failed to queue bytes into serial port");
                        },
                    }
                }
                CHILD_SIGNAL => {
                    // Print all available siginfo structs, then exit the loop.
                    loop {
                        let result = sigchld_fd.read().map_err(Error::SignalFd)?;
                        if let Some(siginfo) = result {
                            error!("child {} died: signo {}, status {}, code {}",
                                   siginfo.ssi_pid,
                                   siginfo.ssi_signo,
                                   siginfo.ssi_status,
                                   siginfo.ssi_code);
                        }
                        break 'poll;
                    }
                }
                t if t >= VM_BASE && t < VM_BASE + (control_sockets.len() as u32) => {
                    let socket = &control_sockets[(t - VM_BASE) as usize];
                    match VmRequest::recv(&mut scm, socket.as_ref()) {
                        Ok(request) => {
                            let mut running = true;
                            let response =
                                request.execute(vm, next_dev_pfn,
                                                &mut running, &balloon_host_socket);
                            if let Err(e) = response.send(&mut scm, socket.as_ref()) {
                                error!("failed to send VmResponse: {:?}", e);
                            }
                            if !running {
                                info!("control socket requested exit");
                                break 'poll;
                            }
                        }
                        Err(e) => error!("failed to recv VmRequest: {:?}", e),
                    }
                }
                _ => {}
            }
        }
    }

    // vcpu threads MUST see the kill signaled flag, otherwise they may
    // re-enter the VM.
    kill_signaled.store(true, Ordering::SeqCst);
    for handle in vcpu_handles {
        match handle.kill(0) {
            Ok(_) => {
                if let Err(e) = handle.join() {
                    error!("failed to join vcpu thread: {:?}", e);
                }
            }
            Err(e) => error!("failed to kill vcpu thread: {:?}", e),
        }
    }

    stdin_lock
        .set_canon_mode()
        .expect("failed to restore canonical mode for terminal");

    Ok(())
}

pub fn run_config(cfg: Config) -> Result<()> {
    if cfg.multiprocess {
        // Printing something to the syslog before entering minijail so that libc's syslogger has a
        // chance to open files necessary for its operation, like `/etc/localtime`. After jailing,
        // access to those files will not be possible.
        info!("crosvm entering multiprocess mode");
    }


    // Masking signals is inherently dangerous, since this can persist across clones/execs. Do this
    // before any jailed devices have been spawned, so that we can catch any of them that fail very
    // quickly.
    let sigchld_fd = SignalFd::new(libc::SIGCHLD).map_err(Error::CreateSignalFd)?;

    let mut control_sockets = Vec::new();
    if let Some(ref path) = cfg.socket_path {
        let path = Path::new(path);
        let control_socket = UnixDatagram::bind(path).map_err(Error::CreateSocket)?;
        control_sockets.push(UnlinkUnixDatagram(control_socket));
    }

    let kill_signaled = Arc::new(AtomicBool::new(false));
    let exit_evt = EventFd::new().map_err(Error::CreateEventFd)?;

    let mem = setup_memory(cfg.memory)?;
    let kvm = Kvm::new().map_err(Error::CreateKvm)?;
    let mut vm = setup_vm(&kvm, mem.clone())?;

    let mut cmdline = kernel_cmdline::Cmdline::new(CMDLINE_MAX_SIZE);
    cmdline
        .insert_str("console=ttyS0 noacpi reboot=k panic=1 pci=off")
        .unwrap();

    let mut next_dev_pfn = BASE_DEV_MEMORY_PFN;
    let mut control_sockets = Vec::new();
    let (io_bus, stdio_serial) = setup_io_bus(&mut vm,
                                              exit_evt.try_clone().map_err(Error::CloneEventFd)?)?;

    let (balloon_host_socket, balloon_device_socket) = UnixDatagram::pair()
        .map_err(Error::CreateSocket)?;
    let mmio_bus = setup_mmio_bus(&cfg,
                                  &mut vm,
                                  &mem,
                                  &mut cmdline,
                                  &mut control_sockets,
                                  balloon_device_socket)?;

    if !cfg.params.is_empty() {
        cmdline.insert_str(&cfg.params).map_err(Error::Cmdline)?;
    }

    let vcpu_count = cfg.vcpu_count.unwrap_or(1);
    let kernel_image = File::open(cfg.kernel_path.as_path())
        .map_err(|e| Error::OpenKernel(cfg.kernel_path.clone(), e))?;
    setup_system_memory(&mem,
                        vcpu_count,
                        kernel_image,
                        &CString::new(cmdline).unwrap())?;

    let vcpu_handles = Vec::with_capacity(vcpu_count as usize);
    let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));
    for cpu_id in 0..vcpu_count {
        let exit_evt = exit_evt.try_clone().map_err(Error::CloneEventFd)?;
        setup_vcpu(&kvm,
                   &vm,
                   cpu_id,
                   vcpu_count,
                   vcpu_thread_barrier.clone(),
                   exit_evt,
                   kill_signaled.clone(),
                   io_bus.clone(),
                   mmio_bus.clone())?;
    }
    vcpu_thread_barrier.wait();

    run_control(&mut vm,
                control_sockets,
                &mut next_dev_pfn,
                stdio_serial,
                exit_evt,
                sigchld_fd,
                kill_signaled,
                vcpu_handles,
                balloon_host_socket)
}
