// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::ffi::{CString, CStr};
use std::fmt;
use std::error;
use std::fs::{File, OpenOptions, remove_file};
use std::io::{self, stdin};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Barrier};
use std::thread;
use std::thread::JoinHandle;

use libc;
use libc::c_int;

use device_manager;
use devices;
use io_jail::{self, Minijail};
use kernel_cmdline;
use kvm::*;
use net_util::Tap;
use qcow::{self, QcowFile};
use sys_util::*;
use sys_util;
use vhost;
use vm_control::VmRequest;

use Config;
use DiskType;

use arch::LinuxArch;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::X8664arch as Arch;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use aarch64::AArch64 as Arch;

pub enum Error {
    BalloonDeviceNew(devices::virtio::BalloonError),
    BlockDeviceNew(sys_util::Error),
    ChownWaylandRoot(sys_util::Error),
    CloneEventFd(sys_util::Error),
    Cmdline(kernel_cmdline::Error),
    CreateEventFd(sys_util::Error),
    CreateGuestMemory(Box<error::Error>),
    CreateIrqChip(Box<error::Error>),
    CreateKvm(sys_util::Error),
    CreatePollContext(sys_util::Error),
    CreateSignalFd(sys_util::SignalFdError),
    CreateSocket(io::Error),
    CreateVcpu(sys_util::Error),
    CreateVm(Box<error::Error>),
    DeviceJail(io_jail::Error),
    DevicePivotRoot(io_jail::Error),
    Disk(io::Error),
    DiskImageLock(sys_util::Error),
    FailedCLOEXECCheck,
    FailedToDupFd,
    GetWaylandGroup(sys_util::Error),
    InvalidFdPath,
    NetDeviceNew(devices::virtio::NetError),
    NoVarEmpty,
    OpenKernel(PathBuf, io::Error),
    PollContextAdd(sys_util::Error),
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
    SetupSystemMemory(Box<error::Error>),
    ConfigureVcpu(Box<error::Error>),
    LoadKernel(Box<error::Error>),
    SetupIoBus(Box<error::Error>),
    SetupMMIOBus(Box<error::Error>),
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
            &Error::CreatePollContext(ref e) => write!(f, "failed to create poll context: {:?}", e),
            &Error::CreateSignalFd(ref e) => write!(f, "failed to create signalfd: {:?}", e),
            &Error::CreateSocket(ref e) => write!(f, "failed to create socket: {}", e),
            &Error::CreateVcpu(ref e) => write!(f, "failed to create VCPU: {:?}", e),
            &Error::CreateVm(ref e) => write!(f, "failed to create KVM VM object: {:?}", e),
            &Error::DeviceJail(ref e) => write!(f, "failed to jail device: {}", e),
            &Error::DevicePivotRoot(ref e) => write!(f, "failed to pivot root device: {}", e),
            &Error::Disk(ref e) => write!(f, "failed to load disk image: {}", e),
            &Error::DiskImageLock(ref e) => write!(f, "failed to lock disk image: {:?}", e),
            &Error::FailedCLOEXECCheck => {
                write!(f, "/proc/self/fd argument failed check for CLOEXEC")
            }
            &Error::FailedToDupFd => write!(f, "failed to dup fd from /proc/self/fd"),
            &Error::GetWaylandGroup(ref e) => {
                write!(f, "could not find gid for wayland group: {:?}", e)
            }
            &Error::InvalidFdPath => write!(f, "failed parsing a /proc/self/fd/*"),
            &Error::NetDeviceNew(ref e) => write!(f, "failed to set up virtio networking: {:?}", e),
            &Error::NoVarEmpty => write!(f, "/var/empty doesn't exist, can't jail devices."),
            &Error::OpenKernel(ref p, ref e) => {
                write!(f, "failed to open kernel image {:?}: {}", p, e)
            }
            &Error::PollContextAdd(ref e) => write!(f, "failed to add fd to poll context: {:?}", e),
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
            &Error::SetupSystemMemory(ref e) => write!(f, "error setting up system memory: {}", e),
            &Error::ConfigureVcpu(ref e) => write!(f, "failed to configure vcpu: {}", e),
            &Error::LoadKernel(ref e) => write!(f, "failed to load kernel: {}", e),
            &Error::SetupIoBus(ref e) => write!(f, "failed to setup iobus: {}", e),
            &Error::SetupMMIOBus(ref e) => write!(f, "failed to setup mmio bus: {}", e),
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
    #[cfg(debug_assertions)]
    j.log_seccomp_filter_failures();
    j.parse_seccomp_filters(seccomp_policy)
        .map_err(|e| Error::DeviceJail(e))?;
    j.use_seccomp_filter();
    // Don't do init setup.
    j.run_as_init();
    Ok(j)
}

fn setup_mmio_bus(cfg: &Config,
                  vm: &mut Vm,
                  mem: &GuestMemory,
                  cmdline: &mut kernel_cmdline::Cmdline,
                  control_sockets: &mut Vec<UnlinkUnixDatagram>,
                  balloon_device_socket: UnixDatagram)
                  -> Result<devices::Bus> {
    static DEFAULT_PIVOT_ROOT: &'static str = "/var/empty";
    let mut device_manager = Arch::get_device_manager(vm, mem.clone()).
        map_err(|e| Error::SetupMMIOBus(e))?;

    // An empty directory for jailed device's pivot root.
    let empty_root_path = Path::new(DEFAULT_PIVOT_ROOT);
    if cfg.multiprocess && !empty_root_path.exists() {
        return Err(Error::NoVarEmpty);
    }

    for disk in &cfg.disks {
        // Special case '/proc/self/fd/*' paths. The FD is already open, just use it.
        let mut raw_image: File = if disk.path.parent() == Some(Path::new("/proc/self/fd")) {
            if !disk.path.is_file() {
                return Err(Error::InvalidFdPath);
            }
            let raw_fd = disk.path.file_name()
                .and_then(|fd_osstr| fd_osstr.to_str())
                .and_then(|fd_str| fd_str.parse::<c_int>().ok())
                .ok_or(Error::InvalidFdPath)?;
            unsafe {
                // The FD is valid and this process owns it because it exists in /proc/self/fd.
                // Ensure |raw_image| is the only owner by first duping it then closing the
                // original.
                // Checking that close-on-exec isn't set helps filter out FDs that were opened by
                // crosvm as all crosvm FDs are close on exec.
                let flags = libc::fcntl(raw_fd, libc::F_GETFD);
                if flags < 0 || (flags & libc::FD_CLOEXEC) != 0 {
                    return Err(Error::FailedCLOEXECCheck);
                }

                let dup_fd = libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 0) as RawFd;
                if dup_fd < 0 {
                    return Err(Error::FailedToDupFd);
                }
                libc::close(raw_fd);
                File::from_raw_fd(dup_fd)
            }
        } else {
            OpenOptions::new()
                .read(true)
                .write(disk.writable)
                .open(&disk.path)
                .map_err(|e| Error::Disk(e))?
        };
        // Lock the disk image to prevent other crosvm instances from using it.
        let lock_op = if disk.writable {
            FlockOperation::LockExclusive
        } else {
            FlockOperation::LockShared
        };
        flock(&raw_image, lock_op, true).map_err(Error::DiskImageLock)?;

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
            if let Some(mac_address) = cfg.mac_address {
                let net_box: Box<devices::virtio::VirtioDevice> = if cfg.vhost_net {
                    Box::new(devices::virtio::vhost::Net::<Tap, vhost::Net<Tap>>::new(host_ip,
                                                                                      netmask,
                                                                                      mac_address,
                                                                                      &mem)
                                       .map_err(|e| Error::VhostNetDeviceNew(e))?)
                } else {
                    Box::new(devices::virtio::Net::<Tap>::new(host_ip, netmask, mac_address)
                                       .map_err(|e| Error::NetDeviceNew(e))?)
                };

                let jail = if cfg.multiprocess {
                    let policy_path: PathBuf = if cfg.vhost_net {
                        cfg.seccomp_policy_dir.join("vhost_net_device.policy")
                    } else {
                        cfg.seccomp_policy_dir.join("net_device.policy")
                    };

                    Some(create_base_minijail(empty_root_path, &policy_path)?)
                } else {
                    None
                };

                device_manager
                    .register_mmio(net_box, jail, cmdline)
                    .map_err(Error::RegisterNet)?;
            }
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
            let crosvm_user_group = CStr::from_bytes_with_nul(b"crosvm\0").unwrap();
            let crosvm_uid = match get_user_id(&crosvm_user_group) {
                Ok(u) => u,
                Err(e) => {
                    warn!("falling back to current user id for Wayland: {:?}", e);
                    geteuid()
                }
            };
            let crosvm_gid = match get_group_id(&crosvm_user_group) {
                Ok(u) => u,
                Err(e) => {
                    warn!("falling back to current group id for Wayland: {:?}", e);
                    getegid()
                }
            };
            jail.change_uid(crosvm_uid);
            jail.change_gid(crosvm_gid);
            jail.uidmap(&format!("{0} {0} 1", crosvm_uid))
                .map_err(Error::SettingUidMap)?;
            jail.gidmap(&format!("{0} {0} 1", crosvm_gid))
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


fn setup_vcpu(kvm: &Kvm,
              vm: &Vm,
              cpu_id: u32,
              vcpu_count: u32)
              -> Result<Vcpu> {
    let vcpu = Vcpu::new(cpu_id as libc::c_ulong, &kvm, &vm)
        .map_err(Error::CreateVcpu)?;
    Arch::configure_vcpu(vm.get_memory(), &kvm, &vm, &vcpu, cpu_id as u64, vcpu_count as u64).
        map_err(Error::ConfigureVcpu)?;
    Ok(vcpu)
}

fn run_vcpu(vcpu: Vcpu,
            cpu_id: u32,
            start_barrier: Arc<Barrier>,
            io_bus: devices::Bus,
            mmio_bus: devices::Bus,
            exit_evt: EventFd,
            kill_signaled: Arc<AtomicBool>) -> Result<JoinHandle<()>> {
    thread::Builder::new()
        .name(format!("crosvm_vcpu{}", cpu_id))
        .spawn(move || {
            unsafe {
                extern "C" fn handle_signal() {}
                // Our signal handler does nothing and is trivially async signal safe.
                register_signal_handler(SIGRTMIN() + 0, handle_signal)
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
                            VcpuExit::SystemEvent(_, _) =>
                                //TODO handle reboot and crash events
                                kill_signaled.store(true, Ordering::SeqCst),
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
               balloon_host_socket: UnixDatagram,
               _irqchip_fd: Option<File>)
               -> Result<()> {
    const MAX_VM_FD_RECV: usize = 1;

    #[derive(PollToken)]
    enum Token {
        Exit,
        Stdin,
        ChildSignal,
        VmControl { index: usize },
    }

    let stdin_handle = stdin();
    let stdin_lock = stdin_handle.lock();
    stdin_lock
        .set_raw_mode()
        .expect("failed to set terminal raw mode");

    let poll_ctx = PollContext::new().map_err(Error::CreatePollContext)?;
    poll_ctx.add(&exit_evt, Token::Exit).map_err(Error::PollContextAdd)?;
    if let Err(e) = poll_ctx.add(&stdin_handle, Token::Stdin) {
        warn!("failed to add stdin to poll context: {:?}", e);
    }
    poll_ctx.add(&sigchld_fd, Token::ChildSignal).map_err(Error::PollContextAdd)?;
    for (index, socket) in control_sockets.iter().enumerate() {
        poll_ctx.add(socket.as_ref(), Token::VmControl{ index }).map_err(Error::PollContextAdd)?;
    }

    let mut scm = Scm::new(MAX_VM_FD_RECV);

    'poll: loop {
        let events = {
            match poll_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to poll: {:?}", e);
                    break;
                }
            }
        };
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
                        },
                        Err(e) => {
                            warn!("error while reading stdin: {:?}", e);
                            let _ = poll_ctx.delete(&stdin_handle);
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
                Token::ChildSignal => {
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
                Token::VmControl { index } => {
                    if let Some(socket) = control_sockets.get(index as usize) {
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
                }
            }
        }
        for event in events.iter_hungup() {
            // It's possible more data is readable and buffered while the socket is hungup, so
            // don't delete the socket from the poll context until we're sure all the data is
            // read.
            if !event.readable() {
                match event.token() {
                    Token::Exit => {},
                    Token::Stdin => {
                        let _ = poll_ctx.delete(&stdin_handle);
                    },
                    Token::ChildSignal => {},
                    Token::VmControl { index } => {
                        if let Some(socket) = control_sockets.get(index as usize) {
                            let _ = poll_ctx.delete(socket.as_ref());
                        }
                    },
                }
            }
        }
    }

    // vcpu threads MUST see the kill signaled flag, otherwise they may
    // re-enter the VM.
    kill_signaled.store(true, Ordering::SeqCst);
    for handle in vcpu_handles {
        match handle.kill(SIGRTMIN() + 0) {
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

    let mem_size = cfg.memory.unwrap_or(256) << 20;
    let mem = Arch::setup_memory(mem_size as u64).map_err(|e| Error::CreateGuestMemory(e))?;
    let kvm = Kvm::new().map_err(Error::CreateKvm)?;
    let mut vm = Arch::create_vm(&kvm, mem.clone()).map_err(|e| Error::CreateVm(e))?;

    let vcpu_count = cfg.vcpu_count.unwrap_or(1);
    let mut vcpu_handles = Vec::with_capacity(vcpu_count as usize);
    let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));
    let mut vcpus = Vec::with_capacity(vcpu_count as usize);
    for cpu_id in 0..vcpu_count {
        let vcpu = setup_vcpu(&kvm, &vm, cpu_id, vcpu_count)?;
        vcpus.push(vcpu);
    }

    let irq_chip = Arch::create_irq_chip(&vm).map_err(|e| Error::CreateIrqChip(e))?;
    let mut cmdline = Arch::get_base_linux_cmdline();
    let mut next_dev_pfn = Arch::get_base_dev_pfn(mem_size as u64);
    let (io_bus, stdio_serial) = Arch::setup_io_bus(&mut vm,
                                                    exit_evt.try_clone().
                                                    map_err(Error::CloneEventFd)?).
        map_err(|e| Error::SetupIoBus(e))?;

    let (balloon_host_socket, balloon_device_socket) = UnixDatagram::pair()
        .map_err(Error::CreateSocket)?;
    let mmio_bus = setup_mmio_bus(&cfg,
                                  &mut vm,
                                  &mem,
                                  &mut cmdline,
                                  &mut control_sockets,
                                  balloon_device_socket)?;

    for param in &cfg.params {
        cmdline.insert_str(&param).map_err(Error::Cmdline)?;
    }

    let mut kernel_image = File::open(cfg.kernel_path.as_path())
        .map_err(|e| Error::OpenKernel(cfg.kernel_path.clone(), e))?;

    // separate out load_kernel from other setup to get a specific error for
    // kernel loading
    Arch::load_kernel(&mem, &mut kernel_image).map_err(|e| Error::LoadKernel(e))?;
    Arch::setup_system_memory(&mem, mem_size as u64, vcpu_count,
                              &CString::new(cmdline).unwrap()).
        map_err(|e| Error::SetupSystemMemory(e))?;

    for (cpu_id, vcpu) in vcpus.into_iter().enumerate() {
        let handle = run_vcpu(vcpu,
                              cpu_id as u32,
                              vcpu_thread_barrier.clone(),
                              io_bus.clone(),
                              mmio_bus.clone(),
                              exit_evt.try_clone().map_err(Error::CloneEventFd)?,
                              kill_signaled.clone())?;
        vcpu_handles.push(handle);
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
                balloon_host_socket,
                irq_chip)
}
