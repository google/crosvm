// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Runs a virtual machine under KVM

extern crate devices;
extern crate libc;
extern crate io_jail;
extern crate kvm;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
extern crate x86_64;
extern crate kernel_loader;
extern crate byteorder;
#[macro_use]
extern crate sys_util;
extern crate vm_control;
extern crate data_model;

pub mod argument;
pub mod kernel_cmdline;
pub mod device_manager;

use std::ffi::{CString, CStr};
use std::fmt;
use std::fs::{File, OpenOptions, remove_file};
use std::io::{stdin, stdout};
use std::net;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::string::String;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Barrier};
use std::thread;
use std::thread::{sleep, JoinHandle};
use std::time::Duration;

use io_jail::Minijail;
use kvm::*;
use sys_util::{GuestAddress, GuestMemory, EventFd, TempDir, Terminal, Poller, Pollable, Scm,
               register_signal_handler, Killable, SignalFd, chown, getpid, geteuid, getegid,
               get_user_id, get_group_id, kill_process_group, reap_child, syslog};


use argument::{Argument, set_arguments, print_help};
use device_manager::*;
use vm_control::{VmRequest, VmResponse};

enum Error {
    OpenKernel(PathBuf, std::io::Error),
    Socket(std::io::Error),
    Disk(std::io::Error),
    BlockDeviceNew(sys_util::Error),
    VhostNetDeviceNew(devices::virtio::vhost::Error),
    NetDeviceNew(devices::virtio::NetError),
    NoVarEmpty,
    VhostVsockDeviceNew(devices::virtio::vhost::Error),
    DeviceJail(io_jail::Error),
    DevicePivotRoot(io_jail::Error),
    RegisterBlock(device_manager::Error),
    RegisterNet(device_manager::Error),
    RegisterWayland(device_manager::Error),
    RegisterVsock(device_manager::Error),
    Cmdline(kernel_cmdline::Error),
    GetWaylandGroup(sys_util::Error),
    SettingUidMap(io_jail::Error),
    SettingGidMap(io_jail::Error),
    ChownWaylandRoot(sys_util::Error),
    RegisterIrqfd(sys_util::Error),
    RegisterRng(device_manager::Error),
    RngDeviceNew(devices::virtio::RngError),
    KernelLoader(kernel_loader::Error),
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ConfigureSystem(x86_64::Error),
    EventFd(sys_util::Error),
    SignalFd(sys_util::SignalFdError),
    Kvm(sys_util::Error),
    Vm(sys_util::Error),
    Vcpu(sys_util::Error),
    SpawnVcpu(std::io::Error),
    Sys(sys_util::Error),
}

impl std::convert::From<kernel_loader::Error> for Error {
    fn from(e: kernel_loader::Error) -> Error {
        Error::KernelLoader(e)
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl std::convert::From<x86_64::Error> for Error {
    fn from(e: x86_64::Error) -> Error {
        Error::ConfigureSystem(e)
    }
}

impl std::convert::From<sys_util::Error> for Error {
    fn from(e: sys_util::Error) -> Error {
        Error::Sys(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::OpenKernel(ref p, ref e) => write!(f, "failed to open kernel image {:?}: {}", p, e),
            &Error::Socket(ref e) => write!(f, "failed to create socket: {}", e),
            &Error::Disk(ref e) => write!(f, "failed to load disk image: {}", e),
            &Error::BlockDeviceNew(ref e) => write!(f, "failed to create block device: {:?}", e),
            &Error::RegisterBlock(ref e) => write!(f, "error registering block device: {:?}", e),
            &Error::VhostNetDeviceNew(ref e) => write!(f, "failed to set up vhost networking: {:?}", e),
            &Error::RegisterVsock(ref e) => write!(f, "error registering virtual socket device: {:?}", e),
            &Error::NetDeviceNew(ref e) => write!(f, "failed to set up virtio networking: {:?}", e),
            &Error::NoVarEmpty => write!(f, "/var/empty doesn't exist, can't jail devices."),
            &Error::DeviceJail(ref e) => write!(f, "failed to jail device: {}", e),
            &Error::DevicePivotRoot(ref e) => write!(f, "failed to pivot root device: {}", e),
            &Error::VhostVsockDeviceNew(ref e) => write!(f, "failed to set up virtual socket device: {:?}", e),
            &Error::RegisterNet(ref e) => write!(f, "error registering net device: {:?}", e),
            &Error::RegisterRng(ref e) => write!(f, "error registering rng device: {:?}", e),
            &Error::RngDeviceNew(ref e) => write!(f, "failed to set up rng: {:?}", e),
            &Error::RegisterWayland(ref e) => write!(f, "error registering wayland device: {}", e),
            &Error::SettingUidMap(ref e) => write!(f, "error setting UID map: {}", e),
            &Error::SettingGidMap(ref e) => write!(f, "error setting GID map: {}", e),
            &Error::ChownWaylandRoot(ref e) => write!(f, "error chowning wayland root directory: {:?}", e),
            &Error::Cmdline(ref e) => write!(f, "the given kernel command line was invalid: {}", e),
            &Error::GetWaylandGroup(ref e) => write!(f, "could not find gid for wayland group: {:?}", e),
            &Error::RegisterIrqfd(ref e) => write!(f, "error registering irqfd: {:?}", e),
            &Error::KernelLoader(ref e) => write!(f, "error loading kernel: {:?}", e),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            &Error::ConfigureSystem(ref e) => write!(f, "error configuring system: {:?}", e),
            &Error::EventFd(ref e) => write!(f, "error creating EventFd: {:?}", e),
            &Error::SignalFd(ref e) => write!(f, "error with SignalFd: {:?}", e),
            &Error::Kvm(ref e) => write!(f, "error creating Kvm: {:?}", e),
            &Error::Vm(ref e) => write!(f, "error creating Vm: {:?}", e),
            &Error::Vcpu(ref e) => write!(f, "error creating Vcpu: {:?}", e),
            &Error::SpawnVcpu(ref e) => write!(f, "error creating spawning Vcpu: {}", e),
            &Error::Sys(ref e) => write!(f, "error with system call: {:?}", e),
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

struct DiskOption {
    path: PathBuf,
    writable: bool,
}

struct Config {
    disks: Vec<DiskOption>,
    vcpu_count: Option<u32>,
    memory: Option<usize>,
    kernel_path: PathBuf,
    params: String,
    host_ip: Option<net::Ipv4Addr>,
    netmask: Option<net::Ipv4Addr>,
    mac_address: Option<String>,
    vhost_net: bool,
    wayland_socket_path: Option<PathBuf>,
    wayland_group: Option<String>,
    socket_path: Option<PathBuf>,
    multiprocess: bool,
    seccomp_policy_dir: PathBuf,
    cid: Option<u64>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            disks: Vec::new(),
            vcpu_count: None,
            memory: None,
            kernel_path: PathBuf::default(),
            params: String::new(),
            host_ip: None,
            netmask: None,
            mac_address: None,
            vhost_net: false,
            wayland_socket_path: None,
            wayland_group: None,
            socket_path: None,
            multiprocess: true,
            seccomp_policy_dir: PathBuf::from(SECCOMP_POLICY_DIR),
            cid: None,
        }
    }
}

const KERNEL_START_OFFSET: usize = 0x200000;
const CMDLINE_OFFSET: usize = 0x20000;
const CMDLINE_MAX_SIZE: usize = KERNEL_START_OFFSET - CMDLINE_OFFSET;
const BASE_DEV_MEMORY_PFN: u64 = 1u64 << 26;

static SECCOMP_POLICY_DIR: &'static str = "/usr/share/policy/crosvm";

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
    j.parse_seccomp_filters(seccomp_policy)
        .map_err(|e| Error::DeviceJail(e))?;
    j.use_seccomp_filter();
    // Don't do init setup.
    j.run_as_init();
    Ok(j)
}

// Wait for all children to exit. Return true if they have all exited, false
// otherwise.
fn wait_all_children() -> bool {
    const CHILD_WAIT_MAX_ITER: isize = 10;
    const CHILD_WAIT_MS: u64 = 10;
    for _ in 0..CHILD_WAIT_MAX_ITER {
        loop {
            match reap_child() {
                Ok(0) => break,
                // We expect ECHILD which indicates that there were no children left.
                Err(e) if e.errno() == libc::ECHILD => return true,
                Err(e) => {
                    warn!("error while waiting for children: {:?}", e);
                    return false;
                }
                // We reaped one child, so continue reaping.
                _ => {},
            }
        }
        // There's no timeout option for waitpid which reap_child calls internally, so our only
        // recourse is to sleep while waiting for the children to exit.
        sleep(Duration::from_millis(CHILD_WAIT_MS));
    }

    // If we've made it to this point, not all of the children have exited.
    return false;
}

fn run_config(cfg: Config) -> Result<()> {
    static DEFAULT_PIVOT_ROOT: &'static str = "/var/empty";

    if cfg.multiprocess {
        // Printing something to the syslog before entering minijail so that libc's syslogger has a
        // chance to open files necessary for its operation, like `/etc/localtime`. After jailing,
        // access to those files will not be possible.
        info!("crosvm entering multiprocess mode");
    }

    let kernel_image = File::open(cfg.kernel_path.as_path())
        .map_err(|e| Error::OpenKernel(cfg.kernel_path.clone(), e))?;

    let mut control_sockets = Vec::new();
    if let Some(ref path) = cfg.socket_path {
        let path = Path::new(path);
        let control_socket = UnixDatagram::bind(path).map_err(|e| Error::Socket(e))?;
        control_sockets.push(UnlinkUnixDatagram(control_socket));
    }

    let mem_size = cfg.memory.unwrap_or(256) << 20;
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    let arch_mem_regions = vec![(GuestAddress(0), mem_size)];
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let arch_mem_regions = x86_64::arch_memory_regions(mem_size);
    let guest_mem =
        GuestMemory::new(&arch_mem_regions).expect("new mmap failed");

    let mut cmdline = kernel_cmdline::Cmdline::new(CMDLINE_MAX_SIZE);
    cmdline
        .insert_str("console=ttyS0 noacpi reboot=k panic=1 pci=off")
        .unwrap();

    let mut device_manager = DeviceManager::new(guest_mem.clone(), 0x1000, 0xd0000000, 5);

    // An empty directory for jailed device's pivot root.
    let empty_root_path = Path::new(DEFAULT_PIVOT_ROOT);
    if cfg.multiprocess && !empty_root_path.exists() {
        return Err(Error::NoVarEmpty);
    }

    for disk in cfg.disks {
        let disk_image = OpenOptions::new()
                            .read(true)
                            .write(disk.writable)
                            .open(disk.path)
                            .map_err(|e| Error::Disk(e))?;

        let block_box = Box::new(devices::virtio::Block::new(disk_image)
                    .map_err(|e| Error::BlockDeviceNew(e))?);
        let jail = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("block_device.policy");
            Some(create_base_minijail(empty_root_path, &policy_path)?)
        }
        else {
            None
        };

        device_manager.register_mmio(block_box, jail, &mut cmdline)
                .map_err(Error::RegisterBlock)?;
    }

    let rng_box = Box::new(devices::virtio::Rng::new().map_err(Error::RngDeviceNew)?);
    let rng_jail = if cfg.multiprocess {
        let policy_path: PathBuf = cfg.seccomp_policy_dir.join("rng_device.policy");
        Some(create_base_minijail(empty_root_path, &policy_path)?)
    } else {
        None
    };
    device_manager.register_mmio(rng_box, rng_jail, &mut cmdline)
        .map_err(Error::RegisterRng)?;

    // We checked above that if the IP is defined, then the netmask is, too.
    if let Some(host_ip) = cfg.host_ip {
        if let Some(netmask) = cfg.netmask {
            let net_box: Box<devices::virtio::VirtioDevice> = if cfg.vhost_net {
                Box::new(devices::virtio::vhost::Net::new(host_ip, netmask, &guest_mem)
                                   .map_err(|e| Error::VhostNetDeviceNew(e))?)
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

            device_manager.register_mmio(net_box, jail, &mut cmdline).map_err(Error::RegisterNet)?;
        }
    }

    let wl_root = TempDir::new(&PathBuf::from("/tmp/wl_root"))?;
    if let Some(wayland_socket_path) = cfg.wayland_socket_path {
        let jailed_wayland_path = Path::new("/wayland-0");

        let (host_socket, device_socket) = UnixDatagram::pair().map_err(Error::Socket)?;
        control_sockets.push(UnlinkUnixDatagram(host_socket));
        let wl_box = Box::new(devices::virtio::Wl::new(if cfg.multiprocess {
            &jailed_wayland_path
        } else {
            wayland_socket_path.as_path()
        },
        device_socket)?);

        let jail = if cfg.multiprocess {
            let wl_root_path = wl_root.as_path().unwrap(); // Won't fail if new succeeded.
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("wl_device.policy");
            let mut jail = create_base_minijail(wl_root_path, &policy_path)?;

            // Bind mount the wayland socket into jail's root. This is necessary since each
            // new wayland context must open() the socket.
            jail.mount_bind(wayland_socket_path.as_path(), jailed_wayland_path, true)
                .unwrap();

            // Set the uid/gid for the jailed process, and give a basic id map. This
            // is required for the above bind mount to work.
            let wayland_group = cfg.wayland_group.unwrap_or(String::from("wayland"));
            let wayland_cstr = CString::new(wayland_group.into_bytes()).unwrap();
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
            let crosvm_gid = match get_group_id(&crosvm_user_group) {
                Ok(u) => u,
                Err(e) => {
                    warn!("falling back to current group id for Wayland: {:?}", e);
                    getegid()
                }
            };
            jail.change_uid(crosvm_uid);
            jail.change_gid(wayland_gid);
            jail.uidmap(&format!("{0} {0} 1", crosvm_uid))
                .map_err(Error::SettingUidMap)?;
            jail.gidmap(&format!("{0} {0} 1", wayland_gid))
                .map_err(Error::SettingGidMap)?;

            // chown the root directory for the jail so we can actually bind mount the socket.
            let wayland_root_cstr = CString::new(wl_root_path.as_os_str().to_str().unwrap())
                .unwrap();
            chown(&wayland_root_cstr, crosvm_uid, crosvm_gid)
                .map_err(Error::ChownWaylandRoot)?;

            Some(jail)
        } else {
            None
        };
        device_manager
            .register_mmio(wl_box, jail, &mut cmdline)
            .map_err(Error::RegisterWayland)?;
    }

    if let Some(cid) = cfg.cid {
        let vsock_box = Box::new(devices::virtio::vhost::Vsock::new(cid, &guest_mem)
            .map_err(|e| Error::VhostVsockDeviceNew(e))?);

        let jail = if cfg.multiprocess {
            let policy_path: PathBuf = cfg.seccomp_policy_dir.join("vhost_vsock_device.policy");

            Some(create_base_minijail(empty_root_path, &policy_path)?)
        } else {
            None
        };

        device_manager.register_mmio(vsock_box, jail, &mut cmdline).map_err(Error::RegisterVsock)?;
    }

    if !cfg.params.is_empty() {
        cmdline
            .insert_str(cfg.params)
            .map_err(|e| Error::Cmdline(e))?;
    }

    run_kvm(device_manager.vm_requests,
            kernel_image,
            &CString::new(cmdline).unwrap(),
            cfg.vcpu_count.unwrap_or(1),
            guest_mem,
            &device_manager.bus,
            control_sockets)
}

fn run_kvm(requests: Vec<VmRequest>,
           mut kernel_image: File,
           cmdline: &CStr,
           vcpu_count: u32,
           guest_mem: GuestMemory,
           mmio_bus: &devices::Bus,
           control_sockets: Vec<UnlinkUnixDatagram>)
           -> Result<()> {
    let kvm = Kvm::new().map_err(Error::Kvm)?;
    let kernel_start_addr = GuestAddress(KERNEL_START_OFFSET);
    let cmdline_addr = GuestAddress(CMDLINE_OFFSET);

    let mut vm = Vm::new(&kvm, guest_mem).map_err(Error::Vm)?;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let tss_addr = GuestAddress(0xfffbd000);
        vm.set_tss_addr(tss_addr).expect("set tss addr failed");
        vm.create_pit().expect("create pit failed");
    }
    vm.create_irq_chip().expect("create irq chip failed");

    let mut next_dev_pfn = BASE_DEV_MEMORY_PFN;
    for request in requests {
        let mut running = false;
        if let VmResponse::Err(e) = request.execute(&mut vm, &mut next_dev_pfn, &mut running) {
            return Err(Error::Vm(e));
        }
        if !running {
            info!("configuration requested exit");
            return Ok(());
        }
    }

    kernel_loader::load_kernel(vm.get_memory(), kernel_start_addr, &mut kernel_image)?;
    kernel_loader::load_cmdline(vm.get_memory(), cmdline_addr, cmdline)?;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    x86_64::configure_system(vm.get_memory(),
                             kernel_start_addr,
                             cmdline_addr,
                             cmdline.to_bytes().len() + 1,
                             vcpu_count as u8)?;

    let mut io_bus = devices::Bus::new();

    let exit_evt = EventFd::new().expect("failed to create exit eventfd");

    // Masking signals is inherently dangerous, since this can persist across
    // clones/execs. Do this after any jailed devices have been spawned, but
    // before the vcpus spawn so they also inherit the masking for SIGCHLD.
    let sigchld_fd = SignalFd::new(libc::SIGCHLD)
        .expect("failed to create child signalfd");

    struct NoDevice;
    impl devices::BusDevice for NoDevice {}

    let com_evt_1_3 = EventFd::new().map_err(Error::EventFd)?;
    let com_evt_2_4 = EventFd::new().map_err(Error::EventFd)?;
    let stdio_serial =
        Arc::new(Mutex::new(
                    devices::Serial::new_out(com_evt_1_3.try_clone().map_err(Error::EventFd)?,
                Box::new(stdout()))));
    let nul_device = Arc::new(Mutex::new(NoDevice));
    io_bus.insert(stdio_serial.clone(), 0x3f8, 0x8).unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(devices::Serial::new_sink(com_evt_2_4
                                                             .try_clone()
                                                             .map_err(Error::EventFd)?))),
                0x2f8,
                0x8)
        .unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(devices::Serial::new_sink(com_evt_1_3
                                                             .try_clone()
                                                             .map_err(Error::EventFd)?))),
                0x3e8,
                0x8)
        .unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(devices::Serial::new_sink(com_evt_2_4
                                                             .try_clone()
                                                             .map_err(Error::EventFd)?))),
                0x2e8,
                0x8)
        .unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(devices::Cmos::new())), 0x70, 0x2)
        .unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(devices::I8042Device::new(exit_evt
                                                             .try_clone()
                                                             .map_err(Error::EventFd)?))),
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

    let kill_signaled = Arc::new(AtomicBool::new(false));
    let mut vcpu_handles = Vec::with_capacity(vcpu_count as usize);
    let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));
    for cpu_id in 0..vcpu_count {
        let mmio_bus = mmio_bus.clone();
        let io_bus = io_bus.clone();
        let kill_signaled = kill_signaled.clone();
        let vcpu_thread_barrier = vcpu_thread_barrier.clone();
        let vcpu_exit_evt = exit_evt.try_clone().map_err(Error::EventFd)?;
        let vcpu = Vcpu::new(cpu_id as libc::c_ulong, &kvm, &vm).map_err(Error::Vcpu)?;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        x86_64::configure_vcpu(vm.get_memory(),
                               kernel_start_addr,
                               &kvm,
                               &vcpu,
                               cpu_id as u64,
                               vcpu_count as u64)?;
        vcpu_handles.push(thread::Builder::new()
                              .name(format!("crosvm_vcpu{}", cpu_id))
                              .spawn(move || {
            unsafe {
                extern "C" fn handle_signal() {}
                // Our signal handler does nothing and is trivially async signal safe.
                register_signal_handler(0, handle_signal)
                    .expect("failed to register vcpu signal handler");
            }

            vcpu_thread_barrier.wait();
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
            vcpu_exit_evt
                .write(1)
                .expect("failed to signal vcpu exit eventfd");
        }).map_err(Error::SpawnVcpu)?);
    }

    vcpu_thread_barrier.wait();

    run_control(vm,
                control_sockets,
                next_dev_pfn,
                stdio_serial,
                exit_evt,
                sigchld_fd,
                kill_signaled,
                vcpu_handles)
}

fn run_control(mut vm: Vm,
               control_sockets: Vec<UnlinkUnixDatagram>,
               mut next_dev_pfn: u64,
               stdio_serial: Arc<Mutex<devices::Serial>>,
               exit_evt: EventFd,
               sigchld_fd: SignalFd,
               kill_signaled: Arc<AtomicBool>,
               vcpu_handles: Vec<JoinHandle<()>>)
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
                                request.execute(&mut vm, &mut next_dev_pfn, &mut running);
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

fn set_argument(cfg: &mut Config, name: &str, value: Option<&str>) -> argument::Result<()> {
    match name {
        "" => {
            if !cfg.kernel_path.as_os_str().is_empty() {
                return Err(argument::Error::TooManyArguments("expected exactly one kernel path"
                                                                 .to_owned()));
            } else {
                let kernel_path = PathBuf::from(value.unwrap());
                if !kernel_path.exists() {
                    return Err(argument::Error::InvalidValue {
                                   value: value.unwrap().to_owned(),
                                   expected: "this kernel path does not exist",
                               });
                }
                cfg.kernel_path = kernel_path;
            }
        }
        "params" => {
            if cfg.params.ends_with(|c| !char::is_whitespace(c)) {
                cfg.params.push(' ');
            }
            cfg.params.push_str(&value.unwrap());
        }
        "cpus" => {
            if cfg.vcpu_count.is_some() {
                return Err(argument::Error::TooManyArguments("`cpus` already given".to_owned()));
            }
            cfg.vcpu_count =
                Some(value
                         .unwrap()
                         .parse()
                         .map_err(|_| {
                                      argument::Error::InvalidValue {
                                          value: value.unwrap().to_owned(),
                                          expected: "this value for `cpus` needs to be integer",
                                      }
                                  })?)
        }
        "mem" => {
            if cfg.memory.is_some() {
                return Err(argument::Error::TooManyArguments("`mem` already given".to_owned()));
            }
            cfg.memory =
                Some(value
                         .unwrap()
                         .parse()
                         .map_err(|_| {
                                      argument::Error::InvalidValue {
                                          value: value.unwrap().to_owned(),
                                          expected: "this value for `mem` needs to be integer",
                                      }
                                  })?)
        }
        "root" | "disk" | "rwdisk" => {
            let disk_path = PathBuf::from(value.unwrap());
            if !disk_path.exists() {
                return Err(argument::Error::InvalidValue {
                               value: value.unwrap().to_owned(),
                               expected: "this disk path does not exist",
                           });
            }
            if name == "root" {
                if cfg.disks.len() >= 26 {
                    return Err(argument::Error::TooManyArguments("ran out of letters for to assign to root disk".to_owned()));
                }
                let white = if cfg.params.ends_with(|c| !char::is_whitespace(c)) {
                    " "
                } else {
                    ""
                };
                cfg.params
                    .push_str(&format!("{}root=/dev/vd{} ro",
                                       white,
                                       char::from('a' as u8 + cfg.disks.len() as u8)));
            }
            cfg.disks
                .push(DiskOption {
                          path: disk_path,
                          writable: name.starts_with("rw"),
                      });
        }
        "host_ip" => {
            if cfg.host_ip.is_some() {
                return Err(argument::Error::TooManyArguments("`host_ip` already given".to_owned()));
            }
            cfg.host_ip =
                Some(value
                         .unwrap()
                         .parse()
                         .map_err(|_| {
                                      argument::Error::InvalidValue {
                                          value: value.unwrap().to_owned(),
                                          expected: "`host_ip` needs to be in the form \"x.x.x.x\"",
                                      }
                                  })?)
        }
        "netmask" => {
            if cfg.netmask.is_some() {
                return Err(argument::Error::TooManyArguments("`netmask` already given".to_owned()));
            }
            cfg.netmask =
                Some(value
                         .unwrap()
                         .parse()
                         .map_err(|_| {
                                      argument::Error::InvalidValue {
                                          value: value.unwrap().to_owned(),
                                          expected: "`netmask` needs to be in the form \"x.x.x.x\"",
                                      }
                                  })?)
        }
        "mac" => {
            if cfg.mac_address.is_some() {
                return Err(argument::Error::TooManyArguments("`mac` already given".to_owned()));
            }
            cfg.mac_address = Some(value.unwrap().to_owned());
        }
        "wayland-sock" => {
            if cfg.wayland_socket_path.is_some() {
                return Err(argument::Error::TooManyArguments("`wayland-sock` already given"
                                                                 .to_owned()));
            }
            let wayland_socket_path = PathBuf::from(value.unwrap());
            if !wayland_socket_path.exists() {
                return Err(argument::Error::InvalidValue {
                               value: value.unwrap().to_string(),
                               expected: "Wayland socket does not exist",
                           });
            }
            cfg.wayland_socket_path = Some(wayland_socket_path);
        }
        "wayland-group" => {
            if cfg.wayland_group.is_some() {
                return Err(argument::Error::TooManyArguments("`wayland-group` already given"
                                                                 .to_owned()));
            }
            cfg.wayland_group = Some(value.unwrap().to_owned());
        }
        "socket" => {
            if cfg.socket_path.is_some() {
                return Err(argument::Error::TooManyArguments("`socket` already given".to_owned()));
            }
            let mut socket_path = PathBuf::from(value.unwrap());
            if socket_path.is_dir() {
                socket_path.push(format!("crosvm-{}.sock", getpid()));
            }
            if socket_path.exists() {
                return Err(argument::Error::InvalidValue {
                               value: socket_path.to_string_lossy().into_owned(),
                               expected: "this socket path already exists",
                           });
            }
            cfg.socket_path = Some(socket_path);
        }
        "multiprocess" => {
            cfg.multiprocess = true;
        }
        "disable-sandbox" => {
            cfg.multiprocess = false;
        }
        "cid" => {
            if cfg.cid.is_some() {
                return Err(argument::Error::TooManyArguments("`cid` alread given".to_owned()));
            }
            cfg.cid = Some(value.unwrap().parse().map_err(|_| {
                argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: "this value for `cid` must be an unsigned integer",
                }
            })?);
        }
        "seccomp-policy-dir" => {
            // `value` is Some because we are in this match so it's safe to unwrap.
            cfg.seccomp_policy_dir = PathBuf::from(value.unwrap());
        },
        "help" => return Err(argument::Error::PrintHelp),
        _ => unreachable!(),
    }
    Ok(())
}


fn run_vm(args: std::env::Args) {
    let arguments =
        &[Argument::positional("KERNEL", "bzImage of kernel to run"),
          Argument::short_value('p',
                                "params",
                                "PARAMS",
                                "Extra kernel command line arguments. Can be given more than once."),
          Argument::short_value('c', "cpus", "N", "Number of VCPUs. (default: 1)"),
          Argument::short_value('m',
                                "mem",
                                "N",
                                "Amount of guest memory in MiB. (default: 256)"),
          Argument::short_value('r',
                                "root",
                                "PATH",
                                "Path to a root disk image. Like `--disk` but adds appropriate kernel command line option."),
          Argument::short_value('d', "disk", "PATH", "Path to a disk image."),
          Argument::value("rwdisk", "PATH", "Path to a writable disk image."),
          Argument::value("host_ip",
                          "IP",
                          "IP address to assign to host tap interface."),
          Argument::value("netmask", "NETMASK", "Netmask for VM subnet."),
          Argument::value("mac", "MAC", "MAC address for VM."),
          Argument::value("wayland-sock", "PATH", "Path to the Wayland socket to use."),
          Argument::value("wayland-group",
                          "GROUP",
                          "Name of the group with access to the Wayland socket."),
          Argument::short_value('s',
                                "socket",
                                "PATH",
                                "Path to put the control socket. If PATH is a directory, a name will be generated."),
          Argument::short_flag('u', "multiprocess", "Run each device in a child process(default)."),
          Argument::flag("disable-sandbox", "Run all devices in one, non-sandboxed process."),
          Argument::value("cid", "CID", "Context ID for virtual sockets"),
          Argument::value("seccomp-policy-dir", "PATH", "Path to seccomp .policy files."),
          Argument::short_flag('h', "help", "Print help message.")];

    let mut cfg = Config::default();
    let match_res = set_arguments(args, &arguments[..], |name, value| set_argument(&mut cfg, name, value)).and_then(|_| {
        if cfg.kernel_path.as_os_str().is_empty() {
            return Err(argument::Error::ExpectedArgument("`KERNEL`".to_owned()));
        }
        if cfg.host_ip.is_some() || cfg.netmask.is_some() || cfg.mac_address.is_some() {
            if cfg.host_ip.is_none() {
                return Err(argument::Error::ExpectedArgument("`host_ip` missing from network config".to_owned()));
            }
            if cfg.netmask.is_none() {
                return Err(argument::Error::ExpectedArgument("`netmask` missing from network config".to_owned()));
            }
            if cfg.mac_address.is_none() {
                return Err(argument::Error::ExpectedArgument("`mac` missing from network config".to_owned()));
            }
        }
        Ok(())
    });

    match match_res {
        Ok(_) => {
            match run_config(cfg) {
                Ok(_) => info!("crosvm has exited normally"),
                Err(e) => error!("{}", e),
            }
        }
        Err(argument::Error::PrintHelp) => print_help("crosvm run", "KERNEL", &arguments[..]),
        Err(e) => println!("{}", e),
    }
}

fn stop_vms(args: std::env::Args) {
    let mut scm = Scm::new(1);
    if args.len() == 0 {
        print_help("crosvm stop", "VM_SOCKET...", &[]);
        println!("Stops the crosvm instance listening on each `VM_SOCKET` given.");
    }
    for socket_path in args {
        match UnixDatagram::unbound().and_then(|s| {
                                                   s.connect(&socket_path)?;
                                                   Ok(s)
                                               }) {
            Ok(s) => {
                if let Err(e) = VmRequest::Exit.send(&mut scm, &s) {
                    error!("failed to send stop request to socket at '{}': {:?}",
                           socket_path,
                           e);
                }
            }
            Err(e) => error!("failed to connect to socket at '{}': {}", socket_path, e),
        }
    }
}


fn print_usage() {
    print_help("crosvm", "[stop|run]", &[]);
    println!("Commands:");
    println!("    stop - Stops crosvm instances via their control sockets.");
    println!("    run  - Start a new crosvm instance.");
}

fn main() {
    if let Err(e) = syslog::init() {
        println!("failed to initiailize syslog: {:?}", e);
        return;
    }

    let mut args = std::env::args();
    if args.next().is_none() {
        error!("expected executable name");
        return;
    }

    match args.next().as_ref().map(|a| a.as_ref()) {
        None => print_usage(),
        Some("stop") => {
            stop_vms(args);
        }
        Some("run") => {
            run_vm(args);
        }
        Some(c) => {
            println!("invalid subcommand: {:?}", c);
            print_usage();
        }
    }

    // Reap exit status from any child device processes. At this point, all devices should have been
    // dropped in the main process and told to shutdown. Try over a period of 100ms, since it may
    // take some time for the processes to shut down.
    if !wait_all_children() {
        // We gave them a chance, and it's too late.
        warn!("not all child processes have exited; sending SIGKILL");
        if let Err(e) = kill_process_group() {
            // We're now at the mercy of the OS to clean up after us.
            warn!("unable to kill all child processes: {:?}", e);
        }
    }

    // WARNING: Any code added after this point is not guaranteed to run
    // since we may forcibly kill this process (and its children) above.
}
