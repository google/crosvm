// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Runs a virtual machine under KVM

extern crate clap;
extern crate libc;
extern crate io_jail;
extern crate kvm;
extern crate x86_64;
extern crate kernel_loader;
extern crate byteorder;
#[macro_use] extern crate sys_util;
extern crate net_sys;
extern crate net_util;
extern crate vhost;
extern crate virtio_sys;

use std::ffi::{CString, CStr};
use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{stdin, stdout};
use std::net;
use std::path::{Path, PathBuf};
use std::ptr;
use std::string::String;
use std::sync::{Arc, Mutex, Barrier};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{spawn, sleep, JoinHandle};
use std::time::Duration;

use clap::{Arg, App, SubCommand};

use device_manager::{DeviceManager, VmRequest};
use io_jail::Minijail;
use kvm::*;
use sys_util::{GuestAddress, GuestMemory, EventFd, TempDir, Terminal, Poller, Pollable,
               register_signal_handler, Killable, SignalFd, syslog};

pub mod hw;
pub mod kernel_cmdline;
pub mod control_socket;
pub mod device_manager;

use control_socket::*;

enum Error {
    Socket(std::io::Error),
    Disk(std::io::Error),
    BlockDeviceNew(sys_util::Error),
    BlockDeviceRootSetup(sys_util::Error),
    VhostNetDeviceNew(hw::virtio::VhostNetError),
    NetDeviceNew(hw::virtio::NetError),
    NetDeviceRootSetup(sys_util::Error),
    MacAddressNeedsNetConfig,
    NetMissingConfig,
    DeviceJail(io_jail::Error),
    DevicePivotRoot(io_jail::Error),
    RegisterBlock(device_manager::Error),
    RegisterNet(device_manager::Error),
    Cmdline(kernel_cmdline::Error),
    RegisterIoevent(sys_util::Error),
    RegisterIrqfd(sys_util::Error),
    RegisterRng(device_manager::Error),
    RngDeviceNew(hw::virtio::RngError),
    RngDeviceRootSetup(sys_util::Error),
    KernelLoader(kernel_loader::Error),
    ConfigureSystem(x86_64::Error),
    EventFd(sys_util::Error),
    SignalFd(sys_util::SignalFdError),
    Kvm(sys_util::Error),
    Vm(sys_util::Error),
    Vcpu(sys_util::Error),
    Sys(sys_util::Error),
}

impl std::convert::From<kernel_loader::Error> for Error {
    fn from(e: kernel_loader::Error) -> Error {
        Error::KernelLoader(e)
    }
}

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
            &Error::Socket(ref e) => write!(f, "failed to create socket: {}", e),
            &Error::Disk(ref e) => write!(f, "failed to load disk image: {}", e),
            &Error::BlockDeviceNew(ref e) => write!(f, "failed to create block device: {:?}", e),
            &Error::BlockDeviceRootSetup(ref e) => {
                write!(f, "failed to create root directory for a block device: {:?}", e)
            }
            &Error::RegisterBlock(ref e) => write!(f, "error registering block device: {:?}", e),
            &Error::VhostNetDeviceNew(ref e) => write!(f, "failed to set up vhost networking: {:?}", e),
            &Error::NetDeviceNew(ref e) => write!(f, "failed to set up virtio networking: {:?}", e),
            &Error::NetDeviceRootSetup(ref e) => {
                write!(f, "failed to create root directory for a net device: {:?}", e)
            }
            &Error::MacAddressNeedsNetConfig => write!(f, "MAC address can only be specified when host IP and netmask are provided"),
            &Error::NetMissingConfig => write!(f, "networking requires both host IP and netmask specified"),
            &Error::DeviceJail(ref e) => write!(f, "failed to jail device: {:?}", e),
            &Error::DevicePivotRoot(ref e) => write!(f, "failed to pivot root device: {:?}", e),
            &Error::RegisterNet(ref e) => write!(f, "error registering net device: {:?}", e),
            &Error::RegisterRng(ref e) => write!(f, "error registering rng device: {:?}", e),
            &Error::RngDeviceNew(ref e) => write!(f, "failed to set up rng: {:?}", e),
            &Error::RngDeviceRootSetup(ref e) => {
                write!(f, "failed to create root directory for a rng device: {:?}", e)
            }
            &Error::Cmdline(ref e) => write!(f, "the given kernel command line was invalid: {}", e),
            &Error::RegisterIoevent(ref e) => write!(f, "error registering ioevent: {:?}", e),
            &Error::RegisterIrqfd(ref e) => write!(f, "error registering irqfd: {:?}", e),
            &Error::KernelLoader(ref e) => write!(f, "error loading kernel: {:?}", e),
            &Error::ConfigureSystem(ref e) => write!(f, "error configuring system: {:?}", e),
            &Error::EventFd(ref e) => write!(f, "error creating EventFd: {:?}", e),
            &Error::SignalFd(ref e) => write!(f, "error with SignalFd: {:?}", e),
            &Error::Kvm(ref e) => write!(f, "error creating Kvm: {:?}", e),
            &Error::Vm(ref e) => write!(f, "error creating Vm: {:?}", e),
            &Error::Vcpu(ref e) => write!(f, "error creating Vcpu: {:?}", e),
            &Error::Sys(ref e) => write!(f, "error with system call: {:?}", e),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

struct DiskOption<'a> {
    path: &'a str,
    writable: bool,
}

struct Config<'a> {
    disks: Vec<DiskOption<'a>>,
    vcpu_count: Option<u32>,
    memory: Option<usize>,
    kernel_image: File,
    params: Option<String>,
    host_ip: Option<net::Ipv4Addr>,
    netmask: Option<net::Ipv4Addr>,
    mac_address: Option<String>,
    vhost_net: bool,
    socket_path: Option<String>,
    multiprocess: bool,
    warn_unknown_ports: bool,
}

const KERNEL_START_OFFSET: usize = 0x200000;
const CMDLINE_OFFSET: usize = 0x20000;
const CMDLINE_MAX_SIZE: usize = KERNEL_START_OFFSET - CMDLINE_OFFSET;

fn create_base_minijail(root: &Path, seccomp_policy: &Path) -> Result<Minijail> {
    // All child jails run in a new user namespace without any users mapped,
    // they run as nobody unless otherwise configured.
    let mut j = Minijail::new().map_err(|e| Error::DeviceJail(e))?;
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
    Ok(j)
}

// Wait for all children to exit. Return true if they have all exited, false
// otherwise.
fn wait_all_children() -> bool {
    const CHILD_WAIT_MAX_ITER: isize = 10;
    const CHILD_WAIT_MS: u64 = 10;
    for _ in 0..CHILD_WAIT_MAX_ITER {
        // waitpid() is safe when used in this manner; we will check
        // without blocking if there are any child processes that
        // are still running or need their exit statuses reaped.
        loop {
            let ret = unsafe {
                libc::waitpid(-1, ptr::null_mut(), libc::WNOHANG)
            };
            // waitpid() returns -1 when there are no children left, and
            // returns 0 when there are children alive but not yet exited.
            if ret < 0 {
                let err = sys_util::Error::last().errno();
                // We expect ECHILD which indicates that there were
                // no children left.
                if err == libc::ECHILD {
                    return true;
                }
                else {
                    warn!("waitpid returned {} while waiting for children",
                          err);
                }
                return false;
            } else if ret == 0 {
                break;
            }
        }
        // There's no timeout option for waitpid, so our only recourse
        // is to use WNOHANG and sleep while waiting for the children
        // to exit.
        sleep(Duration::from_millis(CHILD_WAIT_MS));
    }

    // If we've made it to this point, not all of the children have exited.
    return false;
}

fn run_config(cfg: Config) -> Result<()> {
    if cfg.mac_address.is_some() &&
       (cfg.netmask.is_none() || cfg.host_ip.is_none()) {
        return Err(Error::MacAddressNeedsNetConfig);
    }

    if cfg.netmask.is_some() != cfg.host_ip.is_some() {
        return Err(Error::NetMissingConfig);
    }

    let socket = if let Some(ref socket_path) = cfg.socket_path {
        Some(ControlSocketRecv::new(socket_path)
                 .map_err(|e| Error::Socket(e))?)
    } else {
        None
    };

    let mem_size = cfg.memory.unwrap_or(256) << 20;
    let guest_mem =
        GuestMemory::new(&x86_64::arch_memory_regions(mem_size)).expect("new mmap failed");

    let mut cmdline = kernel_cmdline::Cmdline::new(CMDLINE_MAX_SIZE);
    cmdline
        .insert_str("console=ttyS0 noapic noacpi reboot=k panic=1 pci=off")
        .unwrap();

    let mut device_manager = DeviceManager::new(guest_mem.clone(), 0x1000, 0xd0000000, 5);

    let block_root = TempDir::new(&PathBuf::from("/tmp/block_root"))
        .map_err(Error::BlockDeviceRootSetup)?;
    for disk in cfg.disks {
        let disk_image = OpenOptions::new()
                            .read(true)
                            .write(disk.writable)
                            .open(disk.path)
                            .map_err(|e| Error::Disk(e))?;

        let block_box = Box::new(hw::virtio::Block::new(disk_image)
                    .map_err(|e| Error::BlockDeviceNew(e))?);
        let jail = if cfg.multiprocess {
            let block_root_path = block_root.as_path().unwrap(); // Won't fail if new succeeded.
            Some(create_base_minijail(block_root_path, Path::new("block_device.policy"))?)
        }
        else {
            None
        };

        device_manager.register_mmio(block_box, jail, &mut cmdline)
                .map_err(Error::RegisterBlock)?;
    }

    let rng_root = TempDir::new(&PathBuf::from("/tmp/rng_root"))
        .map_err(Error::RngDeviceRootSetup)?;
    let rng_box = Box::new(hw::virtio::Rng::new().map_err(Error::RngDeviceNew)?);
    let rng_jail = if cfg.multiprocess {
        let rng_root_path = rng_root.as_path().unwrap(); // Won't fail if new succeeded.
        Some(create_base_minijail(rng_root_path, Path::new("rng_device.policy"))?)
    } else {
        None
    };
    device_manager.register_mmio(rng_box, rng_jail, &mut cmdline)
        .map_err(Error::RegisterRng)?;

    // We checked above that if the IP is defined, then the netmask is, too.
    let net_root = TempDir::new(&PathBuf::from("/tmp/net_root"))
        .map_err(Error::NetDeviceRootSetup)?;
    if let Some(host_ip) = cfg.host_ip {
        if let Some(netmask) = cfg.netmask {
            let net_box: Box<hw::virtio::VirtioDevice> = if cfg.vhost_net {
                Box::new(hw::virtio::VhostNet::new(host_ip, netmask, &guest_mem)
                                   .map_err(|e| Error::VhostNetDeviceNew(e))?)
            } else {
                Box::new(hw::virtio::Net::new(host_ip, netmask)
                                   .map_err(|e| Error::NetDeviceNew(e))?)
            };

            let jail = if cfg.multiprocess {
                let net_root_path = net_root.as_path().unwrap(); // Won't fail if new succeeded.

                let policy_path = if cfg.vhost_net {
                    Path::new("vhost_net_device.policy")
                } else {
                    Path::new("net_device.policy")
                };

                Some(create_base_minijail(net_root_path, policy_path)?)
            }
            else {
                None
            };

            device_manager.register_mmio(net_box, jail, &mut cmdline).map_err(Error::RegisterNet)?;
        }
    }

    if let Some(params) = cfg.params {
        cmdline
            .insert_str(params)
            .map_err(|e| Error::Cmdline(e))?;
    }

    run_kvm(device_manager.vm_requests,
            cfg.kernel_image,
            &CString::new(cmdline).unwrap(),
            cfg.vcpu_count.unwrap_or(1),
            guest_mem,
            &device_manager.bus,
            socket,
            cfg.warn_unknown_ports)
}

fn run_kvm(requests: Vec<VmRequest>,
           mut kernel_image: File,
           cmdline: &CStr,
           vcpu_count: u32,
           guest_mem: GuestMemory,
           mmio_bus: &hw::Bus,
           control_socket: Option<ControlSocketRecv>,
           warn_unknown_ports: bool)
           -> Result<()> {
    let kvm = Kvm::new().map_err(Error::Kvm)?;
    let tss_addr = GuestAddress(0xfffbd000);
    let kernel_start_addr = GuestAddress(KERNEL_START_OFFSET);
    let cmdline_addr = GuestAddress(CMDLINE_OFFSET);

    let vm = Vm::new(&kvm, guest_mem).map_err(Error::Vm)?;
    vm.set_tss_addr(tss_addr).expect("set tss addr failed");
    vm.create_pit().expect("create pit failed");
    vm.create_irq_chip().expect("create irq chip failed");

    for request in requests {
        match request {
            VmRequest::RegisterIoevent(evt, addr, datamatch) => {
                vm.register_ioevent(&evt, addr, datamatch)
                    .map_err(Error::RegisterIoevent)?
            }
            VmRequest::RegisterIrqfd(evt, irq) => {
                vm.register_irqfd(&evt, irq)
                    .map_err(Error::RegisterIrqfd)?
            }
        }
    }

    kernel_loader::load_kernel(vm.get_memory(), kernel_start_addr, &mut kernel_image)?;
    kernel_loader::load_cmdline(vm.get_memory(), cmdline_addr, cmdline)?;
    x86_64::configure_system(vm.get_memory(),
                             kernel_start_addr,
                             cmdline_addr,
                             cmdline.to_bytes().len() + 1,
                             vcpu_count as u8)?;

    let mut io_bus = hw::Bus::new();

    let exit_evt = EventFd::new().expect("failed to create exit eventfd");

    // Masking signals is inherently dangerous, since this can persist across
    // clones/execs. Do this after any jailed devices have been spawned, but
    // before the vcpus spawn so they also inherit the masking for SIGCHLD.
    let sigchld_fd = SignalFd::new(libc::SIGCHLD)
        .expect("failed to create child signalfd");

    struct NoDevice;
    impl hw::BusDevice for NoDevice {}

    let com_evt_1_3 = EventFd::new().map_err(Error::EventFd)?;
    let com_evt_2_4 = EventFd::new().map_err(Error::EventFd)?;
    let stdio_serial =
        Arc::new(Mutex::new(hw::Serial::new_out(com_evt_1_3.try_clone().map_err(Error::EventFd)?,
                                                Box::new(stdout()))));
    let nul_device = Arc::new(Mutex::new(NoDevice));
    io_bus.insert(stdio_serial.clone(), 0x3f8, 0x8).unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(hw::Serial::new_sink(com_evt_2_4
                                                             .try_clone()
                                                             .map_err(Error::EventFd)?))),
                0x2f8,
                0x8)
        .unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(hw::Serial::new_sink(com_evt_1_3
                                                             .try_clone()
                                                             .map_err(Error::EventFd)?))),
                0x3e8,
                0x8)
        .unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(hw::Serial::new_sink(com_evt_2_4
                                                             .try_clone()
                                                             .map_err(Error::EventFd)?))),
                0x2e8,
                0x8)
        .unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(hw::Cmos::new())), 0x70, 0x2)
        .unwrap();
    io_bus
        .insert(Arc::new(Mutex::new(hw::I8042Device::new(exit_evt
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
        let vcpu = Vcpu::new(cpu_id as u64, &kvm, &vm).map_err(Error::Vcpu)?;
        x86_64::configure_vcpu(vm.get_memory(),
                               kernel_start_addr,
                               &kvm,
                               &vcpu,
                               cpu_id as u64,
                               vcpu_count as u64)?;
        vcpu_handles.push(spawn(move || {
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
                                if !io_bus.read(addr as u64, data) && warn_unknown_ports {
                                    println!("warning: unhandled I/O port {}-bit read at 0x{:03x}",
                                             data.len() << 3,
                                             addr);
                                }
                            }

                            VcpuExit::IoOut(addr, data) => {
                                if !io_bus.write(addr as u64, data) && warn_unknown_ports {
                                    println!("warning: unhandled I/O port {}-bit write at 0x{:03x}",
                                             data.len() << 3,
                                             addr);
                                }
                            }

                            VcpuExit::MmioRead(addr, data) => {
                                if !mmio_bus.read(addr, data) && warn_unknown_ports {
                                    println!("warning: unhandled mmio {}-bit read at 0x{:08x}",
                                             data.len() << 3,
                                             addr);
                                }
                            }

                            VcpuExit::MmioWrite(addr, data) => {
                                if !mmio_bus.write(addr, data) && warn_unknown_ports {
                                    println!("warning: unhandled mmio {}-bit write at 0x{:08x}",
                                             data.len() << 3,
                                             addr);
                                }
                            }

                            VcpuExit::Hlt => break,
                            VcpuExit::Shutdown => break,
                            r => println!("unexpected vcpu exit: {:?}", r),
                        }
                    }
                    Err(e) => {
                        if e.errno() != libc::EAGAIN {
                            break;
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
        }));
    }

    vcpu_thread_barrier.wait();

    run_control(control_socket,
                stdio_serial,
                exit_evt,
                sigchld_fd,
                kill_signaled,
                vcpu_handles)
}

fn run_control(control_socket: Option<ControlSocketRecv>,
               stdio_serial: Arc<Mutex<hw::Serial>>,
               exit_evt: EventFd,
               sigchld_fd: SignalFd,
               kill_signaled: Arc<AtomicBool>,
               vcpu_handles: Vec<JoinHandle<()>>)
               -> Result<()> {
    const EXIT: u32 = 1;
    const STDIN: u32 = 2;
    const CONTROL: u32 = 3;
    const CHILD_SIGNAL: u32 = 4;

    let stdin_handle = stdin();
    let stdin_lock = stdin_handle.lock();
    stdin_lock
        .set_raw_mode()
        .expect("failed to set terminal raw mode");

    let mut pollables = Vec::new();
    pollables.push((EXIT, &exit_evt as &Pollable));
    pollables.push((STDIN, &stdin_lock as &Pollable));
    if let Some(socket) = control_socket.as_ref() {
        pollables.push((CONTROL, socket as &Pollable));
    }
    pollables.push((CHILD_SIGNAL, &sigchld_fd as &Pollable));

    let mut poller = Poller::new(4);

    'poll: loop {
        let poll_res = {
            match poller.poll(&pollables[..]) {
                Ok(v) => v,
                Err(e) => {
                    println!("failed to poll: {:?}", e);
                    break;
                }
            }
        };
        for i in poll_res {
            match *i {
                EXIT => {
                    println!("vcpu requested shutdown");
                    break 'poll;
                }
                STDIN => {
                    let mut out = [0u8; 64];
                    let count = stdin_lock.read_raw(&mut out[..]).unwrap_or_default();
                    if count != 0 {
                        stdio_serial
                            .lock()
                            .unwrap()
                            .queue_input_bytes(&out[..count])
                            .expect("failed to queue bytes into serial port");
                    }
                }
                CONTROL if control_socket.is_some() => {
                    if let Some(socket) = control_socket.as_ref() {
                        match socket.recv().unwrap() {
                            Command::Stop => {
                                println!("control socket requested shutdown");
                                break 'poll;
                            }
                            _ => {}
                        }
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
                    println!("failed to join vcpu thread: {:?}", e);
                }
            }
            Err(e) => println!("failed to kill vcpu thread: {:?}", e),
        }
    }

    stdin_lock
        .set_canon_mode()
        .expect("failed to restore canonical mode for terminal");

    Ok(())
}

fn main() {
    if let Err(e) = syslog::init() {
        println!("failed to initiailize syslog: {:?}", e);
        return;
    }
    let matches = App::new("crosvm")
        .version("0.1.0")
        .author("The Chromium OS Authors")
        .about("Runs a virtual machine under KVM")
        .subcommand(SubCommand::with_name("stop").arg(Arg::with_name("socket")
                                                          .required(true)
                                                          .multiple(true)
                                                          .index(1)
                                                          .value_name("PATH")
                                                          .help("path of the control sockets")))
        .subcommand(SubCommand::with_name("run")
                        .arg(Arg::with_name("disk")
                                 .short("d")
                                 .long("disk")
                                 .value_name("FILE")
                                 .help("disk image")
                                 .multiple(true)
                                 .number_of_values(1)
                                 .takes_value(true))
                        .arg(Arg::with_name("writable")
                                 .short("w")
                                 .long("writable")
                                 .value_name("FILE")
                                 .help("make disk image writable")
                                 .multiple(true)
                                 .number_of_values(1)
                                 .takes_value(true))
                        .arg(Arg::with_name("cpus")
                                 .short("c")
                                 .long("cpus")
                                 .value_name("N")
                                 .help("number of VCPUs")
                                 .takes_value(true))
                        .arg(Arg::with_name("memory")
                                 .short("m")
                                 .long("mem")
                                 .value_name("N")
                                 .help("amount of guest memory in MiB")
                                 .takes_value(true))
                        .arg(Arg::with_name("params")
                                 .short("p")
                                 .long("params")
                                 .value_name("params")
                                 .help("extra kernel command line arguments")
                                 .takes_value(true))
                        .arg(Arg::with_name("multiprocess")
                                 .short("u")
                                 .long("multiprocess")
                                 .help("run the devices in a child process"))
                        .arg(Arg::with_name("host_ip")
                                 .long("host_ip")
                                 .value_name("HOST_IP")
                                 .help("IP address to assign to host tap interface"))
                        .arg(Arg::with_name("netmask")
                                 .long("netmask")
                                 .value_name("NETMASK")
                                 .help("netmask for VM subnet"))
                        .arg(Arg::with_name("mac")
                                 .long("mac")
                                 .value_name("MAC")
                                 .help("mac address for VM"))
                        .arg(Arg::with_name("vhost_net")
                                 .long("vhost_net")
                                 .help("use vhost_net for networking"))
                        .arg(Arg::with_name("socket")
                                 .short("s")
                                 .long("socket")
                                 .value_name("PATH")
                                 .help("Path to put the control socket. If PATH is a directory, a name will be generated.")
                                 .takes_value(true))
                        .arg(Arg::with_name("warn-unknown-ports")
                                 .long("warn-unknown-ports")
                                 .help("warn when an the VM uses an unknown port"))
                        .arg(Arg::with_name("KERNEL")
                                 .required(true)
                                 .index(1)
                                 .help("bzImage of kernel to run")))
        .get_matches();

    match matches.subcommand() {
        ("stop", Some(matches)) => {
            for socket_path in matches.values_of("socket").unwrap() {
                let res = match ControlSocketSend::new(socket_path) {
                    Ok(s) => s.send(&Command::Stop),
                    Err(e) => Err(e),
                };
                if let Err(e) = res {
                    println!("failed to send stop command to socket at '{}': {}",
                             socket_path,
                             e);
                }
            }
        }
        ("run", Some(matches)) => {
            let mut disks = Vec::new();
            matches.values_of("disk").map(|paths| {
                disks.extend(paths.map(|ref p| {
                    DiskOption {
                        path: p,
                        writable: false,
                    }
                }))
            });
            if let Some(write_paths) = matches.values_of("writable") {
                for path in write_paths {
                    disks.iter_mut().find(|ref mut d| d.path == path).map(
                        |ref mut d| d.writable = true,
                    );
                }
            }
            let config = Config {
                disks: disks,
                vcpu_count: matches.value_of("cpus").and_then(|v| v.parse().ok()),
                memory: matches.value_of("memory").and_then(|v| v.parse().ok()),
                kernel_image: File::open(matches.value_of("KERNEL").unwrap())
                    .expect("Expected kernel image path to be valid"),
                params: matches.value_of("params").map(|s| s.to_string()),
                multiprocess: matches.is_present("multiprocess"),
                host_ip: matches.value_of("host_ip").and_then(|v| v.parse().ok()),
                netmask: matches.value_of("netmask").and_then(|v| v.parse().ok()),
                mac_address: matches.value_of("mac").map(|s| s.to_string()),
                vhost_net: matches.is_present("vhost_net"),
                socket_path: matches.value_of("socket").map(|s| s.to_string()),
                warn_unknown_ports: matches.is_present("warn-unknown-ports"),
            };

            match run_config(config) {
                Ok(_) => println!("crosvm has exited normally"),
                Err(e) => println!("{}", e),
            }

            // Reap exit status from any child device processes. At this point,
            // all devices should have been dropped in the main process and
            // told to shutdown. Try over a period of 100ms, since it may
            // take some time for the processes to shut down.
            if !wait_all_children() {
                // We gave them a chance, and it's too late.
                // A pid of 0 will kill any processes left in our process group,
                // which is safe for us to do (we spawned them).
                warn!("not all child processes have exited; sending SIGKILL");
                let ret = unsafe { libc::kill(0, libc::SIGKILL) };
                if ret < 0 {
                    // We're now at the mercy of the OS to clean up after us.
                    warn!("unable to kill all child processes");
                }
            }

            // WARNING: Any code added after this point is not guaranteed to run
            // since we may forcibly kill this process (and its children) above.
        }
        _ => {}
    }
}
