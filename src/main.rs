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

use std::ffi::{CString, CStr};
use std::fmt;
use std::fs::File;
use std::io::{stdin, stdout};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::string::String;
use std::sync::{Arc, Mutex, Barrier};
use std::thread::{spawn, JoinHandle};

use clap::{Arg, App, SubCommand};

use io_jail::Minijail;
use kvm::*;
use sys_util::{GuestAddress, GuestMemory, EventFd, TempDir, Terminal, Poller, Pollable,
               register_signal_handler, Killable};

pub mod hw;
pub mod kernel_cmdline;
pub mod control_socket;

use control_socket::*;

enum Error {
    Socket(std::io::Error),
    Disk(std::io::Error),
    BlockDeviceNew(sys_util::Error),
    BlockDeviceJail(io_jail::Error),
    BlockDevicePivotRoot(io_jail::Error),
    BlockDeviceRootSetup(sys_util::Error),
    Cmdline(kernel_cmdline::Error),
    ProxyDeviceCreation(std::io::Error),
    RegisterIoevent(sys_util::Error),
    RegisterIrqfd(sys_util::Error),
    KernelLoader(kernel_loader::Error),
    ConfigureSystem(x86_64::Error),
    EventFd(sys_util::Error),
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
            &Error::BlockDeviceJail(ref e) => write!(f, "failed to jail block device: {:?}", e),
            &Error::BlockDevicePivotRoot(ref e) => {
                write!(f, "failed to pivot root block device: {:?}", e)
            }
            &Error::BlockDeviceRootSetup(ref e) => {
                write!(f, "failed to create root directory for a block device: {:?}", e)
            }
            &Error::Cmdline(ref e) => write!(f, "the given kernel command line was invalid: {}", e),
            &Error::ProxyDeviceCreation(ref e) => write!(f, "failed to create proxy device: {}", e),
            &Error::RegisterIoevent(ref e) => write!(f, "error registering ioevent: {:?}", e),
            &Error::RegisterIrqfd(ref e) => write!(f, "error registering irqfd: {:?}", e),
            &Error::KernelLoader(ref e) => write!(f, "error loading kernel: {:?}", e),
            &Error::ConfigureSystem(ref e) => write!(f, "error configuring system: {:?}", e),
            &Error::EventFd(ref e) => write!(f, "error creating EventFd: {:?}", e),
            &Error::Kvm(ref e) => write!(f, "error creating Kvm: {:?}", e),
            &Error::Vm(ref e) => write!(f, "error creating Vm: {:?}", e),
            &Error::Vcpu(ref e) => write!(f, "error creating Vcpu: {:?}", e),
            &Error::Sys(ref e) => write!(f, "error with system call: {:?}", e),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

struct Config {
    disk_path: Option<String>,
    vcpu_count: Option<u32>,
    memory: Option<usize>,
    kernel_image: File,
    params: Option<String>,
    socket_path: Option<String>,
    multiprocess: bool,
    warn_unknown_ports: bool,
}

enum VmRequest {
    RegisterIoevent(EventFd, IoeventAddress, u32),
    RegisterIrqfd(EventFd, u32),
}

const KERNEL_START_OFFSET: usize = 0x200000;
const CMDLINE_OFFSET: usize = 0x20000;
const CMDLINE_MAX_SIZE: usize = KERNEL_START_OFFSET - CMDLINE_OFFSET;

fn create_block_device_jail(root: &Path) -> Result<Minijail> {
    // All child jails run in a new user namespace without any users mapped,
    // they run as nobody unless otherwise configured.
    let mut j = Minijail::new().map_err(|e| Error::BlockDeviceJail(e))?;
    // Don't need any capabilities.
    j.use_caps(0);
    // Create a new mount namespace with an empty root FS.
    j.namespace_vfs();
    j.enter_pivot_root(root)
        .map_err(|e| Error::BlockDevicePivotRoot(e))?;
    // Run in an empty network namespace.
    j.namespace_net();
    // Apply the block device seccomp policy.
    j.no_new_privs();
    j.parse_seccomp_filters(Path::new("block_device.policy"))
        .map_err(|e| Error::BlockDeviceJail(e))?;
    j.use_seccomp_filter();
    Ok(j)
}

fn run_config(cfg: Config) -> Result<()> {
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

    let mut vm_requests = Vec::new();

    let mut bus = hw::Bus::new();

    let mmio_len = 0x1000;
    let mut mmio_base: u64 = 0xd0000000;
    let mut irq: u32 = 5;

    let block_root = TempDir::new(&PathBuf::from("/tmp/block_root"))
        .map_err(Error::BlockDeviceRootSetup)?;

    if let Some(ref disk_path) = cfg.disk_path {
        // List of FDs to keep open in the child after it forks.
        let mut keep_fds: Vec<RawFd> = Vec::new();

        let disk_image = File::open(disk_path).map_err(|e| Error::Disk(e))?;
        keep_fds.push(disk_image.as_raw_fd());

        let block_box = Box::new(hw::virtio::Block::new(disk_image)
                                     .map_err(|e| Error::BlockDeviceNew(e))?);
        let block_mmio = hw::virtio::MmioDevice::new(guest_mem.clone(), block_box)?;
        for (i, queue_evt) in block_mmio.queue_evts().iter().enumerate() {
            let io_addr = IoeventAddress::Mmio(mmio_base + hw::virtio::NOITFY_REG_OFFSET as u64);
            vm_requests.push(VmRequest::RegisterIoevent(queue_evt.try_clone()?, io_addr, i as u32));
            keep_fds.push(queue_evt.as_raw_fd());
        }

        if let Some(interrupt_evt) = block_mmio.interrupt_evt() {
            vm_requests.push(VmRequest::RegisterIrqfd(interrupt_evt.try_clone()?, irq));
            keep_fds.push(interrupt_evt.as_raw_fd());
        }

        if cfg.multiprocess {
            // block_root.as_path() won't fail if block_root::new succeeded.
            let block_root_path = block_root.as_path().unwrap();
            let jail = create_block_device_jail(block_root_path)?;
            let proxy_dev = hw::ProxyDevice::new(block_mmio, move |keep_pipe| {
                keep_fds.push(keep_pipe.as_raw_fd());
                // Need to panic here as there isn't a way to recover from a
                // partly-jailed process.
                unsafe {
                    // This is OK as we have whitelisted all the FDs we need open.
                    jail.enter(Some(&keep_fds)).unwrap();
                }
            })
                    .map_err(|e| Error::ProxyDeviceCreation(e))?;
            bus.insert(Arc::new(Mutex::new(proxy_dev)), mmio_base, mmio_len)
                .unwrap();
        } else {
            bus.insert(Arc::new(Mutex::new(block_mmio)), mmio_base, mmio_len)
                .unwrap();
        }

        cmdline
            .insert("virtio_mmio.device",
                    &format!("4K@0x{:08x}:{}", mmio_base, irq))
            .map_err(Error::Cmdline)?;
        cmdline
            .insert("root", "/dev/vda")
            .map_err(Error::Cmdline)?;
        mmio_base += mmio_len;
        irq += 1;
    }

    if let Some(params) = cfg.params {
        cmdline
            .insert_str(params)
            .map_err(|e| Error::Cmdline(e))?;
    }

    run_kvm(vm_requests,
            cfg.kernel_image,
            &CString::new(cmdline).unwrap(),
            cfg.vcpu_count.unwrap_or(1),
            guest_mem,
            bus,
            socket,
            cfg.warn_unknown_ports)
}

fn run_kvm(requests: Vec<VmRequest>,
           mut kernel_image: File,
           cmdline: &CStr,
           vcpu_count: u32,
           guest_mem: GuestMemory,
           mmio_bus: hw::Bus,
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

    let mut vcpu_handles = Vec::with_capacity(vcpu_count as usize);
    let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));
    for cpu_id in 0..vcpu_count {
        let mmio_bus = mmio_bus.clone();
        let io_bus = io_bus.clone();
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
            }
            vcpu_exit_evt
                .write(1)
                .expect("failed to signal vcpu exit eventfd");
        }));
    }

    vcpu_thread_barrier.wait();

    run_control(control_socket, stdio_serial, exit_evt, vcpu_handles)
}

fn run_control(control_socket: Option<ControlSocketRecv>,
               stdio_serial: Arc<Mutex<hw::Serial>>,
               exit_evt: EventFd,
               vcpu_handles: Vec<JoinHandle<()>>)
               -> Result<()> {
    const EXIT: u32 = 1;
    const STDIN: u32 = 2;
    const CONTROL: u32 = 3;

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

    let mut poller = Poller::new(3);

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
                _ => {}
            }
        }
    }

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
                                 .help("rootfs disk image")
                                 .takes_value(true))
                        .arg(Arg::with_name("cpus")
                                 .short("c")
                                 .long("cpus")
                                 .value_name("N")
                                 .help("number of VCPUs (WARNING: CURRENTLY UNUSED)")
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
            let config = Config {
                disk_path: matches.value_of("disk").map(|s| s.to_string()),
                vcpu_count: matches.value_of("cpus").and_then(|v| v.parse().ok()),
                memory: matches.value_of("memory").and_then(|v| v.parse().ok()),
                kernel_image: File::open(matches.value_of("KERNEL").unwrap())
                    .expect("Expected kernel image path to be valid"),
                params: matches.value_of("params").map(|s| s.to_string()),
                multiprocess: matches.is_present("multiprocess"),
                socket_path: matches.value_of("socket").map(|s| s.to_string()),
                warn_unknown_ports: matches.is_present("warn-unknown-ports"),
            };

            match run_config(config) {
                Ok(_) => println!("crosvm has exited normally"),
                Err(e) => println!("{}", e),
            }
        }
        _ => {}
    }
}
