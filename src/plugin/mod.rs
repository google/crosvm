// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod process;
mod vcpu;

use std::fmt;
use std::fs::File;
use std::io;
use std::os::unix::io::{IntoRawFd, FromRawFd};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use libc::{socketpair, ioctl, c_ulong, AF_UNIX, SOCK_SEQPACKET, FIOCLEX, EAGAIN, EINTR, EINVAL,
           ENOENT, EPERM, EDEADLK, EEXIST, EBADF, EOVERFLOW, SIGCHLD, MS_NOSUID, MS_NODEV};

use protobuf::ProtobufError;

use io_jail::{self, Minijail};
use kvm::{Kvm, Vm, Vcpu, VcpuExit, IoeventAddress, NoDatamatch};
use net_util::{Error as TapError, Tap, TapT};
use sys_util::{EventFd, MmapError, Killable, SignalFd, SignalFdError, PollContext, PollToken,
               GuestMemory, Result as SysResult, Error as SysError, block_signal, clear_signal,
               SIGRTMIN, register_signal_handler, geteuid, getegid};

use Config;

use self::process::*;
use self::vcpu::*;

const MAX_DATAGRAM_SIZE: usize = 4096;
const MAX_VCPU_DATAGRAM_SIZE: usize = 0x40000;

/// An error that occurs during the lifetime of a plugin process.
pub enum Error {
    CloneEventFd(SysError),
    CloneVcpuSocket(io::Error),
    CreateEventFd(SysError),
    CreateIrqChip(SysError),
    CreateJail(io_jail::Error),
    CreateKvm(SysError),
    CreateMainSocket(SysError),
    CreatePIT(SysError),
    CreatePollContext(SysError),
    CreateSignalFd(SignalFdError),
    CreateSocketPair(io::Error),
    CreateVcpu(SysError),
    CreateVcpuSocket(SysError),
    CreateVm(SysError),
    DecodeRequest(ProtobufError),
    EncodeResponse(ProtobufError),
    MountLib(io_jail::Error),
    MountLib64(io_jail::Error),
    MountPlugin(io_jail::Error),
    MountPluginLib(io_jail::Error),
    MountRoot(io_jail::Error),
    NoVarEmpty,
    ParsePivotRoot(io_jail::Error),
    ParseSeccomp(io_jail::Error),
    PluginFailed(i32),
    PluginKill(SysError),
    PluginKilled(i32),
    PluginRunJail(io_jail::Error),
    PluginSocketHup,
    PluginSocketPoll(SysError),
    PluginSocketRecv(SysError),
    PluginSocketSend(SysError),
    PluginSpawn(io::Error),
    PluginTimeout,
    PluginWait(SysError),
    Poll(SysError),
    PollContextAdd(SysError),
    SetGidMap(io_jail::Error),
    SetUidMap(io_jail::Error),
    SigChild {
        pid: u32,
        signo: u32,
        status: i32,
        code: i32,
    },
    SignalFd(SignalFdError),
    SpawnVcpu(io::Error),
    TapOpen(TapError),
    TapSetIp(TapError),
    TapSetNetmask(TapError),
    TapSetMacAddress(TapError),
    TapEnable(TapError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CloneEventFd(ref e) => write!(f, "failed to clone eventfd: {:?}", e),
            Error::CloneVcpuSocket(ref e) => write!(f, "failed to clone vcpu socket: {:?}", e),
            Error::CreateEventFd(ref e) => write!(f, "failed to create eventfd: {:?}", e),
            Error::CreateIrqChip(ref e) => write!(f, "failed to create kvm irqchip: {:?}", e),
            Error::CreateJail(ref e) => write!(f, "failed to create jail: {}", e),
            Error::CreateKvm(ref e) => write!(f, "error creating Kvm: {:?}", e),
            Error::CreateMainSocket(ref e) => {
                write!(f, "error creating main request socket: {:?}", e)
            }
            Error::CreatePIT(ref e) => write!(f, "failed to create kvm PIT: {:?}", e),
            Error::CreatePollContext(ref e) => write!(f, "failed to create poll context: {:?}", e),
            Error::CreateSignalFd(ref e) => write!(f, "failed to create signalfd: {:?}", e),
            Error::CreateSocketPair(ref e) => write!(f, "failed to create socket pair: {}", e),
            Error::CreateVcpu(ref e) => write!(f, "error creating vcpu: {:?}", e),
            Error::CreateVcpuSocket(ref e) => {
                write!(f, "error creating vcpu request socket: {:?}", e)
            }
            Error::CreateVm(ref e) => write!(f, "error creating vm: {:?}", e),
            Error::DecodeRequest(ref e) => write!(f, "failed to decode plugin request: {}", e),
            Error::EncodeResponse(ref e) => write!(f, "failed to encode plugin response: {}", e),
            Error::MountLib(ref e) => write!(f, "failed to mount: {}", e),
            Error::MountLib64(ref e) => write!(f, "failed to mount: {}", e),
            Error::MountPlugin(ref e) => write!(f, "failed to mount: {}", e),
            Error::MountPluginLib(ref e) => write!(f, "failed to mount: {}", e),
            Error::MountRoot(ref e) => write!(f, "failed to mount: {}", e),
            Error::NoVarEmpty => write!(f, "no /var/empty for jailed process to pivot root into"),
            Error::ParsePivotRoot(ref e) => write!(f, "failed to set jail pivot root: {}", e),
            Error::ParseSeccomp(ref e) => write!(f, "failed to parse jail seccomp filter: {}", e),
            Error::PluginFailed(ref e) => write!(f, "plugin exited with error: {}", e),
            Error::PluginKill(ref e) => write!(f, "error sending kill signal to plugin: {:?}", e),
            Error::PluginKilled(ref e) => write!(f, "plugin exited with signal {}", e),
            Error::PluginRunJail(ref e) => write!(f, "failed to run jail: {}", e),
            Error::PluginSocketHup => write!(f, "plugin request socket has been hung up"),
            Error::PluginSocketPoll(ref e) => {
                write!(f, "failed to poll plugin request sockets: {:?}", e)
            }
            Error::PluginSocketRecv(ref e) => {
                write!(f, "failed to recv from plugin request socket: {:?}", e)
            }
            Error::PluginSocketSend(ref e) => {
                write!(f, "failed to send to plugin request socket: {:?}", e)
            }
            Error::PluginSpawn(ref e) => write!(f, "failed to spawn plugin: {}", e),
            Error::PluginTimeout => write!(f, "plugin did not exit within timeout"),
            Error::PluginWait(ref e) => write!(f, "error waiting for plugin to exit: {:?}", e),
            Error::Poll(ref e) => write!(f, "failed to poll all FDs: {:?}", e),
            Error::PollContextAdd(ref e) => write!(f, "failed to add fd to poll context: {:?}", e),
            Error::SetGidMap(ref e) => write!(f, "failed to set gidmap for jail: {}", e),
            Error::SetUidMap(ref e) => write!(f, "failed to set uidmap for jail: {}", e),
            Error::SigChild {
                pid,
                signo,
                status,
                code,
            } => {
                write!(f,
                       "process {} died with signal {}, status {}, and code {}",
                       pid,
                       signo,
                       status,
                       code)
            }
            Error::SignalFd(ref e) => write!(f, "failed to read signal fd: {:?}", e),
            Error::SpawnVcpu(ref e) => write!(f, "error spawning vcpu thread: {}", e),
            Error::TapOpen(ref e) => write!(f, "error opening tap device: {:?}", e),
            Error::TapSetIp(ref e) => write!(f, "error setting tap ip: {:?}", e),
            Error::TapSetNetmask(ref e) => write!(f, "error setting tap netmask: {:?}", e),
            Error::TapSetMacAddress(ref e) => write!(f, "error setting tap mac address: {:?}", e),
            Error::TapEnable(ref e) => write!(f, "error enabling tap device: {:?}", e),
        }
    }
}

type Result<T> = result::Result<T, Error>;

fn downcast_file<F: IntoRawFd>(f: F) -> File {
    unsafe { File::from_raw_fd(f.into_raw_fd()) }
}

fn new_seqpacket_pair() -> SysResult<(UnixDatagram, UnixDatagram)> {
    let mut fds = [0, 0];
    unsafe {
        let ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds.as_mut_ptr());
        if ret == 0 {
            ioctl(fds[0], FIOCLEX);
            Ok((UnixDatagram::from_raw_fd(fds[0]), UnixDatagram::from_raw_fd(fds[1])))
        } else {
            Err(SysError::last())
        }
    }
}

fn proto_to_sys_err(e: ProtobufError) -> SysError {
    match e {
        ProtobufError::IoError(e) => SysError::new(e.raw_os_error().unwrap_or(EINVAL)),
        _ => SysError::new(EINVAL),
    }
}

fn io_to_sys_err(e: io::Error) -> SysError {
    SysError::new(e.raw_os_error().unwrap_or(EINVAL))
}

fn mmap_to_sys_err(e: MmapError) -> SysError {
    match e {
        MmapError::SystemCallFailed(e) => e,
        _ => SysError::new(EINVAL),
    }
}

fn create_plugin_jail(root: &Path, seccomp_policy: &Path) -> Result<Minijail> {
    // All child jails run in a new user namespace without any users mapped,
    // they run as nobody unless otherwise configured.
    let mut j = Minijail::new().map_err(Error::CreateJail)?;
    j.namespace_pids();
    j.namespace_user();
    j.uidmap(&format!("{0} {0} 1", geteuid()))
        .map_err(Error::SetUidMap)?;
    j.gidmap(&format!("{0} {0} 1", getegid()))
        .map_err(Error::SetGidMap)?;
    j.namespace_user_disable_setgroups();
    // Don't need any capabilities.
    j.use_caps(0);
    // Create a new mount namespace with an empty root FS.
    j.namespace_vfs();
    j.enter_pivot_root(root).map_err(Error::ParsePivotRoot)?;
    // Run in an empty network namespace.
    j.namespace_net();
    j.no_new_privs();
    // Use TSYNC only for the side effect of it using SECCOMP_RET_TRAP, which will correctly kill
    // the entire plugin process if a worker thread commits a seccomp violation.
    j.set_seccomp_filter_tsync();
    j.parse_seccomp_filters(seccomp_policy)
        .map_err(Error::ParseSeccomp)?;
    j.use_seccomp_filter();
    // Don't do init setup.
    j.run_as_init();

    // Create a tmpfs in the plugin's root directory so that we can bind mount it's executable
    // file into it.  The size=67108864 is size=64*1024*1024 or size=64MB.
    j.mount_with_data(Path::new("none"),
                         Path::new("/"),
                         "tmpfs",
                         (MS_NOSUID | MS_NODEV) as usize,
                         "size=67108864")
        .map_err(Error::MountRoot)?;

    Ok(j)
}

/// Each `PluginObject` represents one object that was instantiated by the guest using the `Create`
/// request.
///
/// Each such object has an ID associated with it that exists in an ID space shared by every variant
/// of `PluginObject`. This allows all the objects to be indexed in a single map, and allows for a
/// common destroy method.
///

/// In addition to the destory method, each object may have methods specific to its variant type.
/// These variant methods must be done by matching the variant to the expected type for that method.
/// For example, getting the dirty log from a `Memory` object starting with an ID:
///
/// ```
/// match objects.get(&request_id) {
///    Some(&PluginObject::Memory { slot, length }) => vm.get_dirty_log(slot, &mut dirty_log[..])
///    _ => return Err(SysError::new(ENOENT)),
/// }
/// ```
enum PluginObject {
    IoEvent {
        evt: EventFd,
        addr: IoeventAddress,
        length: u32,
        datamatch: u64,
    },
    Memory { slot: u32, length: usize },
    IrqEvent { irq_id: u32, evt: EventFd },
}

impl PluginObject {
    fn destroy(self, vm: &mut Vm) -> SysResult<()> {
        match self {
            PluginObject::IoEvent {
                evt,
                addr,
                length,
                datamatch,
            } => {
                match length {
                    0 => vm.unregister_ioevent(&evt, addr, NoDatamatch),
                    1 => vm.unregister_ioevent(&evt, addr, datamatch as u8),
                    2 => vm.unregister_ioevent(&evt, addr, datamatch as u16),
                    4 => vm.unregister_ioevent(&evt, addr, datamatch as u32),
                    8 => vm.unregister_ioevent(&evt, addr, datamatch as u64),
                    _ => Err(SysError::new(EINVAL)),
                }
            }
            PluginObject::Memory { slot, .. } => vm.remove_device_memory(slot).and(Ok(())),
            PluginObject::IrqEvent { irq_id, evt } => vm.unregister_irqfd(&evt, irq_id),
        }
    }
}

pub fn run_vcpus(kvm: &Kvm,
                 vm: &Vm,
                 plugin: &Process,
                 vcpu_count: u32,
                 kill_signaled: &Arc<AtomicBool>,
                 exit_evt: &EventFd,
                 vcpu_handles: &mut Vec<thread::JoinHandle<()>>)
                 -> Result<()> {
    let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count) as usize));
    for cpu_id in 0..vcpu_count {
        let kill_signaled = kill_signaled.clone();
        let vcpu_thread_barrier = vcpu_thread_barrier.clone();
        let vcpu_exit_evt = exit_evt.try_clone().map_err(Error::CloneEventFd)?;
        let vcpu_plugin = plugin.create_vcpu(cpu_id)?;
        let vcpu = Vcpu::new(cpu_id as c_ulong, kvm, vm)
            .map_err(Error::CreateVcpu)?;

        vcpu_handles.push(thread::Builder::new()
                              .name(format!("crosvm_vcpu{}", cpu_id))
                              .spawn(move || {
            unsafe {
                extern "C" fn handle_signal() {}
                // Our signal handler does nothing and is trivially async signal safe.
                // We need to install this signal handler even though we do block
                // the signal below, to ensure that this signal will interrupt
                // execution of KVM_RUN (this is implementation issue).
                register_signal_handler(SIGRTMIN() + 0, handle_signal)
                    .expect("failed to register vcpu signal handler");
            }

            // We do not really want the signal handler to run...
            block_signal(SIGRTMIN() + 0)
                .expect("failed to block signal");
            // Tell KVM to not block anything when entering kvm run
            // because we will be using first RT signal to kick the VCPU.
            vcpu.set_signal_mask(&[])
                .expect("failed to set up KVM VCPU signal mask");

            let res = vcpu_plugin.init(&vcpu);
            vcpu_thread_barrier.wait();
            if let Err(e) = res {
                error!("failed to initialize vcpu {}: {:?}", cpu_id, e);
            } else {
                loop {
                    let run_res = vcpu.run();
                    match run_res {
                        Ok(run) => {
                            match run {
                                VcpuExit::IoIn(addr, data) => {
                                    vcpu_plugin.io_read(addr as u64, data, &vcpu);
                                }
                                VcpuExit::IoOut(addr, data) => {
                                    vcpu_plugin.io_write(addr as u64, data, &vcpu);
                                }
                                VcpuExit::MmioRead(addr, data) => {
                                    vcpu_plugin.mmio_read(addr as u64, data, &vcpu);
                                }
                                VcpuExit::MmioWrite(addr, data) => {
                                    vcpu_plugin.mmio_write(addr as u64, data, &vcpu);
                                }
                                VcpuExit::Hlt => break,
                                VcpuExit::Shutdown => break,
                                VcpuExit::InternalError => {
                                    error!("vcpu {} has internal error", cpu_id);
                                    break;
                                }
                                r => warn!("unexpected vcpu exit: {:?}", r),
                            }
                        }
                        Err(e) => {
                            match e.errno() {
                                EAGAIN | EINTR => {}
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

                    // Try to clear the signal that we use to kick VCPU if it is
                    // pending before attempting to handle pause requests.
                    clear_signal(SIGRTMIN() + 0)
                        .expect("failed to clear pending signal");

                    if let Err(e) = vcpu_plugin.pre_run(&vcpu) {
                        error!("failed to process pause on vcpu {}: {:?}", cpu_id, e);
                        break;
                    }
                }
            }
            vcpu_exit_evt
                .write(1)
                .expect("failed to signal vcpu exit eventfd");
        })
                              .map_err(Error::SpawnVcpu)?);
    }
    Ok(())
}

#[derive(PollToken)]
enum Token {
    Exit,
    ChildSignal,
    Plugin { index: usize },
}

/// Run a VM with a plugin process specified by `cfg`.
///
/// Not every field of `cfg` will be used. In particular, most field that pertain to a specific
/// device are ignored because the plugin is responsible for emulating hardware.
pub fn run_config(cfg: Config) -> Result<()> {
    info!("crosvm starting plugin process");

    // Masking signals is inherently dangerous, since this can persist across clones/execs. Do this
    // before any jailed devices have been spawned, so that we can catch any of them that fail very
    // quickly.
    let sigchld_fd = SignalFd::new(SIGCHLD).map_err(Error::CreateSignalFd)?;

    let jail = if cfg.multiprocess {
        // An empty directory for jailed plugin pivot root.
        let empty_root_path = Path::new("/var/empty");
        if !empty_root_path.exists() {
            return Err(Error::NoVarEmpty);
        }

        let policy_path = cfg.seccomp_policy_dir.join("plugin.policy");
        let jail = create_plugin_jail(empty_root_path, &policy_path)?;
        Some(jail)
    } else {
        None
    };

    let mut tap_opt: Option<Tap> = None;
    if let Some(host_ip) = cfg.host_ip {
        if let Some(netmask) = cfg.netmask {
            if let Some(mac_address) = cfg.mac_address {
                let tap = Tap::new(false).map_err(Error::TapOpen)?;
                tap.set_ip_addr(host_ip).map_err(Error::TapSetIp)?;
                tap.set_netmask(netmask)
                    .map_err(Error::TapSetNetmask)?;
                tap.set_mac_address(mac_address)
                    .map_err(Error::TapSetMacAddress)?;

                tap.enable().map_err(Error::TapEnable)?;
                tap_opt = Some(tap);
            }
        }
    }

    let plugin_args: Vec<&str> = cfg.params.iter().map(|s| &s[..]).collect();

    let plugin_path = cfg.plugin.as_ref().unwrap().as_path();
    let vcpu_count = cfg.vcpu_count.unwrap_or(1);
    let mem = GuestMemory::new(&[]).unwrap();
    let kvm = Kvm::new().map_err(Error::CreateKvm)?;
    let mut vm = Vm::new(&kvm, mem).map_err(Error::CreateVm)?;
    vm.create_irq_chip().map_err(Error::CreateIrqChip)?;
    vm.create_pit().map_err(Error::CreatePIT)?;
    let mut plugin = Process::new(vcpu_count, plugin_path, &plugin_args, jail)?;

    let mut res = Ok(());
    // If Some, we will exit after enough time is passed to shutdown cleanly.
    let mut dying_instant: Option<Instant> = None;
    let duration_to_die = Duration::from_millis(1000);

    let exit_evt = EventFd::new().map_err(Error::CreateEventFd)?;
    let kill_signaled = Arc::new(AtomicBool::new(false));
    let mut vcpu_handles = Vec::with_capacity(vcpu_count as usize);

    let poll_ctx = PollContext::new().map_err(Error::CreatePollContext)?;
    poll_ctx
        .add(&exit_evt, Token::Exit)
        .map_err(Error::PollContextAdd)?;
    poll_ctx
        .add(&sigchld_fd, Token::ChildSignal)
        .map_err(Error::PollContextAdd)?;

    let mut sockets_to_drop = Vec::new();
    let mut redo_poll_ctx_sockets = true;
    // In this loop, make every attempt to not return early. If an error is encountered, set `res`
    // to the error, set `dying_instant` to now, and signal the plugin that it will be killed soon.
    // If the plugin cannot be singaled because it is dead of `signal_kill` failed, simply break
    // from the poll loop so that the VCPU threads can be cleaned up.
    'poll: loop {
        // After we have waited long enough, it's time to give up and exit.
        if dying_instant
               .map(|i| i.elapsed() >= duration_to_die)
               .unwrap_or(false) {
            break;
        }

        if redo_poll_ctx_sockets {
            for (index, socket) in plugin.sockets().iter().enumerate() {
                poll_ctx
                    .add(socket, Token::Plugin { index })
                    .map_err(Error::PollContextAdd)?;
            }
        }

        let plugin_socket_count = plugin.sockets().len();
        let events = {
            let poll_res = match dying_instant {
                Some(ref inst) => poll_ctx.wait_timeout(duration_to_die - inst.elapsed()),
                None => poll_ctx.wait(),
            };
            match poll_res {
                Ok(v) => v,
                Err(e) => {
                    // Polling no longer works, time to break and cleanup,
                    if res.is_ok() {
                        res = Err(Error::Poll(e));
                    }
                    break;
                }
            }
        };
        for event in events.iter_readable() {
            match event.token() {
                Token::Exit => {
                    // No need to check the exit event if we are already doing cleanup.
                    let _ = poll_ctx.delete(&exit_evt);
                    dying_instant.get_or_insert(Instant::now());
                    let sig_res = plugin.signal_kill();
                    if res.is_ok() && sig_res.is_err() {
                        res = sig_res.map_err(Error::PluginKill);
                    }
                }
                Token::ChildSignal => {
                    // Print all available siginfo structs, then exit the loop.
                    loop {
                        match sigchld_fd.read() {
                            Ok(Some(siginfo)) => {
                                // If the plugin process has ended, there is no need to continue
                                // processing plugin connections, so we break early.
                                if siginfo.ssi_pid == plugin.pid() as u32 {
                                    break 'poll;
                                }
                                // Because SIGCHLD is not expected from anything other than the
                                // plugin process, report it as an error.
                                if res.is_ok() {
                                    res = Err(Error::SigChild {
                                                  pid: siginfo.ssi_pid,
                                                  signo: siginfo.ssi_signo,
                                                  status: siginfo.ssi_status,
                                                  code: siginfo.ssi_code,
                                              })
                                }
                            }
                            Ok(None) => break, // No more signals to read.
                            Err(e) => {
                                // Something really must be messed up for this to happen, continue
                                // processing connections for a limited time.
                                if res.is_ok() {
                                    res = Err(Error::SignalFd(e));
                                }
                                break;
                            }
                        }
                    }
                    // As we only spawn the plugin process, getting a SIGCHLD can only mean
                    // something went wrong.
                    dying_instant.get_or_insert(Instant::now());
                    let sig_res = plugin.signal_kill();
                    if res.is_ok() && sig_res.is_err() {
                        res = sig_res.map_err(Error::PluginKill);
                    }
                }
                Token::Plugin { index } => {
                    match plugin.handle_socket(index,
                                               &kvm,
                                               &mut vm,
                                               &vcpu_handles,
                                               tap_opt.as_ref()) {
                        Ok(_) => {}
                        // A HUP is an expected event for a socket, so don't bother warning about
                        // it.
                        Err(Error::PluginSocketHup) => sockets_to_drop.push(index),
                        // Only one connection out of potentially many is broken. Drop it, but don't
                        // start cleaning up. Because the error isn't returned, we will warn about
                        // it here.
                        Err(e) => {
                            warn!("error handling plugin socket: {}", e);
                            sockets_to_drop.push(index);
                        }
                    }
                }
            }
        }

        if vcpu_handles.is_empty() && dying_instant.is_none() && plugin.is_started() {
            let res = run_vcpus(&kvm,
                                &vm,
                                &plugin,
                                vcpu_count,
                                &kill_signaled,
                                &exit_evt,
                                &mut vcpu_handles);
            if let Err(e) = res {
                dying_instant.get_or_insert(Instant::now());
                error!("failed to start vcpus: {}", e);
            }
        }

        redo_poll_ctx_sockets = !sockets_to_drop.is_empty() ||
                                plugin.sockets().len() != plugin_socket_count;

        // Cleanup all of the sockets that we have determined were disconnected or suffered some
        // other error.
        plugin.drop_sockets(&mut sockets_to_drop);
        sockets_to_drop.clear();

        if redo_poll_ctx_sockets {
            for socket in plugin.sockets() {
                let _ = poll_ctx.delete(socket);
            }
        }
    }

    // vcpu threads MUST see the kill signaled flag, otherwise they may re-enter the VM.
    kill_signaled.store(true, Ordering::SeqCst);
    // Depending on how we ended up here, the plugin process, or a VCPU thread waiting for requests
    // might be stuck. The `signal_kill` call will unstick all the VCPU threads by closing their
    // blocked connections.
    plugin.signal_kill().map_err(Error::PluginKill)?;
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

    match plugin.try_wait() {
        // The plugin has run out of time by now
        Ok(ProcessStatus::Running) => return Err(Error::PluginTimeout),
        // Return an error discovered earlier in this function.
        Ok(ProcessStatus::Success) => return res,
        Ok(ProcessStatus::Fail(code)) => return Err(Error::PluginFailed(code)),
        Ok(ProcessStatus::Signal(code)) => return Err(Error::PluginKilled(code)),
        Err(e) => return Err(Error::PluginWait(e)),
    };
}
