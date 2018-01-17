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
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use libc::{socketpair, ioctl, c_ulong, AF_UNIX, SOCK_SEQPACKET, FIOCLEX, EAGAIN, EINTR, EINVAL,
           ENOENT, EPERM, EDEADLK, ENOTTY, EEXIST, EBADF, EOVERFLOW, SIGCHLD};

use protobuf::ProtobufError;

use kvm::{Kvm, Vm, Vcpu, VcpuExit, IoeventAddress, NoDatamatch};
use sys_util::{EventFd, MmapError, Killable, SignalFd, SignalFdError, Poller, Pollable,
               GuestMemory, Result as SysResult, Error as SysError, register_signal_handler};

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
    CreateKvm(SysError),
    CreateMainSocket(SysError),
    CreateSignalFd(SignalFdError),
    CreateSocketPair(io::Error),
    CreateVcpu(SysError),
    CreateVcpuSocket(SysError),
    CreateVm(SysError),
    DecodeRequest(ProtobufError),
    EncodeResponse(ProtobufError),
    PluginFailed(i32),
    PluginKill(SysError),
    PluginKilled(i32),
    PluginSocketHup,
    PluginSocketPoll(SysError),
    PluginSocketRecv(SysError),
    PluginSocketSend(SysError),
    PluginSpawn(io::Error),
    PluginTimeout,
    PluginWait(SysError),
    Poll(SysError),
    SigChild {
        pid: u32,
        signo: u32,
        status: i32,
        code: i32,
    },
    SignalFd(SignalFdError),
    SpawnVcpu(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CloneEventFd(ref e) => write!(f, "failed to clone eventfd: {:?}", e),
            Error::CloneVcpuSocket(ref e) => write!(f, "failed to clone vcpu socket: {:?}", e),
            Error::CreateEventFd(ref e) => write!(f, "failed to create eventfd: {:?}", e),
            Error::CreateIrqChip(ref e) => write!(f, "failed to create kvm irqchip: {:?}", e),
            Error::CreateKvm(ref e) => write!(f, "error creating Kvm: {:?}", e),
            Error::CreateMainSocket(ref e) => {
                write!(f, "error creating main request socket: {:?}", e)
            }
            Error::CreateSignalFd(ref e) => write!(f, "failed to create signalfd: {:?}", e),
            Error::CreateSocketPair(ref e) => write!(f, "failed to create socket pair: {}", e),
            Error::CreateVcpu(ref e) => write!(f, "error creating vcpu: {:?}", e),
            Error::CreateVcpuSocket(ref e) => {
                write!(f, "error creating vcpu request socket: {:?}", e)
            }
            Error::CreateVm(ref e) => write!(f, "error creating vm: {:?}", e),
            Error::DecodeRequest(ref e) => write!(f, "failed to decode plugin request: {}", e),
            Error::EncodeResponse(ref e) => write!(f, "failed to encode plugin response: {}", e),
            Error::PluginFailed(ref e) => write!(f, "plugin exited with error: {}", e),
            Error::PluginKill(ref e) => write!(f, "error sending kill signal to plugin: {:?}", e),
            Error::PluginKilled(ref e) => write!(f, "plugin exited with signal {}", e),
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
        ProtobufError::IoError(e) => SysError::new(-e.raw_os_error().unwrap_or(EINVAL)),
        _ => SysError::new(-EINVAL),
    }
}

fn io_to_sys_err(e: io::Error) -> SysError {
    SysError::new(-e.raw_os_error().unwrap_or(EINVAL))
}

fn mmap_to_sys_err(e: MmapError) -> SysError {
    match e {
        MmapError::SystemCallFailed(e) => e,
        _ => SysError::new(-EINVAL),
    }
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
///    _ => return Err(SysError::new(-ENOENT)),
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
                    _ => Err(SysError::new(-EINVAL)),
                }
            }
            PluginObject::Memory { slot, .. } => vm.remove_device_memory(slot).and(Ok(())),
            PluginObject::IrqEvent { irq_id, evt } => vm.unregister_irqfd(&evt, irq_id),
        }
    }
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

    let vcpu_count = cfg.vcpu_count.unwrap_or(1);
    let mem = GuestMemory::new(&[]).unwrap();
    let kvm = Kvm::new().map_err(Error::CreateKvm)?;
    let mut vm = Vm::new(&kvm, mem).map_err(Error::CreateVm)?;
    vm.create_irq_chip().map_err(Error::CreateIrqChip)?;
    let mut plugin = Process::new(vcpu_count, &mut vm, &cfg.plugin.unwrap())?;

    let exit_evt = EventFd::new().map_err(Error::CreateEventFd)?;
    let kill_signaled = Arc::new(AtomicBool::new(false));
    let mut vcpu_handles = Vec::with_capacity(vcpu_count as usize);
    let vcpu_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));
    for cpu_id in 0..vcpu_count {
        let kill_signaled = kill_signaled.clone();
        let vcpu_thread_barrier = vcpu_thread_barrier.clone();
        let vcpu_exit_evt = exit_evt.try_clone().map_err(Error::CloneEventFd)?;
        let vcpu_plugin = plugin.create_vcpu(cpu_id)?;
        let vcpu = Vcpu::new(cpu_id as c_ulong, &kvm, &vm)
            .map_err(Error::CreateVcpu)?;

        vcpu_handles.push(thread::Builder::new()
                              .name(format!("crosvm_vcpu{}", cpu_id))
                              .spawn(move || {
            unsafe {
                extern "C" fn handle_signal() {}
                // Our signal handler does nothing and is trivially async signal safe.
                register_signal_handler(0, handle_signal)
                    .expect("failed to register vcpu signal handler");
            }

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

    vcpu_thread_barrier.wait();

    const EXIT: u32 = 0;
    const CHILD_SIGNAL: u32 = 1;
    const PLUGIN_BASE: u32 = 2;

    let mut sockets_to_drop = Vec::new();
    let mut poller = Poller::new(3);

    let mut res = Ok(());
    // If Some, we will exit after enough time is passed to shutdown cleanly.
    let mut dying_instant: Option<Instant> = None;
    let duration_to_die = Duration::from_millis(1000);

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

        let tokens = {
            let mut pollables = Vec::new();
            // No need to check the exit event if we are already doing cleanup.
            if dying_instant.is_none() {
                pollables.push((EXIT, &exit_evt as &Pollable));
            }
            pollables.push((CHILD_SIGNAL, &sigchld_fd as &Pollable));
            for (i, socket) in plugin.sockets().iter().enumerate() {
                pollables.push((PLUGIN_BASE + i as u32, socket as &Pollable));
            }

            let poll_res = match dying_instant {
                Some(ref inst) => {
                    poller.poll_timeout(&pollables[..], &mut (duration_to_die - inst.elapsed()))
                }
                None => poller.poll(&pollables[..]),
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
        for &token in tokens {
            match token {
                EXIT => {
                    dying_instant.get_or_insert(Instant::now());
                    let sig_res = plugin.signal_kill();
                    if res.is_ok() && sig_res.is_err() {
                        res = sig_res.map_err(Error::PluginKill);
                    }
                }
                CHILD_SIGNAL => {
                    // Print all available siginfo structs, then exit the loop.
                    loop {
                        match sigchld_fd.read() {
                            Ok(Some(siginfo)) => {
                                // If the plugin process has ended, there is no need to continue
                                // processing plugin connections, so we break early.
                                if siginfo.ssi_pid == plugin.pid() {
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
                t if t >= PLUGIN_BASE && t < PLUGIN_BASE + (plugin.sockets().len() as u32) => {
                    let socket_index = (t - PLUGIN_BASE) as usize;
                    match plugin.handle_socket(socket_index, &mut vm, &vcpu_handles) {
                        Ok(_) => {}
                        // A HUP is an expected event for a socket, so don't bother warning about
                        // it.
                        Err(Error::PluginSocketHup) => sockets_to_drop.push(socket_index),
                        // Only one connection out of potentially many is broken. Drop it, but don't
                        // start cleaning up. Because the error isn't returned, we will warn about
                        // it here.
                        Err(e) => {
                            warn!("error handling plugin socket: {}", e);
                            sockets_to_drop.push(socket_index);
                        }
                    }
                }
                _ => {}
            }
        }

        // Cleanup all of the sockets that we have determined were disconnected or suffered some
        // other error.
        plugin.drop_sockets(&mut sockets_to_drop);
        sockets_to_drop.clear();
    }

    // vcpu threads MUST see the kill signaled flag, otherwise they may re-enter the VM.
    kill_signaled.store(true, Ordering::SeqCst);
    // Depending on how we ended up here, the plugin process, or a VCPU thread waiting for requests
    // might be stuck. The `signal_kill` call will unstick all the VCPU threads by closing their
    // blocked connections.
    plugin.signal_kill().map_err(Error::PluginKill)?;
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
