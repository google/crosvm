// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::hash_map::{HashMap, Entry, VacantEntry};
use std::env::set_var;
use std::fs::File;
use std::net::Shutdown;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

use libc::{waitpid, pid_t, EINVAL, WNOHANG, WIFEXITED, WEXITSTATUS, WTERMSIG};

use protobuf;
use protobuf::Message;

use io_jail::Minijail;
use kvm::{Vm, IoeventAddress, NoDatamatch, IrqSource, IrqRoute, dirty_log_bitmap_size};
use sys_util::{EventFd, MemoryMapping, Killable, Scm, Poller, Pollable, SharedMemory,
               GuestAddress, Result as SysResult, Error as SysError};
use plugin_proto::*;

use super::*;

/// The status of a process, either that it is running, or that it exited under some condition.
pub enum ProcessStatus {
    /// The process is running and therefore has no information about its result.
    Running,
    /// The process has exited with a successful code.
    Success,
    /// The process failed with the given exit code.
    Fail(i32),
    /// The process was terminated with the given signal code.
    Signal(i32),
}

/// Creates, owns, and handles messages from a plugin process.
///
/// A plugin process has control over a single VM and a fixed number of VCPUs via a set of unix
/// domain socket connections and a protocol defined in `plugin_proto`. The plugin process is run in
/// an unprivileged manner as a child process spawned via a path to a arbitrary executable.
pub struct Process {
    started: bool,
    plugin_pid: pid_t,
    request_sockets: Vec<UnixDatagram>,
    objects: HashMap<u32, PluginObject>,
    shared_vcpu_state: Arc<RwLock<SharedVcpuState>>,
    per_vcpu_states: Vec<Arc<Mutex<PerVcpuState>>>,

    // Resource to sent to plugin
    kill_evt: EventFd,
    vcpu_sockets: Vec<(UnixDatagram, UnixDatagram)>,

    // Socket Transmission
    scm: Scm,
    request_buffer: Vec<u8>,
    datagram_files: Vec<File>,
    response_buffer: Vec<u8>,
}

impl Process {
    /// Creates a new plugin process for the given number of vcpus and VM.
    ///
    /// This will immediately spawn the plugin process and wait for the child to signal that it is
    /// ready to start. This call may block indefinitely.
    ///
    /// Set the `jail` argument to spawn the plugin process within the preconfigured jail.
    /// Due to an API limitation in libminijail necessitating that this function set an environment
    /// variable, this function is not thread-safe.
    pub fn new(cpu_count: u32,
               vm: &mut Vm,
               cmd: &Path,
               args: &[&str],
               jail: Option<Minijail>)
               -> Result<Process> {
        let (request_socket, child_socket) = new_seqpacket_pair().map_err(Error::CreateMainSocket)?;

        let mut vcpu_sockets: Vec<(UnixDatagram, UnixDatagram)> = Vec::with_capacity(cpu_count as
                                                                                     usize);
        for _ in 0..cpu_count {
            vcpu_sockets.push(new_seqpacket_pair().map_err(Error::CreateVcpuSocket)?);
        }
        let mut per_vcpu_states: Vec<Arc<Mutex<PerVcpuState>>> = Vec::new();
        per_vcpu_states.resize(cpu_count as usize, Default::default());

        let plugin_pid = match jail {
            Some(jail) => {
                set_var("CROSVM_SOCKET", child_socket.as_raw_fd().to_string());
                jail.run(cmd, &[0, 1, 2, child_socket.as_raw_fd()], args)
                    .map_err(Error::PluginRunJail)?
            }
            None => {
                Command::new(cmd)
                    .args(args)
                    .env("CROSVM_SOCKET", child_socket.as_raw_fd().to_string())
                    .spawn()
                    .map_err(Error::PluginSpawn)?
                    .id() as pid_t
            }
        };

        // Very important to drop the child socket so that the pair will properly hang up if the
        // plugin process exits or closes its end.
        drop(child_socket);

        let request_sockets = vec![request_socket];

        let mut plugin = Process {
            started: false,
            plugin_pid,
            request_sockets,
            objects: Default::default(),
            shared_vcpu_state: Default::default(),
            per_vcpu_states,
            kill_evt: EventFd::new().map_err(Error::CreateEventFd)?,
            vcpu_sockets,
            scm: Scm::new(1),
            request_buffer: vec![0; MAX_DATAGRAM_SIZE],
            datagram_files: Vec::new(),
            response_buffer: Vec::new(),
        };

        plugin.run_until_started(vm)?;

        Ok(plugin)
    }


    fn run_until_started(&mut self, vm: &mut Vm) -> Result<()> {
        let mut sockets_to_drop = Vec::new();
        let mut poller = Poller::new(1);
        while !self.started {
            if self.request_sockets.is_empty() {
                break;
            }

            let tokens = {
                let mut pollables = Vec::with_capacity(self.objects.len());
                for (i, socket) in self.request_sockets.iter().enumerate() {
                    pollables.push((i as u32, socket as &Pollable));
                }
                poller
                    .poll(&pollables[..])
                    .map_err(Error::PluginSocketPoll)?
            };

            for &token in tokens {
                match self.handle_socket(token as usize, vm, &[]) {
                    Ok(_) => {}
                    Err(Error::PluginSocketHup) => sockets_to_drop.push(token as usize),
                    r => return r,
                }
            }

            self.drop_sockets(&mut sockets_to_drop);
            sockets_to_drop.clear();
        }

        Ok(())
    }

    /// Creates a VCPU plugin connection object, used by a VCPU run loop to communicate with the
    /// plugin process.
    ///
    /// While each invocation of `create_vcpu` with the given `cpu_id` will return a unique
    /// `PluginVcpu` object, the underlying resources are shared by each `PluginVcpu` resulting from
    /// the same `cpu_id`.
    pub fn create_vcpu(&self, cpu_id: u32) -> Result<PluginVcpu> {
        let vcpu_socket = self.vcpu_sockets[cpu_id as usize]
            .0
            .try_clone()
            .map_err(Error::CloneVcpuSocket)?;
        Ok(PluginVcpu::new(self.shared_vcpu_state.clone(),
                           self.per_vcpu_states[cpu_id as usize].clone(),
                           vcpu_socket))
    }

    /// Returns if the plugin process indicated the VM was ready to start.
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// Returns the process ID of the plugin process.
    pub fn pid(&self) -> pid_t {
        self.plugin_pid
    }

    /// Returns a slice of each socket that should be polled.
    ///
    /// If any socket in this slice becomes readable, `handle_socket` should be called with the
    /// index of that socket. If any socket becomes closed, its index should be passed to
    /// `drop_sockets`.
    pub fn sockets(&self) -> &[UnixDatagram] {
        &self.request_sockets
    }

    /// Drops the each socket identified by its index in the slice returned by `sockets`.
    ///
    /// The given `socket_idxs` slice will be modified in an arbitrary way for efficient removal of
    /// the sockets from internal data structures.
    pub fn drop_sockets(&mut self, socket_idxs: &mut [usize]) {
        // Takes a mutable slice so that the indices can be sorted for efficient removal in
        // request_sockets..
        socket_idxs.sort_unstable_by(|a, b| b.cmp(a));
        let old_len = self.request_sockets.len();
        for &socket_index in socket_idxs.iter() {
            // swap_remove changes the index of the last element, but we already know that one
            // doesn't need to be removed because we are removing sockets in descending order thanks
            // to the above sort.
            self.request_sockets.swap_remove(socket_index);
        }
        assert_eq!(old_len - socket_idxs.len(), self.request_sockets.len());
    }

    /// Gently requests that the plugin process exit cleanly, and ends handling of all VCPU
    /// connections.
    ///
    /// The plugin process can ignore the given signal, and so some timeout should be used before
    /// forcefully terminating the process.
    ///
    /// Any blocked VCPU connections will get interrupted so that the VCPU threads can exit cleanly.
    /// Any subsequent attempt to use the VCPU connections will fail.
    pub fn signal_kill(&mut self) -> SysResult<()> {
        self.kill_evt.write(1)?;
        // By shutting down our half of the VCPU sockets, any blocked calls in the VCPU threads will
        // unblock, allowing them to exit cleanly.
        for sock in self.vcpu_sockets.iter() {
            sock.0.shutdown(Shutdown::Both)?;
        }
        Ok(())
    }

    /// Waits without blocking for the plugin process to exit and returns the status.
    pub fn try_wait(&mut self) -> SysResult<ProcessStatus> {
        let mut status = 0;
        // Safe because waitpid is given a valid pointer of correct size and mutability, and the
        // return value is checked.
        let ret = unsafe { waitpid(self.plugin_pid, &mut status, WNOHANG) };
        match ret {
            -1 => Err(SysError::last()),
            0 => Ok(ProcessStatus::Running),
            _ => {
                // Trivially safe
                if unsafe { WIFEXITED(status) } {
                    match unsafe { WEXITSTATUS(status) } { // Trivially safe
                        0 => Ok(ProcessStatus::Success),
                        code => Ok(ProcessStatus::Fail(code)),
                    }
                } else {
                    // Plugin terminated but has no exit status, so it must have been signaled.
                    Ok(ProcessStatus::Signal(unsafe { WTERMSIG(status) })) // Trivially safe
                }
            }
        }
    }

    fn handle_io_event(entry: VacantEntry<u32, PluginObject>,
                       vm: &mut Vm,
                       io_event: &MainRequest_Create_IoEvent)
                       -> SysResult<RawFd> {
        let evt = EventFd::new()?;
        let addr = match io_event.space {
            AddressSpace::IOPORT => IoeventAddress::Pio(io_event.address),
            AddressSpace::MMIO => IoeventAddress::Mmio(io_event.address),
        };
        match io_event.length {
            0 => vm.register_ioevent(&evt, addr, NoDatamatch)?,
            1 => vm.register_ioevent(&evt, addr, io_event.datamatch as u8)?,
            2 => vm.register_ioevent(&evt, addr, io_event.datamatch as u16)?,
            4 => vm.register_ioevent(&evt, addr, io_event.datamatch as u32)?,
            8 => vm.register_ioevent(&evt, addr, io_event.datamatch as u64)?,
            _ => return Err(SysError::new(-EINVAL)),
        };

        let fd = evt.as_raw_fd();
        entry.insert(PluginObject::IoEvent {
                         evt,
                         addr,
                         length: io_event.length,
                         datamatch: io_event.datamatch,
                     });
        Ok(fd)
    }


    fn handle_memory(entry: VacantEntry<u32, PluginObject>,
                     vm: &mut Vm,
                     memfd: File,
                     offset: u64,
                     start: u64,
                     length: u64,
                     read_only: bool,
                     dirty_log: bool)
                     -> SysResult<()> {
        let shm = SharedMemory::from_raw_fd(memfd)?;
        // Checking the seals ensures the plugin process won't shrink the mmapped file, causing us
        // to SIGBUS in the future.
        let seals = shm.get_seals()?;
        if !seals.shrink_seal() {
            return Err(SysError::new(-EPERM));
        }
        // Check to make sure we don't mmap areas beyond the end of the memfd.
        match length.checked_add(offset) {
            Some(end) if end > shm.size() => return Err(SysError::new(-EINVAL)),
            None => return Err(SysError::new(-EOVERFLOW)),
            _ => {}
        }
        let mem = MemoryMapping::from_fd_offset(&shm, length as usize, offset as usize)
            .map_err(mmap_to_sys_err)?;
        let slot = vm.add_device_memory(GuestAddress(start), mem, read_only, dirty_log)?;
        entry.insert(PluginObject::Memory {
                         slot,
                         length: length as usize,
                     });
        Ok(())
    }

    fn handle_reserve_range(&mut self, reserve_range: &MainRequest_ReserveRange) -> SysResult<()> {
        match self.shared_vcpu_state.write() {
            Ok(mut lock) => {
                let space = match reserve_range.space {
                    AddressSpace::IOPORT => IoSpace::Ioport,
                    AddressSpace::MMIO => IoSpace::Mmio,
                };
                match reserve_range.length {
                    0 => lock.unreserve_range(space, reserve_range.start),
                    _ => lock.reserve_range(space, reserve_range.start, reserve_range.length),
                }
            }
            Err(_) => Err(SysError::new(-EDEADLK)),
        }
    }

    fn handle_set_irq_routing(vm: &mut Vm,
                              irq_routing: &MainRequest_SetIrqRouting)
                              -> SysResult<()> {
        let mut routes = Vec::with_capacity(irq_routing.routes.len());
        for route in irq_routing.routes.iter() {
            routes.push(IrqRoute {
                            gsi: route.irq_id,
                            source: if route.has_irqchip() {
                                let irqchip = route.get_irqchip();
                                IrqSource::Irqchip {
                                    chip: irqchip.irqchip,
                                    pin: irqchip.pin,
                                }
                            } else if route.has_msi() {
                let msi = route.get_msi();
                IrqSource::Msi {
                    address: msi.address,
                    data: msi.data,
                }
            } else {
                // Because route is a oneof field in the proto definition, this should
                // only happen if a new variant gets added without updating this chained
                // if block.
                return Err(SysError::new(-EINVAL));
            },
                        });
        }
        vm.set_gsi_routing(&routes[..])
    }

    fn handle_pause_vcpus(&self, vcpu_handles: &[JoinHandle<()>], cpu_mask: u64, user_data: u64) {
        for (cpu_id, (handle, per_cpu_state)) in
            vcpu_handles
                .iter()
                .zip(self.per_vcpu_states.iter())
                .enumerate() {
            if cpu_mask & (1 << cpu_id) != 0 {
                per_cpu_state.lock().unwrap().request_pause(user_data);
                if let Err(e) = handle.kill(0) {
                    error!("failed to interrupt vcpu {}: {:?}", cpu_id, e);
                }
            }
        }
    }

    /// Handles a request on a readable socket identified by its index in the slice returned by
    /// `sockets`.
    ///
    /// The `vm` is used to service request that affect the VM. The `vcpu_handles` slice is used to
    /// interrupt a VCPU thread currently running in the VM if the socket request it.
    pub fn handle_socket(&mut self,
                         index: usize,
                         vm: &mut Vm,
                         vcpu_handles: &[JoinHandle<()>])
                         -> Result<()> {
        let msg_size = self.scm
            .recv(&self.request_sockets[index],
                  &mut [&mut self.request_buffer],
                  &mut self.datagram_files)
            .map_err(Error::PluginSocketRecv)?;

        if msg_size == 0 {
            return Err(Error::PluginSocketHup);
        }

        let request = protobuf::parse_from_bytes::<MainRequest>(&self.request_buffer[..msg_size])
            .map_err(Error::DecodeRequest)?;

        let mut response_files = Vec::new();
        let mut response_fds = Vec::new();
        let mut response = MainResponse::new();
        let res = if request.has_create() {
            response.mut_create();
            let create = request.get_create();
            match self.objects.entry(create.id) {
                Entry::Vacant(entry) => {
                    if create.has_io_event() {
                        match Self::handle_io_event(entry, vm, create.get_io_event()) {
                            Ok(fd) => {
                                response_fds.push(fd);
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }
                    } else if create.has_memory() {
                        let memory = create.get_memory();
                        match self.datagram_files.pop() {
                            Some(memfd) => {
                                Self::handle_memory(entry,
                                                    vm,
                                                    memfd,
                                                    memory.offset,
                                                    memory.start,
                                                    memory.length,
                                                    memory.read_only,
                                                    memory.dirty_log)
                            }
                            None => Err(SysError::new(-EBADF)),
                        }
                    } else if create.has_irq_event() {
                        let irq_event = create.get_irq_event();
                        match (EventFd::new(), EventFd::new()) {
                            (Ok(evt), Ok(resample_evt)) => {
                                match vm.register_irqfd_resample(&evt,
                                                                 &resample_evt,
                                                                 irq_event.irq_id) {
                                    Ok(()) => {
                                        response_fds.push(evt.as_raw_fd());
                                        response_fds.push(resample_evt.as_raw_fd());
                                        response_files.push(downcast_file(resample_evt));
                                        entry.insert(PluginObject::IrqEvent {
                                            irq_id: irq_event.irq_id,
                                            evt,
                                        });
                                        Ok(())
                                    }
                                    Err(e) => Err(e),
                                }
                            }
                            (Err(e), _) | (_, Err(e)) => Err(e),
                        }
                    } else {
                        Err(SysError::new(-ENOTTY))
                    }
                }
                Entry::Occupied(_) => Err(SysError::new(-EEXIST)),
            }
        } else if request.has_destroy() {
            response.mut_destroy();
            match self.objects.entry(request.get_destroy().id) {
                Entry::Occupied(entry) => entry.remove().destroy(vm),
                Entry::Vacant(_) => Err(SysError::new(-ENOENT)),
            }
        } else if request.has_new_connection() {
            response.mut_new_connection();
            match new_seqpacket_pair() {
                Ok((request_socket, child_socket)) => {
                    self.request_sockets.push(request_socket);
                    response_fds.push(child_socket.as_raw_fd());
                    response_files.push(downcast_file(child_socket));
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else if request.has_get_shutdown_eventfd() {
            response.mut_get_shutdown_eventfd();
            response_fds.push(self.kill_evt.as_raw_fd());
            Ok(())
        } else if request.has_reserve_range() {
            response.mut_reserve_range();
            self.handle_reserve_range(request.get_reserve_range())
        } else if request.has_set_irq() {
            response.mut_set_irq();
            let irq = request.get_set_irq();
            vm.set_irq_line(irq.irq_id, irq.active)
        } else if request.has_set_irq_routing() {
            response.mut_set_irq_routing();
            Self::handle_set_irq_routing(vm, request.get_set_irq_routing())
        } else if request.has_set_identity_map_addr() {
            response.mut_set_identity_map_addr();
            let addr = request.get_set_identity_map_addr().address;
            vm.set_identity_map_addr(GuestAddress(addr as u64))
        } else if request.has_pause_vcpus() {
            response.mut_pause_vcpus();
            let pause_vcpus = request.get_pause_vcpus();
            self.handle_pause_vcpus(vcpu_handles, pause_vcpus.cpu_mask, pause_vcpus.user);
            Ok(())
        } else if request.has_get_vcpus() {
            response.mut_get_vcpus();
            response_fds.extend(self.vcpu_sockets.iter().map(|s| s.1.as_raw_fd()));
            Ok(())
        } else if request.has_start() {
            response.mut_start();
            if self.started {
                Err(SysError::new(-EINVAL))
            } else {
                self.started = true;
                Ok(())
            }
        } else if request.has_dirty_log() {
            let dirty_log_response = response.mut_dirty_log();
            match self.objects.get(&request.get_dirty_log().id) {
                Some(&PluginObject::Memory { slot, length }) => {
                    let dirty_log = dirty_log_response.mut_bitmap();
                    dirty_log.resize(dirty_log_bitmap_size(length), 0);
                    vm.get_dirty_log(slot, &mut dirty_log[..])
                }
                _ => Err(SysError::new(-ENOENT)),
            }
        } else {
            Err(SysError::new(-ENOTTY))
        };

        if let Err(e) = res {
            response.errno = e.errno();
        }

        self.datagram_files.clear();
        self.response_buffer.clear();
        response
            .write_to_vec(&mut self.response_buffer)
            .map_err(Error::EncodeResponse)?;
        assert_ne!(self.response_buffer.len(), 0);
        self.scm
            .send(&self.request_sockets[index],
                  &[&self.response_buffer[..]],
                  &response_fds)
            .map_err(Error::PluginSocketSend)?;

        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Ignore the result because there is nothing we can do about it.
        if let Err(e) = self.signal_kill() {
            error!("failed to singal kill event for plugin: {:?}", e);
        }
    }
}
