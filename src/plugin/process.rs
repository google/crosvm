// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::hash_map::{Entry, HashMap, VacantEntry};
use std::env::set_var;
use std::fs::File;
use std::io::Write;
use std::mem::transmute;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

use net_util;
use net_util::Error as NetError;

use libc::{pid_t, waitpid, EINVAL, ENODATA, ENOTTY, WEXITSTATUS, WIFEXITED, WNOHANG, WTERMSIG};

use protobuf;
use protobuf::Message;

use io_jail::Minijail;
use kvm::{dirty_log_bitmap_size, Datamatch, IoeventAddress, IrqRoute, IrqSource, PicId, Vm};
use kvm_sys::{kvm_clock_data, kvm_ioapic_state, kvm_pic_state, kvm_pit_state2};
use protos::plugin::*;
use sync::Mutex;
use sys_util::{
    error, Error as SysError, EventFd, GuestAddress, Killable, MemoryMapping, Result as SysResult,
    ScmSocket, SharedMemory, SIGRTMIN,
};

use super::*;

// Wrapper types to make the kvm state structs DataInit
use data_model::DataInit;
#[derive(Copy, Clone)]
struct VmPicState(kvm_pic_state);
unsafe impl DataInit for VmPicState {}
#[derive(Copy, Clone)]
struct VmIoapicState(kvm_ioapic_state);
unsafe impl DataInit for VmIoapicState {}
#[derive(Copy, Clone)]
struct VmPitState(kvm_pit_state2);
unsafe impl DataInit for VmPitState {}
#[derive(Copy, Clone)]
struct VmClockState(kvm_clock_data);
unsafe impl DataInit for VmClockState {}

fn get_vm_state(vm: &Vm, state_set: MainRequest_StateSet) -> SysResult<Vec<u8>> {
    Ok(match state_set {
        MainRequest_StateSet::PIC0 => VmPicState(vm.get_pic_state(PicId::Primary)?)
            .as_slice()
            .to_vec(),
        MainRequest_StateSet::PIC1 => VmPicState(vm.get_pic_state(PicId::Secondary)?)
            .as_slice()
            .to_vec(),
        MainRequest_StateSet::IOAPIC => VmIoapicState(vm.get_ioapic_state()?).as_slice().to_vec(),
        MainRequest_StateSet::PIT => VmPitState(vm.get_pit_state()?).as_slice().to_vec(),
        MainRequest_StateSet::CLOCK => VmClockState(vm.get_clock()?).as_slice().to_vec(),
    })
}

fn set_vm_state(vm: &Vm, state_set: MainRequest_StateSet, state: &[u8]) -> SysResult<()> {
    match state_set {
        MainRequest_StateSet::PIC0 => vm.set_pic_state(
            PicId::Primary,
            &VmPicState::from_slice(state)
                .ok_or(SysError::new(EINVAL))?
                .0,
        ),
        MainRequest_StateSet::PIC1 => vm.set_pic_state(
            PicId::Secondary,
            &VmPicState::from_slice(state)
                .ok_or(SysError::new(EINVAL))?
                .0,
        ),
        MainRequest_StateSet::IOAPIC => vm.set_ioapic_state(
            &VmIoapicState::from_slice(state)
                .ok_or(SysError::new(EINVAL))?
                .0,
        ),
        MainRequest_StateSet::PIT => vm.set_pit_state(
            &VmPitState::from_slice(state)
                .ok_or(SysError::new(EINVAL))?
                .0,
        ),
        MainRequest_StateSet::CLOCK => vm.set_clock(
            &VmClockState::from_slice(state)
                .ok_or(SysError::new(EINVAL))?
                .0,
        ),
    }
}

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
/// A plugin process has control over a single VM and a fixed number of VCPUs via a set of pipes & unix
/// domain socket connections and a protocol defined in `protos::plugin`. The plugin process is run
/// in an unprivileged manner as a child process spawned via a path to a arbitrary executable.
pub struct Process {
    started: bool,
    plugin_pid: pid_t,
    request_sockets: Vec<UnixDatagram>,
    objects: HashMap<u32, PluginObject>,
    shared_vcpu_state: Arc<RwLock<SharedVcpuState>>,
    per_vcpu_states: Vec<Arc<Mutex<PerVcpuState>>>,

    // Resource to sent to plugin
    kill_evt: EventFd,
    vcpu_pipes: Vec<VcpuPipe>,

    // Socket Transmission
    request_buffer: Vec<u8>,
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
    pub fn new(
        cpu_count: u32,
        cmd: &Path,
        args: &[&str],
        jail: Option<Minijail>,
    ) -> Result<Process> {
        let (request_socket, child_socket) =
            new_seqpacket_pair().map_err(Error::CreateMainSocket)?;

        let mut vcpu_pipes: Vec<VcpuPipe> = Vec::with_capacity(cpu_count as usize);
        for _ in 0..cpu_count {
            vcpu_pipes.push(new_pipe_pair().map_err(Error::CreateVcpuSocket)?);
        }
        let mut per_vcpu_states: Vec<Arc<Mutex<PerVcpuState>>> =
            Vec::with_capacity(cpu_count as usize);
        // TODO(zachr): replace with `resize_default` when that stabilizes. Using a plain `resize`
        // is incorrect because each element in the `Vec` will contain a shared reference to the
        // same `PerVcpuState` instance. This happens because `resize` fills new slots using clones
        // of the instance given to `resize`.
        for _ in 0..cpu_count {
            per_vcpu_states.push(Default::default());
        }

        let plugin_pid = match jail {
            Some(jail) => {
                set_var("CROSVM_SOCKET", child_socket.as_raw_fd().to_string());
                jail.run(cmd, &[0, 1, 2, child_socket.as_raw_fd()], args)
                    .map_err(Error::PluginRunJail)?
            }
            None => Command::new(cmd)
                .args(args)
                .env("CROSVM_SOCKET", child_socket.as_raw_fd().to_string())
                .spawn()
                .map_err(Error::PluginSpawn)?
                .id() as pid_t,
        };

        Ok(Process {
            started: false,
            plugin_pid,
            request_sockets: vec![request_socket],
            objects: Default::default(),
            shared_vcpu_state: Default::default(),
            per_vcpu_states,
            kill_evt: EventFd::new().map_err(Error::CreateEventFd)?,
            vcpu_pipes,
            request_buffer: vec![0; MAX_DATAGRAM_SIZE],
            response_buffer: Vec::new(),
        })
    }

    /// Creates a VCPU plugin connection object, used by a VCPU run loop to communicate with the
    /// plugin process.
    ///
    /// While each invocation of `create_vcpu` with the given `cpu_id` will return a unique
    /// `PluginVcpu` object, the underlying resources are shared by each `PluginVcpu` resulting from
    /// the same `cpu_id`.
    pub fn create_vcpu(&self, cpu_id: u32) -> Result<PluginVcpu> {
        let vcpu_pipe_read = self.vcpu_pipes[cpu_id as usize]
            .crosvm_read
            .try_clone()
            .map_err(Error::CloneVcpuPipe)?;
        let vcpu_pipe_write = self.vcpu_pipes[cpu_id as usize]
            .crosvm_write
            .try_clone()
            .map_err(Error::CloneVcpuPipe)?;
        Ok(PluginVcpu::new(
            self.shared_vcpu_state.clone(),
            self.per_vcpu_states[cpu_id as usize].clone(),
            vcpu_pipe_read,
            vcpu_pipe_write,
        ))
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
        // Normally we'd get any blocked recv() calls in the VCPU threads
        // to unblock by calling shutdown().  However, we're using pipes
        // (for improved performance), and pipes don't have shutdown so
        // instead we'll write a shutdown message to ourselves using the
        // the writable side of the pipe (normally used by the plugin).
        for pipe in self.vcpu_pipes.iter_mut() {
            let mut shutdown_request = VcpuRequest::new();
            shutdown_request.set_shutdown(VcpuRequest_Shutdown::new());
            let mut buffer = Vec::new();
            shutdown_request
                .write_to_vec(&mut buffer)
                .map_err(proto_to_sys_err)?;
            pipe.plugin_write
                .write(&buffer[..])
                .map_err(io_to_sys_err)?;
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
                    match unsafe { WEXITSTATUS(status) } {
                        // Trivially safe
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

    fn handle_io_event(
        entry: VacantEntry<u32, PluginObject>,
        vm: &mut Vm,
        io_event: &MainRequest_Create_IoEvent,
    ) -> SysResult<RawFd> {
        let evt = EventFd::new()?;
        let addr = match io_event.space {
            AddressSpace::IOPORT => IoeventAddress::Pio(io_event.address),
            AddressSpace::MMIO => IoeventAddress::Mmio(io_event.address),
        };
        match io_event.length {
            0 => vm.register_ioevent(&evt, addr, Datamatch::AnyLength)?,
            1 => vm.register_ioevent(&evt, addr, Datamatch::U8(Some(io_event.datamatch as u8)))?,
            2 => {
                vm.register_ioevent(&evt, addr, Datamatch::U16(Some(io_event.datamatch as u16)))?
            }
            4 => {
                vm.register_ioevent(&evt, addr, Datamatch::U32(Some(io_event.datamatch as u32)))?
            }
            8 => {
                vm.register_ioevent(&evt, addr, Datamatch::U64(Some(io_event.datamatch as u64)))?
            }
            _ => return Err(SysError::new(EINVAL)),
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

    fn handle_memory(
        entry: VacantEntry<u32, PluginObject>,
        vm: &mut Vm,
        memfd: File,
        offset: u64,
        start: u64,
        length: u64,
        read_only: bool,
        dirty_log: bool,
    ) -> SysResult<()> {
        let shm = SharedMemory::from_raw_fd(memfd)?;
        // Checking the seals ensures the plugin process won't shrink the mmapped file, causing us
        // to SIGBUS in the future.
        let seals = shm.get_seals()?;
        if !seals.shrink_seal() {
            return Err(SysError::new(EPERM));
        }
        // Check to make sure we don't mmap areas beyond the end of the memfd.
        match length.checked_add(offset) {
            Some(end) if end > shm.size() => return Err(SysError::new(EINVAL)),
            None => return Err(SysError::new(EOVERFLOW)),
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
            Err(_) => Err(SysError::new(EDEADLK)),
        }
    }

    fn handle_set_irq_routing(
        vm: &mut Vm,
        irq_routing: &MainRequest_SetIrqRouting,
    ) -> SysResult<()> {
        let mut routes = Vec::with_capacity(irq_routing.routes.len());
        for route in &irq_routing.routes {
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
                    return Err(SysError::new(EINVAL));
                },
            });
        }
        vm.set_gsi_routing(&routes[..])
    }

    fn handle_pause_vcpus(&self, vcpu_handles: &[JoinHandle<()>], cpu_mask: u64, user_data: u64) {
        for (cpu_id, (handle, per_cpu_state)) in
            vcpu_handles.iter().zip(&self.per_vcpu_states).enumerate()
        {
            if cpu_mask & (1 << cpu_id) != 0 {
                per_cpu_state.lock().request_pause(user_data);
                if let Err(e) = handle.kill(SIGRTMIN() + 0) {
                    error!("failed to interrupt vcpu {}: {}", cpu_id, e);
                }
            }
        }
    }

    fn handle_get_net_config(
        tap: &net_util::Tap,
        config: &mut MainResponse_GetNetConfig,
    ) -> SysResult<()> {
        // Log any NetError so that the cause can be found later, but extract and return the
        // underlying errno for the client as well.
        fn map_net_error(s: &str, e: NetError) -> SysError {
            error!("failed to get {}: {}", s, e);
            e.sys_error()
        }

        let ip_addr = tap.ip_addr().map_err(|e| map_net_error("IP address", e))?;
        config.set_host_ipv4_address(u32::from(ip_addr));

        let netmask = tap.netmask().map_err(|e| map_net_error("netmask", e))?;
        config.set_netmask(u32::from(netmask));

        let result_mac_addr = config.mut_host_mac_address();
        let mac_addr_octets = tap
            .mac_address()
            .map_err(|e| map_net_error("mac address", e))?
            .octets();
        result_mac_addr.resize(mac_addr_octets.len(), 0);
        result_mac_addr.clone_from_slice(&mac_addr_octets);

        Ok(())
    }

    /// Handles a request on a readable socket identified by its index in the slice returned by
    /// `sockets`.
    ///
    /// The `vm` is used to service request that affect the VM. The `vcpu_handles` slice is used to
    /// interrupt a VCPU thread currently running in the VM if the socket request it.
    pub fn handle_socket(
        &mut self,
        index: usize,
        kvm: &Kvm,
        vm: &mut Vm,
        vcpu_handles: &[JoinHandle<()>],
        taps: &[Tap],
    ) -> Result<()> {
        let (msg_size, request_file) = self.request_sockets[index]
            .recv_with_fd(&mut self.request_buffer)
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
                        match request_file {
                            Some(memfd) => Self::handle_memory(
                                entry,
                                vm,
                                memfd,
                                memory.offset,
                                memory.start,
                                memory.length,
                                memory.read_only,
                                memory.dirty_log,
                            ),
                            None => Err(SysError::new(EBADF)),
                        }
                    } else if create.has_irq_event() {
                        let irq_event = create.get_irq_event();
                        match (EventFd::new(), EventFd::new()) {
                            (Ok(evt), Ok(resample_evt)) => match vm.register_irqfd_resample(
                                &evt,
                                &resample_evt,
                                irq_event.irq_id,
                            ) {
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
                            },
                            (Err(e), _) | (_, Err(e)) => Err(e),
                        }
                    } else {
                        Err(SysError::new(ENOTTY))
                    }
                }
                Entry::Occupied(_) => Err(SysError::new(EEXIST)),
            }
        } else if request.has_destroy() {
            response.mut_destroy();
            match self.objects.entry(request.get_destroy().id) {
                Entry::Occupied(entry) => entry.remove().destroy(vm),
                Entry::Vacant(_) => Err(SysError::new(ENOENT)),
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
        } else if request.has_check_extension() {
            // Safe because the Cap enum is not read by the check_extension method. In that method,
            // cap is cast back to an integer and fed to an ioctl. If the extension name is actually
            // invalid, the kernel will safely reject the extension under the assumption that the
            // capability is legitimately unsupported.
            let cap = unsafe { transmute(request.get_check_extension().extension) };
            response.mut_check_extension().has_extension = vm.check_extension(cap);
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
        } else if request.has_get_state() {
            let response_state = response.mut_get_state();
            match get_vm_state(vm, request.get_get_state().set) {
                Ok(state) => {
                    response_state.state = state;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else if request.has_set_state() {
            response.mut_set_state();
            let set_state = request.get_set_state();
            set_vm_state(vm, set_state.set, set_state.get_state())
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
            for pipe in self.vcpu_pipes.iter() {
                response_fds.push(pipe.plugin_write.as_raw_fd());
                response_fds.push(pipe.plugin_read.as_raw_fd());
            }
            Ok(())
        } else if request.has_start() {
            response.mut_start();
            if self.started {
                Err(SysError::new(EINVAL))
            } else {
                self.started = true;
                Ok(())
            }
        } else if request.has_get_net_config() {
            match taps.first() {
                Some(tap) => {
                    match Self::handle_get_net_config(tap, response.mut_get_net_config()) {
                        Ok(_) => {
                            response_fds.push(tap.as_raw_fd());
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
                None => Err(SysError::new(ENODATA)),
            }
        } else if request.has_dirty_log() {
            let dirty_log_response = response.mut_dirty_log();
            match self.objects.get(&request.get_dirty_log().id) {
                Some(&PluginObject::Memory { slot, length }) => {
                    let dirty_log = dirty_log_response.mut_bitmap();
                    dirty_log.resize(dirty_log_bitmap_size(length), 0);
                    vm.get_dirty_log(slot, &mut dirty_log[..])
                }
                _ => Err(SysError::new(ENOENT)),
            }
        } else if request.has_get_supported_cpuid() {
            let cpuid_response = &mut response.mut_get_supported_cpuid().entries;
            match kvm.get_supported_cpuid() {
                Ok(mut cpuid) => {
                    for entry in cpuid.mut_entries_slice() {
                        cpuid_response.push(cpuid_kvm_to_proto(entry));
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else if request.has_get_emulated_cpuid() {
            let cpuid_response = &mut response.mut_get_emulated_cpuid().entries;
            match kvm.get_emulated_cpuid() {
                Ok(mut cpuid) => {
                    for entry in cpuid.mut_entries_slice() {
                        cpuid_response.push(cpuid_kvm_to_proto(entry));
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else if request.has_get_msr_index_list() {
            let msr_list_response = &mut response.mut_get_msr_index_list().indices;
            match kvm.get_msr_index_list() {
                Ok(indices) => {
                    for entry in indices {
                        msr_list_response.push(entry);
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else {
            Err(SysError::new(ENOTTY))
        };

        if let Err(e) = res {
            response.errno = e.errno();
        }

        self.response_buffer.clear();
        response
            .write_to_vec(&mut self.response_buffer)
            .map_err(Error::EncodeResponse)?;
        assert_ne!(self.response_buffer.len(), 0);
        self.request_sockets[index]
            .send_with_fds(&self.response_buffer[..], &response_fds)
            .map_err(Error::PluginSocketSend)?;

        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Ignore the result because there is nothing we can do about it.
        if let Err(e) = self.signal_kill() {
            error!("failed to signal kill event for plugin: {}", e);
        }
    }
}
