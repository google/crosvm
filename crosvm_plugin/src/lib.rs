// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_os = "android", target_os = "linux"))]
#![cfg(target_arch = "x86_64")]
#![allow(non_camel_case_types)]

//! This module implements the dynamically loaded client library API used by a crosvm plugin,
//! defined in `crosvm.h`. It implements the client half of the plugin protocol, which is defined in
//! the `protos::plugin` module.
//!
//! To implement the `crosvm.h` C API, each function and struct definition is repeated here, with
//! concrete definitions for each struct. Most functions are thin shims to the underlying object
//! oriented Rust implementation method. Most methods require a request over the crosvm connection,
//! which is done by creating a `MainRequest` or `VcpuRequest` protobuf and sending it over the
//! connection's socket. Then, that socket is read for a `MainResponse` or `VcpuResponse`, which is
//! translated to the appropriate return type for the C API.

use std::env;
use std::fs::File;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use std::mem::size_of;
use std::mem::swap;
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixDatagram;
use std::ptr;
use std::ptr::null_mut;
use std::result;
use std::slice;
use std::slice::from_raw_parts;
use std::slice::from_raw_parts_mut;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use base::ScmSocket;
use kvm::dirty_log_bitmap_size;
use kvm_sys::kvm_clock_data;
use kvm_sys::kvm_cpuid_entry2;
use kvm_sys::kvm_debugregs;
use kvm_sys::kvm_fpu;
use kvm_sys::kvm_ioapic_state;
use kvm_sys::kvm_lapic_state;
use kvm_sys::kvm_mp_state;
use kvm_sys::kvm_msr_entry;
use kvm_sys::kvm_pic_state;
use kvm_sys::kvm_pit_state2;
use kvm_sys::kvm_regs;
use kvm_sys::kvm_sregs;
use kvm_sys::kvm_vcpu_events;
use kvm_sys::kvm_xcrs;
use libc::E2BIG;
use libc::EINVAL;
use libc::ENOENT;
use libc::ENOTCONN;
use libc::EPROTO;
use protobuf::Enum;
use protobuf::Message;
use protos::plugin::*;

#[cfg(feature = "stats")]
mod stats;

// Needs to be large enough to receive all the VCPU sockets.
const MAX_DATAGRAM_FD: usize = 32;
// Needs to be large enough for a sizable dirty log.
const MAX_DATAGRAM_SIZE: usize = 0x40000;

const CROSVM_IRQ_ROUTE_IRQCHIP: u32 = 0;
const CROSVM_IRQ_ROUTE_MSI: u32 = 1;

const CROSVM_VCPU_EVENT_KIND_INIT: u32 = 0;
const CROSVM_VCPU_EVENT_KIND_IO_ACCESS: u32 = 1;
const CROSVM_VCPU_EVENT_KIND_PAUSED: u32 = 2;
const CROSVM_VCPU_EVENT_KIND_HYPERV_HCALL: u32 = 3;
const CROSVM_VCPU_EVENT_KIND_HYPERV_SYNIC: u32 = 4;

pub const CROSVM_GPU_SERVER_FD_ENV: &str = "CROSVM_GPU_SERVER_FD";
pub const CROSVM_SOCKET_ENV: &str = "CROSVM_SOCKET";
#[cfg(feature = "stats")]
pub const CROSVM_STATS_ENV: &str = "CROSVM_STATS";

#[repr(C)]
#[derive(Copy, Clone)]
pub struct crosvm_net_config {
    tap_fd: c_int,
    host_ipv4_address: u32,
    netmask: u32,
    host_mac_address: [u8; 6],
    _reserved: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct anon_irqchip {
    irqchip: u32,
    pin: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct anon_msi {
    address: u64,
    data: u32,
}

#[repr(C)]
pub union anon_route {
    irqchip: anon_irqchip,
    msi: anon_msi,
    reserved: [u8; 16],
}

#[repr(C)]
pub struct crosvm_irq_route {
    irq_id: u32,
    kind: u32,
    route: anon_route,
}

const CROSVM_MAX_HINT_COUNT: u32 = 1;
const CROSVM_MAX_HINT_DETAIL_COUNT: u32 = 32;
const CROSVM_HINT_ON_WRITE: u16 = 1;

#[repr(C)]
pub struct crosvm_hint {
    hint_version: u32,
    reserved: u32,
    address_space: u32,
    address_flags: u16,
    details_count: u16,
    address: u64,
    details: *const crosvm_hint_detail,
}

#[repr(C)]
pub struct crosvm_hint_detail {
    match_rax: bool,
    match_rbx: bool,
    match_rcx: bool,
    match_rdx: bool,
    reserved1: [u8; 4],
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    send_sregs: bool,
    send_debugregs: bool,
    reserved2: [u8; 6],
}

fn proto_error_to_int(e: protobuf::Error) -> c_int {
    std::io::Error::from(e).raw_os_error().unwrap_or(EINVAL)
}

fn fd_cast<F: FromRawFd>(f: File) -> F {
    // Safe because we are transferring unique ownership.
    unsafe { F::from_raw_fd(f.into_raw_fd()) }
}

#[derive(Default)]
struct IdAllocator(AtomicUsize);

impl IdAllocator {
    fn alloc(&self) -> u32 {
        self.0.fetch_add(1, Ordering::Relaxed) as u32
    }

    fn free(&self, id: u32) {
        let _ = self.0.compare_exchange(
            id as usize + 1,
            id as usize,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Stat {
    IoEvent,
    MemoryGetDirtyLog,
    IrqEventGetFd,
    IrqEventGetResampleFd,
    Connect,
    DestroyConnection,
    GetShutdownEvent,
    CheckExtentsion,
    EnableVmCapability,
    EnableVcpuCapability,
    GetSupportedCpuid,
    GetEmulatedCpuid,
    GetHypervCpuid,
    GetMsrIndexList,
    NetGetConfig,
    ReserveRange,
    ReserveAsyncWriteRange,
    SetIrq,
    SetIrqRouting,
    GetPicState,
    SetPicState,
    GetIoapicState,
    SetIoapicState,
    GetPitState,
    SetPitState,
    GetClock,
    SetClock,
    SetIdentityMapAddr,
    PauseVcpus,
    Start,
    GetVcpu,
    VcpuWait,
    VcpuResume,
    VcpuGetRegs,
    VcpuSetRegs,
    VcpuGetSregs,
    VcpuSetSregs,
    GetFpu,
    SetFpu,
    GetDebugRegs,
    SetDebugRegs,
    GetXCRegs,
    SetXCRegs,
    VcpuGetMsrs,
    VcpuSetMsrs,
    VcpuSetCpuid,
    VcpuGetLapicState,
    VcpuSetLapicState,
    VcpuGetMpState,
    VcpuSetMpState,
    VcpuGetVcpuEvents,
    VcpuSetVcpuEvents,
    NewConnection,
    SetHypercallHint,

    Count,
}

#[cfg(feature = "stats")]
fn record(a: Stat) -> stats::StatUpdater {
    unsafe { stats::STATS.record(a) }
}

#[cfg(not(feature = "stats"))]
fn record(_a: Stat) -> u32 {
    0
}

#[cfg(feature = "stats")]
fn printstats() {
    // Unsafe due to racy access - OK for stats
    if std::env::var(CROSVM_STATS_ENV).is_ok() {
        unsafe {
            stats::STATS.print();
        }
    }
}

#[cfg(not(feature = "stats"))]
fn printstats() {}

pub struct crosvm {
    id_allocator: Arc<IdAllocator>,
    socket: UnixDatagram,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    vcpus: Arc<[crosvm_vcpu]>,
}

impl crosvm {
    fn from_connection(socket: UnixDatagram) -> result::Result<crosvm, c_int> {
        let mut crosvm = crosvm {
            id_allocator: Default::default(),
            socket,
            request_buffer: Vec::new(),
            response_buffer: vec![0; MAX_DATAGRAM_SIZE],
            vcpus: Arc::new([]),
        };
        crosvm.load_all_vcpus()?;
        Ok(crosvm)
    }

    fn new(
        id_allocator: Arc<IdAllocator>,
        socket: UnixDatagram,
        vcpus: Arc<[crosvm_vcpu]>,
    ) -> crosvm {
        crosvm {
            id_allocator,
            socket,
            request_buffer: Vec::new(),
            response_buffer: vec![0; MAX_DATAGRAM_SIZE],
            vcpus,
        }
    }

    fn get_id_allocator(&self) -> &IdAllocator {
        &self.id_allocator
    }

    fn main_transaction(
        &mut self,
        request: &MainRequest,
        fds: &[RawFd],
    ) -> result::Result<(MainResponse, Vec<File>), c_int> {
        self.request_buffer.clear();
        request
            .write_to_vec(&mut self.request_buffer)
            .map_err(proto_error_to_int)?;
        self.socket
            .send_with_fds(&[IoSlice::new(self.request_buffer.as_slice())], fds)
            // raw_os_error is expected to be `Some` because it is constructed via
            // `std::io::Error::last_os_error()`.
            .map_err(|e| -e.raw_os_error().unwrap_or(EINVAL))?;

        let mut datagram_fds = [0; MAX_DATAGRAM_FD];
        let (msg_size, fd_count) = self
            .socket
            .recv_with_fds(
                IoSliceMut::new(&mut self.response_buffer),
                &mut datagram_fds,
            )
            // raw_os_error is expected to be `Some` because it is constructed via
            // `std::io::Error::last_os_error()`.
            .map_err(|e| -e.raw_os_error().unwrap_or(EINVAL))?;
        // Safe because the first fd_count fds from recv_with_fds are owned by us and valid.
        let datagram_files = datagram_fds[..fd_count]
            .iter()
            .map(|&fd| unsafe { File::from_raw_fd(fd) })
            .collect();

        let response: MainResponse = Message::parse_from_bytes(&self.response_buffer[..msg_size])
            .map_err(proto_error_to_int)?;
        if response.errno != 0 {
            return Err(response.errno);
        }
        Ok((response, datagram_files))
    }

    fn try_clone(&mut self) -> result::Result<crosvm, c_int> {
        let mut r = MainRequest::new();
        r.mut_new_connection();
        let mut files = self.main_transaction(&r, &[])?.1;
        match files.pop() {
            Some(new_socket) => Ok(crosvm::new(
                self.id_allocator.clone(),
                fd_cast(new_socket),
                self.vcpus.clone(),
            )),
            None => Err(EPROTO),
        }
    }

    fn destroy(&mut self, id: u32) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        r.mut_destroy().id = id;
        self.main_transaction(&r, &[])?;
        self.get_id_allocator().free(id);
        printstats();
        Ok(())
    }

    // Only call this at `from_connection` function.
    fn load_all_vcpus(&mut self) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        r.mut_get_vcpus();
        let (_, mut files) = self.main_transaction(&r, &[])?;
        if files.is_empty() || files.len() % 2 != 0 {
            return Err(EPROTO);
        }

        let mut vcpus = Vec::with_capacity(files.len() / 2);
        while files.len() > 1 {
            let write_pipe = files.remove(0);
            let read_pipe = files.remove(0);
            vcpus.push(crosvm_vcpu::new(fd_cast(read_pipe), fd_cast(write_pipe)));
        }
        self.vcpus = Arc::from(vcpus);
        Ok(())
    }

    fn get_shutdown_event(&mut self) -> result::Result<File, c_int> {
        let mut r = MainRequest::new();
        r.mut_get_shutdown_eventfd();
        let (_, mut files) = self.main_transaction(&r, &[])?;
        match files.pop() {
            Some(f) => Ok(f),
            None => Err(EPROTO),
        }
    }

    fn check_extension(&mut self, extension: u32) -> result::Result<bool, c_int> {
        let mut r = MainRequest::new();
        r.mut_check_extension().extension = extension;
        let (response, _) = self.main_transaction(&r, &[])?;
        if !response.has_check_extension() {
            return Err(EPROTO);
        }
        Ok(response.check_extension().has_extension)
    }

    fn get_supported_cpuid(
        &mut self,
        cpuid_entries: &mut [kvm_cpuid_entry2],
        cpuid_count: &mut usize,
    ) -> result::Result<(), c_int> {
        *cpuid_count = 0;

        let mut r = MainRequest::new();
        r.mut_get_supported_cpuid();

        let (response, _) = self.main_transaction(&r, &[])?;
        if !response.has_get_supported_cpuid() {
            return Err(EPROTO);
        }

        let supported_cpuids = response.get_supported_cpuid();

        *cpuid_count = supported_cpuids.entries.len();
        if *cpuid_count > cpuid_entries.len() {
            return Err(E2BIG);
        }

        for (proto_entry, kvm_entry) in supported_cpuids
            .entries
            .iter()
            .zip(cpuid_entries.iter_mut())
        {
            *kvm_entry = cpuid_proto_to_kvm(proto_entry);
        }

        Ok(())
    }

    fn get_emulated_cpuid(
        &mut self,
        cpuid_entries: &mut [kvm_cpuid_entry2],
        cpuid_count: &mut usize,
    ) -> result::Result<(), c_int> {
        *cpuid_count = 0;

        let mut r = MainRequest::new();
        r.mut_get_emulated_cpuid();

        let (response, _) = self.main_transaction(&r, &[])?;
        if !response.has_get_emulated_cpuid() {
            return Err(EPROTO);
        }

        let emulated_cpuids = response.get_emulated_cpuid();

        *cpuid_count = emulated_cpuids.entries.len();
        if *cpuid_count > cpuid_entries.len() {
            return Err(E2BIG);
        }

        for (proto_entry, kvm_entry) in emulated_cpuids.entries.iter().zip(cpuid_entries.iter_mut())
        {
            *kvm_entry = cpuid_proto_to_kvm(proto_entry);
        }

        Ok(())
    }

    fn get_msr_index_list(
        &mut self,
        msr_indices: &mut [u32],
        msr_count: &mut usize,
    ) -> result::Result<(), c_int> {
        *msr_count = 0;

        let mut r = MainRequest::new();
        r.mut_get_msr_index_list();

        let (response, _) = self.main_transaction(&r, &[])?;
        if !response.has_get_msr_index_list() {
            return Err(EPROTO);
        }

        let msr_list = response.get_msr_index_list();

        *msr_count = msr_list.indices.len();
        if *msr_count > msr_indices.len() {
            return Err(E2BIG);
        }

        for (proto_entry, kvm_entry) in msr_list.indices.iter().zip(msr_indices.iter_mut()) {
            *kvm_entry = *proto_entry;
        }

        Ok(())
    }

    fn reserve_range(
        &mut self,
        space: u32,
        start: u64,
        length: u64,
        async_write: bool,
    ) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        let reserve = r.mut_reserve_range();
        reserve.space = AddressSpace::from_i32(space as i32).ok_or(EINVAL)?.into();
        reserve.start = start;
        reserve.length = length;
        reserve.async_write = async_write;

        self.main_transaction(&r, &[])?;
        Ok(())
    }

    fn set_irq(&mut self, irq_id: u32, active: bool) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        let set_irq = r.mut_set_irq();
        set_irq.irq_id = irq_id;
        set_irq.active = active;

        self.main_transaction(&r, &[])?;
        Ok(())
    }

    fn set_irq_routing(&mut self, routing: &[crosvm_irq_route]) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        let set_irq_routing = &mut r.mut_set_irq_routing().routes;
        for route in routing {
            let mut entry = main_request::set_irq_routing::Route::new();
            entry.irq_id = route.irq_id;
            match route.kind {
                CROSVM_IRQ_ROUTE_IRQCHIP => {
                    let irqchip = entry.mut_irqchip();
                    // Safe because route.kind indicates which union field is valid.
                    irqchip.irqchip = unsafe { route.route.irqchip }.irqchip;
                    irqchip.pin = unsafe { route.route.irqchip }.pin;
                }
                CROSVM_IRQ_ROUTE_MSI => {
                    let msi = entry.mut_msi();
                    // Safe because route.kind indicates which union field is valid.
                    msi.address = unsafe { route.route.msi }.address;
                    msi.data = unsafe { route.route.msi }.data;
                }
                _ => return Err(EINVAL),
            }
            set_irq_routing.push(entry);
        }

        self.main_transaction(&r, &[])?;
        Ok(())
    }

    fn set_hint(
        &mut self,
        space: u32,
        addr: u64,
        on_write: bool,
        hints: &[crosvm_hint_detail],
    ) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        let req = r.mut_set_call_hint();
        let set_hints = &mut req.hints;
        for hint in hints {
            let mut entry = main_request::set_call_hint::RegHint::new();
            entry.match_rax = hint.match_rax;
            entry.match_rbx = hint.match_rbx;
            entry.match_rcx = hint.match_rcx;
            entry.match_rdx = hint.match_rdx;
            entry.rax = hint.rax;
            entry.rbx = hint.rbx;
            entry.rcx = hint.rcx;
            entry.rdx = hint.rdx;
            entry.send_sregs = hint.send_sregs;
            entry.send_debugregs = hint.send_debugregs;
            set_hints.push(entry);
        }
        req.space = AddressSpace::from_i32(space as i32).ok_or(EINVAL)?.into();
        req.address = addr;
        req.on_write = on_write;

        self.main_transaction(&r, &[])?;
        Ok(())
    }

    fn get_state(
        &mut self,
        state_set: main_request::StateSet,
        out: &mut [u8],
    ) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        r.mut_get_state().set = state_set.into();
        let (response, _) = self.main_transaction(&r, &[])?;
        if !response.has_get_state() {
            return Err(EPROTO);
        }
        let get_state = response.get_state();
        if get_state.state.len() != out.len() {
            return Err(EPROTO);
        }
        out.copy_from_slice(&get_state.state);
        Ok(())
    }

    fn set_state(
        &mut self,
        state_set: main_request::StateSet,
        new_state: &[u8],
    ) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        let set_state = r.mut_set_state();
        set_state.set = state_set.into();
        set_state.state = new_state.to_vec();

        self.main_transaction(&r, &[])?;
        Ok(())
    }

    fn set_identity_map_addr(&mut self, addr: u32) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        r.mut_set_identity_map_addr().address = addr;

        self.main_transaction(&r, &[])?;
        Ok(())
    }

    fn pause_vcpus(&mut self, cpu_mask: u64, user: *mut c_void) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        let pause_vcpus = r.mut_pause_vcpus();
        pause_vcpus.cpu_mask = cpu_mask;
        pause_vcpus.user = user as u64;
        self.main_transaction(&r, &[])?;
        Ok(())
    }

    fn start(&mut self) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        r.mut_start();
        self.main_transaction(&r, &[])?;
        Ok(())
    }

    fn get_vcpu(&mut self, cpu_id: u32) -> Result<*mut crosvm_vcpu, c_int> {
        if let Some(vcpu) = self.vcpus.get(cpu_id as usize) {
            Ok(vcpu as *const crosvm_vcpu as *mut crosvm_vcpu)
        } else {
            Err(ENOENT)
        }
    }

    fn get_net_config(&mut self) -> result::Result<crosvm_net_config, c_int> {
        let mut r = MainRequest::new();
        r.mut_get_net_config();

        let (response, mut files) = self.main_transaction(&r, &[])?;
        if !response.has_get_net_config() {
            return Err(EPROTO);
        }
        let config = response.get_net_config();

        match files.pop() {
            Some(f) => {
                let mut net_config = crosvm_net_config {
                    tap_fd: f.into_raw_fd(),
                    host_ipv4_address: config.host_ipv4_address,
                    netmask: config.netmask,
                    host_mac_address: [0; 6],
                    _reserved: [0; 2],
                };

                let mac_addr = &config.host_mac_address;
                if mac_addr.len() != net_config.host_mac_address.len() {
                    return Err(EPROTO);
                }
                net_config.host_mac_address.copy_from_slice(mac_addr);

                Ok(net_config)
            }
            None => Err(EPROTO),
        }
    }
}

/// This helper macro implements the C API's constructor/destructor for a given type. Because they
/// all follow the same pattern and include lots of boilerplate unsafe code, it makes sense to write
/// it once with this helper macro.
macro_rules! impl_ctor_dtor {
    (
        $t:ident,
        $ctor:ident ( $( $x:ident: $y:ty ),* ),
        $dtor:ident,
    ) => {
        #[allow(unused_unsafe)]
        #[no_mangle]
        pub unsafe extern fn $ctor(self_: *mut crosvm, $($x: $y,)* obj_ptr: *mut *mut $t) -> c_int {
            let self_ = &mut (*self_);
            match $t::create(self_, $($x,)*) {
                Ok(obj) => {
                    *obj_ptr = Box::into_raw(Box::new(obj));
                    0
                }
                Err(e) => -e,
            }
        }
        #[no_mangle]
        pub unsafe extern fn $dtor(self_: *mut crosvm, obj_ptr: *mut *mut $t) -> c_int {
            let self_ = &mut (*self_);
            let obj = Box::from_raw(*obj_ptr);
            match self_.destroy(obj.id) {
                Ok(_) => {
                    *obj_ptr = null_mut();
                    0
                }
                Err(e) =>  {
                    Box::into_raw(obj);
                    -e
                }
            }
        }
    }
}

pub struct crosvm_io_event {
    id: u32,
    evt: File,
}

impl crosvm_io_event {
    // Clippy: we use ptr::read_unaligned to read from pointers that may be
    // underaligned. Dereferencing such a pointer is always undefined behavior
    // in Rust.
    //
    // Lint can be unsuppressed once Clippy recognizes this pattern as correct.
    // https://github.com/rust-lang/rust-clippy/issues/2881
    #[allow(clippy::cast_ptr_alignment)]
    unsafe fn create(
        crosvm: &mut crosvm,
        space: u32,
        addr: u64,
        length: u32,
        datamatch: *const u8,
    ) -> result::Result<crosvm_io_event, c_int> {
        let datamatch = match length {
            0 => 0,
            1 => ptr::read_unaligned(datamatch) as u64,
            2 => ptr::read_unaligned(datamatch as *const u16) as u64,
            4 => ptr::read_unaligned(datamatch as *const u32) as u64,
            8 => ptr::read_unaligned(datamatch as *const u64),
            _ => return Err(EINVAL),
        };
        Self::safe_create(crosvm, space, addr, length, datamatch)
    }

    fn safe_create(
        crosvm: &mut crosvm,
        space: u32,
        addr: u64,
        length: u32,
        datamatch: u64,
    ) -> result::Result<crosvm_io_event, c_int> {
        let id = crosvm.get_id_allocator().alloc();

        let mut r = MainRequest::new();
        let create = r.mut_create();
        create.id = id;
        let io_event = create.mut_io_event();
        io_event.space = AddressSpace::from_i32(space as i32).ok_or(EINVAL)?.into();
        io_event.address = addr;
        io_event.length = length;
        io_event.datamatch = datamatch;

        let ret = match crosvm.main_transaction(&r, &[]) {
            Ok((_, mut files)) => match files.pop() {
                Some(evt) => return Ok(crosvm_io_event { id, evt }),
                None => EPROTO,
            },
            Err(e) => e,
        };
        crosvm.get_id_allocator().free(id);
        Err(ret)
    }
}

impl_ctor_dtor!(
    crosvm_io_event,
    crosvm_create_io_event(space: u32, addr: u64, len: u32, datamatch: *const u8),
    crosvm_destroy_io_event,
);

#[no_mangle]
pub unsafe extern "C" fn crosvm_io_event_fd(this: *mut crosvm_io_event) -> c_int {
    let _u = record(Stat::IoEvent);
    (*this).evt.as_raw_fd()
}

pub struct crosvm_memory {
    id: u32,
    length: u64,
}

impl crosvm_memory {
    fn create(
        crosvm: &mut crosvm,
        fd: c_int,
        offset: u64,
        length: u64,
        start: u64,
        read_only: bool,
        dirty_log: bool,
    ) -> result::Result<crosvm_memory, c_int> {
        const PAGE_MASK: u64 = 0x0fff;
        if offset & PAGE_MASK != 0 || length & PAGE_MASK != 0 {
            return Err(EINVAL);
        }
        let id = crosvm.get_id_allocator().alloc();

        let mut r = MainRequest::new();
        let create = r.mut_create();
        create.id = id;
        let memory = create.mut_memory();
        memory.offset = offset;
        memory.start = start;
        memory.length = length;
        memory.read_only = read_only;
        memory.dirty_log = dirty_log;

        let ret = match crosvm.main_transaction(&r, &[fd]) {
            Ok(_) => return Ok(crosvm_memory { id, length }),
            Err(e) => e,
        };
        crosvm.get_id_allocator().free(id);
        Err(ret)
    }

    fn get_dirty_log(&mut self, crosvm: &mut crosvm) -> result::Result<Vec<u8>, c_int> {
        let mut r = MainRequest::new();
        r.mut_dirty_log().id = self.id;
        let (mut response, _) = crosvm.main_transaction(&r, &[])?;
        if !response.has_dirty_log() {
            return Err(EPROTO);
        }
        Ok(response.take_dirty_log().bitmap)
    }
}

impl_ctor_dtor!(
    crosvm_memory,
    crosvm_create_memory(
        fd: c_int,
        offset: u64,
        length: u64,
        start: u64,
        read_only: bool,
        dirty_log: bool
    ),
    crosvm_destroy_memory,
);

#[no_mangle]
pub unsafe extern "C" fn crosvm_memory_get_dirty_log(
    crosvm: *mut crosvm,
    this: *mut crosvm_memory,
    log: *mut u8,
) -> c_int {
    let _u = record(Stat::MemoryGetDirtyLog);
    let crosvm = &mut *crosvm;
    let this = &mut *this;
    let log_slice = slice::from_raw_parts_mut(log, dirty_log_bitmap_size(this.length as usize));
    match this.get_dirty_log(crosvm) {
        Ok(bitmap) => {
            if bitmap.len() == log_slice.len() {
                log_slice.copy_from_slice(&bitmap);
                0
            } else {
                -EPROTO
            }
        }
        Err(e) => -e,
    }
}

pub struct crosvm_irq_event {
    id: u32,
    trigger_evt: File,
    resample_evt: File,
}

impl crosvm_irq_event {
    fn create(crosvm: &mut crosvm, irq_id: u32) -> result::Result<crosvm_irq_event, c_int> {
        let id = crosvm.get_id_allocator().alloc();

        let mut r = MainRequest::new();
        let create = r.mut_create();
        create.id = id;
        let irq_event = create.mut_irq_event();
        irq_event.irq_id = irq_id;
        irq_event.resample = true;

        let ret = match crosvm.main_transaction(&r, &[]) {
            Ok((_, mut files)) => {
                if files.len() >= 2 {
                    let resample_evt = files.pop().unwrap();
                    let trigger_evt = files.pop().unwrap();
                    return Ok(crosvm_irq_event {
                        id,
                        trigger_evt,
                        resample_evt,
                    });
                }
                EPROTO
            }
            Err(e) => e,
        };
        crosvm.get_id_allocator().free(id);
        Err(ret)
    }
}

impl_ctor_dtor!(
    crosvm_irq_event,
    crosvm_create_irq_event(irq_id: u32),
    crosvm_destroy_irq_event,
);

#[no_mangle]
pub unsafe extern "C" fn crosvm_irq_event_get_fd(this: *mut crosvm_irq_event) -> c_int {
    let _u = record(Stat::IrqEventGetFd);
    (*this).trigger_evt.as_raw_fd()
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_irq_event_get_resample_fd(this: *mut crosvm_irq_event) -> c_int {
    let _u = record(Stat::IrqEventGetResampleFd);
    (*this).resample_evt.as_raw_fd()
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
#[repr(C)]
struct anon_io_access {
    address_space: u32,
    __reserved0: [u8; 4],
    address: u64,
    data: *mut u8,
    length: u32,
    is_write: u8,
    no_resume: u8,
    __reserved1: [u8; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
struct anon_hyperv_call {
    input: u64,
    result: *mut u8,
    params: [u64; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
struct anon_hyperv_synic {
    msr: u32,
    reserved: u32,
    control: u64,
    evt_page: u64,
    msg_page: u64,
}

#[repr(C)]
union anon_vcpu_event {
    io_access: anon_io_access,
    user: *mut c_void,
    hyperv_call: anon_hyperv_call,
    hyperv_synic: anon_hyperv_synic,
    #[allow(dead_code)]
    __reserved: [u8; 64],
}

#[repr(C)]
pub struct crosvm_vcpu_event {
    kind: u32,
    __reserved: [u8; 4],
    event: anon_vcpu_event,
}

// |get| tracks if the |cache| contains a cached value that can service get()
// requests.  A set() call will populate |cache| and |set| to true to record
// that the next resume() should apply the state.  We've got two choices on
// what to do about |get| on a set(): 1) leave it as true, or 2) clear it and
// have any call to get() first apply any pending set.  Currently #2 is used
// to favor correctness over performance (it gives KVM a chance to
// modify/massage the values input to the set call). A plugin will rarely
// (if ever) issue a get() after a set() on the same vcpu exit, so opting for
// #1 is unlikely to provide a tangible performance gain.
pub struct crosvm_vcpu_reg_cache {
    get: bool,
    set: bool,
    cache: Vec<u8>,
}

pub struct crosvm_vcpu {
    read_pipe: File,
    write_pipe: File,
    send_init: bool,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    response_base: usize,
    response_length: usize,
    resume_data: Vec<u8>,

    regs: crosvm_vcpu_reg_cache,
    sregs: crosvm_vcpu_reg_cache,
    debugregs: crosvm_vcpu_reg_cache,
}

fn read_varint32(data: &[u8]) -> (u32, usize) {
    let mut value: u32 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in data.iter().enumerate() {
        if b < 0x80 {
            return match (b as u32).checked_shl(shift) {
                None => (0, 0),
                Some(b) => (value | b, i + 1),
            };
        }
        match ((b as u32) & 0x7F).checked_shl(shift) {
            None => return (0, 0),
            Some(b) => value |= b,
        }
        shift += 7;
    }
    (0, 0)
}

impl crosvm_vcpu {
    fn new(read_pipe: File, write_pipe: File) -> crosvm_vcpu {
        crosvm_vcpu {
            read_pipe,
            write_pipe,
            send_init: true,
            request_buffer: Vec::new(),
            response_buffer: vec![0; MAX_DATAGRAM_SIZE],
            response_base: 0,
            response_length: 0,
            resume_data: Vec::new(),
            regs: crosvm_vcpu_reg_cache {
                get: false,
                set: false,
                cache: vec![],
            },
            sregs: crosvm_vcpu_reg_cache {
                get: false,
                set: false,
                cache: vec![],
            },
            debugregs: crosvm_vcpu_reg_cache {
                get: false,
                set: false,
                cache: vec![],
            },
        }
    }
    fn vcpu_send(&mut self, request: &VcpuRequest) -> result::Result<(), c_int> {
        self.request_buffer.clear();
        request
            .write_to_vec(&mut self.request_buffer)
            .map_err(proto_error_to_int)?;
        self.write_pipe
            .write(self.request_buffer.as_slice())
            .map_err(|e| -e.raw_os_error().unwrap_or(EINVAL))?;
        Ok(())
    }

    fn vcpu_recv(&mut self) -> result::Result<VcpuResponse, c_int> {
        if self.response_length == 0 {
            let msg_size = self
                .read_pipe
                .read(&mut self.response_buffer)
                .map_err(|e| -e.raw_os_error().unwrap_or(EINVAL))?;
            self.response_base = 0;
            self.response_length = msg_size;
        }
        if self.response_length == 0 {
            return Err(EINVAL);
        }
        let (value, bytes) = read_varint32(
            &self.response_buffer[self.response_base..self.response_base + self.response_length],
        );
        let total_size: usize = bytes + value as usize;
        if bytes == 0 || total_size > self.response_length {
            return Err(EINVAL);
        }
        let response: VcpuResponse = Message::parse_from_bytes(
            &self.response_buffer[self.response_base + bytes..self.response_base + total_size],
        )
        .map_err(proto_error_to_int)?;
        self.response_base += total_size;
        self.response_length -= total_size;
        if response.errno != 0 {
            return Err(response.errno);
        }
        Ok(response)
    }

    fn vcpu_transaction(&mut self, request: &VcpuRequest) -> result::Result<VcpuResponse, c_int> {
        self.vcpu_send(request)?;
        let response: VcpuResponse = self.vcpu_recv()?;
        Ok(response)
    }

    fn wait(&mut self, event: &mut crosvm_vcpu_event) -> result::Result<(), c_int> {
        if self.send_init {
            self.send_init = false;
            let mut r = VcpuRequest::new();
            r.mut_wait();
            self.vcpu_send(&r)?;
        }
        let mut response: VcpuResponse = self.vcpu_recv()?;
        if !response.has_wait() {
            return Err(EPROTO);
        }
        let wait = response.mut_wait();
        if wait.has_init() {
            event.kind = CROSVM_VCPU_EVENT_KIND_INIT;
            self.regs.get = false;
            self.sregs.get = false;
            self.debugregs.get = false;
            Ok(())
        } else if wait.has_io() {
            let mut io = wait.take_io();
            event.kind = CROSVM_VCPU_EVENT_KIND_IO_ACCESS;
            event.event.io_access = anon_io_access {
                address_space: io.space.value() as u32,
                __reserved0: Default::default(),
                address: io.address,
                data: io.data.as_mut_ptr(),
                length: io.data.len() as u32,
                is_write: io.is_write as u8,
                no_resume: io.no_resume as u8,
                __reserved1: Default::default(),
            };
            self.resume_data = io.data;
            self.regs.get = !io.regs.is_empty();
            if self.regs.get {
                swap(&mut self.regs.cache, &mut io.regs);
            }
            self.sregs.get = !io.sregs.is_empty();
            if self.sregs.get {
                swap(&mut self.sregs.cache, &mut io.sregs);
            }
            self.debugregs.get = !io.debugregs.is_empty();
            if self.debugregs.get {
                swap(&mut self.debugregs.cache, &mut io.debugregs);
            }
            Ok(())
        } else if wait.has_user() {
            let user = wait.user();
            event.kind = CROSVM_VCPU_EVENT_KIND_PAUSED;
            event.event.user = user.user as *mut c_void;
            self.regs.get = false;
            self.sregs.get = false;
            self.debugregs.get = false;
            Ok(())
        } else if wait.has_hyperv_call() {
            let hv = wait.hyperv_call();
            event.kind = CROSVM_VCPU_EVENT_KIND_HYPERV_HCALL;
            self.resume_data = vec![0; 8];
            event.event.hyperv_call = anon_hyperv_call {
                input: hv.input,
                result: self.resume_data.as_mut_ptr(),
                params: [hv.params0, hv.params1],
            };
            self.regs.get = false;
            self.sregs.get = false;
            self.debugregs.get = false;
            Ok(())
        } else if wait.has_hyperv_synic() {
            let hv = wait.hyperv_synic();
            event.kind = CROSVM_VCPU_EVENT_KIND_HYPERV_SYNIC;
            event.event.hyperv_synic = anon_hyperv_synic {
                msr: hv.msr,
                reserved: 0,
                control: hv.control,
                evt_page: hv.evt_page,
                msg_page: hv.msg_page,
            };
            self.regs.get = false;
            self.sregs.get = false;
            self.debugregs.get = false;
            Ok(())
        } else {
            Err(EPROTO)
        }
    }

    fn resume(&mut self) -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        let resume = r.mut_resume();
        swap(&mut resume.data, &mut self.resume_data);

        if self.regs.set {
            swap(&mut resume.regs, &mut self.regs.cache);
            self.regs.set = false;
        }
        if self.sregs.set {
            swap(&mut resume.sregs, &mut self.sregs.cache);
            self.sregs.set = false;
        }
        if self.debugregs.set {
            swap(&mut resume.debugregs, &mut self.debugregs.cache);
            self.debugregs.set = false;
        }

        self.vcpu_send(&r)?;
        Ok(())
    }

    fn get_state(
        &mut self,
        state_set: vcpu_request::StateSet,
        out: &mut [u8],
    ) -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        r.mut_get_state().set = state_set.into();
        let response = self.vcpu_transaction(&r)?;
        if !response.has_get_state() {
            return Err(EPROTO);
        }
        let get_state = response.get_state();
        if get_state.state.len() != out.len() {
            return Err(EPROTO);
        }
        out.copy_from_slice(&get_state.state);
        Ok(())
    }

    fn set_state(
        &mut self,
        state_set: vcpu_request::StateSet,
        new_state: &[u8],
    ) -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        let set_state = r.mut_set_state();
        set_state.set = state_set.into();
        set_state.state = new_state.to_vec();

        self.vcpu_transaction(&r)?;
        Ok(())
    }

    fn set_state_from_cache(
        &mut self,
        state_set: vcpu_request::StateSet,
    ) -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        let set_state = r.mut_set_state();
        set_state.set = state_set.into();
        match state_set {
            vcpu_request::StateSet::REGS => {
                swap(&mut set_state.state, &mut self.regs.cache);
                self.regs.set = false;
            }
            vcpu_request::StateSet::SREGS => {
                swap(&mut set_state.state, &mut self.sregs.cache);
                self.sregs.set = false;
            }
            vcpu_request::StateSet::DEBUGREGS => {
                swap(&mut set_state.state, &mut self.debugregs.cache);
                self.debugregs.set = false;
            }
            _ => return Err(EINVAL),
        }

        self.vcpu_transaction(&r)?;
        Ok(())
    }

    fn get_hyperv_cpuid(
        &mut self,
        cpuid_entries: &mut [kvm_cpuid_entry2],
        cpuid_count: &mut usize,
    ) -> result::Result<(), c_int> {
        *cpuid_count = 0;

        let mut r = VcpuRequest::new();
        r.mut_get_hyperv_cpuid();

        let response = self.vcpu_transaction(&r)?;
        if !response.has_get_hyperv_cpuid() {
            return Err(EPROTO);
        }

        let hyperv_cpuids = response.get_hyperv_cpuid();

        *cpuid_count = hyperv_cpuids.entries.len();
        if *cpuid_count > cpuid_entries.len() {
            return Err(E2BIG);
        }

        for (proto_entry, kvm_entry) in hyperv_cpuids.entries.iter().zip(cpuid_entries.iter_mut()) {
            *kvm_entry = cpuid_proto_to_kvm(proto_entry);
        }

        Ok(())
    }

    fn get_msrs(
        &mut self,
        msr_entries: &mut [kvm_msr_entry],
        msr_count: &mut usize,
    ) -> result::Result<(), c_int> {
        *msr_count = 0;

        let mut r = VcpuRequest::new();
        let entry_indices: &mut Vec<u32> = &mut r.mut_get_msrs().entry_indices;
        for entry in msr_entries.iter() {
            entry_indices.push(entry.index);
        }

        let response = self.vcpu_transaction(&r)?;
        if !response.has_get_msrs() {
            return Err(EPROTO);
        }
        let get_msrs = response.get_msrs();
        *msr_count = get_msrs.entry_data.len();
        if *msr_count > msr_entries.len() {
            return Err(E2BIG);
        }
        for (&msr_data, msr_entry) in get_msrs.entry_data.iter().zip(msr_entries) {
            msr_entry.data = msr_data;
        }
        Ok(())
    }

    fn set_msrs(&mut self, msr_entries: &[kvm_msr_entry]) -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        let set_msrs_entries = &mut r.mut_set_msrs().entries;
        for msr_entry in msr_entries {
            let mut entry = vcpu_request::MsrEntry::new();
            entry.index = msr_entry.index;
            entry.data = msr_entry.data;
            set_msrs_entries.push(entry);
        }

        self.vcpu_transaction(&r)?;
        Ok(())
    }

    fn set_cpuid(&mut self, cpuid_entries: &[kvm_cpuid_entry2]) -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        let set_cpuid_entries = &mut r.mut_set_cpuid().entries;
        for cpuid_entry in cpuid_entries {
            set_cpuid_entries.push(cpuid_kvm_to_proto(cpuid_entry));
        }

        self.vcpu_transaction(&r)?;
        Ok(())
    }

    fn enable_capability(&mut self, capability: u32) -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        r.mut_enable_capability().capability = capability;
        self.vcpu_transaction(&r)?;
        Ok(())
    }
}

// crosvm API signals success as 0 and errors as negative values
// derived from `errno`.
fn to_crosvm_rc<T>(r: result::Result<T, c_int>) -> c_int {
    match r {
        Ok(_) => 0,
        Err(e) => -e,
    }
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_connect(out: *mut *mut crosvm) -> c_int {
    let _u = record(Stat::Connect);
    let socket_name = match env::var(CROSVM_SOCKET_ENV) {
        Ok(v) => v,
        _ => return -ENOTCONN,
    };

    let socket = match socket_name.parse() {
        Ok(v) if v < 0 => return -EINVAL,
        Ok(v) => v,
        _ => return -EINVAL,
    };

    let socket = UnixDatagram::from_raw_fd(socket);
    let crosvm = match crosvm::from_connection(socket) {
        Ok(c) => c,
        Err(e) => return -e,
    };
    *out = Box::into_raw(Box::new(crosvm));
    0
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_new_connection(self_: *mut crosvm, out: *mut *mut crosvm) -> c_int {
    let _u = record(Stat::NewConnection);
    let self_ = &mut (*self_);
    match self_.try_clone() {
        Ok(cloned) => {
            *out = Box::into_raw(Box::new(cloned));
            0
        }
        Err(e) => -e,
    }
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_destroy_connection(self_: *mut *mut crosvm) -> c_int {
    let _u = record(Stat::DestroyConnection);
    drop(Box::from_raw(*self_));
    *self_ = null_mut();
    0
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_shutdown_eventfd(self_: *mut crosvm) -> c_int {
    let _u = record(Stat::GetShutdownEvent);
    let self_ = &mut (*self_);
    match self_.get_shutdown_event() {
        Ok(f) => f.into_raw_fd(),
        Err(e) => -e,
    }
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_check_extension(
    self_: *mut crosvm,
    extension: u32,
    has_extension: *mut bool,
) -> c_int {
    let _u = record(Stat::CheckExtentsion);
    let self_ = &mut (*self_);
    let ret = self_.check_extension(extension);

    if let Ok(supported) = ret {
        *has_extension = supported;
    }
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_enable_capability(
    _self_: *mut crosvm,
    _capability: u32,
    _flags: u32,
    _args: *const u64,
) -> c_int {
    let _u = record(Stat::EnableVmCapability);
    -EINVAL
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_supported_cpuid(
    this: *mut crosvm,
    entry_count: u32,
    cpuid_entries: *mut kvm_cpuid_entry2,
    out_count: *mut u32,
) -> c_int {
    let _u = record(Stat::GetSupportedCpuid);
    let this = &mut *this;
    let cpuid_entries = from_raw_parts_mut(cpuid_entries, entry_count as usize);
    let mut cpuid_count: usize = 0;
    let ret = this.get_supported_cpuid(cpuid_entries, &mut cpuid_count);
    *out_count = cpuid_count as u32;
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_emulated_cpuid(
    this: *mut crosvm,
    entry_count: u32,
    cpuid_entries: *mut kvm_cpuid_entry2,
    out_count: *mut u32,
) -> c_int {
    let _u = record(Stat::GetEmulatedCpuid);
    let this = &mut *this;
    let cpuid_entries = from_raw_parts_mut(cpuid_entries, entry_count as usize);
    let mut cpuid_count: usize = 0;
    let ret = this.get_emulated_cpuid(cpuid_entries, &mut cpuid_count);
    *out_count = cpuid_count as u32;
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_msr_index_list(
    this: *mut crosvm,
    entry_count: u32,
    msr_indices: *mut u32,
    out_count: *mut u32,
) -> c_int {
    let _u = record(Stat::GetMsrIndexList);
    let this = &mut *this;
    let msr_indices = from_raw_parts_mut(msr_indices, entry_count as usize);
    let mut msr_count: usize = 0;
    let ret = this.get_msr_index_list(msr_indices, &mut msr_count);
    *out_count = msr_count as u32;
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_net_get_config(
    self_: *mut crosvm,
    config: *mut crosvm_net_config,
) -> c_int {
    let _u = record(Stat::NetGetConfig);
    let self_ = &mut (*self_);
    let ret = self_.get_net_config();

    if let Ok(c) = ret {
        *config = c;
    }

    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_reserve_range(
    self_: *mut crosvm,
    space: u32,
    start: u64,
    length: u64,
) -> c_int {
    let _u = record(Stat::ReserveRange);
    let self_ = &mut (*self_);
    let ret = self_.reserve_range(space, start, length, false);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_reserve_async_write_range(
    self_: *mut crosvm,
    space: u32,
    start: u64,
    length: u64,
) -> c_int {
    let _u = record(Stat::ReserveAsyncWriteRange);
    let self_ = &mut (*self_);
    let ret = self_.reserve_range(space, start, length, true);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_irq(self_: *mut crosvm, irq_id: u32, active: bool) -> c_int {
    let _u = record(Stat::SetIrq);
    let self_ = &mut (*self_);
    let ret = self_.set_irq(irq_id, active);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_irq_routing(
    self_: *mut crosvm,
    route_count: u32,
    routes: *const crosvm_irq_route,
) -> c_int {
    let _u = record(Stat::SetIrqRouting);
    let self_ = &mut (*self_);
    let ret = self_.set_irq_routing(slice::from_raw_parts(routes, route_count as usize));
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_hypercall_hint(
    self_: *mut crosvm,
    hints_count: u32,
    hints: *const crosvm_hint,
) -> c_int {
    let _u = record(Stat::SetHypercallHint);
    let self_ = &mut (*self_);

    if hints_count < 1 {
        let ret = self_.set_hint(0, 0, false, &[]);
        return to_crosvm_rc(ret);
    }
    if hints_count > CROSVM_MAX_HINT_COUNT {
        return -EINVAL;
    }
    let hints = slice::from_raw_parts(hints, hints_count as usize);
    let hint = &hints[0];
    if hint.hint_version != 0
        || hint.reserved != 0
        || hint.address == 0
        || (hint.address_flags != 0 && hint.address_flags != CROSVM_HINT_ON_WRITE)
        || hint.details_count > CROSVM_MAX_HINT_DETAIL_COUNT as u16
    {
        return -EINVAL;
    }
    let ret = self_.set_hint(
        hint.address_space,
        hint.address,
        hint.address_flags == CROSVM_HINT_ON_WRITE,
        slice::from_raw_parts(hint.details, hint.details_count as usize),
    );
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_pic_state(
    this: *mut crosvm,
    primary: bool,
    state: *mut kvm_pic_state,
) -> c_int {
    let _u = record(Stat::GetPicState);
    let this = &mut *this;
    let state_set = if primary {
        main_request::StateSet::PIC0
    } else {
        main_request::StateSet::PIC1
    };
    let state = from_raw_parts_mut(state as *mut u8, size_of::<kvm_pic_state>());
    let ret = this.get_state(state_set, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_pic_state(
    this: *mut crosvm,
    primary: bool,
    state: *mut kvm_pic_state,
) -> c_int {
    let _u = record(Stat::SetPicState);
    let this = &mut *this;
    let state_set = if primary {
        main_request::StateSet::PIC0
    } else {
        main_request::StateSet::PIC1
    };
    let state = from_raw_parts(state as *mut u8, size_of::<kvm_pic_state>());
    let ret = this.set_state(state_set, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_ioapic_state(
    this: *mut crosvm,
    state: *mut kvm_ioapic_state,
) -> c_int {
    let _u = record(Stat::GetIoapicState);
    let this = &mut *this;
    let state = from_raw_parts_mut(state as *mut u8, size_of::<kvm_ioapic_state>());
    let ret = this.get_state(main_request::StateSet::IOAPIC, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_ioapic_state(
    this: *mut crosvm,
    state: *const kvm_ioapic_state,
) -> c_int {
    let _u = record(Stat::SetIoapicState);
    let this = &mut *this;
    let state = from_raw_parts(state as *mut u8, size_of::<kvm_ioapic_state>());
    let ret = this.set_state(main_request::StateSet::IOAPIC, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_pit_state(
    this: *mut crosvm,
    state: *mut kvm_pit_state2,
) -> c_int {
    let _u = record(Stat::GetPitState);
    let this = &mut *this;
    let state = from_raw_parts_mut(state as *mut u8, size_of::<kvm_pit_state2>());
    let ret = this.get_state(main_request::StateSet::PIT, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_pit_state(
    this: *mut crosvm,
    state: *const kvm_pit_state2,
) -> c_int {
    let _u = record(Stat::SetPitState);
    let this = &mut *this;
    let state = from_raw_parts(state as *mut u8, size_of::<kvm_pit_state2>());
    let ret = this.set_state(main_request::StateSet::PIT, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_clock(
    this: *mut crosvm,
    clock_data: *mut kvm_clock_data,
) -> c_int {
    let _u = record(Stat::GetClock);
    let this = &mut *this;
    let state = from_raw_parts_mut(clock_data as *mut u8, size_of::<kvm_clock_data>());
    let ret = this.get_state(main_request::StateSet::CLOCK, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_clock(
    this: *mut crosvm,
    clock_data: *const kvm_clock_data,
) -> c_int {
    let _u = record(Stat::SetClock);
    let this = &mut *this;
    let state = from_raw_parts(clock_data as *mut u8, size_of::<kvm_clock_data>());
    let ret = this.set_state(main_request::StateSet::CLOCK, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_identity_map_addr(self_: *mut crosvm, addr: u32) -> c_int {
    let _u = record(Stat::SetIdentityMapAddr);
    let self_ = &mut (*self_);
    let ret = self_.set_identity_map_addr(addr);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_pause_vcpus(
    self_: *mut crosvm,
    cpu_mask: u64,
    user: *mut c_void,
) -> c_int {
    let _u = record(Stat::PauseVcpus);
    let self_ = &mut (*self_);
    let ret = self_.pause_vcpus(cpu_mask, user);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_start(self_: *mut crosvm) -> c_int {
    let _u = record(Stat::Start);
    let self_ = &mut (*self_);
    let ret = self_.start();
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_vcpu(
    self_: *mut crosvm,
    cpu_id: u32,
    out: *mut *mut crosvm_vcpu,
) -> c_int {
    let _u = record(Stat::GetVcpu);
    let self_ = &mut (*self_);
    let ret = self_.get_vcpu(cpu_id);

    if let Ok(vcpu) = ret {
        *out = vcpu;
    }
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_wait(
    this: *mut crosvm_vcpu,
    event: *mut crosvm_vcpu_event,
) -> c_int {
    let _u = record(Stat::VcpuWait);
    let this = &mut *this;
    let event = &mut *event;
    let ret = this.wait(event);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_resume(this: *mut crosvm_vcpu) -> c_int {
    let _u = record(Stat::VcpuResume);
    let this = &mut *this;
    let ret = this.resume();
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_regs(
    this: *mut crosvm_vcpu,
    regs: *mut kvm_regs,
) -> c_int {
    let _u = record(Stat::VcpuGetRegs);
    let this = &mut *this;
    if this.regs.set {
        if let Err(e) = this.set_state_from_cache(vcpu_request::StateSet::REGS) {
            return -e;
        }
    }
    let regs = from_raw_parts_mut(regs as *mut u8, size_of::<kvm_regs>());
    if this.regs.get {
        regs.copy_from_slice(&this.regs.cache);
        0
    } else {
        let ret = this.get_state(vcpu_request::StateSet::REGS, regs);
        to_crosvm_rc(ret)
    }
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_regs(
    this: *mut crosvm_vcpu,
    regs: *const kvm_regs,
) -> c_int {
    let _u = record(Stat::VcpuSetRegs);
    let this = &mut *this;
    this.regs.get = false;
    let regs = from_raw_parts(regs as *mut u8, size_of::<kvm_regs>());
    this.regs.set = true;
    this.regs.cache = regs.to_vec();
    0
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_sregs(
    this: *mut crosvm_vcpu,
    sregs: *mut kvm_sregs,
) -> c_int {
    let _u = record(Stat::VcpuGetSregs);
    let this = &mut *this;
    if this.sregs.set {
        if let Err(e) = this.set_state_from_cache(vcpu_request::StateSet::SREGS) {
            return -e;
        }
    }
    let sregs = from_raw_parts_mut(sregs as *mut u8, size_of::<kvm_sregs>());
    if this.sregs.get {
        sregs.copy_from_slice(&this.sregs.cache);
        0
    } else {
        let ret = this.get_state(vcpu_request::StateSet::SREGS, sregs);
        to_crosvm_rc(ret)
    }
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_sregs(
    this: *mut crosvm_vcpu,
    sregs: *const kvm_sregs,
) -> c_int {
    let _u = record(Stat::VcpuSetSregs);
    let this = &mut *this;
    this.sregs.get = false;
    let sregs = from_raw_parts(sregs as *mut u8, size_of::<kvm_sregs>());
    this.sregs.set = true;
    this.sregs.cache = sregs.to_vec();
    0
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_fpu(this: *mut crosvm_vcpu, fpu: *mut kvm_fpu) -> c_int {
    let _u = record(Stat::GetFpu);
    let this = &mut *this;
    let fpu = from_raw_parts_mut(fpu as *mut u8, size_of::<kvm_fpu>());
    let ret = this.get_state(vcpu_request::StateSet::FPU, fpu);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_fpu(this: *mut crosvm_vcpu, fpu: *const kvm_fpu) -> c_int {
    let _u = record(Stat::SetFpu);
    let this = &mut *this;
    let fpu = from_raw_parts(fpu as *mut u8, size_of::<kvm_fpu>());
    let ret = this.set_state(vcpu_request::StateSet::FPU, fpu);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_debugregs(
    this: *mut crosvm_vcpu,
    dregs: *mut kvm_debugregs,
) -> c_int {
    let _u = record(Stat::GetDebugRegs);
    let this = &mut *this;
    if this.debugregs.set {
        if let Err(e) = this.set_state_from_cache(vcpu_request::StateSet::DEBUGREGS) {
            return -e;
        }
    }
    let dregs = from_raw_parts_mut(dregs as *mut u8, size_of::<kvm_debugregs>());
    if this.debugregs.get {
        dregs.copy_from_slice(&this.debugregs.cache);
        0
    } else {
        let ret = this.get_state(vcpu_request::StateSet::DEBUGREGS, dregs);
        to_crosvm_rc(ret)
    }
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_debugregs(
    this: *mut crosvm_vcpu,
    dregs: *const kvm_debugregs,
) -> c_int {
    let _u = record(Stat::SetDebugRegs);
    let this = &mut *this;
    this.debugregs.get = false;
    let dregs = from_raw_parts(dregs as *mut u8, size_of::<kvm_debugregs>());
    this.debugregs.set = true;
    this.debugregs.cache = dregs.to_vec();
    0
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_xcrs(
    this: *mut crosvm_vcpu,
    xcrs: *mut kvm_xcrs,
) -> c_int {
    let _u = record(Stat::GetXCRegs);
    let this = &mut *this;
    let xcrs = from_raw_parts_mut(xcrs as *mut u8, size_of::<kvm_xcrs>());
    let ret = this.get_state(vcpu_request::StateSet::XCREGS, xcrs);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_xcrs(
    this: *mut crosvm_vcpu,
    xcrs: *const kvm_xcrs,
) -> c_int {
    let _u = record(Stat::SetXCRegs);
    let this = &mut *this;
    let xcrs = from_raw_parts(xcrs as *mut u8, size_of::<kvm_xcrs>());
    let ret = this.set_state(vcpu_request::StateSet::XCREGS, xcrs);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_hyperv_cpuid(
    this: *mut crosvm_vcpu,
    entry_count: u32,
    cpuid_entries: *mut kvm_cpuid_entry2,
    out_count: *mut u32,
) -> c_int {
    let _u = record(Stat::GetHypervCpuid);
    let this = &mut *this;
    let cpuid_entries = from_raw_parts_mut(cpuid_entries, entry_count as usize);
    let mut cpuid_count: usize = 0;
    let ret = this.get_hyperv_cpuid(cpuid_entries, &mut cpuid_count);
    *out_count = cpuid_count as u32;
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_msrs(
    this: *mut crosvm_vcpu,
    msr_count: u32,
    msr_entries: *mut kvm_msr_entry,
    out_count: *mut u32,
) -> c_int {
    let _u = record(Stat::VcpuGetMsrs);
    let this = &mut *this;
    let msr_entries = from_raw_parts_mut(msr_entries, msr_count as usize);
    let mut count: usize = 0;
    let ret = this.get_msrs(msr_entries, &mut count);
    *out_count = count as u32;
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_msrs(
    this: *mut crosvm_vcpu,
    msr_count: u32,
    msr_entries: *const kvm_msr_entry,
) -> c_int {
    let _u = record(Stat::VcpuSetMsrs);
    let this = &mut *this;
    let msr_entries = from_raw_parts(msr_entries, msr_count as usize);
    let ret = this.set_msrs(msr_entries);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_cpuid(
    this: *mut crosvm_vcpu,
    cpuid_count: u32,
    cpuid_entries: *const kvm_cpuid_entry2,
) -> c_int {
    let _u = record(Stat::VcpuSetCpuid);
    let this = &mut *this;
    let cpuid_entries = from_raw_parts(cpuid_entries, cpuid_count as usize);
    let ret = this.set_cpuid(cpuid_entries);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_enable_capability(
    this: *mut crosvm_vcpu,
    capability: u32,
    flags: u32,
    args: *const u64,
) -> c_int {
    let _u = record(Stat::EnableVcpuCapability);
    let this = &mut *this;
    let args = slice::from_raw_parts(args, 4);

    if flags != 0 || args.iter().any(|v| *v != 0) {
        return -EINVAL;
    }

    let ret = this.enable_capability(capability);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_lapic_state(
    this: *mut crosvm_vcpu,
    state: *mut kvm_lapic_state,
) -> c_int {
    let _u = record(Stat::VcpuGetLapicState);
    let this = &mut *this;
    let state = from_raw_parts_mut(state as *mut u8, size_of::<kvm_lapic_state>());
    let ret = this.get_state(vcpu_request::StateSet::LAPIC, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_lapic_state(
    this: *mut crosvm_vcpu,
    state: *const kvm_lapic_state,
) -> c_int {
    let _u = record(Stat::VcpuSetLapicState);
    let this = &mut *this;
    let state = from_raw_parts(state as *mut u8, size_of::<kvm_lapic_state>());
    let ret = this.set_state(vcpu_request::StateSet::LAPIC, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_mp_state(
    this: *mut crosvm_vcpu,
    state: *mut kvm_mp_state,
) -> c_int {
    let _u = record(Stat::VcpuGetMpState);
    let this = &mut *this;
    let state = from_raw_parts_mut(state as *mut u8, size_of::<kvm_mp_state>());
    let ret = this.get_state(vcpu_request::StateSet::MP, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_mp_state(
    this: *mut crosvm_vcpu,
    state: *const kvm_mp_state,
) -> c_int {
    let _u = record(Stat::VcpuSetMpState);
    let this = &mut *this;
    let state = from_raw_parts(state as *mut u8, size_of::<kvm_mp_state>());
    let ret = this.set_state(vcpu_request::StateSet::MP, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_vcpu_events(
    this: *mut crosvm_vcpu,
    events: *mut kvm_vcpu_events,
) -> c_int {
    let _u = record(Stat::VcpuGetVcpuEvents);
    let this = &mut *this;
    let events = from_raw_parts_mut(events as *mut u8, size_of::<kvm_vcpu_events>());
    let ret = this.get_state(vcpu_request::StateSet::EVENTS, events);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_vcpu_events(
    this: *mut crosvm_vcpu,
    events: *const kvm_vcpu_events,
) -> c_int {
    let _u = record(Stat::VcpuSetVcpuEvents);
    let this = &mut *this;
    let events = from_raw_parts(events as *mut u8, size_of::<kvm_vcpu_events>());
    let ret = this.set_state(vcpu_request::StateSet::EVENTS, events);
    to_crosvm_rc(ret)
}
