// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(non_camel_case_types)]

//! This module implements the dynamically loaded client library API used by a crosvm plugin,
//! defined in `crosvm.h`. It implements the client half of the plugin protocol, which is defined in
//! the plugin_proto module.
//!
//! To implement the `crosvm.h` C API, each function and struct definition is repeated here, with
//! concrete definitions for each struct. Most functions are thin shims to the underlying object
//! oriented Rust implementation method. Most methods require a request over the crosvm connection,
//! which is done by creating a `MainRequest` or `VcpuRequest` protobuf and sending it over the
//! connection's socket. Then, that socket is read for a `MainResponse` or `VcpuResponse`, which is
//! translated to the appropriate return type for the C API.

extern crate libc;
extern crate sys_util;
extern crate kvm;
extern crate kvm_sys;
extern crate plugin_proto;
extern crate protobuf;

use std::env;
use std::fs::File;
use std::mem::{swap, size_of};
use std::os::raw::{c_int, c_void};
use std::os::unix::io::{AsRawFd, IntoRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::ptr::null_mut;
use std::result;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::slice;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use libc::{E2BIG, ENOTCONN, EINVAL, EPROTO, ENOENT};

use protobuf::{Message, ProtobufEnum, RepeatedField, parse_from_bytes};

use sys_util::Scm;

use kvm::dirty_log_bitmap_size;

use kvm_sys::{kvm_regs, kvm_sregs, kvm_fpu, kvm_debugregs, kvm_xcrs, kvm_msr_entry,
              kvm_cpuid_entry2, kvm_lapic_state, kvm_mp_state, kvm_pic_state, kvm_ioapic_state,
              kvm_pit_state2, kvm_vcpu_events};

use plugin_proto::*;

// Needs to be large enough to receive all the VCPU sockets.
const MAX_DATAGRAM_FD: usize = 32;
// Needs to be large enough for a sizable dirty log.
const MAX_DATAGRAM_SIZE: usize = 0x40000;

const CROSVM_IRQ_ROUTE_IRQCHIP: u32 = 0;
const CROSVM_IRQ_ROUTE_MSI: u32 = 1;

const CROSVM_VCPU_EVENT_KIND_INIT: u32 = 0;
const CROSVM_VCPU_EVENT_KIND_IO_ACCESS: u32 = 1;
const CROSVM_VCPU_EVENT_KIND_PAUSED: u32 = 2;

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

fn proto_error_to_int(e: protobuf::ProtobufError) -> c_int {
    match e {
        protobuf::ProtobufError::IoError(e) => e.raw_os_error().unwrap_or(EINVAL),
        _ => EINVAL,
    }
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
        self.0
            .compare_and_swap(id as usize + 1, id as usize, Ordering::Relaxed);
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum Stat {
    IoEventFd,
    MemoryGetDirtyLog,
    IrqEventGetFd,
    IrqEventGetResampleFd,
    Connect,
    DestroyConnection,
    GetShutdownEventFd,
    CheckExtentsion,
    GetSupportedCpuid,
    GetEmulatedCpuid,
    GetMsrIndexList,
    NetGetConfig,
    ReserveRange,
    SetIrq,
    SetIrqRouting,
    GetPicState,
    SetPicState,
    GetIoapicState,
    SetIoapicState,
    GetPitState,
    SetPitState,
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

    Count,
}

#[derive(Clone, Copy)]
struct StatEntry {
    count: u64,
    total: u64,
    max: u64,
}

struct StatUpdater {
    idx: usize,
    start: Instant,
}

struct GlobalStats {
    entries: [StatEntry; Stat::Count as usize],
}

static mut STATS: GlobalStats = GlobalStats {
        entries: [ StatEntry { count: 0, total: 0, max: 0};
                   Stat::Count as usize]
};

impl GlobalStats {
    // Record latency from this call until the end of block/function
    // Example:
    // pub fn foo() {
    //     let _u = STATS.record(Stat::Foo);
    //     // ... some operation ...
    // }
    // The added STATS.record will record latency of "some operation" and will
    // update max and average latencies for it under Stats::Foo. Subsequent
    // call to STATS.print() will print out max and average latencies for all
    // operations that were performed.
    fn record(&mut self, idx: Stat) -> StatUpdater {
        StatUpdater { idx: idx as usize, start: Instant::now() }
    }

    fn print(&self) {
        for idx in 0 .. Stat::Count as usize {
            let ref e = self.entries[idx as usize];
            let stat = unsafe { std::mem::transmute::<u8,Stat>(idx as u8) };
            if e.count > 0 {
                println!("Stat::{:?}: avg {}ns max {}ns",
                         stat, e.total / e.count, e.max);
            }
        }
    }

    fn update(&mut self, idx: usize, elapsed_nanos: u64) {
        let ref mut e = self.entries[idx as usize];
        e.total += elapsed_nanos;
        if e.max < elapsed_nanos {
            e.max = elapsed_nanos;
        }
        e.count += 1;
    }
}

impl Drop for StatUpdater {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        let elapsed_nanos = elapsed.as_secs() * 1000000000 +
                            elapsed.subsec_nanos() as u64;
        // Unsafe due to racy access - OK for stats
        unsafe { STATS.update(self.idx, elapsed_nanos); }
    }
}

pub struct crosvm {
    id_allocator: Arc<IdAllocator>,
    socket: UnixDatagram,
    fd_messager: Scm,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    vcpus: Arc<Vec<crosvm_vcpu>>,
}

impl crosvm {
    fn from_connection(socket: UnixDatagram) -> result::Result<crosvm, c_int> {
        let mut crosvm = crosvm {
            id_allocator: Default::default(),
            socket,
            fd_messager: Scm::new(MAX_DATAGRAM_FD),
            request_buffer: Vec::new(),
            response_buffer: vec![0; MAX_DATAGRAM_SIZE],
            vcpus: Default::default(),
        };
        crosvm.load_all_vcpus()?;
        Ok(crosvm)
    }

    fn new(id_allocator: Arc<IdAllocator>,
           socket: UnixDatagram,
           vcpus: Arc<Vec<crosvm_vcpu>>)
           -> crosvm {
        crosvm {
            id_allocator,
            socket,
            fd_messager: Scm::new(MAX_DATAGRAM_FD),
            request_buffer: Vec::new(),
            response_buffer: vec![0; MAX_DATAGRAM_SIZE],
            vcpus,
        }
    }

    fn get_id_allocator(&self) -> &IdAllocator {
        &*self.id_allocator
    }

    fn main_transaction(&mut self,
                        request: &MainRequest,
                        fds: &[RawFd])
                        -> result::Result<(MainResponse, Vec<File>), c_int> {
        self.request_buffer.clear();
        request
            .write_to_vec(&mut self.request_buffer)
            .map_err(proto_error_to_int)?;
        self.fd_messager
            .send(&self.socket, &[self.request_buffer.as_slice()], fds)
            .map_err(|e| -e.errno())?;

        let mut datagram_files = Vec::new();
        let msg_size = self.fd_messager
            .recv(&self.socket,
                  &mut [&mut self.response_buffer],
                  &mut datagram_files)
            .map_err(|e| -e.errno())?;

        let response: MainResponse = parse_from_bytes(&self.response_buffer[..msg_size])
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
            Some(new_socket) => {
                Ok(crosvm::new(self.id_allocator.clone(),
                               fd_cast(new_socket),
                               self.vcpus.clone()))
            }
            None => Err(EPROTO),
        }
    }

    fn destroy(&mut self, id: u32) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        r.mut_destroy().id = id;
        self.main_transaction(&r, &[])?;
        self.get_id_allocator().free(id);
        // Unsafe due to racy access - OK for stats
        if std::env::var("CROSVM_STATS").is_ok() {
            unsafe { STATS.print(); }
        }
        Ok(())
    }

    // Only call this at `from_connection` function.
    fn load_all_vcpus(&mut self) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        r.mut_get_vcpus();
        let (_, files) = self.main_transaction(&r, &[])?;
        if files.is_empty() {
            return Err(EPROTO);
        }
        let vcpus = files
            .into_iter()
            .map(|f| crosvm_vcpu::new(fd_cast(f)))
            .collect();
        // Only called once by the `from_connection` constructor, which makes a new unique
        // `self.vcpus`.
        let self_vcpus = Arc::get_mut(&mut self.vcpus).unwrap();
        *self_vcpus = vcpus;
        Ok(())
    }

    fn get_shutdown_eventfd(&mut self) -> result::Result<File, c_int> {
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
        Ok(response.get_check_extension().has_extension)
    }

    fn get_supported_cpuid(&mut self, cpuid_entries: &mut [kvm_cpuid_entry2])
                           -> result::Result<usize, c_int> {
        let mut r = MainRequest::new();
        r.mut_get_supported_cpuid();

        let (response, _) = self.main_transaction(&r, &[])?;
        if !response.has_get_supported_cpuid() {
            return Err(EPROTO);
        }

        let supported_cpuids: &MainResponse_CpuidResponse = response.get_get_supported_cpuid();
        if supported_cpuids.get_entries().len() > cpuid_entries.len() {
            return Err(E2BIG);
        }

        for (proto_entry, kvm_entry) in
            supported_cpuids.get_entries().iter()
                .zip(cpuid_entries.iter_mut()) {
            *kvm_entry = cpuid_proto_to_kvm(proto_entry);
        }

        Ok(supported_cpuids.get_entries().len())
    }

    fn get_emulated_cpuid(&mut self, cpuid_entries: &mut [kvm_cpuid_entry2])
                           -> result::Result<usize, c_int> {
        let mut r = MainRequest::new();
        r.mut_get_emulated_cpuid();

        let (response, _) = self.main_transaction(&r, &[])?;
        if !response.has_get_emulated_cpuid() {
            return Err(EPROTO);
        }

        let emulated_cpuids: &MainResponse_CpuidResponse = response.get_get_emulated_cpuid();
        if emulated_cpuids.get_entries().len() > cpuid_entries.len() {
            return Err(E2BIG);
        }

        for (proto_entry, kvm_entry) in
            emulated_cpuids.get_entries().iter()
                .zip(cpuid_entries.iter_mut()) {
            *kvm_entry = cpuid_proto_to_kvm(proto_entry);
        }

        Ok(emulated_cpuids.get_entries().len())
    }

    fn get_msr_index_list(&mut self, msr_indices: &mut [u32])
                           -> result::Result<usize, c_int> {
        let mut r = MainRequest::new();
        r.mut_get_msr_index_list();

        let (response, _) = self.main_transaction(&r, &[])?;
        if !response.has_get_msr_index_list() {
            return Err(EPROTO);
        }

        let msr_list: &MainResponse_MsrListResponse = response.get_get_msr_index_list();
        if msr_list.get_indices().len() > msr_indices.len() {
            return Err(E2BIG);
        }

        for (proto_entry, kvm_entry) in
            msr_list.get_indices().iter()
                .zip(msr_indices.iter_mut()) {
            *kvm_entry = *proto_entry;
        }

        Ok(msr_list.get_indices().len())
    }

    fn reserve_range(&mut self, space: u32, start: u64, length: u64) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        {
            let reserve: &mut MainRequest_ReserveRange = r.mut_reserve_range();
            reserve.space = AddressSpace::from_i32(space as i32).ok_or(EINVAL)?;
            reserve.start = start;
            reserve.length = length;
        }
        self.main_transaction(&r, &[])?;
        Ok(())
    }

    fn set_irq(&mut self, irq_id: u32, active: bool) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        {
            let set_irq: &mut MainRequest_SetIrq = r.mut_set_irq();
            set_irq.irq_id = irq_id;
            set_irq.active = active;
        }
        self.main_transaction(&r, &[])?;
        Ok(())
    }

    fn set_irq_routing(&mut self, routing: &[crosvm_irq_route]) -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        {
            let set_irq_routing: &mut RepeatedField<MainRequest_SetIrqRouting_Route> =
                r.mut_set_irq_routing().mut_routes();
            for route in routing {
                let mut entry = MainRequest_SetIrqRouting_Route::new();
                entry.irq_id = route.irq_id;
                match route.kind {
                    CROSVM_IRQ_ROUTE_IRQCHIP => {
                        let irqchip: &mut MainRequest_SetIrqRouting_Route_Irqchip;
                        irqchip = entry.mut_irqchip();
                        // Safe because route.kind indicates which union field is valid.
                        irqchip.irqchip = unsafe { route.route.irqchip }.irqchip;
                        irqchip.pin = unsafe { route.route.irqchip }.pin;
                    }
                    CROSVM_IRQ_ROUTE_MSI => {
                        let msi: &mut MainRequest_SetIrqRouting_Route_Msi = entry.mut_msi();
                        // Safe because route.kind indicates which union field is valid.
                        msi.address = unsafe { route.route.msi }.address;
                        msi.data = unsafe { route.route.msi }.data;
                    }
                    _ => return Err(EINVAL),
                }
                set_irq_routing.push(entry);
            }
        }
        self.main_transaction(&r, &[])?;
        Ok(())
    }

    fn get_state(&mut self, state_set: MainRequest_StateSet, out: &mut [u8])
                 -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        r.mut_get_state().set = state_set;
        let (response, _) = self.main_transaction(&r, &[])?;
        if !response.has_get_state() {
            return Err(EPROTO);
        }
        let get_state: &MainResponse_GetState = response.get_get_state();
        if get_state.state.len() != out.len() {
            return Err(EPROTO);
        }
        out.copy_from_slice(&get_state.state);
        Ok(())
    }

    fn set_state(&mut self, state_set: MainRequest_StateSet, new_state: &[u8])
                 -> result::Result<(), c_int> {
        let mut r = MainRequest::new();
        {
            let set_state: &mut MainRequest_SetState = r.mut_set_state();
            set_state.set = state_set;
            set_state.state = new_state.to_vec();
        }
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
        {
            let pause_vcpus: &mut MainRequest_PauseVcpus = r.mut_pause_vcpus();
            pause_vcpus.cpu_mask = cpu_mask;
            pause_vcpus.user = user as u64;
        }
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
        let config = response.get_get_net_config();

        match files.pop() {
            Some(f) => {
                let mut net_config = crosvm_net_config {
                    tap_fd: f.into_raw_fd(),
                    host_ipv4_address: config.host_ipv4_address,
                    netmask: config.netmask,
                    host_mac_address: [0; 6],
                    _reserved: [0; 2],
                };

                let mac_addr = config.get_host_mac_address();
                if mac_addr.len() != net_config.host_mac_address.len() {
                    return Err(EPROTO)
                }
                net_config.host_mac_address.copy_from_slice(mac_addr);

                Ok(net_config)
            },
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
    unsafe fn create(crosvm: &mut crosvm,
                     space: u32,
                     addr: u64,
                     length: u32,
                     datamatch: *const u8)
                     -> result::Result<crosvm_io_event, c_int> {
        let datamatch = match length {
            0 => 0,
            1 => *(datamatch as *const u8) as u64,
            2 => *(datamatch as *const u16) as u64,
            4 => *(datamatch as *const u32) as u64,
            8 => *(datamatch as *const u64) as u64,
            _ => return Err(EINVAL),
        };
        Self::safe_create(crosvm, space, addr, length, datamatch)
    }

    fn safe_create(crosvm: &mut crosvm,
                   space: u32,
                   addr: u64,
                   length: u32,
                   datamatch: u64)
                   -> result::Result<crosvm_io_event, c_int> {
        let id = crosvm.get_id_allocator().alloc();
        let mut r = MainRequest::new();
        {
            let create: &mut MainRequest_Create = r.mut_create();
            create.id = id;
            let io_event: &mut MainRequest_Create_IoEvent = create.mut_io_event();
            io_event.space = AddressSpace::from_i32(space as i32).ok_or(EINVAL)?;
            io_event.address = addr;
            io_event.length = length;
            io_event.datamatch = datamatch;
        }
        let ret = match crosvm.main_transaction(&r, &[]) {
            Ok((_, mut files)) => {
                match files.pop() {
                    Some(evt) => return Ok(crosvm_io_event { id, evt }),
                    None => EPROTO,
                }
            }
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
    let _u = STATS.record(Stat::IoEventFd);
    (*this).evt.as_raw_fd()
}

pub struct crosvm_memory {
    id: u32,
    length: u64,
}

impl crosvm_memory {
    fn create(crosvm: &mut crosvm,
              fd: c_int,
              offset: u64,
              length: u64,
              start: u64,
              read_only: bool,
              dirty_log: bool)
              -> result::Result<crosvm_memory, c_int> {
        const PAGE_MASK: u64 = 0x0fff;
        if offset & PAGE_MASK != 0 || length & PAGE_MASK != 0 {
            return Err(EINVAL);
        }
        let id = crosvm.get_id_allocator().alloc();
        let mut r = MainRequest::new();
        {
            let create: &mut MainRequest_Create = r.mut_create();
            create.id = id;
            let memory: &mut MainRequest_Create_Memory = create.mut_memory();
            memory.offset = offset;
            memory.start = start;
            memory.length = length;
            memory.read_only = read_only;
            memory.dirty_log = dirty_log;
        }
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
    crosvm_create_memory(fd: c_int, offset: u64, length: u64, start: u64, read_only: bool, dirty_log: bool),
    crosvm_destroy_memory,
);

#[no_mangle]
pub unsafe extern "C" fn crosvm_memory_get_dirty_log(crosvm: *mut crosvm,
                                                     this: *mut crosvm_memory,
                                                     log: *mut u8)
                                                     -> c_int {
    let _u = STATS.record(Stat::MemoryGetDirtyLog);
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
        {
            let create: &mut MainRequest_Create = r.mut_create();
            create.id = id;
            let irq_event: &mut MainRequest_Create_IrqEvent = create.mut_irq_event();
            irq_event.irq_id = irq_id;
            irq_event.resample = true;
        }
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
    let _u = STATS.record(Stat::IrqEventGetFd);
    (*this).trigger_evt.as_raw_fd()
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_irq_event_get_resample_fd(this: *mut crosvm_irq_event) -> c_int {
    let _u = STATS.record(Stat::IrqEventGetResampleFd);
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
    __reserved1: u8,
}

#[repr(C)]
union anon_vcpu_event {
    io_access: anon_io_access,
    user: *mut c_void,
    #[allow(dead_code)]
    __reserved: [u8; 64],
}

#[repr(C)]
pub struct crosvm_vcpu_event {
    kind: u32,
    __reserved: [u8; 4],
    event: anon_vcpu_event,
}

pub struct crosvm_vcpu {
    socket: UnixDatagram,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    resume_data: Vec<u8>,
}

impl crosvm_vcpu {
    fn new(socket: UnixDatagram) -> crosvm_vcpu {
        crosvm_vcpu {
            socket,
            request_buffer: Vec::new(),
            response_buffer: vec![0; MAX_DATAGRAM_SIZE],
            resume_data: Vec::new(),
        }
    }

    fn vcpu_transaction(&mut self, request: &VcpuRequest) -> result::Result<VcpuResponse, c_int> {
        self.request_buffer.clear();
        request
            .write_to_vec(&mut self.request_buffer)
            .map_err(proto_error_to_int)?;
        self.socket
            .send(self.request_buffer.as_slice())
            .map_err(|e| -e.raw_os_error().unwrap_or(EINVAL))?;

        let msg_size = self.socket
            .recv(&mut self.response_buffer)
            .map_err(|e| -e.raw_os_error().unwrap_or(EINVAL))?;

        let response: VcpuResponse = parse_from_bytes(&self.response_buffer[..msg_size])
            .map_err(proto_error_to_int)?;
        if response.errno != 0 {
            return Err(response.errno);
        }
        Ok(response)
    }

    fn wait(&mut self, event: &mut crosvm_vcpu_event) -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        r.mut_wait();
        let mut response: VcpuResponse = self.vcpu_transaction(&r)?;
        if !response.has_wait() {
            return Err(EPROTO);
        }
        let wait: &mut VcpuResponse_Wait = response.mut_wait();
        if wait.has_init() {
            event.kind = CROSVM_VCPU_EVENT_KIND_INIT;
            Ok(())
        } else if wait.has_io() {
            let mut io: VcpuResponse_Wait_Io = wait.take_io();
            event.kind = CROSVM_VCPU_EVENT_KIND_IO_ACCESS;
            event.event.io_access = anon_io_access {
                address_space: io.space.value() as u32,
                __reserved0: Default::default(),
                address: io.address,
                data: io.data.as_mut_ptr(),
                length: io.data.len() as u32,
                is_write: io.is_write as u8,
                __reserved1: Default::default(),
            };
            self.resume_data = io.data;
            Ok(())
        } else if wait.has_user() {
            let user: &VcpuResponse_Wait_User = wait.get_user();
            event.kind = CROSVM_VCPU_EVENT_KIND_PAUSED;
            event.event.user = user.user as *mut c_void;
            Ok(())
        } else {
            Err(EPROTO)
        }
    }

    fn resume(&mut self) -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        {
            let resume: &mut VcpuRequest_Resume = r.mut_resume();
            swap(&mut resume.data, &mut self.resume_data);
        }
        self.vcpu_transaction(&r)?;
        Ok(())
    }

    fn get_state(&mut self,
                 state_set: VcpuRequest_StateSet,
                 out: &mut [u8])
                 -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        r.mut_get_state().set = state_set;
        let response = self.vcpu_transaction(&r)?;
        if !response.has_get_state() {
            return Err(EPROTO);
        }
        let get_state: &VcpuResponse_GetState = response.get_get_state();
        if get_state.state.len() != out.len() {
            return Err(EPROTO);
        }
        out.copy_from_slice(&get_state.state);
        Ok(())
    }

    fn set_state(&mut self,
                 state_set: VcpuRequest_StateSet,
                 new_state: &[u8])
                 -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        {
            let set_state: &mut VcpuRequest_SetState = r.mut_set_state();
            set_state.set = state_set;
            set_state.state = new_state.to_vec();
        }
        self.vcpu_transaction(&r)?;
        Ok(())
    }

    fn get_msrs(&mut self, msr_entries: &mut [kvm_msr_entry]) -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        {
            let entry_indices: &mut Vec<u32> = r.mut_get_msrs().mut_entry_indices();
            for entry in msr_entries.iter() {
                entry_indices.push(entry.index);
            }
        }
        let response = self.vcpu_transaction(&r)?;
        if !response.has_get_msrs() {
            return Err(EPROTO);
        }
        let get_msrs: &VcpuResponse_GetMsrs = response.get_get_msrs();
        if get_msrs.get_entry_data().len() != msr_entries.len() {
            return Err(EPROTO);
        }
        for (&msr_data, msr_entry) in
            get_msrs
                .get_entry_data()
                .iter()
                .zip(msr_entries.iter_mut()) {
            msr_entry.data = msr_data;
        }
        Ok(())
    }

    fn set_msrs(&mut self, msr_entries: &[kvm_msr_entry]) -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        {
            let set_msrs_entries: &mut RepeatedField<VcpuRequest_MsrEntry> = r.mut_set_msrs()
                .mut_entries();
            for msr_entry in msr_entries.iter() {
                let mut entry = VcpuRequest_MsrEntry::new();
                entry.index = msr_entry.index;
                entry.data = msr_entry.data;
                set_msrs_entries.push(entry);
            }
        }
        self.vcpu_transaction(&r)?;
        Ok(())
    }

    fn set_cpuid(&mut self, cpuid_entries: &[kvm_cpuid_entry2]) -> result::Result<(), c_int> {
        let mut r = VcpuRequest::new();
        {
            let set_cpuid_entries: &mut RepeatedField<CpuidEntry> = r.mut_set_cpuid().mut_entries();
            for cpuid_entry in cpuid_entries.iter() {
                set_cpuid_entries.push(cpuid_kvm_to_proto(cpuid_entry));
            }
        }
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
    let _u = STATS.record(Stat::Connect);
    let socket_name = match env::var("CROSVM_SOCKET") {
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
    let _u = STATS.record(Stat::NewConnection);
    let self_ = &mut (*self_);
    match self_.try_clone() {
       Ok(cloned) => {
           *out = Box::into_raw(Box::new(cloned));
           0
       }
       Err(e) => -e
    }
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_destroy_connection(self_: *mut *mut crosvm) -> c_int {
    let _u = STATS.record(Stat::DestroyConnection);
    Box::from_raw(*self_);
    *self_ = null_mut();
    0
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_shutdown_eventfd(self_: *mut crosvm) -> c_int {
    let _u = STATS.record(Stat::GetShutdownEventFd);
    let self_ = &mut (*self_);
    match self_.get_shutdown_eventfd() {
        Ok(f) => f.into_raw_fd(),
        Err(e) => -e,
    }
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_check_extension(self_: *mut crosvm,
                                                extension: u32,
                                                has_extension: *mut bool)
                                                -> c_int {
    let _u = STATS.record(Stat::CheckExtentsion);
    let self_ = &mut (*self_);
    let ret = self_.check_extension(extension);

    if let Ok(supported) = ret {
        *has_extension = supported;
    }
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C"
fn crosvm_get_supported_cpuid(this: *mut crosvm,
                              entry_count: u32,
                              cpuid_entries: *mut kvm_cpuid_entry2,
                              out_count: *mut u32)
                              -> c_int {
    let _u = STATS.record(Stat::GetSupportedCpuid);
    let this = &mut *this;
    let cpuid_entries = from_raw_parts_mut(cpuid_entries, entry_count as usize);
    let ret = this.get_supported_cpuid(cpuid_entries);

    if let Ok(num) = ret {
        *out_count = num as u32;
    }
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C"
fn crosvm_get_emulated_cpuid(this: *mut crosvm,
                             entry_count: u32,
                             cpuid_entries: *mut kvm_cpuid_entry2,
                             out_count: *mut u32)
                             -> c_int {
    let _u = STATS.record(Stat::GetEmulatedCpuid);
    let this = &mut *this;
    let cpuid_entries = from_raw_parts_mut(cpuid_entries, entry_count as usize);
    let ret = this.get_emulated_cpuid(cpuid_entries);

    if let Ok(num) = ret {
        *out_count = num as u32;
    }
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C"
fn crosvm_get_msr_index_list(this: *mut crosvm,
                             entry_count: u32,
                             msr_indices: *mut u32,
                             out_count: *mut u32)
                             -> c_int {
    let _u = STATS.record(Stat::GetMsrIndexList);
    let this = &mut *this;
    let msr_indices = from_raw_parts_mut(msr_indices, entry_count as usize);
    let ret = this.get_msr_index_list(msr_indices);

    if let Ok(num) = ret {
        *out_count = num as u32;
    }
    to_crosvm_rc(ret)
}


#[no_mangle]
pub unsafe extern "C" fn crosvm_net_get_config(self_: *mut crosvm,
                                               config: *mut crosvm_net_config)
                                               -> c_int {
    let _u = STATS.record(Stat::NetGetConfig);
    let self_ = &mut (*self_);
    let ret = self_.get_net_config();

    if let Ok(c) = ret {
        *config = c;
    }

    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_reserve_range(self_: *mut crosvm,
                                              space: u32,
                                              start: u64,
                                              length: u64)
                                              -> c_int {
    let _u = STATS.record(Stat::ReserveRange);
    let self_ = &mut (*self_);
    let ret = self_.reserve_range(space, start, length);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_irq(self_: *mut crosvm, irq_id: u32, active: bool) -> c_int {
    let _u = STATS.record(Stat::SetIrq);
    let self_ = &mut (*self_);
    let ret = self_.set_irq(irq_id, active);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_irq_routing(self_: *mut crosvm,
                                                route_count: u32,
                                                routes: *const crosvm_irq_route)
                                                -> c_int {
    let _u = STATS.record(Stat::SetIrqRouting);
    let self_ = &mut (*self_);
    let ret = self_.set_irq_routing(slice::from_raw_parts(routes, route_count as usize));
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_pic_state(this: *mut crosvm,
                                              primary: bool,
                                              state: *mut kvm_pic_state)
                                              -> c_int {
    let _u = STATS.record(Stat::GetPicState);
    let this = &mut *this;
    let state_set = if primary { MainRequest_StateSet::PIC0 } else { MainRequest_StateSet::PIC1 };
    let state = from_raw_parts_mut(state as *mut u8, size_of::<kvm_pic_state>());
    let ret = this.get_state(state_set, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_pic_state(this: *mut crosvm,
                                              primary: bool,
                                              state: *mut kvm_pic_state)
                                              -> c_int {
    let _u = STATS.record(Stat::SetPicState);
    let this = &mut *this;
    let state_set = if primary { MainRequest_StateSet::PIC0 } else { MainRequest_StateSet::PIC1 };
    let state = from_raw_parts(state as *mut u8, size_of::<kvm_pic_state>());
    let ret = this.set_state(state_set, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_ioapic_state(this: *mut crosvm,
                                                 state: *mut kvm_ioapic_state)
                                                 -> c_int {
    let _u = STATS.record(Stat::GetIoapicState);
    let this = &mut *this;
    let state = from_raw_parts_mut(state as *mut u8, size_of::<kvm_ioapic_state>());
    let ret = this.get_state(MainRequest_StateSet::IOAPIC, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_ioapic_state(this: *mut crosvm,
                                                 state: *const kvm_ioapic_state)
                                                 -> c_int {

    let _u = STATS.record(Stat::SetIoapicState);
    let this = &mut *this;
    let state = from_raw_parts(state as *mut u8, size_of::<kvm_ioapic_state>());
    let ret = this.set_state(MainRequest_StateSet::IOAPIC, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_pit_state(this: *mut crosvm,
                                              state: *mut kvm_pit_state2)
                                              -> c_int {
    let _u = STATS.record(Stat::GetPitState);
    let this = &mut *this;
    let state = from_raw_parts_mut(state as *mut u8, size_of::<kvm_pit_state2>());
    let ret = this.get_state(MainRequest_StateSet::PIT, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_pit_state(this: *mut crosvm,
                                              state: *const kvm_pit_state2)
                                              -> c_int {
    let _u = STATS.record(Stat::SetPitState);
    let this = &mut *this;
    let state = from_raw_parts(state as *mut u8, size_of::<kvm_pit_state2>());
    let ret = this.set_state(MainRequest_StateSet::PIT, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_set_identity_map_addr(self_: *mut crosvm, addr: u32) -> c_int {
    let _u = STATS.record(Stat::SetIdentityMapAddr);
    let self_ = &mut (*self_);
    let ret = self_.set_identity_map_addr(addr);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_pause_vcpus(self_: *mut crosvm,
                                            cpu_mask: u64,
                                            user: *mut c_void)
                                            -> c_int {
    let _u = STATS.record(Stat::PauseVcpus);
    let self_ = &mut (*self_);
    let ret = self_.pause_vcpus(cpu_mask, user);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_start(self_: *mut crosvm) -> c_int {
    let _u = STATS.record(Stat::Start);
    let self_ = &mut (*self_);
    let ret = self_.start();
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_get_vcpu(self_: *mut crosvm,
                                         cpu_id: u32,
                                         out: *mut *mut crosvm_vcpu)
                                         -> c_int {
    let _u = STATS.record(Stat::GetVcpu);
    let self_ = &mut (*self_);
    let ret = self_.get_vcpu(cpu_id);

    if let Ok(vcpu) = ret {
        *out = vcpu;
    }
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_wait(this: *mut crosvm_vcpu,
                                          event: *mut crosvm_vcpu_event)
                                          -> c_int {
    let _u = STATS.record(Stat::VcpuWait);
    let this = &mut *this;
    let event = &mut *event;
    let ret = this.wait(event);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_resume(this: *mut crosvm_vcpu) -> c_int {
    let _u = STATS.record(Stat::VcpuResume);
    let this = &mut *this;
    let ret = this.resume();
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_regs(this: *mut crosvm_vcpu,
                                              regs: *mut kvm_regs)
                                              -> c_int {
    let _u = STATS.record(Stat::VcpuGetRegs);
    let this = &mut *this;
    let regs = from_raw_parts_mut(regs as *mut u8, size_of::<kvm_regs>());
    let ret = this.get_state(VcpuRequest_StateSet::REGS, regs);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_regs(this: *mut crosvm_vcpu,
                                              regs: *const kvm_regs)
                                              -> c_int {
    let _u = STATS.record(Stat::VcpuSetRegs);
    let this = &mut *this;
    let regs = from_raw_parts(regs as *mut u8, size_of::<kvm_regs>());
    let ret = this.set_state(VcpuRequest_StateSet::REGS, regs);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_sregs(this: *mut crosvm_vcpu,
                                               sregs: *mut kvm_sregs)
                                               -> c_int {
    let _u = STATS.record(Stat::VcpuGetSregs);
    let this = &mut *this;
    let sregs = from_raw_parts_mut(sregs as *mut u8, size_of::<kvm_sregs>());
    let ret = this.get_state(VcpuRequest_StateSet::SREGS, sregs);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_sregs(this: *mut crosvm_vcpu,
                                               sregs: *const kvm_sregs)
                                               -> c_int {
    let _u = STATS.record(Stat::VcpuSetSregs);
    let this = &mut *this;
    let sregs = from_raw_parts(sregs as *mut u8, size_of::<kvm_sregs>());
    let ret = this.set_state(VcpuRequest_StateSet::SREGS, sregs);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_fpu(this: *mut crosvm_vcpu, fpu: *mut kvm_fpu) -> c_int {
    let _u = STATS.record(Stat::GetFpu);
    let this = &mut *this;
    let fpu = from_raw_parts_mut(fpu as *mut u8, size_of::<kvm_fpu>());
    let ret = this.get_state(VcpuRequest_StateSet::FPU, fpu);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_fpu(this: *mut crosvm_vcpu, fpu: *const kvm_fpu) -> c_int {
    let _u = STATS.record(Stat::SetFpu);
    let this = &mut *this;
    let fpu = from_raw_parts(fpu as *mut u8, size_of::<kvm_fpu>());
    let ret = this.set_state(VcpuRequest_StateSet::FPU, fpu);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_debugregs(this: *mut crosvm_vcpu,
                                                   dregs: *mut kvm_debugregs)
                                                   -> c_int {
    let _u = STATS.record(Stat::GetDebugRegs);
    let this = &mut *this;
    let dregs = from_raw_parts_mut(dregs as *mut u8, size_of::<kvm_debugregs>());
    let ret = this.get_state(VcpuRequest_StateSet::DEBUGREGS, dregs);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_debugregs(this: *mut crosvm_vcpu,
                                                   dregs: *const kvm_debugregs)
                                                   -> c_int {
    let _u = STATS.record(Stat::SetDebugRegs);
    let this = &mut *this;
    let dregs = from_raw_parts(dregs as *mut u8, size_of::<kvm_debugregs>());
    let ret = this.set_state(VcpuRequest_StateSet::DEBUGREGS, dregs);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_xcrs(this: *mut crosvm_vcpu,
                                              xcrs: *mut kvm_xcrs)
                                              -> c_int {
    let _u = STATS.record(Stat::GetXCRegs);
    let this = &mut *this;
    let xcrs = from_raw_parts_mut(xcrs as *mut u8, size_of::<kvm_xcrs>());
    let ret = this.get_state(VcpuRequest_StateSet::XCREGS, xcrs);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_xcrs(this: *mut crosvm_vcpu,
                                              xcrs: *const kvm_xcrs)
                                              -> c_int {
    let _u = STATS.record(Stat::SetXCRegs);
    let this = &mut *this;
    let xcrs = from_raw_parts(xcrs as *mut u8, size_of::<kvm_xcrs>());
    let ret = this.set_state(VcpuRequest_StateSet::XCREGS, xcrs);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_msrs(this: *mut crosvm_vcpu,
                                              msr_count: u32,
                                              msr_entries: *mut kvm_msr_entry)
                                              -> c_int {
    let _u = STATS.record(Stat::VcpuGetMsrs);
    let this = &mut *this;
    let msr_entries = from_raw_parts_mut(msr_entries, msr_count as usize);
    let ret = this.get_msrs(msr_entries);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_msrs(this: *mut crosvm_vcpu,
                                              msr_count: u32,
                                              msr_entries: *const kvm_msr_entry)
                                              -> c_int {
    let _u = STATS.record(Stat::VcpuSetMsrs);
    let this = &mut *this;
    let msr_entries = from_raw_parts(msr_entries, msr_count as usize);
    let ret = this.set_msrs(msr_entries);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_cpuid(this: *mut crosvm_vcpu,
                                               cpuid_count: u32,
                                               cpuid_entries: *const kvm_cpuid_entry2)
                                               -> c_int {
    let _u = STATS.record(Stat::VcpuSetCpuid);
    let this = &mut *this;
    let cpuid_entries = from_raw_parts(cpuid_entries, cpuid_count as usize);
    let ret = this.set_cpuid(cpuid_entries);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_lapic_state(this: *mut crosvm_vcpu,
                                                     state: *mut kvm_lapic_state)
                                                     -> c_int {
    let _u = STATS.record(Stat::VcpuGetLapicState);
    let this = &mut *this;
    let state = from_raw_parts_mut(state as *mut u8, size_of::<kvm_lapic_state>());
    let ret = this.get_state(VcpuRequest_StateSet::LAPIC, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_lapic_state(this: *mut crosvm_vcpu,
                                                     state: *const kvm_lapic_state)
                                                     -> c_int {

    let _u = STATS.record(Stat::VcpuSetLapicState);
    let this = &mut *this;
    let state = from_raw_parts(state as *mut u8, size_of::<kvm_lapic_state>());
    let ret = this.set_state(VcpuRequest_StateSet::LAPIC, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_mp_state(this: *mut crosvm_vcpu,
                                                  state: *mut kvm_mp_state)
                                                  -> c_int {
    let _u = STATS.record(Stat::VcpuGetMpState);
    let this = &mut *this;
    let state = from_raw_parts_mut(state as *mut u8, size_of::<kvm_mp_state>());
    let ret = this.get_state(VcpuRequest_StateSet::MP, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_mp_state(this: *mut crosvm_vcpu,
                                                  state: *const kvm_mp_state)
                                                  -> c_int {
    let _u = STATS.record(Stat::VcpuSetMpState);
    let this = &mut *this;
    let state = from_raw_parts(state as *mut u8, size_of::<kvm_mp_state>());
    let ret = this.set_state(VcpuRequest_StateSet::MP, state);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_get_vcpu_events(this: *mut crosvm_vcpu,
                                                     events: *mut kvm_vcpu_events)
                                                     -> c_int {
    let _u = STATS.record(Stat::VcpuGetVcpuEvents);
    let this = &mut *this;
    let events = from_raw_parts_mut(events as *mut u8,
                                    size_of::<kvm_vcpu_events>());
    let ret = this.get_state(VcpuRequest_StateSet::EVENTS, events);
    to_crosvm_rc(ret)
}

#[no_mangle]
pub unsafe extern "C" fn crosvm_vcpu_set_vcpu_events(this: *mut crosvm_vcpu,
                                                     events: *const kvm_vcpu_events)
                                                     -> c_int {
    let _u = STATS.record(Stat::VcpuSetVcpuEvents);
    let this = &mut *this;
    let events = from_raw_parts(events as *mut u8,
                                size_of::<kvm_vcpu_events>());
    let ret = this.set_state(VcpuRequest_StateSet::EVENTS, events);
    to_crosvm_rc(ret)
}
