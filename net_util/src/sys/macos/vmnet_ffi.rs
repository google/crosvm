// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Raw FFI bindings to Apple's vmnet.framework and helper types for
//! constructing Objective-C blocks without external crate dependencies.

#![allow(non_camel_case_types, dead_code)]

use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_void;

// ── vmnet types ──────────────────────────────────────────────────────

/// Opaque vmnet interface handle.
#[repr(C)]
pub struct vmnet_interface {
    _opaque: [u8; 0],
}
pub type interface_ref = *mut vmnet_interface;

/// vmnet return status codes.
pub const VMNET_SUCCESS: u32 = 1000;
pub const VMNET_FAILURE: u32 = 1001;

/// vmnet operating modes.
pub const VMNET_HOST_MODE: u64 = 1000;
pub const VMNET_SHARED_MODE: u64 = 1001;
pub const VMNET_BRIDGED_MODE: u64 = 1002;

/// vmnet interface events.
pub const VMNET_INTERFACE_PACKETS_AVAILABLE: u32 = 1 << 0;

/// Packet descriptor for vmnet read/write.
#[repr(C)]
pub struct vmpktdesc {
    pub vm_pkt_size: usize,
    pub vm_pkt_iov: *mut libc::iovec,
    pub vm_pkt_iovcnt: u32,
    pub vm_flags: u32,
}

// ── Opaque Apple framework types ─────────────────────────────────────

pub type dispatch_queue_t = *mut c_void;
pub type dispatch_semaphore_t = *mut c_void;
pub type xpc_object_t = *mut c_void;
pub const DISPATCH_TIME_FOREVER: u64 = !0;

// ── Objective-C Block ABI ────────────────────────────────────────────
//
// We implement the block ABI manually to avoid depending on the `block2` crate.
// See: https://clang.llvm.org/docs/Block-ABI-Apple.html

extern "C" {
    /// The ISA pointer for stack-allocated blocks.
    static _NSConcreteStackBlock: *const c_void;
}

/// Block descriptor (no copy/dispose helpers needed for stack blocks
/// with trivially copyable captures).
#[repr(C)]
struct BlockDescriptor {
    reserved: u64,
    size: u64,
}

/// An Objective-C block with captured data of type `C`.
///
/// The `invoke` function pointer receives `*mut BlockWithCapture<C>` as its
/// first argument (disguised as `*mut c_void`), followed by the block's
/// declared parameters.
#[repr(C)]
pub struct BlockWithCapture<C> {
    isa: *const c_void,
    flags: c_int,
    reserved: c_int,
    invoke: *const c_void,
    descriptor: *const BlockDescriptor,
    pub capture: C,
}

// Flags for a stack block.
const BLOCK_HAS_STRET: c_int = 0;

impl<C> BlockWithCapture<C> {
    /// Create a new stack-allocated block.
    ///
    /// `invoke` must be an `extern "C"` function whose first argument is
    /// `*mut BlockWithCapture<C>`, followed by the block's declared parameters.
    pub fn new(invoke: *const c_void, capture: C) -> Self {
        static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
            reserved: 0,
            // This size is only used for copy/dispose, which we don't use.
            size: 0,
        };
        BlockWithCapture {
            // SAFETY: _NSConcreteStackBlock is a valid class pointer
            isa: unsafe { _NSConcreteStackBlock },
            flags: BLOCK_HAS_STRET,
            reserved: 0,
            invoke,
            descriptor: &DESCRIPTOR,
            capture,
        }
    }

    /// Return a pointer to this block as a raw void pointer, suitable for
    /// passing to vmnet APIs that expect a block parameter.
    pub fn as_ptr(&mut self) -> *mut c_void {
        self as *mut Self as *mut c_void
    }
}

// ── vmnet.framework FFI ──────────────────────────────────────────────

#[link(name = "vmnet", kind = "framework")]
extern "C" {
    pub static vmnet_operation_mode_key: *const c_char;
    pub static vmnet_mac_address_key: *const c_char;
    pub static vmnet_allocate_mac_address_key: *const c_char;
    pub static vmnet_mtu_key: *const c_char;
    pub static vmnet_max_packet_size_key: *const c_char;

    pub fn vmnet_start_interface(
        interface_desc: xpc_object_t,
        queue: dispatch_queue_t,
        handler: *mut c_void, // block
    ) -> interface_ref;

    pub fn vmnet_interface_set_event_callback(
        interface: interface_ref,
        event_mask: u32, // interface_event_t
        queue: dispatch_queue_t,
        handler: *mut c_void, // block
    ) -> u32; // vmnet_return_t

    pub fn vmnet_read(
        interface: interface_ref,
        packets: *mut vmpktdesc,
        pktcnt: *mut c_int,
    ) -> u32;

    pub fn vmnet_write(
        interface: interface_ref,
        packets: *mut vmpktdesc,
        pktcnt: *mut c_int,
    ) -> u32;

    pub fn vmnet_stop_interface(
        interface: interface_ref,
        queue: dispatch_queue_t,
        handler: *mut c_void, // block
    ) -> u32;
}

// ── XPC dictionary helpers ───────────────────────────────────────────

extern "C" {
    pub fn xpc_dictionary_create(
        keys: *const *const c_char,
        values: *const xpc_object_t,
        count: usize,
    ) -> xpc_object_t;
    pub fn xpc_dictionary_set_uint64(dict: xpc_object_t, key: *const c_char, value: u64);
    pub fn xpc_dictionary_set_bool(dict: xpc_object_t, key: *const c_char, value: bool);
    pub fn xpc_dictionary_get_string(dict: xpc_object_t, key: *const c_char) -> *const c_char;
    pub fn xpc_dictionary_get_uint64(dict: xpc_object_t, key: *const c_char) -> u64;
    pub fn xpc_release(object: xpc_object_t);
}

// ── GCD (Grand Central Dispatch) ─────────────────────────────────────

extern "C" {
    pub fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> dispatch_queue_t;
    pub fn dispatch_release(object: *mut c_void);
    pub fn dispatch_semaphore_create(value: isize) -> dispatch_semaphore_t;
    pub fn dispatch_semaphore_signal(dsema: dispatch_semaphore_t) -> isize;
    pub fn dispatch_semaphore_wait(dsema: dispatch_semaphore_t, timeout: u64) -> isize;
}
