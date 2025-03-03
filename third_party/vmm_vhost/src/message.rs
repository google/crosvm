// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Define communication messages for the vhost-user protocol.
//!
//! For message definition, please refer to the [vhost-user spec](https://github.com/qemu/qemu/blob/f7526eece29cd2e36a63b6703508b24453095eb8/docs/interop/vhost-user.txt).

#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use std::fmt::Debug;
use std::marker::PhantomData;

use base::Protection;
use bitflags::bitflags;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use crate::VringConfigData;

/// The VhostUserMemory message has variable message size and variable number of attached file
/// descriptors. Each user memory region entry in the message payload occupies 32 bytes,
/// so setting maximum number of attached file descriptors based on the maximum message size.
/// But rust only implements Default and AsMut traits for arrays with 0 - 32 entries, so further
/// reduce the maximum number...
// pub const MAX_ATTACHED_FD_ENTRIES: usize = (MAX_MSG_SIZE - 8) / 32;
pub const MAX_ATTACHED_FD_ENTRIES: usize = 32;

/// Starting position (inclusion) of the device configuration space in virtio devices.
pub const VHOST_USER_CONFIG_OFFSET: u32 = 0x100;

/// Ending position (exclusion) of the device configuration space in virtio devices.
pub const VHOST_USER_CONFIG_SIZE: u32 = 0x1000;

/// Maximum number of vrings supported.
pub const VHOST_USER_MAX_VRINGS: u64 = 0x8000u64;

/// Message type. Either [[FrontendReq]] or [[BackendReq]].
pub trait Req:
    Clone + Copy + Debug + PartialEq + Eq + PartialOrd + Ord + Into<u32> + TryFrom<u32> + Send + Sync
{
}

/// Error when converting an integer to an enum value.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReqError {
    /// The value does not correspond to a valid message code.
    #[error("The value {0} does not correspond to a valid message code.")]
    InvalidValue(u32),
}

/// Type of requests sent to the backend.
///
/// These are called "front-end message types" in the spec, so we call them `FrontendReq` here even
/// though it is somewhat confusing that the `BackendClient` sends `FrontendReq`s to a
/// `BackendServer`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, enumn::N)]
pub enum FrontendReq {
    /// Get from the underlying vhost implementation the features bit mask.
    GET_FEATURES = 1,
    /// Enable features in the underlying vhost implementation using a bit mask.
    SET_FEATURES = 2,
    /// Set the current frontend as an owner of the session.
    SET_OWNER = 3,
    /// No longer used.
    RESET_OWNER = 4,
    /// Set the memory map regions on the backend so it can translate the vring addresses.
    SET_MEM_TABLE = 5,
    /// Set logging shared memory space.
    SET_LOG_BASE = 6,
    /// Set the logging file descriptor, which is passed as ancillary data.
    SET_LOG_FD = 7,
    /// Set the size of the queue.
    SET_VRING_NUM = 8,
    /// Set the addresses of the different aspects of the vring.
    SET_VRING_ADDR = 9,
    /// Set the base offset in the available vring.
    SET_VRING_BASE = 10,
    /// Get the available vring base offset.
    GET_VRING_BASE = 11,
    /// Set the event file descriptor for adding buffers to the vring.
    SET_VRING_KICK = 12,
    /// Set the event file descriptor to signal when buffers are used.
    SET_VRING_CALL = 13,
    /// Set the event file descriptor to signal when error occurs.
    SET_VRING_ERR = 14,
    /// Get the protocol feature bit mask from the underlying vhost implementation.
    GET_PROTOCOL_FEATURES = 15,
    /// Enable protocol features in the underlying vhost implementation.
    SET_PROTOCOL_FEATURES = 16,
    /// Query how many queues the backend supports.
    GET_QUEUE_NUM = 17,
    /// Signal backend to enable or disable corresponding vring.
    SET_VRING_ENABLE = 18,
    /// Ask vhost user backend to broadcast a fake RARP to notify the migration is terminated
    /// for guest that does not support GUEST_ANNOUNCE.
    SEND_RARP = 19,
    /// Set host MTU value exposed to the guest.
    NET_SET_MTU = 20,
    /// Set the socket file descriptor for backend initiated requests.
    SET_BACKEND_REQ_FD = 21,
    /// Send IOTLB messages with struct vhost_iotlb_msg as payload.
    IOTLB_MSG = 22,
    /// Set the endianness of a VQ for legacy devices.
    SET_VRING_ENDIAN = 23,
    /// Fetch the contents of the virtio device configuration space.
    GET_CONFIG = 24,
    /// Change the contents of the virtio device configuration space.
    SET_CONFIG = 25,
    /// Create a session for crypto operation.
    CREATE_CRYPTO_SESSION = 26,
    /// Close a session for crypto operation.
    CLOSE_CRYPTO_SESSION = 27,
    /// Advise backend that a migration with postcopy enabled is underway.
    POSTCOPY_ADVISE = 28,
    /// Advise backend that a transition to postcopy mode has happened.
    POSTCOPY_LISTEN = 29,
    /// Advise that postcopy migration has now completed.
    POSTCOPY_END = 30,
    /// Get a shared buffer from backend.
    GET_INFLIGHT_FD = 31,
    /// Send the shared inflight buffer back to backend.
    SET_INFLIGHT_FD = 32,
    /// Sets the GPU protocol socket file descriptor.
    GPU_SET_SOCKET = 33,
    /// Ask the vhost user backend to disable all rings and reset all internal
    /// device state to the initial state.
    RESET_DEVICE = 34,
    /// Indicate that a buffer was added to the vring instead of signalling it
    /// using the vring’s kick file descriptor.
    VRING_KICK = 35,
    /// Return a u64 payload containing the maximum number of memory slots.
    GET_MAX_MEM_SLOTS = 36,
    /// Update the memory tables by adding the region described.
    ADD_MEM_REG = 37,
    /// Update the memory tables by removing the region described.
    REM_MEM_REG = 38,
    /// Notify the backend with updated device status as defined in the VIRTIO
    /// specification.
    SET_STATUS = 39,
    /// Query the backend for its device status as defined in the VIRTIO
    /// specification.
    GET_STATUS = 40,
    /// Front-end and back-end negotiate a channel over which to transfer the back-end’s internal
    /// state during migration.
    SET_DEVICE_STATE_FD = 42,
    /// After transferring the back-end’s internal state during migration, check whether the
    /// back-end was able to successfully fully process the state.
    CHECK_DEVICE_STATE = 43,

    // Non-standard message types.
    /// Get a list of the device's shared memory regions.
    GET_SHARED_MEMORY_REGIONS = 1004,
}

impl From<FrontendReq> for u32 {
    fn from(req: FrontendReq) -> u32 {
        req as u32
    }
}

impl Req for FrontendReq {}

impl TryFrom<u32> for FrontendReq {
    type Error = ReqError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        FrontendReq::n(value).ok_or(ReqError::InvalidValue(value))
    }
}

/// Type of requests sending from backends to frontends.
///
/// These are called "backend-end message types" in the spec, so we call them `BackendReq` here
/// even though it is somewhat confusing that the `FrontendClient` sends `BackendReq`s to a
/// `FrontendServer`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, enumn::N)]
pub enum BackendReq {
    /// Send IOTLB messages with struct vhost_iotlb_msg as payload.
    IOTLB_MSG = 1,
    /// Notify that the virtio device's configuration space has changed.
    CONFIG_CHANGE_MSG = 2,
    /// Set host notifier for a specified queue.
    VRING_HOST_NOTIFIER_MSG = 3,
    /// Indicate that a buffer was used from the vring.
    VRING_CALL = 4,
    /// Indicate that an error occurred on the specific vring.
    VRING_ERR = 5,

    // Non-standard message types.
    /// Indicates a request to map a fd into a shared memory region.
    SHMEM_MAP = 1000,
    /// Indicates a request to unmap part of a shared memory region.
    SHMEM_UNMAP = 1001,
    /// Virtio-fs draft: map file content into the window.
    DEPRECATED__FS_MAP = 1002,
    /// Virtio-fs draft: unmap file content from the window.
    DEPRECATED__FS_UNMAP = 1003,
    /// Virtio-fs draft: sync file content.
    DEPRECATED__FS_SYNC = 1004,
    /// Virtio-fs draft: perform a read/write from an fd directly to GPA.
    DEPRECATED__FS_IO = 1005,
    /// Indicates a request to map GPU memory into a shared memory region.
    GPU_MAP = 1006,
    /// Indicates a request to map external memory into a shared memory region.
    EXTERNAL_MAP = 1007,
}

impl From<BackendReq> for u32 {
    fn from(req: BackendReq) -> u32 {
        req as u32
    }
}

impl Req for BackendReq {}

impl TryFrom<u32> for BackendReq {
    type Error = ReqError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        BackendReq::n(value).ok_or(ReqError::InvalidValue(value))
    }
}

/// Vhost message Validator.
pub trait VhostUserMsgValidator {
    /// Validate message syntax only.
    /// It doesn't validate message semantics such as protocol version number and dependency
    /// on feature flags etc.
    fn is_valid(&self) -> bool {
        true
    }
}

// Bit mask for common message flags.
bitflags! {
    /// Common message flags for vhost-user requests and replies.
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct VhostUserHeaderFlag: u32 {
        /// Bits[0..2] is message version number.
        const VERSION = 0x3;
        /// Mark message as reply.
        const REPLY = 0x4;
        /// Sender anticipates a reply message from the peer.
        const NEED_REPLY = 0x8;
        /// All valid bits.
        const ALL_FLAGS = 0xc;
        /// All reserved bits.
        const RESERVED_BITS = !0xf;
    }
}

/// Common message header for vhost-user requests and replies.
/// A vhost-user message consists of 3 header fields and an optional payload. All numbers are in the
/// machine native byte order.
#[repr(C, packed)]
#[derive(Copy)]
pub struct VhostUserMsgHeader<R: Req> {
    request: u32,
    flags: u32,
    size: u32,
    _r: PhantomData<R>,
}

impl<R: Req> Debug for VhostUserMsgHeader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhostUserMsgHeader")
            .field("request", &{ self.request })
            .field("flags", &{ self.flags })
            .field("size", &{ self.size })
            .finish()
    }
}

impl<R: Req> Clone for VhostUserMsgHeader<R> {
    fn clone(&self) -> VhostUserMsgHeader<R> {
        *self
    }
}

impl<R: Req> PartialEq for VhostUserMsgHeader<R> {
    fn eq(&self, other: &Self) -> bool {
        self.request == other.request && self.flags == other.flags && self.size == other.size
    }
}

impl<R: Req> VhostUserMsgHeader<R> {
    /// Create a new instance of `VhostUserMsgHeader`.
    pub fn new(request: R, flags: u32, size: u32) -> Self {
        // Default to protocol version 1
        let fl = (flags & VhostUserHeaderFlag::ALL_FLAGS.bits()) | 0x1;
        VhostUserMsgHeader {
            request: request.into(),
            flags: fl,
            size,
            _r: PhantomData,
        }
    }

    pub fn into_raw(self) -> [u32; 3] {
        [self.request, self.flags, self.size]
    }

    pub fn from_raw(raw: [u32; 3]) -> Self {
        Self {
            request: raw[0],
            flags: raw[1],
            size: raw[2],
            _r: PhantomData,
        }
    }

    /// Get message type.
    pub fn get_code(&self) -> std::result::Result<R, R::Error> {
        R::try_from(self.request)
    }

    /// Set message type.
    pub fn set_code(&mut self, request: R) {
        self.request = request.into();
    }

    /// Get message version number.
    pub fn get_version(&self) -> u32 {
        self.flags & 0x3
    }

    /// Set message version number.
    pub fn set_version(&mut self, ver: u32) {
        self.flags &= !0x3;
        self.flags |= ver & 0x3;
    }

    /// Check whether it's a reply message.
    pub fn is_reply(&self) -> bool {
        (self.flags & VhostUserHeaderFlag::REPLY.bits()) != 0
    }

    /// Mark message as reply.
    pub fn set_reply(&mut self, is_reply: bool) {
        if is_reply {
            self.flags |= VhostUserHeaderFlag::REPLY.bits();
        } else {
            self.flags &= !VhostUserHeaderFlag::REPLY.bits();
        }
    }

    /// Check whether reply for this message is requested.
    pub fn is_need_reply(&self) -> bool {
        (self.flags & VhostUserHeaderFlag::NEED_REPLY.bits()) != 0
    }

    /// Mark that reply for this message is needed.
    pub fn set_need_reply(&mut self, need_reply: bool) {
        if need_reply {
            self.flags |= VhostUserHeaderFlag::NEED_REPLY.bits();
        } else {
            self.flags &= !VhostUserHeaderFlag::NEED_REPLY.bits();
        }
    }

    /// Check whether it's the reply message for the request `req`.
    pub fn is_reply_for(&self, req: &VhostUserMsgHeader<R>) -> bool {
        self.is_reply() && !req.is_reply() && self.request == req.request
    }

    /// Get message size.
    pub fn get_size(&self) -> u32 {
        self.size
    }

    /// Set message size.
    pub fn set_size(&mut self, size: u32) {
        self.size = size;
    }
}

impl<R: Req> Default for VhostUserMsgHeader<R> {
    fn default() -> Self {
        VhostUserMsgHeader {
            request: 0,
            flags: 0x1,
            size: 0,
            _r: PhantomData,
        }
    }
}

impl<T: Req> VhostUserMsgValidator for VhostUserMsgHeader<T> {
    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        if self.get_code().is_err() {
            return false;
        } else if self.get_version() != 0x1 {
            return false;
        } else if (self.flags & VhostUserHeaderFlag::RESERVED_BITS.bits()) != 0 {
            return false;
        }
        true
    }
}

pub const VIRTIO_F_RING_PACKED: u32 = 34;

/// Virtio feature flag for the vhost-user protocol features.
pub const VHOST_USER_F_PROTOCOL_FEATURES: u32 = 30;

// Bit mask for vhost-user protocol feature flags.
bitflags! {
    /// Vhost-user protocol feature flags.
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct VhostUserProtocolFeatures: u64 {
        /// Support multiple queues.
        const MQ = 0x0000_0001;
        /// Support logging through shared memory fd.
        const LOG_SHMFD = 0x0000_0002;
        /// Support broadcasting fake RARP packet.
        const RARP = 0x0000_0004;
        /// Support sending reply messages for requests with NEED_REPLY flag set.
        const REPLY_ACK = 0x0000_0008;
        /// Support setting MTU for virtio-net devices.
        const MTU = 0x0000_0010;
        /// Allow the backend to send requests to the frontend by an optional communication channel.
        const BACKEND_REQ = 0x0000_0020;
        /// Support setting backend endian by SET_VRING_ENDIAN.
        const CROSS_ENDIAN = 0x0000_0040;
        /// Support crypto operations.
        const CRYPTO_SESSION = 0x0000_0080;
        /// Support sending userfault_fd from backends to frontends.
        const PAGEFAULT = 0x0000_0100;
        /// Support Virtio device configuration.
        const CONFIG = 0x0000_0200;
        /// Allow the backend to send fds (at most 8 descriptors in each message) to the frontend.
        const BACKEND_SEND_FD = 0x0000_0400;
        /// Allow the backend to register a host notifier.
        const HOST_NOTIFIER = 0x0000_0800;
        /// Support inflight shmfd.
        const INFLIGHT_SHMFD = 0x0000_1000;
        /// Support resetting the device.
        const RESET_DEVICE = 0x0000_2000;
        /// Support inband notifications.
        const INBAND_NOTIFICATIONS = 0x0000_4000;
        /// Support configuring memory slots.
        const CONFIGURE_MEM_SLOTS = 0x0000_8000;
        /// Support reporting status.
        const STATUS = 0x0001_0000;
        /// Support Xen mmap.
        const XEN_MMAP = 0x0002_0000;
        /// Support VHOST_USER_SET_DEVICE_STATE_FD and VHOST_USER_CHECK_DEVICE_STATE messages.
        const DEVICE_STATE = 0x0008_0000;
        /// Support shared memory regions. (Non-standard.)
        const SHARED_MEMORY_REGIONS = 0x8000_0000;
    }
}

/// A generic message to encapsulate a 64-bit value.
#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserU64 {
    /// The encapsulated 64-bit common value.
    pub value: u64,
}

impl VhostUserU64 {
    /// Create a new instance.
    pub fn new(value: u64) -> Self {
        VhostUserU64 { value }
    }
}

impl VhostUserMsgValidator for VhostUserU64 {}

/// An empty message.
#[repr(C)]
#[derive(Default, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserEmptyMsg;

impl VhostUserMsgValidator for VhostUserEmptyMsg {}

/// A generic message for empty message.
/// ZST in repr(C) has same type layout as repr(rust)
#[repr(C)]
#[derive(Default, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserEmptyMessage;

impl VhostUserMsgValidator for VhostUserEmptyMessage {}

/// Memory region descriptor for the SET_MEM_TABLE request.
#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserMemory {
    /// Number of memory regions in the payload.
    pub num_regions: u32,
    /// Padding for alignment.
    pub padding1: u32,
}

impl VhostUserMemory {
    /// Create a new instance.
    pub fn new(cnt: u32) -> Self {
        VhostUserMemory {
            num_regions: cnt,
            padding1: 0,
        }
    }
}

impl VhostUserMsgValidator for VhostUserMemory {
    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        if self.padding1 != 0 {
            return false;
        } else if self.num_regions == 0 || self.num_regions > MAX_ATTACHED_FD_ENTRIES as u32 {
            return false;
        }
        true
    }
}

/// Memory region descriptors as payload for the SET_MEM_TABLE request.
#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserMemoryRegion {
    /// Guest physical address of the memory region.
    pub guest_phys_addr: u64,
    /// Size of the memory region.
    pub memory_size: u64,
    /// Virtual address in the current process.
    pub user_addr: u64,
    /// Offset where region starts in the mapped memory.
    pub mmap_offset: u64,
}

impl VhostUserMemoryRegion {
    /// Create a new instance.
    pub fn new(guest_phys_addr: u64, memory_size: u64, user_addr: u64, mmap_offset: u64) -> Self {
        VhostUserMemoryRegion {
            guest_phys_addr,
            memory_size,
            user_addr,
            mmap_offset,
        }
    }
}

impl VhostUserMsgValidator for VhostUserMemoryRegion {
    fn is_valid(&self) -> bool {
        if self.memory_size == 0
            || self.guest_phys_addr.checked_add(self.memory_size).is_none()
            || self.user_addr.checked_add(self.memory_size).is_none()
            || self.mmap_offset.checked_add(self.memory_size).is_none()
        {
            return false;
        }
        true
    }
}

/// Payload of the VhostUserMemory message.
pub type VhostUserMemoryPayload = Vec<VhostUserMemoryRegion>;

/// Single memory region descriptor as payload for ADD_MEM_REG and REM_MEM_REG
/// requests.
#[repr(C)]
#[derive(Default, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserSingleMemoryRegion {
    /// Padding for correct alignment
    padding: u64,
    /// Guest physical address of the memory region.
    pub guest_phys_addr: u64,
    /// Size of the memory region.
    pub memory_size: u64,
    /// Virtual address in the current process.
    pub user_addr: u64,
    /// Offset where region starts in the mapped memory.
    pub mmap_offset: u64,
}

impl VhostUserSingleMemoryRegion {
    /// Create a new instance.
    pub fn new(guest_phys_addr: u64, memory_size: u64, user_addr: u64, mmap_offset: u64) -> Self {
        VhostUserSingleMemoryRegion {
            padding: 0,
            guest_phys_addr,
            memory_size,
            user_addr,
            mmap_offset,
        }
    }
}

impl VhostUserMsgValidator for VhostUserSingleMemoryRegion {
    fn is_valid(&self) -> bool {
        if self.memory_size == 0
            || self.guest_phys_addr.checked_add(self.memory_size).is_none()
            || self.user_addr.checked_add(self.memory_size).is_none()
            || self.mmap_offset.checked_add(self.memory_size).is_none()
        {
            return false;
        }
        true
    }
}

/// Vring state descriptor.
#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserVringState {
    /// Vring index.
    pub index: u32,
    /// A common 32bit value to encapsulate vring state etc.
    pub num: u32,
}

impl VhostUserVringState {
    /// Create a new instance.
    pub fn new(index: u32, num: u32) -> Self {
        VhostUserVringState { index, num }
    }
}

impl VhostUserMsgValidator for VhostUserVringState {}

// Bit mask for vring address flags.
bitflags! {
    /// Flags for vring address.
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct VhostUserVringAddrFlags: u32 {
        /// Support log of vring operations.
        /// Modifications to "used" vring should be logged.
        const VHOST_VRING_F_LOG = 0x1;
    }
}

/// Vring address descriptor.
#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserVringAddr {
    /// Vring index.
    pub index: u32,
    /// Vring flags defined by VhostUserVringAddrFlags.
    pub flags: u32,
    /// Ring address of the vring descriptor table.
    pub descriptor: u64,
    /// Ring address of the vring used ring.
    pub used: u64,
    /// Ring address of the vring available ring.
    pub available: u64,
    /// Guest address for logging.
    pub log: u64,
}

impl VhostUserVringAddr {
    /// Create a new instance.
    pub fn new(
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Self {
        VhostUserVringAddr {
            index,
            flags: flags.bits(),
            descriptor,
            used,
            available,
            log,
        }
    }

    /// Create a new instance from `VringConfigData`.
    pub fn from_config_data(index: u32, config_data: &VringConfigData) -> Self {
        let log_addr = config_data.log_addr.unwrap_or(0);
        VhostUserVringAddr {
            index,
            flags: config_data.flags,
            descriptor: config_data.desc_table_addr,
            used: config_data.used_ring_addr,
            available: config_data.avail_ring_addr,
            log: log_addr,
        }
    }
}

impl VhostUserMsgValidator for VhostUserVringAddr {
    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        if (self.flags & !VhostUserVringAddrFlags::all().bits()) != 0 {
            return false;
        } else if self.descriptor & 0xf != 0 {
            return false;
        } else if self.available & 0x1 != 0 {
            return false;
        } else if self.used & 0x3 != 0 {
            return false;
        }
        true
    }
}

// Bit mask for the vhost-user device configuration message.
bitflags! {
    /// Flags for the device configuration message.
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct VhostUserConfigFlags: u32 {
        /// Vhost frontend messages used for writeable fields.
        const WRITABLE = 0x1;
        /// Vhost frontend messages used for live migration.
        const LIVE_MIGRATION = 0x2;
    }
}

/// Message to read/write device configuration space.
#[repr(C, packed)]
#[derive(Default, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserConfig {
    /// Offset of virtio device's configuration space.
    pub offset: u32,
    /// Configuration space access size in bytes.
    pub size: u32,
    /// Flags for the device configuration operation.
    pub flags: u32,
}

impl VhostUserConfig {
    /// Create a new instance.
    pub fn new(offset: u32, size: u32, flags: VhostUserConfigFlags) -> Self {
        VhostUserConfig {
            offset,
            size,
            flags: flags.bits(),
        }
    }
}

impl VhostUserMsgValidator for VhostUserConfig {
    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        let end_addr = match self.size.checked_add(self.offset) {
            Some(addr) => addr,
            None => return false,
        };
        if (self.flags & !VhostUserConfigFlags::all().bits()) != 0 {
            return false;
        } else if self.size == 0 || end_addr > VHOST_USER_CONFIG_SIZE {
            return false;
        }
        true
    }
}

/// Payload for the VhostUserConfig message.
pub type VhostUserConfigPayload = Vec<u8>;

/// Single memory region descriptor as payload for ADD_MEM_REG and REM_MEM_REG
/// requests.
/// This struct is defined by qemu and compiles with arch-dependent padding.
/// Interestingly, all our supported archs (arm, aarch64, x86_64) has same
/// data layout for this type.
#[repr(C)]
#[derive(Default, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserInflight {
    /// Size of the area to track inflight I/O.
    pub mmap_size: u64,
    /// Offset of this area from the start of the supplied file descriptor.
    pub mmap_offset: u64,
    /// Number of virtqueues.
    pub num_queues: u16,
    /// Size of virtqueues.
    pub queue_size: u16,
    /// implicit padding on 64-bit platforms
    pub _padding: [u8; 4],
}

impl VhostUserInflight {
    /// Create a new instance.
    pub fn new(mmap_size: u64, mmap_offset: u64, num_queues: u16, queue_size: u16) -> Self {
        VhostUserInflight {
            mmap_size,
            mmap_offset,
            num_queues,
            queue_size,
            ..Default::default()
        }
    }
}

impl VhostUserMsgValidator for VhostUserInflight {
    fn is_valid(&self) -> bool {
        if self.num_queues == 0 || self.queue_size == 0 {
            return false;
        }
        true
    }
}

/// VHOST_USER_SET_DEVICE_STATE_FD request payload.
#[repr(C)]
#[derive(Default, Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct DeviceStateTransferParameters {
    /// Direction in which the state is transferred
    pub transfer_direction: u32,
    /// State in which the VM guest and devices are.
    pub migration_phase: u32,
}

impl VhostUserMsgValidator for DeviceStateTransferParameters {
    fn is_valid(&self) -> bool {
        // Validated elsewhere.
        true
    }
}

/*
 * TODO: support dirty log, live migration and IOTLB operations.
#[repr(C, packed)]
pub struct VhostUserVringArea {
    pub index: u32,
    pub flags: u32,
    pub size: u64,
    pub offset: u64,
}

#[repr(C, packed)]
pub struct VhostUserLog {
    pub size: u64,
    pub offset: u64,
}

#[repr(C, packed)]
pub struct VhostUserIotlb {
    pub iova: u64,
    pub size: u64,
    pub user_addr: u64,
    pub permission: u8,
    pub optype: u8,
}
*/

/// Flags for SHMEM_MAP messages.
#[repr(transparent)]
#[derive(
    FromBytes,
    Immutable,
    IntoBytes,
    KnownLayout,
    Copy,
    Clone,
    Debug,
    Default,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
)]
pub struct VhostUserShmemMapMsgFlags(u8);

bitflags! {
    impl VhostUserShmemMapMsgFlags: u8 {
        /// Empty permission.
        const EMPTY = 0x0;
        /// Read permission.
        const MAP_R = 0x1;
        /// Write permission.
        const MAP_W = 0x2;
    }
}

impl From<Protection> for VhostUserShmemMapMsgFlags {
    fn from(prot: Protection) -> Self {
        let mut flags = Self::EMPTY;
        flags.set(Self::MAP_R, prot.allows(&Protection::read()));
        flags.set(Self::MAP_W, prot.allows(&Protection::write()));
        flags
    }
}

impl From<VhostUserShmemMapMsgFlags> for Protection {
    fn from(flags: VhostUserShmemMapMsgFlags) -> Self {
        let mut prot = Protection::default();
        if flags.contains(VhostUserShmemMapMsgFlags::MAP_R) {
            prot = prot.set_read();
        }
        if flags.contains(VhostUserShmemMapMsgFlags::MAP_W) {
            prot = prot.set_write();
        }
        prot
    }
}

/// Backend request message to map a file into a shared memory region.
#[repr(C, packed)]
#[derive(Default, Copy, Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserShmemMapMsg {
    /// Flags for the mmap operation
    pub flags: VhostUserShmemMapMsgFlags,
    /// Shared memory region id.
    pub shmid: u8,
    padding: [u8; 6],
    /// Offset into the shared memory region.
    pub shm_offset: u64,
    /// File offset.
    pub fd_offset: u64,
    /// Size of region to map.
    pub len: u64,
}

impl VhostUserMsgValidator for VhostUserShmemMapMsg {
    fn is_valid(&self) -> bool {
        (self.flags.bits() & !VhostUserShmemMapMsgFlags::all().bits()) == 0
            && self.fd_offset.checked_add(self.len).is_some()
            && self.shm_offset.checked_add(self.len).is_some()
    }
}

impl VhostUserShmemMapMsg {
    /// New instance of VhostUserShmemMapMsg struct
    pub fn new(
        shmid: u8,
        shm_offset: u64,
        fd_offset: u64,
        len: u64,
        flags: VhostUserShmemMapMsgFlags,
    ) -> Self {
        Self {
            flags,
            shmid,
            padding: [0; 6],
            shm_offset,
            fd_offset,
            len,
        }
    }
}

/// Backend request message to map GPU memory into a shared memory region.
#[repr(C, packed)]
#[derive(Default, Copy, Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserGpuMapMsg {
    /// Shared memory region id.
    pub shmid: u8,
    padding: [u8; 7],
    /// Offset into the shared memory region.
    pub shm_offset: u64,
    /// Size of region to map.
    pub len: u64,
    /// Index of the memory type.
    pub memory_idx: u32,
    /// Type of share handle.
    pub handle_type: u32,
    /// Device UUID
    pub device_uuid: [u8; 16],
    /// Driver UUID
    pub driver_uuid: [u8; 16],
}

impl VhostUserMsgValidator for VhostUserGpuMapMsg {
    fn is_valid(&self) -> bool {
        self.len > 0
    }
}

impl VhostUserGpuMapMsg {
    /// New instance of VhostUserGpuMapMsg struct
    pub fn new(
        shmid: u8,
        shm_offset: u64,
        len: u64,
        memory_idx: u32,
        handle_type: u32,
        device_uuid: [u8; 16],
        driver_uuid: [u8; 16],
    ) -> Self {
        Self {
            shmid,
            padding: [0; 7],
            shm_offset,
            len,
            memory_idx,
            handle_type,
            device_uuid,
            driver_uuid,
        }
    }
}

/// Backend request message to map external memory into a shared memory region.
#[repr(C, packed)]
#[derive(Default, Copy, Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserExternalMapMsg {
    /// Shared memory region id.
    pub shmid: u8,
    padding: [u8; 7],
    /// Offset into the shared memory region.
    pub shm_offset: u64,
    /// Size of region to map.
    pub len: u64,
    /// Pointer to the memory.
    pub ptr: u64,
}

impl VhostUserMsgValidator for VhostUserExternalMapMsg {
    fn is_valid(&self) -> bool {
        self.len > 0
    }
}

impl VhostUserExternalMapMsg {
    /// New instance of VhostUserExternalMapMsg struct
    pub fn new(shmid: u8, shm_offset: u64, len: u64, ptr: u64) -> Self {
        Self {
            shmid,
            padding: [0; 7],
            shm_offset,
            len,
            ptr,
        }
    }
}

/// Backend request message to unmap part of a shared memory region.
#[repr(C, packed)]
#[derive(Default, Copy, Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostUserShmemUnmapMsg {
    /// Shared memory region id.
    pub shmid: u8,
    padding: [u8; 7],
    /// Offset into the shared memory region.
    pub shm_offset: u64,
    /// Size of region to unmap.
    pub len: u64,
}

impl VhostUserMsgValidator for VhostUserShmemUnmapMsg {
    fn is_valid(&self) -> bool {
        self.shm_offset.checked_add(self.len).is_some()
    }
}

impl VhostUserShmemUnmapMsg {
    /// New instance of VhostUserShmemUnmapMsg struct
    pub fn new(shmid: u8, shm_offset: u64, len: u64) -> Self {
        Self {
            shmid,
            padding: [0; 7],
            shm_offset,
            len,
        }
    }
}

/// Inflight I/O descriptor state for split virtqueues
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct DescStateSplit {
    /// Indicate whether this descriptor (only head) is inflight or not.
    pub inflight: u8,
    /// Padding
    padding: [u8; 5],
    /// List of last batch of used descriptors, only when batching is used for submitting
    pub next: u16,
    /// Preserve order of fetching available descriptors, only for head descriptor
    pub counter: u64,
}

impl DescStateSplit {
    /// New instance of DescStateSplit struct
    pub fn new() -> Self {
        Self::default()
    }
}

/// Inflight I/O queue region for split virtqueues
#[repr(C, packed)]
pub struct QueueRegionSplit {
    /// Features flags of this region
    pub features: u64,
    /// Version of this region
    pub version: u16,
    /// Number of DescStateSplit entries
    pub desc_num: u16,
    /// List to track last batch of used descriptors
    pub last_batch_head: u16,
    /// Idx value of used ring
    pub used_idx: u16,
    /// Pointer to an array of DescStateSplit entries
    pub desc: u64,
}

impl QueueRegionSplit {
    /// New instance of QueueRegionSplit struct
    pub fn new(features: u64, queue_size: u16) -> Self {
        QueueRegionSplit {
            features,
            version: 1,
            desc_num: queue_size,
            last_batch_head: 0,
            used_idx: 0,
            desc: 0,
        }
    }
}

/// Inflight I/O descriptor state for packed virtqueues
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct DescStatePacked {
    /// Indicate whether this descriptor (only head) is inflight or not.
    pub inflight: u8,
    /// Padding
    padding: u8,
    /// Link to next free entry
    pub next: u16,
    /// Link to last entry of descriptor list, only for head
    pub last: u16,
    /// Length of descriptor list, only for head
    pub num: u16,
    /// Preserve order of fetching avail descriptors, only for head
    pub counter: u64,
    /// Buffer ID
    pub id: u16,
    /// Descriptor flags
    pub flags: u16,
    /// Buffer length
    pub len: u32,
    /// Buffer address
    pub addr: u64,
}

impl DescStatePacked {
    /// New instance of DescStatePacked struct
    pub fn new() -> Self {
        Self::default()
    }
}

/// Inflight I/O queue region for packed virtqueues
#[repr(C, packed)]
pub struct QueueRegionPacked {
    /// Features flags of this region
    pub features: u64,
    /// version of this region
    pub version: u16,
    /// size of descriptor state array
    pub desc_num: u16,
    /// head of free DescStatePacked entry list
    pub free_head: u16,
    /// old head of free DescStatePacked entry list
    pub old_free_head: u16,
    /// used idx of descriptor ring
    pub used_idx: u16,
    /// old used idx of descriptor ring
    pub old_used_idx: u16,
    /// device ring wrap counter
    pub used_wrap_counter: u8,
    /// old device ring wrap counter
    pub old_used_wrap_counter: u8,
    /// Padding
    padding: [u8; 7],
    /// Pointer to array tracking state of each descriptor from descriptor ring
    pub desc: u64,
}

impl QueueRegionPacked {
    /// New instance of QueueRegionPacked struct
    pub fn new(features: u64, queue_size: u16) -> Self {
        QueueRegionPacked {
            features,
            version: 1,
            desc_num: queue_size,
            free_head: 0,
            old_free_head: 0,
            used_idx: 0,
            old_used_idx: 0,
            used_wrap_counter: 0,
            old_used_wrap_counter: 0,
            padding: [0; 7],
            desc: 0,
        }
    }
}

/// Virtio shared memory descriptor.
#[repr(C, packed)]
#[derive(Default, Copy, Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct VhostSharedMemoryRegion {
    /// The shared memory region's shmid.
    pub id: u8,
    /// Padding
    padding: [u8; 7],
    /// The length of the shared memory region.
    pub length: u64,
}

impl VhostSharedMemoryRegion {
    /// New instance of VhostSharedMemoryRegion struct
    pub fn new(id: u8, length: u64) -> Self {
        VhostSharedMemoryRegion {
            id,
            padding: [0; 7],
            length,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VhostUserTransferDirection {
    Save,
    Load,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VhostUserMigrationPhase {
    Stopped,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_frontend_request_code() {
        FrontendReq::try_from(0).expect_err("invalid value");
        FrontendReq::try_from(46).expect_err("invalid value");
        FrontendReq::try_from(10000).expect_err("invalid value");

        let code = FrontendReq::try_from(FrontendReq::GET_FEATURES as u32).unwrap();
        assert_eq!(code, code.clone());
    }

    #[test]
    fn check_backend_request_code() {
        BackendReq::try_from(0).expect_err("invalid value");
        BackendReq::try_from(14).expect_err("invalid value");
        BackendReq::try_from(10000).expect_err("invalid value");

        let code = BackendReq::try_from(BackendReq::CONFIG_CHANGE_MSG as u32).unwrap();
        assert_eq!(code, code.clone());
    }

    #[test]
    fn msg_header_ops() {
        let mut hdr = VhostUserMsgHeader::new(FrontendReq::GET_FEATURES, 0, 0x100);
        assert_eq!(hdr.get_code(), Ok(FrontendReq::GET_FEATURES));
        hdr.set_code(FrontendReq::SET_FEATURES);
        assert_eq!(hdr.get_code(), Ok(FrontendReq::SET_FEATURES));

        assert_eq!(hdr.get_version(), 0x1);

        assert!(!hdr.is_reply());
        hdr.set_reply(true);
        assert!(hdr.is_reply());
        hdr.set_reply(false);

        assert!(!hdr.is_need_reply());
        hdr.set_need_reply(true);
        assert!(hdr.is_need_reply());
        hdr.set_need_reply(false);

        assert_eq!(hdr.get_size(), 0x100);
        hdr.set_size(0x200);
        assert_eq!(hdr.get_size(), 0x200);

        assert!(!hdr.is_need_reply());
        assert!(!hdr.is_reply());
        assert_eq!(hdr.get_version(), 0x1);

        // Check version
        hdr.set_version(0x0);
        assert!(!hdr.is_valid());
        hdr.set_version(0x2);
        assert!(!hdr.is_valid());
        hdr.set_version(0x1);
        assert!(hdr.is_valid());

        // Test Debug, Clone, PartiaEq trait
        assert_eq!(hdr, hdr.clone());
        assert_eq!(hdr.clone().get_code(), hdr.get_code());
        assert_eq!(format!("{:?}", hdr.clone()), format!("{:?}", hdr));
    }

    #[test]
    fn test_vhost_user_message_u64() {
        let val = VhostUserU64::default();
        let val1 = VhostUserU64::new(0);

        let a = val.value;
        let b = val1.value;
        assert_eq!(a, b);
        let a = VhostUserU64::new(1).value;
        assert_eq!(a, 1);
    }

    #[test]
    fn check_user_memory() {
        let mut msg = VhostUserMemory::new(1);
        assert!(msg.is_valid());
        msg.num_regions = MAX_ATTACHED_FD_ENTRIES as u32;
        assert!(msg.is_valid());

        msg.num_regions += 1;
        assert!(!msg.is_valid());
        msg.num_regions = 0xFFFFFFFF;
        assert!(!msg.is_valid());
        msg.num_regions = MAX_ATTACHED_FD_ENTRIES as u32;
        msg.padding1 = 1;
        assert!(!msg.is_valid());
    }

    #[test]
    fn check_user_memory_region() {
        let mut msg = VhostUserMemoryRegion {
            guest_phys_addr: 0,
            memory_size: 0x1000,
            user_addr: 0,
            mmap_offset: 0,
        };
        assert!(msg.is_valid());
        msg.guest_phys_addr = 0xFFFFFFFFFFFFEFFF;
        assert!(msg.is_valid());
        msg.guest_phys_addr = 0xFFFFFFFFFFFFF000;
        assert!(!msg.is_valid());
        msg.guest_phys_addr = 0xFFFFFFFFFFFF0000;
        msg.memory_size = 0;
        assert!(!msg.is_valid());
        let a = msg.guest_phys_addr;
        let b = msg.guest_phys_addr;
        assert_eq!(a, b);

        let msg = VhostUserMemoryRegion::default();
        let a = msg.guest_phys_addr;
        assert_eq!(a, 0);
        let a = msg.memory_size;
        assert_eq!(a, 0);
        let a = msg.user_addr;
        assert_eq!(a, 0);
        let a = msg.mmap_offset;
        assert_eq!(a, 0);
    }

    #[test]
    fn test_vhost_user_state() {
        let state = VhostUserVringState::new(5, 8);

        let a = state.index;
        assert_eq!(a, 5);
        let a = state.num;
        assert_eq!(a, 8);
        assert!(state.is_valid());

        let state = VhostUserVringState::default();
        let a = state.index;
        assert_eq!(a, 0);
        let a = state.num;
        assert_eq!(a, 0);
        assert!(state.is_valid());
    }

    #[test]
    fn test_vhost_user_addr() {
        let mut addr = VhostUserVringAddr::new(
            2,
            VhostUserVringAddrFlags::VHOST_VRING_F_LOG,
            0x1000,
            0x2000,
            0x3000,
            0x4000,
        );

        let a = addr.index;
        assert_eq!(a, 2);
        let a = addr.flags;
        assert_eq!(a, VhostUserVringAddrFlags::VHOST_VRING_F_LOG.bits());
        let a = addr.descriptor;
        assert_eq!(a, 0x1000);
        let a = addr.used;
        assert_eq!(a, 0x2000);
        let a = addr.available;
        assert_eq!(a, 0x3000);
        let a = addr.log;
        assert_eq!(a, 0x4000);
        assert!(addr.is_valid());

        addr.descriptor = 0x1001;
        assert!(!addr.is_valid());
        addr.descriptor = 0x1000;

        addr.available = 0x3001;
        assert!(!addr.is_valid());
        addr.available = 0x3000;

        addr.used = 0x2001;
        assert!(!addr.is_valid());
        addr.used = 0x2000;
        assert!(addr.is_valid());
    }

    #[test]
    fn test_vhost_user_state_from_config() {
        let config = VringConfigData {
            queue_size: 128,
            flags: VhostUserVringAddrFlags::VHOST_VRING_F_LOG.bits(),
            desc_table_addr: 0x1000,
            used_ring_addr: 0x2000,
            avail_ring_addr: 0x3000,
            log_addr: Some(0x4000),
        };
        let addr = VhostUserVringAddr::from_config_data(2, &config);

        let a = addr.index;
        assert_eq!(a, 2);
        let a = addr.flags;
        assert_eq!(a, VhostUserVringAddrFlags::VHOST_VRING_F_LOG.bits());
        let a = addr.descriptor;
        assert_eq!(a, 0x1000);
        let a = addr.used;
        assert_eq!(a, 0x2000);
        let a = addr.available;
        assert_eq!(a, 0x3000);
        let a = addr.log;
        assert_eq!(a, 0x4000);
        assert!(addr.is_valid());
    }

    #[test]
    fn check_user_vring_addr() {
        let mut msg =
            VhostUserVringAddr::new(0, VhostUserVringAddrFlags::all(), 0x0, 0x0, 0x0, 0x0);
        assert!(msg.is_valid());

        msg.descriptor = 1;
        assert!(!msg.is_valid());
        msg.descriptor = 0;

        msg.available = 1;
        assert!(!msg.is_valid());
        msg.available = 0;

        msg.used = 1;
        assert!(!msg.is_valid());
        msg.used = 0;

        msg.flags |= 0x80000000;
        assert!(!msg.is_valid());
        msg.flags &= !0x80000000;
    }

    #[test]
    fn check_user_config_msg() {
        let mut msg =
            VhostUserConfig::new(0, VHOST_USER_CONFIG_SIZE, VhostUserConfigFlags::WRITABLE);

        assert!(msg.is_valid());
        msg.size = 0;
        assert!(!msg.is_valid());
        msg.size = 1;
        assert!(msg.is_valid());
        msg.offset = u32::MAX;
        assert!(!msg.is_valid());
        msg.offset = VHOST_USER_CONFIG_SIZE;
        assert!(!msg.is_valid());
        msg.offset = VHOST_USER_CONFIG_SIZE - 1;
        assert!(msg.is_valid());
        msg.size = 2;
        assert!(!msg.is_valid());
        msg.size = 1;
        msg.flags |= VhostUserConfigFlags::LIVE_MIGRATION.bits();
        assert!(msg.is_valid());
        msg.flags |= 0x4;
        assert!(!msg.is_valid());
    }
}
