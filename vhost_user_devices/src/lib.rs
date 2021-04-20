// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Library for implementing vhost-user device executables.
//!
//! This crate provides
//! * `VhostUserBackend` trait, which is a collection of methods to handle vhost-user requests, and
//! * `DeviceRequestHandler` struct, which makes a connection to a VMM and starts an event loop.
//!
//! They are expected to be used as follows:
//! 1. Define a struct which `VhostUserBackend` is implemented for.
//! 2. Create an instance of `DeviceRequestHandler` with the backend and call its `start()` method
//! to start an event loop.
//!
//! ```ignore
//! struct MyBackend {
//!   /* fields */
//! }
//!
//! impl VhostUserBackend for MyBackend {
//!   /* implement methods */
//! }
//!
//! fn main() {
//!   let backend = MyBackend { /* initialize fields */ };
//!   let handler = DeviceRequestHandler::new(backend).unwrap();
//!   let socket = std::path::Path("/path/to/socket");
//!
//!   if let Err(e) = handler.start(socket) {
//!     eprintln!("error happened: {}", e);
//!   }
//! }
//! ```
//!

use std::cell::RefCell;
use std::convert::TryFrom;
use std::num::Wrapping;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use base::{
    error, AsRawDescriptor, Event, EventType, FromRawDescriptor, PollToken, SafeDescriptor,
    SharedMemory, SharedMemoryUnix, WaitContext,
};
use devices::virtio::{Queue, SignalableInterrupt};
use remain::sorted;
use thiserror::Error as ThisError;
use vm_memory::{GuestAddress, GuestMemory, MemoryRegion};
use vmm_vhost::vhost_user::message::{
    VhostUserConfigFlags, VhostUserMemoryRegion, VhostUserProtocolFeatures,
    VhostUserSingleMemoryRegion, VhostUserVirtioFeatures, VhostUserVringAddrFlags,
    VhostUserVringState,
};
use vmm_vhost::vhost_user::{
    Error as VhostError, Listener, Result as VhostResult, SlaveFsCacheReq, SlaveListener,
    VhostUserSlaveReqHandlerMut,
};

/// An event to deliver an interrupt to the guest.
///
/// Unlike `devices::Interrupt`, this doesn't support interrupt status and signal resampling.
// TODO(b/187487351): To avoid sending unnecessary events, we might want to support interrupt
// status. For this purpose, we need a mechanism to share interrupt status between the vmm and the
// device process.
pub struct CallEvent(Event);

impl SignalableInterrupt for CallEvent {
    fn signal(&self, _vector: u16, _interrupt_status_mask: u32) {
        self.0.write(1).unwrap();
    }

    fn signal_config_changed(&self) {} // TODO(dgreid)

    fn get_resample_evt(&self) -> Option<&Event> {
        None
    }

    fn do_interrupt_resample(&self) {}
}

/// Keeps a mpaaing from the vmm's virtual addresses to guest addresses.
/// used to translate messages from the vmm to guest offsets.
#[derive(Default)]
struct MappingInfo {
    vmm_addr: u64,
    guest_phys: u64,
    size: u64,
}

fn vmm_va_to_gpa(maps: &[MappingInfo], vmm_va: u64) -> VhostResult<GuestAddress> {
    for map in maps {
        if vmm_va >= map.vmm_addr && vmm_va < map.vmm_addr + map.size {
            return Ok(GuestAddress(vmm_va - map.vmm_addr + map.guest_phys));
        }
    }
    Err(VhostError::InvalidMessage)
}

/// Trait for vhost-user backend.
pub trait VhostUserBackend
where
    Self: Sized,
    Self::EventToken: PollToken + std::fmt::Debug,
    Self::Error: std::error::Error + std::fmt::Debug,
{
    const MAX_QUEUE_NUM: usize;
    const MAX_VRING_NUM: usize;

    /// Types of tokens that can be associated with polling events.
    type EventToken;

    /// Error type specific to this backend.
    type Error;

    /// Translates a queue's index into `EventToken`.
    fn index_to_event_type(queue_index: usize) -> Option<Self::EventToken>;

    /// The set of feature bits that this backend supports.
    fn features(&self) -> u64;

    /// Acknowledges that this set of features should be enabled.
    fn ack_features(&mut self, value: u64) -> std::result::Result<(), Self::Error>;

    /// Returns the set of enabled features.
    fn acked_features(&self) -> u64;

    /// The set of protocol feature bits that this backend supports.
    fn protocol_features(&self) -> VhostUserProtocolFeatures;

    /// Acknowledges that this set of protocol features should be enabled.
    fn ack_protocol_features(&mut self, _value: u64) -> std::result::Result<(), Self::Error>;

    /// Returns the set of enabled protocol features.
    fn acked_protocol_features(&self) -> u64;

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, dst: &mut [u8]);

    /// Sets guest memory regions.
    fn set_guest_mem(&mut self, mem: GuestMemory);

    /// Returns a backend event to be waited for.
    fn backend_event(&self) -> Option<(&dyn AsRawDescriptor, EventType, Self::EventToken)>;

    /// Processes a given event.
    fn handle_event(
        &mut self,
        wait_ctx: &Rc<WaitContext<HandlerPollToken<Self>>>,
        event: &Self::EventToken,
        vrings: &[Rc<RefCell<Vring>>],
    ) -> std::result::Result<(), Self::Error>;

    /// Resets the vhost-user backend.
    fn reset(&mut self);
}

/// A virtio ring entry.
pub struct Vring {
    pub queue: Queue,
    pub call_evt: Option<Arc<CallEvent>>,
    pub kick_evt: Option<Event>,
    pub enabled: bool,
}

impl Vring {
    fn new(max_size: u16) -> Self {
        Self {
            queue: Queue::new(max_size),
            call_evt: None,
            kick_evt: None,
            enabled: false,
        }
    }

    fn reset(&mut self) {
        self.queue.reset();
        self.call_evt = None;
        self.kick_evt = None;
        self.enabled = false;
    }
}

#[sorted]
#[derive(ThisError, Debug)]
pub enum HandlerError<BackendError: std::error::Error> {
    /// Failed to accept an incoming connection.
    #[error("failed to accept an incoming connection: {0}")]
    AcceptConnection(VhostError),
    /// Failed to create a connection listener.
    #[error("failed to create a connection listener: {0}")]
    CreateConnectionListener(VhostError),
    /// Failed to create a UNIX domain socket listener.
    #[error("failed to create a UNIX domain socket listener: {0}")]
    CreateSocketListener(VhostError),
    /// Failed to handle a backend event.
    #[error("failed to handle a backend event: {0}")]
    HandleBackendEvent(BackendError),
    /// Failed to handle a vhost-user request.
    #[error("failed to handle a vhost-user request: {0}")]
    HandleVhostUserRequest(VhostError),
    /// Invalid queue index is given.
    #[error("invalid queue index is given: {index}")]
    InvalidQueueIndex { index: usize },
    /// Failed to add new FD(s) to wait context.
    #[error("failed to add new FD(s) to wait context: {0}")]
    WaitContextAdd(base::Error),
    /// Failed to create a wait context.
    #[error("failed to create a wait context: {0}")]
    WaitContextCreate(base::Error),
    /// Failed to delete a FD from wait context.
    #[error("failed to delete a FD from wait context: {0}")]
    WaitContextDel(base::Error),
    /// Failed to wait for event.
    #[error("failed to wait for an event triggered: {0}")]
    WaitContextWait(base::Error),
}

type HandlerResult<B, T> = std::result::Result<T, HandlerError<<B as VhostUserBackend>::Error>>;

#[derive(Debug)]
pub enum HandlerPollToken<B: VhostUserBackend> {
    BackendToken(B::EventToken),
    VhostUserRequest,
}

impl<B: VhostUserBackend> PollToken for HandlerPollToken<B> {
    fn as_raw_token(&self) -> u64 {
        match self {
            Self::BackendToken(t) => t.as_raw_token(),
            Self::VhostUserRequest => u64::MAX,
        }
    }

    fn from_raw_token(data: u64) -> Self {
        match data {
            u64::MAX => Self::VhostUserRequest,
            _ => Self::BackendToken(B::EventToken::from_raw_token(data)),
        }
    }
}

/// Structure to have an event loop for interaction between a VMM and `VhostUserBackend`.
pub struct DeviceRequestHandler<B>
where
    B: 'static + VhostUserBackend,
{
    owned: bool,
    vrings: Vec<Rc<RefCell<Vring>>>,
    vmm_maps: Option<Vec<MappingInfo>>,
    backend: Rc<RefCell<B>>,
    wait_ctx: Rc<WaitContext<HandlerPollToken<B>>>,
}

impl<B> DeviceRequestHandler<B>
where
    B: 'static + VhostUserBackend,
{
    /// Creates the handler instance for `backend`.
    pub fn new(backend: B) -> HandlerResult<B, Self> {
        let mut vrings = Vec::with_capacity(B::MAX_QUEUE_NUM as usize);
        for _ in 0..B::MAX_QUEUE_NUM {
            vrings.push(Rc::new(RefCell::new(Vring::new(B::MAX_VRING_NUM as u16))));
        }

        let wait_ctx: WaitContext<HandlerPollToken<B>> =
            WaitContext::new().map_err(HandlerError::WaitContextCreate)?;

        if let Some((evt, typ, token)) = backend.backend_event() {
            wait_ctx
                .add_for_event(evt, typ, HandlerPollToken::BackendToken(token))
                .map_err(HandlerError::WaitContextAdd)?;
        }

        Ok(DeviceRequestHandler {
            owned: false,
            vmm_maps: None,
            vrings,
            backend: Rc::new(RefCell::new(backend)),
            wait_ctx: Rc::new(wait_ctx),
        })
    }

    /// Connects to `socket` and starts an event loop which handles incoming vhost-user requests from
    /// the VMM and events from the backend.
    // TODO(keiichiw): Remove the clippy annotation once we uprev clippy to 1.52.0 or later.
    // cf. https://github.com/rust-lang/rust-clippy/issues/6546
    #[allow(clippy::clippy::result_unit_err)]
    pub fn start<P: AsRef<Path>>(self, socket: P) -> HandlerResult<B, ()> {
        let vrings = self.vrings.clone();
        let backend = self.backend.clone();
        let wait_ctx = self.wait_ctx.clone();

        let listener = Listener::new(socket, true).map_err(HandlerError::CreateSocketListener)?;
        let mut s_listener = SlaveListener::new(listener, Arc::new(std::sync::Mutex::new(self)))
            .map_err(HandlerError::CreateConnectionListener)?;

        let mut req_handler = s_listener
            .accept()
            .map_err(HandlerError::AcceptConnection)?
            .expect("no incoming connection was detected");

        let sd = SafeDescriptor::try_from(&req_handler as &dyn AsRawFd)
            .expect("failed to get safe descriptor for handler");
        wait_ctx
            .add(&sd, HandlerPollToken::VhostUserRequest)
            .map_err(HandlerError::WaitContextAdd)?;

        loop {
            let events = wait_ctx.wait().map_err(HandlerError::WaitContextWait)?;
            for event in events.iter() {
                match &event.token {
                    HandlerPollToken::BackendToken(token) => {
                        backend
                            .borrow_mut()
                            .handle_event(&wait_ctx, &token, &vrings)
                            .map_err(HandlerError::HandleBackendEvent)?;
                    }
                    HandlerPollToken::VhostUserRequest => {
                        req_handler
                            .handle_request()
                            .map_err(HandlerError::HandleVhostUserRequest)?;
                    }
                }
            }
        }
    }

    fn register_kickfd(&self, index: usize, event: &Event) -> HandlerResult<B, ()> {
        let token =
            B::index_to_event_type(index).ok_or(HandlerError::InvalidQueueIndex { index })?;
        self.wait_ctx
            .add(&event.0, HandlerPollToken::BackendToken(token))
            .map_err(HandlerError::WaitContextAdd)
    }

    fn unregister_kickfd(&self, event: &Event) -> HandlerResult<B, ()> {
        self.wait_ctx
            .delete(&event.0)
            .map_err(HandlerError::WaitContextDel)
    }
}

impl<B: VhostUserBackend> VhostUserSlaveReqHandlerMut for DeviceRequestHandler<B> {
    fn set_owner(&mut self) -> VhostResult<()> {
        if self.owned {
            return Err(VhostError::InvalidOperation);
        }
        self.owned = true;
        Ok(())
    }

    fn reset_owner(&mut self) -> VhostResult<()> {
        self.owned = false;
        self.backend.borrow_mut().reset();
        Ok(())
    }

    fn get_features(&mut self) -> VhostResult<u64> {
        let features = self.backend.borrow().features();
        Ok(features)
    }

    fn set_features(&mut self, features: u64) -> VhostResult<()> {
        if !self.owned {
            return Err(VhostError::InvalidOperation);
        }

        if (features & !(self.backend.borrow().features())) != 0 {
            return Err(VhostError::InvalidParam);
        }

        if let Err(e) = self.backend.borrow_mut().ack_features(features) {
            error!("failed to acknowledge features 0x{:x}: {}", features, e);
            return Err(VhostError::InvalidOperation);
        }

        // If VHOST_USER_F_PROTOCOL_FEATURES has not been negotiated, the ring is initialized in an
        // enabled state.
        // If VHOST_USER_F_PROTOCOL_FEATURES has been negotiated, the ring is initialized in a
        // disabled state.
        // Client must not pass data to/from the backend until ring is enabled by
        // VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has been disabled by
        // VHOST_USER_SET_VRING_ENABLE with parameter 0.
        let acked_features = self.backend.borrow().acked_features();
        let vring_enabled = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() & acked_features != 0;
        for v in &mut self.vrings {
            let mut vring = v.borrow_mut();
            vring.enabled = vring_enabled;
        }

        Ok(())
    }

    fn get_protocol_features(&mut self) -> VhostResult<VhostUserProtocolFeatures> {
        Ok(self.backend.borrow().protocol_features())
    }

    fn set_protocol_features(&mut self, features: u64) -> VhostResult<()> {
        if let Err(e) = self.backend.borrow_mut().ack_protocol_features(features) {
            error!("failed to set protocol features 0x{:x}: {}", features, e);
            return Err(VhostError::InvalidOperation);
        }
        Ok(())
    }

    fn set_mem_table(
        &mut self,
        contexts: &[VhostUserMemoryRegion],
        fds: &[RawFd],
    ) -> VhostResult<()> {
        if fds.len() != contexts.len() {
            return Err(VhostError::InvalidParam);
        }

        let mut regions = Vec::with_capacity(fds.len());
        for (region, &fd) in contexts.iter().zip(fds.iter()) {
            let rd = base::validate_raw_descriptor(fd).map_err(|e| {
                error!("invalid fd is given: {}", e);
                VhostError::InvalidParam
            })?;
            // Safe because we verified that we are the unique owner of `rd`.
            let sd = unsafe { SafeDescriptor::from_raw_descriptor(rd) };

            let region = MemoryRegion::new(
                region.memory_size,
                GuestAddress(region.guest_phys_addr),
                region.mmap_offset,
                Arc::new(SharedMemory::from_safe_descriptor(sd).unwrap()),
            )
            .map_err(|e| {
                error!("failed to create a memory region: {}", e);
                VhostError::InvalidOperation
            })?;
            regions.push(region);
        }
        let guest_mem = GuestMemory::from_regions(regions).map_err(|e| {
            error!("failed to create guest memory: {}", e);
            VhostError::InvalidOperation
        })?;

        let vmm_maps = contexts
            .iter()
            .map(|region| MappingInfo {
                vmm_addr: region.user_addr,
                guest_phys: region.guest_phys_addr,
                size: region.memory_size,
            })
            .collect();

        self.backend.borrow_mut().set_guest_mem(guest_mem);

        self.vmm_maps = Some(vmm_maps);
        Ok(())
    }

    fn get_queue_num(&mut self) -> VhostResult<u64> {
        Ok(self.vrings.len() as u64)
    }

    fn set_vring_num(&mut self, index: u32, num: u32) -> VhostResult<()> {
        if index as usize >= self.vrings.len() || num == 0 || num as usize > B::MAX_VRING_NUM {
            return Err(VhostError::InvalidParam);
        }
        let mut vring = self.vrings[index as usize].borrow_mut();
        vring.queue.size = num as u16;

        Ok(())
    }

    fn set_vring_addr(
        &mut self,
        index: u32,
        _flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        _log: u64,
    ) -> VhostResult<()> {
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam);
        }

        let vmm_maps = self.vmm_maps.as_ref().ok_or(VhostError::InvalidParam)?;
        let mut vring = self.vrings[index as usize].borrow_mut();
        vring.queue.desc_table = vmm_va_to_gpa(&vmm_maps, descriptor)?;
        vring.queue.avail_ring = vmm_va_to_gpa(&vmm_maps, available)?;
        vring.queue.used_ring = vmm_va_to_gpa(&vmm_maps, used)?;

        Ok(())
    }

    fn set_vring_base(&mut self, index: u32, base: u32) -> VhostResult<()> {
        if index as usize >= self.vrings.len() || base as usize >= B::MAX_VRING_NUM {
            return Err(VhostError::InvalidParam);
        }

        let mut vring = self.vrings[index as usize].borrow_mut();
        vring.queue.next_avail = Wrapping(base as u16);
        vring.queue.next_used = Wrapping(base as u16);

        Ok(())
    }

    fn get_vring_base(&mut self, index: u32) -> VhostResult<VhostUserVringState> {
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam);
        }

        // Quotation from vhost-user spec:
        // Client must start ring upon receiving a kick (that is, detecting
        // that file descriptor is readable) on the descriptor specified by
        // VHOST_USER_SET_VRING_KICK, and stop ring upon receiving
        // VHOST_USER_GET_VRING_BASE.
        let mut vring = self.vrings[index as usize].borrow_mut();
        vring.reset();
        if let Some(kick) = &vring.kick_evt {
            self.unregister_kickfd(kick).expect("unregister_kickfd");
        }

        Ok(VhostUserVringState::new(
            index,
            vring.queue.next_avail.0 as u32,
        ))
    }

    fn set_vring_kick(&mut self, index: u8, fd: Option<RawFd>) -> VhostResult<()> {
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam);
        }

        if let Some(fd) = fd {
            // TODO(b/186625058): The current code returns an error when `FD_CLOEXEC` is already
            // set, which is not harmful. Once we update the vhost crate's API to pass around `File`
            // instead of `RawFd`, we won't need this validation.
            let rd = base::validate_raw_descriptor(fd).map_err(|e| {
                error!("invalid fd is given: {}", e);
                VhostError::InvalidParam
            })?;
            // Safe because the FD is now owned.
            let kick = unsafe { Event::from_raw_descriptor(rd) };

            self.register_kickfd(index as usize, &kick)
                .expect("register_kickfd");

            let mut vring = self.vrings[index as usize].borrow_mut();
            vring.kick_evt = Some(kick);
            vring.queue.ready = true;
        }
        Ok(())
    }

    fn set_vring_call(&mut self, index: u8, fd: Option<RawFd>) -> VhostResult<()> {
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam);
        }

        if let Some(fd) = fd {
            let rd = base::validate_raw_descriptor(fd).map_err(|e| {
                error!("invalid fd is given: {}", e);
                VhostError::InvalidParam
            })?;
            // Safe because the FD is now owned.
            let call = unsafe { Event::from_raw_descriptor(rd) };
            self.vrings[index as usize].borrow_mut().call_evt = Some(Arc::new(CallEvent(call)));
        }

        Ok(())
    }

    fn set_vring_err(&mut self, _index: u8, _fd: Option<RawFd>) -> VhostResult<()> {
        // TODO
        Ok(())
    }

    fn set_vring_enable(&mut self, index: u32, enable: bool) -> VhostResult<()> {
        if index as usize >= self.vrings.len() {
            return Err(VhostError::InvalidParam);
        }

        // This request should be handled only when VHOST_USER_F_PROTOCOL_FEATURES
        // has been negotiated.
        if self.backend.borrow().acked_features()
            & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
            == 0
        {
            return Err(VhostError::InvalidOperation);
        }

        // Slave must not pass data to/from the backend until ring is
        // enabled by VHOST_USER_SET_VRING_ENABLE with parameter 1,
        // or after it has been disabled by VHOST_USER_SET_VRING_ENABLE
        // with parameter 0.
        let mut vring = self.vrings[index as usize].borrow_mut();
        vring.enabled = enable;

        Ok(())
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        _flags: VhostUserConfigFlags,
    ) -> VhostResult<Vec<u8>> {
        if offset >= size {
            return Err(VhostError::InvalidParam);
        }

        let mut data = vec![0; size as usize];
        self.backend
            .borrow()
            .read_config(u64::from(offset), &mut data);
        Ok(data)
    }

    fn set_config(
        &mut self,
        _offset: u32,
        _buf: &[u8],
        _flags: VhostUserConfigFlags,
    ) -> VhostResult<()> {
        // TODO
        Ok(())
    }

    fn set_slave_req_fd(&mut self, _vu_req: SlaveFsCacheReq) {
        // TODO
    }

    fn get_max_mem_slots(&mut self) -> VhostResult<u64> {
        //TODO
        Ok(0)
    }

    fn add_mem_region(
        &mut self,
        _region: &VhostUserSingleMemoryRegion,
        _fd: RawFd,
    ) -> VhostResult<()> {
        //TODO
        Ok(())
    }

    fn remove_mem_region(&mut self, _region: &VhostUserSingleMemoryRegion) -> VhostResult<()> {
        //TODO
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::mpsc::channel;
    use std::sync::Barrier;

    use data_model::DataInit;
    use devices::virtio::vhost::user::VhostUserHandler;
    use tempfile::{Builder, TempDir};
    use vmm_vhost::vhost_user::Master;

    #[derive(PollToken, Debug)]
    enum FakeToken {
        Queue0,
    }

    #[derive(ThisError, Debug)]
    enum FakeError {
        #[error("invalid features are given: 0x{features:x}")]
        InvalidFeatures { features: u64 },
        #[error("invalid protocol features are given: 0x{features:x}")]
        InvalidProtocolFeatures { features: u64 },
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(C)]
    struct FakeConfig {
        x: u32,
        y: u64,
    }

    unsafe impl DataInit for FakeConfig {}

    const FAKE_CONFIG_DATA: FakeConfig = FakeConfig { x: 1, y: 2 };

    struct FakeBackend {
        mem: Option<GuestMemory>,
        avail_features: u64,
        acked_features: u64,
        acked_protocol_features: VhostUserProtocolFeatures,
    }

    impl FakeBackend {
        fn new() -> Self {
            Self {
                mem: None,
                avail_features: VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits(),
                acked_features: 0,
                acked_protocol_features: VhostUserProtocolFeatures::empty(),
            }
        }
    }

    impl VhostUserBackend for FakeBackend {
        const MAX_QUEUE_NUM: usize = 16;
        const MAX_VRING_NUM: usize = 256;

        type EventToken = FakeToken;
        type Error = FakeError;

        fn index_to_event_type(queue_index: usize) -> Option<Self::EventToken> {
            match queue_index {
                0 => Some(FakeToken::Queue0),
                _ => None,
            }
        }

        fn features(&self) -> u64 {
            self.avail_features
        }

        fn ack_features(&mut self, value: u64) -> std::result::Result<(), Self::Error> {
            let unrequested_features = value & !self.avail_features;
            if unrequested_features != 0 {
                return Err(FakeError::InvalidFeatures {
                    features: unrequested_features,
                });
            }
            self.acked_features |= value;
            Ok(())
        }

        fn acked_features(&self) -> u64 {
            self.acked_features
        }

        fn set_guest_mem(&mut self, mem: GuestMemory) {
            self.mem = Some(mem);
        }

        fn protocol_features(&self) -> VhostUserProtocolFeatures {
            VhostUserProtocolFeatures::CONFIG
        }

        fn ack_protocol_features(&mut self, features: u64) -> std::result::Result<(), Self::Error> {
            let features = VhostUserProtocolFeatures::from_bits(features)
                .ok_or(FakeError::InvalidProtocolFeatures { features })?;
            let supported = self.protocol_features();
            self.acked_protocol_features = features & supported;
            Ok(())
        }

        fn acked_protocol_features(&self) -> u64 {
            self.acked_protocol_features.bits()
        }

        fn backend_event(&self) -> Option<(&dyn AsRawDescriptor, EventType, Self::EventToken)> {
            None
        }

        fn handle_event(
            &mut self,
            _wait_ctx: &Rc<WaitContext<HandlerPollToken<Self>>>,
            _event: &Self::EventToken,
            _vrings: &[Rc<RefCell<Vring>>],
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }

        fn read_config(&self, offset: u64, dst: &mut [u8]) {
            dst.copy_from_slice(&FAKE_CONFIG_DATA.as_slice()[offset as usize..]);
        }

        fn reset(&mut self) {}
    }

    fn temp_dir() -> TempDir {
        Builder::new().prefix("/tmp/vhost_test").tempdir().unwrap()
    }

    #[test]
    fn test_vhost_user_activate() {
        use vmm_vhost::vhost_user::{Listener, SlaveListener};

        const QUEUES_NUM: usize = 2;

        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let listener = Listener::new(&path, true).unwrap();

        let vmm_bar = Arc::new(Barrier::new(2));
        let dev_bar = vmm_bar.clone();

        let (tx, rx) = channel();

        std::thread::spawn(move || {
            // VMM side
            rx.recv().unwrap(); // Ensure the device is ready.

            let vu = Master::connect(&path, 1).unwrap();
            let allow_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            let init_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            let allow_protocol_features = VhostUserProtocolFeatures::CONFIG;
            let mut vmm_handler =
                VhostUserHandler::new(vu, allow_features, init_features, allow_protocol_features)
                    .unwrap();

            println!("read_config");
            let mut buf = vec![0; std::mem::size_of::<FakeConfig>()];
            vmm_handler.read_config::<FakeConfig>(0, &mut buf).unwrap();
            // Check if the obtained config data is correct.
            let config = FakeConfig::from_slice(&buf).unwrap();
            assert_eq!(*config, FAKE_CONFIG_DATA);

            println!("set_mem_table");
            let mem = GuestMemory::new(&vec![(GuestAddress(0x0), 0x10000)]).unwrap();
            vmm_handler.set_mem_table(&mem).unwrap();

            for idx in 0..QUEUES_NUM {
                println!("activate_mem_table: queue_index={}", idx);
                let queue = Queue::new(0x10);
                let queue_evt = Event::new().unwrap();
                let irqfd = Event::new().unwrap();

                vmm_handler
                    .activate_vring(&mem, 0, &queue, &queue_evt, &irqfd)
                    .unwrap();
            }

            vmm_bar.wait();
        });

        // Device side
        let handler = Arc::new(std::sync::Mutex::new(
            DeviceRequestHandler::new(FakeBackend::new()).unwrap(),
        ));
        let mut listener = SlaveListener::new(listener, handler).unwrap();

        // Notify listener is ready.
        tx.send(()).unwrap();

        let mut listener = listener.accept().unwrap().unwrap();

        // VhostUserHandler::new()
        listener.handle_request().expect("set_owner");
        listener.handle_request().expect("get_features");
        listener.handle_request().expect("set_features");
        listener.handle_request().expect("get_protocol_features");
        listener.handle_request().expect("set_protocol_features");

        // VhostUserHandler::read_config()
        listener.handle_request().expect("get_config");

        // VhostUserHandler::set_mem_table()
        listener.handle_request().expect("set_mem_table");

        for _ in 0..QUEUES_NUM {
            // VhostUserHandler::activate_vring()
            listener.handle_request().expect("set_vring_num");
            listener.handle_request().expect("set_vring_addr");
            listener.handle_request().expect("set_vring_base");
            listener.handle_request().expect("set_vring_call");
            listener.handle_request().expect("set_vring_kick");
            listener.handle_request().expect("set_vring_enable");
        }

        dev_bar.wait();
    }
}
