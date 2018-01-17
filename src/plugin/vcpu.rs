// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::{Cell, RefCell};
use std::cmp::min;
use std::cmp::{self, Ord, PartialOrd, PartialEq};
use std::collections::btree_set::BTreeSet;
use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, Mutex, RwLock};

use libc::{EINVAL, EPROTO, ENOENT, EPERM, EPIPE, EDEADLK, ENOTTY};

use protobuf;
use protobuf::Message;

use data_model::DataInit;
use kvm::Vcpu;
use kvm_sys::{kvm_regs, kvm_sregs, kvm_fpu};
use plugin_proto::*;

use super::*;

/// Identifier for an address space in the VM.
#[derive(Copy, Clone)]
pub enum IoSpace {
    Ioport,
    Mmio,
}

#[derive(Debug, Copy, Clone)]
struct Range(u64, u64);

impl Eq for Range {}

impl PartialEq for Range {
    fn eq(&self, other: &Range) -> bool {
        self.0 == other.0
    }
}

impl Ord for Range {
    fn cmp(&self, other: &Range) -> cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for Range {
    fn partial_cmp(&self, other: &Range) -> Option<cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

// Wrapper types to make the kvm register structs DataInit
#[derive(Copy, Clone)]
struct VcpuRegs(kvm_regs);
unsafe impl DataInit for VcpuRegs {}
#[derive(Copy, Clone)]
struct VcpuSregs(kvm_sregs);
unsafe impl DataInit for VcpuSregs {}
#[derive(Copy, Clone)]
struct VcpuFpu(kvm_fpu);
unsafe impl DataInit for VcpuFpu {}


fn get_vcpu_state(vcpu: &Vcpu, state_set: VcpuRequest_StateSet) -> SysResult<Vec<u8>> {
    Ok(match state_set {
           VcpuRequest_StateSet::REGS => VcpuRegs(vcpu.get_regs()?).as_slice().to_vec(),
           VcpuRequest_StateSet::SREGS => VcpuSregs(vcpu.get_sregs()?).as_slice().to_vec(),
           VcpuRequest_StateSet::FPU => VcpuFpu(vcpu.get_fpu()?).as_slice().to_vec(),
       })
}

fn set_vcpu_state(vcpu: &Vcpu, state_set: VcpuRequest_StateSet, state: &[u8]) -> SysResult<()> {
    match state_set {
        VcpuRequest_StateSet::REGS => {
            vcpu.set_regs(&VcpuRegs::from_slice(state)
                               .ok_or(SysError::new(-EINVAL))?
                               .0)
        }
        VcpuRequest_StateSet::SREGS => {
            vcpu.set_sregs(&VcpuSregs::from_slice(state)
                                .ok_or(SysError::new(-EINVAL))?
                                .0)
        }
        VcpuRequest_StateSet::FPU => {
            vcpu.set_fpu(&VcpuFpu::from_slice(state)
                              .ok_or(SysError::new(-EINVAL))?
                              .0)
        }
    }
}


/// State shared by every VCPU, grouped together to make edits to the state coherent across VCPUs.
#[derive(Default)]
pub struct SharedVcpuState {
    ioport_regions: BTreeSet<Range>,
    mmio_regions: BTreeSet<Range>,
}

impl SharedVcpuState {
    /// Reserves the given range for handling by the plugin process.
    ///
    /// This will reject any reservation that overlaps with an existing reservation.
    pub fn reserve_range(&mut self, space: IoSpace, start: u64, length: u64) -> SysResult<()> {
        if length == 0 {
            return Err(SysError::new(-EINVAL));
        }

        // Reject all cases where this reservation is part of another reservation.
        if self.is_reserved(space, start) {
            return Err(SysError::new(-EPERM));
        }

        let last_address = match start.checked_add(length) {
            Some(end) => end - 1,
            None => return Err(SysError::new(-EINVAL)),
        };

        let space = match space {
            IoSpace::Ioport => &mut self.ioport_regions,
            IoSpace::Mmio => &mut self.mmio_regions,
        };

        match space
                  .range(..Range(last_address, 0))
                  .next_back()
                  .cloned() {
            Some(Range(existing_start, _)) if existing_start >= start => Err(SysError::new(-EPERM)),
            _ => {
                space.insert(Range(start, length));
                Ok(())
            }
        }
    }

    //// Releases a reservation previously made at `start` in the given `space`.
    pub fn unreserve_range(&mut self, space: IoSpace, start: u64) -> SysResult<()> {
        let range = Range(start, 0);
        let space = match space {
            IoSpace::Ioport => &mut self.ioport_regions,
            IoSpace::Mmio => &mut self.mmio_regions,
        };
        if space.remove(&range) {
            Ok(())
        } else {
            Err(SysError::new(-ENOENT))
        }
    }

    fn is_reserved(&self, space: IoSpace, addr: u64) -> bool {
        if let Some(Range(start, len)) = self.first_before(space, addr) {
            let offset = addr - start;
            if offset < len {
                return true;
            }
        }
        false
    }

    fn first_before(&self, io_space: IoSpace, addr: u64) -> Option<Range> {
        let space = match io_space {
            IoSpace::Ioport => &self.ioport_regions,
            IoSpace::Mmio => &self.mmio_regions,
        };

        match addr.checked_add(1) {
            Some(next_addr) => space.range(..Range(next_addr, 0)).next_back().cloned(),
            None => None,
        }
    }
}

/// State specific to a VCPU, grouped so that each `PluginVcpu` object will share a canonical
/// version.
#[derive(Default)]
pub struct PerVcpuState {
    pause_request: Option<u64>,
}

impl PerVcpuState {
    /// Indicates that a VCPU should wait until the plugin process resumes the VCPU.
    ///
    /// This method will not cause a VCPU to pause immediately. Instead, the VCPU thread will
    /// continue running until a interrupted, at which point it will check for a pending pause. If
    /// there is another call to `request_pause` for this VCPU before that happens, the last pause
    /// request's `data` will be overwritten with the most recent `data.
    ///
    /// To get an immediate pause after calling `request_pause`, send a signal (with a registered
    /// handler) to the thread handling the VCPU corresponding to this state. This should interrupt
    /// the running VCPU, which should check for a pause with `PluginVcpu::pre_run`.
    pub fn request_pause(&mut self, data: u64) {
        self.pause_request = Some(data);
    }
}

enum VcpuRunData<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

impl<'a> VcpuRunData<'a> {
    fn is_write(&self) -> bool {
        match self {
            &VcpuRunData::Write(_) => true,
            _ => false,
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            &VcpuRunData::Read(ref s) => s,
            &VcpuRunData::Write(ref s) => s,
        }
    }

    fn copy_from_slice(&mut self, data: &[u8]) {
        match self {
            &mut VcpuRunData::Read(ref mut s) => {
                let copy_size = min(s.len(), data.len());
                s.copy_from_slice(&data[..copy_size]);
            }
            _ => {}
        }
    }
}

/// State object for a VCPU's connection with the plugin process.
///
/// This is used by a VCPU thread to allow the plugin process to handle vmexits. Each method may
/// block indefinitely while the plugin process is handling requests. In order to cleanly shutdown
/// during these blocking calls, the `connection` socket should be shutdown. This will end the
/// blocking calls,
pub struct PluginVcpu {
    shared_vcpu_state: Arc<RwLock<SharedVcpuState>>,
    per_vcpu_state: Arc<Mutex<PerVcpuState>>,
    connection: UnixDatagram,
    wait_reason: Cell<Option<VcpuResponse_Wait>>,
    request_buffer: RefCell<Vec<u8>>,
    response_buffer: RefCell<Vec<u8>>,
}

impl PluginVcpu {
    /// Creates the plugin state and connection container for a VCPU thread.
    pub fn new(shared_vcpu_state: Arc<RwLock<SharedVcpuState>>,
               per_vcpu_state: Arc<Mutex<PerVcpuState>>,
               connection: UnixDatagram)
               -> PluginVcpu {
        PluginVcpu {
            shared_vcpu_state,
            per_vcpu_state,
            connection,
            wait_reason: Default::default(),
            request_buffer: Default::default(),
            response_buffer: Default::default(),
        }
    }

    /// Tells the plugin process to initialize this VCPU.
    ///
    /// This should be called for each VCPU before the first run of any of the VCPUs in the VM.
    pub fn init(&self, vcpu: &Vcpu) -> SysResult<()> {
        let mut wait_reason = VcpuResponse_Wait::new();
        wait_reason.mut_init();
        self.wait_reason.set(Some(wait_reason));
        self.handle_until_resume(vcpu)?;
        Ok(())
    }

    /// The VCPU thread should call this before rerunning a VM in order to handle pending requests
    /// to this VCPU.
    pub fn pre_run(&self, vcpu: &Vcpu) -> SysResult<()> {
        match self.per_vcpu_state.lock() {
            Ok(mut per_vcpu_state) => {
                if let Some(user) = per_vcpu_state.pause_request.take() {
                    let mut wait_reason = VcpuResponse_Wait::new();
                    wait_reason.mut_user().user = user;
                    self.wait_reason.set(Some(wait_reason));
                    self.handle_until_resume(vcpu)?;
                }
                Ok(())
            }
            Err(_) => Err(SysError::new(-EDEADLK)),
        }
    }

    fn process(&self, io_space: IoSpace, addr: u64, mut data: VcpuRunData, vcpu: &Vcpu) -> bool {
        let vcpu_state_lock = match self.shared_vcpu_state.read() {
            Ok(l) => l,
            Err(e) => {
                error!("error read locking shared cpu state: {:?}", e);
                return false;
            }
        };

        let first_before_addr = vcpu_state_lock.first_before(io_space, addr);
        // Drops the read lock as soon as possible, to prevent holding lock while blocked in
        // `handle_until_resume`.
        drop(vcpu_state_lock);

        match first_before_addr {
            Some(Range(start, len)) => {
                let offset = addr - start;
                if offset >= len {
                    return false;
                }
                let mut wait_reason = VcpuResponse_Wait::new();
                {
                    let io = wait_reason.mut_io();
                    io.space = match io_space {
                        IoSpace::Ioport => AddressSpace::IOPORT,
                        IoSpace::Mmio => AddressSpace::MMIO,
                    };
                    io.address = addr;
                    io.is_write = data.is_write();
                    io.data = data.as_slice().to_vec();
                }
                self.wait_reason.set(Some(wait_reason));
                match self.handle_until_resume(vcpu) {
                    Ok(resume_data) => data.copy_from_slice(&resume_data),
                    Err(e) if e.errno() == -EPIPE => {}
                    Err(e) => error!("failed to process vcpu requests: {:?}", e),
                }
                true
            }
            None => false,
        }
    }

    /// Has the plugin process handle a IO port read.
    pub fn io_read(&self, addr: u64, data: &mut [u8], vcpu: &Vcpu) -> bool {
        self.process(IoSpace::Ioport, addr, VcpuRunData::Read(data), vcpu)
    }

    /// Has the plugin process handle a IO port write.
    pub fn io_write(&self, addr: u64, data: &[u8], vcpu: &Vcpu) -> bool {
        self.process(IoSpace::Ioport, addr, VcpuRunData::Write(data), vcpu)
    }

    /// Has the plugin process handle a MMIO read.
    pub fn mmio_read(&self, addr: u64, data: &mut [u8], vcpu: &Vcpu) -> bool {
        self.process(IoSpace::Mmio, addr, VcpuRunData::Read(data), vcpu)
    }

    /// Has the plugin process handle a MMIO write.
    pub fn mmio_write(&self, addr: u64, data: &[u8], vcpu: &Vcpu) -> bool {
        self.process(IoSpace::Mmio, addr, VcpuRunData::Write(data), vcpu)
    }

    fn handle_request(&self, vcpu: &Vcpu) -> SysResult<Option<Vec<u8>>> {
        let mut resume_data = None;
        let mut request_buffer = self.request_buffer.borrow_mut();
        request_buffer.resize(MAX_VCPU_DATAGRAM_SIZE, 0);

        let msg_size = self.connection
            .recv(&mut request_buffer)
            .map_err(io_to_sys_err)?;


        let mut request = protobuf::parse_from_bytes::<VcpuRequest>(&request_buffer[..msg_size])
            .map_err(proto_to_sys_err)?;

        let wait_reason = self.wait_reason.take();

        let mut response = VcpuResponse::new();
        let res = if request.has_wait() {
            match wait_reason {
                Some(wait_reason) => {
                    response.set_wait(wait_reason);
                    Ok(())
                }
                None => Err(SysError::new(-EPROTO)),
            }
        } else if wait_reason.is_some() {
            // Any request other than getting the wait_reason while there is one pending is invalid.
            self.wait_reason.set(wait_reason);
            Err(SysError::new(-EPROTO))
        } else if request.has_resume() {
            response.mut_resume();
            resume_data = Some(request.take_resume().take_data());
            Ok(())
        } else if request.has_get_state() {
            let response_state = response.mut_get_state();
            match get_vcpu_state(vcpu, request.get_get_state().set) {
                Ok(state) => {
                    response_state.state = state;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else if request.has_set_state() {
            response.mut_set_state();
            let set_state = request.get_set_state();
            set_vcpu_state(vcpu, set_state.set, set_state.get_state())
        } else {
            Err(SysError::new(-ENOTTY))
        };

        if let Err(e) = res {
            response.errno = e.errno();
        }

        let mut response_buffer = self.response_buffer.borrow_mut();
        response_buffer.clear();
        response
            .write_to_vec(&mut response_buffer)
            .map_err(proto_to_sys_err)?;
        self.connection
            .send(&response_buffer[..])
            .map_err(io_to_sys_err)?;

        Ok(resume_data)
    }

    fn handle_until_resume(&self, vcpu: &Vcpu) -> SysResult<Vec<u8>> {
        loop {
            if let Some(resume_data) = self.handle_request(vcpu)? {
                return Ok(resume_data);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_vcpu_reserve() {
        let mut shared_vcpu_state = SharedVcpuState::default();
        shared_vcpu_state
            .reserve_range(IoSpace::Ioport, 0x10, 0)
            .unwrap_err();
        shared_vcpu_state
            .reserve_range(IoSpace::Ioport, 0x10, 0x10)
            .unwrap();
        shared_vcpu_state
            .reserve_range(IoSpace::Ioport, 0x0f, 0x10)
            .unwrap_err();
        shared_vcpu_state
            .reserve_range(IoSpace::Ioport, 0x10, 0x10)
            .unwrap_err();
        shared_vcpu_state
            .reserve_range(IoSpace::Ioport, 0x10, 0x15)
            .unwrap_err();
        shared_vcpu_state
            .reserve_range(IoSpace::Ioport, 0x12, 0x15)
            .unwrap_err();
        shared_vcpu_state
            .reserve_range(IoSpace::Ioport, 0x12, 0x01)
            .unwrap_err();
        shared_vcpu_state
            .reserve_range(IoSpace::Ioport, 0x0, 0x20)
            .unwrap_err();
        shared_vcpu_state
            .reserve_range(IoSpace::Ioport, 0x20, 0x05)
            .unwrap();
        shared_vcpu_state
            .reserve_range(IoSpace::Ioport, 0x25, 0x05)
            .unwrap();
        shared_vcpu_state
            .reserve_range(IoSpace::Ioport, 0x0, 0x10)
            .unwrap();
    }
}
