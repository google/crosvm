// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::slice;
use std::sync::{Arc, Mutex};

use data_model::DataInit;

use super::connection::{Endpoint, EndpointExt, SocketEndpoint};
use super::message::*;
use super::{take_single_file, Error, Result};

/// Services provided to the master by the slave with interior mutability.
///
/// The [VhostUserSlaveReqHandler] trait defines the services provided to the master by the slave.
/// And the [VhostUserSlaveReqHandlerMut] trait is a helper mirroring [VhostUserSlaveReqHandler],
/// but without interior mutability.
/// The vhost-user specification defines a master communication channel, by which masters could
/// request services from slaves. The [VhostUserSlaveReqHandler] trait defines services provided by
/// slaves, and it's used both on the master side and slave side.
///
/// - on the master side, a stub forwarder implementing [VhostUserSlaveReqHandler] will proxy
///   service requests to slaves.
/// - on the slave side, the [SlaveReqHandler] will forward service requests to a handler
///   implementing [VhostUserSlaveReqHandler].
///
/// The [VhostUserSlaveReqHandler] trait is design with interior mutability to improve performance
/// for multi-threading.
///
/// [VhostUserSlaveReqHandler]: trait.VhostUserSlaveReqHandler.html
/// [VhostUserSlaveReqHandlerMut]: trait.VhostUserSlaveReqHandlerMut.html
/// [SlaveReqHandler]: struct.SlaveReqHandler.html
#[allow(missing_docs)]
pub trait VhostUserSlaveReqHandler {
    fn set_owner(&self) -> Result<()>;
    fn reset_owner(&self) -> Result<()>;
    fn get_features(&self) -> Result<u64>;
    fn set_features(&self, features: u64) -> Result<()>;
    fn set_mem_table(&self, ctx: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()>;
    fn set_vring_num(&self, index: u32, num: u32) -> Result<()>;
    fn set_vring_addr(
        &self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()>;
    fn set_vring_base(&self, index: u32, base: u32) -> Result<()>;
    fn get_vring_base(&self, index: u32) -> Result<VhostUserVringState>;
    fn set_vring_kick(&self, index: u8, fd: Option<File>) -> Result<()>;
    fn set_vring_call(&self, index: u8, fd: Option<File>) -> Result<()>;
    fn set_vring_err(&self, index: u8, fd: Option<File>) -> Result<()>;

    fn get_protocol_features(&self) -> Result<VhostUserProtocolFeatures>;
    fn set_protocol_features(&self, features: u64) -> Result<()>;
    fn get_queue_num(&self) -> Result<u64>;
    fn set_vring_enable(&self, index: u32, enable: bool) -> Result<()>;
    fn get_config(&self, offset: u32, size: u32, flags: VhostUserConfigFlags) -> Result<Vec<u8>>;
    fn set_config(&self, offset: u32, buf: &[u8], flags: VhostUserConfigFlags) -> Result<()>;
    fn set_slave_req_fd(&self, _vu_req: File) {}
    fn get_inflight_fd(&self, inflight: &VhostUserInflight) -> Result<(VhostUserInflight, File)>;
    fn set_inflight_fd(&self, inflight: &VhostUserInflight, file: File) -> Result<()>;
    fn get_max_mem_slots(&self) -> Result<u64>;
    fn add_mem_region(&self, region: &VhostUserSingleMemoryRegion, fd: File) -> Result<()>;
    fn remove_mem_region(&self, region: &VhostUserSingleMemoryRegion) -> Result<()>;
}

/// Services provided to the master by the slave without interior mutability.
///
/// This is a helper trait mirroring the [VhostUserSlaveReqHandler] trait.
#[allow(missing_docs)]
pub trait VhostUserSlaveReqHandlerMut {
    fn set_owner(&mut self) -> Result<()>;
    fn reset_owner(&mut self) -> Result<()>;
    fn get_features(&mut self) -> Result<u64>;
    fn set_features(&mut self, features: u64) -> Result<()>;
    fn set_mem_table(&mut self, ctx: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()>;
    fn set_vring_num(&mut self, index: u32, num: u32) -> Result<()>;
    fn set_vring_addr(
        &mut self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()>;
    fn set_vring_base(&mut self, index: u32, base: u32) -> Result<()>;
    fn get_vring_base(&mut self, index: u32) -> Result<VhostUserVringState>;
    fn set_vring_kick(&mut self, index: u8, fd: Option<File>) -> Result<()>;
    fn set_vring_call(&mut self, index: u8, fd: Option<File>) -> Result<()>;
    fn set_vring_err(&mut self, index: u8, fd: Option<File>) -> Result<()>;

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures>;
    fn set_protocol_features(&mut self, features: u64) -> Result<()>;
    fn get_queue_num(&mut self) -> Result<u64>;
    fn set_vring_enable(&mut self, index: u32, enable: bool) -> Result<()>;
    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
    ) -> Result<Vec<u8>>;
    fn set_config(&mut self, offset: u32, buf: &[u8], flags: VhostUserConfigFlags) -> Result<()>;
    fn set_slave_req_fd(&mut self, _vu_req: File) {}
    fn get_inflight_fd(
        &mut self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)>;
    fn set_inflight_fd(&mut self, inflight: &VhostUserInflight, file: File) -> Result<()>;
    fn get_max_mem_slots(&mut self) -> Result<u64>;
    fn add_mem_region(&mut self, region: &VhostUserSingleMemoryRegion, fd: File) -> Result<()>;
    fn remove_mem_region(&mut self, region: &VhostUserSingleMemoryRegion) -> Result<()>;
}

impl<T: VhostUserSlaveReqHandlerMut> VhostUserSlaveReqHandler for Mutex<T> {
    fn set_owner(&self) -> Result<()> {
        self.lock().unwrap().set_owner()
    }

    fn reset_owner(&self) -> Result<()> {
        self.lock().unwrap().reset_owner()
    }

    fn get_features(&self) -> Result<u64> {
        self.lock().unwrap().get_features()
    }

    fn set_features(&self, features: u64) -> Result<()> {
        self.lock().unwrap().set_features(features)
    }

    fn set_mem_table(&self, ctx: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()> {
        self.lock().unwrap().set_mem_table(ctx, files)
    }

    fn set_vring_num(&self, index: u32, num: u32) -> Result<()> {
        self.lock().unwrap().set_vring_num(index, num)
    }

    fn set_vring_addr(
        &self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()> {
        self.lock()
            .unwrap()
            .set_vring_addr(index, flags, descriptor, used, available, log)
    }

    fn set_vring_base(&self, index: u32, base: u32) -> Result<()> {
        self.lock().unwrap().set_vring_base(index, base)
    }

    fn get_vring_base(&self, index: u32) -> Result<VhostUserVringState> {
        self.lock().unwrap().get_vring_base(index)
    }

    fn set_vring_kick(&self, index: u8, fd: Option<File>) -> Result<()> {
        self.lock().unwrap().set_vring_kick(index, fd)
    }

    fn set_vring_call(&self, index: u8, fd: Option<File>) -> Result<()> {
        self.lock().unwrap().set_vring_call(index, fd)
    }

    fn set_vring_err(&self, index: u8, fd: Option<File>) -> Result<()> {
        self.lock().unwrap().set_vring_err(index, fd)
    }

    fn get_protocol_features(&self) -> Result<VhostUserProtocolFeatures> {
        self.lock().unwrap().get_protocol_features()
    }

    fn set_protocol_features(&self, features: u64) -> Result<()> {
        self.lock().unwrap().set_protocol_features(features)
    }

    fn get_queue_num(&self) -> Result<u64> {
        self.lock().unwrap().get_queue_num()
    }

    fn set_vring_enable(&self, index: u32, enable: bool) -> Result<()> {
        self.lock().unwrap().set_vring_enable(index, enable)
    }

    fn get_config(&self, offset: u32, size: u32, flags: VhostUserConfigFlags) -> Result<Vec<u8>> {
        self.lock().unwrap().get_config(offset, size, flags)
    }

    fn set_config(&self, offset: u32, buf: &[u8], flags: VhostUserConfigFlags) -> Result<()> {
        self.lock().unwrap().set_config(offset, buf, flags)
    }

    fn set_slave_req_fd(&self, vu_req: File) {
        self.lock().unwrap().set_slave_req_fd(vu_req)
    }

    fn get_inflight_fd(&self, inflight: &VhostUserInflight) -> Result<(VhostUserInflight, File)> {
        self.lock().unwrap().get_inflight_fd(inflight)
    }

    fn set_inflight_fd(&self, inflight: &VhostUserInflight, file: File) -> Result<()> {
        self.lock().unwrap().set_inflight_fd(inflight, file)
    }

    fn get_max_mem_slots(&self) -> Result<u64> {
        self.lock().unwrap().get_max_mem_slots()
    }

    fn add_mem_region(&self, region: &VhostUserSingleMemoryRegion, fd: File) -> Result<()> {
        self.lock().unwrap().add_mem_region(region, fd)
    }

    fn remove_mem_region(&self, region: &VhostUserSingleMemoryRegion) -> Result<()> {
        self.lock().unwrap().remove_mem_region(region)
    }
}

/// Server to handle service requests from masters from the master communication channel.
///
/// The [SlaveReqHandler] acts as a server on the slave side, to handle service requests from
/// masters on the master communication channel. It's actually a proxy invoking the registered
/// handler implementing [VhostUserSlaveReqHandler] to do the real work.
///
/// The lifetime of the SlaveReqHandler object should be the same as the underline Unix Domain
/// Socket, so it gets simpler to recover from disconnect.
///
/// [VhostUserSlaveReqHandler]: trait.VhostUserSlaveReqHandler.html
/// [SlaveReqHandler]: struct.SlaveReqHandler.html
pub struct SlaveReqHandler<S: VhostUserSlaveReqHandler, E: Endpoint<MasterReq>> {
    // underlying Unix domain socket for communication
    main_sock: E,
    // the vhost-user backend device object
    backend: Arc<S>,

    virtio_features: u64,
    acked_virtio_features: u64,
    protocol_features: VhostUserProtocolFeatures,
    acked_protocol_features: u64,

    // sending ack for messages without payload
    reply_ack_enabled: bool,
    // whether the endpoint has encountered any failure
    error: Option<i32>,
}

impl<S: VhostUserSlaveReqHandler> SlaveReqHandler<S, SocketEndpoint<MasterReq>> {
    /// Create a vhost-user slave endpoint from a connected socket.
    pub fn from_stream(socket: UnixStream, backend: Arc<S>) -> Self {
        Self::new(SocketEndpoint::from_stream(socket), backend)
    }
}

impl<S: VhostUserSlaveReqHandler, E: Endpoint<MasterReq>> SlaveReqHandler<S, E> {
    /// Create a vhost-user slave endpoint.
    pub(super) fn new(main_sock: E, backend: Arc<S>) -> Self {
        SlaveReqHandler {
            main_sock,
            backend,
            virtio_features: 0,
            acked_virtio_features: 0,
            protocol_features: VhostUserProtocolFeatures::empty(),
            acked_protocol_features: 0,
            reply_ack_enabled: false,
            error: None,
        }
    }

    /// Create a new vhost-user slave endpoint.
    ///
    /// # Arguments
    /// * - `path` - path of Unix domain socket listener to connect to
    /// * - `backend` - handler for requests from the master to the slave
    pub fn connect(path: &str, backend: Arc<S>) -> Result<Self> {
        Ok(Self::new(Endpoint::<MasterReq>::connect(path)?, backend))
    }

    /// Mark endpoint as failed with specified error code.
    pub fn set_failed(&mut self, error: i32) {
        self.error = Some(error);
    }

    /// Main entrance to server slave request from the slave communication channel.
    ///
    /// Receive and handle one incoming request message from the master. The caller needs to:
    /// - serialize calls to this function
    /// - decide what to do when error happens
    /// - optional recover from failure
    pub fn handle_request(&mut self) -> Result<()> {
        // Return error if the endpoint is already in failed state.
        self.check_state()?;

        // The underlying communication channel is a Unix domain socket in
        // stream mode, and recvmsg() is a little tricky here. To successfully
        // receive attached file descriptors, we need to receive messages and
        // corresponding attached file descriptors in this way:
        // . recv messsage header and optional attached file
        // . validate message header
        // . recv optional message body and payload according size field in
        //   message header
        // . validate message body and optional payload
        let (hdr, files) = self.main_sock.recv_header()?;
        self.check_attached_files(&hdr, &files)?;

        let buf = match hdr.get_size() {
            0 => vec![0u8; 0],
            len => {
                let rbuf = self.main_sock.recv_data(len as usize)?;
                if rbuf.len() != len as usize {
                    return Err(Error::InvalidMessage);
                }
                rbuf
            }
        };
        let size = buf.len();

        match hdr.get_code() {
            MasterReq::SET_OWNER => {
                self.check_request_size(&hdr, size, 0)?;
                let res = self.backend.set_owner();
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::RESET_OWNER => {
                self.check_request_size(&hdr, size, 0)?;
                let res = self.backend.reset_owner();
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::GET_FEATURES => {
                self.check_request_size(&hdr, size, 0)?;
                let features = self.backend.get_features()?;
                let msg = VhostUserU64::new(features);
                self.send_reply_message(&hdr, &msg)?;
                self.virtio_features = features;
                self.update_reply_ack_flag();
            }
            MasterReq::SET_FEATURES => {
                let msg = self.extract_request_body::<VhostUserU64>(&hdr, size, &buf)?;
                let res = self.backend.set_features(msg.value);
                self.acked_virtio_features = msg.value;
                self.update_reply_ack_flag();
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::SET_MEM_TABLE => {
                let res = self.set_mem_table(&hdr, size, &buf, files);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::SET_VRING_NUM => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let res = self.backend.set_vring_num(msg.index, msg.num);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::SET_VRING_ADDR => {
                let msg = self.extract_request_body::<VhostUserVringAddr>(&hdr, size, &buf)?;
                let flags = match VhostUserVringAddrFlags::from_bits(msg.flags) {
                    Some(val) => val,
                    None => return Err(Error::InvalidMessage),
                };
                let res = self.backend.set_vring_addr(
                    msg.index,
                    flags,
                    msg.descriptor,
                    msg.used,
                    msg.available,
                    msg.log,
                );
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::SET_VRING_BASE => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let res = self.backend.set_vring_base(msg.index, msg.num);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::GET_VRING_BASE => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let reply = self.backend.get_vring_base(msg.index)?;
                self.send_reply_message(&hdr, &reply)?;
            }
            MasterReq::SET_VRING_CALL => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_call(index, file);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::SET_VRING_KICK => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_kick(index, file);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::SET_VRING_ERR => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_err(index, file);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::GET_PROTOCOL_FEATURES => {
                self.check_request_size(&hdr, size, 0)?;
                let features = self.backend.get_protocol_features()?;
                let msg = VhostUserU64::new(features.bits());
                self.send_reply_message(&hdr, &msg)?;
                self.protocol_features = features;
                self.update_reply_ack_flag();
            }
            MasterReq::SET_PROTOCOL_FEATURES => {
                let msg = self.extract_request_body::<VhostUserU64>(&hdr, size, &buf)?;
                let res = self.backend.set_protocol_features(msg.value);
                self.acked_protocol_features = msg.value;
                self.update_reply_ack_flag();
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::GET_QUEUE_NUM => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, 0)?;
                let num = self.backend.get_queue_num()?;
                let msg = VhostUserU64::new(num);
                self.send_reply_message(&hdr, &msg)?;
            }
            MasterReq::SET_VRING_ENABLE => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                if self.acked_virtio_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                let enable = match msg.num {
                    1 => true,
                    0 => false,
                    _ => return Err(Error::InvalidParam),
                };

                let res = self.backend.set_vring_enable(msg.index, enable);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::GET_CONFIG => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                self.get_config(&hdr, &buf)?;
            }
            MasterReq::SET_CONFIG => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                let res = self.set_config(size, &buf);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::SET_SLAVE_REQ_FD => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::SLAVE_REQ.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                let res = self.set_slave_req_fd(files);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::GET_INFLIGHT_FD => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }

                let msg = self.extract_request_body::<VhostUserInflight>(&hdr, size, &buf)?;
                let (inflight, file) = self.backend.get_inflight_fd(&msg)?;
                let reply_hdr = self.new_reply_header::<VhostUserInflight>(&hdr, 0)?;
                self.main_sock
                    .send_message(&reply_hdr, &inflight, Some(&[file.as_raw_fd()]))?;
            }
            MasterReq::SET_INFLIGHT_FD => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::INFLIGHT_SHMFD.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                let file = take_single_file(files).ok_or(Error::IncorrectFds)?;
                let msg = self.extract_request_body::<VhostUserInflight>(&hdr, size, &buf)?;
                let res = self.backend.set_inflight_fd(&msg, file);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::GET_MAX_MEM_SLOTS => {
                if self.acked_protocol_features
                    & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                self.check_request_size(&hdr, size, 0)?;
                let num = self.backend.get_max_mem_slots()?;
                let msg = VhostUserU64::new(num);
                self.send_reply_message(&hdr, &msg)?;
            }
            MasterReq::ADD_MEM_REG => {
                if self.acked_protocol_features
                    & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }
                let mut files = files.ok_or(Error::InvalidParam)?;
                if files.len() != 1 {
                    return Err(Error::InvalidParam);
                }
                let msg =
                    self.extract_request_body::<VhostUserSingleMemoryRegion>(&hdr, size, &buf)?;
                let res = self.backend.add_mem_region(&msg, files.swap_remove(0));
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::REM_MEM_REG => {
                if self.acked_protocol_features
                    & VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS.bits()
                    == 0
                {
                    return Err(Error::InvalidOperation);
                }

                let msg =
                    self.extract_request_body::<VhostUserSingleMemoryRegion>(&hdr, size, &buf)?;
                let res = self.backend.remove_mem_region(&msg);
                self.send_ack_message(&hdr, res)?;
            }
            _ => {
                return Err(Error::InvalidMessage);
            }
        }
        Ok(())
    }

    fn set_mem_table(
        &mut self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        size: usize,
        buf: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<()> {
        self.check_request_size(hdr, size, hdr.get_size() as usize)?;

        // check message size is consistent
        let hdrsize = mem::size_of::<VhostUserMemory>();
        if size < hdrsize {
            return Err(Error::InvalidMessage);
        }
        let msg = unsafe { &*(buf.as_ptr() as *const VhostUserMemory) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if size != hdrsize + msg.num_regions as usize * mem::size_of::<VhostUserMemoryRegion>() {
            return Err(Error::InvalidMessage);
        }

        // validate number of fds matching number of memory regions
        let files = files.ok_or(Error::InvalidMessage)?;
        if files.len() != msg.num_regions as usize {
            return Err(Error::InvalidMessage);
        }

        // Validate memory regions
        let regions = unsafe {
            slice::from_raw_parts(
                buf.as_ptr().add(hdrsize) as *const VhostUserMemoryRegion,
                msg.num_regions as usize,
            )
        };
        for region in regions.iter() {
            if !region.is_valid() {
                return Err(Error::InvalidMessage);
            }
        }

        self.backend.set_mem_table(regions, files)
    }

    fn get_config(&mut self, hdr: &VhostUserMsgHeader<MasterReq>, buf: &[u8]) -> Result<()> {
        let payload_offset = mem::size_of::<VhostUserConfig>();
        if buf.len() > MAX_MSG_SIZE || buf.len() < payload_offset {
            return Err(Error::InvalidMessage);
        }
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const VhostUserConfig) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if buf.len() - payload_offset != msg.size as usize {
            return Err(Error::InvalidMessage);
        }
        let flags = match VhostUserConfigFlags::from_bits(msg.flags) {
            Some(val) => val,
            None => return Err(Error::InvalidMessage),
        };
        let res = self.backend.get_config(msg.offset, msg.size, flags);

        // vhost-user slave's payload size MUST match master's request
        // on success, uses zero length of payload to indicate an error
        // to vhost-user master.
        match res {
            Ok(ref buf) if buf.len() == msg.size as usize => {
                let reply = VhostUserConfig::new(msg.offset, buf.len() as u32, flags);
                self.send_reply_with_payload(hdr, &reply, buf.as_slice())?;
            }
            Ok(_) => {
                let reply = VhostUserConfig::new(msg.offset, 0, flags);
                self.send_reply_message(hdr, &reply)?;
            }
            Err(_) => {
                let reply = VhostUserConfig::new(msg.offset, 0, flags);
                self.send_reply_message(hdr, &reply)?;
            }
        }
        Ok(())
    }

    fn set_config(&mut self, size: usize, buf: &[u8]) -> Result<()> {
        if size > MAX_MSG_SIZE || size < mem::size_of::<VhostUserConfig>() {
            return Err(Error::InvalidMessage);
        }
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const VhostUserConfig) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if size - mem::size_of::<VhostUserConfig>() != msg.size as usize {
            return Err(Error::InvalidMessage);
        }
        let flags: VhostUserConfigFlags;
        match VhostUserConfigFlags::from_bits(msg.flags) {
            Some(val) => flags = val,
            None => return Err(Error::InvalidMessage),
        }

        self.backend.set_config(msg.offset, buf, flags)
    }

    fn set_slave_req_fd(&mut self, files: Option<Vec<File>>) -> Result<()> {
        let file = take_single_file(files).ok_or(Error::InvalidMessage)?;
        self.backend.set_slave_req_fd(file);
        Ok(())
    }

    fn handle_vring_fd_request(
        &mut self,
        buf: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<(u8, Option<File>)> {
        if buf.len() > MAX_MSG_SIZE || buf.len() < mem::size_of::<VhostUserU64>() {
            return Err(Error::InvalidMessage);
        }
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const VhostUserU64) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }

        // Bits (0-7) of the payload contain the vring index. Bit 8 is the
        // invalid FD flag. This bit is set when there is no file descriptor
        // in the ancillary data. This signals that polling will be used
        // instead of waiting for the call.
        // If Bit 8 is unset, the data must contain a file descriptor.
        let has_fd = (msg.value & 0x100u64) == 0;

        let file = take_single_file(files);

        if has_fd && file.is_none() || !has_fd && file.is_some() {
            return Err(Error::InvalidMessage);
        }

        Ok((msg.value as u8, file))
    }

    fn check_state(&self) -> Result<()> {
        match self.error {
            Some(e) => Err(Error::SocketBroken(std::io::Error::from_raw_os_error(e))),
            None => Ok(()),
        }
    }

    fn check_request_size(
        &self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        size: usize,
        expected: usize,
    ) -> Result<()> {
        if hdr.get_size() as usize != expected
            || hdr.is_reply()
            || hdr.get_version() != 0x1
            || size != expected
        {
            return Err(Error::InvalidMessage);
        }
        Ok(())
    }

    fn check_attached_files(
        &self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        files: &Option<Vec<File>>,
    ) -> Result<()> {
        match hdr.get_code() {
            MasterReq::SET_MEM_TABLE
            | MasterReq::SET_VRING_CALL
            | MasterReq::SET_VRING_KICK
            | MasterReq::SET_VRING_ERR
            | MasterReq::SET_LOG_BASE
            | MasterReq::SET_LOG_FD
            | MasterReq::SET_SLAVE_REQ_FD
            | MasterReq::SET_INFLIGHT_FD
            | MasterReq::ADD_MEM_REG => Ok(()),
            _ if files.is_some() => Err(Error::InvalidMessage),
            _ => Ok(()),
        }
    }

    fn extract_request_body<T: Sized + DataInit + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        size: usize,
        buf: &[u8],
    ) -> Result<T> {
        self.check_request_size(hdr, size, mem::size_of::<T>())?;
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const T) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        Ok(msg)
    }

    fn update_reply_ack_flag(&mut self) {
        let vflag = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let pflag = VhostUserProtocolFeatures::REPLY_ACK;
        if (self.virtio_features & vflag) != 0
            && self.protocol_features.contains(pflag)
            && (self.acked_protocol_features & pflag.bits()) != 0
        {
            self.reply_ack_enabled = true;
        } else {
            self.reply_ack_enabled = false;
        }
    }

    fn new_reply_header<T: Sized + DataInit>(
        &self,
        req: &VhostUserMsgHeader<MasterReq>,
        payload_size: usize,
    ) -> Result<VhostUserMsgHeader<MasterReq>> {
        if mem::size_of::<T>() > MAX_MSG_SIZE
            || payload_size > MAX_MSG_SIZE
            || mem::size_of::<T>() + payload_size > MAX_MSG_SIZE
        {
            return Err(Error::InvalidParam);
        }
        self.check_state()?;
        Ok(VhostUserMsgHeader::new(
            req.get_code(),
            VhostUserHeaderFlag::REPLY.bits(),
            (mem::size_of::<T>() + payload_size) as u32,
        ))
    }

    fn send_ack_message(
        &mut self,
        req: &VhostUserMsgHeader<MasterReq>,
        res: Result<()>,
    ) -> Result<()> {
        if self.reply_ack_enabled && req.is_need_reply() {
            let hdr = self.new_reply_header::<VhostUserU64>(req, 0)?;
            let val = match res {
                Ok(_) => 0,
                Err(_) => 1,
            };
            let msg = VhostUserU64::new(val);
            self.main_sock.send_message(&hdr, &msg, None)?;
        }
        res
    }

    fn send_reply_message<T: DataInit>(
        &mut self,
        req: &VhostUserMsgHeader<MasterReq>,
        msg: &T,
    ) -> Result<()> {
        let hdr = self.new_reply_header::<T>(req, 0)?;
        self.main_sock.send_message(&hdr, msg, None)?;
        Ok(())
    }

    fn send_reply_with_payload<T: Sized + DataInit>(
        &mut self,
        req: &VhostUserMsgHeader<MasterReq>,
        msg: &T,
        payload: &[u8],
    ) -> Result<()> {
        let hdr = self.new_reply_header::<T>(req, payload.len())?;
        self.main_sock
            .send_message_with_payload(&hdr, msg, payload, None)?;
        Ok(())
    }
}

impl<S: VhostUserSlaveReqHandler, E: AsRawFd + Endpoint<MasterReq>> AsRawFd
    for SlaveReqHandler<S, E>
{
    fn as_raw_fd(&self) -> RawFd {
        self.main_sock.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::AsRawFd;

    use super::*;
    use crate::dummy_slave::DummySlaveReqHandler;

    #[test]
    fn test_slave_req_handler_new() {
        let (p1, _p2) = UnixStream::pair().unwrap();
        let endpoint = SocketEndpoint::<MasterReq>::from_stream(p1);
        let backend = Arc::new(Mutex::new(DummySlaveReqHandler::new()));
        let mut handler = SlaveReqHandler::new(endpoint, backend);

        handler.check_state().unwrap();
        handler.set_failed(libc::EAGAIN);
        handler.check_state().unwrap_err();
        assert!(handler.as_raw_fd() >= 0);
    }
}
