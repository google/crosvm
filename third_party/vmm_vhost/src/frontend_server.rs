// Copyright (C) 2019-2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::mem;

use base::AsRawDescriptor;
use base::SafeDescriptor;

use crate::message::*;
use crate::Connection;
use crate::Error;
use crate::HandlerResult;
use crate::Result;
use crate::SlaveReq;
use crate::SystemStream;

/// Trait for vhost-user frontends to respond to requests from the backend.
///
/// Each method corresponds to a vhost-user protocol method. See the specification for details.
pub trait Frontend {
    /// Handle device configuration change notifications.
    fn handle_config_change(&mut self) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle shared memory region mapping requests.
    fn shmem_map(
        &mut self,
        _req: &VhostUserShmemMapMsg,
        _fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle shared memory region unmapping requests.
    fn shmem_unmap(&mut self, _req: &VhostUserShmemUnmapMsg) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    // fn handle_iotlb_msg(&mut self, iotlb: VhostUserIotlb);
    // fn handle_vring_host_notifier(&mut self, area: VhostUserVringArea, fd: RawDescriptor);

    /// Handle GPU shared memory region mapping requests.
    fn gpu_map(
        &mut self,
        _req: &VhostUserGpuMapMsg,
        _descriptor: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle external memory region mapping requests.
    fn external_map(&mut self, _req: &VhostUserExternalMapMsg) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }
}

/// Handles requests from a vhost-user backend connection by dispatching them to [[Frontend]]
/// methods.
pub struct FrontendServer<S: Frontend> {
    // underlying Unix domain socket for communication
    pub(crate) sub_sock: Connection<SlaveReq>,
    tx_sock: Option<SystemStream>,
    // Serializes tx_sock for passing to the backend.
    serialize_tx: Box<dyn Fn(SystemStream) -> SafeDescriptor + Send>,
    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    reply_ack_negotiated: bool,

    frontend: S,
}

impl<S: Frontend> FrontendServer<S> {
    /// Create a server to handle service requests from backends.
    ///
    /// This opens a pair of connected anonymous sockets to form the backend-to-frontend
    /// communication channel. The socket fd returned by [Self::take_tx_descriptor()] should be
    /// sent to the backend by [BackendClient::set_slave_request_fd()].
    ///
    /// [Self::take_tx_descriptor()]: struct.FrontendServer.html#method.take_tx_descriptor
    /// [BackendClient::set_slave_request_fd()]: struct.BackendClient.html#method.set_slave_request_fd
    pub fn new(
        frontend: S,
        serialize_tx: Box<dyn Fn(SystemStream) -> SafeDescriptor + Send>,
    ) -> Result<Self> {
        let (tx, rx) = SystemStream::pair()?;

        Ok(FrontendServer {
            sub_sock: Connection::from(rx),
            tx_sock: Some(tx),
            serialize_tx,
            reply_ack_negotiated: false,
            frontend,
        })
    }

    /// Get the descriptor for the backend to communication with the frontend.
    ///
    /// The caller owns the descriptor. The returned descriptor should be sent to the slave by
    /// [BackendClient::set_slave_request_fd()].
    ///
    /// [BackendClient::set_slave_request_fd()]: struct.BackendClient.html#method.set_slave_request_fd
    pub fn take_tx_descriptor(&mut self) -> SafeDescriptor {
        (self.serialize_tx)(self.tx_sock.take().expect("tx_sock should have a value"))
    }

    /// Set the negotiation state of the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature.
    ///
    /// When the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature has been negotiated,
    /// the "REPLY_ACK" flag will be set in the message header for every request message.
    pub fn set_reply_ack_flag(&mut self, enable: bool) {
        self.reply_ack_negotiated = enable;
    }

    /// Get the underlying frontend
    pub fn frontend_mut(&mut self) -> &mut S {
        &mut self.frontend
    }

    /// Process the next received request.
    ///
    /// The caller needs to:
    /// - serialize calls to this function
    /// - decide what to do when errer happens
    /// - optional recover from failure
    pub fn handle_request(&mut self) -> Result<u64> {
        // The underlying communication channel is a Unix domain socket in
        // stream mode, and recvmsg() is a little tricky here. To successfully
        // receive attached file descriptors, we need to receive messages and
        // corresponding attached file descriptors in this way:
        // . recv messsage header and optional attached file
        // . validate message header
        // . recv optional message body and payload according size field in
        //   message header
        // . validate message body and optional payload
        let (hdr, files) = self.sub_sock.recv_header()?;
        self.check_attached_files(&hdr, &files)?;
        let buf = self.sub_sock.recv_body_bytes(&hdr)?;
        let size = buf.len();

        let res = match hdr.get_code() {
            Ok(SlaveReq::CONFIG_CHANGE_MSG) => {
                self.check_msg_size(&hdr, size, 0)?;
                self.frontend
                    .handle_config_change()
                    .map_err(Error::ReqHandlerError)
            }
            Ok(SlaveReq::SHMEM_MAP) => {
                let msg = self.extract_msg_body::<VhostUserShmemMapMsg>(&hdr, size, &buf)?;
                // check_attached_files() has validated files
                self.frontend
                    .shmem_map(&msg, &files[0])
                    .map_err(Error::ReqHandlerError)
            }
            Ok(SlaveReq::SHMEM_UNMAP) => {
                let msg = self.extract_msg_body::<VhostUserShmemUnmapMsg>(&hdr, size, &buf)?;
                self.frontend
                    .shmem_unmap(&msg)
                    .map_err(Error::ReqHandlerError)
            }
            Ok(SlaveReq::GPU_MAP) => {
                let msg = self.extract_msg_body::<VhostUserGpuMapMsg>(&hdr, size, &buf)?;
                // check_attached_files() has validated files
                self.frontend
                    .gpu_map(&msg, &files[0])
                    .map_err(Error::ReqHandlerError)
            }
            Ok(SlaveReq::EXTERNAL_MAP) => {
                let msg = self.extract_msg_body::<VhostUserExternalMapMsg>(&hdr, size, &buf)?;
                self.frontend
                    .external_map(&msg)
                    .map_err(Error::ReqHandlerError)
            }
            _ => Err(Error::InvalidMessage),
        };

        self.send_reply(&hdr, &res)?;

        res
    }

    fn check_msg_size(
        &self,
        hdr: &VhostUserMsgHeader<SlaveReq>,
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
        hdr: &VhostUserMsgHeader<SlaveReq>,
        files: &[File],
    ) -> Result<()> {
        let expected_num_files = match hdr.get_code().map_err(|_| Error::InvalidMessage)? {
            // Expect a single file is passed.
            SlaveReq::SHMEM_MAP | SlaveReq::GPU_MAP => 1,
            _ => 0,
        };

        if files.len() == expected_num_files {
            Ok(())
        } else {
            Err(Error::InvalidMessage)
        }
    }

    fn extract_msg_body<T: Sized + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<SlaveReq>,
        size: usize,
        buf: &[u8],
    ) -> Result<T> {
        self.check_msg_size(hdr, size, mem::size_of::<T>())?;
        // SAFETY: above check ensures that buf is `T` sized.
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const T) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        Ok(msg)
    }

    fn new_reply_header<T: Sized>(
        &self,
        req: &VhostUserMsgHeader<SlaveReq>,
    ) -> Result<VhostUserMsgHeader<SlaveReq>> {
        Ok(VhostUserMsgHeader::new(
            req.get_code().map_err(|_| Error::InvalidMessage)?,
            VhostUserHeaderFlag::REPLY.bits(),
            mem::size_of::<T>() as u32,
        ))
    }

    fn send_reply(&mut self, req: &VhostUserMsgHeader<SlaveReq>, res: &Result<u64>) -> Result<()> {
        let code = req.get_code().map_err(|_| Error::InvalidMessage)?;
        if code == SlaveReq::SHMEM_MAP
            || code == SlaveReq::SHMEM_UNMAP
            || code == SlaveReq::GPU_MAP
            || code == SlaveReq::EXTERNAL_MAP
            || (self.reply_ack_negotiated && req.is_need_reply())
        {
            let hdr = self.new_reply_header::<VhostUserU64>(req)?;
            let def_err = libc::EINVAL;
            let val = match res {
                Ok(n) => *n,
                Err(e) => match e {
                    Error::ReqHandlerError(ioerr) => match ioerr.raw_os_error() {
                        Some(rawerr) => -rawerr as u64,
                        None => -def_err as u64,
                    },
                    _ => -def_err as u64,
                },
            };
            let msg = VhostUserU64::new(val);
            self.sub_sock.send_message(&hdr, &msg, None)?;
        }
        Ok(())
    }
}
