// Copyright (C) 2019-2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::mem;

use anyhow::bail;
use anyhow::Context;
use base::AsRawDescriptor;
use zerocopy::IntoBytes;

use crate::message::*;
use crate::BackendReq;
use crate::Connection;
use crate::Error;
use crate::Result;

trait VhostUserReply: Sized {
    fn serialize(&self) -> anyhow::Result<Vec<u8>>;
}

impl VhostUserReply for VhostUserU64 {
    fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.as_bytes().to_owned())
    }
}

impl VhostUserReply for VhostUserRequestResponse {
    fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(anyhow::Error::new)
    }
}

/// Trait for vhost-user frontends to respond to requests from the backend.
///
/// Each method corresponds to a vhost-user protocol method. See the specification for details.
pub trait Frontend {
    /// Handle device configuration change notifications.
    fn handle_config_change(&mut self) -> anyhow::Result<()> {
        bail!("config change not supported")
    }

    /// Handle shared memory region mapping requests.
    fn shmem_map(
        &mut self,
        _req: &VhostUserShmemMapMsg,
        _fd: &dyn AsRawDescriptor,
    ) -> anyhow::Result<()> {
        bail!("shmem map not supported")
    }

    /// Handle shared memory region unmapping requests.
    fn shmem_unmap(&mut self, _req: &VhostUserShmemUnmapMsg) -> anyhow::Result<()> {
        bail!("shmem unmap not supported")
    }

    // fn handle_iotlb_msg(&mut self, iotlb: VhostUserIotlb);
    // fn handle_vring_host_notifier(&mut self, area: VhostUserVringArea, fd: RawDescriptor);

    /// Handle GPU shared memory region mapping requests.
    fn gpu_map(
        &mut self,
        _req: &VhostUserGpuMapMsg,
        _descriptor: &dyn AsRawDescriptor,
    ) -> anyhow::Result<()> {
        bail!("GPU map not supported")
    }

    /// Handle external memory region mapping requests.
    fn external_map(&mut self, _req: &VhostUserExternalMapMsg) -> anyhow::Result<()> {
        bail!("external map not supported")
    }
}

/// Handles requests from a vhost-user backend connection by dispatching them to [[Frontend]]
/// methods.
pub struct FrontendServer<S: Frontend> {
    // underlying Unix domain socket for communication
    pub(crate) sub_sock: Connection<BackendReq>,
    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    reply_ack_negotiated: bool,

    frontend: S,
}

impl<S: Frontend> FrontendServer<S> {
    /// Create a server to handle requests from `connection`.
    pub(crate) fn new(frontend: S, connection: Connection<BackendReq>) -> Result<Self> {
        Ok(FrontendServer {
            sub_sock: connection,
            reply_ack_negotiated: false,
            frontend,
        })
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
    pub fn handle_request(&mut self) -> Result<()> {
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

        match hdr.get_code() {
            Ok(BackendReq::CONFIG_CHANGE_MSG) => {
                self.check_msg_size(&hdr, size, 0)?;
                let res = self.frontend.handle_config_change();
                if self.reply_ack_negotiated && hdr.is_need_reply() {
                    let reply_msg = match &res {
                        Ok(_) => 0,
                        Err(_) => -libc::EINVAL as u64,
                    };
                    self.send_reply(&hdr, &VhostUserU64::new(reply_msg))?;
                }
                res.context("failed to handle config change")
                    .map_err(Error::ReqHandlerError)
            }
            Ok(BackendReq::SHMEM_MAP) => {
                let msg = self.extract_msg_body::<VhostUserShmemMapMsg>(&hdr, size, &buf)?;
                // check_attached_files() has validated files
                let res = self
                    .frontend
                    .shmem_map(&msg, &files[0])
                    .context("handle shmem map")
                    .map_err(VhostUserRequestError::handler_error);
                self.send_reply(&hdr, &res)?;
                res.map_err(|e| e.into())
            }
            Ok(BackendReq::SHMEM_UNMAP) => {
                let msg = self.extract_msg_body::<VhostUserShmemUnmapMsg>(&hdr, size, &buf)?;
                let res = self
                    .frontend
                    .shmem_unmap(&msg)
                    .context("handle shmem unmap")
                    .map_err(VhostUserRequestError::handler_error);
                self.send_reply(&hdr, &res)?;
                res.map_err(|e| e.into())
            }
            Ok(BackendReq::GPU_MAP) => {
                let msg = self.extract_msg_body::<VhostUserGpuMapMsg>(&hdr, size, &buf)?;
                // check_attached_files() has validated files
                let res = self
                    .frontend
                    .gpu_map(&msg, &files[0])
                    .context("handle gpu map")
                    .map_err(VhostUserRequestError::handler_error);
                self.send_reply(&hdr, &res)?;
                res.map_err(|e| e.into())
            }
            Ok(BackendReq::EXTERNAL_MAP) => {
                let msg = self.extract_msg_body::<VhostUserExternalMapMsg>(&hdr, size, &buf)?;
                let res = self
                    .frontend
                    .external_map(&msg)
                    .context("handle external map")
                    .map_err(VhostUserRequestError::handler_error);
                self.send_reply(&hdr, &res)?;
                res.map_err(|e| e.into())
            }
            _ => {
                if self.reply_ack_negotiated && hdr.is_need_reply() {
                    self.send_reply(&hdr, &VhostUserU64::new(-libc::EINVAL as u64))?;
                }
                Err(Error::InvalidMessage)
            }
        }
    }

    fn check_msg_size(
        &self,
        hdr: &VhostUserMsgHeader<BackendReq>,
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
        hdr: &VhostUserMsgHeader<BackendReq>,
        files: &[File],
    ) -> Result<()> {
        let expected_num_files = match hdr.get_code().map_err(|_| Error::InvalidMessage)? {
            // Expect a single file is passed.
            BackendReq::SHMEM_MAP | BackendReq::GPU_MAP => 1,
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
        hdr: &VhostUserMsgHeader<BackendReq>,
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

    fn new_reply_header(
        &self,
        req: &VhostUserMsgHeader<BackendReq>,
        size: usize,
    ) -> Result<VhostUserMsgHeader<BackendReq>> {
        Ok(VhostUserMsgHeader::new(
            req.get_code().map_err(|_| Error::InvalidMessage)?,
            VhostUserHeaderFlag::REPLY.bits(),
            size.try_into()
                .unwrap_or_else(|e| panic!("body size({}) too large: {}", size, e)),
        ))
    }

    fn send_reply(
        &mut self,
        req: &VhostUserMsgHeader<BackendReq>,
        res: &impl VhostUserReply,
    ) -> Result<()> {
        let raw_response = res.serialize().map_err(|_| Error::SerializationFailed)?;
        let raw_response: &[u8] = &raw_response;
        let hdr = self.new_reply_header(req, raw_response.len())?;
        self.sub_sock.send_message(&hdr, raw_response, None)?;
        Ok(())
    }
}
