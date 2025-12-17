// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem;
use std::string::ToString;

use base::AsRawDescriptor;
use base::RawDescriptor;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

use crate::message::*;
use crate::BackendReq;
use crate::Connection;
use crate::Error;
use crate::Frontend;
use crate::HandlerResult;
use crate::Result;

/// Client for a vhost-user frontend. Allows a backend to send requests to the frontend.
pub struct FrontendClient {
    sock: Connection<BackendReq>,

    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    reply_ack_negotiated: bool,
}

impl FrontendClient {
    /// Create a new instance from the given connection.
    pub fn new(ep: Connection<BackendReq>) -> Self {
        FrontendClient {
            sock: ep,
            reply_ack_negotiated: false,
        }
    }

    fn send_message<T>(
        &mut self,
        request: BackendReq,
        msg: &T,
        fds: Option<&[RawDescriptor]>,
    ) -> HandlerResult<u64>
    where
        T: IntoBytes + Immutable,
    {
        let len = mem::size_of::<T>();
        let mut hdr = VhostUserMsgHeader::new(request, 0, len as u32);
        if self.reply_ack_negotiated {
            hdr.set_need_reply(true);
        }
        self.sock
            .send_message(&hdr, msg, fds)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        self.wait_for_reply(&hdr)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn wait_for_reply(&mut self, hdr: &VhostUserMsgHeader<BackendReq>) -> Result<u64> {
        let code = hdr.get_code().map_err(|_| Error::InvalidMessage)?;
        if code != BackendReq::GPU_MAP
            && code != BackendReq::EXTERNAL_MAP
            && !self.reply_ack_negotiated
        {
            return Ok(0);
        }

        let (reply, body, rfds) = self.sock.recv_message::<VhostUserU64>()?;
        if !reply.is_valid() || !reply.is_reply_for(hdr) || !rfds.is_empty() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if body.value != 0 {
            return Err(Error::FrontendInternalError);
        }

        Ok(body.value)
    }

    /// Set the negotiation state of the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature.
    ///
    /// When the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature has been negotiated, the
    /// "REPLY_ACK" flag will be set in the message header for every backend to frontend request
    /// message.
    pub fn set_reply_ack_flag(&mut self, enable: bool) {
        self.reply_ack_negotiated = enable;
    }
}

impl Frontend for FrontendClient {
    /// Handle shared memory region mapping requests.
    fn shmem_map(&mut self, req: &VhostUserMMap, fd: &dyn AsRawDescriptor) -> HandlerResult<u64> {
        self.send_message(BackendReq::SHMEM_MAP, req, Some(&[fd.as_raw_descriptor()]))
    }

    /// Handle shared memory region unmapping requests.
    fn shmem_unmap(&mut self, req: &VhostUserShmemUnmapMsg) -> HandlerResult<u64> {
        self.send_message(BackendReq::SHMEM_UNMAP, req, None)
    }

    /// Handle config change requests.
    fn handle_config_change(&mut self) -> HandlerResult<u64> {
        self.send_message(BackendReq::CONFIG_CHANGE_MSG, &VhostUserEmptyMessage, None)
    }

    /// Handle GPU shared memory region mapping requests.
    fn gpu_map(
        &mut self,
        req: &VhostUserGpuMapMsg,
        descriptor: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        self.send_message(
            BackendReq::GPU_MAP,
            req,
            Some(&[descriptor.as_raw_descriptor()]),
        )
    }

    /// Handle external memory region mapping requests.
    fn external_map(&mut self, req: &VhostUserExternalMapMsg) -> HandlerResult<u64> {
        self.send_message(BackendReq::EXTERNAL_MAP, req, None)
    }
}
