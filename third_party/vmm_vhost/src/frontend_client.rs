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
    sock: Connection,

    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    //
    // When true, we automatically set the "need_reply" bit for a subset of message types where we
    // think it is useful to receive an ACK.
    reply_ack_negotiated: bool,
}

impl FrontendClient {
    /// Create a new instance from the given connection.
    pub fn new(ep: Connection, reply_ack_negotiated: bool) -> Self {
        FrontendClient {
            sock: ep,
            reply_ack_negotiated,
        }
    }

    fn send_message<T>(
        &mut self,
        request: BackendReq,
        msg: &T,
        fds: Option<&[RawDescriptor]>,
        want_reply: bool,
    ) -> HandlerResult<()>
    where
        T: IntoBytes + Immutable,
    {
        let need_reply = want_reply && self.reply_ack_negotiated;

        let len = mem::size_of::<T>();
        let hdr = VhostUserMsgHeader::new_request_header(request, len as u32, need_reply);
        self.sock
            .send_message(&hdr, msg, fds)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let non_standard_forced_reply =
            [BackendReq::GPU_MAP, BackendReq::EXTERNAL_MAP].contains(&request);
        if need_reply || non_standard_forced_reply {
            self.wait_for_reply(&hdr)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        Ok(())
    }

    fn wait_for_reply(&mut self, hdr: &VhostUserMsgHeader) -> Result<()> {
        let (reply, body, rfds) = self.sock.recv_message::<VhostUserU64>()?;
        if !reply.is_valid() || !reply.is_reply_for(hdr) || !rfds.is_empty() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if body.value != 0 {
            return Err(Error::FrontendInternalError);
        }

        Ok(())
    }
}

impl Frontend for FrontendClient {
    /// Handle shared memory region mapping requests.
    fn shmem_map(&mut self, req: &VhostUserMMap, fd: &dyn AsRawDescriptor) -> HandlerResult<()> {
        if !self.reply_ack_negotiated {
            base::warn!("SHMEM_MAP without REPLY_ACK is prone to race conditions");
        }
        self.send_message(
            BackendReq::SHMEM_MAP,
            req,
            Some(&[fd.as_raw_descriptor()]),
            /* want_reply= */ true,
        )
    }

    /// Handle shared memory region unmapping requests.
    fn shmem_unmap(&mut self, req: &VhostUserMMap) -> HandlerResult<()> {
        self.send_message(
            BackendReq::SHMEM_UNMAP,
            req,
            None,
            /* want_reply= */ true,
        )
    }

    /// Handle config change requests.
    fn handle_config_change(&mut self) -> HandlerResult<()> {
        self.send_message(
            BackendReq::CONFIG_CHANGE_MSG,
            &VhostUserEmptyMessage,
            None,
            /* want_reply= */ false,
        )
    }

    /// Handle GPU shared memory region mapping requests.
    fn gpu_map(
        &mut self,
        req: &VhostUserGpuMapMsg,
        descriptor: &dyn AsRawDescriptor,
    ) -> HandlerResult<()> {
        self.send_message(
            BackendReq::GPU_MAP,
            req,
            Some(&[descriptor.as_raw_descriptor()]),
            /* want_reply= */ false,
        )
    }

    /// Handle external memory region mapping requests.
    fn external_map(&mut self, req: &VhostUserExternalMapMsg) -> HandlerResult<()> {
        self.send_message(
            BackendReq::EXTERNAL_MAP,
            req,
            None,
            /* want_reply= */ false,
        )
    }
}
