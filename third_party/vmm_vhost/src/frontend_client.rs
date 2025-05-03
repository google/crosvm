// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem;

use anyhow::ensure;
use anyhow::Context;
use base::AsRawDescriptor;
use base::RawDescriptor;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

use crate::message::*;
use crate::BackendReq;
use crate::Connection;
use crate::Frontend;

trait VhostUserReply: Sized {
    fn deserialize(raw_body: &[u8]) -> anyhow::Result<Self>;
    fn ok(self) -> anyhow::Result<()>;
}

impl VhostUserReply for VhostUserU64 {
    fn deserialize(raw_body: &[u8]) -> anyhow::Result<Self> {
        VhostUserU64::read_from_bytes(raw_body).map_err(|e| anyhow::anyhow!("{}", e))
    }

    fn ok(self) -> anyhow::Result<()> {
        let value = self.value;
        if value != 0 {
            return Err(anyhow::anyhow!(
                "operation failed with non-zero payload {}",
                value
            ));
        }
        Ok(())
    }
}

impl VhostUserReply for VhostUserRequestResponse {
    fn deserialize(raw_body: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(raw_body).context("failed to deserialize the response")
    }

    fn ok(self) -> anyhow::Result<()> {
        self.map_err(anyhow::Error::new)
    }
}

/// Client for a vhost-user frontend. Allows a backend to send requests to the frontend.
pub struct FrontendClient {
    sock: Connection<BackendReq>,

    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    reply_ack_negotiated: bool,

    // whether the connection has encountered any failure
    error: Option<i32>,
}

impl FrontendClient {
    /// Create a new instance from the given connection.
    pub fn new(ep: Connection<BackendReq>) -> Self {
        FrontendClient {
            sock: ep,
            reply_ack_negotiated: false,
            error: None,
        }
    }

    fn send_message<T>(
        &mut self,
        request: BackendReq,
        msg: &T,
        fds: Option<&[RawDescriptor]>,
    ) -> anyhow::Result<VhostUserMsgHeader<BackendReq>>
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
            .context("failed to send the message")?;
        Ok(hdr)
    }

    fn wait_for_reply<T: VhostUserReply>(
        &mut self,
        hdr: &VhostUserMsgHeader<BackendReq>,
    ) -> anyhow::Result<()> {
        let (reply, rfds) = self
            .sock
            .recv_header()
            .context("failed to receive the header")?;
        let raw_body = self
            .sock
            .recv_body_bytes(&reply)
            .context("failed to receive the body")?;
        ensure!(
            reply.is_reply_for(hdr),
            "the reply doesn't match the request header. reply: {:?} request header: {:?}",
            reply,
            hdr
        );
        ensure!(rfds.is_empty(), "the reply shouldn't include fds");
        let body = T::deserialize(&raw_body).context("failed to deserilize the message body")?;
        body.ok().context("failed on the vhost server")
    }

    /// Set the negotiation state of the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature.
    ///
    /// When the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature has been negotiated, the
    /// "REPLY_ACK" flag will be set in the message header for every backend to frontend request
    /// message.
    pub fn set_reply_ack_flag(&mut self, enable: bool) {
        self.reply_ack_negotiated = enable;
    }

    /// Mark connection as failed with specified error code.
    pub fn set_failed(&mut self, error: i32) {
        self.error = Some(error);
    }
}

impl Frontend for FrontendClient {
    /// Handle shared memory region mapping requests.
    fn shmem_map(
        &mut self,
        req: &VhostUserShmemMapMsg,
        fd: &dyn AsRawDescriptor,
    ) -> anyhow::Result<()> {
        let hdr = self
            .send_message(BackendReq::SHMEM_MAP, req, Some(&[fd.as_raw_descriptor()]))
            .context("failed to send the shmem map message")?;
        self.wait_for_reply::<VhostUserRequestResponse>(&hdr)
    }

    /// Handle shared memory region unmapping requests.
    fn shmem_unmap(&mut self, req: &VhostUserShmemUnmapMsg) -> anyhow::Result<()> {
        let hdr = self
            .send_message(BackendReq::SHMEM_UNMAP, req, None)
            .context("failed to send the shmem unmap message")?;
        self.wait_for_reply::<VhostUserRequestResponse>(&hdr)
    }

    /// Handle config change requests.
    fn handle_config_change(&mut self) -> anyhow::Result<()> {
        let hdr = self
            .send_message(BackendReq::CONFIG_CHANGE_MSG, &VhostUserEmptyMessage, None)
            .context("failed to send the config change message")?;
        if self.reply_ack_negotiated {
            self.wait_for_reply::<VhostUserU64>(&hdr)
        } else {
            Ok(())
        }
    }

    /// Handle GPU shared memory region mapping requests.
    fn gpu_map(
        &mut self,
        req: &VhostUserGpuMapMsg,
        descriptor: &dyn AsRawDescriptor,
    ) -> anyhow::Result<()> {
        let hdr = self
            .send_message(
                BackendReq::GPU_MAP,
                req,
                Some(&[descriptor.as_raw_descriptor()]),
            )
            .context("failed to send the GPU map message")?;
        self.wait_for_reply::<VhostUserRequestResponse>(&hdr)
    }

    /// Handle external memory region mapping requests.
    fn external_map(&mut self, req: &VhostUserExternalMapMsg) -> anyhow::Result<()> {
        let hdr = self
            .send_message(BackendReq::EXTERNAL_MAP, req, None)
            .context("failed to send the external map message")?;
        self.wait_for_reply::<VhostUserRequestResponse>(&hdr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_req_set_failed() {
        let (p1, _p2) = Connection::pair().unwrap();
        let mut frontend_client = FrontendClient::new(p1);

        assert!(frontend_client.error.is_none());
        frontend_client.set_failed(libc::EAGAIN);
        assert_eq!(frontend_client.error, Some(libc::EAGAIN));
    }
}
