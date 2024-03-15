// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem;
use std::string::ToString;

use base::AsRawDescriptor;
use base::RawDescriptor;
use zerocopy::AsBytes;

use crate::message::*;
use crate::Connection;
use crate::Error;
use crate::Frontend;
use crate::HandlerResult;
use crate::Result;
use crate::SlaveReq;
use crate::SystemStream;

/// Client for a vhost-user frontend. Allows a backend to send requests to the frontend.
pub struct FrontendClient {
    sock: Connection<SlaveReq>,

    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    reply_ack_negotiated: bool,

    // whether the connection has encountered any failure
    error: Option<i32>,
}

impl FrontendClient {
    /// Create a new instance from the given connection.
    pub fn new(ep: Connection<SlaveReq>) -> Self {
        FrontendClient {
            sock: ep,
            reply_ack_negotiated: false,
            error: None,
        }
    }

    /// Create a new instance from a `SystemStream` object.
    pub fn from_stream(connection: SystemStream) -> Self {
        Self::new(Connection::from(connection))
    }

    fn send_message<T>(
        &mut self,
        request: SlaveReq,
        msg: &T,
        fds: Option<&[RawDescriptor]>,
    ) -> HandlerResult<u64>
    where
        T: AsBytes,
    {
        let len = mem::size_of::<T>();
        let mut hdr = VhostUserMsgHeader::new(request, 0, len as u32);
        if self.reply_ack_negotiated {
            hdr.set_need_reply(true);
        }
        self.sock
            .send_message(&hdr, msg, fds)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        self.wait_for_reply(&hdr)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }

    fn wait_for_reply(&mut self, hdr: &VhostUserMsgHeader<SlaveReq>) -> Result<u64> {
        let code = hdr.get_code().map_err(|_| Error::InvalidMessage)?;
        if code != SlaveReq::SHMEM_MAP
            && code != SlaveReq::SHMEM_UNMAP
            && code != SlaveReq::GPU_MAP
            && code != SlaveReq::EXTERNAL_MAP
            && !self.reply_ack_negotiated
        {
            return Ok(0);
        }

        let (reply, body, rfds) = self.sock.recv_message::<VhostUserU64>()?;
        if !reply.is_reply_for(hdr) || !rfds.is_empty() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if body.value != 0 {
            return Err(Error::MasterInternalError);
        }

        Ok(body.value)
    }

    /// Set the negotiation state of the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature.
    ///
    /// When the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature has been negotiated,
    /// the "REPLY_ACK" flag will be set in the message header for every slave to master request
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
    ) -> HandlerResult<u64> {
        self.send_message(SlaveReq::SHMEM_MAP, req, Some(&[fd.as_raw_descriptor()]))
    }

    /// Handle shared memory region unmapping requests.
    fn shmem_unmap(&mut self, req: &VhostUserShmemUnmapMsg) -> HandlerResult<u64> {
        self.send_message(SlaveReq::SHMEM_UNMAP, req, None)
    }

    /// Handle config change requests.
    fn handle_config_change(&mut self) -> HandlerResult<u64> {
        self.send_message(SlaveReq::CONFIG_CHANGE_MSG, &VhostUserEmptyMessage, None)
    }

    /// Handle GPU shared memory region mapping requests.
    fn gpu_map(
        &mut self,
        req: &VhostUserGpuMapMsg,
        descriptor: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        self.send_message(
            SlaveReq::GPU_MAP,
            req,
            Some(&[descriptor.as_raw_descriptor()]),
        )
    }

    /// Handle external memory region mapping requests.
    fn external_map(&mut self, req: &VhostUserExternalMapMsg) -> HandlerResult<u64> {
        self.send_message(SlaveReq::EXTERNAL_MAP, req, None)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::SystemStream;

    #[test]
    fn test_slave_req_set_failed() {
        let (p1, _p2) = SystemStream::pair().unwrap();
        let mut frontend_client = FrontendClient::from_stream(p1);

        assert!(frontend_client.error.is_none());
        frontend_client.set_failed(libc::EAGAIN);
        assert_eq!(frontend_client.error, Some(libc::EAGAIN));
    }
}
