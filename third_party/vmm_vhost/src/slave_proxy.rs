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
use crate::HandlerResult;
use crate::Result;
use crate::SlaveReq;
use crate::SystemStream;
use crate::VhostUserMasterReqHandler;

/// Request proxy to send slave requests to the master through the slave communication channel.
///
/// The [Slave] acts as a message proxy to forward slave requests to the master through the
/// vhost-user slave communication channel. The forwarded messages will be handled by the
/// [MasterReqHandler] server.
///
/// [Slave]: struct.Slave.html
/// [MasterReqHandler]: struct.MasterReqHandler.html
pub struct Slave {
    sock: Connection<SlaveReq>,

    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    reply_ack_negotiated: bool,

    // whether the connection has encountered any failure
    error: Option<i32>,
}

impl Slave {
    /// Constructs a new slave proxy from the given connection.
    pub fn new(ep: Connection<SlaveReq>) -> Self {
        Slave {
            sock: ep,
            reply_ack_negotiated: false,
            error: None,
        }
    }

    /// Create a new instance from a `SystemStream` object.
    pub fn from_stream(sock: SystemStream) -> Self {
        Self::new(Connection::from(sock))
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

impl VhostUserMasterReqHandler for Slave {
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

    /// Forward vhost-user-fs map file requests to the slave.
    fn fs_slave_map(
        &mut self,
        fs: &VhostUserFSSlaveMsg,
        fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        self.send_message(SlaveReq::FS_MAP, fs, Some(&[fd.as_raw_descriptor()]))
    }

    /// Forward vhost-user-fs unmap file requests to the master.
    fn fs_slave_unmap(&mut self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
        self.send_message(SlaveReq::FS_UNMAP, fs, None)
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
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::SystemStream;

    #[test]
    fn test_slave_req_set_failed() {
        let (p1, _p2) = SystemStream::pair().unwrap();
        let mut fs_cache = Slave::from_stream(p1);

        assert!(fs_cache.error.is_none());
        fs_cache.set_failed(libc::EAGAIN);
        assert_eq!(fs_cache.error, Some(libc::EAGAIN));
    }

    #[test]
    fn test_slave_recv_negative() {
        let (p1, p2) = SystemStream::pair().unwrap();
        let mut fs_cache = Slave::from_stream(p1);
        let master = Connection::from(p2);

        let len = mem::size_of::<VhostUserU64>();
        let mut hdr = VhostUserMsgHeader::new(
            SlaveReq::FS_MAP,
            VhostUserHeaderFlag::REPLY.bits(),
            len as u32,
        );
        let body = VhostUserU64::new(0);

        master
            .send_message(&hdr, &body, Some(&[master.as_raw_descriptor()]))
            .unwrap();
        fs_cache
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &master)
            .unwrap();

        fs_cache.set_reply_ack_flag(true);
        fs_cache
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &master)
            .unwrap_err();

        hdr.set_code(SlaveReq::FS_UNMAP);
        master.send_message(&hdr, &body, None).unwrap();
        fs_cache
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &master)
            .unwrap_err();
        hdr.set_code(SlaveReq::FS_MAP);

        let body = VhostUserU64::new(1);
        master.send_message(&hdr, &body, None).unwrap();
        fs_cache
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &master)
            .unwrap_err();

        let body = VhostUserU64::new(0);
        master.send_message(&hdr, &body, None).unwrap();
        fs_cache
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &master)
            .unwrap();
    }
}
