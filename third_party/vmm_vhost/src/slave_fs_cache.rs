// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{SlaveFsCacheReqSocket, SystemStream};
use base::{AsRawDescriptor, RawDescriptor};
use std::io;
use std::mem;
use std::sync::{Arc, Mutex, MutexGuard};

use super::connection::EndpointExt;
use super::message::*;
use super::{Error, HandlerResult, Result, VhostUserMasterReqHandler};

struct SlaveFsCacheReqInternal {
    sock: SlaveFsCacheReqSocket,

    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    reply_ack_negotiated: bool,

    // whether the endpoint has encountered any failure
    error: Option<i32>,
}

impl SlaveFsCacheReqInternal {
    fn check_state(&self) -> Result<u64> {
        match self.error {
            Some(e) => Err(Error::SocketBroken(std::io::Error::from_raw_os_error(e))),
            None => Ok(0),
        }
    }

    fn send_message(
        &mut self,
        request: SlaveReq,
        fs: &VhostUserFSSlaveMsg,
        fds: Option<&[RawDescriptor]>,
    ) -> Result<u64> {
        self.check_state()?;

        let len = mem::size_of::<VhostUserFSSlaveMsg>();
        let mut hdr = VhostUserMsgHeader::new(request, 0, len as u32);
        if self.reply_ack_negotiated {
            hdr.set_need_reply(true);
        }
        self.sock.send_message(&hdr, fs, fds)?;

        self.wait_for_ack(&hdr)
    }

    fn wait_for_ack(&mut self, hdr: &VhostUserMsgHeader<SlaveReq>) -> Result<u64> {
        self.check_state()?;
        if !self.reply_ack_negotiated {
            return Ok(0);
        }

        let (reply, body, rfds) = self.sock.recv_body::<VhostUserU64>()?;
        if !reply.is_reply_for(hdr) || rfds.is_some() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if body.value != 0 {
            return Err(Error::MasterInternalError);
        }

        Ok(body.value)
    }
}

/// Request proxy to send vhost-user-fs slave requests to the master through the slave
/// communication channel.
///
/// The [SlaveFsCacheReq] acts as a message proxy to forward vhost-user-fs slave requests to the
/// master through the vhost-user slave communication channel. The forwarded messages will be
/// handled by the [MasterReqHandler] server.
///
/// [SlaveFsCacheReq]: struct.SlaveFsCacheReq.html
/// [MasterReqHandler]: struct.MasterReqHandler.html
#[derive(Clone)]
pub struct SlaveFsCacheReq {
    // underlying socket for communication
    node: Arc<Mutex<SlaveFsCacheReqInternal>>,
}

impl SlaveFsCacheReq {
    fn new(ep: SlaveFsCacheReqSocket) -> Self {
        SlaveFsCacheReq {
            node: Arc::new(Mutex::new(SlaveFsCacheReqInternal {
                sock: ep,
                reply_ack_negotiated: false,
                error: None,
            })),
        }
    }

    fn node(&self) -> MutexGuard<SlaveFsCacheReqInternal> {
        self.node.lock().unwrap()
    }

    fn send_message(
        &self,
        request: SlaveReq,
        fs: &VhostUserFSSlaveMsg,
        fds: Option<&[RawDescriptor]>,
    ) -> io::Result<u64> {
        self.node()
            .send_message(request, fs, fds)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))
    }

    /// Create a new instance from a `SystemStream` object.
    pub fn from_stream(sock: SystemStream) -> Self {
        Self::new(SlaveFsCacheReqSocket::from(sock))
    }

    /// Set the negotiation state of the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature.
    ///
    /// When the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature has been negotiated,
    /// the "REPLY_ACK" flag will be set in the message header for every slave to master request
    /// message.
    pub fn set_reply_ack_flag(&self, enable: bool) {
        self.node().reply_ack_negotiated = enable;
    }

    /// Mark endpoint as failed with specified error code.
    pub fn set_failed(&self, error: i32) {
        self.node().error = Some(error);
    }
}

impl VhostUserMasterReqHandler for SlaveFsCacheReq {
    /// Forward vhost-user-fs map file requests to the slave.
    fn fs_slave_map(
        &self,
        fs: &VhostUserFSSlaveMsg,
        fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        self.send_message(SlaveReq::FS_MAP, fs, Some(&[fd.as_raw_descriptor()]))
    }

    /// Forward vhost-user-fs unmap file requests to the master.
    fn fs_slave_unmap(&self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
        self.send_message(SlaveReq::FS_UNMAP, fs, None)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::connection::Endpoint;

    #[test]
    fn test_slave_fs_cache_req_set_failed() {
        let (p1, _p2) = SystemStream::pair().unwrap();
        let fs_cache = SlaveFsCacheReq::from_stream(p1);

        assert!(fs_cache.node().error.is_none());
        fs_cache.set_failed(libc::EAGAIN);
        assert_eq!(fs_cache.node().error, Some(libc::EAGAIN));
    }

    #[test]
    fn test_slave_fs_cache_send_failure() {
        let (p1, p2) = SystemStream::pair().unwrap();
        let fs_cache = SlaveFsCacheReq::from_stream(p1);

        fs_cache.set_failed(libc::ECONNRESET);
        fs_cache
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &p2)
            .unwrap_err();
        fs_cache
            .fs_slave_unmap(&VhostUserFSSlaveMsg::default())
            .unwrap_err();
        fs_cache.node().error = None;
    }

    #[test]
    fn test_slave_fs_cache_recv_negative() {
        let (p1, p2) = SystemStream::pair().unwrap();
        let fs_cache = SlaveFsCacheReq::from_stream(p1);
        let mut master = SlaveFsCacheReqSocket::from_connection(p2);

        let len = mem::size_of::<VhostUserFSSlaveMsg>();
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
