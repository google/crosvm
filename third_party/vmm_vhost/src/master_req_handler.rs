// Copyright (C) 2019-2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        mod linux;
    } else if #[cfg(windows)] {
        mod windows;
    }
}

use std::fs::File;
use std::mem;
use std::sync::Arc;
use std::sync::Mutex;

use base::AsRawDescriptor;
use base::SafeDescriptor;

use crate::message::*;
use crate::Endpoint;
use crate::Error;
use crate::HandlerResult;
use crate::Result;
use crate::SlaveReq;
use crate::SystemStream;

/// Define services provided by masters for the slave communication channel.
///
/// The vhost-user specification defines a slave communication channel, by which slaves could
/// request services from masters. The [VhostUserMasterReqHandler] trait defines services provided
/// by masters, and it's used both on the master side and slave side.
/// - on the slave side, a stub forwarder implementing [VhostUserMasterReqHandler] will proxy
///   service requests to masters. The [Slave] is an example stub forwarder.
/// - on the master side, the [MasterReqHandler] will forward service requests to a handler
///   implementing [VhostUserMasterReqHandler].
///
/// The [VhostUserMasterReqHandler] trait is design with interior mutability to improve performance
/// for multi-threading.
///
/// [VhostUserMasterReqHandler]: trait.VhostUserMasterReqHandler.html
/// [MasterReqHandler]: struct.MasterReqHandler.html
/// [Slave]: struct.Slave.html
pub trait VhostUserMasterReqHandler {
    /// Handle device configuration change notifications.
    fn handle_config_change(&self) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle shared memory region mapping requests.
    fn shmem_map(
        &self,
        _req: &VhostUserShmemMapMsg,
        _fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle shared memory region unmapping requests.
    fn shmem_unmap(&self, _req: &VhostUserShmemUnmapMsg) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs map file requests.
    fn fs_slave_map(
        &self,
        _fs: &VhostUserFSSlaveMsg,
        _fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs unmap file requests.
    fn fs_slave_unmap(&self, _fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs sync file requests.
    fn fs_slave_sync(&self, _fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs file IO requests.
    fn fs_slave_io(
        &self,
        _fs: &VhostUserFSSlaveMsg,
        _fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    // fn handle_iotlb_msg(&mut self, iotlb: VhostUserIotlb);
    // fn handle_vring_host_notifier(&mut self, area: VhostUserVringArea, fd: &dyn AsRawDescriptor);

    /// Handle GPU shared memory region mapping requests.
    fn gpu_map(
        &self,
        _req: &VhostUserGpuMapMsg,
        _descriptor: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }
}

/// A helper trait mirroring [VhostUserMasterReqHandler] but without interior mutability.
///
/// [VhostUserMasterReqHandler]: trait.VhostUserMasterReqHandler.html
pub trait VhostUserMasterReqHandlerMut {
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

    /// Handle virtio-fs map file requests.
    fn fs_slave_map(
        &mut self,
        _fs: &VhostUserFSSlaveMsg,
        _fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs unmap file requests.
    fn fs_slave_unmap(&mut self, _fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs sync file requests.
    fn fs_slave_sync(&mut self, _fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs file IO requests.
    fn fs_slave_io(
        &mut self,
        _fs: &VhostUserFSSlaveMsg,
        _fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
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
}

impl<S: VhostUserMasterReqHandlerMut> VhostUserMasterReqHandler for Mutex<S> {
    fn handle_config_change(&self) -> HandlerResult<u64> {
        self.lock().unwrap().handle_config_change()
    }

    fn shmem_map(
        &self,
        req: &VhostUserShmemMapMsg,
        fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        self.lock().unwrap().shmem_map(req, fd)
    }

    fn shmem_unmap(&self, req: &VhostUserShmemUnmapMsg) -> HandlerResult<u64> {
        self.lock().unwrap().shmem_unmap(req)
    }

    fn fs_slave_map(
        &self,
        fs: &VhostUserFSSlaveMsg,
        fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        self.lock().unwrap().fs_slave_map(fs, fd)
    }

    fn fs_slave_unmap(&self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
        self.lock().unwrap().fs_slave_unmap(fs)
    }

    fn fs_slave_sync(&self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
        self.lock().unwrap().fs_slave_sync(fs)
    }

    fn fs_slave_io(
        &self,
        fs: &VhostUserFSSlaveMsg,
        fd: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        self.lock().unwrap().fs_slave_io(fs, fd)
    }

    fn gpu_map(
        &self,
        req: &VhostUserGpuMapMsg,
        descriptor: &dyn AsRawDescriptor,
    ) -> HandlerResult<u64> {
        self.lock().unwrap().gpu_map(req, descriptor)
    }
}

/// The [MasterReqHandler] acts as a server on the master side, to handle service requests from
/// slaves on the slave communication channel. It's actually a proxy invoking the registered
/// handler implementing [VhostUserMasterReqHandler] to do the real work.
///
/// [MasterReqHandler]: struct.MasterReqHandler.html
/// [VhostUserMasterReqHandler]: trait.VhostUserMasterReqHandler.html
///
/// Server to handle service requests from slaves from the slave communication channel.
pub struct MasterReqHandler<S: VhostUserMasterReqHandler> {
    // underlying Unix domain socket for communication
    sub_sock: Endpoint<SlaveReq>,
    tx_sock: Option<SystemStream>,
    // Serializes tx_sock for passing to the backend.
    serialize_tx: Box<dyn Fn(SystemStream) -> SafeDescriptor + Send>,
    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    reply_ack_negotiated: bool,

    /// the VirtIO backend device object
    backend: Arc<S>,
}

impl<S: VhostUserMasterReqHandler> MasterReqHandler<S> {
    /// Create a server to handle service requests from slaves on the slave communication channel.
    ///
    /// This opens a pair of connected anonymous sockets to form the slave communication channel.
    /// The socket fd returned by [Self::take_tx_descriptor()] should be sent to the slave by
    /// [Master::set_slave_request_fd()].
    ///
    /// [Self::take_tx_descriptor()]: struct.MasterReqHandler.html#method.take_tx_descriptor
    /// [Master::set_slave_request_fd()]: struct.Master.html#method.set_slave_request_fd
    pub fn new(
        backend: Arc<S>,
        serialize_tx: Box<dyn Fn(SystemStream) -> SafeDescriptor + Send>,
    ) -> Result<Self> {
        let (tx, rx) = SystemStream::pair()?;

        Ok(MasterReqHandler {
            sub_sock: Endpoint::from(rx),
            tx_sock: Some(tx),
            serialize_tx,
            reply_ack_negotiated: false,
            backend,
        })
    }

    /// Get the descriptor for the slave to communication with the master.
    ///
    /// The caller owns the descriptor. The returned descriptor should be sent to the slave by
    /// [Master::set_slave_request_fd()].
    ///
    /// [Master::set_slave_request_fd()]: struct.Master.html#method.set_slave_request_fd
    pub fn take_tx_descriptor(&mut self) -> SafeDescriptor {
        (self.serialize_tx)(self.tx_sock.take().expect("tx_sock should have a value"))
    }

    /// Set the negotiation state of the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature.
    ///
    /// When the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature has been negotiated,
    /// the "REPLY_ACK" flag will be set in the message header for every slave to master request
    /// message.
    pub fn set_reply_ack_flag(&mut self, enable: bool) {
        self.reply_ack_negotiated = enable;
    }

    /// Get the underlying backend device
    pub fn backend(&self) -> Arc<S> {
        Arc::clone(&self.backend)
    }

    /// Main entrance to server slave request from the slave communication channel.
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
        let buf = match hdr.get_size() {
            0 => vec![0u8; 0],
            len => {
                let rbuf = self.sub_sock.recv_data(len as usize)?;
                if rbuf.len() != len as usize {
                    return Err(Error::InvalidMessage);
                }
                rbuf
            }
        };
        let size = buf.len();

        let res = match hdr.get_code() {
            Ok(SlaveReq::CONFIG_CHANGE_MSG) => {
                self.check_msg_size(&hdr, size, 0)?;
                self.backend
                    .handle_config_change()
                    .map_err(Error::ReqHandlerError)
            }
            Ok(SlaveReq::SHMEM_MAP) => {
                let msg = self.extract_msg_body::<VhostUserShmemMapMsg>(&hdr, size, &buf)?;
                // check_attached_files() has validated files
                self.backend
                    .shmem_map(&msg, &files.unwrap()[0])
                    .map_err(Error::ReqHandlerError)
            }
            Ok(SlaveReq::SHMEM_UNMAP) => {
                let msg = self.extract_msg_body::<VhostUserShmemUnmapMsg>(&hdr, size, &buf)?;
                self.backend
                    .shmem_unmap(&msg)
                    .map_err(Error::ReqHandlerError)
            }
            Ok(SlaveReq::FS_MAP) => {
                let msg = self.extract_msg_body::<VhostUserFSSlaveMsg>(&hdr, size, &buf)?;
                // check_attached_files() has validated files
                self.backend
                    .fs_slave_map(&msg, &files.unwrap()[0])
                    .map_err(Error::ReqHandlerError)
            }
            Ok(SlaveReq::FS_UNMAP) => {
                let msg = self.extract_msg_body::<VhostUserFSSlaveMsg>(&hdr, size, &buf)?;
                self.backend
                    .fs_slave_unmap(&msg)
                    .map_err(Error::ReqHandlerError)
            }
            Ok(SlaveReq::FS_SYNC) => {
                let msg = self.extract_msg_body::<VhostUserFSSlaveMsg>(&hdr, size, &buf)?;
                self.backend
                    .fs_slave_sync(&msg)
                    .map_err(Error::ReqHandlerError)
            }
            Ok(SlaveReq::FS_IO) => {
                let msg = self.extract_msg_body::<VhostUserFSSlaveMsg>(&hdr, size, &buf)?;
                // check_attached_files() has validated files
                self.backend
                    .fs_slave_io(&msg, &files.unwrap()[0])
                    .map_err(Error::ReqHandlerError)
            }
            Ok(SlaveReq::GPU_MAP) => {
                let msg = self.extract_msg_body::<VhostUserGpuMapMsg>(&hdr, size, &buf)?;
                // check_attached_files() has validated files
                self.backend
                    .gpu_map(&msg, &files.unwrap()[0])
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
        files: &Option<Vec<File>>,
    ) -> Result<()> {
        match hdr.get_code().map_err(|_| Error::InvalidMessage)? {
            SlaveReq::SHMEM_MAP | SlaveReq::FS_MAP | SlaveReq::FS_IO | SlaveReq::GPU_MAP => {
                // Expect a single file is passed.
                match files {
                    Some(files) if files.len() == 1 => Ok(()),
                    _ => Err(Error::InvalidMessage),
                }
            }
            _ if files.is_some() => Err(Error::InvalidMessage),
            _ => Ok(()),
        }
    }

    fn extract_msg_body<T: Sized + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<SlaveReq>,
        size: usize,
        buf: &[u8],
    ) -> Result<T> {
        self.check_msg_size(hdr, size, mem::size_of::<T>())?;
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
