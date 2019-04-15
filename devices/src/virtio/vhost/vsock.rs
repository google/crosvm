// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::thread;

use byteorder::{ByteOrder, LittleEndian};

use ::vhost::Vsock as VhostVsockHandle;
use sys_util::{error, warn, EventFd, GuestMemory};
use virtio_sys::vhost;

use super::worker::Worker;
use super::{Error, Result};
use crate::virtio::{Queue, VirtioDevice, TYPE_VSOCK};

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 3;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

pub struct Vsock {
    worker_kill_evt: Option<EventFd>,
    kill_evt: Option<EventFd>,
    vhost_handle: Option<VhostVsockHandle>,
    cid: u64,
    interrupt: Option<EventFd>,
    avail_features: u64,
    acked_features: u64,
}

impl Vsock {
    /// Create a new virtio-vsock device with the given VM cid.
    pub fn new(cid: u64, mem: &GuestMemory) -> Result<Vsock> {
        let kill_evt = EventFd::new().map_err(Error::CreateKillEventFd)?;
        let handle = VhostVsockHandle::new(mem).map_err(Error::VhostOpen)?;

        let avail_features = 1 << vhost::VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << vhost::VIRTIO_RING_F_INDIRECT_DESC
            | 1 << vhost::VIRTIO_RING_F_EVENT_IDX
            | 1 << vhost::VHOST_F_LOG_ALL
            | 1 << vhost::VIRTIO_F_ANY_LAYOUT
            | 1 << vhost::VIRTIO_F_VERSION_1;

        Ok(Vsock {
            worker_kill_evt: Some(kill_evt.try_clone().map_err(Error::CloneKillEventFd)?),
            kill_evt: Some(kill_evt),
            vhost_handle: Some(handle),
            cid,
            interrupt: Some(EventFd::new().map_err(Error::VhostIrqCreate)?),
            avail_features,
            acked_features: 0,
        })
    }

    pub fn new_for_testing(cid: u64, features: u64) -> Vsock {
        Vsock {
            worker_kill_evt: None,
            kill_evt: None,
            vhost_handle: None,
            cid,
            interrupt: None,
            avail_features: features,
            acked_features: 0,
        }
    }

    pub fn acked_features(&self) -> u64 {
        self.acked_features
    }
}

impl Drop for Vsock {
    fn drop(&mut self) {
        // Only kill the child if it claimed its eventfd.
        if self.worker_kill_evt.is_none() {
            if let Some(kill_evt) = &self.kill_evt {
                // Ignore the result because there is nothing we can do about it.
                let _ = kill_evt.write(1);
            }
        }
    }
}

impl VirtioDevice for Vsock {
    fn keep_fds(&self) -> Vec<RawFd> {
        let mut keep_fds = Vec::new();

        if let Some(handle) = &self.vhost_handle {
            keep_fds.push(handle.as_raw_fd());
        }

        if let Some(interrupt) = &self.interrupt {
            keep_fds.push(interrupt.as_raw_fd());
        }

        if let Some(worker_kill_evt) = &self.worker_kill_evt {
            keep_fds.push(worker_kill_evt.as_raw_fd());
        }

        keep_fds
    }

    fn device_type(&self) -> u32 {
        TYPE_VSOCK
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match offset {
            0 if data.len() == 8 => LittleEndian::write_u64(data, self.cid),
            0 if data.len() == 4 => LittleEndian::write_u32(data, (self.cid & 0xffffffff) as u32),
            4 if data.len() == 4 => {
                LittleEndian::write_u32(data, ((self.cid >> 32) & 0xffffffff) as u32)
            }
            _ => warn!(
                "vsock: virtio-vsock received invalid read request of {} bytes at offset {}",
                data.len(),
                offset
            ),
        }
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("vsock: virtio-vsock got unknown feature ack: {:x}", v);

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn activate(
        &mut self,
        _: GuestMemory,
        interrupt_evt: EventFd,
        interrupt_resample_evt: EventFd,
        status: Arc<AtomicUsize>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
            error!("net: expected {} queues, got {}", NUM_QUEUES, queues.len());
            return;
        }

        if let Some(vhost_handle) = self.vhost_handle.take() {
            if let Some(interrupt) = self.interrupt.take() {
                if let Some(kill_evt) = self.worker_kill_evt.take() {
                    let acked_features = self.acked_features;
                    let cid = self.cid;
                    let worker_result = thread::Builder::new()
                        .name("vhost_vsock".to_string())
                        .spawn(move || {
                            // The third vq is an event-only vq that is not handled by the vhost
                            // subsystem (but still needs to exist).  Split it off here.
                            let vhost_queues = queues[..2].to_vec();
                            let mut worker = Worker::new(
                                vhost_queues,
                                vhost_handle,
                                interrupt,
                                status,
                                interrupt_evt,
                                interrupt_resample_evt,
                                acked_features,
                            );
                            let activate_vqs = |handle: &VhostVsockHandle| -> Result<()> {
                                handle.set_cid(cid).map_err(Error::VhostVsockSetCid)?;
                                handle.start().map_err(Error::VhostVsockStart)?;
                                Ok(())
                            };
                            let result =
                                worker.run(queue_evts, QUEUE_SIZES, kill_evt, activate_vqs);
                            if let Err(e) = result {
                                error!("vsock worker thread exited with error: {:?}", e);
                            }
                        });

                    if let Err(e) = worker_result {
                        error!("failed to spawn vhost_vsock worker: {}", e);
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use byteorder::{ByteOrder, LittleEndian};
    #[test]
    fn ack_features() {
        let cid = 5;
        let features: u64 = (1 << 20) | (1 << 49) | (1 << 2) | (1 << 19);
        let mut acked_features: u64 = 0;
        let mut unavailable_features: u64 = 0;

        let mut vsock = Vsock::new_for_testing(cid, features);
        assert_eq!(acked_features, vsock.acked_features());

        acked_features |= 1 << 2;
        vsock.ack_features(acked_features);
        assert_eq!(acked_features, vsock.acked_features());

        acked_features |= 1 << 49;
        vsock.ack_features(acked_features);
        assert_eq!(acked_features, vsock.acked_features());

        acked_features |= 1 << 60;
        unavailable_features |= 1 << 60;
        vsock.ack_features(acked_features);
        assert_eq!(
            acked_features & !unavailable_features,
            vsock.acked_features()
        );

        acked_features |= 1 << 1;
        unavailable_features |= 1 << 1;
        vsock.ack_features(acked_features);
        assert_eq!(
            acked_features & !unavailable_features,
            vsock.acked_features()
        );
    }

    #[test]
    fn read_config() {
        let cid = 0xfca9a559fdcb9756;
        let vsock = Vsock::new_for_testing(cid, 0);

        let mut buf = [0 as u8; 8];
        vsock.read_config(0, &mut buf);
        assert_eq!(cid, LittleEndian::read_u64(&buf));

        vsock.read_config(0, &mut buf[..4]);
        assert_eq!((cid & 0xffffffff) as u32, LittleEndian::read_u32(&buf[..4]));

        vsock.read_config(4, &mut buf[..4]);
        assert_eq!((cid >> 32) as u32, LittleEndian::read_u32(&buf[..4]));

        let data: [u8; 8] = [8, 226, 5, 46, 159, 59, 89, 77];
        buf.copy_from_slice(&data);

        vsock.read_config(12, &mut buf);
        assert_eq!(&buf, &data);
    }

    #[test]
    fn features() {
        let cid = 5;
        let features: u64 = 0xfc195ae8db88cff9;

        let vsock = Vsock::new_for_testing(cid, features);
        assert_eq!(features, vsock.features());
    }
}
