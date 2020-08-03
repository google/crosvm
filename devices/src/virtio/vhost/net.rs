// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::thread;

use net_util::{MacAddress, TapT};

use base::{error, warn, EventFd};
use vhost::NetT as VhostNetT;
use virtio_sys::virtio_net;
use vm_memory::GuestMemory;

use super::control_socket::*;
use super::worker::Worker;
use super::{Error, Result};
use crate::pci::MsixStatus;
use crate::virtio::{Interrupt, Queue, VirtioDevice, TYPE_NET};
use msg_socket::{MsgReceiver, MsgSender};

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

pub struct Net<T: TapT, U: VhostNetT<T>> {
    workers_kill_evt: Option<EventFd>,
    kill_evt: EventFd,
    worker_thread: Option<thread::JoinHandle<(Worker<U>, T)>>,
    tap: Option<T>,
    vhost_net_handle: Option<U>,
    vhost_interrupt: Option<Vec<EventFd>>,
    avail_features: u64,
    acked_features: u64,
    request_socket: Option<VhostDevRequestSocket>,
    response_socket: Option<VhostDevResponseSocket>,
}

impl<T, U> Net<T, U>
where
    T: TapT,
    U: VhostNetT<T>,
{
    /// Create a new virtio network device with the given IP address and
    /// netmask.
    pub fn new(
        ip_addr: Ipv4Addr,
        netmask: Ipv4Addr,
        mac_addr: MacAddress,
        mem: &GuestMemory,
    ) -> Result<Net<T, U>> {
        let kill_evt = EventFd::new().map_err(Error::CreateKillEventFd)?;

        let tap: T = T::new(true, false).map_err(Error::TapOpen)?;
        tap.set_ip_addr(ip_addr).map_err(Error::TapSetIp)?;
        tap.set_netmask(netmask).map_err(Error::TapSetNetmask)?;
        tap.set_mac_address(mac_addr)
            .map_err(Error::TapSetMacAddress)?;

        // Set offload flags to match the virtio features below.
        tap.set_offload(
            net_sys::TUN_F_CSUM | net_sys::TUN_F_UFO | net_sys::TUN_F_TSO4 | net_sys::TUN_F_TSO6,
        )
        .map_err(Error::TapSetOffload)?;

        // We declare VIRTIO_NET_F_MRG_RXBUF, so set the vnet hdr size to match.
        let vnet_hdr_size = mem::size_of::<virtio_net::virtio_net_hdr_mrg_rxbuf>() as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(Error::TapSetVnetHdrSize)?;

        tap.enable().map_err(Error::TapEnable)?;
        let vhost_net_handle = U::new(mem).map_err(Error::VhostOpen)?;

        let avail_features = 1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_HOST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_MRG_RXBUF
            | 1 << virtio_sys::vhost::VIRTIO_RING_F_INDIRECT_DESC
            | 1 << virtio_sys::vhost::VIRTIO_RING_F_EVENT_IDX
            | 1 << virtio_sys::vhost::VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << virtio_sys::vhost::VIRTIO_F_VERSION_1;

        let mut vhost_interrupt = Vec::new();
        for _ in 0..NUM_QUEUES {
            vhost_interrupt.push(EventFd::new().map_err(Error::VhostIrqCreate)?);
        }

        let (request_socket, response_socket) = create_control_sockets();

        Ok(Net {
            workers_kill_evt: Some(kill_evt.try_clone().map_err(Error::CloneKillEventFd)?),
            kill_evt,
            worker_thread: None,
            tap: Some(tap),
            vhost_net_handle: Some(vhost_net_handle),
            vhost_interrupt: Some(vhost_interrupt),
            avail_features,
            acked_features: 0u64,
            request_socket,
            response_socket,
        })
    }
}

impl<T, U> Drop for Net<T, U>
where
    T: TapT,
    U: VhostNetT<T>,
{
    fn drop(&mut self) {
        // Only kill the child if it claimed its eventfd.
        if self.workers_kill_evt.is_none() {
            // Ignore the result because there is nothing we can do about it.
            let _ = self.kill_evt.write(1);
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
    }
}

impl<T, U> VirtioDevice for Net<T, U>
where
    T: TapT + 'static,
    U: VhostNetT<T> + 'static,
{
    fn keep_fds(&self) -> Vec<RawFd> {
        let mut keep_fds = Vec::new();

        if let Some(tap) = &self.tap {
            keep_fds.push(tap.as_raw_fd());
        }

        if let Some(vhost_net_handle) = &self.vhost_net_handle {
            keep_fds.push(vhost_net_handle.as_raw_fd());
        }

        if let Some(vhost_interrupt) = &self.vhost_interrupt {
            for vhost_int in vhost_interrupt.iter() {
                keep_fds.push(vhost_int.as_raw_fd());
            }
        }

        if let Some(workers_kill_evt) = &self.workers_kill_evt {
            keep_fds.push(workers_kill_evt.as_raw_fd());
        }
        keep_fds.push(self.kill_evt.as_raw_fd());

        if let Some(request_socket) = &self.request_socket {
            keep_fds.push(request_socket.as_raw_fd());
        }

        if let Some(response_socket) = &self.response_socket {
            keep_fds.push(response_socket.as_raw_fd());
        }

        keep_fds
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        let mut v = value;

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("net: virtio net got unknown feature ack: {:x}", v);

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn activate(
        &mut self,
        _: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
            error!("net: expected {} queues, got {}", NUM_QUEUES, queues.len());
            return;
        }

        if let Some(vhost_net_handle) = self.vhost_net_handle.take() {
            if let Some(tap) = self.tap.take() {
                if let Some(vhost_interrupt) = self.vhost_interrupt.take() {
                    if let Some(kill_evt) = self.workers_kill_evt.take() {
                        let acked_features = self.acked_features;
                        let socket = if self.response_socket.is_some() {
                            self.response_socket.take()
                        } else {
                            None
                        };
                        let worker_result = thread::Builder::new()
                            .name("vhost_net".to_string())
                            .spawn(move || {
                                let mut worker = Worker::new(
                                    queues,
                                    vhost_net_handle,
                                    vhost_interrupt,
                                    interrupt,
                                    acked_features,
                                    kill_evt,
                                    socket,
                                );
                                let activate_vqs = |handle: &U| -> Result<()> {
                                    for idx in 0..NUM_QUEUES {
                                        handle
                                            .set_backend(idx, Some(&tap))
                                            .map_err(Error::VhostNetSetBackend)?;
                                    }
                                    Ok(())
                                };
                                let cleanup_vqs = |handle: &U| -> Result<()> {
                                    for idx in 0..NUM_QUEUES {
                                        handle
                                            .set_backend(idx, None)
                                            .map_err(Error::VhostNetSetBackend)?;
                                    }
                                    Ok(())
                                };
                                let result =
                                    worker.run(queue_evts, QUEUE_SIZES, activate_vqs, cleanup_vqs);
                                if let Err(e) = result {
                                    error!("net worker thread exited with error: {}", e);
                                }
                                (worker, tap)
                            });

                        match worker_result {
                            Err(e) => {
                                error!("failed to spawn vhost_net worker: {}", e);
                                return;
                            }
                            Ok(join_handle) => {
                                self.worker_thread = Some(join_handle);
                            }
                        }
                    }
                }
            }
        }
    }

    fn on_device_sandboxed(&mut self) {
        // ignore the error but to log the error. We don't need to do
        // anything here because when activate, the other vhost set up
        // will be failed to stop the activate thread.
        if let Some(vhost_net_handle) = &self.vhost_net_handle {
            match vhost_net_handle.set_owner() {
                Ok(_) => {}
                Err(e) => error!("{}: failed to set owner: {:?}", self.debug_label(), e),
            }
        }
    }

    fn control_notify(&self, behavior: MsixStatus) {
        if self.worker_thread.is_none() || self.request_socket.is_none() {
            return;
        }
        if let Some(socket) = &self.request_socket {
            match behavior {
                MsixStatus::EntryChanged(index) => {
                    if let Err(e) = socket.send(&VhostDevRequest::MsixEntryChanged(index)) {
                        error!(
                            "{} failed to send VhostMsixEntryChanged request for entry {}: {:?}",
                            self.debug_label(),
                            index,
                            e
                        );
                        return;
                    }
                    if let Err(e) = socket.recv() {
                        error!("{} failed to receive VhostMsixEntryChanged response for entry {}: {:?}", self.debug_label(), index, e);
                    }
                }
                MsixStatus::Changed => {
                    if let Err(e) = socket.send(&VhostDevRequest::MsixChanged) {
                        error!(
                            "{} failed to send VhostMsixChanged request: {:?}",
                            self.debug_label(),
                            e
                        );
                        return;
                    }
                    if let Err(e) = socket.recv() {
                        error!(
                            "{} failed to receive VhostMsixChanged response {:?}",
                            self.debug_label(),
                            e
                        );
                    }
                }
                _ => {}
            }
        }
    }

    fn reset(&mut self) -> bool {
        // Only kill the child if it claimed its eventfd.
        if self.workers_kill_evt.is_none() && self.kill_evt.write(1).is_err() {
            error!("{}: failed to notify the kill event", self.debug_label());
            return false;
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            match worker_thread.join() {
                Err(_) => {
                    error!("{}: failed to get back resources", self.debug_label());
                    return false;
                }
                Ok((worker, tap)) => {
                    self.vhost_net_handle = Some(worker.vhost_handle);
                    self.tap = Some(tap);
                    self.vhost_interrupt = Some(worker.vhost_interrupt);
                    self.workers_kill_evt = Some(worker.kill_evt);
                    self.response_socket = worker.response_socket;
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::virtio::VIRTIO_MSI_NO_VECTOR;
    use net_util::fakes::FakeTap;
    use std::result;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use vhost::net::fakes::FakeNet;
    use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError};

    fn create_guest_memory() -> result::Result<GuestMemory, GuestMemoryError> {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x4000)])
    }

    fn create_net_common() -> Net<FakeTap, FakeNet<FakeTap>> {
        let guest_memory = create_guest_memory().unwrap();
        Net::<FakeTap, FakeNet<FakeTap>>::new(
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "de:21:e8:47:6b:6a".parse().unwrap(),
            &guest_memory,
        )
        .unwrap()
    }

    #[test]
    fn create_net() {
        create_net_common();
    }

    #[test]
    fn keep_fds() {
        let net = create_net_common();
        let fds = net.keep_fds();
        assert!(fds.len() >= 1, "We should have gotten at least one fd");
    }

    #[test]
    fn features() {
        let net = create_net_common();
        assert_eq!(net.features(), 5117103235);
    }

    #[test]
    fn ack_features() {
        let mut net = create_net_common();
        // Just testing that we don't panic, for now
        net.ack_features(1);
        net.ack_features(1 << 32);
    }

    #[test]
    fn activate() {
        let mut net = create_net_common();
        let guest_memory = create_guest_memory().unwrap();
        // Just testing that we don't panic, for now
        net.activate(
            guest_memory,
            Interrupt::new(
                Arc::new(AtomicUsize::new(0)),
                EventFd::new().unwrap(),
                EventFd::new().unwrap(),
                None,
                VIRTIO_MSI_NO_VECTOR,
            ),
            vec![Queue::new(1)],
            vec![EventFd::new().unwrap()],
        );
    }
}
