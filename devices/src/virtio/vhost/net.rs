// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::thread;

use net_sys;
use net_util::{MacAddress, TapT};

use sys_util::{EventFd, GuestMemory};
use vhost::NetT as VhostNetT;
use virtio_sys::{vhost, virtio_net};

use super::{Error, Result};
use super::super::{Queue, VirtioDevice, TYPE_NET};
use super::worker::Worker;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &'static [u16] = &[QUEUE_SIZE; NUM_QUEUES];

pub struct Net<T: TapT, U: VhostNetT<T>> {
    workers_kill_evt: Option<EventFd>,
    kill_evt: EventFd,
    tap: Option<T>,
    vhost_net_handle: Option<U>,
    vhost_interrupt: Option<EventFd>,
    avail_features: u64,
    acked_features: u64,
}

impl<T, U> Net<T, U>
where
    T: TapT,
    U: VhostNetT<T>,
{
    /// Create a new virtio network device with the given IP address and
    /// netmask.
    pub fn new(ip_addr: Ipv4Addr,
               netmask: Ipv4Addr,
               mac_addr: MacAddress,
               mem: &GuestMemory) -> Result<Net<T, U>> {
        let kill_evt = EventFd::new().map_err(Error::CreateKillEventFd)?;

        let tap: T = T::new(true).map_err(Error::TapOpen)?;
        tap.set_ip_addr(ip_addr).map_err(Error::TapSetIp)?;
        tap.set_netmask(netmask).map_err(Error::TapSetNetmask)?;
        tap.set_mac_address(mac_addr).map_err(Error::TapSetMacAddress)?;

        // Set offload flags to match the virtio features below.
        tap.set_offload(
            net_sys::TUN_F_CSUM | net_sys::TUN_F_UFO | net_sys::TUN_F_TSO4 | net_sys::TUN_F_TSO6,
        ).map_err(Error::TapSetOffload)?;

        // We declare VIRTIO_NET_F_MRG_RXBUF, so set the vnet hdr size to match.
        let vnet_hdr_size = mem::size_of::<virtio_net::virtio_net_hdr_mrg_rxbuf>() as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size).map_err(Error::TapSetVnetHdrSize)?;

        tap.enable().map_err(Error::TapEnable)?;
        let vhost_net_handle = U::new(mem).map_err(Error::VhostOpen)?;

        let avail_features =
            1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM | 1 << virtio_net::VIRTIO_NET_F_CSUM |
                1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4 |
                1 << virtio_net::VIRTIO_NET_F_GUEST_UFO |
                1 << virtio_net::VIRTIO_NET_F_HOST_TSO4 |
                1 << virtio_net::VIRTIO_NET_F_HOST_UFO |
                1 << virtio_net::VIRTIO_NET_F_MRG_RXBUF |
                1 << vhost::VIRTIO_RING_F_INDIRECT_DESC |
                1 << vhost::VIRTIO_RING_F_EVENT_IDX |
                1 << vhost::VIRTIO_F_NOTIFY_ON_EMPTY | 1 << vhost::VIRTIO_F_VERSION_1;

        Ok(Net {
            workers_kill_evt: Some(kill_evt.try_clone().map_err(Error::CloneKillEventFd)?),
            kill_evt: kill_evt,
            tap: Some(tap),
            vhost_net_handle: Some(vhost_net_handle),
            vhost_interrupt: Some(EventFd::new().map_err(Error::VhostIrqCreate)?),
            avail_features: avail_features,
            acked_features: 0u64,
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
    }
}

impl<T, U> VirtioDevice for Net<T, U>
where
    T: TapT + 'static,
    U: VhostNetT<T> + 'static,
{
    fn keep_fds(&self) -> Vec<RawFd> {
        let mut keep_fds = Vec::new();

        if let Some(ref tap) = self.tap {
            keep_fds.push(tap.as_raw_fd());
        }

        if let Some(ref vhost_net_handle) = self.vhost_net_handle {
            keep_fds.push(vhost_net_handle.as_raw_fd());
        }

        if let Some(ref vhost_interrupt) = self.vhost_interrupt {
            keep_fds.push(vhost_interrupt.as_raw_fd());
        }

        if let Some(ref workers_kill_evt) = self.workers_kill_evt {
            keep_fds.push(workers_kill_evt.as_raw_fd());
        }

        keep_fds
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self, page: u32) -> u32 {
        match page {
            0 => self.avail_features as u32,
            1 => (self.avail_features >> 32) as u32,
            _ => {
                warn!("net: virtio net got request for features page: {}", page);
                0u32
            },
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => value as u64,
            1 => (value as u64) << 32,
            _ => {
                warn!(
                    "net: virtio net device cannot ack unknown feature page: {}",
                    page
                );
                0u64
            },
        };

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
        interrupt_evt: EventFd,
        status: Arc<AtomicUsize>,
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
                        let worker_result = thread::Builder::new()
                            .name("vhost_net".to_string())
                            .spawn(move || {
                                let mut worker = Worker::new(queues,
                                                             vhost_net_handle,
                                                             vhost_interrupt,
                                                             status,
                                                             interrupt_evt,
                                                             acked_features);
                                let activate_vqs = |handle: &U| -> Result<()> {
                                    for idx in 0..NUM_QUEUES {
                                        handle
                                            .set_backend(idx, &tap)
                                            .map_err(Error::VhostNetSetBackend)?;
                                    }
                                    Ok(())
                                };
                                let result =
                                    worker.run(queue_evts, QUEUE_SIZES, kill_evt, activate_vqs);
                                if let Err(e) = result {
                                    error!("net worker thread exited with error: {:?}", e);
                                }
                            });

                        if let Err(e) = worker_result {
                            error!("failed to spawn vhost_net worker: {}", e);
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::result;
    use net_util::fakes::FakeTap;
    use sys_util::{GuestAddress, GuestMemory, GuestMemoryError};
    use vhost::net::fakes::FakeNet;

    fn create_guest_memory() -> result::Result<GuestMemory, GuestMemoryError> {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x100);
        GuestMemory::new(&vec![(start_addr1, 0x100), (start_addr2, 0x400)])
    }

    fn create_net_common() -> Net<FakeTap, FakeNet<FakeTap>> {
        let guest_memory = create_guest_memory().unwrap();
        Net::<FakeTap, FakeNet<FakeTap>>::new(
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "de:21:e8:47:6b:6a".parse().unwrap(),
            &guest_memory,
        ).unwrap()
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
        assert_eq!(net.features(0), 822135939);
        assert_eq!(net.features(1), 1);
        assert_eq!(net.features(2), 0);
    }

    #[test]
    fn ack_features() {
        let mut net = create_net_common();
        // Just testing that we don't panic, for now
        net.ack_features(0, 1);
        net.ack_features(1, 1);
    }

    #[test]
    fn activate() {
        let mut net = create_net_common();
        let guest_memory = create_guest_memory().unwrap();
        // Just testing that we don't panic, for now
        net.activate(
            guest_memory,
            EventFd::new().unwrap(),
            Arc::new(AtomicUsize::new(0)),
            vec![Queue::new(1)],
            vec![EventFd::new().unwrap()],
        );
    }
}
