// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::net::Ipv4Addr;
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::spawn;

use net_sys;
use net_util::{Tap, Error as TapError};
use sys_util::{Error as SysError, EventFd, GuestMemory, Poller};
use vhost::{Error as VhostError, Net as VhostNetHandle, Vhost};
use virtio_sys::{vhost, virtio_net};
use virtio_sys::virtio_net::virtio_net_hdr_mrg_rxbuf;

use super::{VirtioDevice, Queue, INTERRUPT_STATUS_USED_RING, TYPE_NET};

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &'static [u16] = &[QUEUE_SIZE, QUEUE_SIZE];

#[derive(Debug)]
pub enum VhostNetError {
    /// Creating kill eventfd failed.
    CreateKillEventFd(SysError),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(SysError),
    /// Open tap device failed.
    TapOpen(TapError),
    /// Setting tap IP failed.
    TapSetIp(TapError),
    /// Setting tap netmask failed.
    TapSetNetmask(TapError),
    /// Setting tap interface offload flags failed.
    TapSetOffload(TapError),
    /// Setting vnet header size failed.
    TapSetVnetHdrSize(TapError),
    /// Enabling tap interface failed.
    TapEnable(TapError),
    /// Open vhost-net device failed.
    VhostOpen(VhostError),
    /// Set owner failed.
    VhostSetOwner(VhostError),
    /// Get features failed.
    VhostGetFeatures(VhostError),
    /// Set features failed.
    VhostSetFeatures(VhostError),
    /// Set mem table failed.
    VhostSetMemTable(VhostError),
    /// Set vring num failed.
    VhostSetVringNum(VhostError),
    /// Set vring addr failed.
    VhostSetVringAddr(VhostError),
    /// Set vring base failed.
    VhostSetVringBase(VhostError),
    /// Set vring call failed.
    VhostSetVringCall(VhostError),
    /// Set vring kick failed.
    VhostSetVringKick(VhostError),
    /// Net set backend failed.
    VhostNetSetBackend(VhostError),
    /// Failed to create vhost eventfd.
    VhostIrqCreate(SysError),
    /// Failed to read vhost eventfd.
    VhostIrqRead(SysError),
    /// Error while polling for events.
    PollError(SysError),
}

struct Worker {
    queues: Vec<Queue>,
    tap: Tap,
    vhost_net_handle: VhostNetHandle,
    vhost_interrupt: EventFd,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    acked_features: u64,
}

impl Worker {
    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    fn run(&mut self, queue_evts: Vec<EventFd>, kill_evt: EventFd) -> Result<(), VhostNetError> {
        // Preliminary setup for vhost net.
        self.vhost_net_handle
            .set_owner()
            .map_err(VhostNetError::VhostSetOwner)?;

        let avail_features = self.vhost_net_handle
            .get_features()
            .map_err(VhostNetError::VhostGetFeatures)?;

        let features: c_ulonglong = self.acked_features & avail_features;
        self.vhost_net_handle
            .set_features(features)
            .map_err(VhostNetError::VhostSetFeatures)?;

        self.vhost_net_handle
            .set_mem_table()
            .map_err(VhostNetError::VhostSetMemTable)?;

        for (queue_index, ref queue) in self.queues.iter().enumerate() {
            self.vhost_net_handle
                .set_vring_num(queue_index, queue.max_size)
                .map_err(VhostNetError::VhostSetVringNum)?;

            self.vhost_net_handle
                .set_vring_addr(QUEUE_SIZES[queue_index],
                                queue.actual_size(),
                                queue_index,
                                0,
                                queue.desc_table,
                                queue.used_ring,
                                queue.avail_ring,
                                None)
                .map_err(VhostNetError::VhostSetVringAddr)?;
            self.vhost_net_handle
                .set_vring_base(queue_index, 0)
                .map_err(VhostNetError::VhostSetVringBase)?;
            self.vhost_net_handle
                .set_vring_call(queue_index, &self.vhost_interrupt)
                .map_err(VhostNetError::VhostSetVringCall)?;
            self.vhost_net_handle
                .set_vring_kick(queue_index, &queue_evts[queue_index])
                .map_err(VhostNetError::VhostSetVringKick)?;
            self.vhost_net_handle
                .set_backend(queue_index, &self.tap)
                .map_err(VhostNetError::VhostNetSetBackend)?;
        }

        const VHOST_IRQ: u32 = 1;
        const KILL: u32 = 2;

        let mut poller = Poller::new(2);

        'poll: loop {
            let tokens = match poller.poll(&[(VHOST_IRQ, &self.vhost_interrupt),
                                             (KILL, &kill_evt)]) {
                Ok(v) => v,
                Err(e) => return Err(VhostNetError::PollError(e)),
            };

            let mut needs_interrupt = false;
            for &token in tokens {
                match token {
                    VHOST_IRQ => {
                        needs_interrupt = true;
                        self.vhost_interrupt
                            .read()
                            .map_err(VhostNetError::VhostIrqRead)?;
                    }
                    KILL => break 'poll,
                    _ => unreachable!(),
                }
            }
            if needs_interrupt {
                self.signal_used_queue();
            }
        }
        Ok(())
    }
}

pub struct VhostNet {
    workers_kill_evt: Option<EventFd>,
    kill_evt: EventFd,
    tap: Option<Tap>,
    vhost_net_handle: Option<VhostNetHandle>,
    vhost_interrupt: Option<EventFd>,
    avail_features: u64,
    acked_features: u64,
}

impl VhostNet {
    /// Create a new virtio network device with the given IP address and
    /// netmask.
    pub fn new(ip_addr: Ipv4Addr,
               netmask: Ipv4Addr,
               mem: &GuestMemory)
               -> Result<VhostNet, VhostNetError> {
        let kill_evt = EventFd::new().map_err(VhostNetError::CreateKillEventFd)?;

        let tap = Tap::new().map_err(VhostNetError::TapOpen)?;
        tap.set_ip_addr(ip_addr)
            .map_err(VhostNetError::TapSetIp)?;
        tap.set_netmask(netmask)
            .map_err(VhostNetError::TapSetNetmask)?;

        // Set offload flags to match the virtio features below.
        tap.set_offload(net_sys::TUN_F_CSUM | net_sys::TUN_F_UFO |
                        net_sys::TUN_F_TSO4 | net_sys::TUN_F_TSO6)
            .map_err(VhostNetError::TapSetOffload)?;

        // We declare VIRTIO_NET_F_MRG_RXBUF, so set the vnet hdr size to match.
        let vnet_hdr_size = mem::size_of::<virtio_net_hdr_mrg_rxbuf>() as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(VhostNetError::TapSetVnetHdrSize)?;

        tap.enable().map_err(VhostNetError::TapEnable)?;
        let vhost_net_handle = VhostNetHandle::new(mem)
            .map_err(VhostNetError::VhostOpen)?;

        let avail_features =
            1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM |
            1 << virtio_net::VIRTIO_NET_F_CSUM |
            1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4 |
            1 << virtio_net::VIRTIO_NET_F_GUEST_UFO |
            1 << virtio_net::VIRTIO_NET_F_HOST_TSO4 |
            1 << virtio_net::VIRTIO_NET_F_HOST_UFO |
            1 << virtio_net::VIRTIO_NET_F_MRG_RXBUF |
            1 << vhost::VIRTIO_RING_F_INDIRECT_DESC |
            1 << vhost::VIRTIO_RING_F_EVENT_IDX |
            1 << vhost::VIRTIO_F_NOTIFY_ON_EMPTY |
            1 << vhost::VIRTIO_F_VERSION_1;

        Ok(VhostNet {
               workers_kill_evt: Some(kill_evt
                                          .try_clone()
                                          .map_err(VhostNetError::CloneKillEventFd)?),
               kill_evt: kill_evt,
               tap: Some(tap),
               vhost_net_handle: Some(vhost_net_handle),
               vhost_interrupt: Some(EventFd::new().map_err(VhostNetError::VhostIrqCreate)?),
               avail_features: avail_features,
               acked_features: 0u64,
           })
    }
}

impl Drop for VhostNet {
    fn drop(&mut self) {
        // Only kill the child if it claimed its eventfd.
        if self.workers_kill_evt.is_none() {
            // Ignore the result because there is nothing we can do about it.
            let _ = self.kill_evt.write(1);
        }
    }
}

impl VirtioDevice for VhostNet {
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
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => value as u64,
            1 => (value as u64) << 32,
            _ => {
                warn!("net: virtio net device cannot ack unknown feature page: {}",
                      page);
                0u64
            }
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

    fn activate(&mut self,
                _: GuestMemory,
                interrupt_evt: EventFd,
                status: Arc<AtomicUsize>,
                queues: Vec<Queue>,
                queue_evts: Vec<EventFd>) {
        if queues.len() != 2 || queue_evts.len() != 2 {
            error!("net: expected 2 queues, got {}", queues.len());
            return;
        }

        if let Some(vhost_net_handle) = self.vhost_net_handle.take() {
            if let Some(tap) = self.tap.take() {
                if let Some(vhost_interrupt) = self.vhost_interrupt.take() {
                    if let Some(kill_evt) = self.workers_kill_evt.take() {
                        let acked_features = self.acked_features;
                        spawn(move || {
                            let mut worker = Worker {
                                queues: queues,
                                tap: tap,
                                vhost_net_handle: vhost_net_handle,
                                vhost_interrupt: vhost_interrupt,
                                interrupt_status: status,
                                interrupt_evt: interrupt_evt,
                                acked_features: acked_features,
                            };
                            let result = worker.run(queue_evts, kill_evt);
                            if let Err(e) = result {
                                error!("net worker thread exited with error: {:?}", e);
                            }
                        });
                    }
                }
            }
        }
    }
}
