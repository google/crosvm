// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::net::Ipv4Addr;
use std::path::Path;
use std::thread;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use base::Tube;
use net_util::MacAddress;
use net_util::TapT;
use vhost::NetT as VhostNetT;
use virtio_sys::virtio_net;
use vm_memory::GuestMemory;

use super::control_socket::*;
use super::worker::Worker;
use super::Error;
use super::Result;
use crate::pci::MsixStatus;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;
use crate::Suspendable;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

pub struct Net<T: TapT, U: VhostNetT<T>> {
    workers_kill_evt: Option<Event>,
    kill_evt: Event,
    worker_thread: Option<thread::JoinHandle<(Worker<U>, T)>>,
    tap: Option<T>,
    vhost_net_handle: Option<U>,
    vhost_interrupt: Option<Vec<Event>>,
    avail_features: u64,
    acked_features: u64,
    request_tube: Tube,
    response_tube: Option<Tube>,
}

impl<T, U> Net<T, U>
where
    T: TapT,
    U: VhostNetT<T>,
{
    /// Create a new virtio network device with the given IP address and
    /// netmask.
    pub fn new(
        vhost_net_device_path: &Path,
        base_features: u64,
        ip_addr: Ipv4Addr,
        netmask: Ipv4Addr,
        mac_addr: MacAddress,
    ) -> Result<Net<T, U>> {
        let kill_evt = Event::new().map_err(Error::CreateKillEvent)?;

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
        let vhost_net_handle = U::new(vhost_net_device_path).map_err(Error::VhostOpen)?;

        let avail_features = base_features
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_HOST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_MRG_RXBUF;

        let mut vhost_interrupt = Vec::new();
        for _ in 0..NUM_QUEUES {
            vhost_interrupt.push(Event::new().map_err(Error::VhostIrqCreate)?);
        }

        let (request_tube, response_tube) = Tube::pair().map_err(Error::CreateTube)?;

        Ok(Net {
            workers_kill_evt: Some(kill_evt.try_clone().map_err(Error::CloneKillEvent)?),
            kill_evt,
            worker_thread: None,
            tap: Some(tap),
            vhost_net_handle: Some(vhost_net_handle),
            vhost_interrupt: Some(vhost_interrupt),
            avail_features,
            acked_features: 0u64,
            request_tube,
            response_tube: Some(response_tube),
        })
    }
}

impl<T, U> Drop for Net<T, U>
where
    T: TapT,
    U: VhostNetT<T>,
{
    fn drop(&mut self) {
        // Only kill the child if it claimed its event.
        if self.workers_kill_evt.is_none() {
            // Ignore the result because there is nothing we can do about it.
            let _ = self.kill_evt.signal();
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
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = Vec::new();

        if let Some(tap) = &self.tap {
            keep_rds.push(tap.as_raw_descriptor());
        }

        if let Some(vhost_net_handle) = &self.vhost_net_handle {
            keep_rds.push(vhost_net_handle.as_raw_descriptor());
        }

        if let Some(vhost_interrupt) = &self.vhost_interrupt {
            for vhost_int in vhost_interrupt.iter() {
                keep_rds.push(vhost_int.as_raw_descriptor());
            }
        }

        if let Some(workers_kill_evt) = &self.workers_kill_evt {
            keep_rds.push(workers_kill_evt.as_raw_descriptor());
        }
        keep_rds.push(self.kill_evt.as_raw_descriptor());

        keep_rds.push(self.request_tube.as_raw_descriptor());

        if let Some(response_tube) = &self.response_tube {
            keep_rds.push(response_tube.as_raw_descriptor());
        }

        keep_rds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Net
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
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<(Queue, Event)>,
    ) -> anyhow::Result<()> {
        if queues.len() != NUM_QUEUES {
            return Err(anyhow!(
                "net: expected {} queues, got {}",
                NUM_QUEUES,
                queues.len()
            ));
        }

        let vhost_net_handle = self
            .vhost_net_handle
            .take()
            .context("missing vhost_net_handle")?;
        let tap = self.tap.take().context("missing tap")?;
        let vhost_interrupt = self
            .vhost_interrupt
            .take()
            .context("missing vhost_interrupt")?;
        let kill_evt = self.workers_kill_evt.take().context("missing kill_evt")?;
        let acked_features = self.acked_features;
        let socket = if self.response_tube.is_some() {
            self.response_tube.take()
        } else {
            None
        };
        let mut worker = Worker::new(
            queues,
            vhost_net_handle,
            vhost_interrupt,
            interrupt,
            acked_features,
            kill_evt,
            socket,
            self.supports_iommu(),
        );
        let activate_vqs = |handle: &U| -> Result<()> {
            for idx in 0..NUM_QUEUES {
                handle
                    .set_backend(idx, Some(&tap))
                    .map_err(Error::VhostNetSetBackend)?;
            }
            Ok(())
        };
        worker
            .init(mem, QUEUE_SIZES, activate_vqs)
            .context("net worker init exited with error")?;
        let worker_thread = thread::Builder::new()
            .name("vhost_net".to_string())
            .spawn(move || {
                let cleanup_vqs = |handle: &U| -> Result<()> {
                    for idx in 0..NUM_QUEUES {
                        handle
                            .set_backend(idx, None)
                            .map_err(Error::VhostNetSetBackend)?;
                    }
                    Ok(())
                };
                let result = worker.run(cleanup_vqs);
                if let Err(e) = result {
                    error!("net worker thread exited with error: {}", e);
                }
                (worker, tap)
            })
            .context("failed to spawn vhost_net worker")?;

        self.worker_thread = Some(worker_thread);
        Ok(())
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
        if self.worker_thread.is_none() {
            return;
        }
        match behavior {
            MsixStatus::EntryChanged(index) => {
                if let Err(e) = self
                    .request_tube
                    .send(&VhostDevRequest::MsixEntryChanged(index))
                {
                    error!(
                        "{} failed to send VhostMsixEntryChanged request for entry {}: {:?}",
                        self.debug_label(),
                        index,
                        e
                    );
                    return;
                }
                if let Err(e) = self.request_tube.recv::<VhostDevResponse>() {
                    error!(
                        "{} failed to receive VhostMsixEntryChanged response for entry {}: {:?}",
                        self.debug_label(),
                        index,
                        e
                    );
                }
            }
            MsixStatus::Changed => {
                if let Err(e) = self.request_tube.send(&VhostDevRequest::MsixChanged) {
                    error!(
                        "{} failed to send VhostMsixChanged request: {:?}",
                        self.debug_label(),
                        e
                    );
                    return;
                }
                if let Err(e) = self.request_tube.recv::<VhostDevResponse>() {
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

    fn reset(&mut self) -> bool {
        // Only kill the child if it claimed its event.
        if self.workers_kill_evt.is_none() && self.kill_evt.signal().is_err() {
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
                    self.response_tube = worker.response_tube;
                    return true;
                }
            }
        }
        false
    }
}

impl<T, U> Suspendable for Net<T, U>
where
    T: TapT + 'static,
    U: VhostNetT<T> + 'static,
{
}

#[cfg(test)]
pub mod tests {
    use std::path::PathBuf;
    use std::result;

    use hypervisor::ProtectionType;
    use net_util::sys::unix::fakes::FakeTap;
    use vhost::net::fakes::FakeNet;
    use vm_memory::GuestAddress;
    use vm_memory::GuestMemory;
    use vm_memory::GuestMemoryError;

    use super::*;
    use crate::virtio::base_features;
    use crate::virtio::VIRTIO_MSI_NO_VECTOR;
    use crate::IrqLevelEvent;

    fn create_guest_memory() -> result::Result<GuestMemory, GuestMemoryError> {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        GuestMemory::new(&[(start_addr1, 0x1000), (start_addr2, 0x4000)])
    }

    fn create_net_common() -> Net<FakeTap, FakeNet<FakeTap>> {
        let features = base_features(ProtectionType::Unprotected);
        Net::<FakeTap, FakeNet<FakeTap>>::new(
            &PathBuf::from(""),
            features,
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "de:21:e8:47:6b:6a".parse().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn create_net() {
        create_net_common();
    }

    #[test]
    fn keep_rds() {
        let net = create_net_common();
        let fds = net.keep_rds();
        assert!(
            !fds.is_empty(),
            "We should have gotten at least one descriptor"
        );
    }

    #[test]
    fn features() {
        let net = create_net_common();
        let expected_features = 1 << 0 // VIRTIO_NET_F_CSUM
            | 1 << 1 // VIRTIO_NET_F_GUEST_CSUM
            | 1 << 7 // VIRTIO_NET_F_GUEST_TSO4
            | 1 << 10 // VIRTIO_NET_F_GUEST_UFO
            | 1 << 11 // VIRTIO_NET_F_HOST_TSO4
            | 1 << 14 // VIRTIO_NET_F_HOST_UFO
            | 1 << 15 // VIRTIO_NET_F_MRG_RXBUF
            | 1 << 29 // VIRTIO_RING_F_EVENT_IDX
            | 1 << 32; // VIRTIO_F_VERSION_1
        assert_eq!(net.features(), expected_features);
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
        let _ = net.activate(
            guest_memory,
            Interrupt::new(IrqLevelEvent::new().unwrap(), None, VIRTIO_MSI_NO_VECTOR),
            vec![
                (Queue::new(1), Event::new().unwrap()),
                (Queue::new(1), Event::new().unwrap()),
            ],
        );
    }
}
