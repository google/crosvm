// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::mem;
use std::path::Path;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use base::Tube;
use base::WorkerThread;
use net_util::MacAddress;
use net_util::TapT;
use vhost::NetT as VhostNetT;
use virtio_sys::virtio_config::VIRTIO_F_RING_PACKED;
use virtio_sys::virtio_net;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;

use super::control_socket::*;
use super::worker::Worker;
use super::Error;
use super::Result;
use crate::pci::MsixStatus;
use crate::virtio::copy_config;
use crate::virtio::net::build_config;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

pub struct Net<T: TapT + 'static, U: VhostNetT<T> + 'static> {
    worker_thread: Option<WorkerThread<(Worker<U>, T)>>,
    tap: Option<T>,
    guest_mac: Option<[u8; 6]>,
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
    /// Creates a new virtio network device from a tap device that has already been
    /// configured.
    pub fn new(
        vhost_net_device_path: &Path,
        base_features: u64,
        tap: T,
        mac_addr: Option<MacAddress>,
        use_packed_queue: bool,
    ) -> Result<Net<T, U>> {
        // Set offload flags to match the virtio features below.
        tap.set_offload(
            net_sys::TUN_F_CSUM | net_sys::TUN_F_UFO | net_sys::TUN_F_TSO4 | net_sys::TUN_F_TSO6,
        )
        .map_err(Error::TapSetOffload)?;

        // We declare VIRTIO_NET_F_MRG_RXBUF, so set the vnet hdr size to match.
        let vnet_hdr_size = mem::size_of::<virtio_net::virtio_net_hdr_mrg_rxbuf>() as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(Error::TapSetVnetHdrSize)?;

        let vhost_net_handle = U::new(vhost_net_device_path).map_err(Error::VhostOpen)?;

        let mut avail_features = base_features
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_CSUM
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_GUEST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_HOST_TSO4
            | 1 << virtio_net::VIRTIO_NET_F_HOST_UFO
            | 1 << virtio_net::VIRTIO_NET_F_MRG_RXBUF;

        if use_packed_queue {
            avail_features |= 1 << VIRTIO_F_RING_PACKED;
        }

        if mac_addr.is_some() {
            avail_features |= 1 << virtio_net::VIRTIO_NET_F_MAC;
        }

        let mut vhost_interrupt = Vec::new();
        for _ in 0..NUM_QUEUES {
            vhost_interrupt.push(Event::new().map_err(Error::VhostIrqCreate)?);
        }

        let (request_tube, response_tube) = Tube::pair().map_err(Error::CreateTube)?;

        Ok(Net {
            worker_thread: None,
            tap: Some(tap),
            guest_mac: mac_addr.map(|mac| mac.octets()),
            vhost_net_handle: Some(vhost_net_handle),
            vhost_interrupt: Some(vhost_interrupt),
            avail_features,
            acked_features: 0u64,
            request_tube,
            response_tube: Some(response_tube),
        })
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

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let vq_pairs = QUEUE_SIZES.len() / 2;
        // VIRTIO_NET_F_MTU is not set.
        let config_space = build_config(vq_pairs as u16, /* mtu= */ 0, self.guest_mac);
        copy_config(data, 0, config_space.as_bytes(), offset);
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: BTreeMap<usize, Queue>,
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
        worker
            .init(mem, QUEUE_SIZES, activate_vqs, None)
            .context("net worker init exited with error")?;
        self.worker_thread = Some(WorkerThread::start("vhost_net", move |kill_evt| {
            let cleanup_vqs = |handle: &U| -> Result<()> {
                for idx in 0..NUM_QUEUES {
                    handle
                        .set_backend(idx, None)
                        .map_err(Error::VhostNetSetBackend)?;
                }
                Ok(())
            };
            let result = worker.run(cleanup_vqs, kill_evt);
            if let Err(e) = result {
                error!("net worker thread exited with error: {}", e);
            }
            (worker, tap)
        }));

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
        if let Some(worker_thread) = self.worker_thread.take() {
            let (worker, tap) = worker_thread.stop();
            self.vhost_net_handle = Some(worker.vhost_handle);
            self.tap = Some(tap);
            self.vhost_interrupt = Some(worker.vhost_interrupt);
            self.response_tube = worker.response_tube;
            return true;
        }
        false
    }
}

#[cfg(test)]
pub mod tests {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::result;

    use base::pagesize;
    use hypervisor::ProtectionType;
    use net_util::sys::linux::fakes::FakeTap;
    use net_util::TapTCommon;
    use vhost::net::fakes::FakeNet;
    use vm_memory::GuestAddress;
    use vm_memory::GuestMemory;
    use vm_memory::GuestMemoryError;

    use super::*;
    use crate::virtio::base_features;
    use crate::virtio::QueueConfig;
    use crate::virtio::VIRTIO_MSI_NO_VECTOR;
    use crate::IrqLevelEvent;

    fn create_guest_memory() -> result::Result<GuestMemory, GuestMemoryError> {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(pagesize() as u64);
        GuestMemory::new(&[
            (start_addr1, pagesize() as u64),
            (start_addr2, 4 * pagesize() as u64),
        ])
    }

    fn create_net_common() -> Net<FakeTap, FakeNet<FakeTap>> {
        let tap = FakeTap::new(true, false).unwrap();
        tap.set_ip_addr(Ipv4Addr::new(127, 0, 0, 1))
            .map_err(Error::TapSetIp)
            .unwrap();
        tap.set_netmask(Ipv4Addr::new(255, 255, 255, 0))
            .map_err(Error::TapSetNetmask)
            .unwrap();
        let mac = "de:21:e8:47:6b:6a".parse().unwrap();
        tap.set_mac_address(mac).unwrap();
        tap.enable().unwrap();

        let features = base_features(ProtectionType::Unprotected);
        Net::<FakeTap, FakeNet<FakeTap>>::new(&PathBuf::from(""), features, tap, Some(mac), false)
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
            | 1 << 5 // VIRTIO_NET_F_MAC
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

        let mut q0 = QueueConfig::new(1, 0);
        q0.set_ready(true);
        let q0 = q0
            .activate(&guest_memory, Event::new().unwrap())
            .expect("QueueConfig::activate");

        let mut q1 = QueueConfig::new(1, 0);
        q1.set_ready(true);
        let q1 = q1
            .activate(&guest_memory, Event::new().unwrap())
            .expect("QueueConfig::activate");

        // Just testing that we don't panic, for now
        let _ = net.activate(
            guest_memory,
            Interrupt::new(IrqLevelEvent::new().unwrap(), None, VIRTIO_MSI_NO_VECTOR),
            BTreeMap::from([(0, q0), (1, q1)]),
        );
    }
}
