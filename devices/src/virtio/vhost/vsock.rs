// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::os::unix::prelude::OpenOptionsExt;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::open_file_or_duplicate;
use base::warn;
use base::AsRawDescriptor;
use base::RawDescriptor;
use base::Tube;
use base::WorkerThread;
use data_model::Le64;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
use vhost::Vhost;
use vhost::Vsock as VhostVsockHandle;
use vm_memory::GuestMemory;
use zerocopy::IntoBytes;

use super::control_socket::VhostDevRequest;
use super::control_socket::VhostDevResponse;
use super::worker::VringBase;
use super::worker::Worker;
use super::Error;
use crate::pci::MsixStatus;
use crate::virtio::copy_config;
use crate::virtio::device_constants::vsock::NUM_QUEUES;
use crate::virtio::vsock::VsockConfig;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;

const DEFAULT_MAX_QUEUE_SIZE: u16 = 256;

pub struct Vsock {
    worker_thread: Option<WorkerThread<Worker<VhostVsockHandle>>>,
    worker_client_tube: Tube,
    worker_server_tube: Option<Tube>,
    vhost_handle: Option<VhostVsockHandle>,
    cid: u64,
    avail_features: u64,
    acked_features: u64,
    // vrings_base states:
    // None - device was just created or is running.
    // Some - device was put to sleep after running or was restored.
    vrings_base: Option<Vec<VringBase>>,
    // Some iff the device is active and awake.
    event_queue: Option<Queue>,
    // If true, we should send a TRANSPORT_RESET event to the guest at the next opportunity.
    needs_transport_reset: bool,
    max_queue_sizes: [u16; NUM_QUEUES],
}

#[derive(Serialize, Deserialize)]
struct VsockSnapshot {
    cid: u64,
    avail_features: u64,
    acked_features: u64,
    vrings_base: Vec<VringBase>,
}

impl Vsock {
    /// Create a new virtio-vsock device with the given VM cid.
    pub fn new(base_features: u64, vsock_config: &VsockConfig) -> anyhow::Result<Vsock> {
        let device_file = open_file_or_duplicate(
            &vsock_config.vhost_device,
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK),
        )
        .with_context(|| {
            format!(
                "failed to open virtual socket device {}",
                vsock_config.vhost_device.display(),
            )
        })?;

        let handle = VhostVsockHandle::new(device_file);

        let avail_features = base_features;

        let (worker_client_tube, worker_server_tube) = Tube::pair().map_err(Error::CreateTube)?;

        Ok(Vsock {
            worker_thread: None,
            worker_client_tube,
            worker_server_tube: Some(worker_server_tube),
            vhost_handle: Some(handle),
            cid: vsock_config.cid,
            avail_features,
            acked_features: 0,
            vrings_base: None,
            event_queue: None,
            needs_transport_reset: false,
            max_queue_sizes: vsock_config
                .max_queue_sizes
                .unwrap_or([DEFAULT_MAX_QUEUE_SIZE; NUM_QUEUES]),
        })
    }

    pub fn new_for_testing(cid: u64, features: u64) -> Vsock {
        let (worker_client_tube, worker_server_tube) = Tube::pair().unwrap();
        Vsock {
            worker_thread: None,
            worker_client_tube,
            worker_server_tube: Some(worker_server_tube),
            vhost_handle: None,
            cid,
            avail_features: features,
            acked_features: 0,
            vrings_base: None,
            event_queue: None,
            needs_transport_reset: false,
            max_queue_sizes: [DEFAULT_MAX_QUEUE_SIZE; NUM_QUEUES],
        }
    }

    pub fn acked_features(&self) -> u64 {
        self.acked_features
    }
}

impl VirtioDevice for Vsock {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = Vec::new();

        if let Some(handle) = &self.vhost_handle {
            keep_rds.push(handle.as_raw_descriptor());
        }
        keep_rds.push(self.worker_client_tube.as_raw_descriptor());
        if let Some(worker_server_tube) = &self.worker_server_tube {
            keep_rds.push(worker_server_tube.as_raw_descriptor());
        }

        keep_rds
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Vsock
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.max_queue_sizes[..]
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let cid = Le64::from(self.cid);
        copy_config(data, 0, cid.as_bytes(), offset);
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
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        if queues.len() != NUM_QUEUES {
            return Err(anyhow!(
                "vsock: expected {} queues, got {}",
                NUM_QUEUES,
                queues.len()
            ));
        }

        let vhost_handle = self.vhost_handle.take().context("missing vhost_handle")?;
        let acked_features = self.acked_features;
        let cid = self.cid;

        // The third vq is an event-only vq that is not handled by the vhost
        // subsystem (but still needs to exist).  Split it off here.
        let mut event_queue = queues.remove(&2).unwrap();
        // Send TRANSPORT_RESET event if needed.
        if self.needs_transport_reset {
            self.needs_transport_reset = false;

            // We assume the event queue is non-empty. This should be OK for existing use cases
            // because we expect the guest vsock driver to be initialized at the time of snapshot
            // and this is only the event we ever write to the queue.
            //
            // If that assumption becomes invalid, we could integrate this logic into the worker
            // thread's event loop so that it can wait for space in the queue.
            let mut avail_desc = event_queue
                .pop()
                .expect("event queue is empty, can't send transport reset event");
            let transport_reset = virtio_sys::virtio_vsock::virtio_vsock_event{
                id: virtio_sys::virtio_vsock::virtio_vsock_event_id_VIRTIO_VSOCK_EVENT_TRANSPORT_RESET.into(),
            };
            avail_desc
                .writer
                .write_obj(transport_reset)
                .expect("failed to write transport reset event");
            event_queue.add_used(avail_desc);
            event_queue.trigger_interrupt();
        }
        self.event_queue = Some(event_queue);

        let mut worker = Worker::new(
            "vhost-vsock",
            queues,
            vhost_handle,
            interrupt,
            acked_features,
            Some(
                self.worker_server_tube
                    .take()
                    .expect("worker control tube missing"),
            ),
            mem,
            self.vrings_base.take(),
        )
        .context("vsock worker init exited with error")?;
        worker
            .vhost_handle
            .set_cid(cid)
            .map_err(Error::VhostVsockSetCid)?;
        worker
            .vhost_handle
            .start()
            .map_err(Error::VhostVsockStart)?;

        self.worker_thread = Some(WorkerThread::start("vhost_vsock", move |kill_evt| {
            let result = worker.run(kill_evt);
            if let Err(e) = result {
                error!("vsock worker thread exited with error: {:?}", e);
            }
            worker
        }));

        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        if let Some(worker_thread) = self.worker_thread.take() {
            let worker = worker_thread.stop();
            worker
                .vhost_handle
                .stop()
                .context("failed to stop vrings")?;
            // Call get_vring_base to stop the queues.
            for (pos, _) in worker.queues.iter() {
                worker
                    .vhost_handle
                    .get_vring_base(*pos)
                    .context("get_vring_base failed")?;
            }

            self.vhost_handle = Some(worker.vhost_handle);
            self.worker_server_tube = worker.response_tube;
        }
        self.acked_features = 0;
        self.vrings_base = None;
        self.event_queue = None;
        self.needs_transport_reset = false;
        Ok(())
    }

    fn on_device_sandboxed(&mut self) {
        // ignore the error but to log the error. We don't need to do
        // anything here because when activate, the other vhost set up
        // will be failed to stop the activate thread.
        if let Some(vhost_handle) = &self.vhost_handle {
            match vhost_handle.set_owner() {
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
                    .worker_client_tube
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
                if let Err(e) = self.worker_client_tube.recv::<VhostDevResponse>() {
                    error!(
                        "{} failed to receive VhostMsixEntryChanged response for entry {}: {:?}",
                        self.debug_label(),
                        index,
                        e
                    );
                }
            }
            MsixStatus::Changed => {
                if let Err(e) = self.worker_client_tube.send(&VhostDevRequest::MsixChanged) {
                    error!(
                        "{} failed to send VhostMsixChanged request: {:?}",
                        self.debug_label(),
                        e
                    );
                    return;
                }
                if let Err(e) = self.worker_client_tube.recv::<VhostDevResponse>() {
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

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        if let Some(worker_thread) = self.worker_thread.take() {
            let worker = worker_thread.stop();
            worker
                .vhost_handle
                .stop()
                .context("failed to stop vrings")?;
            let mut queues: BTreeMap<usize, Queue> = worker.queues;
            let mut vrings_base = Vec::new();
            for (pos, _) in queues.iter() {
                let vring_base = VringBase {
                    index: *pos,
                    base: worker.vhost_handle.get_vring_base(*pos)?,
                };
                vrings_base.push(vring_base);
            }
            self.vrings_base = Some(vrings_base);
            self.vhost_handle = Some(worker.vhost_handle);
            self.worker_server_tube = worker.response_tube;
            queues.insert(
                2,
                self.event_queue.take().expect("Vsock event queue missing"),
            );
            return Ok(Some(BTreeMap::from_iter(queues)));
        }
        Ok(None)
    }

    fn virtio_wake(
        &mut self,
        device_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        match device_state {
            None => Ok(()),
            Some((mem, interrupt, queues)) => {
                // TODO: activate is just what we want at the moment, but we should probably move
                // it into a "start workers" function to make it obvious that it isn't strictly
                // used for activate events.
                self.activate(mem, interrupt, queues)?;
                Ok(())
            }
        }
    }

    fn virtio_snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        let vrings_base = self.vrings_base.clone().unwrap_or_default();
        AnySnapshot::to_any(VsockSnapshot {
            // `cid` and `avail_features` are snapshot as a safeguard. Upon restore, validate
            // cid and avail_features in the current vsock match the previously snapshot vsock.
            cid: self.cid,
            avail_features: self.avail_features,
            acked_features: self.acked_features,
            vrings_base,
        })
        .context("failed to snapshot virtio console")
    }

    fn virtio_restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        let deser: VsockSnapshot =
            AnySnapshot::from_any(data).context("failed to deserialize virtio vsock")?;
        anyhow::ensure!(
            self.cid == deser.cid,
            "Virtio vsock incorrect cid for restore:\n Expected: {}, Actual: {}",
            self.cid,
            deser.cid,
        );
        anyhow::ensure!(
            self.avail_features == deser.avail_features,
            "Virtio vsock incorrect avail features for restore:\n Expected: {}, Actual: {}",
            self.avail_features,
            deser.avail_features,
        );
        self.acked_features = deser.acked_features;
        self.vrings_base = Some(deser.vrings_base);
        // Send the TRANSPORT_RESET on next wake so that the guest knows that its existing vsock
        // connections are broken.
        self.needs_transport_reset = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use super::*;

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

        let mut buf = [0u8; 8];
        vsock.read_config(0, &mut buf);
        assert_eq!(cid, u64::from_le_bytes(buf));

        vsock.read_config(0, &mut buf[..4]);
        assert_eq!(
            (cid & 0xffffffff) as u32,
            u32::from_le_bytes(buf[..4].try_into().unwrap())
        );

        vsock.read_config(4, &mut buf[..4]);
        assert_eq!(
            (cid >> 32) as u32,
            u32::from_le_bytes(buf[..4].try_into().unwrap())
        );

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
