// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::RawDescriptor;
use base::Tube;
use base::WorkerThread;
use vhost::Scmi as VhostScmiHandle;
use vhost::Vhost;
use vm_memory::GuestMemory;

use super::control_socket::VhostDevRequest;
use super::control_socket::VhostDevResponse;
use super::worker::Worker;
use super::Error;
use super::Result;
use crate::pci::MsixStatus;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;
use crate::Suspendable;

const QUEUE_SIZE: u16 = 128;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];
const VIRTIO_SCMI_F_P2A_CHANNELS: u32 = 0;

pub struct Scmi {
    worker_thread: Option<WorkerThread<()>>,
    worker_client_tube: Tube,
    worker_server_tube: Option<Tube>,
    vhost_handle: Option<VhostScmiHandle>,
    avail_features: u64,
    acked_features: u64,
}

impl Scmi {
    /// Create a new virtio-scmi device.
    pub fn new(vhost_scmi_device_path: &Path, base_features: u64) -> Result<Scmi> {
        let handle = VhostScmiHandle::new(vhost_scmi_device_path).map_err(Error::VhostOpen)?;

        let avail_features = base_features | 1 << VIRTIO_SCMI_F_P2A_CHANNELS;

        let (worker_client_tube, worker_server_tube) = Tube::pair().map_err(Error::CreateTube)?;

        Ok(Scmi {
            worker_thread: None,
            worker_client_tube,
            worker_server_tube: Some(worker_server_tube),
            vhost_handle: Some(handle),
            avail_features,
            acked_features: 0,
        })
    }

    pub fn acked_features(&self) -> u64 {
        self.acked_features
    }
}

impl VirtioDevice for Scmi {
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
        DeviceType::Scmi
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
            warn!("scmi: virtio-scmi got unknown feature ack: {:x}", v);

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
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
        let vhost_handle = self.vhost_handle.take().context("missing vhost_handle")?;
        let acked_features = self.acked_features;
        let mut worker = Worker::new(
            "vhost-scmi",
            queues,
            vhost_handle,
            interrupt,
            acked_features,
            self.worker_server_tube
                .take()
                .expect("worker control tube missing"),
            mem,
            None,
        )
        .context("vhost worker init exited with error")?;

        self.worker_thread = Some(WorkerThread::start("vhost_scmi", move |kill_evt| {
            let result = worker.run(kill_evt);
            if let Err(e) = result {
                error!("vhost_scmi worker thread exited with error: {:?}", e);
            }
        }));
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
}

impl Suspendable for Scmi {}
