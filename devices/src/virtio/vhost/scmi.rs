// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::anyhow;
use anyhow::Context;
use base::WorkerThread;
use base::{error, warn, AsRawDescriptor, Event, RawDescriptor};
use vhost::Scmi as VhostScmiHandle;
use vhost::Vhost;
use vm_memory::GuestMemory;

use super::worker::Worker;
use super::{Error, Result};
use crate::virtio::{DeviceType, Interrupt, Queue, VirtioDevice};
use crate::Suspendable;

const QUEUE_SIZE: u16 = 128;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];
const VIRTIO_SCMI_F_P2A_CHANNELS: u32 = 0;

pub struct Scmi {
    worker_thread: Option<WorkerThread<()>>,
    vhost_handle: Option<VhostScmiHandle>,
    interrupts: Option<Vec<Event>>,
    avail_features: u64,
    acked_features: u64,
}

impl Scmi {
    /// Create a new virtio-scmi device.
    pub fn new(vhost_scmi_device_path: &Path, base_features: u64) -> Result<Scmi> {
        let handle = VhostScmiHandle::new(vhost_scmi_device_path).map_err(Error::VhostOpen)?;

        let avail_features = base_features | 1 << VIRTIO_SCMI_F_P2A_CHANNELS;

        let mut interrupts = Vec::new();
        for _ in 0..NUM_QUEUES {
            interrupts.push(Event::new().map_err(Error::VhostIrqCreate)?);
        }

        Ok(Scmi {
            worker_thread: None,
            vhost_handle: Some(handle),
            interrupts: Some(interrupts),
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

        if let Some(interrupt) = &self.interrupts {
            for vhost_int in interrupt.iter() {
                keep_rds.push(vhost_int.as_raw_descriptor());
            }
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
        let interrupts = self.interrupts.take().context("missing interrupts")?;
        let acked_features = self.acked_features;
        let mut worker = Worker::new(
            queues,
            vhost_handle,
            interrupts,
            interrupt,
            acked_features,
            None,
            self.supports_iommu(),
        );
        let activate_vqs = |_handle: &VhostScmiHandle| -> Result<()> { Ok(()) };

        worker
            .init(mem, QUEUE_SIZES, activate_vqs, None)
            .context("vhost worker init exited with error")?;

        self.worker_thread = Some(WorkerThread::start("vhost_scmi", move |kill_evt| {
            let cleanup_vqs = |_handle: &VhostScmiHandle| -> Result<()> { Ok(()) };
            let result = worker.run(cleanup_vqs, kill_evt);
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
}

impl Suspendable for Scmi {}
