// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! virtio-console and vhost-user-console device shared backend implementation

use base::RawDescriptor;
use data_model::Le32;
use hypervisor::ProtectionType;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::AsBytes;

use crate::virtio::base_features;
use crate::virtio::console::port::ConsolePort;
use crate::virtio::console::port::ConsolePortSnapshot;
use crate::virtio::console::worker::WorkerHandle;
use crate::virtio::console::worker::WorkerPort;
use crate::virtio::copy_config;
use crate::virtio::device_constants::console::virtio_console_config;
use crate::virtio::device_constants::console::VIRTIO_CONSOLE_F_MULTIPORT;
use crate::virtio::Interrupt;
use crate::virtio::Queue;

pub struct ConsoleDevice {
    avail_features: u64,
    pub(crate) ports: Vec<ConsolePort>,
    worker: Option<WorkerHandle>,
}

#[derive(Serialize, Deserialize)]
pub struct ConsoleSnapshot {
    avail_features: u64,
    ports: Vec<ConsolePortSnapshot>,
}

impl ConsoleDevice {
    /// Create a console device that does not support the multiport feature.
    pub fn new_single_port(protection_type: ProtectionType, port: ConsolePort) -> ConsoleDevice {
        ConsoleDevice {
            avail_features: base_features(protection_type),
            ports: vec![port],
            worker: None,
        }
    }

    /// Create a console device with the multiport feature enabled.
    pub fn new_multi_port(
        protection_type: ProtectionType,
        ports: Vec<ConsolePort>,
    ) -> ConsoleDevice {
        // Port 0 must always exist.
        assert!(!ports.is_empty());

        let avail_features = base_features(protection_type) | (1 << VIRTIO_CONSOLE_F_MULTIPORT);

        ConsoleDevice {
            avail_features,
            ports,
            worker: None,
        }
    }

    pub fn features(&self) -> u64 {
        self.avail_features
    }

    pub fn max_ports(&self) -> usize {
        self.ports.len()
    }

    /// Returns the maximum number of queues supported by this device.
    pub fn max_queues(&self) -> usize {
        // The port 0 receive and transmit queues always exist;
        // other queues only exist if VIRTIO_CONSOLE_F_MULTIPORT is set.
        let num_queues = self.ports.len().max(1);
        if self.avail_features & (1 << VIRTIO_CONSOLE_F_MULTIPORT) != 0 {
            // Each port has two queues (tx & rx), plus 2 for control receiveq and transmitq.
            num_queues * 2 + 2
        } else {
            // port0 receiveq + transmitq
            2
        }
    }

    pub fn read_config(&self, offset: u64, data: &mut [u8]) {
        let max_nr_ports = self.max_ports();
        let config = virtio_console_config {
            max_nr_ports: Le32::from(max_nr_ports as u32),
            ..Default::default()
        };
        copy_config(data, 0, config.as_bytes(), offset);
    }

    pub fn keep_rds(&self) -> Vec<RawDescriptor> {
        self.ports.iter().flat_map(ConsolePort::keep_rds).collect()
    }

    fn ensure_worker_started(&mut self, interrupt: Interrupt) -> &mut WorkerHandle {
        self.worker.get_or_insert_with(|| {
            let ports = self
                .ports
                .iter_mut()
                .map(WorkerPort::from_console_port)
                .collect();
            WorkerHandle::new(interrupt, ports).expect("failed to create console worker")
        })
    }

    fn ensure_worker_stopped(&mut self) {
        if let Some(mut worker) = self.worker.take() {
            worker.stop();
        }
    }

    pub fn start_queue(
        &mut self,
        idx: usize,
        queue: Queue,
        interrupt: Interrupt,
    ) -> anyhow::Result<()> {
        let worker = self.ensure_worker_started(interrupt);
        worker.start_queue(idx, queue)
    }

    pub fn stop_queue(&mut self, idx: usize) -> anyhow::Result<Option<Queue>> {
        match self.worker.as_mut() {
            Some(worker) => worker.stop_queue(idx),
            None => Ok(None),
        }
    }

    pub fn reset(&mut self) -> anyhow::Result<()> {
        for idx in 0..self.max_queues() {
            let _ = self.stop_queue(idx);
        }
        self.ensure_worker_stopped();
        Ok(())
    }

    pub fn start_input_threads(&mut self) {
        for port in self.ports.iter_mut() {
            port.start_input_thread();
        }
    }

    pub fn stop_input_threads(&mut self) {
        for port in self.ports.iter_mut() {
            port.stop_input_thread();
        }
    }

    pub fn snapshot(&mut self) -> anyhow::Result<ConsoleSnapshot> {
        let mut ports = Vec::new();
        for port in &mut self.ports {
            ports.push(port.snapshot());
        }

        Ok(ConsoleSnapshot {
            avail_features: self.avail_features,
            ports,
        })
    }

    pub fn restore(&mut self, snap: &ConsoleSnapshot) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.avail_features == snap.avail_features,
            "Virtio console incorrect features for restore: Expected: {}, Actual: {}",
            self.avail_features,
            snap.avail_features,
        );

        for (port, port_snap) in self.ports.iter_mut().zip(snap.ports.iter()) {
            port.restore(port_snap);
        }

        Ok(())
    }
}
