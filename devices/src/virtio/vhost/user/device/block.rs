// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod sys;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use cros_async::Executor;
use serde::Deserialize;
use serde::Serialize;
pub use sys::start_device as run_block_device;
pub use sys::Options;
use vm_memory::GuestMemory;
use vmm_vhost::message::*;

use crate::virtio;
use crate::virtio::block::asynchronous::BlockAsync;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::handler::VhostUserBackend;
use crate::virtio::vhost::user::device::VhostUserDevice;
use crate::virtio::Interrupt;
use crate::virtio::VirtioDevice;

const NUM_QUEUES: u16 = 16;

struct BlockBackend {
    inner: Box<BlockAsync>,

    avail_features: u64,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
}

#[derive(Serialize, Deserialize)]
struct BlockBackendSnapshot {
    acked_features: u64,
    // `avail_features` and `acked_protocol_features` don't need to be snapshotted, but they are
    // to be used to make sure that the proper features are used on `restore`.
    avail_features: u64,
    acked_protocol_features: u64,
}

impl VhostUserDevice for BlockAsync {
    fn max_queue_num(&self) -> usize {
        NUM_QUEUES as usize
    }

    fn into_req_handler(
        self: Box<Self>,
        _ex: &Executor,
    ) -> anyhow::Result<Box<dyn vmm_vhost::Backend>> {
        let avail_features = self.features() | 1 << VHOST_USER_F_PROTOCOL_FEATURES;
        let backend = BlockBackend {
            inner: self,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
        };
        let handler = DeviceRequestHandler::new(Box::new(backend));
        Ok(Box::new(handler))
    }
}

impl VhostUserBackend for BlockBackend {
    fn max_queue_num(&self) -> usize {
        NUM_QUEUES as usize
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, value: u64) -> anyhow::Result<()> {
        let unrequested_features = value & !self.avail_features;
        if unrequested_features != 0 {
            bail!("invalid features are given: {:#x}", unrequested_features);
        }

        self.acked_features |= value;

        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::SLAVE_REQ
    }

    fn ack_protocol_features(&mut self, features: u64) -> anyhow::Result<()> {
        let features = VhostUserProtocolFeatures::from_bits(features)
            .ok_or_else(|| anyhow!("invalid protocol features are given: {:#x}", features))?;
        let supported = self.protocol_features();
        self.acked_protocol_features = features & supported;
        Ok(())
    }

    fn acked_protocol_features(&self) -> u64 {
        self.acked_protocol_features.bits()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.inner.read_config(offset, data)
    }

    fn reset(&mut self) {
        self.inner.reset();
    }

    fn start_queue(
        &mut self,
        idx: usize,
        queue: virtio::Queue,
        mem: GuestMemory,
        doorbell: Interrupt,
    ) -> anyhow::Result<()> {
        self.inner.start_queue(idx, queue, mem, doorbell)
    }

    fn stop_queue(&mut self, idx: usize) -> anyhow::Result<virtio::Queue> {
        self.inner.stop_queue(idx)
    }

    fn stop_non_queue_workers(&mut self) -> anyhow::Result<()> {
        // TODO: This assumes that `reset` only stops workers which might not be true in the
        // future. Consider moving the `reset` code into a `stop_all_workers` method or, maybe,
        // make `stop_queue` implicitly stop a worker thread when there is no active queue.
        self.inner.reset();
        Ok(())
    }

    fn snapshot(&self) -> anyhow::Result<Vec<u8>> {
        // The queue states are being snapshotted in the device handler.
        let serialized_bytes = serde_json::to_vec(&BlockBackendSnapshot {
            acked_features: self.acked_features,
            avail_features: self.avail_features,
            acked_protocol_features: self.acked_protocol_features.bits(),
        })
        .context("Failed to serialize BlockBackendSnapshot")?;

        Ok(serialized_bytes)
    }

    fn restore(&mut self, data: Vec<u8>) -> anyhow::Result<()> {
        let block_backend_snapshot: BlockBackendSnapshot =
            serde_json::from_slice(&data).context("Failed to deserialize BlockBackendSnapshot")?;
        anyhow::ensure!(
            self.avail_features == block_backend_snapshot.avail_features,
            "Vhost user block restored avail_features do not match. Live: {:?}, snapshot: {:?}",
            self.avail_features,
            block_backend_snapshot.avail_features,
        );
        anyhow::ensure!(
            self.acked_protocol_features.bits() == block_backend_snapshot.acked_protocol_features,
            "Vhost user block restored acked_protocol_features do not match. Live: {:?}, \
            snapshot: {:?}",
            self.acked_protocol_features,
            block_backend_snapshot.acked_protocol_features
        );
        self.acked_features = block_backend_snapshot.acked_features;
        Ok(())
    }
}
