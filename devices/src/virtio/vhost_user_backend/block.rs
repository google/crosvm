// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod sys;

use anyhow::Context;
use cros_async::Executor;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
pub use sys::start_device as run_block_device;
pub use sys::Options;
use vm_memory::GuestMemory;
use vmm_vhost::message::*;

use crate::virtio;
use crate::virtio::block::asynchronous::BlockAsync;
use crate::virtio::vhost_user_backend::handler::DeviceRequestHandler;
use crate::virtio::vhost_user_backend::handler::VhostUserDevice;
use crate::virtio::vhost_user_backend::VhostUserDeviceBuilder;
use crate::virtio::VirtioDevice;

const NUM_QUEUES: u16 = 16;

struct BlockBackend {
    inner: Box<BlockAsync>,

    avail_features: u64,
}

#[derive(Serialize, Deserialize)]
struct BlockBackendSnapshot {
    // `avail_features` don't need to be snapshotted, but they are
    // to be used to make sure that the proper features are used on `restore`.
    avail_features: u64,
}

impl VhostUserDeviceBuilder for BlockAsync {
    fn build(self: Box<Self>, _ex: &Executor) -> anyhow::Result<Box<dyn vmm_vhost::Backend>> {
        let avail_features = self.features() | 1 << VHOST_USER_F_PROTOCOL_FEATURES;
        let backend = BlockBackend {
            inner: self,
            avail_features,
        };
        let handler = DeviceRequestHandler::new(backend);
        Ok(Box::new(handler))
    }
}

impl VhostUserDevice for BlockBackend {
    fn max_queue_num(&self) -> usize {
        NUM_QUEUES as usize
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::BACKEND_REQ
            | VhostUserProtocolFeatures::DEVICE_STATE
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.inner.read_config(offset, data)
    }

    fn reset(&mut self) {
        if let Err(e) = self.inner.reset() {
            base::error!("reset failed: {:#}", e);
        }
    }

    fn start_queue(
        &mut self,
        idx: usize,
        queue: virtio::Queue,
        mem: GuestMemory,
    ) -> anyhow::Result<()> {
        self.inner.start_queue(idx, queue, mem)
    }

    fn stop_queue(&mut self, idx: usize) -> anyhow::Result<virtio::Queue> {
        self.inner.stop_queue(idx)
    }

    fn enter_suspended_state(&mut self) -> anyhow::Result<()> {
        // TODO: This assumes that `reset` only stops workers which might not be true in the
        // future. Consider moving the `reset` code into a `stop_all_workers` method or, maybe,
        // make `stop_queue` implicitly stop a worker thread when there is no active queue.
        self.inner.reset()?;
        Ok(())
    }

    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        // The queue states are being snapshotted in the device handler.
        AnySnapshot::to_any(BlockBackendSnapshot {
            avail_features: self.avail_features,
        })
        .context("Failed to serialize BlockBackendSnapshot")
    }

    fn restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        let block_backend_snapshot: BlockBackendSnapshot =
            AnySnapshot::from_any(data).context("Failed to deserialize BlockBackendSnapshot")?;
        anyhow::ensure!(
            self.avail_features == block_backend_snapshot.avail_features,
            "Vhost user block restored avail_features do not match. Live: {:?}, snapshot: {:?}",
            self.avail_features,
            block_backend_snapshot.avail_features,
        );
        Ok(())
    }
}
