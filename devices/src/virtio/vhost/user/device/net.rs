// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod sys;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use base::error;
use base::Event;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::IntoAsync;
use futures::future::AbortHandle;
use net_util::TapT;
use once_cell::sync::OnceCell;
pub use sys::start_device as run_net_device;
pub use sys::Options;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use zerocopy::AsBytes;

use crate::virtio;
use crate::virtio::net::build_config;
use crate::virtio::net::process_ctrl;
use crate::virtio::net::process_tx;
use crate::virtio::net::virtio_features_to_tap_offload;
use crate::virtio::vhost::user::device::handler::sys::Doorbell;
use crate::virtio::vhost::user::device::handler::VhostUserBackend;

thread_local! {
    pub(crate) static NET_EXECUTOR: OnceCell<Executor> = OnceCell::new();
}

// TODO(b/188947559): Come up with better way to include these constants. Compiler errors happen
// if they are kept in the trait.
const MAX_QUEUE_NUM: usize = 3; /* rx, tx, ctrl */

async fn run_tx_queue<T: TapT>(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    mut tap: T,
    doorbell: Doorbell,
    kick_evt: EventAsync,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for tx queue: {}", e);
            break;
        }

        process_tx(&doorbell, &mut queue, &mem, &mut tap);
    }
}

async fn run_ctrl_queue<T: TapT>(
    mut queue: virtio::Queue,
    mem: GuestMemory,
    mut tap: T,
    doorbell: Doorbell,
    kick_evt: EventAsync,
    acked_features: u64,
    vq_pairs: u16,
) {
    loop {
        if let Err(e) = kick_evt.next_val().await {
            error!("Failed to read kick event for tx queue: {}", e);
            break;
        }

        if let Err(e) = process_ctrl(
            &doorbell,
            &mut queue,
            &mem,
            &mut tap,
            acked_features,
            vq_pairs,
        ) {
            error!("Failed to process ctrl queue: {}", e);
            break;
        }
    }
}

pub(crate) struct NetBackend<T: TapT + IntoAsync> {
    tap: T,
    avail_features: u64,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
    workers: [Option<AbortHandle>; MAX_QUEUE_NUM],
    mtu: u16,
    #[cfg(all(windows, feature = "slirp"))]
    slirp_kill_event: Event,
}

impl<T: 'static> NetBackend<T>
where
    T: TapT + IntoAsync,
{
    fn max_vq_pairs() -> usize {
        MAX_QUEUE_NUM / 2
    }
}

impl<T: 'static> VhostUserBackend for NetBackend<T>
where
    T: TapT + IntoAsync,
{
    fn max_queue_num(&self) -> usize {
        MAX_QUEUE_NUM
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

        self.tap
            .set_offload(virtio_features_to_tap_offload(self.acked_features))
            .context("failed to set tap offload to match features")?;

        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
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
        let config_space = build_config(Self::max_vq_pairs() as u16, self.mtu, None);
        virtio::copy_config(data, 0, config_space.as_bytes(), offset);
    }

    fn reset(&mut self) {}

    fn start_queue(
        &mut self,
        idx: usize,
        queue: virtio::Queue,
        mem: GuestMemory,
        doorbell: Doorbell,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
        sys::start_queue(self, idx, queue, mem, doorbell, kick_evt)
    }

    fn stop_queue(&mut self, idx: usize) {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            handle.abort();
        }
    }
}
