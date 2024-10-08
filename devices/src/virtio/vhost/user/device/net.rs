// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod sys;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::AsRawDescriptors;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::IntoAsync;
use cros_async::TaskHandle;
use futures::channel::oneshot;
use futures::pin_mut;
use futures::select_biased;
use futures::FutureExt;
use net_util::TapT;
use once_cell::sync::OnceCell;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
pub use sys::start_device as run_net_device;
pub use sys::Options;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use zerocopy::IntoBytes;

use crate::virtio;
use crate::virtio::net::build_config;
use crate::virtio::net::process_ctrl;
use crate::virtio::net::process_tx;
use crate::virtio::net::virtio_features_to_tap_offload;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::handler::Error as DeviceError;
use crate::virtio::vhost::user::device::handler::VhostUserDevice;
use crate::virtio::vhost::user::VhostUserDeviceBuilder;
use crate::virtio::Queue;

thread_local! {
    pub(crate) static NET_EXECUTOR: OnceCell<Executor> = const { OnceCell::new() };
}

// TODO(b/188947559): Come up with better way to include these constants. Compiler errors happen
// if they are kept in the trait.
const MAX_QUEUE_NUM: usize = 3; /* rx, tx, ctrl */

async fn run_tx_queue<T: TapT>(
    mut queue: Queue,
    mut tap: T,
    kick_evt: EventAsync,
    mut stop_rx: oneshot::Receiver<()>,
) -> Queue {
    let kick_evt_future = kick_evt.next_val().fuse();
    pin_mut!(kick_evt_future);
    loop {
        select_biased! {
            kick = kick_evt_future => {
                kick_evt_future.set(kick_evt.next_val().fuse());
                if let Err(e) = kick {
                    error!("Failed to read kick event for tx queue: {}", e);
                    break;
                }
            }
            _ = stop_rx => {
                break;
            }
        }

        process_tx(&mut queue, &mut tap);
    }
    queue
}

async fn run_ctrl_queue<T: TapT>(
    mut queue: Queue,
    mut tap: T,
    kick_evt: EventAsync,
    acked_features: u64,
    vq_pairs: u16,
    mut stop_rx: oneshot::Receiver<()>,
) -> Queue {
    let kick_evt_future = kick_evt.next_val().fuse();
    pin_mut!(kick_evt_future);
    loop {
        select_biased! {
            kick = kick_evt_future => {
                kick_evt_future.set(kick_evt.next_val().fuse());
                if let Err(e) = kick {
                    error!("Failed to read kick event for tx queue: {}", e);
                    break;
                }
            }
            _ = stop_rx => {
                break;
            }
        }

        if let Err(e) = process_ctrl(&mut queue, &mut tap, acked_features, vq_pairs) {
            error!("Failed to process ctrl queue: {}", e);
            break;
        }
    }
    queue
}

pub struct NetBackend<T: TapT + IntoAsync> {
    tap: T,
    avail_features: u64,
    acked_features: u64,
    mtu: u16,
    #[cfg(all(windows, feature = "slirp"))]
    slirp_kill_event: base::Event,
    workers: [Option<(TaskHandle<Queue>, oneshot::Sender<()>)>; MAX_QUEUE_NUM],
}

#[derive(Serialize, Deserialize)]
pub struct NetBackendSnapshot {
    acked_feature: u64,
}

impl<T: 'static> NetBackend<T>
where
    T: TapT + IntoAsync,
{
    fn max_vq_pairs() -> usize {
        MAX_QUEUE_NUM / 2
    }
}

impl<T: 'static> AsRawDescriptors for NetBackend<T>
where
    T: TapT + IntoAsync + AsRawDescriptors,
{
    fn as_raw_descriptors(&self) -> Vec<base::RawDescriptor> {
        self.tap.as_raw_descriptors()
    }
}

impl<T: 'static> VhostUserDevice for NetBackend<T>
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
        self.acked_features |= value;

        self.tap
            .set_offload(virtio_features_to_tap_offload(self.acked_features))
            .context("failed to set tap offload to match features")?;

        Ok(())
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::DEVICE_STATE
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
    ) -> anyhow::Result<()> {
        sys::start_queue(self, idx, queue, mem)
    }

    fn stop_queue(&mut self, idx: usize) -> anyhow::Result<virtio::Queue> {
        if let Some((task, stop_tx)) = self.workers.get_mut(idx).and_then(Option::take) {
            if stop_tx.send(()).is_err() {
                return Err(anyhow!("Failed to request stop for net queue future"));
            }

            // Wait for queue_task to be aborted.
            let queue = NET_EXECUTOR
                .with(|ex| {
                    let ex = ex.get().expect("Executor not initialized");
                    ex.run_until(task)
                })
                .context("Failed to resolve queue worker future")?;

            Ok(queue)
        } else {
            Err(anyhow::Error::new(DeviceError::WorkerNotFound))
        }
    }

    fn enter_suspended_state(&mut self) -> anyhow::Result<()> {
        // No non-queue workers.
        Ok(())
    }

    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        AnySnapshot::to_any(NetBackendSnapshot {
            acked_feature: self.acked_features,
        })
        .context("Failed to serialize NetBackendSnapshot")
    }

    fn restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        let net_backend_snapshot: NetBackendSnapshot =
            AnySnapshot::from_any(data).context("Failed to deserialize NetBackendSnapshot")?;
        self.acked_features = net_backend_snapshot.acked_feature;
        Ok(())
    }
}

impl<T> VhostUserDeviceBuilder for NetBackend<T>
where
    T: TapT + IntoAsync + 'static,
{
    fn build(self: Box<Self>, ex: &Executor) -> anyhow::Result<Box<dyn vmm_vhost::Backend>> {
        NET_EXECUTOR.with(|thread_ex| {
            let _ = thread_ex.set(ex.clone());
        });
        let handler = DeviceRequestHandler::new(*self);

        Ok(Box::new(handler))
    }
}
