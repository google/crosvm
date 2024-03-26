// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod sys;

use std::borrow::Borrow;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use base::error;
use base::warn;
use cros_async::sync::RwLock as AsyncRwLock;
use cros_async::EventAsync;
use cros_async::Executor;
use futures::channel::mpsc;
use futures::FutureExt;
use hypervisor::ProtectionType;
use once_cell::sync::OnceCell;
use serde::Deserialize;
use serde::Serialize;
pub use sys::run_snd_device;
pub use sys::Options;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;
use zerocopy::AsBytes;

use crate::virtio;
use crate::virtio::copy_config;
use crate::virtio::device_constants::snd::virtio_snd_config;
use crate::virtio::snd::common_backend::async_funcs::handle_ctrl_queue;
use crate::virtio::snd::common_backend::async_funcs::handle_pcm_queue;
use crate::virtio::snd::common_backend::async_funcs::send_pcm_response_worker;
use crate::virtio::snd::common_backend::create_stream_info_builders;
use crate::virtio::snd::common_backend::hardcoded_snd_data;
use crate::virtio::snd::common_backend::hardcoded_virtio_snd_config;
use crate::virtio::snd::common_backend::stream_info::StreamInfo;
use crate::virtio::snd::common_backend::stream_info::StreamInfoBuilder;
use crate::virtio::snd::common_backend::stream_info::StreamInfoSnapshot;
use crate::virtio::snd::common_backend::Error;
use crate::virtio::snd::common_backend::PcmResponse;
use crate::virtio::snd::common_backend::SndData;
use crate::virtio::snd::common_backend::MAX_QUEUE_NUM;
use crate::virtio::snd::constants::VIRTIO_SND_R_PCM_PREPARE;
use crate::virtio::snd::constants::VIRTIO_SND_R_PCM_START;
use crate::virtio::snd::parameters::Parameters;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::handler::Error as DeviceError;
use crate::virtio::vhost::user::device::handler::VhostUserDevice;
use crate::virtio::vhost::user::device::handler::WorkerState;
use crate::virtio::vhost::user::VhostUserDeviceBuilder;
use crate::virtio::Interrupt;
use crate::virtio::Queue;

static SND_EXECUTOR: OnceCell<Executor> = OnceCell::new();

// Async workers:
// 0 - ctrl
// 1 - event
// 2 - tx
// 3 - rx
const PCM_RESPONSE_WORKER_IDX_OFFSET: usize = 2;
struct SndBackend {
    cfg: virtio_snd_config,
    avail_features: u64,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
    workers: [Option<WorkerState<Rc<AsyncRwLock<Queue>>, Result<(), Error>>>; MAX_QUEUE_NUM],
    // tx and rx
    response_workers: [Option<WorkerState<Rc<AsyncRwLock<Queue>>, Result<(), Error>>>; 2],
    snd_data: Rc<SndData>,
    streams: Rc<AsyncRwLock<Vec<AsyncRwLock<StreamInfo>>>>,
    tx_send: mpsc::UnboundedSender<PcmResponse>,
    rx_send: mpsc::UnboundedSender<PcmResponse>,
    tx_recv: Option<mpsc::UnboundedReceiver<PcmResponse>>,
    rx_recv: Option<mpsc::UnboundedReceiver<PcmResponse>>,
}

#[derive(Serialize, Deserialize)]
struct SndBackendSnapshot {
    avail_features: u64,
    acked_features: u64,
    acked_protocol_features: u64,
    stream_infos: Option<Vec<StreamInfoSnapshot>>,
    snd_data: SndData,
}

impl SndBackend {
    pub fn new(params: Parameters) -> anyhow::Result<Self> {
        let cfg = hardcoded_virtio_snd_config(&params);
        let avail_features = virtio::base_features(ProtectionType::Unprotected)
            | 1 << VHOST_USER_F_PROTOCOL_FEATURES;

        let snd_data = hardcoded_snd_data(&params);
        let mut keep_rds = Vec::new();
        let builders = create_stream_info_builders(&params, &snd_data, &mut keep_rds)?;

        if snd_data.pcm_info_len() != builders.len() {
            error!(
                "snd: expected {} stream info builders, got {}",
                snd_data.pcm_info_len(),
                builders.len(),
            )
        }

        let streams = builders
            .into_iter()
            .map(StreamInfoBuilder::build)
            .map(AsyncRwLock::new)
            .collect();
        let streams = Rc::new(AsyncRwLock::new(streams));

        let (tx_send, tx_recv) = mpsc::unbounded();
        let (rx_send, rx_recv) = mpsc::unbounded();

        Ok(SndBackend {
            cfg,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            workers: Default::default(),
            response_workers: Default::default(),
            snd_data: Rc::new(snd_data),
            streams,
            tx_send,
            rx_send,
            tx_recv: Some(tx_recv),
            rx_recv: Some(rx_recv),
        })
    }
}

impl VhostUserDeviceBuilder for SndBackend {
    fn build(self: Box<Self>, _ex: &Executor) -> anyhow::Result<Box<dyn vmm_vhost::Backend>> {
        let handler = DeviceRequestHandler::new(*self);
        Ok(Box::new(handler))
    }
}

impl VhostUserDevice for SndBackend {
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

        Ok(())
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::MQ
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
        copy_config(data, 0, self.cfg.as_bytes(), offset)
    }

    fn reset(&mut self) {
        let ex = SND_EXECUTOR.get().expect("Executor not initialized");
        for worker in self.workers.iter_mut().filter_map(Option::take) {
            let _ = ex.run_until(worker.queue_task.cancel());
        }
    }

    fn start_queue(
        &mut self,
        idx: usize,
        queue: virtio::Queue,
        _mem: GuestMemory,
        doorbell: Interrupt,
    ) -> anyhow::Result<()> {
        if self.workers[idx].is_some() {
            warn!("Starting new queue handler without stopping old handler");
            self.stop_queue(idx)?;
        }

        // Safe because the executor is initialized in main() below.
        let ex = SND_EXECUTOR.get().expect("Executor not initialized");

        let kick_evt = queue
            .event()
            .try_clone()
            .context("failed to clone queue event")?;
        let mut kick_evt =
            EventAsync::new(kick_evt, ex).context("failed to create EventAsync for kick_evt")?;
        let queue = Rc::new(AsyncRwLock::new(queue));
        let queue_task = match idx {
            0 => {
                // ctrl queue
                let streams = self.streams.clone();
                let snd_data = self.snd_data.clone();
                let tx_send = self.tx_send.clone();
                let rx_send = self.rx_send.clone();
                let ctrl_queue = queue.clone();
                Some(ex.spawn_local(async move {
                    handle_ctrl_queue(
                        ex,
                        &streams,
                        &snd_data,
                        ctrl_queue,
                        &mut kick_evt,
                        doorbell,
                        tx_send,
                        rx_send,
                        None,
                    )
                    .await
                }))
            }
            // TODO(woodychow): Add event queue support
            //
            // Note: Even though we don't support the event queue, we still need to keep track of
            // the Queue so we can return it back in stop_queue. As such, we create a do nothing
            // future to "run" this queue so that we track a WorkerState for it (which is how
            // we return the Queue back).
            1 => Some(ex.spawn_local(async move { Ok(()) })),
            2 | 3 => {
                let (send, recv) = if idx == 2 {
                    (self.tx_send.clone(), self.tx_recv.take())
                } else {
                    (self.rx_send.clone(), self.rx_recv.take())
                };
                let mut recv = recv.ok_or_else(|| anyhow!("queue restart is not supported"))?;
                let streams = Rc::clone(&self.streams);
                let queue_pcm_queue = queue.clone();
                let queue_task = ex.spawn_local(async move {
                    handle_pcm_queue(&streams, send, queue_pcm_queue, &kick_evt, None).await
                });

                let queue_response_queue = queue.clone();
                let response_queue_task = ex.spawn_local(async move {
                    send_pcm_response_worker(queue_response_queue, doorbell, &mut recv, None).await
                });

                self.response_workers[idx - PCM_RESPONSE_WORKER_IDX_OFFSET] = Some(WorkerState {
                    queue_task: response_queue_task,
                    queue: queue.clone(),
                });

                Some(queue_task)
            }
            _ => bail!("attempted to start unknown queue: {}", idx),
        };

        if let Some(queue_task) = queue_task {
            self.workers[idx] = Some(WorkerState { queue_task, queue });
        }
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) -> anyhow::Result<virtio::Queue> {
        let ex = SND_EXECUTOR.get().expect("Executor not initialized");
        let worker_queue_rc = self
            .workers
            .get_mut(idx)
            .and_then(Option::take)
            .map(|worker| {
                // Wait for queue_task to be aborted.
                let _ = ex.run_until(worker.queue_task.cancel());
                worker.queue
            });

        if idx == 2 || idx == 3 {
            if let Some(worker) = self
                .response_workers
                .get_mut(idx - PCM_RESPONSE_WORKER_IDX_OFFSET)
                .and_then(Option::take)
            {
                // Wait for queue_task to be aborted.
                let _ = ex.run_until(worker.queue_task.cancel());
            }
        }

        if let Some(queue_rc) = worker_queue_rc {
            match Rc::try_unwrap(queue_rc) {
                Ok(queue_mutex) => Ok(queue_mutex.into_inner()),
                Err(_) => panic!("failed to recover queue from worker"),
            }
        } else {
            Err(anyhow::Error::new(DeviceError::WorkerNotFound))
        }
    }

    fn snapshot(&self) -> anyhow::Result<Vec<u8>> {
        // now_or_never will succeed here because no workers are running.
        let stream_info_snaps = if let Some(stream_infos) = &self.streams.lock().now_or_never() {
            let mut snaps = Vec::new();
            for stream_info in stream_infos.iter() {
                snaps.push(
                    stream_info
                        .lock()
                        .now_or_never()
                        .expect("failed to lock audio state during snapshot")
                        .snapshot(),
                );
            }
            Some(snaps)
        } else {
            None
        };
        let snd_data_ref: &SndData = self.snd_data.borrow();
        serde_json::to_vec(&SndBackendSnapshot {
            avail_features: self.avail_features,
            acked_protocol_features: self.acked_protocol_features.bits(),
            acked_features: self.acked_features,
            stream_infos: stream_info_snaps,
            snd_data: snd_data_ref.clone(),
        })
        .context("Failed to serialize SndBackendSnapshot")
    }

    fn restore(&mut self, data: Vec<u8>) -> anyhow::Result<()> {
        let deser: SndBackendSnapshot = serde_json::from_slice(data.as_slice())
            .context("Failed to deserialize SndBackendSnapshot")?;
        anyhow::ensure!(
            deser.avail_features == self.avail_features,
            "avail features doesn't match on restore: expected: {}, got: {}",
            deser.avail_features,
            self.avail_features
        );
        anyhow::ensure!(
            self.acked_protocol_features.bits() == deser.acked_protocol_features,
            "Vhost user snd restored acked_protocol_features do not match. Live: {:?}, \
            snapshot: {:?}",
            self.acked_protocol_features,
            deser.acked_protocol_features,
        );
        let snd_data = self.snd_data.borrow();
        anyhow::ensure!(
            &deser.snd_data == snd_data,
            "snd data doesn't match on restore: expected: {:?}, got: {:?}",
            deser.snd_data,
            snd_data,
        );
        self.acked_features = deser.acked_features;

        // Wondering why we can pass ex to a move block *and* still use it
        // afterwards? It's a &'static, which is the only kind of reference that
        // can taken by a future run via spawn/spawn_local.
        let ex = SND_EXECUTOR.get().expect("executor must be initialized");
        let streams_rc = self.streams.clone();
        let tx_send_clone = self.tx_send.clone();
        let rx_send_clone = self.rx_send.clone();

        let restore_task = ex.spawn_local(async move {
            if let Some(stream_infos) = &deser.stream_infos {
                for (stream, stream_info) in streams_rc.lock().await.iter().zip(stream_infos.iter())
                {
                    stream.lock().await.restore(stream_info);
                    if stream_info.state == VIRTIO_SND_R_PCM_START
                        || stream_info.state == VIRTIO_SND_R_PCM_PREPARE
                    {
                        stream
                            .lock()
                            .await
                            .prepare(ex, &tx_send_clone, &rx_send_clone)
                            .await
                            .expect("failed to prepare PCM");
                    }
                    if stream_info.state == VIRTIO_SND_R_PCM_START {
                        stream
                            .lock()
                            .await
                            .start()
                            .await
                            .expect("failed to start PCM");
                    }
                }
            }
        });
        ex.run_until(restore_task)
            .expect("failed to restore streams");
        Ok(())
    }

    fn stop_non_queue_workers(&mut self) -> anyhow::Result<()> {
        // This device has no non-queue workers to stop.
        Ok(())
    }
}
