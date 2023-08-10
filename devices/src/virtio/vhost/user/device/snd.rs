// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod sys;

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
use hypervisor::ProtectionType;
use once_cell::sync::OnceCell;
pub use sys::run_snd_device;
pub use sys::Options;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserVirtioFeatures;
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
use crate::virtio::snd::common_backend::Error;
use crate::virtio::snd::common_backend::PcmResponse;
use crate::virtio::snd::common_backend::SndData;
use crate::virtio::snd::common_backend::MAX_QUEUE_NUM;
use crate::virtio::snd::parameters::Parameters;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::handler::Error as DeviceError;
use crate::virtio::vhost::user::device::handler::VhostUserBackend;
use crate::virtio::vhost::user::device::handler::WorkerState;
use crate::virtio::vhost::user::VhostUserDevice;
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

impl SndBackend {
    pub fn new(params: Parameters) -> anyhow::Result<Self> {
        let cfg = hardcoded_virtio_snd_config(&params);
        let avail_features = virtio::base_features(ProtectionType::Unprotected)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

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

impl VhostUserDevice for SndBackend {
    fn max_queue_num(&self) -> usize {
        MAX_QUEUE_NUM
    }

    fn into_req_handler(
        self: Box<Self>,
        ops: Box<dyn super::handler::VhostUserPlatformOps>,
        _ex: &Executor,
    ) -> anyhow::Result<Box<dyn vmm_vhost::VhostUserSlaveReqHandler>> {
        let handler = DeviceRequestHandler::new(self, ops);
        Ok(Box::new(std::sync::Mutex::new(handler)))
    }
}

impl VhostUserBackend for SndBackend {
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
            1 => None, // TODO(woodychow): Add event queue support
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
        if let Some(worker) = self.workers.get_mut(idx).and_then(Option::take) {
            // Wait for queue_task to be aborted.
            let _ = ex.run_until(worker.queue_task.cancel());
        }
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
        if let Some(worker) = self.workers.get_mut(idx).and_then(Option::take) {
            let queue = match Rc::try_unwrap(worker.queue) {
                Ok(queue_mutex) => queue_mutex.into_inner(),
                Err(_) => panic!("failed to recover queue from worker"),
            };

            Ok(queue)
        } else {
            Err(anyhow::Error::new(DeviceError::WorkerNotFound))
        }
    }
}
