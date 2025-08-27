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
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
pub use sys::run_snd_device;
pub use sys::Options;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;
use zerocopy::IntoBytes;

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
use crate::virtio::Queue;

// Async workers:
// 0 - ctrl
// 1 - event
// 2 - tx
// 3 - rx
const PCM_RESPONSE_WORKER_IDX_OFFSET: usize = 2;
struct SndBackend {
    ex: Executor,
    cfg: virtio_snd_config,
    avail_features: u64,
    workers: [Option<WorkerState<Rc<AsyncRwLock<Queue>>, Result<(), Error>>>; MAX_QUEUE_NUM],
    // tx and rx
    response_workers: [Option<WorkerState<Rc<AsyncRwLock<Queue>>, Result<(), Error>>>; 2],
    snd_data: Rc<SndData>,
    streams: Rc<AsyncRwLock<Vec<AsyncRwLock<StreamInfo>>>>,
    tx_send: mpsc::UnboundedSender<PcmResponse>,
    rx_send: mpsc::UnboundedSender<PcmResponse>,
    tx_recv: Option<mpsc::UnboundedReceiver<PcmResponse>>,
    rx_recv: Option<mpsc::UnboundedReceiver<PcmResponse>>,
    // Appended to logs for when there are mutliple audio devices.
    card_index: usize,
}

#[derive(Serialize, Deserialize)]
struct SndBackendSnapshot {
    avail_features: u64,
    stream_infos: Option<Vec<StreamInfoSnapshot>>,
    snd_data: SndData,
}

impl SndBackend {
    pub fn new(
        ex: &Executor,
        params: Parameters,
        #[cfg(windows)] audio_client_guid: Option<String>,
        card_index: usize,
    ) -> anyhow::Result<Self> {
        let cfg = hardcoded_virtio_snd_config(&params);
        let avail_features = virtio::base_features(ProtectionType::Unprotected)
            | 1 << VHOST_USER_F_PROTOCOL_FEATURES;

        let snd_data = hardcoded_snd_data(&params);
        let mut keep_rds = Vec::new();
        let builders = create_stream_info_builders(&params, &snd_data, &mut keep_rds, card_index)?;

        if snd_data.pcm_info_len() != builders.len() {
            error!(
                "[Card {}] snd: expected {} stream info builders, got {}",
                card_index,
                snd_data.pcm_info_len(),
                builders.len(),
            )
        }

        let streams = builders.into_iter();

        #[cfg(windows)]
        let streams = streams
            .map(|stream_builder| stream_builder.audio_client_guid(audio_client_guid.clone()));

        let streams = streams
            .map(StreamInfoBuilder::build)
            .map(AsyncRwLock::new)
            .collect();
        let streams = Rc::new(AsyncRwLock::new(streams));

        let (tx_send, tx_recv) = mpsc::unbounded();
        let (rx_send, rx_recv) = mpsc::unbounded();

        Ok(SndBackend {
            ex: ex.clone(),
            cfg,
            avail_features,
            workers: Default::default(),
            response_workers: Default::default(),
            snd_data: Rc::new(snd_data),
            streams,
            tx_send,
            rx_send,
            tx_recv: Some(tx_recv),
            rx_recv: Some(rx_recv),
            card_index,
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

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::DEVICE_STATE
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.cfg.as_bytes(), offset)
    }

    fn reset(&mut self) {
        for worker in self.workers.iter_mut().filter_map(Option::take) {
            let _ = self.ex.run_until(worker.queue_task.cancel());
        }
    }

    fn start_queue(
        &mut self,
        idx: usize,
        queue: virtio::Queue,
        _mem: GuestMemory,
    ) -> anyhow::Result<()> {
        if self.workers[idx].is_some() {
            warn!(
                "[Card {}] Starting new queue handler without stopping old handler",
                self.card_index
            );
            self.stop_queue(idx)?;
        }

        let kick_evt = queue
            .event()
            .try_clone()
            .with_context(|| format!("[Card {}] failed to clone queue event", self.card_index))?;
        let mut kick_evt = EventAsync::new(kick_evt, &self.ex).with_context(|| {
            format!(
                "[Card {}] failed to create EventAsync for kick_evt",
                self.card_index
            )
        })?;
        let queue = Rc::new(AsyncRwLock::new(queue));
        let card_index = self.card_index;
        let queue_task = match idx {
            0 => {
                // ctrl queue
                let streams = self.streams.clone();
                let snd_data = self.snd_data.clone();
                let tx_send = self.tx_send.clone();
                let rx_send = self.rx_send.clone();
                let ctrl_queue = queue.clone();

                let ex_clone = self.ex.clone();
                Some(self.ex.spawn_local(async move {
                    handle_ctrl_queue(
                        &ex_clone,
                        &streams,
                        &snd_data,
                        ctrl_queue,
                        &mut kick_evt,
                        tx_send,
                        rx_send,
                        card_index,
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
            1 => Some(self.ex.spawn_local(async move { Ok(()) })),
            2 | 3 => {
                let (send, recv) = if idx == 2 {
                    (self.tx_send.clone(), self.tx_recv.take())
                } else {
                    (self.rx_send.clone(), self.rx_recv.take())
                };
                let mut recv = recv.ok_or_else(|| {
                    anyhow!("[Card {}] queue restart is not supported", self.card_index)
                })?;
                let streams = Rc::clone(&self.streams);
                let queue_pcm_queue = queue.clone();
                let queue_task = self.ex.spawn_local(async move {
                    handle_pcm_queue(&streams, send, queue_pcm_queue, &kick_evt, card_index, None)
                        .await
                });

                let queue_response_queue = queue.clone();
                let response_queue_task = self.ex.spawn_local(async move {
                    send_pcm_response_worker(queue_response_queue, &mut recv, None).await
                });

                self.response_workers[idx - PCM_RESPONSE_WORKER_IDX_OFFSET] = Some(WorkerState {
                    queue_task: response_queue_task,
                    queue: queue.clone(),
                });

                Some(queue_task)
            }
            _ => bail!(
                "[Card {}] attempted to start unknown queue: {}",
                self.card_index,
                idx
            ),
        };

        if let Some(queue_task) = queue_task {
            self.workers[idx] = Some(WorkerState { queue_task, queue });
        }
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) -> anyhow::Result<virtio::Queue> {
        let worker_queue_rc = self
            .workers
            .get_mut(idx)
            .and_then(Option::take)
            .map(|worker| {
                // Wait for queue_task to be aborted.
                let _ = self.ex.run_until(worker.queue_task.cancel());
                worker.queue
            });

        if idx == 2 || idx == 3 {
            if let Some(worker) = self
                .response_workers
                .get_mut(idx - PCM_RESPONSE_WORKER_IDX_OFFSET)
                .and_then(Option::take)
            {
                // Wait for queue_task to be aborted.
                let _ = self.ex.run_until(worker.queue_task.cancel());
            }
        }

        if let Some(queue_rc) = worker_queue_rc {
            match Rc::try_unwrap(queue_rc) {
                Ok(queue_mutex) => Ok(queue_mutex.into_inner()),
                Err(_) => panic!(
                    "[Card {}] failed to recover queue from worker",
                    self.card_index
                ),
            }
        } else {
            Err(anyhow::Error::new(DeviceError::WorkerNotFound))
        }
    }

    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        // now_or_never will succeed here because no workers are running.
        let stream_info_snaps = if let Some(stream_infos) = &self.streams.lock().now_or_never() {
            let mut snaps = Vec::new();
            for stream_info in stream_infos.iter() {
                snaps.push(
                    stream_info
                        .lock()
                        .now_or_never()
                        .unwrap_or_else(|| {
                            panic!(
                                "[Card {}] failed to lock audio state during snapshot",
                                self.card_index
                            )
                        })
                        .snapshot(),
                );
            }
            Some(snaps)
        } else {
            None
        };
        let snd_data_ref: &SndData = self.snd_data.borrow();
        AnySnapshot::to_any(SndBackendSnapshot {
            avail_features: self.avail_features,
            stream_infos: stream_info_snaps,
            snd_data: snd_data_ref.clone(),
        })
        .with_context(|| {
            format!(
                "[Card {}] Failed to serialize SndBackendSnapshot",
                self.card_index
            )
        })
    }

    fn restore(&mut self, data: AnySnapshot) -> anyhow::Result<()> {
        let deser: SndBackendSnapshot = AnySnapshot::from_any(data).with_context(|| {
            format!(
                "[Card {}] Failed to deserialize SndBackendSnapshot",
                self.card_index
            )
        })?;
        anyhow::ensure!(
            deser.avail_features == self.avail_features,
            "[Card {}] avail features doesn't match on restore: expected: {}, got: {}",
            self.card_index,
            deser.avail_features,
            self.avail_features
        );
        let snd_data = self.snd_data.borrow();
        anyhow::ensure!(
            &deser.snd_data == snd_data,
            "[Card {}] snd data doesn't match on restore: expected: {:?}, got: {:?}",
            self.card_index,
            deser.snd_data,
            snd_data,
        );

        let ex_clone = self.ex.clone();
        let streams_rc = self.streams.clone();
        let tx_send_clone = self.tx_send.clone();
        let rx_send_clone = self.rx_send.clone();

        let card_index = self.card_index;
        let restore_task = self.ex.spawn_local(async move {
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
                            .prepare(&ex_clone, &tx_send_clone, &rx_send_clone)
                            .await
                            .unwrap_or_else(|_| {
                                panic!("[Card {}] failed to prepare PCM", card_index)
                            });
                    }
                    if stream_info.state == VIRTIO_SND_R_PCM_START {
                        stream.lock().await.start().await.unwrap_or_else(|_| {
                            panic!("[Card {}] failed to start PCM", card_index)
                        });
                    }
                }
            }
        });
        self.ex
            .run_until(restore_task)
            .unwrap_or_else(|_| panic!("[Card {}] failed to restore streams", self.card_index));
        Ok(())
    }

    fn enter_suspended_state(&mut self) -> anyhow::Result<()> {
        // This device has no non-queue workers to stop.
        Ok(())
    }
}
