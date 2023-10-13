// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod shm_streams;
mod shm_vios;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use self::shm_streams::*;
pub use self::shm_vios::*;

pub mod streams;
mod worker;

use std::collections::BTreeMap;
use std::io::Error as IoError;
use std::path::Path;
use std::sync::mpsc::RecvError;
use std::sync::mpsc::SendError;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::Error as BaseError;
use base::RawDescriptor;
use base::WorkerThread;
use data_model::Le32;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use streams::StreamMsg;
use streams::StreamSnapshot;
use sync::Mutex;
use thiserror::Error as ThisError;
use vm_memory::GuestMemory;
use worker::*;
use zerocopy::AsBytes;

use crate::virtio::copy_config;
use crate::virtio::device_constants::snd::virtio_snd_config;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;

const QUEUE_SIZES: &[u16] = &[64, 64, 64, 64];

#[sorted]
#[derive(ThisError, Debug)]
pub enum SoundError {
    #[error("The driver sent an invalid message")]
    BadDriverMsg,
    #[error("Failed to get event notifier from VioS client: {0}")]
    ClientEventNotifier(Error),
    #[error("Failed to create VioS client: {0}")]
    ClientNew(Error),
    #[error("Failed to create event pair: {0}")]
    CreateEvent(BaseError),
    #[error("Failed to create thread: {0}")]
    CreateThread(IoError),
    #[error("Attempted a {0} operation while on the wrong state: {1}, this is a bug")]
    ImpossibleState(&'static str, &'static str),
    #[error("Error consuming queue event: {0}")]
    QueueEvt(BaseError),
    #[error("Failed to read/write from/to queue: {0}")]
    QueueIO(IoError),
    #[error("Failed to receive message: {0}")]
    StreamThreadRecv(RecvError),
    #[error("Failed to send message: {0}")]
    StreamThreadSend(SendError<Box<StreamMsg>>),
    #[error("Error creating WaitContext: {0}")]
    WaitCtx(BaseError),
}

pub type Result<T> = std::result::Result<T, SoundError>;

pub struct Sound {
    config: virtio_snd_config,
    virtio_features: u64,
    worker_thread: Option<WorkerThread<anyhow::Result<Worker>>>,
    vios_client: Arc<Mutex<VioSClient>>,
    saved_stream_state: Vec<StreamSnapshot>,
}

#[derive(Serialize, Deserialize)]
struct SoundSnapshot {
    config: virtio_snd_config,
    virtio_features: u64,
    vios_client: VioSClientSnapshot,
    saved_stream_state: Vec<StreamSnapshot>,
}

impl VirtioDevice for Sound {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        self.vios_client.lock().keep_rds()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Sound
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.config.as_bytes(), offset);
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        error!("virtio-snd: driver attempted a config write which is not allowed by the spec");
    }

    fn features(&self) -> u64 {
        self.virtio_features
    }

    fn activate(
        &mut self,
        _mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        if self.worker_thread.is_some() {
            return Err(anyhow!("virtio-snd: Device is already active"));
        }
        if queues.len() != 4 {
            return Err(anyhow!(
                "virtio-snd: device activated with wrong number of queues: {}",
                queues.len(),
            ));
        }
        let control_queue = queues.remove(&0).unwrap();
        let event_queue = queues.remove(&1).unwrap();
        let tx_queue = queues.remove(&2).unwrap();
        let rx_queue = queues.remove(&3).unwrap();

        let vios_client = self.vios_client.clone();
        vios_client
            .lock()
            .start_bg_thread()
            .context("Failed to start vios background thread")?;

        let saved_stream_state: Vec<StreamSnapshot> = self.saved_stream_state.drain(..).collect();
        self.worker_thread =
            Some(WorkerThread::start(
                "v_snd_vios",
                move |kill_evt| match Worker::try_new(
                    vios_client,
                    interrupt,
                    Arc::new(Mutex::new(control_queue)),
                    event_queue,
                    Arc::new(Mutex::new(tx_queue)),
                    Arc::new(Mutex::new(rx_queue)),
                    saved_stream_state,
                ) {
                    Ok(mut worker) => match worker.control_loop(kill_evt) {
                        Ok(_) => Ok(worker),
                        Err(e) => {
                            error!("virtio-snd: Error in worker loop: {}", e);
                            Err(anyhow!("virtio-snd: Error in worker loop: {}", e))
                        }
                    },
                    Err(e) => {
                        error!("virtio-snd: Failed to create worker: {}", e);
                        Err(anyhow!("virtio-snd: Failed to create worker: {}", e))
                    }
                },
            ));

        Ok(())
    }

    fn reset(&mut self) -> bool {
        let mut ret = true;

        if let Some(worker_thread) = self.worker_thread.take() {
            let worker_status = worker_thread.stop();
            ret = worker_status.is_ok();
        }
        if let Err(e) = self.vios_client.lock().stop_bg_thread() {
            error!("virtio-snd: Failed to stop vios background thread: {}", e);
            ret = false;
        }
        ret
    }

    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
        if let Some(worker_thread) = self.worker_thread.take() {
            // The worker is stopped first but not unwrapped until after the VioSClient is stopped.
            // If the worker fails to stop and returns an error, but that error is unwrapped, the
            // vios_client background thread could remain running. Instead, by delaying the unwrap,
            // we can ensure the signal to both threads to stop is sent.
            let worker = worker_thread.stop();
            self.vios_client
                .lock()
                .stop_bg_thread()
                .context("failed to stop VioS Client background thread")?;
            let mut worker = worker.context("failed to stop worker_thread")?;
            self.saved_stream_state = worker.saved_stream_state.drain(..).collect();
            let ctrl_queue = worker.control_queue.clone();
            let event_queue = worker.event_queue.take().unwrap();
            let tx_queue = worker.tx_queue.clone();
            let rx_queue = worker.rx_queue.clone();

            // Must drop worker to drop all references to queues.
            // This also drops the io_thread
            drop(worker);

            let ctrl_queue = match Arc::try_unwrap(ctrl_queue) {
                Ok(q) => q.into_inner(),
                Err(_) => panic!("too many refs to snd control queue"),
            };
            let tx_queue = match Arc::try_unwrap(tx_queue) {
                Ok(q) => q.into_inner(),
                Err(_) => panic!("too many refs to snd tx queue"),
            };
            let rx_queue = match Arc::try_unwrap(rx_queue) {
                Ok(q) => q.into_inner(),
                Err(_) => panic!("too many refs to snd rx queue"),
            };
            let queues = vec![ctrl_queue, event_queue, tx_queue, rx_queue];
            return Ok(Some(BTreeMap::from_iter(queues.into_iter().enumerate())));
        }
        Ok(None)
    }

    fn virtio_wake(
        &mut self,
        device_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        match device_state {
            None => Ok(()),
            Some((mem, interrupt, queues)) => {
                // TODO: activate is just what we want at the moment, but we should probably move
                // it into a "start workers" function to make it obvious that it isn't strictly
                // used for activate events.
                self.activate(mem, interrupt, queues)?;
                Ok(())
            }
        }
    }

    fn virtio_snapshot(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(SoundSnapshot {
            config: self.config,
            virtio_features: self.virtio_features,
            vios_client: self.vios_client.lock().snapshot(),
            saved_stream_state: self.saved_stream_state.clone(),
        })
        .context("failed to serialize VioS Client")
    }

    fn virtio_restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let data: SoundSnapshot =
            serde_json::from_value(data).context("failed to deserialize VioS Client")?;
        anyhow::ensure!(
            data.config == self.config,
            "config doesn't match on restore: expected: {:?}, got: {:?}",
            data.config,
            self.config
        );
        anyhow::ensure!(
            data.virtio_features == self.virtio_features,
            "virtio_features doesn't match on restore: expected: {}, got: {}",
            data.virtio_features,
            self.virtio_features
        );
        self.saved_stream_state = data.saved_stream_state;
        self.vios_client.lock().restore(data.vios_client)
    }
}

/// Creates a new virtio sound device connected to a VioS backend
pub fn new_sound<P: AsRef<Path>>(path: P, virtio_features: u64) -> Result<Sound> {
    let vios_client = VioSClient::try_new(path).map_err(SoundError::ClientNew)?;
    let jacks = Le32::from(vios_client.num_jacks());
    let streams = Le32::from(vios_client.num_streams());
    let chmaps = Le32::from(vios_client.num_chmaps());
    Ok(Sound {
        config: virtio_snd_config {
            jacks,
            streams,
            chmaps,
        },
        virtio_features,
        worker_thread: None,
        vios_client: Arc::new(Mutex::new(vios_client)),
        saved_stream_state: Vec::new(),
    })
}
