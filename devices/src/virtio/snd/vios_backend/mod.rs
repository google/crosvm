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

use std::io::Error as IoError;
use std::path::Path;
use std::sync::mpsc::RecvError;
use std::sync::mpsc::SendError;
use std::sync::Arc;
use std::thread;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::Error as BaseError;
use base::Event;
use base::RawDescriptor;
use data_model::Le32;
use remain::sorted;
use streams::StreamMsg;
use sync::Mutex;
use thiserror::Error as ThisError;
use vm_memory::GuestMemory;
use worker::*;
use zerocopy::AsBytes;

use crate::virtio::copy_config;
use crate::virtio::device_constants::snd::virtio_snd_config;
use crate::virtio::DescriptorError;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;
use crate::Suspendable;

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
    #[error("Failed to create Reader from descriptor chain: {0}")]
    CreateReader(DescriptorError),
    #[error("Failed to create thread: {0}")]
    CreateThread(IoError),
    #[error("Failed to create Writer from descriptor chain: {0}")]
    CreateWriter(DescriptorError),
    #[error("Error with queue descriptor: {0}")]
    Descriptor(DescriptorError),
    #[error("Attempted a {0} operation while on the wrong state: {1}, this is a bug")]
    ImpossibleState(&'static str, &'static str),
    #[error("Error consuming queue event: {0}")]
    QueueEvt(BaseError),
    #[error("Failed to read/write from/to queue: {0}")]
    QueueIO(IoError),
    #[error("Failed to receive message: {0}")]
    StreamThreadRecv(RecvError),
    #[error("Failed to send message: {0}")]
    StreamThreadSend(SendError<StreamMsg>),
    #[error("Error creating WaitContext: {0}")]
    WaitCtx(BaseError),
}

pub type Result<T> = std::result::Result<T, SoundError>;

pub struct Sound {
    config: virtio_snd_config,
    virtio_features: u64,
    worker_thread: Option<thread::JoinHandle<bool>>,
    kill_evt: Option<Event>,
    vios_client: Arc<VioSClient>,
}

impl VirtioDevice for Sound {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        self.vios_client.keep_rds()
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
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<(Queue, Event)>,
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
        let (self_kill_evt, kill_evt) = Event::new()
            .and_then(|e| Ok((e.try_clone()?, e)))
            .context("failed to create kill Event pair")?;
        self.kill_evt = Some(self_kill_evt);
        let (control_queue, control_queue_evt) = queues.remove(0);
        let (event_queue, event_queue_evt) = queues.remove(0);
        let (tx_queue, tx_queue_evt) = queues.remove(0);
        let (rx_queue, rx_queue_evt) = queues.remove(0);

        let vios_client = self.vios_client.clone();
        vios_client
            .start_bg_thread()
            .context("Failed to start vios background thread")?;

        let worker_thread = thread::Builder::new()
            .name("v_snd_vios".to_string())
            .spawn(move || {
                match Worker::try_new(
                    vios_client,
                    interrupt,
                    mem,
                    Arc::new(Mutex::new(control_queue)),
                    control_queue_evt,
                    event_queue,
                    event_queue_evt,
                    Arc::new(Mutex::new(tx_queue)),
                    tx_queue_evt,
                    Arc::new(Mutex::new(rx_queue)),
                    rx_queue_evt,
                ) {
                    Ok(mut worker) => match worker.control_loop(kill_evt) {
                        Ok(_) => true,
                        Err(e) => {
                            error!("virtio-snd: Error in worker loop: {}", e);
                            false
                        }
                    },
                    Err(e) => {
                        error!("virtio-snd: Failed to create worker: {}", e);
                        false
                    }
                }
            })
            .context("failed to spawn virtio_snd worker thread")?;

        self.worker_thread = Some(worker_thread);
        Ok(())
    }

    fn reset(&mut self) -> bool {
        let mut ret = true;
        if let Some(kill_evt) = self.kill_evt.take() {
            if let Err(e) = kill_evt.signal() {
                error!("virtio-snd: failed to notify the kill event: {}", e);
                ret = false;
            }
        } else if let Some(worker_thread) = self.worker_thread.take() {
            match worker_thread.join() {
                Err(e) => {
                    error!("virtio-snd: Worker thread panicked: {:?}", e);
                    ret = false;
                }
                Ok(worker_status) => {
                    ret = worker_status;
                }
            }
        }
        if let Err(e) = self.vios_client.stop_bg_thread() {
            error!("virtio-snd: Failed to stop vios background thread: {}", e);
            ret = false;
        }
        ret
    }
}

impl Suspendable for Sound {}

/// Creates a new virtio sound device connected to a VioS backend
pub fn new_sound<P: AsRef<Path>>(path: P, virtio_features: u64) -> Result<Sound> {
    let vios_client = Arc::new(VioSClient::try_new(path).map_err(SoundError::ClientNew)?);
    Ok(Sound {
        config: virtio_snd_config {
            jacks: Le32::from(vios_client.num_jacks()),
            streams: Le32::from(vios_client.num_streams()),
            chmaps: Le32::from(vios_client.num_chmaps()),
        },
        virtio_features,
        worker_thread: None,
        kill_evt: None,
        vios_client,
    })
}
