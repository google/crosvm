// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::net::UnixListener;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use argh::FromArgs;
use base::{warn, Event, UnlinkUnixListener};
use cros_async::{sync::Mutex as AsyncMutex, EventAsync, Executor};
use data_model::DataInit;
use futures::channel::mpsc;
use futures::future::{AbortHandle, Abortable};
use hypervisor::ProtectionType;
use once_cell::sync::OnceCell;
use sync::Mutex;
use vm_memory::GuestMemory;
use vmm_vhost::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use crate::virtio::snd::cras_backend::{
    async_funcs::{handle_ctrl_queue, handle_pcm_queue, send_pcm_response_worker},
    hardcoded_snd_data, hardcoded_virtio_snd_config, Parameters, PcmResponse, SndData, StreamInfo,
    MAX_QUEUE_NUM, MAX_VRING_LEN,
};
use crate::virtio::snd::layout::virtio_snd_config;
use crate::virtio::vhost::user::device::handler::{
    DeviceRequestHandler, Doorbell, VhostUserBackend,
};
use crate::virtio::{self, copy_config};

static SND_EXECUTOR: OnceCell<Executor> = OnceCell::new();

// Async workers:
// 0 - ctrl
// 1 - event
// 2 - tx
// 3 - rx
const PCM_RESPONSE_WORKER_IDX_OFFSET: usize = 2;
struct CrasSndBackend {
    cfg: virtio_snd_config,
    avail_features: u64,
    acked_features: u64,
    acked_protocol_features: VhostUserProtocolFeatures,
    workers: [Option<AbortHandle>; MAX_QUEUE_NUM],
    response_workers: [Option<AbortHandle>; 2], // tx and rx
    snd_data: Rc<SndData>,
    streams: Rc<AsyncMutex<Vec<AsyncMutex<StreamInfo<'static>>>>>,
    params: Parameters,
    tx_send: mpsc::UnboundedSender<PcmResponse>,
    rx_send: mpsc::UnboundedSender<PcmResponse>,
    tx_recv: Option<mpsc::UnboundedReceiver<PcmResponse>>,
    rx_recv: Option<mpsc::UnboundedReceiver<PcmResponse>>,
}

impl CrasSndBackend {
    pub fn new(params: Parameters) -> anyhow::Result<Self> {
        let cfg = hardcoded_virtio_snd_config(&params);
        let avail_features = virtio::base_features(ProtectionType::Unprotected)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let snd_data = hardcoded_snd_data(&params);

        let mut streams: Vec<AsyncMutex<StreamInfo>> = Vec::new();
        streams.resize_with(snd_data.pcm_info_len(), Default::default);
        let streams = Rc::new(AsyncMutex::new(streams));

        let (tx_send, tx_recv) = mpsc::unbounded();
        let (rx_send, rx_recv) = mpsc::unbounded();

        Ok(CrasSndBackend {
            cfg,
            avail_features,
            acked_features: 0,
            acked_protocol_features: VhostUserProtocolFeatures::empty(),
            workers: Default::default(),
            response_workers: Default::default(),
            snd_data: Rc::new(snd_data),
            streams,
            params,
            tx_send,
            rx_send,
            tx_recv: Some(tx_recv),
            rx_recv: Some(rx_recv),
        })
    }
}

impl VhostUserBackend for CrasSndBackend {
    const MAX_QUEUE_NUM: usize = MAX_QUEUE_NUM;
    const MAX_VRING_LEN: u16 = MAX_VRING_LEN;

    type Error = anyhow::Error;

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
        copy_config(data, 0, self.cfg.as_slice(), offset)
    }

    fn reset(&mut self) {
        for handle in self.workers.iter_mut().filter_map(Option::take) {
            handle.abort();
        }
    }

    fn start_queue(
        &mut self,
        idx: usize,
        mut queue: virtio::Queue,
        mem: GuestMemory,
        doorbell: Arc<Mutex<Doorbell>>,
        kick_evt: Event,
    ) -> anyhow::Result<()> {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            warn!("Starting new queue handler without stopping old handler");
            handle.abort();
        }

        // Safe because the executor is initialized in main() below.
        let ex = SND_EXECUTOR.get().expect("Executor not initialized");

        // Enable any virtqueue features that were negotiated (like VIRTIO_RING_F_EVENT_IDX).
        queue.ack_features(self.acked_features);

        let kick_evt =
            EventAsync::new(kick_evt.0, ex).context("failed to create EventAsync for kick_evt")?;
        let (handle, registration) = AbortHandle::new_pair();
        match idx {
            0 => {
                // ctrl queue
                let streams = self.streams.clone();
                let snd_data = self.snd_data.clone();
                let tx_send = self.tx_send.clone();
                let rx_send = self.rx_send.clone();
                let params = self.params.clone();
                ex.spawn_local(Abortable::new(
                    async move {
                        handle_ctrl_queue(
                            &ex, &mem, &streams, &*snd_data, queue, kick_evt, &doorbell, tx_send,
                            rx_send, &params,
                        )
                        .await
                    },
                    registration,
                ))
                .detach();
            }
            1 => {} // TODO(woodychow): Add event queue support
            2 | 3 => {
                let (send, recv) = if idx == 2 {
                    (self.tx_send.clone(), self.tx_recv.take())
                } else {
                    (self.rx_send.clone(), self.rx_recv.take())
                };
                let mut recv = recv.ok_or_else(|| anyhow!("queue restart is not supported"))?;
                let queue = Rc::new(AsyncMutex::new(queue));
                let queue2 = Rc::clone(&queue);
                let mem = Rc::new(mem);
                let mem2 = Rc::clone(&mem);
                let streams = Rc::clone(&self.streams);
                ex.spawn_local(Abortable::new(
                    async move { handle_pcm_queue(&*mem, &streams, send, &queue, kick_evt).await },
                    registration,
                ))
                .detach();

                let (handle2, registration2) = AbortHandle::new_pair();

                ex.spawn_local(Abortable::new(
                    async move {
                        send_pcm_response_worker(&*mem2, &queue2, &doorbell, &mut recv).await
                    },
                    registration2,
                ))
                .detach();

                self.response_workers[idx - PCM_RESPONSE_WORKER_IDX_OFFSET] = Some(handle2);
            }
            _ => bail!("attempted to start unknown queue: {}", idx),
        }

        self.workers[idx] = Some(handle);
        Ok(())
    }

    fn stop_queue(&mut self, idx: usize) {
        if let Some(handle) = self.workers.get_mut(idx).and_then(Option::take) {
            handle.abort();
        }
        if idx == 2 || idx == 3 {
            if let Some(handle) = self
                .response_workers
                .get_mut(idx - PCM_RESPONSE_WORKER_IDX_OFFSET)
                .and_then(Option::take)
            {
                handle.abort();
            }
        }
    }
}

#[derive(FromArgs)]
#[argh(description = "")]
struct Options {
    #[argh(option, description = "path to a socket", arg_name = "PATH")]
    socket: String,
    #[argh(
        option,
        description = "comma separated key=value pairs for setting up cras snd devices.
Possible key values:
capture - Enable audio capture. Default to false.
client_type - Set specific client type for cras backend.
num_output_streams - Set number of output PCM streams.
num_input_streams - Set number of input PCM streams.
Example: [capture=true,client=crosvm,socket=unified,num_output_streams=1,num_input_streams=1]",
        arg_name = "CONFIG"
    )]
    config: Option<String>,
}

/// Starts a vhost-user snd device with the cras backend.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_cras_snd_device(program_name: &str, args: &[&str]) -> anyhow::Result<()> {
    let opts = match Options::from_args(&[program_name], args) {
        Ok(opts) => opts,
        Err(e) => {
            if e.status.is_err() {
                bail!(e.output);
            } else {
                println!("{}", e.output);
            }
            return Ok(());
        }
    };
    let params = opts
        .config
        .unwrap_or("".to_string())
        .parse::<Parameters>()?;

    let snd_device = CrasSndBackend::new(params)?;

    // Create and bind unix socket
    let listener = UnixListener::bind(opts.socket).map(UnlinkUnixListener)?;

    let handler = DeviceRequestHandler::new(snd_device);

    // Child, we can continue by spawning the executor and set up the device
    let ex = Executor::new().context("Failed to create executor")?;

    let _ = SND_EXECUTOR.set(ex.clone());

    // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
    ex.run_until(handler.run_with_listener(listener, &ex))?
}
