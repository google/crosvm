// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::rc::Rc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::error;
use base::warn;
use base::Event;
use cros_async::sync::Mutex as AsyncMutex;
use cros_async::EventAsync;
use cros_async::Executor;
use data_model::DataInit;
use futures::channel::mpsc;
use futures::future::AbortHandle;
use futures::future::Abortable;
use hypervisor::ProtectionType;
use once_cell::sync::OnceCell;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserVirtioFeatures;

use crate::virtio;
use crate::virtio::copy_config;
use crate::virtio::device_constants::snd::virtio_snd_config;
use crate::virtio::snd::common_backend::async_funcs::handle_ctrl_queue;
use crate::virtio::snd::common_backend::async_funcs::handle_pcm_queue;
use crate::virtio::snd::common_backend::async_funcs::send_pcm_response_worker;
use crate::virtio::snd::common_backend::create_stream_source_generators;
use crate::virtio::snd::common_backend::hardcoded_snd_data;
use crate::virtio::snd::common_backend::hardcoded_virtio_snd_config;
use crate::virtio::snd::common_backend::stream_info::StreamInfo;
use crate::virtio::snd::common_backend::PcmResponse;
use crate::virtio::snd::common_backend::SndData;
use crate::virtio::snd::common_backend::MAX_QUEUE_NUM;
use crate::virtio::snd::common_backend::MAX_VRING_LEN;
use crate::virtio::snd::parameters::Parameters;
use crate::virtio::vhost::user::device::handler::sys::Doorbell;
use crate::virtio::vhost::user::device::handler::VhostUserBackend;
use crate::virtio::vhost::user::device::listener::sys::VhostUserListener;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;

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
    workers: [Option<AbortHandle>; MAX_QUEUE_NUM],
    response_workers: [Option<AbortHandle>; 2], // tx and rx
    snd_data: Rc<SndData>,
    streams: Rc<AsyncMutex<Vec<AsyncMutex<StreamInfo>>>>,
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
        let generators = create_stream_source_generators(&params, &snd_data);

        if snd_data.pcm_info_len() != generators.len() {
            error!(
                "snd: expected {} stream source generators, got {}",
                snd_data.pcm_info_len(),
                generators.len(),
            )
        }

        let streams = generators
            .into_iter()
            .map(|generator| AsyncMutex::new(StreamInfo::new(generator)))
            .collect();
        let streams = Rc::new(AsyncMutex::new(streams));

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

impl VhostUserBackend for SndBackend {
    fn max_queue_num(&self) -> usize {
        MAX_QUEUE_NUM
    }

    fn max_vring_len(&self) -> u16 {
        MAX_VRING_LEN
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
        doorbell: Doorbell,
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

        let mut kick_evt =
            EventAsync::new(kick_evt, ex).context("failed to create EventAsync for kick_evt")?;
        let (handle, registration) = AbortHandle::new_pair();
        match idx {
            0 => {
                // ctrl queue
                let streams = self.streams.clone();
                let snd_data = self.snd_data.clone();
                let tx_send = self.tx_send.clone();
                let rx_send = self.rx_send.clone();
                ex.spawn_local(Abortable::new(
                    async move {
                        handle_ctrl_queue(
                            ex,
                            &mem,
                            &streams,
                            &snd_data,
                            &mut queue,
                            &mut kick_evt,
                            doorbell,
                            tx_send,
                            rx_send,
                            None,
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
                    async move {
                        handle_pcm_queue(&mem, &streams, send, &queue, &kick_evt, None).await
                    },
                    registration,
                ))
                .detach();

                let (handle2, registration2) = AbortHandle::new_pair();

                ex.spawn_local(Abortable::new(
                    async move {
                        send_pcm_response_worker(&mem2, &queue2, doorbell, &mut recv, None).await
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
#[argh(subcommand, name = "snd")]
/// Snd device
pub struct Options {
    #[argh(option, arg_name = "PATH")]
    /// path to bind a listening vhost-user socket
    socket: Option<String>,
    #[argh(option, arg_name = "STRING")]
    /// VFIO-PCI device name (e.g. '0000:00:07.0')
    vfio: Option<String>,
    #[argh(
        option,
        arg_name = "CONFIG",
        from_str_fn(snd_parameters_from_str),
        default = "Default::default()",
        long = "config"
    )]
    /// comma separated key=value pairs for setting up cras snd devices.
    /// Possible key values:
    /// capture - Enable audio capture. Default to false.
    /// backend - Which backend to use for vhost-snd (null|cras).
    /// client_type - Set specific client type for cras backend.
    /// socket_type - Set socket type for cras backend.
    /// num_output_devices - Set number of output PCM devices.
    /// num_input_devices - Set number of input PCM devices.
    /// num_output_streams - Set number of output PCM streams per device.
    /// num_input_streams - Set number of input PCM streams per device.
    /// Example: [capture=true,backend=BACKEND,
    /// num_output_devices=1,num_input_devices=1,num_output_streams=1,num_input_streams=1]
    params: Parameters,
}

fn snd_parameters_from_str(input: &str) -> Result<Parameters, String> {
    serde_keyvalue::from_key_values(input).map_err(|e| e.to_string())
}

/// Starts a vhost-user snd device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_snd_device(opts: Options) -> anyhow::Result<()> {
    let snd_device = Box::new(SndBackend::new(opts.params)?);

    // Child, we can continue by spawning the executor and set up the device
    let ex = Executor::new().context("Failed to create executor")?;

    let _ = SND_EXECUTOR.set(ex.clone());

    let listener = VhostUserListener::new_from_socket_or_vfio(
        &opts.socket,
        &opts.vfio,
        snd_device.max_queue_num(),
        None,
    )?;
    // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
    ex.run_until(listener.run_backend(snd_device, &ex))?
}
