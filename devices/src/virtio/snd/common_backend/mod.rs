// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// virtio-sound spec: https://github.com/oasis-tcs/virtio-spec/blob/master/virtio-sound.tex

use std::collections::BTreeMap;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use audio_streams::BoxError;
use base::debug;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::Descriptor;
use base::Error as SysError;
use base::Event;
use base::RawDescriptor;
use base::WorkerThread;
use cros_async::block_on;
use cros_async::sync::Condvar;
use cros_async::sync::RwLock as AsyncRwLock;
use cros_async::AsyncError;
use cros_async::EventAsync;
use cros_async::Executor;
use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::channel::oneshot::Canceled;
use futures::future::FusedFuture;
use futures::join;
use futures::pin_mut;
use futures::select;
use futures::Future;
use futures::FutureExt;
use thiserror::Error as ThisError;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;

use crate::virtio::async_utils;
use crate::virtio::copy_config;
use crate::virtio::device_constants::snd::virtio_snd_config;
use crate::virtio::snd::common_backend::async_funcs::*;
use crate::virtio::snd::common_backend::stream_info::StreamInfo;
use crate::virtio::snd::common_backend::stream_info::StreamInfoBuilder;
use crate::virtio::snd::constants::*;
use crate::virtio::snd::file_backend::create_file_stream_source_generators;
use crate::virtio::snd::file_backend::Error as FileError;
use crate::virtio::snd::layout::*;
use crate::virtio::snd::null_backend::create_null_stream_source_generators;
use crate::virtio::snd::parameters::Parameters;
use crate::virtio::snd::parameters::StreamSourceBackend;
use crate::virtio::snd::sys::create_stream_source_generators as sys_create_stream_source_generators;
use crate::virtio::snd::sys::set_audio_thread_priority;
use crate::virtio::snd::sys::SysAsyncStreamObjects;
use crate::virtio::snd::sys::SysAudioStreamSourceGenerator;
use crate::virtio::snd::sys::SysBufferWriter;
use crate::virtio::DescriptorChain;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;

pub mod async_funcs;
pub mod stream_info;

// control + event + tx + rx queue
pub const MAX_QUEUE_NUM: usize = 4;
pub const MAX_VRING_LEN: u16 = 1024;

#[derive(ThisError, Debug)]
pub enum Error {
    /// next_async failed.
    #[error("Failed to read descriptor asynchronously: {0}")]
    Async(AsyncError),
    /// Creating stream failed.
    #[error("Failed to create stream: {0}")]
    CreateStream(BoxError),
    /// Creating stream failed.
    #[error("No stream source found.")]
    EmptyStreamSource,
    /// Creating kill event failed.
    #[error("Failed to create kill event: {0}")]
    CreateKillEvent(SysError),
    /// Creating WaitContext failed.
    #[error("Failed to create wait context: {0}")]
    CreateWaitContext(SysError),
    #[error("Failed to create file stream source generator")]
    CreateFileStreamSourceGenerator(FileError),
    /// Cloning kill event failed.
    #[error("Failed to clone kill event: {0}")]
    CloneKillEvent(SysError),
    // Future error.
    #[error("Unexpected error. Done was not triggered before dropped: {0}")]
    DoneNotTriggered(Canceled),
    /// Error reading message from queue.
    #[error("Failed to read message: {0}")]
    ReadMessage(io::Error),
    /// Failed writing a response to a control message.
    #[error("Failed to write message response: {0}")]
    WriteResponse(io::Error),
    // Mpsc read error.
    #[error("Error in mpsc: {0}")]
    MpscSend(futures::channel::mpsc::SendError),
    // Oneshot send error.
    #[error("Error in oneshot send")]
    OneshotSend(()),
    /// Stream not found.
    #[error("stream id ({0}) < num_streams ({1})")]
    StreamNotFound(usize, usize),
    /// Fetch buffer error
    #[error("Failed to get buffer from CRAS: {0}")]
    FetchBuffer(BoxError),
    /// Invalid buffer size
    #[error("Invalid buffer size")]
    InvalidBufferSize,
    /// IoError
    #[error("I/O failed: {0}")]
    Io(io::Error),
    /// Operation not supported.
    #[error("Operation not supported")]
    OperationNotSupported,
    /// Writing to a buffer in the guest failed.
    #[error("failed to write to buffer: {0}")]
    WriteBuffer(io::Error),
    // Invalid PCM worker state.
    #[error("Invalid PCM worker state")]
    InvalidPCMWorkerState,
    // Invalid backend.
    #[error("Backend is not implemented")]
    InvalidBackend,
    // Failed to generate StreamSource
    #[error("Failed to generate stream source: {0}")]
    GenerateStreamSource(BoxError),
    // PCM worker unexpectedly quitted.
    #[error("PCM worker quitted unexpectedly")]
    PCMWorkerQuittedUnexpectedly,
}

pub enum DirectionalStream {
    Input(
        Box<dyn audio_streams::capture::AsyncCaptureBufferStream>,
        usize, // `period_size` in `usize`
    ),
    Output(
        Box<dyn audio_streams::AsyncPlaybackBufferStream>,
        Box<dyn PlaybackBufferWriter>,
    ),
}

#[derive(Copy, Clone, std::cmp::PartialEq, Eq)]
pub enum WorkerStatus {
    Pause = 0,
    Running = 1,
    Quit = 2,
}

// Stores constant data
#[derive(Clone)]
pub struct SndData {
    pub(crate) jack_info: Vec<virtio_snd_jack_info>,
    pub(crate) pcm_info: Vec<virtio_snd_pcm_info>,
    pub(crate) chmap_info: Vec<virtio_snd_chmap_info>,
}

impl SndData {
    pub fn pcm_info_len(&self) -> usize {
        self.pcm_info.len()
    }

    pub fn pcm_info_iter(&self) -> std::slice::Iter<'_, virtio_snd_pcm_info> {
        self.pcm_info.iter()
    }
}

const SUPPORTED_FORMATS: u64 = 1 << VIRTIO_SND_PCM_FMT_U8
    | 1 << VIRTIO_SND_PCM_FMT_S16
    | 1 << VIRTIO_SND_PCM_FMT_S24
    | 1 << VIRTIO_SND_PCM_FMT_S32;
const SUPPORTED_FRAME_RATES: u64 = 1 << VIRTIO_SND_PCM_RATE_8000
    | 1 << VIRTIO_SND_PCM_RATE_11025
    | 1 << VIRTIO_SND_PCM_RATE_16000
    | 1 << VIRTIO_SND_PCM_RATE_22050
    | 1 << VIRTIO_SND_PCM_RATE_32000
    | 1 << VIRTIO_SND_PCM_RATE_44100
    | 1 << VIRTIO_SND_PCM_RATE_48000;

// Response from pcm_worker to pcm_queue
pub struct PcmResponse {
    pub(crate) desc_chain: DescriptorChain,
    pub(crate) status: virtio_snd_pcm_status, // response to the pcm message
    pub(crate) done: Option<oneshot::Sender<()>>, // when pcm response is written to the queue
}

pub struct VirtioSnd {
    cfg: virtio_snd_config,
    snd_data: SndData,
    stream_info_builders: Vec<StreamInfoBuilder>,
    avail_features: u64,
    acked_features: u64,
    queue_sizes: Box<[u16]>,
    worker_thread: Option<WorkerThread<()>>,
    keep_rds: Vec<Descriptor>,
}

impl VirtioSnd {
    pub fn new(base_features: u64, params: Parameters) -> Result<VirtioSnd, Error> {
        let params = resize_parameters_pcm_device_config(params);
        let cfg = hardcoded_virtio_snd_config(&params);
        let snd_data = hardcoded_snd_data(&params);
        let avail_features = base_features;
        let mut keep_rds: Vec<RawDescriptor> = Vec::new();

        let stream_info_builders = create_stream_info_builders(&params, &snd_data, &mut keep_rds)?;

        Ok(VirtioSnd {
            cfg,
            snd_data,
            stream_info_builders,
            avail_features,
            acked_features: 0,
            queue_sizes: vec![MAX_VRING_LEN; MAX_QUEUE_NUM].into_boxed_slice(),
            worker_thread: None,
            keep_rds: keep_rds.iter().map(|rd| Descriptor(*rd)).collect(),
        })
    }
}

fn create_stream_source_generators(
    params: &Parameters,
    snd_data: &SndData,
    keep_rds: &mut Vec<RawDescriptor>,
) -> Result<Vec<SysAudioStreamSourceGenerator>, Error> {
    let generators = match params.backend {
        StreamSourceBackend::NULL => create_null_stream_source_generators(snd_data),
        StreamSourceBackend::FILE => {
            create_file_stream_source_generators(params, snd_data, keep_rds)
                .map_err(Error::CreateFileStreamSourceGenerator)?
        }
        StreamSourceBackend::Sys(backend) => {
            sys_create_stream_source_generators(backend, params, snd_data)
        }
    };
    Ok(generators)
}

/// Creates [`StreamInfoBuilder`]s by calling [`create_stream_source_generators()`] then zip
/// them with [`crate::virtio::snd::parameters::PCMDeviceParameters`] from the params to set
/// the parameters on each [`StreamInfoBuilder`] (e.g. effects).
pub(crate) fn create_stream_info_builders(
    params: &Parameters,
    snd_data: &SndData,
    keep_rds: &mut Vec<RawDescriptor>,
) -> Result<Vec<StreamInfoBuilder>, Error> {
    Ok(create_stream_source_generators(params, snd_data, keep_rds)?
        .into_iter()
        .map(Arc::new)
        .zip(snd_data.pcm_info_iter())
        .map(|(generator, pcm_info)| {
            let device_params = params.get_device_params(pcm_info).unwrap_or_default();
            StreamInfo::builder(generator).effects(device_params.effects.unwrap_or_default())
        })
        .collect())
}

// To be used with hardcoded_snd_data
pub fn hardcoded_virtio_snd_config(params: &Parameters) -> virtio_snd_config {
    virtio_snd_config {
        jacks: 0.into(),
        streams: params.get_total_streams().into(),
        chmaps: (params.num_output_devices * 3 + params.num_input_devices).into(),
    }
}

// To be used with hardcoded_virtio_snd_config
pub fn hardcoded_snd_data(params: &Parameters) -> SndData {
    let jack_info: Vec<virtio_snd_jack_info> = Vec::new();
    let mut pcm_info: Vec<virtio_snd_pcm_info> = Vec::new();
    let mut chmap_info: Vec<virtio_snd_chmap_info> = Vec::new();

    for dev in 0..params.num_output_devices {
        for _ in 0..params.num_output_streams {
            pcm_info.push(virtio_snd_pcm_info {
                hdr: virtio_snd_info {
                    hda_fn_nid: dev.into(),
                },
                features: 0.into(), /* 1 << VIRTIO_SND_PCM_F_XXX */
                formats: SUPPORTED_FORMATS.into(),
                rates: SUPPORTED_FRAME_RATES.into(),
                direction: VIRTIO_SND_D_OUTPUT,
                channels_min: 1,
                channels_max: 6,
                padding: [0; 5],
            });
        }
    }
    for dev in 0..params.num_input_devices {
        for _ in 0..params.num_input_streams {
            pcm_info.push(virtio_snd_pcm_info {
                hdr: virtio_snd_info {
                    hda_fn_nid: dev.into(),
                },
                features: 0.into(), /* 1 << VIRTIO_SND_PCM_F_XXX */
                formats: SUPPORTED_FORMATS.into(),
                rates: SUPPORTED_FRAME_RATES.into(),
                direction: VIRTIO_SND_D_INPUT,
                channels_min: 1,
                channels_max: 2,
                padding: [0; 5],
            });
        }
    }
    // Use stereo channel map.
    let mut positions = [VIRTIO_SND_CHMAP_NONE; VIRTIO_SND_CHMAP_MAX_SIZE];
    positions[0] = VIRTIO_SND_CHMAP_FL;
    positions[1] = VIRTIO_SND_CHMAP_FR;
    for dev in 0..params.num_output_devices {
        chmap_info.push(virtio_snd_chmap_info {
            hdr: virtio_snd_info {
                hda_fn_nid: dev.into(),
            },
            direction: VIRTIO_SND_D_OUTPUT,
            channels: 2,
            positions,
        });
    }
    for dev in 0..params.num_input_devices {
        chmap_info.push(virtio_snd_chmap_info {
            hdr: virtio_snd_info {
                hda_fn_nid: dev.into(),
            },
            direction: VIRTIO_SND_D_INPUT,
            channels: 2,
            positions,
        });
    }
    positions[2] = VIRTIO_SND_CHMAP_RL;
    positions[3] = VIRTIO_SND_CHMAP_RR;
    for dev in 0..params.num_output_devices {
        chmap_info.push(virtio_snd_chmap_info {
            hdr: virtio_snd_info {
                hda_fn_nid: dev.into(),
            },
            direction: VIRTIO_SND_D_OUTPUT,
            channels: 4,
            positions,
        });
    }
    positions[2] = VIRTIO_SND_CHMAP_FC;
    positions[3] = VIRTIO_SND_CHMAP_LFE;
    positions[4] = VIRTIO_SND_CHMAP_RL;
    positions[5] = VIRTIO_SND_CHMAP_RR;
    for dev in 0..params.num_output_devices {
        chmap_info.push(virtio_snd_chmap_info {
            hdr: virtio_snd_info {
                hda_fn_nid: dev.into(),
            },
            direction: VIRTIO_SND_D_OUTPUT,
            channels: 6,
            positions,
        });
    }

    SndData {
        jack_info,
        pcm_info,
        chmap_info,
    }
}

fn resize_parameters_pcm_device_config(mut params: Parameters) -> Parameters {
    if params.output_device_config.len() > params.num_output_devices as usize {
        warn!("Truncating output device config due to length > number of output devices");
    }
    params
        .output_device_config
        .resize_with(params.num_output_devices as usize, Default::default);

    if params.input_device_config.len() > params.num_input_devices as usize {
        warn!("Truncating input device config due to length > number of input devices");
    }
    params
        .input_device_config
        .resize_with(params.num_input_devices as usize, Default::default);

    params
}

impl VirtioDevice for VirtioSnd {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        self.keep_rds
            .iter()
            .map(|descr| descr.as_raw_descriptor())
            .collect()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Sound
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn features(&self) -> u64 {
        self.avail_features
    }

    fn ack_features(&mut self, mut v: u64) {
        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("virtio_fs got unknown feature ack: {:x}", v);

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.cfg.as_bytes(), offset)
    }

    fn activate(
        &mut self,
        guest_mem: GuestMemory,
        interrupt: Interrupt,
        queues: BTreeMap<usize, (Queue, Event)>,
    ) -> anyhow::Result<()> {
        if queues.len() != self.queue_sizes.len() {
            return Err(anyhow!(
                "snd: expected {} queues, got {}",
                self.queue_sizes.len(),
                queues.len()
            ));
        }

        let snd_data = self.snd_data.clone();
        let stream_info_builders = self.stream_info_builders.to_vec();

        self.worker_thread = Some(WorkerThread::start("v_snd_common", move |kill_evt| {
            let _thread_priority_handle = set_audio_thread_priority();
            if let Err(e) = _thread_priority_handle {
                warn!("Failed to set audio thread to real time: {}", e);
            };
            if let Err(err_string) = run_worker(
                interrupt,
                queues,
                guest_mem,
                snd_data,
                kill_evt,
                stream_info_builders,
            ) {
                error!("{}", err_string);
            }
        }));

        Ok(())
    }

    fn reset(&mut self) -> bool {
        if let Some(worker_thread) = self.worker_thread.take() {
            worker_thread.stop();
        }

        true
    }
}

#[derive(PartialEq)]
enum LoopState {
    Continue,
    Break,
}

fn run_worker(
    interrupt: Interrupt,
    queues: BTreeMap<usize, (Queue, Event)>,
    mem: GuestMemory,
    snd_data: SndData,
    kill_evt: Event,
    stream_info_builders: Vec<StreamInfoBuilder>,
) -> Result<(), String> {
    let ex = Executor::new().expect("Failed to create an executor");

    if snd_data.pcm_info_len() != stream_info_builders.len() {
        error!(
            "snd: expected {} streams, got {}",
            snd_data.pcm_info_len(),
            stream_info_builders.len(),
        );
    }
    let streams = stream_info_builders
        .into_iter()
        .map(StreamInfoBuilder::build)
        .map(AsyncRwLock::new)
        .collect();
    let streams = Rc::new(AsyncRwLock::new(streams));

    let mut queues: Vec<(Queue, EventAsync)> = queues
        .into_iter()
        .map(|(_, (q, e))| {
            (
                q,
                EventAsync::new(e, &ex).expect("Failed to create async event for queue"),
            )
        })
        .collect();

    let (ctrl_queue, mut ctrl_queue_evt) = queues.remove(0);
    let ctrl_queue = Rc::new(AsyncRwLock::new(ctrl_queue));
    let (_event_queue, _event_queue_evt) = queues.remove(0);
    let (tx_queue, tx_queue_evt) = queues.remove(0);
    let (rx_queue, rx_queue_evt) = queues.remove(0);

    let tx_queue = Rc::new(AsyncRwLock::new(tx_queue));
    let rx_queue = Rc::new(AsyncRwLock::new(rx_queue));

    let (tx_send, mut tx_recv) = mpsc::unbounded();
    let (rx_send, mut rx_recv) = mpsc::unbounded();

    let f_resample = async_utils::handle_irq_resample(&ex, interrupt.clone()).fuse();

    // Exit if the kill event is triggered.
    let f_kill = async_utils::await_and_exit(&ex, kill_evt).fuse();

    pin_mut!(f_resample, f_kill);

    loop {
        if run_worker_once(
            &ex,
            &streams,
            &mem,
            interrupt.clone(),
            &snd_data,
            &mut f_kill,
            &mut f_resample,
            ctrl_queue.clone(),
            &mut ctrl_queue_evt,
            tx_queue.clone(),
            &tx_queue_evt,
            tx_send.clone(),
            &mut tx_recv,
            rx_queue.clone(),
            &rx_queue_evt,
            rx_send.clone(),
            &mut rx_recv,
        ) == LoopState::Break
        {
            break;
        }

        if let Err(e) = reset_streams(
            &ex,
            &streams,
            &mem,
            interrupt.clone(),
            &tx_queue,
            &mut tx_recv,
            &rx_queue,
            &mut rx_recv,
        ) {
            error!("Error reset streams: {}", e);
            break;
        }
    }

    Ok(())
}

async fn notify_reset_signal(reset_signal: &(AsyncRwLock<bool>, Condvar)) {
    let (lock, cvar) = reset_signal;
    *lock.lock().await = true;
    cvar.notify_all();
}

/// Runs all workers once and exit if any worker exit.
///
/// Returns [`LoopState::Break`] if the worker `f_kill` or `f_resample` exit, or something went wrong
/// on shutdown process. The caller should not run the worker again and should exit the main loop.
///
/// If this function returns [`LoopState::Continue`], the caller can continue the main loop by resetting
/// the streams and run the worker again.
fn run_worker_once(
    ex: &Executor,
    streams: &Rc<AsyncRwLock<Vec<AsyncRwLock<StreamInfo>>>>,
    mem: &GuestMemory,
    interrupt: Interrupt,
    snd_data: &SndData,
    mut f_kill: &mut (impl Future<Output = anyhow::Result<()>> + FusedFuture + Unpin),
    mut f_resample: &mut (impl Future<Output = anyhow::Result<()>> + FusedFuture + Unpin),
    ctrl_queue: Rc<AsyncRwLock<Queue>>,
    ctrl_queue_evt: &mut EventAsync,
    tx_queue: Rc<AsyncRwLock<Queue>>,
    tx_queue_evt: &EventAsync,
    tx_send: mpsc::UnboundedSender<PcmResponse>,
    tx_recv: &mut mpsc::UnboundedReceiver<PcmResponse>,
    rx_queue: Rc<AsyncRwLock<Queue>>,
    rx_queue_evt: &EventAsync,
    rx_send: mpsc::UnboundedSender<PcmResponse>,
    rx_recv: &mut mpsc::UnboundedReceiver<PcmResponse>,
) -> LoopState {
    let tx_send2 = tx_send.clone();
    let rx_send2 = rx_send.clone();

    let reset_signal = (AsyncRwLock::new(false), Condvar::new());

    let f_ctrl = handle_ctrl_queue(
        ex,
        mem,
        streams,
        snd_data,
        ctrl_queue,
        ctrl_queue_evt,
        interrupt.clone(),
        tx_send,
        rx_send,
        Some(&reset_signal),
    )
    .fuse();

    // TODO(woodychow): Enable this when libcras sends jack connect/disconnect evts
    // let f_event = handle_event_queue(
    //     &mem,
    //     snd_state,
    //     event_queue,
    //     event_queue_evt,
    //     interrupt,
    // );
    let f_tx = handle_pcm_queue(
        mem,
        streams,
        tx_send2,
        tx_queue.clone(),
        tx_queue_evt,
        Some(&reset_signal),
    )
    .fuse();
    let f_tx_response = send_pcm_response_worker(
        mem,
        tx_queue,
        interrupt.clone(),
        tx_recv,
        Some(&reset_signal),
    )
    .fuse();
    let f_rx = handle_pcm_queue(
        mem,
        streams,
        rx_send2,
        rx_queue.clone(),
        rx_queue_evt,
        Some(&reset_signal),
    )
    .fuse();
    let f_rx_response =
        send_pcm_response_worker(mem, rx_queue, interrupt, rx_recv, Some(&reset_signal)).fuse();

    pin_mut!(f_ctrl, f_tx, f_tx_response, f_rx, f_rx_response);

    let done = async {
        select! {
            res = f_ctrl => (res.context("error in handling ctrl queue"), LoopState::Continue),
            res = f_tx => (res.context("error in handling tx queue"), LoopState::Continue),
            res = f_tx_response => (res.context("error in handling tx response"), LoopState::Continue),
            res = f_rx => (res.context("error in handling rx queue"), LoopState::Continue),
            res = f_rx_response => (res.context("error in handling rx response"), LoopState::Continue),

            // For following workers, do not continue the loop
            res = f_resample => (res.context("error in handle_irq_resample"), LoopState::Break),
            res = f_kill => (res.context("error in await_and_exit"), LoopState::Break),
        }
    };

    match ex.run_until(done) {
        Ok((res, loop_state)) => {
            if let Err(e) = res {
                error!("Error in worker: {:#}", e);
            }
            if loop_state == LoopState::Break {
                return LoopState::Break;
            }
        }
        Err(e) => {
            error!("Error happened in executor: {}", e);
        }
    }

    warn!("Shutting down all workers for reset procedure");
    block_on(notify_reset_signal(&reset_signal));

    let shutdown = async {
        loop {
            let (res, worker_name) = select!(
                res = f_ctrl => (res, "f_ctrl"),
                res = f_tx => (res, "f_tx"),
                res = f_tx_response => (res, "f_tx_response"),
                res = f_rx => (res, "f_rx"),
                res = f_rx_response => (res, "f_rx_response"),
                complete => break,
            );
            match res {
                Ok(_) => debug!("Worker {} stopped", worker_name),
                Err(e) => error!("Worker {} stopped with error {}", worker_name, e),
            };
        }
    };

    if let Err(e) = ex.run_until(shutdown) {
        error!("Error happened in executor while shutdown: {}", e);
        return LoopState::Break;
    }

    LoopState::Continue
}

fn reset_streams(
    ex: &Executor,
    streams: &Rc<AsyncRwLock<Vec<AsyncRwLock<StreamInfo>>>>,
    mem: &GuestMemory,
    interrupt: Interrupt,
    tx_queue: &Rc<AsyncRwLock<Queue>>,
    tx_recv: &mut mpsc::UnboundedReceiver<PcmResponse>,
    rx_queue: &Rc<AsyncRwLock<Queue>>,
    rx_recv: &mut mpsc::UnboundedReceiver<PcmResponse>,
) -> Result<(), AsyncError> {
    let reset_signal = (AsyncRwLock::new(false), Condvar::new());

    let do_reset = async {
        let streams = streams.read_lock().await;
        for stream_info in &*streams {
            let mut stream_info = stream_info.lock().await;
            if stream_info.state == VIRTIO_SND_R_PCM_START {
                if let Err(e) = stream_info.stop().await {
                    error!("Error on stop while resetting stream: {}", e);
                }
            }
            if stream_info.state == VIRTIO_SND_R_PCM_STOP
                || stream_info.state == VIRTIO_SND_R_PCM_PREPARE
            {
                if let Err(e) = stream_info.release().await {
                    error!("Error on release while resetting stream: {}", e);
                }
            }
            stream_info.just_reset = true;
        }

        notify_reset_signal(&reset_signal).await;
    };

    // Run these in a loop to ensure that they will survive until do_reset is finished
    let f_tx_response = async {
        while send_pcm_response_worker(
            mem,
            tx_queue.clone(),
            interrupt.clone(),
            tx_recv,
            Some(&reset_signal),
        )
        .await
        .is_err()
        {}
    };

    let f_rx_response = async {
        while send_pcm_response_worker(
            mem,
            rx_queue.clone(),
            interrupt.clone(),
            rx_recv,
            Some(&reset_signal),
        )
        .await
        .is_err()
        {}
    };

    let reset = async {
        join!(f_tx_response, f_rx_response, do_reset);
    };

    ex.run_until(reset)
}

#[cfg(test)]
#[allow(clippy::needless_update)]
mod tests {
    use audio_streams::StreamEffect;

    use super::*;
    use crate::virtio::snd::parameters::PCMDeviceParameters;

    #[test]
    fn test_virtio_snd_new() {
        let params = Parameters {
            num_output_devices: 3,
            num_input_devices: 2,
            num_output_streams: 3,
            num_input_streams: 2,
            output_device_config: vec![PCMDeviceParameters {
                effects: Some(vec![StreamEffect::EchoCancellation]),
                ..PCMDeviceParameters::default()
            }],
            input_device_config: vec![PCMDeviceParameters {
                effects: Some(vec![StreamEffect::EchoCancellation]),
                ..PCMDeviceParameters::default()
            }],
            ..Default::default()
        };

        let res = VirtioSnd::new(123, params).unwrap();

        // Default values
        assert_eq!(res.snd_data.jack_info.len(), 0);
        assert_eq!(res.acked_features, 0);
        assert_eq!(res.worker_thread.is_none(), true);

        assert_eq!(res.avail_features, 123); // avail_features must be equal to the input
        assert_eq!(res.cfg.jacks.to_native(), 0);
        assert_eq!(res.cfg.streams.to_native(), 13); // (Output = 3*3) + (Input = 2*2)
        assert_eq!(res.cfg.chmaps.to_native(), 11); // (Output = 3*3) + (Input = 2*1)

        // Check snd_data.pcm_info
        assert_eq!(res.snd_data.pcm_info.len(), 13);
        // Check hda_fn_nid (PCM Device number)
        let expected_hda_fn_nid = vec![0, 0, 0, 1, 1, 1, 2, 2, 2, 0, 0, 1, 1];
        for (i, pcm_info) in res.snd_data.pcm_info.iter().enumerate() {
            assert_eq!(
                pcm_info.hdr.hda_fn_nid.to_native(),
                expected_hda_fn_nid[i],
                "pcm_info index {} incorrect hda_fn_nid",
                i
            );
        }
        // First 9 devices must be OUTPUT
        for i in 0..9 {
            assert_eq!(
                res.snd_data.pcm_info[i].direction, VIRTIO_SND_D_OUTPUT,
                "pcm_info index {} incorrect direction",
                i
            );
        }
        // Next 4 devices must be INPUT
        for i in 9..13 {
            assert_eq!(
                res.snd_data.pcm_info[i].direction, VIRTIO_SND_D_INPUT,
                "pcm_info index {} incorrect direction",
                i
            );
        }

        // Check snd_data.chmap_info
        assert_eq!(res.snd_data.chmap_info.len(), 11);
        let expected_hda_fn_nid = vec![0, 1, 2, 0, 1, 0, 1, 2, 0, 1, 2];
        // Check hda_fn_nid (PCM Device number)
        for (i, chmap_info) in res.snd_data.chmap_info.iter().enumerate() {
            assert_eq!(
                chmap_info.hdr.hda_fn_nid.to_native(),
                expected_hda_fn_nid[i],
                "chmap_info index {} incorrect hda_fn_nid",
                i
            );
        }
    }

    #[test]
    fn test_resize_parameters_pcm_device_config_truncate() {
        // If pcm_device_config is larger than number of devices, it will be truncated
        let params = Parameters {
            num_output_devices: 1,
            num_input_devices: 1,
            output_device_config: vec![PCMDeviceParameters::default(); 3],
            input_device_config: vec![PCMDeviceParameters::default(); 3],
            ..Parameters::default()
        };
        let params = resize_parameters_pcm_device_config(params);
        assert_eq!(params.output_device_config.len(), 1);
        assert_eq!(params.input_device_config.len(), 1);
    }

    #[test]
    fn test_resize_parameters_pcm_device_config_extend() {
        let params = Parameters {
            num_output_devices: 3,
            num_input_devices: 2,
            num_output_streams: 3,
            num_input_streams: 2,
            output_device_config: vec![PCMDeviceParameters {
                effects: Some(vec![StreamEffect::EchoCancellation]),
                ..PCMDeviceParameters::default()
            }],
            input_device_config: vec![PCMDeviceParameters {
                effects: Some(vec![StreamEffect::EchoCancellation]),
                ..PCMDeviceParameters::default()
            }],
            ..Default::default()
        };

        let params = resize_parameters_pcm_device_config(params);

        // Check output_device_config correctly extended
        assert_eq!(
            params.output_device_config,
            vec![
                PCMDeviceParameters {
                    // Keep from the parameters
                    effects: Some(vec![StreamEffect::EchoCancellation]),
                    ..PCMDeviceParameters::default()
                },
                PCMDeviceParameters::default(), // Extended with default
                PCMDeviceParameters::default(), // Extended with default
            ]
        );

        // Check input_device_config correctly extended
        assert_eq!(
            params.input_device_config,
            vec![
                PCMDeviceParameters {
                    // Keep from the parameters
                    effects: Some(vec![StreamEffect::EchoCancellation]),
                    ..PCMDeviceParameters::default()
                },
                PCMDeviceParameters::default(), // Extended with default
            ]
        );
    }
}
