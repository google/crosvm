// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// virtio-sound spec: https://github.com/oasis-tcs/virtio-spec/blob/master/virtio-sound.tex

use std::io;
use std::rc::Rc;
use std::thread;

use anyhow::Context;
use audio_streams::BoxError;
use audio_streams::StreamSourceGenerator;
use base::debug;
use base::error;
use base::warn;
use base::Error as SysError;
use base::Event;
use base::RawDescriptor;
use cros_async::block_on;
use cros_async::sync::Condvar;
use cros_async::sync::Mutex as AsyncMutex;
use cros_async::AsyncError;
use cros_async::EventAsync;
use cros_async::Executor;
use data_model::DataInit;
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

use crate::virtio::async_utils;
use crate::virtio::copy_config;
use crate::virtio::device_constants::snd::virtio_snd_config;
use crate::virtio::snd::common_backend::async_funcs::*;
use crate::virtio::snd::common_backend::stream_info::StreamInfo;
use crate::virtio::snd::constants::*;
use crate::virtio::snd::layout::*;
use crate::virtio::snd::null_backend::create_null_stream_source_generators;
use crate::virtio::snd::parameters::Parameters;
use crate::virtio::snd::parameters::StreamSourceBackend;
use crate::virtio::snd::sys::create_stream_source_generators as sys_create_stream_source_generators;
use crate::virtio::snd::sys::set_audio_thread_priority;
use crate::virtio::DescriptorError;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;
use crate::virtio::Writer;
use crate::Suspendable;

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
    /// Creating kill event failed.
    #[error("Failed to create kill event: {0}")]
    CreateKillEvent(SysError),
    /// Creating WaitContext failed.
    #[error("Failed to create wait context: {0}")]
    CreateWaitContext(SysError),
    /// Cloning kill event failed.
    #[error("Failed to clone kill event: {0}")]
    CloneKillEvent(SysError),
    /// Descriptor chain was invalid.
    #[error("Failed to valildate descriptor chain: {0}")]
    DescriptorChain(DescriptorError),
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
    Input(Box<dyn audio_streams::capture::AsyncCaptureBufferStream>),
    Output(Box<dyn audio_streams::AsyncPlaybackBufferStream>),
}

#[derive(Copy, Clone, std::cmp::PartialEq)]
pub enum WorkerStatus {
    Pause = 0,
    Running = 1,
    Quit = 2,
}

// Stores constant data
#[derive(Clone)]
pub struct SndData {
    jack_info: Vec<virtio_snd_jack_info>,
    pcm_info: Vec<virtio_snd_pcm_info>,
    chmap_info: Vec<virtio_snd_chmap_info>,
}

impl SndData {
    pub fn pcm_info_len(&self) -> usize {
        self.pcm_info.len()
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
    desc_index: u16,
    status: virtio_snd_pcm_status, // response to the pcm message
    writer: Writer,
    done: Option<oneshot::Sender<()>>, // when pcm response is written to the queue
}

pub struct VirtioSnd {
    cfg: virtio_snd_config,
    snd_data: SndData,
    avail_features: u64,
    acked_features: u64,
    queue_sizes: Box<[u16]>,
    worker_threads: Vec<thread::JoinHandle<()>>,
    kill_evt: Option<Event>,
    params: Parameters,
}

impl VirtioSnd {
    pub fn new(base_features: u64, params: Parameters) -> Result<VirtioSnd, Error> {
        let cfg = hardcoded_virtio_snd_config(&params);
        let snd_data = hardcoded_snd_data(&params);
        let avail_features = base_features;

        Ok(VirtioSnd {
            cfg,
            snd_data,
            avail_features,
            acked_features: 0,
            queue_sizes: vec![MAX_VRING_LEN; MAX_QUEUE_NUM].into_boxed_slice(),
            worker_threads: Vec::new(),
            kill_evt: None,
            params,
        })
    }
}

pub(crate) fn create_stream_source_generators(
    params: &Parameters,
    snd_data: &SndData,
) -> Vec<Box<dyn StreamSourceGenerator>> {
    match params.backend {
        StreamSourceBackend::NULL => create_null_stream_source_generators(snd_data),
        StreamSourceBackend::Sys(backend) => {
            sys_create_stream_source_generators(backend, params, snd_data)
        }
    }
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

impl VirtioDevice for VirtioSnd {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
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
        copy_config(data, 0, self.cfg.as_slice(), offset)
    }

    fn activate(
        &mut self,
        guest_mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
    ) {
        if queues.len() != self.queue_sizes.len() || queue_evts.len() != self.queue_sizes.len() {
            error!(
                "snd: expected {} queues, got {}",
                self.queue_sizes.len(),
                queues.len()
            );
        }

        let (self_kill_evt, kill_evt) =
            match Event::new().and_then(|evt| Ok((evt.try_clone()?, evt))) {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to create kill Event pair: {}", e);
                    return;
                }
            };
        self.kill_evt = Some(self_kill_evt);

        let snd_data = self.snd_data.clone();
        let stream_source_generators = create_stream_source_generators(&self.params, &snd_data);
        let worker_result = thread::Builder::new()
            .name("virtio_snd w".to_string())
            .spawn(move || {
                set_audio_thread_priority();
                if let Err(err_string) = run_worker(
                    interrupt,
                    queues,
                    guest_mem,
                    snd_data,
                    queue_evts,
                    kill_evt,
                    stream_source_generators,
                ) {
                    error!("{}", err_string);
                }
            });

        let join_handle = match worker_result {
            Err(e) => {
                error!("failed to spawn virtio_snd worker: {}", e);
                return;
            }
            Ok(join_handle) => join_handle,
        };
        self.worker_threads.push(join_handle);
    }

    fn reset(&mut self) -> bool {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.signal();
        }

        true
    }
}

impl Suspendable for VirtioSnd {}

impl Drop for VirtioSnd {
    fn drop(&mut self) {
        self.reset();
    }
}

#[derive(PartialEq)]
enum LoopState {
    Continue,
    Break,
}

fn run_worker(
    interrupt: Interrupt,
    mut queues: Vec<Queue>,
    mem: GuestMemory,
    snd_data: SndData,
    queue_evts: Vec<Event>,
    kill_evt: Event,
    stream_source_generators: Vec<Box<dyn StreamSourceGenerator>>,
) -> Result<(), String> {
    let ex = Executor::new().expect("Failed to create an executor");

    if snd_data.pcm_info_len() != stream_source_generators.len() {
        error!(
            "snd: expected {} streams, got {}",
            snd_data.pcm_info_len(),
            stream_source_generators.len(),
        );
    }
    let streams = stream_source_generators
        .into_iter()
        .map(|generator| AsyncMutex::new(StreamInfo::new(generator)))
        .collect();
    let streams = Rc::new(AsyncMutex::new(streams));

    let mut ctrl_queue = queues.remove(0);
    let _event_queue = queues.remove(0);
    let tx_queue = Rc::new(AsyncMutex::new(queues.remove(0)));
    let rx_queue = Rc::new(AsyncMutex::new(queues.remove(0)));

    let mut evts_async: Vec<EventAsync> = queue_evts
        .into_iter()
        .map(|e| EventAsync::new(e, &ex).expect("Failed to create async event for queue"))
        .collect();

    let mut ctrl_queue_evt = evts_async.remove(0);
    let _event_queue_evt = evts_async.remove(0);
    let tx_queue_evt = evts_async.remove(0);
    let rx_queue_evt = evts_async.remove(0);

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
            &mut ctrl_queue,
            &mut ctrl_queue_evt,
            &tx_queue,
            &tx_queue_evt,
            tx_send.clone(),
            &mut tx_recv,
            &rx_queue,
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

async fn notify_reset_signal(reset_signal: &(AsyncMutex<bool>, Condvar)) {
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
    streams: &Rc<AsyncMutex<Vec<AsyncMutex<StreamInfo>>>>,
    mem: &GuestMemory,
    interrupt: Interrupt,
    snd_data: &SndData,
    mut f_kill: &mut (impl Future<Output = anyhow::Result<()>> + FusedFuture + Unpin),
    mut f_resample: &mut (impl Future<Output = anyhow::Result<()>> + FusedFuture + Unpin),
    ctrl_queue: &mut Queue,
    ctrl_queue_evt: &mut EventAsync,
    tx_queue: &Rc<AsyncMutex<Queue>>,
    tx_queue_evt: &EventAsync,
    tx_send: mpsc::UnboundedSender<PcmResponse>,
    tx_recv: &mut mpsc::UnboundedReceiver<PcmResponse>,
    rx_queue: &Rc<AsyncMutex<Queue>>,
    rx_queue_evt: &EventAsync,
    rx_send: mpsc::UnboundedSender<PcmResponse>,
    rx_recv: &mut mpsc::UnboundedReceiver<PcmResponse>,
) -> LoopState {
    let tx_send2 = tx_send.clone();
    let rx_send2 = rx_send.clone();

    let reset_signal = (AsyncMutex::new(false), Condvar::new());

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
        tx_queue,
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
        rx_queue,
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
    streams: &Rc<AsyncMutex<Vec<AsyncMutex<StreamInfo>>>>,
    mem: &GuestMemory,
    interrupt: Interrupt,
    tx_queue: &Rc<AsyncMutex<Queue>>,
    tx_recv: &mut mpsc::UnboundedReceiver<PcmResponse>,
    rx_queue: &Rc<AsyncMutex<Queue>>,
    rx_recv: &mut mpsc::UnboundedReceiver<PcmResponse>,
) -> Result<(), AsyncError> {
    let reset_signal = (AsyncMutex::new(false), Condvar::new());

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
            tx_queue,
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
            rx_queue,
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
