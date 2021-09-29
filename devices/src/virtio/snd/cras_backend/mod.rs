// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// virtio-sound spec: https://github.com/oasis-tcs/virtio-spec/blob/master/virtio-sound.tex

use std::io;
use std::rc::Rc;
use std::str::{FromStr, ParseBoolError};
use std::thread;

use audio_streams::{SampleFormat, StreamSource};
use base::{error, warn, Error as SysError, Event, RawDescriptor};
use cros_async::sync::{Condvar, Mutex as AsyncMutex};
use cros_async::{select4, AsyncError, EventAsync, Executor, SelectResult};
use data_model::DataInit;
use futures::channel::mpsc;
use futures::{pin_mut, Future, TryFutureExt};
use libcras::{BoxError, CrasClient, CrasClientType, CrasSocketType};
use sys_util::{set_rt_prio_limit, set_rt_round_robin};
use thiserror::Error as ThisError;
use vm_memory::GuestMemory;

use crate::virtio::snd::common::*;
use crate::virtio::snd::constants::*;
use crate::virtio::snd::layout::*;
use crate::virtio::{
    copy_config, DescriptorChain, DescriptorError, Interrupt, Queue, VirtioDevice, TYPE_SOUND,
};

pub mod async_funcs;
use crate::virtio::snd::cras_backend::async_funcs::*;

// control + event + tx + rx queue
const NUM_QUEUES: usize = 4;
const QUEUE_SIZE: u16 = 1024;
const AUDIO_THREAD_RTPRIO: u16 = 10; // Matches other cros audio clients.

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
    /// Error reading message from queue.
    #[error("Failed to read message: {0}")]
    ReadMessage(io::Error),
    /// Failed writing a response to a control message.
    #[error("Failed to write message response: {0}")]
    WriteResponse(io::Error),
    /// Libcras error.
    #[error("Error in libcras: {0}")]
    Libcras(libcras::Error),
    // Mpsc read error.
    #[error("Error in mpsc: {0}")]
    MpscRead(futures::channel::mpsc::SendError),
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
    /// Failed to parse parameters.
    #[error("Invalid cras snd parameter: {0}")]
    UnknownParameter(String),
    /// Unknown cras snd parameter value.
    #[error("Invalid cras snd parameter value ({0}): {1}")]
    InvalidParameterValue(String, String),
    /// Failed to parse bool value.
    #[error("Invalid bool value: {0}")]
    InvalidBoolValue(ParseBoolError),
}

/// Holds the parameters for a cras sound device
#[derive(Debug, Clone)]
pub struct Parameters {
    pub capture: bool,
    pub client_type: CrasClientType,
    pub socket_type: CrasSocketType,
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters {
            capture: true,
            client_type: CrasClientType::CRAS_CLIENT_TYPE_CROSVM,
            socket_type: CrasSocketType::Unified,
        }
    }
}

impl FromStr for Parameters {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut params: Parameters = Default::default();
        let opts = s
            .split(',')
            .map(|frag| frag.split('='))
            .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

        for (k, v) in opts {
            match k {
                "capture" => {
                    params.capture = v.parse::<bool>().map_err(Error::InvalidBoolValue)?;
                }
                "client_type" => {
                    params.client_type = v.parse().map_err(|e: libcras::CrasSysError| {
                        Error::InvalidParameterValue(v.to_string(), e.to_string())
                    })?;
                }
                "socket_type" => {
                    params.socket_type = v.parse().map_err(|e: libcras::Error| {
                        Error::InvalidParameterValue(v.to_string(), e.to_string())
                    })?;
                }
                _ => {
                    return Err(Error::UnknownParameter(k.to_string()));
                }
            }
        }

        Ok(params)
    }
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
pub struct StreamInfo<'a> {
    client: Option<CrasClient<'a>>,
    channels: u8,
    format: SampleFormat,
    frame_rate: u32,
    buffer_bytes: usize,
    period_bytes: usize,
    direction: u8,
    state: u32, // VIRTIO_SND_R_PCM_SET_PARAMS -> VIRTIO_SND_R_PCM_STOP, or 0 (uninitialized)

    // Worker related
    status_mutex: Rc<AsyncMutex<WorkerStatus>>,
    cv: Rc<Condvar>,
    sender: Option<mpsc::UnboundedSender<DescriptorChain>>,
    worker_future: Option<Box<dyn Future<Output = Result<(), Error>> + Unpin>>,
}

impl Default for StreamInfo<'_> {
    fn default() -> Self {
        StreamInfo {
            client: None,
            channels: 0,
            format: SampleFormat::U8,
            frame_rate: 0,
            buffer_bytes: 0,
            period_bytes: 0,
            direction: 0,
            state: 0,
            status_mutex: Rc::new(AsyncMutex::new(WorkerStatus::Pause)),
            cv: Rc::new(Condvar::new()),
            sender: None,
            worker_future: None,
        }
    }
}

// Stores constant data
pub struct SndData {
    jack_info: Vec<virtio_snd_jack_info>,
    pcm_info: Vec<virtio_snd_pcm_info>,
    chmap_info: Vec<virtio_snd_chmap_info>,
}

const SUPPORTED_FORMATS: u64 = 1 << VIRTIO_SND_PCM_FMT_U8
    | 1 << VIRTIO_SND_PCM_FMT_S16
    | 1 << VIRTIO_SND_PCM_FMT_S24
    | 1 << VIRTIO_SND_PCM_FMT_S32;
const SUPPORTED_FRAME_RATES: u64 = 1 << VIRTIO_SND_PCM_RATE_8000
    | 1 << VIRTIO_SND_PCM_RATE_11025
    | 1 << VIRTIO_SND_PCM_RATE_16000
    | 1 << VIRTIO_SND_PCM_RATE_22050
    | 1 << VIRTIO_SND_PCM_RATE_44100
    | 1 << VIRTIO_SND_PCM_RATE_48000;

impl<'a> StreamInfo<'a> {
    async fn prepare(
        &mut self,
        ex: &Executor,
        mem: GuestMemory,
        tx_queue: &Rc<AsyncMutex<Queue>>,
        rx_queue: &Rc<AsyncMutex<Queue>>,
        interrupt: &Rc<Interrupt>,
        params: &Parameters,
    ) -> Result<(), Error> {
        if self.state != VIRTIO_SND_R_PCM_SET_PARAMS
            && self.state != VIRTIO_SND_R_PCM_PREPARE
            && self.state != VIRTIO_SND_R_PCM_RELEASE
        {
            error!(
                "Invalid PCM state transition from {} to {}",
                get_virtio_snd_r_pcm_cmd_name(self.state),
                get_virtio_snd_r_pcm_cmd_name(VIRTIO_SND_R_PCM_PREPARE)
            );
            return Err(Error::OperationNotSupported);
        }
        let frame_size = self.channels as usize * self.format.sample_bytes();
        if self.period_bytes % frame_size != 0 {
            error!("period_bytes must be divisible by frame size");
            return Err(Error::OperationNotSupported);
        }
        if self.client.is_none() {
            let mut client = CrasClient::with_type(params.socket_type).map_err(Error::Libcras)?;
            if params.capture {
                client.enable_cras_capture();
            }
            client.set_client_type(params.client_type);
            self.client = Some(client);
        }
        // (*)
        // `buffer_size` in `audio_streams` API indicates the buffer size in bytes that the stream
        // consumes (or transmits) each time (next_playback/capture_buffer).
        // `period_bytes` in virtio-snd device (or ALSA) indicates the device transmits (or
        // consumes) for each PCM message.
        // Therefore, `buffer_size` in `audio_streams` == `period_bytes` in virtio-snd.
        let (stream, pcm_queue) = match self.direction {
            VIRTIO_SND_D_OUTPUT => (
                DirectionalStream::Output(
                    self.client
                        .as_mut()
                        .unwrap()
                        .new_async_playback_stream(
                            self.channels as usize,
                            self.format,
                            self.frame_rate,
                            // See (*)
                            self.period_bytes / frame_size,
                            &ex,
                        )
                        .map_err(Error::CreateStream)?
                        .1,
                ),
                tx_queue.clone(),
            ),
            VIRTIO_SND_D_INPUT => {
                (
                    DirectionalStream::Input(
                        self.client
                            .as_mut()
                            .unwrap()
                            .new_async_capture_stream(
                                self.channels as usize,
                                self.format,
                                self.frame_rate,
                                // See (*)
                                self.period_bytes / frame_size,
                                &[],
                                &ex,
                            )
                            .map_err(Error::CreateStream)?
                            .1,
                    ),
                    rx_queue.clone(),
                )
            }
            _ => unreachable!(),
        };

        let (sender, receiver) = mpsc::unbounded();
        self.sender = Some(sender);
        self.state = VIRTIO_SND_R_PCM_PREPARE;

        self.status_mutex = Rc::new(AsyncMutex::new(WorkerStatus::Pause));
        self.cv = Rc::new(Condvar::new());
        let f = start_pcm_worker(
            ex.clone(),
            stream,
            receiver,
            self.status_mutex.clone(),
            self.cv.clone(),
            mem,
            pcm_queue,
            interrupt.clone(),
            self.period_bytes,
        );
        self.worker_future = Some(Box::new(ex.spawn_local(f).into_future()));
        Ok(())
    }

    async fn start(&mut self) -> Result<(), Error> {
        if self.state != VIRTIO_SND_R_PCM_PREPARE && self.state != VIRTIO_SND_R_PCM_STOP {
            error!(
                "Invalid PCM state transition from {} to {}",
                get_virtio_snd_r_pcm_cmd_name(self.state),
                get_virtio_snd_r_pcm_cmd_name(VIRTIO_SND_R_PCM_START)
            );
            return Err(Error::OperationNotSupported);
        }
        self.state = VIRTIO_SND_R_PCM_START;
        *self.status_mutex.lock().await = WorkerStatus::Running;
        self.cv.notify_one();
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), Error> {
        if self.state != VIRTIO_SND_R_PCM_START {
            error!(
                "Invalid PCM state transition from {} to {}",
                get_virtio_snd_r_pcm_cmd_name(self.state),
                get_virtio_snd_r_pcm_cmd_name(VIRTIO_SND_R_PCM_STOP)
            );
            return Err(Error::OperationNotSupported);
        }
        self.state = VIRTIO_SND_R_PCM_STOP;
        *self.status_mutex.lock().await = WorkerStatus::Pause;
        self.cv.notify_one();
        Ok(())
    }

    async fn release(&mut self) -> Result<(), Error> {
        if self.state != VIRTIO_SND_R_PCM_PREPARE && self.state != VIRTIO_SND_R_PCM_STOP {
            error!(
                "Invalid PCM state transition from {} to {}",
                get_virtio_snd_r_pcm_cmd_name(self.state),
                get_virtio_snd_r_pcm_cmd_name(VIRTIO_SND_R_PCM_RELEASE)
            );
            return Err(Error::OperationNotSupported);
        }
        self.state = VIRTIO_SND_R_PCM_RELEASE;
        self.release_worker().await?;
        self.client = None;
        Ok(())
    }

    async fn release_worker(&mut self) -> Result<(), Error> {
        *self.status_mutex.lock().await = WorkerStatus::Quit;
        self.cv.notify_one();
        match self.sender.take() {
            Some(s) => s.close_channel(),
            None => (),
        }
        match self.worker_future.take() {
            Some(f) => f.await?,
            None => (),
        }
        Ok(())
    }
}

pub struct VirtioSndCras {
    cfg: virtio_snd_config,
    avail_features: u64,
    acked_features: u64,
    queue_sizes: Box<[u16]>,
    worker_threads: Vec<thread::JoinHandle<()>>,
    kill_evt: Option<Event>,
    params: Parameters,
}

impl VirtioSndCras {
    pub fn new(base_features: u64, params: Parameters) -> Result<VirtioSndCras, Error> {
        let cfg = virtio_snd_config {
            jacks: 0.into(),
            streams: 2.into(),
            chmaps: 2.into(),
        };

        let avail_features = base_features;

        Ok(VirtioSndCras {
            cfg,
            avail_features,
            acked_features: 0,
            queue_sizes: vec![QUEUE_SIZE; NUM_QUEUES].into_boxed_slice(),
            worker_threads: Vec::new(),
            kill_evt: None,
            params,
        })
    }
}

impl VirtioDevice for VirtioSndCras {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn device_type(&self) -> u32 {
        TYPE_SOUND
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

        let mut jack_info: Vec<virtio_snd_jack_info> = Vec::new();
        let mut pcm_info: Vec<virtio_snd_pcm_info> = Vec::new();
        let mut chmap_info: Vec<virtio_snd_chmap_info> = Vec::new();

        for i in 0..Into::<u32>::into(self.cfg.jacks) {
            let snd_info = virtio_snd_info {
                hda_fn_nid: i.into(),
            };
            // TODO(woodychow): Remove this hack
            // Assume this single device for now
            jack_info.push(virtio_snd_jack_info {
                hdr: snd_info,
                features: 0.into(),
                hda_reg_defconf: 0.into(),
                hda_reg_caps: 0.into(),
                connected: 0,
                padding: [0; 7],
            });
        }

        // for _ in 0..(Into::<u32>::into(self.cfg.streams) as usize) {
        // TODO(woodychow): Remove this hack
        // Assume this single device for now
        pcm_info.push(virtio_snd_pcm_info {
            hdr: virtio_snd_info {
                hda_fn_nid: 0.into(),
            },
            features: 0.into(), /* 1 << VIRTIO_SND_PCM_F_XXX */
            formats: SUPPORTED_FORMATS.into(),
            rates: SUPPORTED_FRAME_RATES.into(),
            direction: VIRTIO_SND_D_OUTPUT,
            channels_min: 1,
            channels_max: 2,
            padding: [0; 5],
        });
        pcm_info.push(virtio_snd_pcm_info {
            hdr: virtio_snd_info {
                hda_fn_nid: 0.into(),
            },
            features: 0.into(), /* 1 << VIRTIO_SND_PCM_F_XXX */
            formats: SUPPORTED_FORMATS.into(),
            rates: SUPPORTED_FRAME_RATES.into(),
            direction: VIRTIO_SND_D_INPUT,
            channels_min: 1,
            channels_max: 2,
            padding: [0; 5],
        });
        // }

        // for _ in 0..(Into::<u32>::into(self.cfg.chmaps) as usize) {

        // Use stereo channel map.
        let mut positions = [VIRTIO_SND_CHMAP_NONE; VIRTIO_SND_CHMAP_MAX_SIZE];
        positions[0] = VIRTIO_SND_CHMAP_FL;
        positions[1] = VIRTIO_SND_CHMAP_FR;

        chmap_info.push(virtio_snd_chmap_info {
            hdr: virtio_snd_info {
                hda_fn_nid: 0.into(),
            },
            direction: VIRTIO_SND_D_OUTPUT,
            channels: 2,
            positions,
        });
        chmap_info.push(virtio_snd_chmap_info {
            hdr: virtio_snd_info {
                hda_fn_nid: 0.into(),
            },
            direction: VIRTIO_SND_D_INPUT,
            channels: 2,
            positions,
        });
        // }

        let params = self.params.clone();

        let worker_result = thread::Builder::new()
            .name("virtio_snd w".to_string())
            .spawn(move || {
                if let Err(e) = set_rt_prio_limit(u64::from(AUDIO_THREAD_RTPRIO))
                    .and_then(|_| set_rt_round_robin(i32::from(AUDIO_THREAD_RTPRIO)))
                {
                    warn!("Failed to set audio thread to real time: {}", e);
                }

                let mut streams: Vec<AsyncMutex<StreamInfo>> = Vec::new();
                streams.resize_with(pcm_info.len(), Default::default);

                let streams = Rc::new(AsyncMutex::new(streams));

                let snd_data = SndData {
                    jack_info,
                    pcm_info,
                    chmap_info,
                };

                if let Err(err_string) = run_worker(
                    interrupt, queues, guest_mem, streams, snd_data, queue_evts, kill_evt, params,
                ) {
                    error!("{}", err_string);
                }
            });

        match worker_result {
            Err(e) => {
                error!("failed to spawn virtio_snd worker: {}", e);
                return;
            }
            Ok(join_handle) => self.worker_threads.push(join_handle),
        }
    }

    fn reset(&mut self) -> bool {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        true
    }
}

impl Drop for VirtioSndCras {
    fn drop(&mut self) {
        self.reset();
    }
}

fn run_worker(
    interrupt: Interrupt,
    mut queues: Vec<Queue>,
    mem: GuestMemory,
    streams: Rc<AsyncMutex<Vec<AsyncMutex<StreamInfo<'_>>>>>,
    snd_data: SndData,
    queue_evts: Vec<Event>,
    kill_evt: Event,
    params: Parameters,
) -> Result<(), String> {
    let ex = Executor::new().expect("Failed to create an executor");

    let interrupt = Rc::new(interrupt);

    let ctrl_queue = queues.remove(0);
    let _event_queue = queues.remove(0);
    let tx_queue = Rc::new(AsyncMutex::new(queues.remove(0)));
    let rx_queue = Rc::new(AsyncMutex::new(queues.remove(0)));

    let mut evts_async: Vec<EventAsync> = queue_evts
        .into_iter()
        .map(|e| EventAsync::new(e.0, &ex).expect("Failed to create async event for queue"))
        .collect();

    let ctrl_queue_evt = evts_async.remove(0);
    let _event_queue_evt = evts_async.remove(0);
    let tx_queue_evt = evts_async.remove(0);
    let rx_queue_evt = evts_async.remove(0);

    let f_ctrl = handle_ctrl_queue(
        &ex,
        &mem,
        &streams,
        &snd_data,
        ctrl_queue,
        ctrl_queue_evt,
        &interrupt,
        &tx_queue,
        &rx_queue,
        &params,
    );
    pin_mut!(f_ctrl);

    // TODO(woodychow): Enable this when libcras sends jack connect/disconnect evts
    // let f_event = handle_event_queue(
    //     &mem,
    //     snd_state,
    //     event_queue,
    //     event_queue_evt,
    //     interrupt,
    // );
    // pin_mut!(f_event);

    let f_tx = handle_pcm_queue(&mem, &streams, &tx_queue, tx_queue_evt, &interrupt);
    pin_mut!(f_tx);

    let f_rx = handle_pcm_queue(&mem, &streams, &rx_queue, rx_queue_evt, &interrupt);
    pin_mut!(f_rx);

    // Exit if the kill event is triggered.
    let kill_evt = EventAsync::new(kill_evt.0, &ex).expect("failed to set up the kill event");
    let f_kill = wait_kill(kill_evt);
    pin_mut!(f_kill);

    match ex.run_until(select4(f_ctrl, f_tx, f_rx, f_kill)) {
        Ok((ctrl_res, tx_res, rx_res, _kill_res)) => {
            if let SelectResult::Finished(Err(e)) = ctrl_res {
                return Err(format!("Error in handling ctrl queue: {}", e));
            }
            if let SelectResult::Finished(Err(e)) = tx_res {
                return Err(format!("Error in handling tx queue: {}", e));
            }
            if let SelectResult::Finished(Err(e)) = rx_res {
                return Err(format!("Error in handling rx queue: {}", e));
            }
        }
        Err(e) => {
            error!("Error happened in executor: {}", e);
        }
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parameters_fromstr() {
        fn check_success(
            s: &str,
            capture: bool,
            client_type: CrasClientType,
            socket_type: CrasSocketType,
        ) {
            let params = s.parse::<Parameters>().expect("parse should have succeded");
            assert_eq!(params.capture, capture);
            assert_eq!(params.client_type, client_type);
            assert_eq!(params.socket_type, socket_type);
        }
        fn check_failure(s: &str) {
            s.parse::<Parameters>()
                .expect_err("parse should have failed");
        }

        check_success(
            "capture=false",
            false,
            CrasClientType::CRAS_CLIENT_TYPE_CROSVM,
            CrasSocketType::Unified,
        );
        check_success(
            "capture=true,client_type=crosvm",
            true,
            CrasClientType::CRAS_CLIENT_TYPE_CROSVM,
            CrasSocketType::Unified,
        );
        check_success(
            "capture=true,client_type=arcvm",
            true,
            CrasClientType::CRAS_CLIENT_TYPE_ARCVM,
            CrasSocketType::Unified,
        );
        check_failure("capture=true,client_type=none");
        check_success(
            "socket_type=legacy",
            true,
            CrasClientType::CRAS_CLIENT_TYPE_CROSVM,
            CrasSocketType::Legacy,
        );
        check_success(
            "socket_type=unified",
            true,
            CrasClientType::CRAS_CLIENT_TYPE_CROSVM,
            CrasSocketType::Unified,
        );
    }
}
