// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use audio_streams::SampleFormat;
use audio_streams::StreamEffect;
use base::error;
use base::warn;
use cros_async::sync::Condvar;
use cros_async::sync::RwLock as AsyncRwLock;
use cros_async::Executor;
use futures::channel::mpsc;
use futures::Future;
use futures::TryFutureExt;
use serde::Deserialize;
use serde::Serialize;

use super::Error;
use super::PcmResponse;
use super::WorkerStatus;
use crate::virtio::snd::common::*;
use crate::virtio::snd::common_backend::async_funcs::*;
use crate::virtio::snd::common_backend::DirectionalStream;
use crate::virtio::snd::common_backend::SysAsyncStreamObjects;
use crate::virtio::snd::constants::*;
use crate::virtio::snd::sys::SysAudioStreamSource;
use crate::virtio::snd::sys::SysAudioStreamSourceGenerator;
use crate::virtio::DescriptorChain;

/// Parameters for setting parameters in StreamInfo
#[derive(Copy, Clone, Debug)]
pub struct SetParams {
    pub channels: u8,
    pub format: SampleFormat,
    pub frame_rate: u32,
    pub buffer_bytes: usize,
    pub period_bytes: usize,
    pub dir: u8,
}

/// StreamInfoBuilder builds a [`StreamInfo`]. It is used when we want to store the parameters to
/// create a [`StreamInfo`] beforehand and actually create it later. (as is the case with VirtioSnd)
///
/// To create a new StreamInfoBuilder, see [`StreamInfo::builder()`].
#[derive(Clone)]
pub struct StreamInfoBuilder {
    stream_source_generator: Arc<SysAudioStreamSourceGenerator>,
    effects: Vec<StreamEffect>,
    #[cfg(windows)]
    audio_client_guid: Option<String>,
}

impl StreamInfoBuilder {
    /// Creates a StreamInfoBuilder with minimal required fields:
    ///
    /// * `stream_source_generator`: Generator which generates stream source in
    ///   [`StreamInfo::prepare()`].
    pub fn new(stream_source_generator: Arc<SysAudioStreamSourceGenerator>) -> Self {
        StreamInfoBuilder {
            stream_source_generator,
            effects: vec![],
            #[cfg(windows)]
            audio_client_guid: None,
        }
    }

    /// Set the [`StreamEffect`]s to use when creating a stream from the stream source in
    /// [`StreamInfo::prepare()`]. The default value is no effects.
    pub fn effects(mut self, effects: Vec<StreamEffect>) -> Self {
        self.effects = effects;
        self
    }

    #[cfg(windows)]
    pub fn audio_client_guid(mut self, audio_client_guid: Option<String>) -> Self {
        self.audio_client_guid = audio_client_guid;
        self
    }

    /// Builds a [`StreamInfo`].
    pub fn build(self) -> StreamInfo {
        self.into()
    }
}

/// StreamInfo represents a virtio snd stream.
///
/// To create a StreamInfo, see [`StreamInfo::builder()`] and [`StreamInfoBuilder::build()`].
pub struct StreamInfo {
    pub(crate) stream_source: Option<SysAudioStreamSource>,
    stream_source_generator: Arc<SysAudioStreamSourceGenerator>,
    pub(crate) channels: u8,
    pub(crate) format: SampleFormat,
    pub(crate) frame_rate: u32,
    buffer_bytes: usize,
    pub(crate) period_bytes: usize,
    direction: u8,  // VIRTIO_SND_D_*
    pub state: u32, // VIRTIO_SND_R_PCM_SET_PARAMS -> VIRTIO_SND_R_PCM_STOP, or 0 (uninitialized)
    // Stream effects to use when creating a new stream on [`prepare()`].
    pub(crate) effects: Vec<StreamEffect>,

    // just_reset set to true after reset. Make invalid state transition return Ok. Set to false
    // after a valid state transition to SET_PARAMS or PREPARE.
    pub just_reset: bool,

    // Worker related
    pub status_mutex: Rc<AsyncRwLock<WorkerStatus>>,
    pub sender: Option<mpsc::UnboundedSender<DescriptorChain>>,
    worker_future: Option<Box<dyn Future<Output = Result<(), Error>> + Unpin>>,
    release_signal: Option<Rc<(AsyncRwLock<bool>, Condvar)>>, // Signal worker on release
    ex: Option<Executor>, // Executor provided on `prepare()`. Used on `drop()`.
    #[cfg(windows)]
    pub(crate) playback_stream_cache: Option<(
        Arc<AsyncRwLock<Box<dyn audio_streams::AsyncPlaybackBufferStream>>>,
        Rc<AsyncRwLock<Box<dyn PlaybackBufferWriter>>>,
    )>,
    #[cfg(windows)]
    pub(crate) audio_client_guid: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StreamInfoSnapshot {
    pub(crate) channels: u8,
    pub(crate) format: SampleFormat,
    pub(crate) frame_rate: u32,
    buffer_bytes: usize,
    pub(crate) period_bytes: usize,
    direction: u8,  // VIRTIO_SND_D_*
    pub state: u32, // VIRTIO_SND_R_PCM_SET_PARAMS -> VIRTIO_SND_R_PCM_STOP, or 0 (uninitialized)
    effects: Vec<StreamEffect>,
    pub just_reset: bool,
}

impl fmt::Debug for StreamInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamInfo")
            .field("channels", &self.channels)
            .field("format", &self.format)
            .field("frame_rate", &self.frame_rate)
            .field("buffer_bytes", &self.buffer_bytes)
            .field("period_bytes", &self.period_bytes)
            .field("direction", &get_virtio_direction_name(self.direction))
            .field("state", &get_virtio_snd_r_pcm_cmd_name(self.state))
            .field("effects", &self.effects)
            .finish()
    }
}

impl Drop for StreamInfo {
    fn drop(&mut self) {
        if let Some(ex) = self.ex.take() {
            if self.state == VIRTIO_SND_R_PCM_START {
                match ex.run_until(self.stop()) {
                    Err(e) => error!("Drop stream error on stop in executor: {}", e),
                    Ok(Err(e)) => error!("Drop stream error on stop: {}", e),
                    _ => {}
                }
            }
            if self.state == VIRTIO_SND_R_PCM_PREPARE || self.state == VIRTIO_SND_R_PCM_STOP {
                match ex.run_until(self.release()) {
                    Err(e) => error!("Drop stream error on release in executor: {}", e),
                    Ok(Err(e)) => error!("Drop stream error on release: {}", e),
                    _ => {}
                }
            }
        }
    }
}

impl From<StreamInfoBuilder> for StreamInfo {
    fn from(builder: StreamInfoBuilder) -> Self {
        StreamInfo {
            stream_source: None,
            stream_source_generator: builder.stream_source_generator,
            channels: 0,
            format: SampleFormat::U8,
            frame_rate: 0,
            buffer_bytes: 0,
            period_bytes: 0,
            direction: 0,
            state: 0,
            effects: builder.effects,
            just_reset: false,
            status_mutex: Rc::new(AsyncRwLock::new(WorkerStatus::Pause)),
            sender: None,
            worker_future: None,
            release_signal: None,
            ex: None,
            #[cfg(windows)]
            playback_stream_cache: None,
            #[cfg(windows)]
            audio_client_guid: None,
        }
    }
}

impl StreamInfo {
    /// Creates a minimal [`StreamInfoBuilder`]. See [`StreamInfoBuilder::new()`] for
    /// the description of each parameter.
    pub fn builder(
        stream_source_generator: Arc<SysAudioStreamSourceGenerator>,
    ) -> StreamInfoBuilder {
        StreamInfoBuilder::new(stream_source_generator)
    }

    /// Sets parameters of the stream, putting it into [`VIRTIO_SND_R_PCM_SET_PARAMS`] state.
    ///
    /// * `params`: [`SetParams`] for the pcm stream runtime configuration.
    pub async fn set_params(&mut self, params: SetParams) -> Result<(), Error> {
        if self.state != 0
            && self.state != VIRTIO_SND_R_PCM_SET_PARAMS
            && self.state != VIRTIO_SND_R_PCM_PREPARE
            && self.state != VIRTIO_SND_R_PCM_RELEASE
        {
            error!(
                "Invalid PCM state transition from {} to {}",
                get_virtio_snd_r_pcm_cmd_name(self.state),
                get_virtio_snd_r_pcm_cmd_name(VIRTIO_SND_R_PCM_SET_PARAMS)
            );
            return Err(Error::OperationNotSupported);
        }

        // Only required for PREPARE -> SET_PARAMS
        self.release_worker().await;

        self.channels = params.channels;
        self.format = params.format;
        self.frame_rate = params.frame_rate;
        self.buffer_bytes = params.buffer_bytes;
        self.period_bytes = params.period_bytes;
        self.direction = params.dir;
        self.state = VIRTIO_SND_R_PCM_SET_PARAMS;
        self.just_reset = false;
        Ok(())
    }

    /// Prepares the stream, putting it into [`VIRTIO_SND_R_PCM_PREPARE`] state.
    ///
    /// * `ex`: [`Executor`] to run the pcm worker.
    /// * `tx_send`: Sender for sending `PcmResponse` for tx queue. (playback stream)
    /// * `rx_send`: Sender for sending `PcmResponse` for rx queue. (capture stream)
    pub async fn prepare(
        &mut self,
        ex: &Executor,
        tx_send: &mpsc::UnboundedSender<PcmResponse>,
        rx_send: &mpsc::UnboundedSender<PcmResponse>,
    ) -> Result<(), Error> {
        if self.state == 0 && self.just_reset {
            return Ok(());
        }
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
        self.just_reset = false;
        if self.state == VIRTIO_SND_R_PCM_PREPARE {
            self.release_worker().await;
        }
        let frame_size = self.channels as usize * self.format.sample_bytes();
        if self.period_bytes % frame_size != 0 {
            error!("period_bytes must be divisible by frame size");
            return Err(Error::OperationNotSupported);
        }
        self.stream_source = Some(
            self.stream_source_generator
                .generate()
                .map_err(Error::GenerateStreamSource)?,
        );
        let stream_objects = match self.direction {
            VIRTIO_SND_D_OUTPUT => SysAsyncStreamObjects {
                stream: self
                    .create_directionstream_output(
                        frame_size,
                        #[cfg(windows)]
                        self.audio_client_guid.clone(),
                        ex,
                    )
                    .await?,
                pcm_sender: tx_send.clone(),
            },
            VIRTIO_SND_D_INPUT => {
                let buffer_reader = self.set_up_async_capture_stream(frame_size, ex).await?;
                SysAsyncStreamObjects {
                    stream: DirectionalStream::Input(self.period_bytes, Box::new(buffer_reader)),
                    pcm_sender: rx_send.clone(),
                }
            }
            _ => unreachable!(),
        };

        let (sender, receiver) = mpsc::unbounded();
        self.sender = Some(sender);
        self.state = VIRTIO_SND_R_PCM_PREPARE;

        self.status_mutex = Rc::new(AsyncRwLock::new(WorkerStatus::Pause));
        let period_dur = Duration::from_secs_f64(
            self.period_bytes as f64 / frame_size as f64 / self.frame_rate as f64,
        );
        let release_signal = Rc::new((AsyncRwLock::new(false), Condvar::new()));
        self.release_signal = Some(release_signal.clone());
        let f = start_pcm_worker(
            ex.clone(),
            stream_objects.stream,
            receiver,
            self.status_mutex.clone(),
            stream_objects.pcm_sender,
            period_dur,
            release_signal,
        );
        self.worker_future = Some(Box::new(ex.spawn_local(f).into_future()));
        self.ex = Some(ex.clone());
        Ok(())
    }

    /// Starts the stream, putting it into [`VIRTIO_SND_R_PCM_START`] state.
    pub async fn start(&mut self) -> Result<(), Error> {
        if self.just_reset {
            return Ok(());
        }
        if self.state != VIRTIO_SND_R_PCM_PREPARE && self.state != VIRTIO_SND_R_PCM_STOP {
            error!(
                "Invalid PCM state transition from {} to {}",
                get_virtio_snd_r_pcm_cmd_name(self.state),
                get_virtio_snd_r_pcm_cmd_name(VIRTIO_SND_R_PCM_START)
            );
            return Err(Error::OperationNotSupported);
        }
        self.state = VIRTIO_SND_R_PCM_START;
        let mut status = self.status_mutex.lock().await;
        if *status != WorkerStatus::Quit {
            *status = WorkerStatus::Running;
        }
        Ok(())
    }

    /// Stops the stream, putting it into [`VIRTIO_SND_R_PCM_STOP`] state.
    pub async fn stop(&mut self) -> Result<(), Error> {
        if self.just_reset {
            return Ok(());
        }
        if self.state != VIRTIO_SND_R_PCM_START {
            error!(
                "Invalid PCM state transition from {} to {}",
                get_virtio_snd_r_pcm_cmd_name(self.state),
                get_virtio_snd_r_pcm_cmd_name(VIRTIO_SND_R_PCM_STOP)
            );
            return Err(Error::OperationNotSupported);
        }
        self.state = VIRTIO_SND_R_PCM_STOP;
        let mut status = self.status_mutex.lock().await;
        if *status != WorkerStatus::Quit {
            *status = WorkerStatus::Pause;
        }
        Ok(())
    }

    /// Releases the stream, putting it into [`VIRTIO_SND_R_PCM_RELEASE`] state.
    pub async fn release(&mut self) -> Result<(), Error> {
        if self.just_reset {
            return Ok(());
        }
        if self.state != VIRTIO_SND_R_PCM_PREPARE && self.state != VIRTIO_SND_R_PCM_STOP {
            error!(
                "Invalid PCM state transition from {} to {}",
                get_virtio_snd_r_pcm_cmd_name(self.state),
                get_virtio_snd_r_pcm_cmd_name(VIRTIO_SND_R_PCM_RELEASE)
            );
            return Err(Error::OperationNotSupported);
        }
        self.state = VIRTIO_SND_R_PCM_RELEASE;
        self.stream_source = None;
        self.release_worker().await;
        Ok(())
    }

    async fn release_worker(&mut self) {
        *self.status_mutex.lock().await = WorkerStatus::Quit;
        if let Some(s) = self.sender.take() {
            s.close_channel();
        }

        if let Some(release_signal) = self.release_signal.take() {
            let (lock, cvar) = &*release_signal;
            let mut signalled = lock.lock().await;
            *signalled = true;
            cvar.notify_all();
        }

        if let Some(f) = self.worker_future.take() {
            f.await
                .map_err(|error| warn!("Failure on releasing the worker_future: {}", error))
                .ok();
        }
        self.ex.take(); // Remove ex as the worker is finished
    }

    pub fn snapshot(&self) -> StreamInfoSnapshot {
        StreamInfoSnapshot {
            channels: self.channels,
            format: self.format,
            frame_rate: self.frame_rate,
            buffer_bytes: self.buffer_bytes,
            period_bytes: self.period_bytes,
            direction: self.direction, // VIRTIO_SND_D_*
            // VIRTIO_SND_R_PCM_SET_PARAMS -> VIRTIO_SND_R_PCM_STOP, or 0 (uninitialized)
            state: self.state,
            effects: self.effects.clone(),
            just_reset: self.just_reset,
        }
    }

    pub fn restore(&mut self, state: &StreamInfoSnapshot) {
        self.channels = state.channels;
        self.format = state.format;
        self.frame_rate = state.frame_rate;
        self.buffer_bytes = state.buffer_bytes;
        self.period_bytes = state.period_bytes;
        self.direction = state.direction;
        self.effects = state.effects.clone();
        self.just_reset = state.just_reset;
    }
}

#[cfg(test)]
mod tests {
    use audio_streams::NoopStreamSourceGenerator;

    use super::*;

    fn new_stream() -> StreamInfo {
        StreamInfo::builder(Arc::new(Box::new(NoopStreamSourceGenerator::new()))).build()
    }

    fn stream_set_params(
        mut stream: StreamInfo,
        ex: &Executor,
        expected_ok: bool,
        expected_state: u32,
    ) -> StreamInfo {
        let result = ex.run_until(stream.set_params(SetParams {
            channels: 2,
            format: SampleFormat::U8,
            frame_rate: 48000,
            buffer_bytes: 1024,
            period_bytes: 512,
            dir: VIRTIO_SND_D_OUTPUT,
        }));
        assert_eq!(result.unwrap().is_ok(), expected_ok);
        assert_eq!(stream.state, expected_state);
        stream
    }

    fn stream_prepare(
        mut stream: StreamInfo,
        ex: &Executor,
        expected_ok: bool,
        expected_state: u32,
    ) -> StreamInfo {
        let (tx_send, _) = mpsc::unbounded();
        let (rx_send, _) = mpsc::unbounded();

        let result = ex.run_until(stream.prepare(ex, &tx_send, &rx_send));
        assert_eq!(result.unwrap().is_ok(), expected_ok);
        assert_eq!(stream.state, expected_state);
        stream
    }

    fn stream_start(
        mut stream: StreamInfo,
        ex: &Executor,
        expected_ok: bool,
        expected_state: u32,
    ) -> StreamInfo {
        let result = ex.run_until(stream.start());
        assert_eq!(result.unwrap().is_ok(), expected_ok);
        assert_eq!(stream.state, expected_state);
        stream
    }

    fn stream_stop(
        mut stream: StreamInfo,
        ex: &Executor,
        expected_ok: bool,
        expected_state: u32,
    ) -> StreamInfo {
        let result = ex.run_until(stream.stop());
        assert_eq!(result.unwrap().is_ok(), expected_ok);
        assert_eq!(stream.state, expected_state);
        stream
    }

    fn stream_release(
        mut stream: StreamInfo,
        ex: &Executor,
        expected_ok: bool,
        expected_state: u32,
    ) -> StreamInfo {
        let result = ex.run_until(stream.release());
        assert_eq!(result.unwrap().is_ok(), expected_ok);
        assert_eq!(stream.state, expected_state);
        stream
    }

    #[test]
    fn test_transitions_from_0() {
        let ex = Executor::new().expect("Failed to create an executor");

        // Valid transition to: {SET_PARAMS}
        stream_set_params(new_stream(), &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS);

        // Invalid transition to: {PREPARE, START, STOP, RELEASE}
        stream_prepare(new_stream(), &ex, false, 0);
        stream_start(new_stream(), &ex, false, 0);
        stream_stop(new_stream(), &ex, false, 0);
        stream_release(new_stream(), &ex, false, 0);
    }

    #[test]
    fn test_transitions_from_set_params() {
        let ex = Executor::new().expect("Failed to create an executor");
        let new_stream_set_params = || -> StreamInfo {
            stream_set_params(new_stream(), &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS)
        };

        // Valid transition to: {SET_PARAMS, PREPARE}
        stream_set_params(
            new_stream_set_params(),
            &ex,
            true,
            VIRTIO_SND_R_PCM_SET_PARAMS,
        );
        stream_prepare(new_stream_set_params(), &ex, true, VIRTIO_SND_R_PCM_PREPARE);

        // Invalid transition to: {START, STOP, RELEASE}
        stream_start(
            new_stream_set_params(),
            &ex,
            false,
            VIRTIO_SND_R_PCM_SET_PARAMS,
        );
        stream_stop(
            new_stream_set_params(),
            &ex,
            false,
            VIRTIO_SND_R_PCM_SET_PARAMS,
        );
        stream_release(
            new_stream_set_params(),
            &ex,
            false,
            VIRTIO_SND_R_PCM_SET_PARAMS,
        );
    }

    #[test]
    fn test_transitions_from_prepare() {
        let ex = Executor::new().expect("Failed to create an executor");
        let new_stream_prepare = || -> StreamInfo {
            let stream = stream_set_params(new_stream(), &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS);
            stream_prepare(stream, &ex, true, VIRTIO_SND_R_PCM_PREPARE)
        };

        // Valid transition to: {SET_PARAMS, PREPARE, START, RELEASE}
        stream_set_params(new_stream_prepare(), &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS);
        stream_prepare(new_stream_prepare(), &ex, true, VIRTIO_SND_R_PCM_PREPARE);
        stream_start(new_stream_prepare(), &ex, true, VIRTIO_SND_R_PCM_START);
        stream_release(new_stream_prepare(), &ex, true, VIRTIO_SND_R_PCM_RELEASE);

        // Invalid transition to: {STOP}
        stream_stop(new_stream_prepare(), &ex, false, VIRTIO_SND_R_PCM_PREPARE);
    }

    #[test]
    fn test_transitions_from_start() {
        let ex = Executor::new().expect("Failed to create an executor");
        let new_stream_start = || -> StreamInfo {
            let mut stream =
                stream_set_params(new_stream(), &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS);
            stream = stream_prepare(stream, &ex, true, VIRTIO_SND_R_PCM_PREPARE);
            stream_start(stream, &ex, true, VIRTIO_SND_R_PCM_START)
        };

        // Valid transition to: {STOP}
        stream_stop(new_stream_start(), &ex, true, VIRTIO_SND_R_PCM_STOP);

        // Invalid transition to: {SET_PARAMS, PREPARE, START, RELEASE}
        stream_set_params(new_stream_start(), &ex, false, VIRTIO_SND_R_PCM_START);
        stream_prepare(new_stream_start(), &ex, false, VIRTIO_SND_R_PCM_START);
        stream_start(new_stream_start(), &ex, false, VIRTIO_SND_R_PCM_START);
        stream_release(new_stream_start(), &ex, false, VIRTIO_SND_R_PCM_START);
    }

    #[test]
    fn test_transitions_from_stop() {
        let ex = Executor::new().expect("Failed to create an executor");
        let new_stream_stop = || -> StreamInfo {
            let mut stream =
                stream_set_params(new_stream(), &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS);
            stream = stream_prepare(stream, &ex, true, VIRTIO_SND_R_PCM_PREPARE);
            stream = stream_start(stream, &ex, true, VIRTIO_SND_R_PCM_START);
            stream_stop(stream, &ex, true, VIRTIO_SND_R_PCM_STOP)
        };

        // Valid transition to: {START, RELEASE}
        stream_start(new_stream_stop(), &ex, true, VIRTIO_SND_R_PCM_START);
        stream_release(new_stream_stop(), &ex, true, VIRTIO_SND_R_PCM_RELEASE);

        // Invalid transition to: {SET_PARAMS, PREPARE, STOP}
        stream_set_params(new_stream_stop(), &ex, false, VIRTIO_SND_R_PCM_STOP);
        stream_prepare(new_stream_stop(), &ex, false, VIRTIO_SND_R_PCM_STOP);
        stream_stop(new_stream_stop(), &ex, false, VIRTIO_SND_R_PCM_STOP);
    }

    #[test]
    fn test_transitions_from_release() {
        let ex = Executor::new().expect("Failed to create an executor");
        let new_stream_release = || -> StreamInfo {
            let mut stream =
                stream_set_params(new_stream(), &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS);
            stream = stream_prepare(stream, &ex, true, VIRTIO_SND_R_PCM_PREPARE);
            stream_release(stream, &ex, true, VIRTIO_SND_R_PCM_RELEASE)
        };

        // Valid transition to: {SET_PARAMS, PREPARE}
        stream_set_params(new_stream_release(), &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS);
        stream_prepare(new_stream_release(), &ex, true, VIRTIO_SND_R_PCM_PREPARE);

        // Invalid transition to: {START, STOP, RELEASE}
        stream_start(new_stream_release(), &ex, false, VIRTIO_SND_R_PCM_RELEASE);
        stream_stop(new_stream_release(), &ex, false, VIRTIO_SND_R_PCM_RELEASE);
        stream_release(new_stream_release(), &ex, false, VIRTIO_SND_R_PCM_RELEASE);
    }

    #[test]
    fn test_transitions_from_0_just_reset() {
        let ex = Executor::new().expect("Failed to create an executor");
        let new_stream_0 = || -> StreamInfo {
            let mut stream = new_stream();
            stream.just_reset = true;
            stream
        };

        // Valid transition to: {SET_PARAMS}
        // After valid transition, just_reset reset to false
        let mut stream = new_stream_0();
        stream = stream_set_params(stream, &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS);
        assert_eq!(stream.just_reset, false);

        // Invalid transition to: {PREPARE, START, STOP, RELEASE}
        // Return Ok but state doesn't change
        stream_prepare(new_stream_0(), &ex, true, 0);
        stream_start(new_stream_0(), &ex, true, 0);
        stream_stop(new_stream_0(), &ex, true, 0);
        stream_release(new_stream_0(), &ex, true, 0);
    }

    #[test]
    fn test_transitions_from_set_params_just_reset() {
        let ex = Executor::new().expect("Failed to create an executor");
        let new_stream_set_params = || -> StreamInfo {
            let mut stream =
                stream_set_params(new_stream(), &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS);
            stream.just_reset = true;
            stream
        };

        // Valid transition to: {SET_PARAMS, PREPARE}
        // After valid transition, just_reset reset to false
        let mut stream = new_stream_set_params();
        stream = stream_set_params(stream, &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS);
        assert_eq!(stream.just_reset, false);

        let mut stream = new_stream_set_params();
        stream = stream_prepare(stream, &ex, true, VIRTIO_SND_R_PCM_PREPARE);
        assert_eq!(stream.just_reset, false);

        // Invalid transition to: {START, STOP, RELEASE}
        // Return Ok but state doesn't change
        stream_start(
            new_stream_set_params(),
            &ex,
            true,
            VIRTIO_SND_R_PCM_SET_PARAMS,
        );
        stream_stop(
            new_stream_set_params(),
            &ex,
            true,
            VIRTIO_SND_R_PCM_SET_PARAMS,
        );
        stream_release(
            new_stream_set_params(),
            &ex,
            true,
            VIRTIO_SND_R_PCM_SET_PARAMS,
        );
    }

    #[test]
    fn test_transitions_from_release_just_reset() {
        let ex = Executor::new().expect("Failed to create an executor");
        let new_stream_release = || -> StreamInfo {
            let mut stream =
                stream_set_params(new_stream(), &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS);
            stream = stream_prepare(stream, &ex, true, VIRTIO_SND_R_PCM_PREPARE);
            stream = stream_release(stream, &ex, true, VIRTIO_SND_R_PCM_RELEASE);
            stream.just_reset = true;
            stream
        };

        // Valid transition to: {SET_PARAMS, PREPARE}
        // After valid transition, just_reset reset to false
        let mut stream = new_stream_release();
        stream = stream_set_params(stream, &ex, true, VIRTIO_SND_R_PCM_SET_PARAMS);
        assert_eq!(stream.just_reset, false);

        let mut stream = new_stream_release();
        stream = stream_prepare(stream, &ex, true, VIRTIO_SND_R_PCM_PREPARE);
        assert_eq!(stream.just_reset, false);

        // Invalid transition to: {START, STOP, RELEASE}
        // Return Ok but state doesn't change
        stream_start(new_stream_release(), &ex, true, VIRTIO_SND_R_PCM_RELEASE);
        stream_stop(new_stream_release(), &ex, true, VIRTIO_SND_R_PCM_RELEASE);
        stream_release(new_stream_release(), &ex, true, VIRTIO_SND_R_PCM_RELEASE);
    }

    #[test]
    fn test_stream_info_builder() {
        let builder = StreamInfo::builder(Arc::new(Box::new(NoopStreamSourceGenerator::new())))
            .effects(vec![StreamEffect::EchoCancellation]);

        let stream = builder.build();
        assert_eq!(stream.effects, vec![StreamEffect::EchoCancellation]);
    }
}
