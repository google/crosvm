// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_os = "android", feature = "libaaudio_stub"))]

#[cfg(feature = "libaaudio_stub")]
mod libaaudio_stub;

use std::os::raw::c_void;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use audio_streams::capture::AsyncCaptureBuffer;
use audio_streams::capture::AsyncCaptureBufferStream;
use audio_streams::capture::CaptureBuffer;
use audio_streams::capture::CaptureBufferStream;
use audio_streams::AsyncBufferCommit;
use audio_streams::AsyncPlaybackBuffer;
use audio_streams::AsyncPlaybackBufferStream;
use audio_streams::AudioStreamsExecutor;
use audio_streams::BoxError;
use audio_streams::BufferCommit;
use audio_streams::NoopStreamControl;
use audio_streams::PlaybackBuffer;
use audio_streams::PlaybackBufferStream;
use audio_streams::SampleFormat;
use audio_streams::StreamControl;
use audio_streams::StreamEffect;
use audio_streams::StreamSource;
use audio_streams::StreamSourceGenerator;
use base::debug;
use base::info;
use base::warn;
use thiserror::Error;

#[derive(Clone, Copy)]
enum AndroidAudioStreamDirection {
    Input = 1,
    Output = 0,
}

#[derive(Error, Debug)]
pub enum AAudioError {
    #[error("Failed to create stream builder")]
    StreamBuilderCreation,
    #[error("Failed to open stream")]
    StreamOpen,
    #[error("Failed to start stream")]
    StreamStart,
    #[error("Failed to delete stream builder")]
    StreamBuilderDelete,
    #[error("Unsupported sample format: {0}")]
    UnsupportedFormat(SampleFormat),
}

// Opaque blob
#[repr(C)]
struct AAudioStream {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

// Opaque blob
#[repr(C)]
struct AAudioStreamBuilder {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

type AaudioFormatT = i32;
type AaudioResultT = i32;
const AAUDIO_OK: AaudioResultT = 0;
// From Android NDK `<aaudio/AAudio.h>`:
const AAUDIO_FORMAT_PCM_I16: AaudioFormatT = 1;
const AAUDIO_FORMAT_PCM_I32: AaudioFormatT = 4;

fn to_aaudio_format(format: SampleFormat) -> Result<AaudioFormatT, AAudioError> {
    match format {
        SampleFormat::S16LE => Ok(AAUDIO_FORMAT_PCM_I16),
        SampleFormat::S32LE => Ok(AAUDIO_FORMAT_PCM_I32),
        // AAudio has no 8-bit format, and AAUDIO_FORMAT_PCM_I32 is full scale, so S24 (24 bits in
        // a 32-bit container) would need a shift.
        SampleFormat::U8 | SampleFormat::S24LE => Err(AAudioError::UnsupportedFormat(format)),
    }
}

extern "C" {
    fn AAudio_createStreamBuilder(builder: *mut *mut AAudioStreamBuilder) -> AaudioResultT;
    fn AAudioStreamBuilder_delete(builder: *mut AAudioStreamBuilder) -> AaudioResultT;
    fn AAudioStreamBuilder_setBufferCapacityInFrames(
        builder: *mut AAudioStreamBuilder,
        num_frames: i32,
    );
    fn AAudioStreamBuilder_setDirection(builder: *mut AAudioStreamBuilder, direction: u32);
    fn AAudioStreamBuilder_setFormat(builder: *mut AAudioStreamBuilder, format: AaudioFormatT);
    fn AAudioStreamBuilder_setSampleRate(builder: *mut AAudioStreamBuilder, sample_rate: i32);
    fn AAudioStreamBuilder_setChannelCount(builder: *mut AAudioStreamBuilder, channel_count: i32);
    fn AAudioStreamBuilder_openStream(
        builder: *mut AAudioStreamBuilder,
        stream: *mut *mut AAudioStream,
    ) -> AaudioResultT;
    fn AAudioStream_getBufferSizeInFrames(stream: *mut AAudioStream) -> i32;
    fn AAudioStream_requestStart(stream: *mut AAudioStream) -> AaudioResultT;
    fn AAudioStream_requestStop(stream: *mut AAudioStream) -> AaudioResultT;
    fn AAudioStream_read(
        stream: *mut AAudioStream,
        buffer: *mut c_void,
        num_frames: i32,
        timeout_nanoseconds: i64,
    ) -> AaudioResultT;
    fn AAudioStream_write(
        stream: *mut AAudioStream,
        buffer: *const c_void,
        num_frames: i32,
        timeout_nanoseconds: i64,
    ) -> AaudioResultT;
    fn AAudioStream_close(stream: *mut AAudioStream) -> AaudioResultT;
}

struct AAudioStreamPtr {
    // TODO: Use callback function to avoid possible thread preemption and glitches cause by
    // using AAudio APIs in different threads.
    stream_ptr: *mut AAudioStream,
}

// SAFETY:
// AudioStream.drop.buffer_ptr: *const u8 points to AudioStream.buffer, which would be alive
// whenever AudioStream.drop.buffer_ptr is alive.
unsafe impl Send for AndroidAudioStreamCommit {}

/// Asks the host whether the guest may capture audio. Implementations must not block: they run
/// on the audio executor. One delegate is shared by all capture streams of a card, so streams
/// waiting at the same time share one request and all receive its answer.
pub trait AudioPermissionDelegate: Send + Sync {
    /// Sends a permission request to the host unless one is already outstanding.
    fn request_permission(&self) -> Result<(), BoxError>;
    /// Returns the host's answer to the outstanding request, or `Poll::Pending` if it has not
    /// answered yet.
    fn poll_permission(&self) -> Poll<Result<bool, BoxError>>;
}

struct AudioStream {
    buffer: Box<[u8]>,
    frame_size: usize,
    frame_rate: u32,
    num_channels: usize,
    format: SampleFormat,
    next_frame: Instant,
    start_time: Option<Instant>,
    /// Frames paced since `start_time`. u64 so it can't overflow (i32 overflowed after ~12.4 h at
    /// 48 kHz).
    total_frames: u64,
    buffer_drop: AndroidAudioStreamCommit,
    read_count: i32,
    aaudio_buffer_size: usize,
    permission_delegate: Option<Arc<dyn AudioPermissionDelegate>>,
    /// A permission request was sent and its answer has not been applied yet.
    permission_pending: bool,
}

struct AndroidAudioStreamCommit {
    buffer_ptr: *const u8,
    stream: AAudioStreamPtr,
    direction: AndroidAudioStreamDirection,
}

impl BufferCommit for AndroidAudioStreamCommit {
    fn commit(&mut self, _nwritten: usize) {
        // This traits function is never called.
        unimplemented!();
    }
}

#[async_trait(?Send)]
impl AsyncBufferCommit for AndroidAudioStreamCommit {
    async fn commit(&mut self, nwritten: usize) {
        match self.direction {
            AndroidAudioStreamDirection::Input => {}
            AndroidAudioStreamDirection::Output => {
                // SAFETY:
                // The AAudioStream_write reads buffer for nwritten * frame_size bytes
                // It is safe since nwritten < buffer_size and the buffer.len() == buffer_size *
                // frame_size
                let frames_written: i32 = unsafe {
                    AAudioStream_write(
                        self.stream.stream_ptr,
                        self.buffer_ptr as *const c_void,
                        nwritten as i32,
                        0, // this call will not wait.
                    )
                };
                if frames_written < 0 {
                    warn!("AAudio stream write failed.");
                } else if (frames_written as usize) < nwritten {
                    // Currently, the frames unable to write by the AAudio API are dropped.
                    warn!(
                        "Android Audio Stream:  Drop {} frames",
                        nwritten - (frames_written as usize)
                    );
                }
            }
        }
    }
}

fn create_and_open_aaudio_stream(
    num_channels: usize,
    format: SampleFormat,
    frame_rate: u32,
    buffer_size: usize,
    direction: AndroidAudioStreamDirection,
) -> Result<(*mut AAudioStream, usize), BoxError> {
    let aaudio_format = to_aaudio_format(format)?;
    let mut stream_ptr: *mut AAudioStream = std::ptr::null_mut();
    let mut builder: *mut AAudioStreamBuilder = std::ptr::null_mut();
    // SAFETY:
    // Interfacing with the AAudio C API. `&mut builder` and `&mut stream_ptr` are valid
    // out-pointers to local variables, and `builder` and `stream_ptr` are only used after
    // `AAudio_createStreamBuilder` and `AAudioStreamBuilder_openStream` succeed with `AAUDIO_OK`.
    unsafe {
        let res = AAudio_createStreamBuilder(&mut builder);
        if res != AAUDIO_OK {
            warn!("AAudio_createStreamBuilder failed: {res}");
            return Err(Box::new(AAudioError::StreamBuilderCreation));
        }
        AAudioStreamBuilder_setDirection(builder, direction as u32);
        AAudioStreamBuilder_setBufferCapacityInFrames(builder, buffer_size as i32 * 2);
        AAudioStreamBuilder_setFormat(builder, aaudio_format);
        AAudioStreamBuilder_setSampleRate(builder, frame_rate as i32);
        AAudioStreamBuilder_setChannelCount(builder, num_channels as i32);
        let res = AAudioStreamBuilder_openStream(builder, &mut stream_ptr);
        if res != AAUDIO_OK {
            warn!("AAudioStreamBuilder_openStream failed: {res}");
            let _ = AAudioStreamBuilder_delete(builder);
            return Err(Box::new(AAudioError::StreamOpen));
        }
        let res = AAudioStreamBuilder_delete(builder);
        if res != AAUDIO_OK {
            warn!("AAudioStreamBuilder_delete failed: {res}");
            let _ = AAudioStream_close(stream_ptr);
            return Err(Box::new(AAudioError::StreamBuilderDelete));
        }
        let res = AAudioStream_requestStart(stream_ptr);
        if res != AAUDIO_OK {
            warn!("AAudioStream_requestStart failed: {res}");
            let _ = AAudioStream_close(stream_ptr);
            return Err(Box::new(AAudioError::StreamStart));
        }
    }
    // SAFETY:
    // Interfacing with the AAudio C API. Assumes correct linking
    // and `stream_ptr` is valid and properly initialized.
    let aaudio_buffer_size = unsafe { AAudioStream_getBufferSizeInFrames(stream_ptr) } as usize;
    Ok((stream_ptr, aaudio_buffer_size))
}

impl AudioStream {
    pub fn new(
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        direction: AndroidAudioStreamDirection,
        permission_delegate: Option<Arc<dyn AudioPermissionDelegate>>,
    ) -> Result<Self, BoxError> {
        // Reject unsupported formats up front: capture streams only open AAudio in start().
        to_aaudio_format(format)?;
        let frame_size = format.sample_bytes() * num_channels;
        let buffer = vec![0; buffer_size * frame_size].into_boxed_slice();

        // Capture streams defer AAudio stream creation until start() is called,
        // preventing premature device initialization during guest boot.
        let (stream_ptr, aaudio_buffer_size) = match direction {
            AndroidAudioStreamDirection::Input => (std::ptr::null_mut(), 0),
            AndroidAudioStreamDirection::Output => create_and_open_aaudio_stream(
                num_channels,
                format,
                frame_rate,
                buffer_size,
                direction,
            )?,
        };
        let stream = AAudioStreamPtr { stream_ptr };
        let buffer_drop = AndroidAudioStreamCommit {
            stream,
            buffer_ptr: buffer.as_ptr(),
            direction,
        };
        Ok(AudioStream {
            buffer,
            frame_size,
            frame_rate,
            num_channels,
            format,
            next_frame: Instant::now(),
            start_time: None,
            total_frames: 0,
            buffer_drop,
            read_count: 0,
            aaudio_buffer_size,
            permission_delegate,
            permission_pending: false,
        })
    }

    fn reset_capture_timing(&mut self) {
        self.read_count = 0;
        self.start_time = None;
        self.total_frames = 0;
    }

    /// Opens and starts the AAudio capture stream synchronously. This blocks the executor thread
    /// for the duration of the AAudio open (tens of milliseconds); `pace_period()` tolerates that.
    fn open_capture_stream(&mut self) -> Result<(), BoxError> {
        let buffer_size = self.buffer.len() / self.frame_size;
        let open_start = Instant::now();
        let (stream_ptr, aaudio_buffer_size) = create_and_open_aaudio_stream(
            self.num_channels,
            self.format,
            self.frame_rate,
            buffer_size,
            self.buffer_drop.direction,
        )?;
        self.buffer_drop.stream.stream_ptr = stream_ptr;
        self.aaudio_buffer_size = aaudio_buffer_size;
        info!(
            "AAudio capture stream opened in {:?} (period_frames={}, aaudio_buffer_size={})",
            open_start.elapsed(),
            buffer_size,
            self.aaudio_buffer_size
        );
        Ok(())
    }

    /// Applies the host's answer to a pending permission request, if it has arrived. On grant,
    /// opens the AAudio capture stream and resets the capture timing.
    fn poll_permission(&mut self) {
        if !self.permission_pending {
            return;
        }
        let Some(delegate) = &self.permission_delegate else {
            return;
        };
        let Poll::Ready(answer) = delegate.poll_permission() else {
            return;
        };
        self.permission_pending = false;
        match answer {
            Ok(true) => match self.open_capture_stream() {
                Ok(()) => {
                    info!("Audio capture permission granted; opened capture stream");
                    self.reset_capture_timing();
                }
                Err(e) => warn!("Failed to open AAudioStream after permission grant: {e}"),
            },
            Ok(false) => warn!("Audio capture permission denied; streaming silence."),
            Err(e) => warn!("Audio permission check failed ({e}); streaming silence."),
        }
    }

    /// Paces period production to real time. Adds `period_frames` to the running frame count and
    /// waits until that period is due.
    ///
    /// If the executor thread was blocked (for example by a synchronous AAudio open/close for
    /// another stream on the same card), the due time can already be in the past. In that case
    /// this does NOT call `ex.delay()` with a zero duration (`TimerAsync::sleep(0)` disarms the
    /// timerfd and never wakes, permanently stalling the worker). When more than two periods
    /// behind, the pacing clock is re-anchored at "now" so the stream does not burst several
    /// periods back-to-back to catch up.
    async fn pace_period(
        &mut self,
        ex: &dyn AudioStreamsExecutor,
        period_frames: u64,
        label: &'static str,
    ) -> Result<(), BoxError> {
        self.total_frames += period_frames;
        let start_time = match self.start_time {
            Some(time) => {
                let now = Instant::now();
                let delay = self.next_frame.saturating_duration_since(now);
                if !delay.is_zero() {
                    ex.delay(delay).await?;
                    time
                } else {
                    let behind = now.saturating_duration_since(self.next_frame);
                    let period = Duration::from_nanos(
                        period_frames * 1_000_000_000 / self.frame_rate as u64,
                    );
                    if behind > period * 2 {
                        warn!(
                            "{label} pacing: {:?} behind schedule (period {:?}); \
                             re-anchoring pacing clock",
                            behind, period
                        );
                        self.start_time = Some(now);
                        self.total_frames = period_frames;
                        now
                    } else {
                        debug!("{label} pacing: {:?} behind schedule; not sleeping", behind);
                        time
                    }
                }
            }
            None => {
                let now = Instant::now();
                self.start_time = Some(now);
                now
            }
        };
        // Convert whole seconds and the leftover frames separately: total_frames * 1e9 would
        // overflow u64 after ~106 h at 48 kHz, while the leftover is always < frame_rate.
        let rate = self.frame_rate as u64;
        self.next_frame = start_time
            + Duration::from_secs(self.total_frames / rate)
            + Duration::from_nanos(self.total_frames % rate * 1_000_000_000 / rate);
        Ok(())
    }
}

impl PlaybackBufferStream for AudioStream {
    fn next_playback_buffer<'b, 's: 'b>(&'s mut self) -> Result<PlaybackBuffer<'b>, BoxError> {
        // This traits function is never called.
        unimplemented!();
    }
}

#[async_trait(?Send)]
impl AsyncPlaybackBufferStream for AudioStream {
    async fn next_playback_buffer<'a>(
        &'a mut self,
        ex: &dyn AudioStreamsExecutor,
    ) -> Result<AsyncPlaybackBuffer<'a>, BoxError> {
        let period_frames = (self.buffer.len() / self.frame_size) as u64;
        self.pace_period(ex, period_frames, "playback").await?;
        Ok(
            AsyncPlaybackBuffer::new(self.frame_size, self.buffer.as_mut(), &mut self.buffer_drop)
                .map_err(Box::new)?,
        )
    }
}

#[async_trait(?Send)]
impl CaptureBufferStream for AudioStream {
    fn next_capture_buffer<'b, 's: 'b>(&'s mut self) -> Result<CaptureBuffer<'b>, BoxError> {
        // This traits function is never called.
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl AsyncCaptureBufferStream for AudioStream {
    fn start(&mut self) -> Result<(), BoxError> {
        self.reset_capture_timing();
        if !self.buffer_drop.stream.stream_ptr.is_null() {
            // Already open and started: stop() always closes the stream, so this only happens if
            // start() is called twice. Don't open a second stream over it.
            return Ok(());
        }
        if let Some(delegate) = &self.permission_delegate {
            // Do not wait for the answer here: holding back capture periods while the host shows
            // its permission dialog stalls the guest hw_ptr, and ALSA hw: clients fail with
            // -EIO. Instead next_capture_buffer() streams paced silence and polls each period.
            info!("Capture start(): requesting host audio permission; silence until answered");
            match delegate.request_permission() {
                Ok(()) => {
                    self.permission_pending = true;
                    // Apply an immediate answer before returning.
                    self.poll_permission();
                }
                Err(e) => {
                    warn!("Failed to request audio permission ({e}); streaming silence.");
                    self.permission_pending = false;
                }
            }
            return Ok(());
        }
        self.open_capture_stream()
    }

    fn stop(&mut self) -> Result<(), BoxError> {
        self.permission_pending = false;
        // Close rather than only stop the stream: a stopped stream keeps its AudioRecord client
        // registered in AudioFlinger, which keeps the microphone and its privacy indicator on.
        // Nullify `stream_ptr` so `Drop for AAudioStreamPtr` does not double-close the stream;
        // the next start() reopens it.
        let stream_ptr = std::mem::replace(
            &mut self.buffer_drop.stream.stream_ptr,
            std::ptr::null_mut(),
        );
        if !stream_ptr.is_null() {
            // SAFETY:
            // Interfacing with the AAudio C API. Assumes correct linking
            // and `stream_ptr` is valid and properly initialized.
            let stop_res = unsafe { AAudioStream_requestStop(stream_ptr) };
            if stop_res != AAUDIO_OK {
                warn!("AAudio stream requestStop failed: {stop_res}");
            }
            // SAFETY:
            // Interfacing with the AAudio C API. Assumes correct linking
            // and `stream_ptr` is valid and properly initialized.
            let close_res = unsafe { AAudioStream_close(stream_ptr) };
            if close_res != AAUDIO_OK {
                warn!("AAudio stream close failed: {close_res}");
            }
        }
        self.aaudio_buffer_size = 0;
        self.reset_capture_timing();
        Ok(())
    }

    async fn next_capture_buffer<'a>(
        &'a mut self,
        ex: &dyn AudioStreamsExecutor,
    ) -> Result<AsyncCaptureBuffer<'a>, BoxError> {
        let buffer_size = self.buffer.len() / self.frame_size;
        // On grant this opens the stream and resets the capture timing, so this call then behaves
        // like the first call after start(): warm-up period skipped, clock re-anchored without
        // delay.
        self.poll_permission();
        self.read_count = self.read_count.saturating_add(1);
        self.pace_period(ex, buffer_size as u64, "capture").await?;

        if self.buffer_drop.stream.stream_ptr.is_null() {
            self.buffer.fill(0);
            return Ok(AsyncCaptureBuffer::new(
                buffer_size,
                self.buffer.as_mut(),
                &mut self.buffer_drop,
            )
            .map_err(Box::new)?);
        }

        // Skip only the first period after start so AudioFlinger has delivered roughly one
        // period of data before the first non-blocking read. Skipping longer than the AAudio
        // buffer capacity (2 periods) overflows AudioFlinger's RecordThread and delays the
        // STARTING -> STARTED transition that AAudioStream_read() drives on legacy streams.
        if self.read_count <= 1 {
            self.buffer.fill(0);
            return Ok(AsyncCaptureBuffer::new(
                buffer_size,
                self.buffer.as_mut(),
                &mut self.buffer_drop,
            )
            .map_err(Box::new)?);
        }

        // SAFETY:
        // The AAudioStream_read writes buffer for buffer.len() / frame_size * frame_size bytes
        let frames_read = unsafe {
            AAudioStream_read(
                self.buffer_drop.stream.stream_ptr,
                self.buffer.as_mut_ptr() as *mut c_void,
                (buffer_size) as i32,
                0,
            )
        };

        if frames_read < 0 {
            warn!("AAudio stream read failed: {frames_read}");
            self.buffer.fill(0);
        } else if (frames_read as usize) < buffer_size {
            warn!(
                "AAudio stream read data not enough. frames read: {frames_read}, buffer size: {buffer_size}",
            );
            self.buffer[frames_read as usize * self.frame_size..].fill(0);
        }

        Ok(
            AsyncCaptureBuffer::new(buffer_size, self.buffer.as_mut(), &mut self.buffer_drop)
                .map_err(Box::new)?,
        )
    }
}

impl Drop for AAudioStreamPtr {
    fn drop(&mut self) {
        if !self.stream_ptr.is_null() {
            // SAFETY:
            // Interfacing with the AAudio C API. Assumes correct linking
            // and `stream_ptr` are valid and properly initialized.
            if unsafe { AAudioStream_close(self.stream_ptr) } != AAUDIO_OK {
                warn!("AAudio stream close failed.");
            }
        }
    }
}

#[derive(Default, Clone)]
struct AndroidAudioStreamSource {
    permission_delegate: Option<Arc<dyn AudioPermissionDelegate>>,
}

impl StreamSource for AndroidAudioStreamSource {
    #[allow(clippy::type_complexity)]
    fn new_playback_stream(
        &mut self,
        _num_channels: usize,
        _format: SampleFormat,
        _frame_rate: u32,
        _buffer_size: usize,
    ) -> Result<(Box<dyn StreamControl>, Box<dyn PlaybackBufferStream>), BoxError> {
        // This traits function is never called.
        unimplemented!();
    }

    #[allow(clippy::type_complexity)]
    fn new_async_playback_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        _ex: &dyn AudioStreamsExecutor,
    ) -> Result<(Box<dyn StreamControl>, Box<dyn AsyncPlaybackBufferStream>), BoxError> {
        let audio_stream = AudioStream::new(
            num_channels,
            format,
            frame_rate,
            buffer_size,
            AndroidAudioStreamDirection::Output,
            None,
        )?;
        Ok((Box::new(NoopStreamControl::new()), Box::new(audio_stream)))
    }

    #[allow(clippy::type_complexity)]
    fn new_capture_stream(
        &mut self,
        _num_channels: usize,
        _format: SampleFormat,
        _frame_rate: u32,
        _buffer_size: usize,
        _effects: &[StreamEffect],
    ) -> std::result::Result<(Box<dyn StreamControl>, Box<dyn CaptureBufferStream>), BoxError> {
        // This traits function is never called.
        unimplemented!();
    }

    #[allow(clippy::type_complexity)]
    fn new_async_capture_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        _effects: &[StreamEffect],
        _ex: &dyn AudioStreamsExecutor,
    ) -> std::result::Result<(Box<dyn StreamControl>, Box<dyn AsyncCaptureBufferStream>), BoxError>
    {
        let audio_stream = AudioStream::new(
            num_channels,
            format,
            frame_rate,
            buffer_size,
            AndroidAudioStreamDirection::Input,
            self.permission_delegate.clone(),
        )?;
        Ok((Box::new(NoopStreamControl::new()), Box::new(audio_stream)))
    }
}

#[derive(Default, Clone)]
pub struct AndroidAudioStreamSourceGenerator {
    permission_delegate: Option<Arc<dyn AudioPermissionDelegate>>,
}

impl AndroidAudioStreamSourceGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a generator whose capture streams ask `delegate` for permission before opening
    /// the microphone.
    pub fn with_permission_delegate(delegate: Arc<dyn AudioPermissionDelegate>) -> Self {
        Self {
            permission_delegate: Some(delegate),
        }
    }
}

/// `AndroidAudioStreamSourceGenerator` is a struct that implements [`StreamSourceGenerator`]
/// for `AndroidAudioStreamSource`.
impl StreamSourceGenerator for AndroidAudioStreamSourceGenerator {
    fn generate(&self) -> Result<Box<dyn StreamSource>, BoxError> {
        Ok(Box::new(AndroidAudioStreamSource {
            permission_delegate: self.permission_delegate.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;

    use futures::FutureExt;

    use super::*;

    struct TestExecutor;

    #[async_trait(?Send)]
    impl AudioStreamsExecutor for TestExecutor {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        fn async_unix_stream(
            &self,
            _f: std::os::unix::net::UnixStream,
        ) -> std::io::Result<audio_streams::AsyncStream> {
            unimplemented!()
        }

        #[cfg(windows)]
        unsafe fn async_event(
            &self,
            _event: std::os::windows::io::RawHandle,
        ) -> std::io::Result<Box<dyn audio_streams::EventAsyncWrapper>> {
            unimplemented!()
        }

        async fn delay(&self, _dur: Duration) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_capture_stream_deferred_open() {
        let stream = AudioStream::new(
            2,
            SampleFormat::S16LE,
            48000,
            480,
            AndroidAudioStreamDirection::Input,
            None,
        )
        .expect("Failed to create capture stream");

        assert!(stream.buffer_drop.stream.stream_ptr.is_null());
        assert_eq!(stream.aaudio_buffer_size, 0);
    }

    #[test]
    fn test_capture_stream_stop_unstarted() {
        let mut stream = AudioStream::new(
            2,
            SampleFormat::S16LE,
            48000,
            480,
            AndroidAudioStreamDirection::Input,
            None,
        )
        .expect("Failed to create capture stream");

        assert!(stream.buffer_drop.stream.stream_ptr.is_null());
        assert!(stream.stop().is_ok());
        assert!(stream.buffer_drop.stream.stream_ptr.is_null());
    }

    #[test]
    fn test_capture_stream_unstarted_next_buffer() {
        async fn run_test() {
            let mut stream = AudioStream::new(
                2,
                SampleFormat::S16LE,
                48000,
                480,
                AndroidAudioStreamDirection::Input,
                None,
            )
            .expect("Failed to create capture stream");

            let ex = TestExecutor;
            let mut buf = AsyncCaptureBufferStream::next_capture_buffer(&mut stream, &ex)
                .await
                .expect("Failed to get next capture buffer");

            let mut out = [0xa5u8; 480 * 2 * 2];
            assert_eq!(buf.read(&mut out).unwrap(), 480 * 2 * 2);
            for b in out.iter() {
                assert_eq!(*b, 0, "Unstarted stream should yield zeroes");
            }
        }

        run_test().now_or_never().expect("future should be ready");
    }

    #[test]
    fn test_source_generator_new_async_capture_stream() {
        let generator = AndroidAudioStreamSourceGenerator::new();
        let mut source = generator
            .generate()
            .expect("Failed to generate stream source");
        let ex = TestExecutor;
        let (_control, mut stream) = source
            .new_async_capture_stream(2, SampleFormat::S16LE, 48000, 480, &[], &ex)
            .expect("Failed to create new async capture stream");

        assert!(stream.stop().is_ok());
    }

    /// Executor that records requested delays and fails the test on a zero-duration delay
    /// (which would disarm the timerfd and hang the worker forever).
    #[derive(Default)]
    struct RecordingExecutor {
        delays: std::cell::RefCell<Vec<Duration>>,
    }

    #[async_trait(?Send)]
    impl AudioStreamsExecutor for RecordingExecutor {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        fn async_unix_stream(
            &self,
            _f: std::os::unix::net::UnixStream,
        ) -> std::io::Result<audio_streams::AsyncStream> {
            unimplemented!()
        }

        #[cfg(windows)]
        unsafe fn async_event(
            &self,
            _event: std::os::windows::io::RawHandle,
        ) -> std::io::Result<Box<dyn audio_streams::EventAsyncWrapper>> {
            unimplemented!()
        }

        async fn delay(&self, dur: Duration) -> std::io::Result<()> {
            assert!(
                !dur.is_zero(),
                "pacing must never request a zero-duration delay"
            );
            self.delays.borrow_mut().push(dur);
            Ok(())
        }
    }

    /// Unstarted capture stream with 10 ms periods (480 frames @ 48 kHz).
    fn new_unstarted_capture_stream() -> AudioStream {
        AudioStream::new(
            2,
            SampleFormat::S16LE,
            48000,
            480,
            AndroidAudioStreamDirection::Input,
            None,
        )
        .expect("Failed to create capture stream")
    }

    #[test]
    fn test_pacing_on_time_uses_nonzero_delay() {
        async fn run_test() {
            let mut stream = new_unstarted_capture_stream();
            let ex = RecordingExecutor::default();
            // Next period is due in the future: pacing must sleep for a non-zero duration and
            // keep the existing clock.
            let start = Instant::now();
            stream.start_time = Some(start);
            stream.next_frame = start + Duration::from_secs(1);

            let _buf = AsyncCaptureBufferStream::next_capture_buffer(&mut stream, &ex)
                .await
                .expect("Failed to get capture buffer");

            let delays = ex.delays.borrow();
            assert_eq!(delays.len(), 1);
            assert!(delays[0] > Duration::ZERO && delays[0] <= Duration::from_secs(1));
            assert_eq!(stream.start_time, Some(start));
        }

        run_test().now_or_never().expect("future should be ready");
    }

    #[test]
    fn test_pacing_slightly_behind_skips_delay_keeps_clock() {
        async fn run_test() {
            let mut stream = new_unstarted_capture_stream();
            let ex = RecordingExecutor::default();
            // Less than two periods behind: no sleep, pacing clock is kept.
            let start = Instant::now()
                .checked_sub(Duration::from_millis(100))
                .expect("clock too early");
            stream.start_time = Some(start);
            stream.total_frames = 4800 - 240; // due 95 ms after start, i.e. ~5 ms ago
            stream.next_frame = start + Duration::from_millis(95);

            let _buf = AsyncCaptureBufferStream::next_capture_buffer(&mut stream, &ex)
                .await
                .expect("Failed to get capture buffer");

            assert!(ex.delays.borrow().is_empty());
            assert_eq!(stream.start_time, Some(start));
            assert_eq!(stream.total_frames, 4800 - 240 + 480);
        }

        run_test().now_or_never().expect("future should be ready");
    }

    #[test]
    fn test_pacing_far_behind_reanchors_clock() {
        async fn run_test() {
            let mut stream = new_unstarted_capture_stream();
            let ex = RecordingExecutor::default();
            // Simulate the executor having been blocked for a long time (e.g. by a synchronous
            // AAudio open/close for another stream): the next period is ~1 s overdue.
            let start = Instant::now()
                .checked_sub(Duration::from_secs(2))
                .expect("clock too early");
            stream.start_time = Some(start);
            stream.total_frames = 48000;
            stream.next_frame = start + Duration::from_secs(1);

            let before = Instant::now();
            let _buf = AsyncCaptureBufferStream::next_capture_buffer(&mut stream, &ex)
                .await
                .expect("Failed to get capture buffer");

            assert!(ex.delays.borrow().is_empty());
            let new_start = stream.start_time.expect("pacing clock should be set");
            assert!(
                new_start >= before,
                "pacing clock should be re-anchored to now"
            );
            assert_eq!(stream.total_frames, 480);
            assert_eq!(stream.next_frame, new_start + Duration::from_millis(10));
        }

        run_test().now_or_never().expect("future should be ready");
    }

    #[test]
    fn test_pacing_counter_does_not_overflow() {
        async fn run_test() {
            // Both counts are past i32::MAX (~12.4 h at 48 kHz); the second is also past where
            // total_frames * 1e9 overflows u64 (~106 h).
            for (frames, expected) in [
                (48_000 * 50_000, Duration::from_secs(50_000)),
                (
                    48_000 * 2_000_000 + 24_000,
                    Duration::from_secs(2_000_000) + Duration::from_millis(500),
                ),
            ] {
                let mut stream = new_unstarted_capture_stream();
                let ex = RecordingExecutor::default();
                let start = Instant::now();
                stream.start_time = Some(start);
                stream.total_frames = frames - 480;
                stream.next_frame = start + Duration::from_secs(1);

                stream
                    .pace_period(&ex, 480, "test")
                    .await
                    .expect("pacing failed");

                assert_eq!(ex.delays.borrow().len(), 1);
                assert_eq!(stream.start_time, Some(start));
                assert_eq!(stream.total_frames, frames);
                assert_eq!(stream.next_frame, start + expected);
            }
        }

        run_test().now_or_never().expect("future should be ready");
    }

    #[test]
    fn test_to_aaudio_format_mapping() {
        assert!(matches!(
            to_aaudio_format(SampleFormat::S16LE),
            Ok(AAUDIO_FORMAT_PCM_I16)
        ));
        assert!(matches!(
            to_aaudio_format(SampleFormat::S32LE),
            Ok(AAUDIO_FORMAT_PCM_I32)
        ));
        for format in [SampleFormat::U8, SampleFormat::S24LE] {
            assert!(matches!(
                to_aaudio_format(format),
                Err(AAudioError::UnsupportedFormat(f)) if f == format
            ));
        }
    }

    #[test]
    fn test_new_stream_rejects_unsupported_format() {
        for format in [SampleFormat::U8, SampleFormat::S24LE] {
            for direction in [
                AndroidAudioStreamDirection::Output,
                AndroidAudioStreamDirection::Input,
            ] {
                assert!(AudioStream::new(2, format, 48000, 480, direction, None).is_err());
            }
        }
    }

    #[test]
    fn test_capture_stream_stop_closes_and_start_reopens() {
        let mut stream = new_unstarted_capture_stream();

        assert!(stream.start().is_ok());
        assert!(!stream.buffer_drop.stream.stream_ptr.is_null());
        assert!(stream.aaudio_buffer_size > 0);

        // Dirty the pacing state so stop() has something to reset.
        stream.read_count = 10;
        stream.start_time = Some(Instant::now());
        stream.total_frames = 4800;

        assert!(stream.stop().is_ok());
        assert!(stream.buffer_drop.stream.stream_ptr.is_null());
        assert_eq!(stream.aaudio_buffer_size, 0);
        assert_eq!(stream.read_count, 0);
        assert!(stream.start_time.is_none());
        assert_eq!(stream.total_frames, 0);

        // A closed stream is reopened by the next start().
        assert!(stream.start().is_ok());
        assert!(!stream.buffer_drop.stream.stream_ptr.is_null());
        assert!(stream.aaudio_buffer_size > 0);
    }

    struct MockPermissionDelegate {
        answer: Mutex<Poll<Result<bool, String>>>,
        fail_requests: bool,
        requests: AtomicUsize,
    }

    impl MockPermissionDelegate {
        fn new(answer: Poll<Result<bool, String>>) -> Self {
            Self {
                answer: Mutex::new(answer),
                fail_requests: false,
                requests: AtomicUsize::new(0),
            }
        }

        fn set_answer(&self, answer: Poll<Result<bool, String>>) {
            *self.answer.lock().unwrap() = answer;
        }

        fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    impl AudioPermissionDelegate for MockPermissionDelegate {
        fn request_permission(&self) -> Result<(), BoxError> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            if self.fail_requests {
                return Err("mock request failure".into());
            }
            Ok(())
        }

        fn poll_permission(&self) -> Poll<Result<bool, BoxError>> {
            self.answer
                .lock()
                .unwrap()
                .clone()
                .map(|answer| answer.map_err(BoxError::from))
        }
    }

    fn new_capture_stream_with_delegate(delegate: &Arc<MockPermissionDelegate>) -> AudioStream {
        AudioStream::new(
            2,
            SampleFormat::S16LE,
            48000,
            480,
            AndroidAudioStreamDirection::Input,
            Some(delegate.clone()),
        )
        .expect("Failed to create capture stream")
    }

    async fn read_period_is_silent(stream: &mut AudioStream) -> bool {
        let mut buf = AsyncCaptureBufferStream::next_capture_buffer(stream, &TestExecutor)
            .await
            .expect("Failed to get capture buffer");
        let mut out = [0xa5u8; 480 * 2 * 2];
        assert_eq!(buf.read(&mut out).unwrap(), 480 * 2 * 2);
        out.iter().all(|&b| b == 0)
    }

    #[test]
    fn test_capture_permission_granted_opens_in_start() {
        let delegate = Arc::new(MockPermissionDelegate::new(Poll::Ready(Ok(true))));
        let mut stream = new_capture_stream_with_delegate(&delegate);

        assert!(stream.start().is_ok());
        assert!(!stream.permission_pending);
        assert!(!stream.buffer_drop.stream.stream_ptr.is_null());
        assert_eq!(delegate.requests(), 1);
    }

    #[test]
    fn test_capture_permission_pending_then_granted() {
        async fn run_test() {
            let delegate = Arc::new(MockPermissionDelegate::new(Poll::Pending));
            let mut stream = new_capture_stream_with_delegate(&delegate);

            assert!(stream.start().is_ok());
            assert!(stream.permission_pending);
            assert!(stream.buffer_drop.stream.stream_ptr.is_null());
            assert!(read_period_is_silent(&mut stream).await);

            // The grant is applied by the next period, which is the skipped warm-up period.
            delegate.set_answer(Poll::Ready(Ok(true)));
            assert!(read_period_is_silent(&mut stream).await);
            assert!(!stream.permission_pending);
            assert!(!stream.buffer_drop.stream.stream_ptr.is_null());
            assert_eq!(stream.read_count, 1);
            assert_eq!(delegate.requests(), 1);
        }

        run_test().now_or_never().expect("future should be ready");
    }

    #[test]
    fn test_capture_permission_denied_streams_silence() {
        async fn run_test() {
            let delegate = Arc::new(MockPermissionDelegate::new(Poll::Ready(Ok(false))));
            let mut stream = new_capture_stream_with_delegate(&delegate);

            assert!(stream.start().is_ok());
            assert!(!stream.permission_pending);
            assert!(stream.buffer_drop.stream.stream_ptr.is_null());
            assert!(read_period_is_silent(&mut stream).await);
        }

        run_test().now_or_never().expect("future should be ready");
    }

    #[test]
    fn test_capture_permission_error_denies() {
        let answer = Poll::Ready(Err("mock poll failure".to_string()));
        let delegate = Arc::new(MockPermissionDelegate::new(answer));
        let mut stream = new_capture_stream_with_delegate(&delegate);
        assert!(stream.start().is_ok());
        assert!(!stream.permission_pending);
        assert!(stream.buffer_drop.stream.stream_ptr.is_null());

        let delegate = Arc::new(MockPermissionDelegate {
            fail_requests: true,
            ..MockPermissionDelegate::new(Poll::Ready(Ok(true)))
        });
        let mut stream = new_capture_stream_with_delegate(&delegate);
        assert!(stream.start().is_ok());
        assert!(!stream.permission_pending);
        assert!(stream.buffer_drop.stream.stream_ptr.is_null());
    }

    #[test]
    fn test_capture_permission_requested_again_after_stop() {
        let delegate = Arc::new(MockPermissionDelegate::new(Poll::Ready(Ok(true))));
        let mut stream = new_capture_stream_with_delegate(&delegate);

        assert!(stream.start().is_ok());
        assert!(!stream.buffer_drop.stream.stream_ptr.is_null());

        assert!(stream.stop().is_ok());
        assert!(!stream.permission_pending);
        assert!(stream.buffer_drop.stream.stream_ptr.is_null());

        assert!(stream.start().is_ok());
        assert_eq!(delegate.requests(), 2);
        assert!(!stream.buffer_drop.stream.stream_ptr.is_null());
    }

    #[test]
    fn test_stop_while_pending_resets_state() {
        let delegate = Arc::new(MockPermissionDelegate::new(Poll::Pending));
        let mut stream = new_capture_stream_with_delegate(&delegate);

        assert!(stream.start().is_ok());
        assert!(stream.permission_pending);

        assert!(stream.stop().is_ok());
        assert!(!stream.permission_pending);
        assert!(stream.buffer_drop.stream.stream_ptr.is_null());
        assert_eq!(delegate.requests(), 1);
    }

    #[test]
    fn test_source_generator_with_permission_delegate() {
        let delegate = Arc::new(MockPermissionDelegate::new(Poll::Pending));
        let generator =
            AndroidAudioStreamSourceGenerator::with_permission_delegate(delegate.clone());
        let mut source = generator
            .generate()
            .expect("Failed to generate stream source");
        let (_control, mut stream) = source
            .new_async_capture_stream(2, SampleFormat::S16LE, 48000, 480, &[], &TestExecutor)
            .expect("Failed to create new async capture stream");

        assert_eq!(delegate.requests(), 0);
        assert!(stream.start().is_ok());
        assert_eq!(delegate.requests(), 1);
        assert!(stream.stop().is_ok());
    }
}
