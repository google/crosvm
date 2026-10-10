// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "audio_aaudio")]
use std::io;
#[cfg(feature = "audio_aaudio")]
use std::io::Read;
#[cfg(feature = "audio_aaudio")]
use std::io::Write;
#[cfg(feature = "audio_aaudio")]
use std::os::unix::net::UnixStream;
#[cfg(feature = "audio_cras")]
use std::path::Path;
#[cfg(feature = "audio_aaudio")]
use std::sync::Arc;
#[cfg(feature = "audio_aaudio")]
use std::task::Poll;

#[cfg(feature = "audio_aaudio")]
use android_audio::AndroidAudioStreamSourceGenerator;
#[cfg(feature = "audio_aaudio")]
use android_audio::AudioPermissionDelegate;
use async_trait::async_trait;
use audio_streams::capture::AsyncCaptureBuffer;
use audio_streams::capture::AsyncCaptureBufferStream;
use audio_streams::capture::NoopCaptureStream;
use audio_streams::AsyncPlaybackBufferStream;
use audio_streams::BoxError;
use audio_streams::SampleFormat;
use audio_streams::StreamEffect;
use audio_streams::StreamSource;
use audio_streams::StreamSourceGenerator;
use base::error;
#[cfg(feature = "audio_aaudio")]
use base::safe_descriptor_from_cmdline_fd;
use base::set_rt_prio_limit;
use base::set_rt_round_robin;
#[cfg(feature = "audio_aaudio")]
use base::AsRawDescriptor;
use base::RawDescriptor;
use cros_async::Executor;
use futures::channel::mpsc::UnboundedSender;
use jail::create_sandbox_minijail;
use jail::JailConfig;
use jail::RunAsUser;
use jail::SandboxConfig;
use jail::MAX_OPEN_FILES_DEFAULT;
#[cfg(feature = "audio_cras")]
use libcras::CrasStreamSourceGenerator;
#[cfg(feature = "audio_cras")]
use libcras::CrasStreamType;
use minijail::Minijail;
use serde::Deserialize;
use serde::Serialize;
#[cfg(feature = "audio_aaudio")]
use sync::Mutex;
#[cfg(feature = "audio_aaudio")]
use vm_control::AudioPermissionRequest;
#[cfg(feature = "audio_aaudio")]
use vm_control::AudioPermissionResponse;

use crate::common_backend::async_funcs::CaptureBufferReader;
use crate::common_backend::async_funcs::PlaybackBufferWriter;
use crate::common_backend::stream_info::StreamInfo;
use crate::common_backend::DirectionalStream;
use crate::common_backend::Error;
use crate::common_backend::PcmResponse;
use crate::common_backend::SndData;
use crate::parameters::Error as ParametersError;
use crate::parameters::Parameters;
use crate::parameters::StreamSourceBackend as Backend;

const AUDIO_THREAD_RTPRIO: u16 = 10; // Matches other cros audio clients.

pub(crate) type SysAudioStreamSourceGenerator = Box<dyn StreamSourceGenerator>;
pub(crate) type SysAudioStreamSource = Box<dyn StreamSource>;
pub(crate) type SysBufferReader = UnixBufferReader;

pub struct SysDirectionOutput {
    pub async_playback_buffer_stream: Box<dyn audio_streams::AsyncPlaybackBufferStream>,
    pub buffer_writer: Box<dyn PlaybackBufferWriter>,
}

pub(crate) struct SysAsyncStreamObjects {
    pub(crate) stream: DirectionalStream,
    pub(crate) pcm_sender: UnboundedSender<PcmResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum StreamSourceBackend {
    #[cfg(feature = "audio_aaudio")]
    AAUDIO,
    #[cfg(feature = "audio_cras")]
    CRAS,
}

// Implemented to make backend serialization possible, since we deserialize from str.
impl From<StreamSourceBackend> for String {
    fn from(backend: StreamSourceBackend) -> Self {
        match backend {
            #[cfg(feature = "audio_aaudio")]
            StreamSourceBackend::AAUDIO => "aaudio".to_owned(),
            #[cfg(feature = "audio_cras")]
            StreamSourceBackend::CRAS => "cras".to_owned(),
        }
    }
}

impl TryFrom<&str> for StreamSourceBackend {
    type Error = ParametersError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            #[cfg(feature = "audio_aaudio")]
            "aaudio" => Ok(StreamSourceBackend::AAUDIO),
            #[cfg(feature = "audio_cras")]
            "cras" => Ok(StreamSourceBackend::CRAS),
            _ => Err(ParametersError::InvalidBackend),
        }
    }
}

/// Asks the host for audio capture permission over the socket passed with the
/// `permission_socket_fd` parameter, using the 1-byte `vm_control` protocol.
///
/// One socket is shared by all capture streams of the card. At most one `Check` is outstanding at
/// a time, and its answer is shared by every stream waiting on it. A `start()` joins the
/// outstanding request, even if its answer is already buffered; bytes buffered with no request
/// outstanding are unsolicited and are discarded. The host must answer each `Check`
/// exactly once (a dismissed dialog is `Denied`); until then capture stays silent. The socket is
/// non-blocking, so this never blocks the audio executor.
#[cfg(feature = "audio_aaudio")]
pub struct FdPermissionDelegate {
    socket: Mutex<PermissionSocket>,
}

#[cfg(feature = "audio_aaudio")]
struct PermissionSocket {
    stream: UnixStream,
    /// A `Check` was sent and its answer has not been read yet.
    in_flight: bool,
    /// Answer to the last completed request.
    answer: Option<bool>,
}

#[cfg(feature = "audio_aaudio")]
impl PermissionSocket {
    /// Reads one byte without blocking, or returns `None` if none is buffered.
    fn try_read(&mut self) -> io::Result<Option<u8>> {
        let mut buf = [0u8; 1];
        loop {
            return match self.stream.read(&mut buf) {
                Ok(0) => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "permission socket closed",
                )),
                Ok(_) => Ok(Some(buf[0])),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(e),
            };
        }
    }

    /// Discards buffered bytes.
    fn drain(&mut self) -> io::Result<()> {
        while let Some(byte) = self.try_read()? {
            base::warn!("Discarding unsolicited audio permission response byte: {byte}");
        }
        Ok(())
    }
}

#[cfg(feature = "audio_aaudio")]
impl FdPermissionDelegate {
    pub fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            socket: Mutex::new(PermissionSocket {
                stream,
                in_flight: false,
                answer: None,
            }),
        })
    }
}

#[cfg(feature = "audio_aaudio")]
impl AudioPermissionDelegate for FdPermissionDelegate {
    fn request_permission(&self) -> Result<(), BoxError> {
        let mut socket = self.socket.lock();
        if socket.in_flight {
            // Join the outstanding Check; poll_permission() hands its answer to every waiter.
            return Ok(());
        }
        // Nothing is outstanding, so anything buffered is unsolicited.
        socket.drain()?;
        socket.answer = None;
        // Rust ignores SIGPIPE, so a closed peer makes this return EPIPE instead of killing us.
        socket
            .stream
            .write_all(&[AudioPermissionRequest::Check.to_wire()])?;
        socket.in_flight = true;
        Ok(())
    }

    fn poll_permission(&self) -> Poll<Result<bool, BoxError>> {
        let mut socket = self.socket.lock();
        if !socket.in_flight {
            return Poll::Ready(
                socket
                    .answer
                    .ok_or_else(|| "no permission request outstanding".into()),
            );
        }
        let result = match socket.try_read() {
            Ok(None) => return Poll::Pending,
            Ok(Some(byte)) => match AudioPermissionResponse::try_from(byte) {
                Ok(AudioPermissionResponse::Granted) => {
                    base::info!("Audio capture permission granted by host");
                    Ok(true)
                }
                Ok(AudioPermissionResponse::Denied) => {
                    base::warn!("Audio capture permission denied by host");
                    Ok(false)
                }
                Err(unknown) => {
                    base::error!("Received invalid audio permission response byte: {unknown}");
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Invalid audio permission response byte: {unknown}"),
                    ))
                }
            },
            Err(e) => Err(e),
        };
        socket.in_flight = false;
        socket.answer = result.as_ref().ok().copied();
        Poll::Ready(result.map_err(BoxError::from))
    }
}

#[cfg(feature = "audio_aaudio")]
pub(crate) fn create_aaudio_stream_source_generators(
    params: &Parameters,
    snd_data: &SndData,
    keep_rds: &mut Vec<RawDescriptor>,
) -> Result<Vec<SysAudioStreamSourceGenerator>, Error> {
    // A bad fd is an error rather than falling back to no delegate, which would capture without
    // asking the host.
    let permission_delegate: Option<Arc<dyn AudioPermissionDelegate>> =
        match params.permission_socket_fd {
            Some(fd) => {
                let socket = safe_descriptor_from_cmdline_fd(&fd)
                    .map_err(|e| Error::PermissionSocket(e.into()))?;
                keep_rds.push(socket.as_raw_descriptor());
                let delegate = FdPermissionDelegate::new(UnixStream::from(socket))
                    .map_err(Error::PermissionSocket)?;
                Some(Arc::new(delegate))
            }
            None => None,
        };
    let mut generators: Vec<Box<dyn StreamSourceGenerator>> =
        Vec::with_capacity(snd_data.pcm_info_len());
    for pcm_info in snd_data.pcm_info_iter() {
        assert_eq!(pcm_info.features, 0); // Should be 0. Android audio backend does not support any
                                          // features.
        let generator = match &permission_delegate {
            Some(delegate) => {
                AndroidAudioStreamSourceGenerator::with_permission_delegate(delegate.clone())
            }
            None => AndroidAudioStreamSourceGenerator::new(),
        };
        generators.push(Box::new(generator));
    }
    Ok(generators)
}

#[cfg(feature = "audio_cras")]
pub(crate) fn create_cras_stream_source_generators(
    params: &Parameters,
    snd_data: &SndData,
) -> Vec<Box<dyn StreamSourceGenerator>> {
    let mut generators: Vec<Box<dyn StreamSourceGenerator>> =
        Vec::with_capacity(snd_data.pcm_info_len());
    for pcm_info in snd_data.pcm_info_iter() {
        let device_params = params.get_device_params(pcm_info).unwrap_or_else(|err| {
            error!("Create cras stream source generator error: {}", err);
            Default::default()
        });
        generators.push(Box::new(CrasStreamSourceGenerator::with_stream_type(
            params.capture,
            device_params.client_type.unwrap_or(params.client_type),
            params.socket_type,
            device_params
                .stream_type
                .unwrap_or(CrasStreamType::CRAS_STREAM_TYPE_DEFAULT),
        )));
    }
    generators
}

// Suppress `ptr_arg`: `keep_rds` must remain `&mut Vec` for cross-platform signature consistency
// and descriptor accumulation when `feature = "audio_aaudio"` is enabled.
#[allow(unused_variables, clippy::ptr_arg)]
pub(crate) fn create_stream_source_generators(
    backend: StreamSourceBackend,
    params: &Parameters,
    snd_data: &SndData,
    keep_rds: &mut Vec<RawDescriptor>,
) -> Result<Vec<Box<dyn StreamSourceGenerator>>, Error> {
    match backend {
        #[cfg(feature = "audio_aaudio")]
        StreamSourceBackend::AAUDIO => {
            create_aaudio_stream_source_generators(params, snd_data, keep_rds)
        }
        #[cfg(feature = "audio_cras")]
        StreamSourceBackend::CRAS => Ok(create_cras_stream_source_generators(params, snd_data)),
    }
}

pub(crate) fn set_audio_thread_priority() -> Result<(), base::Error> {
    set_rt_prio_limit(u64::from(AUDIO_THREAD_RTPRIO))
        .and_then(|_| set_rt_round_robin(i32::from(AUDIO_THREAD_RTPRIO)))
}

impl StreamInfo {
    /// (*)
    /// `buffer_size` in `audio_streams` API indicates the buffer size in bytes that the stream
    /// consumes (or transmits) each time (next_playback/capture_buffer).
    /// `period_bytes` in virtio-snd device (or ALSA) indicates the device transmits (or
    /// consumes) for each PCM message.
    /// Therefore, `buffer_size` in `audio_streams` == `period_bytes` in virtio-snd.
    async fn set_up_async_playback_stream(
        &mut self,
        frame_size: usize,
        ex: &Executor,
    ) -> Result<Box<dyn AsyncPlaybackBufferStream>, Error> {
        Ok(self
            .stream_source
            .as_mut()
            .ok_or(Error::EmptyStreamSource)?
            .async_new_async_playback_stream(
                self.channels as usize,
                self.format,
                self.frame_rate,
                // See (*)
                self.period_bytes / frame_size,
                ex,
            )
            .await
            .map_err(Error::CreateStream)?
            .1)
    }

    pub(crate) async fn set_up_async_capture_stream(
        &mut self,
        frame_size: usize,
        _ex: &Executor,
    ) -> Result<SysBufferReader, Error> {
        // The host capture stream is created by UnixBufferReader once the stream is started, so
        // that a PREPARE without START (e.g. a guest ALSA probe, after which the Linux virtio_snd
        // driver never sends RELEASE) does not keep a host capture stream open.
        let stream_source = self.stream_source.take().ok_or(Error::EmptyStreamSource)?;
        Ok(SysBufferReader::new(
            stream_source,
            self.channels as usize,
            self.format,
            self.frame_rate,
            // See (*)
            self.period_bytes / frame_size,
            self.effects.clone(),
            self.card_index,
        ))
    }

    pub(crate) async fn create_directionstream_output(
        &mut self,
        frame_size: usize,
        ex: &Executor,
    ) -> Result<DirectionalStream, Error> {
        let async_playback_buffer_stream =
            self.set_up_async_playback_stream(frame_size, ex).await?;

        let buffer_writer = UnixBufferWriter::new(self.period_bytes);

        Ok(DirectionalStream::Output(SysDirectionOutput {
            async_playback_buffer_stream,
            buffer_writer: Box::new(buffer_writer),
        }))
    }
}

/// State of the host capture stream owned by [`UnixBufferReader`].
enum UnixCaptureStreamState {
    /// No host capture stream. This is the initial state and the state after `stop()`.
    Stopped,
    /// `start()` was called. The host capture stream is created on the next capture period.
    Starting,
    /// The host capture stream is open.
    Started(Box<dyn AsyncCaptureBufferStream>),
    /// Creating the host capture stream failed. Paced silence is returned until `stop()`.
    StartFailed(NoopCaptureStream),
}

/// Reads capture periods from a host capture stream that is only open between `start()` and
/// `stop()`, so that host privacy indicators (e.g. the ChromeOS microphone indicator driven by
/// CRAS input streams) reflect actual guest capture.
pub(crate) struct UnixBufferReader {
    // Declared before `stream_source` so that an open capture stream is dropped before its source.
    state: UnixCaptureStreamState,
    stream_source: SysAudioStreamSource,
    num_channels: usize,
    format: SampleFormat,
    frame_rate: u32,
    period_frames: usize,
    effects: Vec<StreamEffect>,
    card_index: usize,
}

impl UnixBufferReader {
    fn new(
        stream_source: SysAudioStreamSource,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        period_frames: usize,
        effects: Vec<StreamEffect>,
        card_index: usize,
    ) -> Self {
        UnixBufferReader {
            state: UnixCaptureStreamState::Stopped,
            stream_source,
            num_channels,
            format,
            frame_rate,
            period_frames,
            effects,
            card_index,
        }
    }

    async fn create_and_start_stream(
        &mut self,
        ex: &Executor,
    ) -> Result<Box<dyn AsyncCaptureBufferStream>, BoxError> {
        let (_, mut async_stream) = self
            .stream_source
            .async_new_async_capture_stream(
                self.num_channels,
                self.format,
                self.frame_rate,
                self.period_frames,
                &self.effects,
                ex,
            )
            .await?;
        async_stream.start()?;
        Ok(async_stream)
    }
}

#[async_trait(?Send)]
impl CaptureBufferReader for UnixBufferReader {
    async fn get_next_capture_period(
        &mut self,
        ex: &Executor,
    ) -> Result<AsyncCaptureBuffer, BoxError> {
        // Only open the host capture stream after start().
        if matches!(self.state, UnixCaptureStreamState::Starting) {
            self.state = match self.create_and_start_stream(ex).await {
                Ok(async_stream) => UnixCaptureStreamState::Started(async_stream),
                Err(e) => {
                    error!(
                        "[Card {}] Failed to create capture stream, capturing silence: {}",
                        self.card_index, e
                    );
                    UnixCaptureStreamState::StartFailed(NoopCaptureStream::new(
                        self.num_channels,
                        self.format,
                        self.frame_rate,
                        self.period_frames,
                    ))
                }
            };
        }

        match &mut self.state {
            UnixCaptureStreamState::Started(async_stream) => {
                async_stream.next_capture_buffer(ex).await
            }
            UnixCaptureStreamState::StartFailed(noop_stream) => {
                noop_stream.next_capture_buffer(ex).await
            }
            UnixCaptureStreamState::Stopped | UnixCaptureStreamState::Starting => {
                Err("capture stream is not started".into())
            }
        }
    }

    fn start(&mut self) -> Result<(), BoxError> {
        // Don't replace an open stream, and don't retry a failed one until stop().
        if matches!(self.state, UnixCaptureStreamState::Stopped) {
            self.state = UnixCaptureStreamState::Starting;
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), BoxError> {
        // Switch to Stopped first so that the stream is dropped even if stopping it fails.
        match std::mem::replace(&mut self.state, UnixCaptureStreamState::Stopped) {
            UnixCaptureStreamState::Started(mut async_stream) => async_stream.stop(),
            _ => Ok(()),
        }
    }
}

pub(crate) struct UnixBufferWriter {
    guest_period_bytes: usize,
}

#[async_trait(?Send)]
impl PlaybackBufferWriter for UnixBufferWriter {
    fn new(guest_period_bytes: usize) -> Self {
        UnixBufferWriter { guest_period_bytes }
    }
    fn endpoint_period_bytes(&self) -> usize {
        self.guest_period_bytes
    }
}

pub fn create_jail(
    params: &Parameters,
    jail_config: &JailConfig,
) -> anyhow::Result<Option<Minijail>> {
    let backend = params.backend;
    let policy = match backend {
        Backend::NULL | Backend::FILE => "snd_null_device",
        #[cfg(feature = "audio_aaudio")]
        Backend::Sys(StreamSourceBackend::AAUDIO) => "snd_aaudio_device",
        #[cfg(feature = "audio_cras")]
        Backend::Sys(StreamSourceBackend::CRAS) => "snd_cras_device",
        #[cfg(not(any(feature = "audio_cras", feature = "audio_aaudio")))]
        _ => unreachable!(),
    };

    let mut config = SandboxConfig::new(jail_config, policy);
    #[cfg(feature = "audio_cras")]
    if backend == Backend::Sys(StreamSourceBackend::CRAS) {
        config.bind_mounts = true;
    }
    // TODO(b/267574679): running as current_user may not be required for snd device.
    config.run_as = RunAsUser::CurrentUser;
    #[allow(unused_mut)]
    let mut jail =
        create_sandbox_minijail(&jail_config.pivot_root, MAX_OPEN_FILES_DEFAULT, &config)?;
    #[cfg(feature = "audio_cras")]
    if backend == Backend::Sys(StreamSourceBackend::CRAS) {
        let run_cras_path = Path::new("/run/cras");
        jail.mount_bind(run_cras_path, run_cras_path, true)?;
    }
    Ok(Some(jail))
}

#[cfg(test)]
#[cfg(feature = "audio_aaudio")]
mod tests {
    use std::os::unix::io::IntoRawFd;

    use super::*;

    fn setup() -> (FdPermissionDelegate, UnixStream) {
        let (client, host) = UnixStream::pair().expect("failed to create socketpair");
        (FdPermissionDelegate::new(client).unwrap(), host)
    }

    fn read_request(host: &mut UnixStream) {
        let mut req = [0u8; 1];
        host.read_exact(&mut req).expect("host failed to read req");
        assert_eq!(req[0], AudioPermissionRequest::Check.to_wire());
    }

    fn assert_no_request(host: &mut UnixStream) {
        host.set_nonblocking(true).unwrap();
        let err = host.read(&mut [0u8; 1]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    /// Sends a request, has the host answer with `resp`, and polls for the answer.
    fn answer(resp: u8) -> Poll<Result<bool, BoxError>> {
        let (delegate, mut host) = setup();
        delegate.request_permission().unwrap();
        read_request(&mut host);
        host.write_all(&[resp]).unwrap();
        delegate.poll_permission()
    }

    #[test]
    fn test_permission_delegate_granted() {
        let resp = answer(AudioPermissionResponse::Granted.to_wire());
        assert!(matches!(resp, Poll::Ready(Ok(true))));
    }

    #[test]
    fn test_permission_delegate_denied() {
        let resp = answer(AudioPermissionResponse::Denied.to_wire());
        assert!(matches!(resp, Poll::Ready(Ok(false))));
    }

    #[test]
    fn test_permission_delegate_invalid_response() {
        assert!(matches!(answer(99), Poll::Ready(Err(_))));
    }

    #[test]
    fn test_permission_delegate_peer_closed() {
        let (delegate, mut host) = setup();
        delegate.request_permission().unwrap();
        read_request(&mut host);
        drop(host);
        assert!(matches!(delegate.poll_permission(), Poll::Ready(Err(_))));
    }

    #[test]
    fn test_permission_delegate_pending() {
        let (delegate, _host) = setup();
        delegate.request_permission().unwrap();
        assert!(delegate.poll_permission().is_pending());
    }

    #[test]
    fn test_permission_delegate_dedups_requests() {
        let (delegate, mut host) = setup();
        delegate.request_permission().unwrap();
        delegate.request_permission().unwrap();
        read_request(&mut host);
        assert_no_request(&mut host);
    }

    #[test]
    fn test_permission_delegate_shares_answer() {
        let (delegate, mut host) = setup();
        delegate.request_permission().unwrap();
        read_request(&mut host);
        host.write_all(&[AudioPermissionResponse::Granted.to_wire()])
            .unwrap();
        assert!(matches!(delegate.poll_permission(), Poll::Ready(Ok(true))));
        // A second stream waiting on the same request gets the same answer.
        assert!(matches!(delegate.poll_permission(), Poll::Ready(Ok(true))));
        // The next start() asks again.
        delegate.request_permission().unwrap();
        read_request(&mut host);
    }

    #[test]
    fn test_permission_delegate_late_answer_applies_to_next_start() {
        let (delegate, mut host) = setup();
        delegate.request_permission().unwrap();
        read_request(&mut host);
        // The host answers after the stream that asked has stopped.
        host.write_all(&[AudioPermissionResponse::Denied.to_wire()])
            .unwrap();
        // The next start() joins the outstanding request and gets its answer.
        delegate.request_permission().unwrap();
        assert_no_request(&mut host);
        assert!(matches!(delegate.poll_permission(), Poll::Ready(Ok(false))));
    }

    #[test]
    fn test_permission_delegate_join_keeps_buffered_answer() {
        let (delegate, mut host) = setup();
        delegate.request_permission().unwrap(); // Stream A asks.
        read_request(&mut host);
        delegate.request_permission().unwrap(); // Stream B joins.
        host.write_all(&[AudioPermissionResponse::Granted.to_wire()])
            .unwrap();
        // Stream C starts before A or B polls: it must not discard the answer or ask again.
        delegate.request_permission().unwrap();
        assert_no_request(&mut host);
        assert!(matches!(delegate.poll_permission(), Poll::Ready(Ok(true))));
        // The other waiters get the same answer.
        assert!(matches!(delegate.poll_permission(), Poll::Ready(Ok(true))));
    }

    #[test]
    fn test_permission_delegate_discards_unsolicited_byte() {
        let (delegate, mut host) = setup();
        // A byte sent with no request outstanding must not answer the next Check.
        host.write_all(&[AudioPermissionResponse::Granted.to_wire()])
            .unwrap();
        delegate.request_permission().unwrap();
        read_request(&mut host);
        assert!(delegate.poll_permission().is_pending());
        host.write_all(&[AudioPermissionResponse::Denied.to_wire()])
            .unwrap();
        assert!(matches!(delegate.poll_permission(), Poll::Ready(Ok(false))));
    }

    #[test]
    fn test_create_aaudio_generators_with_and_without_permission_socket() {
        let mut keep_rds = Vec::new();
        let params_default = Parameters {
            backend: Backend::Sys(StreamSourceBackend::AAUDIO),
            ..Default::default()
        };
        let snd_data = crate::common_backend::hardcoded_snd_data(&params_default);

        // Without permission socket
        let generators =
            create_aaudio_stream_source_generators(&params_default, &snd_data, &mut keep_rds)
                .unwrap();
        assert!(keep_rds.is_empty());
        assert_eq!(generators.len(), snd_data.pcm_info_len());

        // With permission socket parsed from key-values. Inherited fds are not close-on-exec.
        let (client, _host) = UnixStream::pair().expect("failed to create socketpair");
        base::clear_descriptor_cloexec(&client).unwrap();
        let client_fd = client.into_raw_fd();
        let params_with_socket: Parameters = serde_keyvalue::from_key_values(&format!(
            "backend=aaudio,permission_socket_fd={client_fd}"
        ))
        .expect("failed to parse Parameters with permission_socket_fd");
        assert_eq!(params_with_socket.permission_socket_fd, Some(client_fd));

        let generators =
            create_aaudio_stream_source_generators(&params_with_socket, &snd_data, &mut keep_rds)
                .unwrap();
        // The delegate owns a validated duplicate of the fd.
        assert_eq!(keep_rds.len(), 1);
        assert_eq!(generators.len(), snd_data.pcm_info_len());
    }
}

#[cfg(test)]
mod capture_tests {
    use std::io::Read;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::time::Duration;

    use audio_streams::AudioStreamsExecutor;
    use audio_streams::NoopStreamControl;
    use audio_streams::NoopStreamSource;
    use audio_streams::PlaybackBufferStream;
    use audio_streams::StreamControl;
    use cros_async::TimerAsync;
    use futures::channel::mpsc;

    use super::*;
    use crate::common_backend::stream_info::SetParams;
    use crate::constants::VIRTIO_SND_D_INPUT;
    use crate::constants::VIRTIO_SND_R_PCM_PREPARE;

    const CHANNELS: usize = 2;
    const FORMAT: SampleFormat = SampleFormat::S16LE;
    const FRAME_RATE: u32 = 48000;
    // 1 ms periods keep the paced tests fast.
    const PERIOD_FRAMES: usize = 48;
    const FRAME_SIZE: usize = 4;
    const PERIOD_BYTES: usize = PERIOD_FRAMES * FRAME_SIZE;

    #[derive(Default)]
    struct Log {
        create_count: usize,
        start_count: usize,
        stop_count: usize,
        active_streams: usize,
        events: Vec<&'static str>,
    }

    #[derive(Clone, Default)]
    struct Shared {
        log: Arc<Mutex<Log>>,
        fail_create: Arc<AtomicBool>,
    }

    impl Shared {
        fn log(&self) -> MutexGuard<'_, Log> {
            self.log.lock().unwrap()
        }
    }

    /// Generates `CountingStreamSource`s for `StreamInfo` tests.
    struct CountingStreamSourceGenerator(Shared);

    impl StreamSourceGenerator for CountingStreamSourceGenerator {
        fn generate(&self) -> Result<Box<dyn StreamSource>, BoxError> {
            Ok(Box::new(CountingStreamSource {
                shared: self.0.clone(),
                inner: NoopStreamSource::new(),
            }))
        }
    }

    /// Stream source that records capture stream creation and its own drop.
    struct CountingStreamSource {
        shared: Shared,
        inner: NoopStreamSource,
    }

    impl Drop for CountingStreamSource {
        fn drop(&mut self) {
            self.shared.log().events.push("source_drop");
        }
    }

    impl StreamSource for CountingStreamSource {
        fn new_playback_stream(
            &mut self,
            num_channels: usize,
            format: SampleFormat,
            frame_rate: u32,
            buffer_size: usize,
        ) -> Result<(Box<dyn StreamControl>, Box<dyn PlaybackBufferStream>), BoxError> {
            self.inner
                .new_playback_stream(num_channels, format, frame_rate, buffer_size)
        }

        fn new_async_capture_stream(
            &mut self,
            num_channels: usize,
            format: SampleFormat,
            frame_rate: u32,
            buffer_size: usize,
            _effects: &[StreamEffect],
            _ex: &dyn AudioStreamsExecutor,
        ) -> Result<(Box<dyn StreamControl>, Box<dyn AsyncCaptureBufferStream>), BoxError> {
            if self.shared.fail_create.load(Ordering::SeqCst) {
                return Err("create failed".into());
            }
            let mut log = self.shared.log();
            log.create_count += 1;
            log.active_streams += 1;
            Ok((
                Box::new(NoopStreamControl::new()),
                Box::new(CountingCaptureStream {
                    shared: self.shared.clone(),
                    // Paces periods, so a running PCM worker yields to the executor.
                    inner: NoopCaptureStream::new(num_channels, format, frame_rate, buffer_size),
                }),
            ))
        }
    }

    /// Capture stream that records start/stop calls and its drop.
    struct CountingCaptureStream {
        shared: Shared,
        inner: NoopCaptureStream,
    }

    impl Drop for CountingCaptureStream {
        fn drop(&mut self) {
            let mut log = self.shared.log();
            log.active_streams -= 1;
            log.events.push("stream_drop");
        }
    }

    #[async_trait(?Send)]
    impl AsyncCaptureBufferStream for CountingCaptureStream {
        async fn next_capture_buffer<'a>(
            &'a mut self,
            ex: &dyn AudioStreamsExecutor,
        ) -> Result<AsyncCaptureBuffer<'a>, BoxError> {
            self.inner.next_capture_buffer(ex).await
        }

        fn start(&mut self) -> Result<(), BoxError> {
            let mut log = self.shared.log();
            log.start_count += 1;
            log.events.push("stream_start");
            Ok(())
        }

        fn stop(&mut self) -> Result<(), BoxError> {
            let mut log = self.shared.log();
            log.stop_count += 1;
            log.events.push("stream_stop");
            Ok(())
        }
    }

    fn new_reader(shared: &Shared) -> UnixBufferReader {
        UnixBufferReader::new(
            Box::new(CountingStreamSource {
                shared: shared.clone(),
                inner: NoopStreamSource::new(),
            }),
            CHANNELS,
            FORMAT,
            FRAME_RATE,
            PERIOD_FRAMES,
            Vec::new(),
            0,
        )
    }

    /// Reads one capture period and returns its bytes.
    fn read_period(ex: &Executor, reader: &mut UnixBufferReader) -> Result<Vec<u8>, BoxError> {
        ex.run_until(async {
            let mut buf = reader.get_next_capture_period(ex).await?;
            let mut data = vec![0xa5u8; PERIOD_BYTES * 2];
            let n = buf.read(&mut data)?;
            data.truncate(n);
            buf.commit().await;
            Ok::<_, BoxError>(data)
        })
        .unwrap()
    }

    /// Runs the executor until `cond` holds, or panics after a timeout.
    fn wait_until(ex: &Executor, shared: &Shared, cond: impl Fn(&Log) -> bool) {
        let met = ex
            .run_until(async {
                for _ in 0..1000 {
                    if cond(&shared.log()) {
                        return true;
                    }
                    TimerAsync::sleep(ex, Duration::from_millis(2))
                        .await
                        .unwrap();
                }
                false
            })
            .unwrap();
        assert!(met, "timed out waiting for condition");
    }

    fn new_prepared_capture_stream(ex: &Executor, shared: &Shared) -> StreamInfo {
        let mut stream = StreamInfo::builder(
            Arc::new(Box::new(CountingStreamSourceGenerator(shared.clone()))),
            0,
        )
        .build();
        ex.run_until(stream.set_params(SetParams {
            channels: CHANNELS as u8,
            format: FORMAT,
            frame_rate: FRAME_RATE,
            buffer_bytes: PERIOD_BYTES * 4,
            period_bytes: PERIOD_BYTES,
            dir: VIRTIO_SND_D_INPUT,
        }))
        .unwrap()
        .unwrap();
        let (tx_send, _) = mpsc::unbounded();
        let (rx_send, _) = mpsc::unbounded();
        ex.run_until(stream.prepare(ex, &tx_send, &rx_send))
            .unwrap()
            .unwrap();
        assert_eq!(stream.state, VIRTIO_SND_R_PCM_PREPARE);
        stream
    }

    #[test]
    fn test_prepare_without_start_does_not_open_capture_stream() {
        let ex = Executor::new().unwrap();
        let shared = Shared::default();
        let mut stream = new_prepared_capture_stream(&ex, &shared);

        // Let the PCM worker run for a few periods.
        ex.run_until(TimerAsync::sleep(&ex, Duration::from_millis(10)))
            .unwrap()
            .unwrap();
        assert_eq!(shared.log().create_count, 0);

        ex.run_until(stream.release()).unwrap().unwrap();
        let log = shared.log();
        assert_eq!(log.create_count, 0);
        assert_eq!(log.events, ["source_drop"]);
    }

    #[test]
    fn test_stream_info_capture_opens_on_start_closes_on_stop() {
        let ex = Executor::new().unwrap();
        let shared = Shared::default();
        let mut stream = new_prepared_capture_stream(&ex, &shared);

        ex.run_until(stream.start()).unwrap().unwrap();
        wait_until(&ex, &shared, |log| log.active_streams == 1);
        assert_eq!(shared.log().create_count, 1);
        assert_eq!(shared.log().start_count, 1);

        ex.run_until(stream.stop()).unwrap().unwrap();
        wait_until(&ex, &shared, |log| log.active_streams == 0);
        assert_eq!(shared.log().stop_count, 1);

        // START after STOP, without a new PREPARE, opens a new stream.
        ex.run_until(stream.start()).unwrap().unwrap();
        wait_until(&ex, &shared, |log| log.active_streams == 1);
        assert_eq!(shared.log().create_count, 2);

        ex.run_until(stream.stop()).unwrap().unwrap();
        ex.run_until(stream.release()).unwrap().unwrap();
        let log = shared.log();
        assert_eq!(log.active_streams, 0);
        assert_eq!(log.events.last(), Some(&"source_drop"));
    }

    #[test]
    fn test_reader_period_while_stopped_errors_without_opening() {
        let ex = Executor::new().unwrap();
        let shared = Shared::default();
        let mut reader = new_reader(&shared);
        assert!(matches!(reader.state, UnixCaptureStreamState::Stopped));

        assert!(read_period(&ex, &mut reader).is_err());
        assert!(matches!(reader.state, UnixCaptureStreamState::Stopped));
        assert_eq!(shared.log().create_count, 0);
    }

    #[test]
    fn test_reader_lazy_lifecycle_start_period_stop() {
        let ex = Executor::new().unwrap();
        let shared = Shared::default();
        let mut reader = new_reader(&shared);
        assert!(matches!(reader.state, UnixCaptureStreamState::Stopped));

        reader.start().unwrap();
        assert!(matches!(reader.state, UnixCaptureStreamState::Starting));
        // The stream is only created on the first period.
        assert_eq!(shared.log().create_count, 0);

        for _ in 0..3 {
            let data = read_period(&ex, &mut reader).unwrap();
            assert_eq!(data.len(), PERIOD_BYTES);
        }
        assert!(matches!(reader.state, UnixCaptureStreamState::Started(_)));
        {
            let log = shared.log();
            assert_eq!(log.create_count, 1);
            assert_eq!(log.start_count, 1);
            assert_eq!(log.active_streams, 1);
        }

        reader.stop().unwrap();
        assert!(matches!(reader.state, UnixCaptureStreamState::Stopped));
        let log = shared.log();
        assert_eq!(log.active_streams, 0);
        assert_eq!(log.events, ["stream_start", "stream_stop", "stream_drop"]);
    }

    #[test]
    fn test_reader_start_is_idempotent() {
        let ex = Executor::new().unwrap();
        let shared = Shared::default();
        let mut reader = new_reader(&shared);

        reader.start().unwrap();
        read_period(&ex, &mut reader).unwrap();
        reader.start().unwrap();
        read_period(&ex, &mut reader).unwrap();

        let log = shared.log();
        assert_eq!(log.create_count, 1);
        assert_eq!(log.start_count, 1);
    }

    #[test]
    fn test_reader_restart_reuses_source() {
        let ex = Executor::new().unwrap();
        let shared = Shared::default();
        let mut reader = new_reader(&shared);

        for _ in 0..2 {
            reader.start().unwrap();
            read_period(&ex, &mut reader).unwrap();
            reader.stop().unwrap();
        }

        let log = shared.log();
        assert_eq!(log.create_count, 2);
        assert_eq!(log.active_streams, 0);
        assert!(!log.events.contains(&"source_drop"));
    }

    #[test]
    fn test_reader_create_failure_falls_back_to_silence() {
        let ex = Executor::new().unwrap();
        let shared = Shared::default();
        let mut reader = new_reader(&shared);

        shared.fail_create.store(true, Ordering::SeqCst);
        reader.start().unwrap();
        assert!(matches!(reader.state, UnixCaptureStreamState::Starting));
        for _ in 0..2 {
            let data = read_period(&ex, &mut reader).unwrap();
            assert_eq!(data.len(), PERIOD_BYTES);
            assert!(data.iter().all(|&b| b == 0));
        }
        assert!(matches!(
            reader.state,
            UnixCaptureStreamState::StartFailed(_)
        ));
        assert_eq!(shared.log().create_count, 0);

        // The next START retries.
        shared.fail_create.store(false, Ordering::SeqCst);
        reader.stop().unwrap();
        assert!(matches!(reader.state, UnixCaptureStreamState::Stopped));
        reader.start().unwrap();
        assert!(matches!(reader.state, UnixCaptureStreamState::Starting));
        read_period(&ex, &mut reader).unwrap();
        assert!(matches!(reader.state, UnixCaptureStreamState::Started(_)));
        let log = shared.log();
        assert_eq!(log.create_count, 1);
        assert_eq!(log.active_streams, 1);
    }

    #[test]
    fn test_reader_drop_while_started_drops_stream_before_source() {
        let ex = Executor::new().unwrap();
        let shared = Shared::default();
        let mut reader = new_reader(&shared);

        reader.start().unwrap();
        read_period(&ex, &mut reader).unwrap();
        drop(reader);

        let log = shared.log();
        assert_eq!(log.stop_count, 0);
        assert_eq!(log.events, ["stream_start", "stream_drop", "source_drop"]);
    }
}
