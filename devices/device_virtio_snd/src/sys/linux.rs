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
use audio_streams::AsyncPlaybackBufferStream;
use audio_streams::BoxError;
use audio_streams::StreamSource;
use audio_streams::StreamSourceGenerator;
#[cfg(feature = "audio_cras")]
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
        ex: &Executor,
    ) -> Result<SysBufferReader, Error> {
        let async_capture_buffer_stream = self
            .stream_source
            .as_mut()
            .ok_or(Error::EmptyStreamSource)?
            .async_new_async_capture_stream(
                self.channels as usize,
                self.format,
                self.frame_rate,
                self.period_bytes / frame_size,
                &self.effects,
                ex,
            )
            .await
            .map_err(Error::CreateStream)?
            .1;
        Ok(SysBufferReader::new(async_capture_buffer_stream))
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

pub(crate) struct UnixBufferReader {
    async_stream: Box<dyn AsyncCaptureBufferStream>,
}

impl UnixBufferReader {
    fn new(async_stream: Box<dyn AsyncCaptureBufferStream>) -> Self
    where
        Self: Sized,
    {
        UnixBufferReader { async_stream }
    }
}
#[async_trait(?Send)]
impl CaptureBufferReader for UnixBufferReader {
    async fn get_next_capture_period(
        &mut self,
        ex: &Executor,
    ) -> Result<AsyncCaptureBuffer, BoxError> {
        Ok(self
            .async_stream
            .next_capture_buffer(ex)
            .await
            .map_err(Error::FetchBuffer)?)
    }

    fn start(&mut self) -> Result<(), BoxError> {
        self.async_stream.start()
    }

    fn stop(&mut self) -> Result<(), BoxError> {
        self.async_stream.stop()
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
