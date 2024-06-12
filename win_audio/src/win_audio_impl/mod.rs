// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/301630330): Address comments from CL once this is sync'd with downstream.

pub mod async_stream;
mod completion_handler;
mod device_notification;
mod wave_format;

use std::convert::From;
use std::fmt::Debug;
use std::num::ParseIntError;
use std::os::raw::c_void;
use std::ptr::null_mut;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::sync::Once;
use std::thread_local;
use std::time::Duration;

use async_trait::async_trait;
use audio_streams::async_api::EventAsyncWrapper;
use audio_streams::capture::AsyncCaptureBuffer;
use audio_streams::capture::CaptureBufferError;
use audio_streams::capture::NoopCaptureStream;
use audio_streams::AsyncBufferCommit;
use audio_streams::AsyncPlaybackBuffer;
use audio_streams::AsyncPlaybackBufferStream;
use audio_streams::AudioStreamsExecutor;
use audio_streams::BoxError;
use audio_streams::BufferCommit;
use audio_streams::NoopStream;
use audio_streams::NoopStreamControl;
use audio_streams::PlaybackBuffer;
use audio_streams::PlaybackBufferError;
use audio_streams::PlaybackBufferStream;
use audio_streams::SampleFormat;
use audio_streams::StreamControl;
use audio_streams::StreamSource;
use base::error;
use base::info;
use base::warn;
use base::AsRawDescriptor;
use base::Error;
use base::Event;
use base::EventExt;
use base::EventWaitResult;
use completion_handler::WinAudioActivateAudioInterfaceCompletionHandler;
use sync::Mutex;
use thiserror::Error as ThisError;
use wave_format::*;
use winapi::shared::guiddef::GUID;
use winapi::shared::guiddef::REFCLSID;
use winapi::um::audioclient::*;
use winapi::um::audiosessiontypes::AUDCLNT_SESSIONFLAGS_DISPLAY_HIDEWHENEXPIRED;
use winapi::um::audiosessiontypes::AUDCLNT_SESSIONFLAGS_EXPIREWHENUNOWNED;
use winapi::um::audiosessiontypes::AUDCLNT_SHAREMODE_SHARED;
use winapi::um::audiosessiontypes::AUDCLNT_STREAMFLAGS_EVENTCALLBACK;
use winapi::um::combaseapi::*;
use winapi::um::coml2api::STGM_READ;
use winapi::um::functiondiscoverykeys_devpkey::PKEY_Device_FriendlyName;
use winapi::um::mmdeviceapi::*;
use winapi::um::objbase::COINIT_APARTMENTTHREADED;
use winapi::um::propidl::PropVariantClear;
use winapi::um::propidl::PROPVARIANT;
use winapi::um::propsys::IPropertyStore;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::unknwnbase::IUnknown;
use winapi::um::winbase::WAIT_OBJECT_0;
use winapi::Interface;
use wio::com::ComPtr;

use crate::async_stream::log_init_error_with_limit;
use crate::async_stream::log_playback_error_with_limit;
use crate::intermediate_resampler_buffer::CaptureResamplerBuffer;
use crate::intermediate_resampler_buffer::PlaybackResamplerBuffer;
use crate::win_audio_impl::device_notification::WinIMMNotificationClient;
use crate::AudioSharedFormat;
use crate::ANDROID_CAPTURE_FRAME_SIZE_BYTES;
use crate::BYTES_PER_32FLOAT;

const READY_TO_READ_TIMEOUT_MS: u32 = 2000;
pub const STEREO_CHANNEL_COUNT: u16 = 2;
pub const MONO_CHANNEL_COUNT: u16 = 1;

// from msdn: https://docs.microsoft.com/en-us/windows/win32/coreaudio/audclnt-streamflags-xxx-constants
// these don't currently exist in winapi
const AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM: u32 = 0x80000000;
const AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY: u32 = 0x08000000;

thread_local!(static THREAD_ONCE_INIT: Once = const { Once::new() });

// Used to differentiate between S_FALSE and S_OK. This means `CoInitializeEx` did not get called.
// Mainly used for testing.
const S_SKIPPED_COINIT: i32 = 2;

const ACTIVATE_AUDIO_EVENT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct WinAudio {
    pub cached_playback_buffer_stream:
        Option<(Arc<Mutex<Box<dyn PlaybackBufferStream>>>, AudioSharedFormat)>,
}
impl WinAudio {
    pub fn new() -> Result<Self, BoxError> {
        Ok(WinAudio {
            cached_playback_buffer_stream: None,
        })
    }

    pub(crate) fn co_init_once_per_thread() -> i32 {
        let mut hr = S_SKIPPED_COINIT;
        THREAD_ONCE_INIT.with(|once| {
            once.call_once(|| {
                // SAFETY: All variables passed into `CoInitializeEx` are hardcoded
                unsafe {
                    // Initializes the COM library for use by the calling thread. Needed so that
                    // `CoCreateInstance` can be called to create a device
                    // enumerator object.
                    //
                    // TODO(b/217413370): `CoUninitialize` is never called at any point in KiwiVm.
                    // It might make sense for all VCPU threads to call `CoInitializeEx` when
                    // starting and `CoUninitialize` when the thread ends. However when switching to
                    // virtio-snd, we need to make sure cros_async threads get `Co(Un)Initialize`
                    // support if needed.
                    hr = CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED);
                };
            })
        });

        hr
    }
}

impl StreamSource for WinAudio {
    /// Returns a stream control and a buffer generator object. The stream control object is not
    /// used. The buffer generator object is a wrapper around WASAPI's objects that will create a
    /// buffer for crosvm to copy audio bytes into.
    fn new_playback_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize, //number of frames;
    ) -> Result<(Box<dyn StreamControl>, Box<dyn PlaybackBufferStream>), BoxError> {
        let hr = WinAudio::co_init_once_per_thread();
        let _ = check_hresult!(hr, WinAudioError::from(hr), "Co Initialized failed");

        let playback_buffer_stream: Box<dyn PlaybackBufferStream> =
            match WinAudioRenderer::new(num_channels, format, frame_rate, buffer_size) {
                Ok(renderer) => Box::new(renderer),
                Err(e) => {
                    warn!(
                        "Failed to create WinAudioRenderer. Fallback to NoopStream with error: {}",
                        e
                    );
                    Box::new(NoopStream::new(
                        num_channels,
                        SampleFormat::S16LE,
                        frame_rate,
                        buffer_size,
                    ))
                }
            };

        Ok((Box::new(NoopStreamControl::new()), playback_buffer_stream))
    }

    /// Similar to `new_playback_stream, but will return an `AsyncPlaybackBufferStream` that can
    /// run async operations.
    fn new_async_playback_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        ex: &dyn AudioStreamsExecutor,
    ) -> Result<(Box<dyn StreamControl>, Box<dyn AsyncPlaybackBufferStream>), BoxError> {
        WinAudio::new_async_playback_stream_helper(
            num_channels,
            format,
            frame_rate,
            buffer_size,
            ex,
        )
    }
}

/// Proxy for a `DeviceRenderer` that handles device invalidated errors by switching to a new
/// `DeviceRenderer` on a new device.
pub(crate) struct WinAudioRenderer {
    pub device: DeviceRendererWrapper,
    audio_client_guid: Option<String>,
}

impl WinAudioRenderer {
    /// Initializes WASAPI objects needed for audio. Only used for the Ac97 device.
    pub fn new(
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        incoming_buffer_size_in_frames: usize,
    ) -> Result<Self, RenderError> {
        let device = DeviceRendererWrapper::new(
            num_channels,
            format,
            frame_rate,
            incoming_buffer_size_in_frames,
            None,
            None,
        )?;
        Ok(Self {
            device,
            audio_client_guid: None,
        })
    }

    fn handle_playback_logging_on_error(e: &RenderError) {
        match &e {
            RenderError::WinAudioError(win_audio_error) => {
                log_playback_error_with_limit(win_audio_error.into());
                match win_audio_error {
                    WinAudioError::GetCurrentPaddingError(hr)
                    | WinAudioError::GetBufferError(hr) => {
                        if *hr == AUDCLNT_E_DEVICE_INVALIDATED {
                            info!(
                                "Recieved AUDLNT_E_DEVICE_INVALIDATED error. No devices \
                             attached, so will start listening for one."
                            );
                        } else {
                            warn!(
                                "Unknown HResult: {} from GetCurrentPadding or GetBufferError. \
                             Will still start listening for a new device",
                                hr
                            );
                        }
                    }
                    _ => warn!(
                        "Unexpected errors. Will still listen for a new device: {}",
                        win_audio_error
                    ),
                }
            }
            _ => {
                log_playback_error_with_limit((&WinAudioError::Unknown).into());
                warn!(
                    "Unexpected non WinAudioError. Will stil start listening for a new device: {}",
                    e
                );
            }
        }
    }

    /// Get the audio format used by the endpoint buffer, whether it be the `NoopStream` buffer
    /// or the WASAPI endpoint buffer.
    pub(crate) fn get_audio_shared_format(&self) -> AudioSharedFormat {
        match &self.device.renderer_stream {
            RendererStream::Device((device_renderer, _)) => device_renderer.audio_shared_format,
            RendererStream::Noop(_) => AudioSharedFormat {
                bit_depth: 32,
                frame_rate: self.device.guest_frame_rate as usize,
                channels: self.device.num_channels,
                shared_audio_engine_period_in_frames: self.device.incoming_buffer_size_in_frames,
                channel_mask: None,
            },
        }
    }
}

/// This is only used by the Ac97 device, so this impl is deprecated.
impl PlaybackBufferStream for WinAudioRenderer {
    /// Returns a wrapper around the WASAPI buffer.
    fn next_playback_buffer<'b, 's: 'b>(&'s mut self) -> Result<PlaybackBuffer<'b>, BoxError> {
        match &mut self.device.renderer_stream {
            RendererStream::Device((device_renderer, _)) => {
                match device_renderer.next_win_buffer() {
                    Ok(_) => {
                        return device_renderer
                            .playback_buffer()
                            .map_err(|e| Box::new(e) as _)
                    }
                    Err(e) => Err(Box::new(e)),
                }
            }
            RendererStream::Noop(_) => {
                error!("Unable to attach to a working audio device, giving up");
                Err(Box::new(WinAudioError::DeviceInvalidated))
            }
        }
    }
}

/// Used to help listen for device related events.
struct DeviceNotifier {
    // Used to register the `IMMNotificationClient`.
    device_enumerator: ComPtr<IMMDeviceEnumerator>,
    // Used to help detect when a new audio device has been attached.
    imm_notification_client: ComPtr<IMMNotificationClient>,
}

impl DeviceNotifier {
    /// Create the notification client that will listen to audio device events.
    pub(crate) fn create_imm_device_notification(
        is_device_available: Arc<AtomicBool>,
        dataflow: EDataFlow,
    ) -> Result<Self, WinAudioError> {
        let mut device_enumerator: *mut c_void = null_mut();

        // Creates a device enumerator in order to select our default audio device.
        //
        // SAFETY: Only `device_enumerator` is being modified and we own it.
        let hr = unsafe {
            CoCreateInstance(
                &CLSID_MMDeviceEnumerator as REFCLSID,
                null_mut(),
                CLSCTX_ALL,
                &IMMDeviceEnumerator::uuidof(),
                &mut device_enumerator,
            )
        };

        check_hresult!(
            hr,
            WinAudioError::GetDeviceEnumeratorError(hr),
            "Win audio create client CoCreateInstance() failed when trying to set up the \
             IMMNotificationClient."
        )?;

        let device_enumerator =
            // SAFETY: We know `device_enumerator` is a valid pointer, otherwise, we would've
            // returned with an error earlier.
            unsafe { ComPtr::from_raw(device_enumerator as *mut IMMDeviceEnumerator) };

        let imm_notification_client =
            WinIMMNotificationClient::create_com_ptr(is_device_available, dataflow);

        // SAFETY: The creation of `imm_notification_client` is always valid.
        let hr = unsafe {
            device_enumerator.RegisterEndpointNotificationCallback(imm_notification_client.as_raw())
        };
        check_hresult!(
            hr,
            WinAudioError::RegisterEndpointNotifError(hr),
            "Win audio errored on RegisterEndpointNotificationCallback."
        )?;

        Ok(DeviceNotifier {
            device_enumerator,
            imm_notification_client,
        })
    }
}

impl Drop for DeviceNotifier {
    // `device_enumerator` and `imm_notification_client` will call `Release` when they are dropped
    // since they are `ComPtr`s.
    fn drop(&mut self) {
        // SAFETY: The `notification_client` is a valid `IMMNotificationClient`.
        unsafe {
            self.device_enumerator
                .UnregisterEndpointNotificationCallback(self.imm_notification_client.as_raw());
        }
    }
}

pub(crate) struct NoopRenderer {
    // Playback stream that helps with sleeping in the playback loop when no devices are available.
    // Audio bytes coming from the guest will be dropped.
    noop_stream: NoopStream,
    // Help listen for device related events, so that a new audio device can be detected.
    _device_notifier: DeviceNotifier,
    // True if a new device is available.
    is_device_available: Arc<AtomicBool>,
}

pub(crate) enum RendererStream {
    Device(
        (
            DeviceRenderer,
            // Buffer that contains a sample rate converter and also helps with managing differing
            // periods between the guest and the host.
            PlaybackResamplerBuffer,
        ),
    ),
    Noop(NoopRenderer),
}

/// Wraps the `DeviceRenderer` and `NoopStream` so that they can easily be interchanged in the
/// middle of audio playback. This also contains fields that helps with creating the aforementioned
/// objects and helps with detecting a new audio device being connected.
pub(crate) struct DeviceRendererWrapper {
    // Helps manage a playback stream.
    pub(crate) renderer_stream: RendererStream,
    // Buffer sent to the CrosVm audio device (ie. Virtio Sound) for it to write to.
    intermediate_buffer: Vec<u8>,
    // guest channel count.
    num_channels: usize,
    // guest bit depth.
    guest_bit_depth: SampleFormat,
    // guest frame rate.
    guest_frame_rate: u32,
    // incoming buffer size from the guest per period.
    incoming_buffer_size_in_frames: usize,
}

impl DeviceRendererWrapper {
    /// If no audio device are detected, then the creation of `DeviceRenderer` will fail. In this
    /// case, a `NoopStream` will be created as well as the set up of the `IMMNotificationClient`.
    fn new(
        num_channels: usize,
        guest_bit_depth: SampleFormat,
        guest_frame_rate: u32,
        incoming_buffer_size_in_frames: usize,
        ex: Option<&dyn AudioStreamsExecutor>,
        audio_client_guid: Option<String>,
    ) -> Result<Self, RenderError> {
        let renderer_stream = match Self::create_device_renderer_and_log_time(
            num_channels,
            guest_frame_rate,
            incoming_buffer_size_in_frames,
            ex,
            audio_client_guid,
        ) {
            Ok(device) => {
                let audio_shared_format = device.audio_shared_format;
                let playback_resampler_buffer = PlaybackResamplerBuffer::new(
                    guest_frame_rate as usize,
                    audio_shared_format.frame_rate,
                    incoming_buffer_size_in_frames,
                    audio_shared_format.shared_audio_engine_period_in_frames,
                    audio_shared_format.channels,
                    audio_shared_format.channel_mask,
                )
                .expect("Failed to create PlaybackResamplerBuffer");

                RendererStream::Device((device, playback_resampler_buffer))
            }

            Err(e) => {
                Self::handle_init_logging_on_error(&e);
                Self::create_noop_stream_with_device_notification(
                    num_channels,
                    guest_frame_rate,
                    incoming_buffer_size_in_frames,
                )?
            }
        };

        Ok(Self {
            renderer_stream,
            intermediate_buffer: vec![
                0;
                incoming_buffer_size_in_frames
                    * num_channels
                    * guest_bit_depth.sample_bytes()
            ],
            num_channels,
            guest_bit_depth,
            guest_frame_rate,
            incoming_buffer_size_in_frames,
        })
    }

    fn handle_init_logging_on_error(e: &RenderError) {
        match &e {
            RenderError::WinAudioError(win_audio_error) => {
                match win_audio_error {
                    WinAudioError::MissingDeviceError(_) => {
                        info!(
                            "No audio playback devices were found. Will start listening for new \
                         devices"
                        );
                    }
                    _ => {
                        warn!(
                            "Unexpected WinAudioError on initialization. Will still listen for \
                        new devices: {}",
                            e
                        );
                    }
                }
                log_init_error_with_limit(win_audio_error.into());
            }
            _ => {
                log_init_error_with_limit((&WinAudioError::Unknown).into());
                error!(
                    "Unhandled NoopStream forced error. These errors should not have been \
                 returned. WIll still listen for new devices: {}",
                    e
                );
            }
        }
    }

    fn create_noop_stream_with_device_notification(
        num_channels: usize,
        guest_frame_rate: u32,
        incoming_buffer_size_in_frames: usize,
    ) -> Result<RendererStream, RenderError> {
        let is_device_available = Arc::new(AtomicBool::new(false));
        let noop_renderer = NoopRenderer {
            noop_stream: NoopStream::new(
                num_channels,
                SampleFormat::S32LE,
                guest_frame_rate,
                incoming_buffer_size_in_frames,
            ),
            _device_notifier: DeviceNotifier::create_imm_device_notification(
                is_device_available.clone(),
                eRender,
            )
            .map_err(RenderError::WinAudioError)?,
            is_device_available,
        };

        Ok(RendererStream::Noop(noop_renderer))
    }

    fn create_device_renderer_and_log_time(
        num_channels: usize,
        frame_rate: u32,
        incoming_buffer_size_in_frames: usize,
        ex: Option<&dyn AudioStreamsExecutor>,
        audio_client_guid: Option<String>,
    ) -> Result<DeviceRenderer, RenderError> {
        let start = std::time::Instant::now();
        let device = DeviceRenderer::new(
            num_channels,
            frame_rate,
            incoming_buffer_size_in_frames,
            ex,
            audio_client_guid,
        )?;
        // This can give us insights to how other long other machines take to initialize audio.
        // Eventually this should be a histogram metric.
        info!(
            "DeviceRenderer took {}ms to initialize audio.",
            start.elapsed().as_millis()
        );
        Ok(device)
    }

    fn get_intermediate_async_buffer(&mut self) -> Result<AsyncPlaybackBuffer, RenderError> {
        let guest_frame_size = self.num_channels * self.guest_bit_depth.sample_bytes();
        // SAFETY: `intermediate_buffer` doesn't get mutated by `Self` after this slice is
        // created.
        let slice = unsafe {
            std::slice::from_raw_parts_mut(
                self.intermediate_buffer.as_mut_ptr(),
                self.intermediate_buffer.len(),
            )
        };
        AsyncPlaybackBuffer::new(guest_frame_size, slice, self).map_err(RenderError::PlaybackBuffer)
    }
}

// SAFETY: DeviceRendererWrapper is safe to send between threads
unsafe impl Send for DeviceRendererWrapper {}

// Implementation of buffer generator object. Used to get a buffer from WASAPI for crosvm to copy
// audio bytes from the guest memory into.
pub(crate) struct DeviceRenderer {
    audio_render_client: ComPtr<IAudioRenderClient>,
    audio_client: ComPtr<IAudioClient>,
    win_buffer: *mut u8,
    pub audio_shared_format: AudioSharedFormat,
    audio_render_client_buffer_frame_count: u32,
    ready_to_read_event: Event,
    async_ready_to_read_event: Option<Box<dyn EventAsyncWrapper>>,
    // Set to true if we should call WASAPI's `GetBuffer`. This should be false if there aren't
    // enough bytes in `playback_resampler_buffer` to write a full Windows endpoint buffer period.
    should_get_next_win_buffer: bool,
}

impl DeviceRenderer {
    // Initializes WASAPI objects needed for audio
    fn new(
        num_channels: usize,
        guest_frame_rate: u32,
        incoming_buffer_size_in_frames: usize,
        ex: Option<&dyn AudioStreamsExecutor>,
        audio_client_guid: Option<String>,
    ) -> Result<Self, RenderError> {
        if num_channels > 2 {
            return Err(RenderError::WinAudioError(
                WinAudioError::InvalidChannelCount(num_channels),
            ));
        }

        info!("Render guest frame rate: {}", guest_frame_rate);

        let audio_client = create_audio_client(eRender).map_err(RenderError::WinAudioError)?;

        let format = get_valid_mix_format(&audio_client).map_err(RenderError::WinAudioError)?;

        let res = if let Some(audio_client_guid) = audio_client_guid {
            info!(
                "IAudioClient initializing with GUID: {:?}",
                audio_client_guid
            );
            Some(Self::convert_session_string_to_guid(audio_client_guid)?)
        } else {
            None
        };

        // SAFETY: `audio_client` is initialized
        let hr = unsafe {
            // Intializes the audio client by setting the buffer size in 100-nanoseconds and
            // specifying the format the audio bytes will be passed in as.
            // Setting `hnsBufferDuration` (in miilisecond units) to 0 will let the audio engine to
            // pick the size that will minimize latency.
            // `hnsPeriodicity` sets the device period and should always be 0 for shared mode.
            audio_client.Initialize(
                AUDCLNT_SHAREMODE_SHARED,
                AUDCLNT_STREAMFLAGS_EVENTCALLBACK
                    | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM
                    | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY
                    | AUDCLNT_SESSIONFLAGS_DISPLAY_HIDEWHENEXPIRED
                    | AUDCLNT_SESSIONFLAGS_EXPIREWHENUNOWNED,
                0, /* hnsBufferDuration */
                0, /* hnsPeriodicity */
                format.as_ptr(),
                match res {
                    Some(guid) => &guid as *const GUID,
                    None => null_mut(),
                },
            )
        };
        check_hresult!(
            hr,
            WinAudioError::AudioClientInitializationError(hr),
            "Audio Client Initialize() failed."
        )
        .map_err(RenderError::WinAudioError)?;

        let (ready_to_read_event, async_ready_to_read_event) =
            create_and_set_audio_client_event(&audio_client, &ex)
                .map_err(RenderError::WinAudioError)?;

        let audio_render_client = DeviceRenderer::create_audio_render_client(&audio_client)?;

        let shared_audio_engine_period_in_frames =
            get_device_period_in_frames(&audio_client, &format);

        let audio_render_client_buffer_frame_count =
            check_endpoint_buffer_size(&audio_client, shared_audio_engine_period_in_frames)
                .map_err(RenderError::WinAudioError)?;
        if incoming_buffer_size_in_frames % shared_audio_engine_period_in_frames != 0 {
            warn!(
                "Rendering: Guest period size: `{}` not divisible by shared audio engine period size: `{}`. \
                 Audio glitches may occur if sample rate conversion isn't on.",
                incoming_buffer_size_in_frames, shared_audio_engine_period_in_frames
            );
        }

        // SAFETY: `audio_client` is initialized
        let hr = unsafe {
            // Starts the audio stream for playback
            audio_client.Start()
        };
        check_hresult!(
            hr,
            WinAudioError::AudioClientStartError(hr),
            "Audio Render Client Start() failed."
        )
        .map_err(RenderError::WinAudioError)?;

        let audio_shared_format =
            format.create_audio_shared_format(shared_audio_engine_period_in_frames);
        Ok(Self {
            audio_render_client,
            audio_client,
            win_buffer: std::ptr::null_mut(),
            audio_shared_format,
            audio_render_client_buffer_frame_count,
            ready_to_read_event,
            async_ready_to_read_event,
            should_get_next_win_buffer: true,
        })
    }

    fn create_audio_render_client(
        audio_client: &IAudioClient,
    ) -> Result<ComPtr<IAudioRenderClient>, RenderError> {
        let mut audio_render_client: *mut c_void = null_mut();

        // SAFETY: `audio_client` is initialized
        let hr = unsafe {
            audio_client.GetService(
                &IID_IAudioRenderClient as *const GUID,
                &mut audio_render_client,
            )
        };
        check_hresult!(
            hr,
            WinAudioError::GetRenderClientError(hr),
            "Audio Client GetService() failed."
        )
        .map_err(RenderError::WinAudioError)?;

        // SAFETY: `audio_render_client` is guaranteed to be initialized
        unsafe {
            Ok(ComPtr::from_raw(
                audio_render_client as *mut IAudioRenderClient,
            ))
        }
    }

    // Returns a wraper around the WASAPI buffer
    fn next_win_buffer(&mut self) -> Result<(), RenderError> {
        // We will wait for windows to tell us when it is ready to take in the next set of
        // audio samples from the guest
        loop {
            // SAFETY: `ready_to_read_event` is guaranteed to be properly initialized
            // and `num_frames_padding` is property initliazed as an empty pointer.
            unsafe {
                let res = WaitForSingleObject(
                    self.ready_to_read_event.as_raw_descriptor(),
                    READY_TO_READ_TIMEOUT_MS,
                );
                if res != WAIT_OBJECT_0 {
                    warn!(
                        "Waiting for ready_to_read_event timed out after {} ms",
                        READY_TO_READ_TIMEOUT_MS
                    );
                    break;
                }
                if self.enough_available_frames()? {
                    break;
                }
            }
        }

        self.get_buffer()?;

        Ok(())
    }

    /// Returns true if the number of frames avaialble in the Windows playback buffer is at least
    /// the size of one full period worth of audio samples.
    fn enough_available_frames(&mut self) -> Result<bool, RenderError> {
        let mut num_frames_padding = 0u32;
        // SAFETY: `num_frames_padding` is an u32 and `GetCurrentPadding` is a simple
        // Windows function that shouldn't fail.
        let hr = unsafe { self.audio_client.GetCurrentPadding(&mut num_frames_padding) };
        check_hresult!(
            hr,
            WinAudioError::GetCurrentPaddingError(hr),
            "Audio Client GetCurrentPadding() failed."
        )
        .map_err(RenderError::WinAudioError)?;

        // If the available free frames is less than the frames that are being sent over from the
        // guest, then we want to only grab the number of frames available.
        let num_frames_available =
            (self.audio_render_client_buffer_frame_count - num_frames_padding) as usize;

        Ok(num_frames_available
            >= self
                .audio_shared_format
                .shared_audio_engine_period_in_frames)
    }

    fn get_buffer(&mut self) -> Result<(), RenderError> {
        self.win_buffer = std::ptr::null_mut();

        // This unsafe block will get the playback buffer and return the size of the buffer
        //
        // SAFETY:
        // This is safe because the contents of `win_buffer` will be
        // released when `ReleaseBuffer` is called in the `BufferCommit` implementation.
        unsafe {
            let hr = self.audio_render_client.GetBuffer(
                self.audio_shared_format
                    .shared_audio_engine_period_in_frames as u32,
                &mut self.win_buffer,
            );
            check_hresult!(
                hr,
                WinAudioError::GetBufferError(hr),
                "Audio Render Client GetBuffer failed."
            )
            .map_err(RenderError::WinAudioError)?;
        }

        Ok(())
    }

    fn playback_buffer(&mut self) -> Result<PlaybackBuffer, RenderError> {
        // SAFETY: `win_buffer` is allocated and retrieved from WASAPI. The size requested,
        // which we specified in `next_win_buffer` is exactly
        // `shared_audio_engine_period_in_frames`, so the size parameter should be valid.
        let (frame_size_bytes, buffer_slice) = unsafe {
            Self::get_frame_size_and_buffer_slice(
                self.audio_shared_format.bit_depth,
                self.audio_shared_format.channels,
                self.win_buffer,
                self.audio_shared_format
                    .shared_audio_engine_period_in_frames,
            )?
        };

        PlaybackBuffer::new(frame_size_bytes, buffer_slice, self)
            .map_err(RenderError::PlaybackBuffer)
    }

    /// # Safety
    ///
    /// Safe only if:
    ///   1. `win_buffer` is pointing to a valid buffer used for holding audio bytes.
    ///   2. `bit_depth`, `channels`, and `shared_audio_engine_period_in_frames` are accurate with
    ///      respect to `win_buffer`, so that a valid slice can be made.
    ///   3. The variables mentioned in reason "2." must calculate a size no greater than the size
    ///      of the buffer pointed to by `win_buffer`.
    unsafe fn get_frame_size_and_buffer_slice<'a>(
        bit_depth: usize,
        channels: usize,
        win_buffer: *mut u8,
        shared_audio_engine_period_in_frames: usize,
    ) -> Result<(usize, &'a mut [u8]), RenderError> {
        if win_buffer.is_null() {
            return Err(RenderError::InvalidBuffer);
        }

        let frame_size_bytes = bit_depth * channels / 8;

        Ok((
            frame_size_bytes,
            std::slice::from_raw_parts_mut(
                win_buffer,
                shared_audio_engine_period_in_frames * frame_size_bytes,
            ),
        ))
    }

    fn convert_session_string_to_guid(audio_client_guid: String) -> Result<GUID, RenderError> {
        let split_guid: Vec<&str> = audio_client_guid.split('-').collect();
        if split_guid.len() != 5 {
            return Err(RenderError::WinAudioError(
                WinAudioError::GuidSplitWrongSize(split_guid.len()),
            ));
        }

        let first = u32::from_str_radix(split_guid[0], 16)
            .map_err(|e| RenderError::WinAudioError(WinAudioError::GuidParseIntError(e)))?;
        let second = u16::from_str_radix(split_guid[1], 16)
            .map_err(|e| RenderError::WinAudioError(WinAudioError::GuidParseIntError(e)))?;
        let third = u16::from_str_radix(split_guid[2], 16)
            .map_err(|e| RenderError::WinAudioError(WinAudioError::GuidParseIntError(e)))?;

        let combined = split_guid[3].to_owned() + split_guid[4];
        let fourth_vec: Vec<String> = combined
            .chars()
            .collect::<Vec<char>>()
            .chunks(2)
            .map(|chunk| chunk.iter().collect())
            .collect();
        let fourth: Vec<u8> = fourth_vec
            .into_iter()
            .map(|byte_str| {
                u8::from_str_radix(&byte_str, 16)
                    .map_err(|e| RenderError::WinAudioError(WinAudioError::GuidParseIntError(e)))
            })
            .collect::<Result<Vec<u8>, RenderError>>()?;

        Ok(GUID {
            Data1: first,
            Data2: second,
            Data3: third,
            Data4: fourth
                .try_into()
                .map_err(|_| RenderError::WinAudioError(WinAudioError::GuidVecConversionError))?,
        })
    }
}

impl BufferCommit for DeviceRenderer {
    // Called after buffer from WASAPI is filled. This will allow the audio bytes to be played as
    // sound.
    fn commit(&mut self, nframes: usize) {
        // SAFETY: `audio_render_client` is initialized and parameters passed
        // into `ReleaseBuffer()` are valid
        unsafe {
            let hr = self.audio_render_client.ReleaseBuffer(nframes as u32, 0);
            let _ = check_hresult!(
                hr,
                WinAudioError::from(hr),
                "Audio Render Client ReleaseBuffer() failed"
            );
        }
    }
}

impl Drop for DeviceRenderer {
    fn drop(&mut self) {
        // SAFETY:
        // audio_client and audio_render_client will be released by ComPtr when dropped. Most likely
        // safe to Release() if audio_client fails to stop. The MSDN doc does not mention that it
        // will crash and this should be done anyways to prevent memory leaks
        unsafe {
            let hr = self.audio_client.Stop();
            let _ = check_hresult!(
                hr,
                WinAudioError::from(hr),
                "Audio Render Client Stop() failed."
            );
        }
    }
}

// SAFETY: DeviceRenderer is safe to send between threads
unsafe impl Send for DeviceRenderer {}

pub(crate) struct WinAudioCapturer {
    pub device: DeviceCapturerWrapper,
}

impl WinAudioCapturer {
    pub(crate) fn get_audio_shared_format(&self) -> AudioSharedFormat {
        match &self.device.capturer_stream {
            CapturerStream::Device((device_capturer, _, _)) => device_capturer.audio_shared_format,
            CapturerStream::Noop(_) => AudioSharedFormat {
                bit_depth: 16,
                frame_rate: self.device.guest_frame_rate as usize,
                channels: self.device.num_channels,
                shared_audio_engine_period_in_frames: self.device.guest_frame_rate as usize / 100,
                channel_mask: None,
            },
        }
    }
}

pub(crate) struct NoopBufferCommit;

#[async_trait(?Send)]
impl AsyncBufferCommit for NoopBufferCommit {
    // For capture, we don't need to `commit`, hence we no-op
    async fn commit(&mut self, _nframes: usize) {
        // No-op
    }
}

pub(crate) struct NoopCapturer {
    // Capture stream that helps with sleeping in the capture loop when no devices are available.
    // This will send 0's to the guest.
    noop_capture_stream: NoopCaptureStream,
    // Help listen for device related events, so that a new audio device can be detected.
    _device_notifier: DeviceNotifier,
    // True if a new device is available.
    is_device_available: Arc<AtomicBool>,
}

pub(crate) enum CapturerStream {
    Device(
        (
            DeviceCapturer,
            // Buffer that contains a sample rate converter and also helps with managing differing
            // periods between the guest and the host.
            CaptureResamplerBuffer,
            // The `AsyncCaptureBuffer` requires an `AsyncBufferCommit` trait, but Windows doesn't
            // need it.
            NoopBufferCommit,
        ),
    ),
    Noop(NoopCapturer),
}

pub(crate) struct DeviceCapturerWrapper {
    // Playback stream when an audio device is available.
    pub(crate) capturer_stream: CapturerStream,
    // guest channel count.
    num_channels: usize,
    // guest bit depth.
    guest_bit_depth: SampleFormat,
    // guest frame rate.
    guest_frame_rate: u32,
    // incoming buffer size from the guest per period.
    outgoing_buffer_size_in_frames: usize,
}

impl DeviceCapturerWrapper {
    fn new(
        num_channels: usize,
        guest_bit_depth: SampleFormat,
        guest_frame_rate: u32,
        outgoing_buffer_size_in_frames: usize,
        ex: Option<&dyn audio_streams::AudioStreamsExecutor>,
    ) -> Result<Self, CaptureError> {
        let capturer_stream = match Self::create_device_capturer_and_log_time(
            num_channels,
            guest_frame_rate,
            outgoing_buffer_size_in_frames,
            ex,
        ) {
            Ok(device) => {
                let audio_shared_format = device.audio_shared_format;
                let capture_resampler_buffer = CaptureResamplerBuffer::new_input_resampler(
                    audio_shared_format.frame_rate,
                    guest_frame_rate as usize,
                    outgoing_buffer_size_in_frames,
                    audio_shared_format.channels,
                    audio_shared_format.channel_mask,
                )
                .expect("Failed to create CaptureResamplerBuffer");

                CapturerStream::Device((device, capture_resampler_buffer, NoopBufferCommit))
            }
            Err(e) => {
                base::warn!("Creating DeviceCapturer failed: {}", e);
                Self::create_noop_capture_stream_with_device_notification(
                    num_channels,
                    guest_bit_depth,
                    guest_frame_rate,
                    outgoing_buffer_size_in_frames,
                )?
            }
        };
        Ok(Self {
            capturer_stream,
            num_channels,
            guest_bit_depth,
            guest_frame_rate,
            outgoing_buffer_size_in_frames,
        })
    }

    fn create_device_capturer_and_log_time(
        num_channels: usize,
        frame_rate: u32,
        outgoing_buffer_size_in_frames: usize,
        ex: Option<&dyn AudioStreamsExecutor>,
    ) -> Result<DeviceCapturer, CaptureError> {
        let start = std::time::Instant::now();
        let device =
            DeviceCapturer::new(num_channels, frame_rate, outgoing_buffer_size_in_frames, ex)?;
        // This can give us insights to how other long other machines take to initialize audio.
        // Eventually this should be a histogram metric.
        info!(
            "DeviceRenderer took {}ms to initialize audio.",
            start.elapsed().as_millis()
        );
        Ok(device)
    }

    /// Read from the Windows capture buffer into the resampler until the resampler has bytes
    /// available to be written to the guest.
    async fn drain_until_bytes_avaialable(
        device_capturer: &mut DeviceCapturer,
        capture_resampler_buffer: &mut CaptureResamplerBuffer,
        outgoing_buffer_size_in_frames: usize,
    ) -> Result<(), CaptureError> {
        while !capture_resampler_buffer.is_next_period_available() {
            device_capturer.async_next_win_buffer().await?;
            Self::drain_to_resampler(
                device_capturer,
                capture_resampler_buffer,
                outgoing_buffer_size_in_frames,
            )?;
        }
        Ok(())
    }

    /// Gets a slice of sample rate converted audio frames and return an `AsyncCaptureBuffer`
    /// with these audio frames to be used by the emulated audio device.
    ///
    /// This assumes the precondition that `capture_resmapler_buffer` has at least a period worth
    /// of audio frames available.
    fn get_async_capture_buffer<'a>(
        capture_resampler_buffer: &mut CaptureResamplerBuffer,
        noop_buffer_commit: &'a mut NoopBufferCommit,
    ) -> Result<AsyncCaptureBuffer<'a>, CaptureError> {
        match capture_resampler_buffer.get_next_period() {
            Some(next_period) => {
                // SAFETY: `next_period`'s buffer is owned by `capture_resampler_buffer`,
                // and the buffer won't be cleared until
                // `capture_resampler_buffer.get_next_period` is called again. That means the
                // clearing won't happen until `next_slice` has been written into the rx queue.
                let next_slice = unsafe {
                    std::slice::from_raw_parts_mut(next_period.as_mut_ptr(), next_period.len())
                };
                return AsyncCaptureBuffer::new(
                    ANDROID_CAPTURE_FRAME_SIZE_BYTES,
                    next_slice,
                    noop_buffer_commit,
                )
                .map_err(CaptureError::CaptureBuffer);
            }
            None => Err(CaptureError::ResamplerNoSamplesAvailable),
        }
    }

    /// Copy all the bytes from the Windows capture buffer into `CaptureResamplerBuffer`.
    ///
    /// This has a precondition that `win_buffer` is not null because `GetBuffer` has been called
    /// to get the next round of capture audio frames.
    fn drain_to_resampler(
        device_capturer: &mut DeviceCapturer,
        capture_resampler_buffer: &mut CaptureResamplerBuffer,
        outgoing_buffer_size_in_frames: usize,
    ) -> Result<(), CaptureError> {
        let mut slice = device_capturer.win_buffer.as_mut_slice();
        let audio_shared_format = device_capturer.audio_shared_format;
        // Guest period in buffer with the audio format provided by WASAPI.
        let guest_period_in_bytes =
            outgoing_buffer_size_in_frames * audio_shared_format.channels * BYTES_PER_32FLOAT;

        while !slice.is_empty() {
            if slice.len() >= guest_period_in_bytes {
                capture_resampler_buffer.convert_and_add(&slice[..guest_period_in_bytes]);
                slice = &mut slice[guest_period_in_bytes..];
            } else {
                capture_resampler_buffer.convert_and_add(slice);
                slice = &mut [];
            }
        }
        Ok(())
    }

    /// Set up a stream that write 0's and set up a listener for new audio capture devices.
    ///
    /// This call assumes that the last capture device has been disconnected and the
    /// `DeviceCapturer` no longer functions properly.
    fn create_noop_capture_stream_with_device_notification(
        num_channels: usize,
        guest_bit_depth: SampleFormat,
        guest_frame_rate: u32,
        outgoing_buffer_size_in_frames: usize,
    ) -> Result<CapturerStream, CaptureError> {
        let is_device_available = Arc::new(AtomicBool::new(false));
        let noop_renderer = NoopCapturer {
            noop_capture_stream: NoopCaptureStream::new(
                num_channels,
                guest_bit_depth,
                guest_frame_rate,
                outgoing_buffer_size_in_frames,
            ),
            _device_notifier: DeviceNotifier::create_imm_device_notification(
                is_device_available.clone(),
                eCapture,
            )
            .map_err(CaptureError::WinAudioError)?,
            is_device_available,
        };

        Ok(CapturerStream::Noop(noop_renderer))
    }
}

// SAFETY: DeviceCapturerWrapper can be sent between threads safely
unsafe impl Send for DeviceCapturerWrapper {}

pub(crate) struct DeviceCapturer {
    audio_capture_client: ComPtr<IAudioCaptureClient>,
    _audio_client: ComPtr<IAudioClient>,
    win_buffer: Vec<u8>,
    pub audio_shared_format: AudioSharedFormat,
    _ready_to_write_event: Event,
    async_ready_to_write_event: Option<Box<dyn EventAsyncWrapper>>,
    last_buffer_flags: u32,
}

impl DeviceCapturer {
    fn new(
        num_channels: usize,
        guest_frame_rate: u32,
        outgoing_buffer_size_in_frames: usize,
        ex: Option<&dyn audio_streams::AudioStreamsExecutor>,
    ) -> Result<Self, CaptureError> {
        if num_channels > 2 {
            return Err(CaptureError::WinAudioError(
                WinAudioError::InvalidChannelCount(num_channels),
            ));
        }

        info!("Capture guest frame rate: {}", guest_frame_rate);

        let audio_client = create_audio_client(eCapture).map_err(CaptureError::WinAudioError)?;

        let format = get_valid_mix_format(&audio_client).map_err(CaptureError::WinAudioError)?;

        // SAFETY: `audio_client` is initialized
        let hr = unsafe {
            // Intializes the audio client by setting the buffer size in 100-nanoseconds and
            // specifying the format the audio bytes will be passed in as.
            // Setting `hnsBufferDuration` (in miilisecond units) to 0 will let the audio engine to
            // pick the size that will minimize latency.
            // `hnsPeriodicity` sets the device period and should always be 0 for shared mode.
            audio_client.Initialize(
                AUDCLNT_SHAREMODE_SHARED,
                AUDCLNT_STREAMFLAGS_EVENTCALLBACK
                    | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM
                    | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY
                    | AUDCLNT_SESSIONFLAGS_DISPLAY_HIDEWHENEXPIRED
                    | AUDCLNT_SESSIONFLAGS_EXPIREWHENUNOWNED,
                0, /* hnsBufferDuration */
                0, /* hnsPeriodicity */
                format.as_ptr(),
                null_mut(),
            )
        };
        check_hresult!(
            hr,
            WinAudioError::from(hr),
            "Audio Client Initialize() failed."
        )
        .map_err(CaptureError::WinAudioError)?;

        let (_ready_to_write_event, async_ready_to_write_event) =
            create_and_set_audio_client_event(&audio_client, &ex)
                .map_err(CaptureError::WinAudioError)?;

        let audio_capture_client = Self::create_audio_capture_client(&audio_client)?;

        let shared_audio_engine_period_in_frames =
            get_device_period_in_frames(&audio_client, &format);

        if outgoing_buffer_size_in_frames % shared_audio_engine_period_in_frames != 0 {
            warn!(
                "Capture: Guest period size: `{}` not divisible by shared audio engine period size: `{}`. \
                 Audio glitches may occur if sample rate conversion isn't on.",
                outgoing_buffer_size_in_frames, shared_audio_engine_period_in_frames
            );
        }

        check_endpoint_buffer_size(&audio_client, shared_audio_engine_period_in_frames)
            .map_err(CaptureError::WinAudioError)?;

        // SAFETY: `audio_client` is initialized
        let hr = unsafe {
            // Starts the audio stream for capture
            audio_client.Start()
        };
        check_hresult!(
            hr,
            WinAudioError::from(hr),
            "Audio Render Client Start() failed."
        )
        .map_err(CaptureError::WinAudioError)?;

        Ok(Self {
            audio_capture_client,
            _audio_client: audio_client,
            win_buffer: Vec::new(),
            audio_shared_format: format
                .create_audio_shared_format(shared_audio_engine_period_in_frames),
            _ready_to_write_event,
            async_ready_to_write_event,
            last_buffer_flags: 0,
        })
    }

    fn create_audio_capture_client(
        audio_client: &IAudioClient,
    ) -> Result<ComPtr<IAudioCaptureClient>, CaptureError> {
        let mut audio_capture_client: *mut c_void = null_mut();

        // SAFETY: `audio_client` is initialized
        let hr = unsafe {
            audio_client.GetService(
                &IID_IAudioCaptureClient as *const GUID,
                &mut audio_capture_client,
            )
        };
        check_hresult!(
            hr,
            WinAudioError::from(hr),
            "Audio Client GetService() failed."
        )
        .map_err(CaptureError::WinAudioError)?;

        // SAFETY: `audio_capture_client` is guaranteed to be initialized
        unsafe {
            Ok(ComPtr::from_raw(
                audio_capture_client as *mut IAudioCaptureClient,
            ))
        }
    }

    // Returns a wrapper around the WASAPI buffer
    async fn async_next_win_buffer(&mut self) -> Result<(), CaptureError> {
        self.win_buffer.clear();

        // We will wait for windows to tell us when it is ready to take in the next set of
        // audio samples from the guest
        let async_ready_to_write_event =
            self.async_ready_to_write_event
                .as_ref()
                .ok_or(CaptureError::WinAudioError(
                    WinAudioError::MissingEventAsync,
                ))?;

        // Unlike the sync version, there is no timeout anymore. So we could get stuck here,
        // although it is unlikely.
        async_ready_to_write_event.wait().await.map_err(|e| {
            CaptureError::WinAudioError(WinAudioError::AsyncError(
                e,
                "Failed to wait for async event to get next capture buffer.".to_string(),
            ))
        })?;

        // TODO(b/253506231): Might need to check for a full period of bytes before returning from
        // this function on AMD. For playback, there was a bug caused from us not doing this.

        self.get_buffer()?;

        Ok(())
    }

    // Drain the capture buffer and store the bytes in `win_buffer`.
    fn get_buffer(&mut self) -> Result<(), CaptureError> {
        // SAFETY:
        //   - `GetBuffer` only take output parameters that are all defined in this unsafe block.
        //   - `ReleaseBuffer` is called after the audio bytes are copied to `win_buffer`, so the
        //     audio bytes from `GetBuffer` will remain valid long enough.
        unsafe {
            let mut packet_length = self.next_packet_size()?;

            // The Windows documentation recommends calling `GetBuffer` until `GetNextPacketSize`
            // returns 0.
            while packet_length != 0 {
                let mut buffer = std::ptr::null_mut();
                let mut num_frames_available = 0;
                let mut flags = 0;

                // Position variables unused for now, but may be useful for debugging.
                let mut device_position = 0;
                let mut qpc_position = 0;
                let hr = self.audio_capture_client.GetBuffer(
                    &mut buffer,
                    &mut num_frames_available,
                    &mut flags,
                    &mut device_position,
                    &mut qpc_position,
                );
                check_hresult!(
                    hr,
                    WinAudioError::from(hr),
                    "Audio Capture Client GetBuffer failed."
                )
                .map_err(CaptureError::WinAudioError)?;

                let buffer_slice = std::slice::from_raw_parts_mut(
                    buffer,
                    num_frames_available as usize
                        * self.audio_shared_format.channels
                        * self.audio_shared_format.bit_depth
                        / 8,
                );

                if flags != 0 && self.last_buffer_flags != flags {
                    warn!(
                        "Audio Cature Client GetBuffer flags were not 0: {}",
                        Self::get_buffer_flags_to_string(flags)
                    );

                    self.last_buffer_flags = flags;
                }

                if flags & AUDCLNT_BUFFERFLAGS_SILENT == 0 {
                    self.win_buffer.extend_from_slice(buffer_slice);
                } else {
                    self.win_buffer
                        .resize(self.win_buffer.len() + buffer_slice.len(), 0);
                }

                let hr = self
                    .audio_capture_client
                    .ReleaseBuffer(num_frames_available);
                check_hresult!(
                    hr,
                    WinAudioError::from(hr),
                    "Audio Capture Client ReleaseBuffer() failed"
                )
                .map_err(CaptureError::WinAudioError)?;

                packet_length = self.next_packet_size()?;
            }
        }

        Ok(())
    }

    fn next_packet_size(&self) -> Result<u32, CaptureError> {
        let mut len = 0;
        // SAFETY: `len` is a valid u32.
        let hr = unsafe { self.audio_capture_client.GetNextPacketSize(&mut len) };
        check_hresult!(
            hr,
            WinAudioError::from(hr),
            "Capture GetNextPacketSize() failed."
        )
        .map_err(CaptureError::WinAudioError)?;
        Ok(len)
    }

    fn get_buffer_flags_to_string(flags: u32) -> String {
        let mut result = Vec::new();
        if flags & AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY != 0 {
            result.push("AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY".to_string());
        }
        if flags & AUDCLNT_BUFFERFLAGS_SILENT != 0 {
            result.push("AUDCLNT_BUFFERFLAGS_SILENT".to_string());
        }
        if flags & AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR != 0 {
            result.push("AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR".to_string());
        }
        result.join(" | ")
    }
}

// SAFETY: DeviceCapturer can be sent between threads safely
unsafe impl Send for DeviceCapturer {}

// Create the `IAudioClient` which is used to create `IAudioRenderClient`, which is used for
// audio playback, or used to create `IAudioCaptureClient`, which is used for audio capture.
fn create_audio_client(dataflow: EDataFlow) -> Result<ComPtr<IAudioClient>, WinAudioError> {
    let mut device_enumerator: *mut c_void = null_mut();

    // Creates a device enumerator in order to select our default audio device.
    //
    // SAFETY: Only `device_enumerator` is being modified and we own it.
    let hr = unsafe {
        CoCreateInstance(
            &CLSID_MMDeviceEnumerator as REFCLSID,
            null_mut(),
            CLSCTX_ALL,
            &IMMDeviceEnumerator::uuidof(),
            &mut device_enumerator,
        )
    };
    check_hresult!(
        hr,
        WinAudioError::GetDeviceEnumeratorError(hr),
        "Win audio create client CoCreateInstance() failed."
    )?;

    let device_enumerator =
        // SAFETY: `device_enumerator` is guaranteed to be initialized
        unsafe { ComPtr::from_raw(device_enumerator as *mut IMMDeviceEnumerator) };

    let mut device: *mut IMMDevice = null_mut();
    // SAFETY: `device_enumerator` is guaranteed to be initialized otherwise this method
    // would've exited
    let hr = unsafe { device_enumerator.GetDefaultAudioEndpoint(dataflow, eConsole, &mut device) };
    check_hresult!(
        hr,
        WinAudioError::MissingDeviceError(hr),
        "Device Enumerator GetDefaultAudioEndpoint() failed."
    )?;

    // SAFETY: `device` is guaranteed to be initialized
    let device = unsafe { ComPtr::from_raw(device) };
    print_device_info(&device)?;

    let is_render = if dataflow == eRender { true } else { false };

    // Call Windows API functions to get the `async_op` which will be used to retrieve the
    // AudioClient. More details above function definition.
    let async_op = enable_auto_stream_routing_and_wait(is_render)?;

    let mut factory: *mut IUnknown = null_mut();

    // SAFETY: `async_op` should be initialized at this point.
    let activate_result_hr = unsafe {
        let mut activate_result_hr = 0;
        let hr = (*async_op).GetActivateResult(&mut activate_result_hr, &mut factory);

        check_hresult!(
            hr,
            WinAudioError::GetActivateResultError(hr),
            "GetActivateResult failed. Cannot retrieve factory to create the Audio Client."
        )?;

        activate_result_hr
    };
    check_hresult!(
        activate_result_hr,
        WinAudioError::ActivateResultRunningError(activate_result_hr),
        "activateResult is an error. Cannot retrieve factory to create the Audio Client."
    )?;

    // SAFETY: `factory` is guaranteed to be initialized.
    let factory = unsafe { ComPtr::from_raw(factory) };

    factory.cast().map_err(WinAudioError::from)
}

// Enables automatic audio device routing (only will work for Windows 10, version 1607+).
// This will return IActivateAudioInterfaceAsyncOperation that can be used to retrive the
// AudioClient.
//
// This function will pretty much works as follows:
// 1. Create the parameters to pass into `ActivateAudioInterfaceAsync`
// 2. Call `ActivateAudioInterfaceAsync` which will run asynchrnously and will call a callback when
//    completed.
// 3. Wait on an event that will be notified when that callback is triggered.
// 4. Return an IActivateAudioInterfaceAsyncOperation which can be used to retrived the AudioClient.
fn enable_auto_stream_routing_and_wait(
    is_render: bool,
) -> Result<ComPtr<IActivateAudioInterfaceAsyncOperation>, WinAudioError> {
    // Event that fires when callback is called.
    let activate_audio_interface_complete_event =
        Event::new_auto_reset().map_err(WinAudioError::CreateActivateAudioEventError)?;

    let cloned_activate_event = activate_audio_interface_complete_event
        .try_clone()
        .map_err(WinAudioError::CloneEvent)?;

    // Create the callback that is called when `ActivateAudioInterfaceAsync` is finished.
    // The field `parent` is irrelevant and is only there to fill in the struct so that
    // this code will run. `ActivateCompleted` is the callback.
    let completion_handler =
        WinAudioActivateAudioInterfaceCompletionHandler::create_com_ptr(cloned_activate_event);

    // Retrieve GUID that represents the default audio device.
    let mut audio_direction_guid_string: *mut u16 = std::ptr::null_mut();

    // This will get the GUID that represents the device we want `ActivateAudioInterfaceAsync`
    // to activate. `DEVINTERFACE_AUDIO_RENDER` represents the users default audio render device, so
    // as a result Windows will always route sound to the default device. Likewise,
    // `DEVINTERFACE_AUDIO_CAPTURE` represents the default audio capture device.
    //
    // SAFETY: We own `audio_direction_guid_string`.
    let hr = unsafe {
        if is_render {
            StringFromIID(
                &DEVINTERFACE_AUDIO_RENDER as *const winapi::shared::guiddef::GUID,
                &mut audio_direction_guid_string,
            )
        } else {
            StringFromIID(
                &DEVINTERFACE_AUDIO_CAPTURE as *const winapi::shared::guiddef::GUID,
                &mut audio_direction_guid_string,
            )
        }
    };
    check_hresult!(
        hr,
        WinAudioError::from(hr),
        format!(
            "Failed to retrive DEVINTERFACE_AUDIO GUID for {}",
            if is_render { "rendering" } else { "capturing" }
        )
    )?;

    let mut async_op: *mut IActivateAudioInterfaceAsyncOperation = std::ptr::null_mut();

    // This will asynchronously run and when completed, it will trigger the
    // `IActivateINterfaceCompletetionHandler` callback.
    // The callback is where the AudioClient can be retrived. This would be easier in C/C++,
    // but since in rust the callback is an extern function, it would be difficult to get the
    // `IAudioClient` from the callback to the scope here, so we use an
    // event to wait for the callback.
    //
    // SAFETY: We own async_op and the completion handler.
    let hr = unsafe {
        ActivateAudioInterfaceAsync(
            audio_direction_guid_string,
            &IAudioClient::uuidof(),
            /* activateParams= */ std::ptr::null_mut(),
            completion_handler.as_raw(),
            &mut async_op,
        )
    };

    // We want to free memory before error checking for `ActivateAudioInterfaceAsync` to prevent
    // a memory leak.
    //
    // SAFETY: `audio_direction_guid_string` should have valid memory
    // and we are freeing up memory here.
    unsafe {
        CoTaskMemFree(audio_direction_guid_string as *mut std::ffi::c_void);
    }

    check_hresult!(
        hr,
        WinAudioError::from(hr),
        "`Activate AudioInterfaceAsync failed."
    )?;

    // Wait for `ActivateAudioInterfaceAsync` to finish. `ActivateAudioInterfaceAsync` should
    // never hang, but added a long timeout just incase.
    match activate_audio_interface_complete_event.wait_timeout(ACTIVATE_AUDIO_EVENT_TIMEOUT) {
        Ok(event_result) => match event_result {
            EventWaitResult::Signaled => {}
            EventWaitResult::TimedOut => {
                return Err(WinAudioError::ActivateAudioEventTimeoutError);
            }
        },
        Err(e) => {
            return Err(WinAudioError::ActivateAudioEventError(e));
        }
    }

    // SAFETY: We own `async_op` and it shouldn't be null if the activate audio event
    // fired.
    unsafe { Ok(ComPtr::from_raw(async_op)) }
}

/// Wrapper for dropping `PROPVARIANT` when out of scope.
///
/// Safe when `prop_variant` is set to a valid `PROPVARIANT`
struct SafePropVariant {
    prop_variant: PROPVARIANT,
}

impl Drop for SafePropVariant {
    fn drop(&mut self) {
        // SAFETY: `prop_variant` is set to a valid `PROPVARIANT` and won't be dropped elsewhere.
        unsafe {
            PropVariantClear(&mut self.prop_variant);
        }
    }
}

// Prints the friendly name for audio `device` to the log.
// Safe when `device` is guaranteed to be successfully initialized.
fn print_device_info(device: &IMMDevice) -> Result<(), WinAudioError> {
    let mut props: *mut IPropertyStore = null_mut();
    // SAFETY: `device` is guaranteed to be initialized
    let hr = unsafe { device.OpenPropertyStore(STGM_READ, &mut props) };
    check_hresult!(
        hr,
        WinAudioError::from(hr),
        "Win audio OpenPropertyStore failed."
    )?;

    // SAFETY: `props` is guaranteed to be initialized
    let props = unsafe { ComPtr::from_raw(props) };

    let mut prop_variant: PROPVARIANT = Default::default();
    // SAFETY: `props` is guaranteed to be initialized
    let hr = unsafe { props.GetValue(&PKEY_Device_FriendlyName, &mut prop_variant) };
    check_hresult!(
        hr,
        WinAudioError::from(hr),
        "Win audio property store GetValue failed."
    )?;
    let safe_prop_variant = SafePropVariant { prop_variant };

    // SAFETY: `val` was populated by a successful GetValue call that returns a pwszVal
    if unsafe { safe_prop_variant.prop_variant.data.pwszVal().is_null() } {
        warn!("Win audio property store GetValue returned a null string");
        return Err(WinAudioError::GenericError);
    }
    // SAFETY: `val` was populated by a successful GetValue call that returned a non-null
    // null-terminated pwszVal
    let device_name = unsafe {
        win_util::from_ptr_win32_wide_string(*(safe_prop_variant.prop_variant).data.pwszVal())
    };
    info!("Creating audio client: {}", device_name);

    Ok(())
}

// TODO(b/259476096): Once Ac97 is deprecated, we won't need to return a regular `Event`.
fn create_and_set_audio_client_event(
    audio_client: &IAudioClient,
    ex: &Option<&dyn audio_streams::AudioStreamsExecutor>,
) -> Result<(Event, Option<Box<dyn EventAsyncWrapper>>), WinAudioError> {
    let ready_event = Event::new_auto_reset().unwrap();
    // SAFETY: `ready_event` will be initialized and also it will have the same
    // lifetime as `audio_client` because they are owned by DeviceRenderer or DeviceCapturer on
    // return.
    let hr = unsafe { audio_client.SetEventHandle(ready_event.as_raw_descriptor()) };
    check_hresult!(
        hr,
        WinAudioError::SetEventHandleError(hr),
        "SetEventHandle() failed."
    )?;

    let async_ready_event = if let Some(ex) = ex {
        // SAFETY:
        // Unsafe if `ready_event` and `async_ready_event` have different
        // lifetimes because both can close the underlying `RawDescriptor`. However, both
        // will be stored in the `DeviceRenderer` or `DeviceCapturer` fields, so this should be
        // safe.
        Some(unsafe {
            ex.async_event(ready_event.as_raw_descriptor())
                .map_err(|e| {
                    WinAudioError::AsyncError(e, "Failed to create async event".to_string())
                })?
        })
    } else {
        None
    };
    Ok((ready_event, async_ready_event))
}

fn get_device_period_in_frames(audio_client: &IAudioClient, format: &WaveAudioFormat) -> usize {
    let mut shared_default_size_in_100nanoseconds: i64 = 0;
    let mut exclusive_min: i64 = 0;
    // SAFETY: `GetDevicePeriod` is taking in intialized valid i64's on the stack created above.
    unsafe {
        audio_client.GetDevicePeriod(
            &mut shared_default_size_in_100nanoseconds,
            &mut exclusive_min,
        );
    };

    format.get_shared_audio_engine_period_in_frames(shared_default_size_in_100nanoseconds as f64)
}

fn check_endpoint_buffer_size(
    audio_client: &IAudioClient,
    shared_audio_engine_period_in_frames: usize,
) -> Result<u32, WinAudioError> {
    let mut audio_client_buffer_frame_count: u32 = 0;
    // SAFETY: audio_client_buffer_frame_count is created above.
    let hr = unsafe { audio_client.GetBufferSize(&mut audio_client_buffer_frame_count) };
    check_hresult!(
        hr,
        WinAudioError::GetBufferSizeError(hr),
        "Audio Client GetBufferSize() failed."
    )?;

    if audio_client_buffer_frame_count < shared_audio_engine_period_in_frames as u32 {
        warn!(
            "The Windows audio engine period size in frames: {} /
            is bigger than the Audio Client's buffer size in frames: {}",
            shared_audio_engine_period_in_frames, audio_client_buffer_frame_count
        );
        return Err(WinAudioError::InvalidIncomingBufferSize);
    }
    Ok(audio_client_buffer_frame_count)
}

// TODO(b/253509368): Rename error so it is more generic for rendering and capturing.
#[derive(Debug, ThisError)]
pub enum WinAudioError {
    #[error("An unknown error has occurred.")]
    Unknown,
    /// The audio device was unplugged or became unavailable.
    #[error("win audio device invalidated")]
    DeviceInvalidated,
    /// A Windows API error occurred.
    /// "unknown win audio error HResult: {}, error code: {}"
    #[error("unknown win audio error HResult: {0}, error code: {1}")]
    WindowsError(i32, Error),
    #[error("buffer pointer is null")]
    InvalidBuffer,
    #[error("playback buffer error: {0}")]
    PlaybackBuffer(PlaybackBufferError),
    #[error("Incoming buffer size invalid")]
    InvalidIncomingBufferSize,
    #[error("Failed to wait for Activate Audio Event callback: {0}")]
    ActivateAudioEventError(Error),
    #[error("Failed to create Activate Audio Event: {0}")]
    CreateActivateAudioEventError(Error),
    #[error("Timed out waiting for Activate Audio Event callback.")]
    ActivateAudioEventTimeoutError,
    #[error("Something went wrong in windows audio.")]
    GenericError,
    #[error("Invalid guest channel count {0} is > than 2")]
    InvalidChannelCount(usize),
    #[error("Async related error: {0}: {1}")]
    AsyncError(std::io::Error, String),
    #[error("Ready to read async event was not set during win_audio initialization.")]
    MissingEventAsync,
    #[error("Failed to clone an event: {0}")]
    CloneEvent(Error),
    #[error("Failed to retrieve device enumerator. HResult: {0}")]
    GetDeviceEnumeratorError(i32),
    #[error("No audio device available. HResult: {0}")]
    MissingDeviceError(i32),
    #[error("Failed to run GetActivateResult. HResult: {0}")]
    GetActivateResultError(i32),
    #[error("Error while running GetActivateResult. HResult: {0}")]
    ActivateResultRunningError(i32),
    #[error("The AudioClient failed to initialize. HResult: {0}")]
    AudioClientInitializationError(i32),
    #[error("The AudioClient failed to set the event handle. HResult: {0}")]
    SetEventHandleError(i32),
    #[error("Failed to retrieve the rendering client. HResult: {0}")]
    GetRenderClientError(i32),
    #[error("The AudioClient failed to get the buffer size. HResult: {0}")]
    GetBufferSizeError(i32),
    #[error("The AudioClient failed to start. HResult: {0}")]
    AudioClientStartError(i32),
    #[error("GetCurrentPadding failed. This could mean the user disconnected their last audio device. HResult: {0}")]
    GetCurrentPaddingError(i32),
    #[error("GetBuffer failed during playback. HResult: {0}")]
    GetBufferError(i32),
    #[error("Failed to register IMMNotificationClient. HResult: {0}")]
    RegisterEndpointNotifError(i32),
    #[error("ReleaseBuffer failed. HResult: {0}")]
    ReleaseBufferError(i32),
    #[error("Failed to parse part of a guid: {0}")]
    GuidParseIntError(ParseIntError),
    #[error("Guid split size is not len 5. It is: {0}")]
    GuidSplitWrongSize(usize),
    #[error("Failed to convert Vector to a slice")]
    GuidVecConversionError,
}

impl From<&WinAudioError> for i64 {
    fn from(error: &WinAudioError) -> i64 {
        let (err_type, hr) = match error {
            WinAudioError::Unknown => (0, 0),
            WinAudioError::GetDeviceEnumeratorError(hr) => (1, *hr),
            WinAudioError::MissingDeviceError(hr) => (2, *hr),
            WinAudioError::GetActivateResultError(hr) => (3, *hr),
            WinAudioError::ActivateResultRunningError(hr) => (4, *hr),
            WinAudioError::AudioClientInitializationError(hr) => (5, *hr),
            WinAudioError::SetEventHandleError(hr) => (6, *hr),
            WinAudioError::GetRenderClientError(hr) => (7, *hr),
            WinAudioError::GetBufferSizeError(hr) => (8, *hr),
            WinAudioError::AudioClientStartError(hr) => (9, *hr),
            WinAudioError::DeviceInvalidated => (10, 0),
            WinAudioError::WindowsError(hr, _) => (11, *hr),
            WinAudioError::InvalidBuffer => (12, 0),
            WinAudioError::PlaybackBuffer(_) => (13, 0),
            WinAudioError::InvalidIncomingBufferSize => (14, 0),
            WinAudioError::ActivateAudioEventError(_) => (15, 0),
            WinAudioError::CreateActivateAudioEventError(_) => (16, 0),
            WinAudioError::ActivateAudioEventTimeoutError => (17, 0),
            WinAudioError::GenericError => (18, 0),
            WinAudioError::InvalidChannelCount(_) => (19, 0),
            WinAudioError::AsyncError(_, _) => (20, 0),
            WinAudioError::MissingEventAsync => (21, 0),
            WinAudioError::CloneEvent(_) => (22, 0),
            WinAudioError::GetCurrentPaddingError(hr) => (23, *hr),
            WinAudioError::GetBufferError(hr) => (24, *hr),
            WinAudioError::RegisterEndpointNotifError(hr) => (25, *hr),
            WinAudioError::ReleaseBufferError(hr) => (26, *hr),
            WinAudioError::GuidParseIntError(_) => (27, 0),
            WinAudioError::GuidSplitWrongSize(_) => (28, 0),
            WinAudioError::GuidVecConversionError => (29, 0),
        };
        ((err_type as u64) << 32 | ((hr as u32) as u64)) as i64
    }
}

impl From<i32> for WinAudioError {
    fn from(winapi_error_code: i32) -> Self {
        match winapi_error_code {
            AUDCLNT_E_DEVICE_INVALIDATED => Self::DeviceInvalidated,
            _ => Self::WindowsError(winapi_error_code, Error::last()),
        }
    }
}

#[derive(Debug, ThisError)]
pub enum RenderError {
    #[error("RenderError: {0}")]
    WinAudioError(WinAudioError),
    #[error("AudioStream RenderBufferError error: {0}")]
    PlaybackBuffer(PlaybackBufferError),
    #[error("buffer pointer is null")]
    InvalidBuffer,
}

#[derive(Debug, ThisError)]
pub enum CaptureError {
    #[error("CaptureError: {0}")]
    WinAudioError(WinAudioError),
    #[error("AudioStream CaptureBufferError error: {0}")]
    CaptureBuffer(CaptureBufferError),
    #[error("CaptureResamplerBuffer has no samples available.")]
    ResamplerNoSamplesAvailable,
    #[error("CaptureResamplerBuffer is missing.")]
    ResamplerMissing,
}

// Unfortunately, Kokoro's VM tests will fail on `GetDefaultAudioEndpoint` most likely because there
// are no audio endpoints on the VMs running the test. These tests can be ran on a windows machine
// with an audio device though.
//
// Thus these test are ignored, but are good for local testing. To run, just use the command:
//
//   $: cargo test -p win_audio win_audio_impl::tests:: -- --ignored
//
// Also, if a STATUS_DLL_NOT_FOUND exception happens, this is because the r8brain.dll can't be
// be found. Just put it in the appropriate spot in the `target` directory.
#[cfg(test)]
mod tests {
    use std::thread;

    use cros_async::Executor;
    use metrics::sys::WaveFormatDetails;
    use winapi::shared::ksmedia::KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;
    use winapi::shared::mmreg::WAVEFORMATEX;
    use winapi::shared::mmreg::WAVEFORMATEXTENSIBLE;
    use winapi::shared::mmreg::WAVE_FORMAT_EXTENSIBLE;
    use winapi::shared::winerror::S_OK;

    use super::*;
    // These tests needs to be ran serially because there is a chance that two different tests
    // running on different threads could open the same event named
    // ACTIVATE_AUDIO_INTERFACE_COMPLETION_EVENT.
    // So the first test thread could trigger it correctly, but the second test thread could open
    // the same triggered event even though the `ActivateAudioInterfaceAsync` operation hasn't
    // completed, thus causing an error.
    //
    // TODO(b/217768491): Randomizing events should resolve the need for serialized tests.
    static SERIALIZE_LOCK: Mutex<()> = Mutex::new(());

    struct SafeCoInit;
    impl SafeCoInit {
        fn new_coinitialize() -> Self {
            // SAFETY: We pass valid parameters to CoInitializeEx.
            unsafe {
                CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED);
            }
            SafeCoInit {}
        }
    }

    impl Drop for SafeCoInit {
        fn drop(&mut self) {
            // SAFETY: We initialized COM, so it is safe to uninitialize it here.
            unsafe {
                CoUninitialize();
            }
        }
    }

    #[test]
    fn test_win_audio_error_to_descriptor_for_no_device() {
        let err = WinAudioError::MissingDeviceError(-2147023728);
        let result: i64 = (&err).into();

        // 2 << 32 | (-2147023728)
        assert_eq!(result, 10737878160);
    }

    #[test]
    fn test_win_audio_error_to_descriptor_for_failed_initialization() {
        let err = WinAudioError::AudioClientInitializationError(-2004287484);
        let result: i64 = (&err).into();

        // 5 << 32 | (-2004287484)
        assert_eq!(result, 23765516292);
    }

    #[test]
    fn test_win_audio_error_to_descriptor_for_getcurrentpadding_error() {
        let err = WinAudioError::GetCurrentPaddingError(-2147023728);
        let result: i64 = (&err).into();

        // 23 << 32 | (-2004287484)
        assert_eq!(result, 100932191376);
    }

    #[test]
    fn test_device_renderer_convert_string_to_guid() {
        let guid_string = "465c4ed4-cda1-4d65-b412-641299a39c2c";
        let result_guid =
            DeviceRenderer::convert_session_string_to_guid(guid_string.to_string()).unwrap();
        assert_eq!(result_guid.Data1, 0x465c4ed4);
        assert_eq!(result_guid.Data2, 0xcda1);
        assert_eq!(result_guid.Data3, 0x4d65);

        let data_4 = result_guid.Data4;
        assert_eq!(data_4[0], 0xb4);
        assert_eq!(data_4[1], 0x12);
        assert_eq!(data_4[2], 0x64);
        assert_eq!(data_4[3], 0x12);
        assert_eq!(data_4[4], 0x99);
        assert_eq!(data_4[5], 0xa3);
        assert_eq!(data_4[6], 0x9c);
        assert_eq!(data_4[7], 0x2c);
    }

    #[ignore]
    #[test]
    fn test_create_win_audio_renderer_no_co_initliazed() {
        let _shared = SERIALIZE_LOCK.lock();
        let win_audio_renderer = DeviceRenderer::new(2, 48000, 720, None, None);
        assert!(win_audio_renderer.is_err());
    }

    #[ignore]
    #[test]
    fn test_create_win_audio_capturer_no_co_initliazed() {
        let _shared = SERIALIZE_LOCK.lock();
        let win_audio_renderer = DeviceCapturer::new(2, 48000, 720, None);
        assert!(win_audio_renderer.is_err());
    }

    #[ignore]
    #[test]
    fn test_create_win_audio_renderer() {
        let _shared = SERIALIZE_LOCK.lock();
        let _co_init = SafeCoInit::new_coinitialize();
        let win_audio_renderer_result = DeviceRenderer::new(2, 48000, 480, None, None);
        assert!(win_audio_renderer_result.is_ok());
        let win_audio_renderer = win_audio_renderer_result.unwrap();
        // This test is dependent on device format settings and machine. Ie. this will probably
        // fail on AMD since its period is normally 513 for 48kHz.
        assert_eq!(
            win_audio_renderer
                .audio_shared_format
                .shared_audio_engine_period_in_frames,
            480
        );
    }

    #[ignore]
    #[test]
    fn test_create_win_audio_capturer() {
        let _shared = SERIALIZE_LOCK.lock();
        let _co_init = SafeCoInit::new_coinitialize();
        let win_audio_capturer_result = DeviceCapturer::new(2, 48000, 480, None);
        assert!(win_audio_capturer_result.is_ok());
        let win_audio_capturer = win_audio_capturer_result.unwrap();
        // This test is dependent on device format settings and machine. Ie. this will probably
        // fail on AMD since its period is normally 513 for 48kHz.
        assert_eq!(
            win_audio_capturer
                .audio_shared_format
                .shared_audio_engine_period_in_frames,
            480
        );
    }

    #[ignore]
    #[test]
    fn test_create_playback_stream() {
        let _shared = SERIALIZE_LOCK.lock();
        let mut win_audio: WinAudio = WinAudio::new().unwrap();
        let (_, mut stream_source) = win_audio
            .new_playback_stream(2, SampleFormat::S16LE, 48000, 480)
            .unwrap();
        let playback_buffer = stream_source.next_playback_buffer().unwrap();

        assert_eq!(playback_buffer.frame_capacity(), 480);
    }

    #[ignore]
    #[test]
    // If the guest buffer is too big, then
    // there is no way to copy audio samples over succiently.
    fn test_guest_buffer_size_bigger_than_audio_render_client_buffer_size() {
        let _shared = SERIALIZE_LOCK.lock();
        let win_audio_renderer = DeviceRenderer::new(2, 48000, 100000, None, None);

        assert!(win_audio_renderer.is_err());
    }

    #[ignore]
    #[test]
    fn test_co_init_called_once_per_thread() {
        let _shared = SERIALIZE_LOCK.lock();
        // Call co init in a background thread
        let join_handle = thread::spawn(move || {
            assert_eq!(WinAudio::co_init_once_per_thread(), S_OK);
        });

        // Wait for thread to finish
        join_handle
            .join()
            .expect("Thread calling co_init_once_per_thread panicked");

        // Call co init twice on the main thread.
        assert_eq!(WinAudio::co_init_once_per_thread(), S_OK);
        // Without thread local once_only this should fail
        assert_eq!(WinAudio::co_init_once_per_thread(), S_SKIPPED_COINIT);
        // SAFETY: We initialized COM, so it is safe to uninitialize it here.
        unsafe {
            CoUninitialize();
        }
    }

    #[ignore]
    #[test]
    fn test_device_renderer_wrapper_noop_stream_proper_set() {
        let _shared = SERIALIZE_LOCK.lock();
        let _co_init = SafeCoInit::new_coinitialize();

        let ex = Executor::new().expect("Failed to create executor.");
        let mut renderer_wrapper =
            DeviceRendererWrapper::new(2, SampleFormat::S16LE, 48000, 480, Some(&ex), None)
                .unwrap();
        assert!(matches!(
            renderer_wrapper.renderer_stream,
            RendererStream::Device(_)
        ));

        renderer_wrapper.renderer_stream =
            DeviceRendererWrapper::create_noop_stream_with_device_notification(2, 48000, 480)
                .unwrap();
        assert!(matches!(
            renderer_wrapper.renderer_stream,
            RendererStream::Noop(_)
        ));
    }

    #[ignore]
    #[test]
    fn test_device_capturer_wrapper_noop_stream_proper_set() {
        let _shared = SERIALIZE_LOCK.lock();
        let _co_init = SafeCoInit::new_coinitialize();

        let ex = Executor::new().expect("Failed to create executor.");
        let mut capturer_wrapper =
            DeviceCapturerWrapper::new(2, SampleFormat::S16LE, 48000, 480, Some(&ex)).unwrap();
        assert!(matches!(
            capturer_wrapper.capturer_stream,
            CapturerStream::Device(_)
        ));

        capturer_wrapper.capturer_stream =
            DeviceCapturerWrapper::create_noop_capture_stream_with_device_notification(
                2,
                SampleFormat::S16LE,
                48000,
                480,
            )
            .unwrap();
        assert!(matches!(
            capturer_wrapper.capturer_stream,
            CapturerStream::Noop(_)
        ));
    }

    // Test may be flakey because other tests will be creating an AudioClient. Putting all tests
    // in one so we can run this individually to prevent the flakiness. This test may fail
    // depending on your selected default audio device.
    #[ignore]
    #[test]
    fn test_check_format_get_mix_format_success() {
        let _shared = SERIALIZE_LOCK.lock();

        let _co_init = SafeCoInit::new_coinitialize();
        let audio_client = create_audio_client(eRender).unwrap();
        let mut format_ptr: *mut WAVEFORMATEX = std::ptr::null_mut();
        // SAFETY: `&mut format_ptr` is valid.
        let _hr = unsafe { audio_client.GetMixFormat(&mut format_ptr) };

        // SAFETY: `format_ptr` is not a null pointer, since it is set by `GetMixFormat`.
        let format = unsafe { WaveAudioFormat::new(format_ptr) };

        // Test format from `GetMixFormat`. This should ALWAYS be valid.
        assert!(check_format(
            &audio_client,
            &format,
            WaveFormatDetails::default(),
            AudioFormatEventType::RequestOk,
        )
        .is_ok());

        let format = WAVEFORMATEXTENSIBLE {
            Format: WAVEFORMATEX {
                wFormatTag: WAVE_FORMAT_EXTENSIBLE,
                nChannels: 2,
                nSamplesPerSec: 48000,
                nAvgBytesPerSec: 8 * 48000,
                nBlockAlign: 8,
                wBitsPerSample: 32,
                cbSize: 22,
            },
            Samples: 32,
            dwChannelMask: 3,
            SubFormat: KSDATAFORMAT_SUBTYPE_IEEE_FLOAT,
        };

        // SAFETY: `GetMixFormat` casts `WAVEFORMATEXTENSIBLE` into a `WAVEFORMATEX` like so.
        // Also this is casting from a bigger to a smaller struct, so it shouldn't be possible for
        // this contructor to access memory it shouldn't.
        let format = unsafe { WaveAudioFormat::new((&format) as *const _ as *mut WAVEFORMATEX) };

        // Test valid custom format.
        assert!(check_format(
            &audio_client,
            &format,
            WaveFormatDetails::default(),
            AudioFormatEventType::RequestOk,
        )
        .is_ok());

        let format = WAVEFORMATEXTENSIBLE {
            Format: WAVEFORMATEX {
                wFormatTag: WAVE_FORMAT_EXTENSIBLE,
                nChannels: 2,
                nSamplesPerSec: 48000,
                nAvgBytesPerSec: 8 * 48000,
                nBlockAlign: 8,
                wBitsPerSample: 3, // This value will cause failure, since bitdepth of 3
                // doesn't make sense
                cbSize: 22,
            },
            Samples: 32,
            dwChannelMask: 3,
            SubFormat: KSDATAFORMAT_SUBTYPE_IEEE_FLOAT,
        };

        // SAFETY: `GetMixFormat` casts `WAVEFORMATEXTENSIBLE` into a `WAVEFORMATEX` like so.
        // Also this is casting from a bigger to a smaller struct, so it shouldn't be possible for
        // this contructor to access memory it shouldn't.
        let format = unsafe { WaveAudioFormat::new((&format) as *const _ as *mut WAVEFORMATEX) };

        // Test invalid format
        assert!(check_format(
            &audio_client,
            &format,
            WaveFormatDetails::default(),
            AudioFormatEventType::RequestOk,
        )
        .is_err());
    }
}
