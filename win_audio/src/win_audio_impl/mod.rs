// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod async_stream;
mod completion_handler;
mod wave_format;

use std::convert::From;
use std::fmt::Debug;
use std::os::raw::c_void;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::Once;
use std::thread_local;
use std::time::Duration;

use audio_streams::async_api::EventAsyncWrapper;
use audio_streams::AsyncPlaybackBufferStream;
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

use crate::AudioSharedFormat;

const READY_TO_READ_TIMEOUT_MS: u32 = 2000;
pub const STEREO_CHANNEL_COUNT: u16 = 2;
pub const MONO_CHANNEL_COUNT: u16 = 1;

// from msdn: https://docs.microsoft.com/en-us/windows/win32/coreaudio/audclnt-streamflags-xxx-constants
// these don't currently exist in winapi
const AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM: u32 = 0x80000000;
const AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY: u32 = 0x08000000;

thread_local!(static THREAD_ONCE_INIT: Once = Once::new());

// Used to differentiate between S_FALSE and S_OK. This means `CoInitializeEx` did not get called. Mainly used for testing.
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
                // Safe because all variables passed into `CoInitializeEx` are hardcoded
                unsafe {
                    // Initializes the COM library for use by the calling thread. Needed so that `CoCreateInstance`
                    // can be called to create a device enumerator object.
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
        _format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize, //number of frames;
    ) -> Result<(Box<dyn StreamControl>, Box<dyn PlaybackBufferStream>), BoxError> {
        let hr = WinAudio::co_init_once_per_thread();
        let _ = check_hresult!(hr, RenderError::from(hr), "Co Initialized failed");

        let playback_buffer_stream: Box<dyn PlaybackBufferStream> =
            match WinAudioRenderer::new(num_channels, frame_rate, buffer_size) {
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
        ex: &dyn audio_streams::AudioStreamsExecutor,
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
    pub device: DeviceRenderer,
    num_channels: usize,
    frame_rate: u32,
    incoming_buffer_size_in_frames: usize,
}

impl WinAudioRenderer {
    const MAX_REATTACH_TRIES: usize = 50;

    // Initializes WASAPI objects needed for audio.
    pub fn new(
        num_channels: usize,
        frame_rate: u32,
        incoming_buffer_size_in_frames: usize,
    ) -> Result<Self, RenderError> {
        let device = Self::create_device_renderer_and_log_time(
            num_channels,
            frame_rate,
            incoming_buffer_size_in_frames,
            None,
        )?;

        Ok(Self {
            device,
            num_channels,
            frame_rate,                     // guest frame rate
            incoming_buffer_size_in_frames, // from the guest`
        })
    }

    fn create_device_renderer_and_log_time(
        num_channels: usize,
        frame_rate: u32,
        incoming_buffer_size_in_frames: usize,
        ex: Option<&dyn audio_streams::AudioStreamsExecutor>,
    ) -> Result<DeviceRenderer, RenderError> {
        let start = std::time::Instant::now();
        let device =
            DeviceRenderer::new(num_channels, frame_rate, incoming_buffer_size_in_frames, ex)?;
        // This can give us insights to how other long other machines take to initialize audio.
        // Eventually this should be a histogram metric.
        info!(
            "DeviceRenderer took {}ms to initialize audio.",
            start.elapsed().as_millis()
        );
        Ok(device)
    }

    // Drops the existing DeviceRenderer and initializes a new DeviceRenderer for the default
    // device.
    fn reattach_device(&mut self) -> Result<(), RenderError> {
        self.device = DeviceRenderer::new(
            self.num_channels,
            self.frame_rate,
            self.incoming_buffer_size_in_frames,
            None,
        )?;
        Ok(())
    }
}

impl PlaybackBufferStream for WinAudioRenderer {
    /// Returns a wrapper around the WASAPI buffer.
    fn next_playback_buffer<'b, 's: 'b>(&'s mut self) -> Result<PlaybackBuffer<'b>, BoxError> {
        for _ in 0..Self::MAX_REATTACH_TRIES {
            match self.device.next_win_buffer() {
                Ok(_) => return self.device.playback_buffer().map_err(|e| Box::new(e) as _),
                // If the audio device was disconnected, set up whatever is now the default device
                // and loop to try again.
                Err(RenderError::DeviceInvalidated) => {
                    warn!("Audio device disconnected, switching to new default device");
                    self.reattach_device()?;
                }
                Err(e) => return Err(Box::new(e)),
            }
        }
        error!("Unable to attach to a working audio device, giving up");
        Err(Box::new(RenderError::DeviceInvalidated))
    }
}

// Implementation of buffer generator object. Used to get a buffer from WASAPI for crosvm to copy audio
// bytes from the guest memory into.
pub(crate) struct DeviceRenderer {
    audio_render_client: ComPtr<IAudioRenderClient>,
    audio_client: ComPtr<IAudioClient>,
    win_buffer: *mut u8,
    pub audio_shared_format: AudioSharedFormat,
    audio_render_client_buffer_frame_count: u32,
    ready_to_read_event: Event,
    async_ready_to_read_event: Option<Box<dyn EventAsyncWrapper>>,
}

impl DeviceRenderer {
    // Initializes WASAPI objects needed for audio
    fn new(
        num_channels: usize,
        _guest_frame_rate: u32,
        incoming_buffer_size_in_frames: usize,
        ex: Option<&dyn audio_streams::AudioStreamsExecutor>,
    ) -> Result<Self, RenderError> {
        if num_channels > 2 {
            return Err(RenderError::InvalidChannelCount(num_channels));
        }

        let audio_client = create_audio_client(eRender)?;

        let format = get_valid_mix_format(&audio_client)?;

        // Safe because `audio_client` is initialized
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
            RenderError::from(hr),
            "Audio Client Initialize() failed."
        )?;

        let (ready_to_read_event, async_ready_to_read_event) =
            create_and_set_audio_client_event(&audio_client, &ex)?;

        let audio_render_client = DeviceRenderer::create_audio_render_client(&audio_client)?;

        let shared_audio_engine_period_in_frames =
            get_device_period_in_frames(&audio_client, &format);

        let audio_render_client_buffer_frame_count =
            check_endpoint_buffer_size(&audio_client, shared_audio_engine_period_in_frames)?;
        if incoming_buffer_size_in_frames % shared_audio_engine_period_in_frames != 0 {
            warn!(
                "Guest period size: `{}` not divisible by shared audio engine period size: `{}`. \
                 Audio glitches may occur if sample rate conversion isn't on.",
                incoming_buffer_size_in_frames, shared_audio_engine_period_in_frames
            );
        }

        // Safe because `audio_client` is initialized
        let hr = unsafe {
            // Starts the audio stream for playback
            audio_client.Start()
        };
        check_hresult!(
            hr,
            RenderError::from(hr),
            "Audio Render Client Start() failed."
        )?;

        Ok(Self {
            audio_render_client,
            audio_client,
            win_buffer: std::ptr::null_mut(),
            audio_shared_format: format
                .create_audio_shared_format(shared_audio_engine_period_in_frames),
            audio_render_client_buffer_frame_count,
            ready_to_read_event,
            async_ready_to_read_event,
        })
    }

    fn create_audio_render_client(
        audio_client: &IAudioClient,
    ) -> Result<ComPtr<IAudioRenderClient>, RenderError> {
        let mut audio_render_client: *mut c_void = null_mut();

        // Safe because `audio_client` is initialized
        let hr = unsafe {
            audio_client.GetService(
                &IID_IAudioRenderClient as *const GUID,
                &mut audio_render_client,
            )
        };
        check_hresult!(
            hr,
            RenderError::from(hr),
            "Audio Client GetService() failed."
        )?;

        // Safe because `audio_render_client` is guaranteed to be initialized
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
            // Safe because `ready_to_read_event` is guarenteed to be properly initialized
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
        // Safe because `num_frames_padding` is an u32 and `GetCurrentPadding` is a simple
        // Windows function that shouldn't fail.
        let mut num_frames_padding = 0u32;
        let hr = unsafe { self.audio_client.GetCurrentPadding(&mut num_frames_padding) };
        check_hresult!(
            hr,
            RenderError::from(hr),
            "Audio Client GetCurrentPadding() failed."
        )?;

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
                RenderError::from(hr),
                "Audio Render Client GetBuffer failed."
            )?;
        }

        Ok(())
    }

    fn playback_buffer(&mut self) -> Result<PlaybackBuffer, RenderError> {
        // Safe because `win_buffer` is allocated and retrieved from WASAPI. The size requested,
        // which we specified in `next_win_buffer` is exactly
        // `shared_audio_engine_period_in_frames`, so the size parameter should be valid.
        let (frame_size_bytes, buffer_slice) = unsafe {
            Self::get_frame_size_and_buffer_slice(
                self.audio_shared_format.bit_depth as usize,
                self.audio_shared_format.channels as usize,
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
}

impl BufferCommit for DeviceRenderer {
    // Called after buffer from WASAPI is filled. This will allow the audio bytes to be played as sound.
    fn commit(&mut self, nframes: usize) {
        // Safe because `audio_render_client` is initialized and parameters passed
        // into `ReleaseBuffer()` are valid
        unsafe {
            let hr = self.audio_render_client.ReleaseBuffer(nframes as u32, 0);
            let _ = check_hresult!(
                hr,
                RenderError::from(hr),
                "Audio Render Client ReleaseBuffer() failed"
            );
        }
    }
}

impl Drop for DeviceRenderer {
    fn drop(&mut self) {
        unsafe {
            let hr = self.audio_client.Stop();
            let _ = check_hresult!(
                hr,
                RenderError::from(hr),
                "Audio Render Client Stop() failed."
            );
            // audio_client and audio_render_client will be released by ComPtr when dropped. Most
            // likely safe to Release() if audio_client fails to stop. The MSDN doc does not mention
            // that it will crash and this should be done anyways to prevent memory leaks
        }
    }
}

unsafe impl Send for DeviceRenderer {}

// Create the `IAudioClient` which is used to create `IAudioRenderClient`, which is used for
// audio playback, or used to create `IAudioCaptureClient`, which is used for audio capture.
fn create_audio_client(dataflow: EDataFlow) -> Result<ComPtr<IAudioClient>, RenderError> {
    let mut device_enumerator: *mut c_void = null_mut();

    // Creates a device enumerator in order to select our default audio device.
    //
    // Safe because only `device_enumerator` is being modified and we own it.
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
        RenderError::from(hr),
        "Win audio create client CoCreateInstance() failed."
    )?;

    // Safe because `device_enumerator` is guaranteed to be initialized
    let device_enumerator =
        unsafe { ComPtr::from_raw(device_enumerator as *mut IMMDeviceEnumerator) };

    let mut device: *mut IMMDevice = null_mut();
    // Safe because `device_enumerator` is guaranteed to be initialized otherwise this method would've
    // exited
    let hr = unsafe { device_enumerator.GetDefaultAudioEndpoint(dataflow, eConsole, &mut device) };
    check_hresult!(
        hr,
        RenderError::from(hr),
        "Device Enumerator GetDefaultAudioEndpoint() failed."
    )?;

    // Safe because `device` is guaranteed to be initialized
    let device = unsafe { ComPtr::from_raw(device) };
    print_device_info(&device)?;

    let is_render = if dataflow == eRender { true } else { false };

    // Call Windows API functions to get the `async_op` which will be used to retrieve the
    // AudioClient. More details above function definition.
    let async_op = enable_auto_stream_routing_and_wait(is_render)?;

    let mut factory: *mut IUnknown = null_mut();

    // Safe because `async_op` should be initialized at this point.
    let activate_result_hr = unsafe {
        let mut activate_result_hr = 0;
        let hr = (*async_op).GetActivateResult(&mut activate_result_hr, &mut factory);

        check_hresult!(
            hr,
            RenderError::from(hr),
            "GetActivateResult failed. Cannot retrieve factory to create the Audio Client."
        )?;

        activate_result_hr
    };
    check_hresult!(
        activate_result_hr,
        RenderError::from(activate_result_hr),
        "activateResult is an error. Cannot retrieve factory to create the Audio Client."
    )?;

    // Safe because `factory` is guaranteed to be initialized.
    let factory = unsafe { ComPtr::from_raw(factory) };

    factory.cast().map_err(RenderError::from)
}

// Enables automatic audio device routing (only will work for Windows 10, version 1607+).
// This will return IActivateAudioInterfaceAsyncOperation that can be used to retrive the
// AudioClient.
//
// This function will pretty much works as follows:
// 1. Create the parameters to pass into `ActivateAudioInterfaceAsync`
// 2. Call `ActivateAudioInterfaceAsync` which will run asynchrnously and will call
//    a callback when completed.
// 3. Wait on an event that will be notified when that callback is triggered.
// 4. Return an IActivateAudioInterfaceAsyncOperation which can be used to retrived the
//    AudioClient.
fn enable_auto_stream_routing_and_wait(
    is_render: bool,
) -> Result<ComPtr<IActivateAudioInterfaceAsyncOperation>, RenderError> {
    // Event that fires when callback is called.
    let activate_audio_interface_complete_event =
        Event::new_auto_reset().map_err(RenderError::CreateActivateAudioEventError)?;

    let cloned_activate_event = activate_audio_interface_complete_event
        .try_clone()
        .map_err(RenderError::CloneEvent)?;

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
    // Safe because we own `audio_direction_guid_string`.
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
        RenderError::from(hr),
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
    // Safe because we own async_op and the completion handler.
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
    // Safe because `audio_direction_guid_string` should have valid memory
    // and we are freeing up memory here.
    unsafe {
        CoTaskMemFree(audio_direction_guid_string as *mut std::ffi::c_void);
    }

    check_hresult!(
        hr,
        RenderError::from(hr),
        "`Activate AudioInterfaceAsync failed."
    )?;

    // Wait for `ActivateAudioInterfaceAsync` to finish. `ActivateAudioInterfaceAsync` should
    // never hang, but added a long timeout just incase.
    match activate_audio_interface_complete_event.wait_timeout(ACTIVATE_AUDIO_EVENT_TIMEOUT) {
        Ok(event_result) => match event_result {
            EventWaitResult::Signaled => {}
            EventWaitResult::TimedOut => {
                return Err(RenderError::ActivateAudioEventTimeoutError);
            }
        },
        Err(e) => {
            return Err(RenderError::ActivateAudioEventError(e));
        }
    }

    // Safe because we own `async_op` and it shouldn't be null if the activate audio event
    // fired.
    unsafe { Ok(ComPtr::from_raw(async_op)) }
}

// Prints the friendly name for audio `device` to the log.
// Safe when `device` is guaranteed to be successfully initialized.
fn print_device_info(device: &IMMDevice) -> Result<(), RenderError> {
    let mut props: *mut IPropertyStore = null_mut();
    // Safe because `device` is guaranteed to be initialized
    let hr = unsafe { device.OpenPropertyStore(STGM_READ, &mut props) };
    check_hresult!(
        hr,
        RenderError::from(hr),
        "Win audio OpenPropertyStore failed."
    )?;

    // Safe because `props` is guaranteed to be initialized
    let props = unsafe { ComPtr::from_raw(props) };

    let mut val: PROPVARIANT = Default::default();
    // Safe because `props` is guaranteed to be initialized
    let hr = unsafe { props.GetValue(&PKEY_Device_FriendlyName, &mut val) };
    check_hresult!(
        hr,
        RenderError::from(hr),
        "Win audio property store GetValue failed."
    )?;

    // Safe because `val` was populated by a successful GetValue call that returns a pwszVal
    if unsafe { val.data.pwszVal().is_null() } {
        warn!("Win audio property store GetValue returned a null string");
        return Err(RenderError::GenericError);
    }
    // Safe because `val` was populated by a successful GetValue call that returned a non-null
    // null-terminated pwszVal
    let device_name = unsafe { win_util::from_ptr_win32_wide_string(*val.data.pwszVal()) };
    info!("Creating audio client: {}", device_name);
    // Safe because `val` was populated by a successful GetValue call
    unsafe {
        // TODO(b/256244007): `PropVariantClear` doesn't get called if this function errors or
        // returns early.
        PropVariantClear(&mut val);
    }

    Ok(())
}

fn create_and_set_audio_client_event(
    audio_client: &IAudioClient,
    ex: &Option<&dyn audio_streams::AudioStreamsExecutor>,
) -> Result<(Event, Option<Box<dyn EventAsyncWrapper>>), RenderError> {
    let ready_event = Event::new_auto_reset().unwrap();
    // Safe because `ready_event` will be initialized and also it will have the same
    // lifetime as `audio_client` because they are owned by DeviceRenderer or DeviceCapturer on
    // return.
    let hr = unsafe { audio_client.SetEventHandle(ready_event.as_raw_descriptor()) };
    check_hresult!(hr, RenderError::from(hr), "SetEventHandle() failed.")?;

    let async_ready_event = if let Some(ex) = ex {
        // Unsafe if `ready_event` and `async_ready_event` have different
        // lifetimes because both can close the underlying `RawDescriptor`. However, both
        // will be stored in the `DeviceRenderer` or `DeviceCapturer` fields, so this should be
        // safe.
        Some(unsafe {
            ex.async_event(ready_event.as_raw_descriptor())
                .map_err(|e| {
                    RenderError::AsyncError(e, "Failed to create async event".to_string())
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
    // Safe because `GetDevicePeriod` are taking in intialized valid i64's on the stack created above.
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
) -> Result<u32, RenderError> {
    let mut audio_client_buffer_frame_count: u32 = 0;
    // Safe because audio_client_buffer_frame_count is created above.
    let hr = unsafe { audio_client.GetBufferSize(&mut audio_client_buffer_frame_count) };
    check_hresult!(
        hr,
        RenderError::from(hr),
        "Audio Client GetBufferSize() failed."
    )?;

    if audio_client_buffer_frame_count < shared_audio_engine_period_in_frames as u32 {
        warn!(
            "The Windows audio engine period size in frames: {} /
            is bigger than the Audio Client's buffer size in frames: {}",
            shared_audio_engine_period_in_frames, audio_client_buffer_frame_count
        );
        return Err(RenderError::InvalidIncomingBufferSize);
    }
    Ok(audio_client_buffer_frame_count)
}

// TODO(b/253509368): Rename error so it is more generic for rendering and capturing.
#[derive(Debug, ThisError)]
pub enum RenderError {
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
}

impl From<i32> for RenderError {
    fn from(winapi_error_code: i32) -> Self {
        match winapi_error_code {
            AUDCLNT_E_DEVICE_INVALIDATED => Self::DeviceInvalidated,
            _ => Self::WindowsError(winapi_error_code, Error::last()),
        }
    }
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

    use metrics::MetricEventType;
    use once_cell::sync::Lazy;
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
    static SERIALIZE_LOCK: Lazy<Mutex<()>> = Lazy::new(Mutex::default);

    struct SafeCoInit;
    impl SafeCoInit {
        fn new_coinitialize() -> Self {
            unsafe {
                CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED);
            }
            SafeCoInit {}
        }
    }

    impl Drop for SafeCoInit {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }

    #[ignore]
    #[test]
    fn test_create_win_audio_renderer_no_co_initliazed() {
        let _shared = SERIALIZE_LOCK.lock();
        let win_audio_renderer = DeviceRenderer::new(2, 48000, 720, None);
        assert!(win_audio_renderer.is_err());
    }

    #[ignore]
    #[test]
    fn test_create_win_audio_renderer() {
        let _shared = SERIALIZE_LOCK.lock();
        let _co_init = SafeCoInit::new_coinitialize();
        let win_audio_renderer_result = DeviceRenderer::new(2, 48000, 480, None);
        assert!(win_audio_renderer_result.is_ok());
        let win_audio_renderer = win_audio_renderer_result.unwrap();
        assert_eq!(
            win_audio_renderer
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
        let win_audio_renderer = DeviceRenderer::new(2, 48000, 100000, None);

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
        unsafe {
            CoUninitialize();
        }
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
        let _hr = unsafe { audio_client.GetMixFormat(&mut format_ptr) };

        // Safe because `format_ptr` is not a null pointer, since it is set by `GetMixFormat`.
        let format = unsafe { WaveAudioFormat::new(format_ptr) };

        // Test format from `GetMixFormat`. This should ALWAYS be valid.
        assert!(check_format(
            &*audio_client,
            &format,
            WaveFormatDetailsProto::new(),
            MetricEventType::AudioFormatRequestOk,
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

        // Safe because `GetMixFormat` casts `WAVEFORMATEXTENSIBLE` into a `WAVEFORMATEX` like so.
        // Also this is casting from a bigger to a smaller struct, so it shouldn't be possible for
        // this contructor to access memory it shouldn't.
        let format = unsafe { WaveAudioFormat::new((&format) as *const _ as *mut WAVEFORMATEX) };

        // Test valid custom format.
        assert!(check_format(
            &*audio_client,
            &format,
            WaveFormatDetailsProto::new(),
            MetricEventType::AudioFormatRequestOk,
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

        // Safe because `GetMixFormat` casts `WAVEFORMATEXTENSIBLE` into a `WAVEFORMATEX` like so.
        // Also this is casting from a bigger to a smaller struct, so it shouldn't be possible for
        // this contructor to access memory it shouldn't.
        let format = unsafe { WaveAudioFormat::new((&format) as *const _ as *mut WAVEFORMATEX) };

        // Test invalid format
        assert!(check_format(
            &*audio_client,
            &format,
            WaveFormatDetailsProto::new(),
            MetricEventType::AudioFormatRequestOk,
        )
        .is_err());
    }
}
