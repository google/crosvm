// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Write;
use std::slice;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

use audio_streams::capture::CaptureBuffer;
use audio_streams::capture::CaptureBufferStream;
use audio_streams::BoxError;
use audio_streams::NoopStreamControl;
use audio_streams::PlaybackBuffer;
use audio_streams::PlaybackBufferError;
use audio_streams::PlaybackBufferStream;
use audio_streams::SampleFormat;
use base::error;
use base::info;
use base::set_audio_thread_priority;
use base::set_thread_priority;
use base::warn;
use base::Event;
use base::EventToken;
use base::RawDescriptor;
use base::ReadNotifier;
use base::Tube;
use base::WaitContext;
use data_model::VolatileSlice;
use remain::sorted;
use sync::Mutex;
use thiserror::Error;
use vm_control::Ac97Control;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use win_audio::intermediate_resampler_buffer::IntermediateResamplerBuffer;
use win_audio::intermediate_resampler_buffer::STEREO_CHANNEL_COUNT;
use winapi::um::winbase::THREAD_PRIORITY_TIME_CRITICAL;

use crate::pci::ac97::sys::AudioStreamSource;
use crate::pci::ac97_bus_master::buffer_completed;
use crate::pci::ac97_bus_master::current_buffer_size;
use crate::pci::ac97_bus_master::Ac97BusMaster;
use crate::pci::ac97_bus_master::Ac97BusMasterRegs;
use crate::pci::ac97_bus_master::AudioResult;
use crate::pci::ac97_bus_master::AudioThreadInfo;
use crate::pci::ac97_bus_master::GuestMemoryError;
use crate::pci::ac97_bus_master::GuestMemoryResult;
use crate::pci::ac97_mixer::Ac97Mixer;
use crate::pci::ac97_regs::*;

// Internal error type used for reporting errors from the audio thread.
#[sorted]
#[derive(Error, Debug)]
pub(crate) enum AudioError {
    // Failure writing to the audio output.
    #[error("Failed to write audio output: {0}")]
    CaptureCopyFailure(std::io::Error),
    // Failure to copy samples to host buffer
    #[error("Failed to write samples to host buffer: {0}")]
    PlaybackCopyingFailure(PlaybackBufferError),
    // Failure to read guest memory.
    #[error("Failed to read guest memory: {0}")]
    ReadingGuestError(GuestMemoryError),
    // Failure to get an buffer from the stream.
    #[error("Failed to get a buffer from the stream: {0}")]
    StreamError(BoxError),
    // Failure writing to the audio output.
    #[error("Failed to write audio output: {0}")]
    WritingOutput(std::io::Error),
}

// Windows specific members of Ac97BusMaster.
#[derive(Default)]
pub struct Ac97BusMasterSys {
    // If true, drop audio samples from the guest.
    mute: Arc<Mutex<bool>>,
    // Event to fire to stop the event listening thread.
    exit_event: Option<Event>,
    // JoinHandle to event listening thread.
    event_listening_thread: Option<thread::JoinHandle<Result<(), AudioError>>>,
}

impl Ac97BusMaster {
    /// Creates an Ac97BusMaster` object that plays audio from `mem` to streams provided by
    /// `audio_server`.
    pub(crate) fn new(
        mem: GuestMemory,
        audio_server: AudioStreamSource,
        ac97_device_tube: Option<Tube>,
    ) -> Self {
        let res = Ac97BusMaster {
            mem,
            regs: Arc::new(Mutex::new(Ac97BusMasterRegs::new())),
            acc_sema: 0,

            po_info: AudioThreadInfo::new(),
            pi_info: AudioThreadInfo::new(),
            pmic_info: AudioThreadInfo::new(),
            audio_server,

            irq_resample_thread: None,
            sys: Ac97BusMasterSys {
                mute: Arc::new(Mutex::new(false)),
                exit_event: None,
                event_listening_thread: None,
            },
        };

        let mut res = res;
        if let Some(ac97_device_tube) = ac97_device_tube {
            res.sys.exit_event = Some(Event::new().unwrap());
            res.sys.event_listening_thread = Some(Ac97BusMaster::start_event_loop(
                ac97_device_tube,
                res.sys.mute.clone(),
                res.sys.exit_event.as_ref().unwrap().try_clone().unwrap(),
                res.audio_server.clone(),
            ));
        }
        res
    }

    fn start_event_loop(
        ac97_device_tube: Tube,
        mute_mutex: Arc<Mutex<bool>>,
        exit_event: Event,
        audio_server: AudioStreamSource,
    ) -> JoinHandle<Result<(), AudioError>> {
        thread::Builder::new()
            .name("Ac97BusMaster event loop".to_string())
            .spawn(move || {
                #[derive(EventToken)]
                enum Token {
                    Mute,
                    Exit,
                }

                let wait_ctx = WaitContext::build_with(&[
                    (ac97_device_tube.get_read_notifier(), Token::Mute),
                    (&exit_event, Token::Exit),
                ])
                .expect("Wait context failed to build with tokens.");

                'event: loop {
                    let events = wait_ctx.wait().expect("Failed to wait.");
                    for event in events {
                        match event.token {
                            Token::Mute => match ac97_device_tube.recv::<Ac97Control>() {
                                Ok(request) => match request {
                                    Ac97Control::Mute(mute) => {
                                        *(mute_mutex.lock()) = mute;
                                        // Release the playback stream cache whenever mute is
                                        // is set to true, which means the emulator is hidden.
                                        //
                                        // If the playback thread is still alive, the playback
                                        // stream containing the audio device will still be alive.
                                        if !audio_server.lock().is_noop_stream() && mute {
                                            audio_server.lock().evict_playback_stream_cache();
                                        }
                                    }
                                },
                                Err(e) => {
                                    panic!("Error in Ac97BusMaster event listening thread: {}", e);
                                }
                            },
                            Token::Exit => {
                                break 'event;
                            }
                        }
                    }
                }
                Ok(())
            })
            .unwrap()
    }

    // Windows doesn't need a reference to the guest memory raw descriptor because we are
    // already reading from it directly.
    pub fn keep_rds(&self) -> Option<Vec<RawDescriptor>> {
        self.audio_server.lock().keep_rds()
    }

    pub(in crate::pci::ac97_bus_master) fn start_audio(
        &mut self,
        func: Ac97Function,
        mixer: &Ac97Mixer,
    ) -> Result<(), BoxError> {
        let sample_rate = self.current_sample_rate(func, mixer) as usize;
        let thread_info = match func {
            Ac97Function::Microphone => &mut self.pmic_info,
            Ac97Function::Input => &mut self.pi_info,
            Ac97Function::Output => &mut self.po_info,
        };

        // `guest_num_channels` is hard coded to 2 because we are assuming that's the format the
        // guest will always give to the audio device. If the guest sends != 2 channels format, then
        // audio won't work properly.
        let guest_num_channels = STEREO_CHANNEL_COUNT;
        let buffer_samples = current_buffer_size(self.regs.lock().func_regs(func), &self.mem)?;
        let buffer_frames = buffer_samples / guest_num_channels;
        thread_info.thread_run.store(true, Ordering::Relaxed);
        let thread_run = thread_info.thread_run.clone();
        let thread_mem = self.mem.clone();
        let thread_regs = self.regs.clone();
        match func {
            Ac97Function::Input => {
                let (stream_control, input_stream) = self.audio_server.lock().new_capture_stream(
                    guest_num_channels,
                    SampleFormat::S16LE,
                    sample_rate as u32,
                    buffer_frames,
                    &[],
                )?;
                self.pi_info.stream_control = Some(stream_control);
                self.update_mixer_settings(mixer);
                self.pi_info.thread = Some(thread::spawn(move || {
                    // Setting thread priority for now because "start_capture" tests fails
                    // on kokoro (not locally) when using pro audio here. Also capture
                    // isn't used for windows this shouldn't even matter.
                    let thread_priority_result =
                        set_thread_priority(THREAD_PRIORITY_TIME_CRITICAL as i32);
                    if thread_priority_result.is_err() {
                        warn!("Failed to set audio thread to TIME_CRITICAL.");
                    }
                    if let Err(e) =
                        audio_in_thread(thread_regs, thread_mem, &thread_run, input_stream)
                    {
                        error!("Capture error: {}", e);
                    }
                    thread_run.store(false, Ordering::Relaxed);
                }));
            }
            Ac97Function::Output => {
                let (output_stream, audio_shared_format) = self
                    .audio_server
                    .lock()
                    .new_playback_stream_and_get_shared_format(
                        guest_num_channels,
                        SampleFormat::S16LE,
                        sample_rate,
                        buffer_frames,
                    )?;
                self.po_info.stream_control = Some(Box::new(NoopStreamControl::new()));
                self.update_mixer_settings(mixer);
                let mute = Arc::new(AtomicBool::new(*self.sys.mute.lock()));

                self.po_info.thread = Some(
                    thread::Builder::new()
                        .name("Ac97BusMaster playback thread".to_string())
                        .spawn(move || {
                            let thread_priority_result = set_audio_thread_priority();
                            if thread_priority_result.is_err() {
                                warn!("Failed to set audio thread to PRO AUDIO.");
                            }
                            let intermediate_buffer = IntermediateResamplerBuffer::new(
                                /* from */ sample_rate,
                                /* to */ audio_shared_format.frame_rate,
                                buffer_frames,
                                audio_shared_format.shared_audio_engine_period_in_frames,
                                audio_shared_format.channels,
                                audio_shared_format.channel_mask,
                            )
                            .unwrap();
                            if let Err(e) = audio_out_thread(
                                thread_regs,
                                thread_mem,
                                &thread_run,
                                output_stream,
                                intermediate_buffer,
                                mute,
                                guest_num_channels,
                            ) {
                                error!("Playback error: {}", e);
                            }
                            thread_run.store(false, Ordering::Relaxed);
                        })
                        .unwrap(),
                );
            }
            Ac97Function::Microphone => (),
        };
        Ok(())
    }
}

impl Drop for Ac97BusMaster {
    fn drop(&mut self) {
        if let Some(exit_event) = &self.sys.exit_event {
            exit_event
                .signal()
                .expect("Failed to write to exit_event in Ac97BusMaster");
        }

        if let Some(event_listening_thread) = self.sys.event_listening_thread.take() {
            match event_listening_thread.join() {
                Ok(thread_join) => {
                    if let Err(e) = thread_join {
                        error!("Ac97BusMaster listening thread exited with error: {}", e);
                    } else {
                        info!("Ac97BusMaster listening thread exited gracefully.");
                    }
                }
                Err(e) => panic!("Ac97BusMaster listening thread panicked: {:?}", e),
            }
        }
    }
}

// Gets the next buffer from the guest. This will return `None` if the DMA controlled stopped bit is
// set, such as after an underrun where CIV hits LVI.
fn next_guest_buffer<'a>(
    func_regs: &mut Ac97FunctionRegs,
    mem: &'a GuestMemory,
) -> GuestMemoryResult<Option<VolatileSlice<'a>>> {
    // value is in bytes
    let sample_size = 2;

    if func_regs.sr & SR_DCH != 0 {
        return Ok(None);
    }
    let next_buffer = func_regs.civ;
    let descriptor_addr = func_regs.bdbar + u32::from(next_buffer) * DESCRIPTOR_LENGTH as u32;
    let buffer_addr_reg: u32 = mem
        .read_obj_from_addr(GuestAddress(u64::from(descriptor_addr)))
        .map_err(GuestMemoryError::ReadingGuestBufferAddress)?;
    let buffer_addr = buffer_addr_reg & !0x03u32; // The address must be aligned to four bytes.
    let control_reg: u32 = mem
        .read_obj_from_addr(GuestAddress(u64::from(descriptor_addr) + 4))
        .map_err(GuestMemoryError::ReadingGuestBufferAddress)?;
    let buffer_samples: usize = control_reg as usize & 0x0000_ffff;

    func_regs.picb = buffer_samples as u16;

    let samples_remaining = func_regs.picb as usize;
    if samples_remaining == 0 {
        return Ok(None);
    }
    let read_pos = GuestAddress(u64::from(buffer_addr));
    Ok(Some(
        mem.get_slice_at_addr(read_pos, samples_remaining * sample_size)
            .map_err(GuestMemoryError::ReadingGuestBufferAddress)?,
    ))
}

// Reads the next buffer from guest memory and writes it to `out_buffer`.
fn play_buffer(
    regs: &mut Ac97BusMasterRegs,
    mem: &GuestMemory,
    out_buffer: &mut PlaybackBuffer,
    intermediate_resampler_buffer: &mut IntermediateResamplerBuffer,
    mute: &Arc<AtomicBool>,
) -> AudioResult<()> {
    // If the current buffer had any samples in it, mark it as done.
    if regs.func_regs_mut(Ac97Function::Output).picb > 0 {
        buffer_completed(regs, mem, Ac97Function::Output)?
    }
    let func_regs = regs.func_regs_mut(Ac97Function::Output);
    let buffer_len = func_regs.picb * 2;
    // If mute is set to true, we want to drop all the audio samples coming from the guest.
    // We still want to read from the guest to prevent it from thinking there is a buffer
    // overrun and to make sure the guest is not in a weird state.
    if let Some(buffer) =
        next_guest_buffer(func_regs, mem)?.filter(|_| !mute.load(Ordering::Relaxed))
    {
        // Safe because we know that `buffer` is a volatile slice, which can be converted to
        // an array of bytes.
        let buffer_slice = unsafe { slice::from_raw_parts(buffer.as_ptr(), buffer.size()) };
        intermediate_resampler_buffer.convert_and_add(buffer_slice);
        if let Some(next_period) = intermediate_resampler_buffer.get_next_period() {
            out_buffer
                .copy_cb_with_checks(next_period.len(), |out| {
                    if out.len() == next_period.len() {
                        out.copy_from_slice(next_period);
                    } else {
                        error!(
                            "Audio resample buffer length mismatch: can't copy {} to {}. \
                                Muting audio.",
                            next_period.len(),
                            out.len(),
                        );
                        mute.store(true, Ordering::Relaxed);
                        out.fill(0);
                    }
                })
                .map_err(AudioError::PlaybackCopyingFailure)?;
        } else {
            warn!("Getting the next period failed");
            write_zeros(out_buffer, buffer_len as usize)?;
        }
    } else {
        write_zeros(out_buffer, buffer_len as usize)?;
    }
    Ok(())
}

fn write_zeros(out_buffer: &mut PlaybackBuffer, buffer_len: usize) -> AudioResult<()> {
    let zeros = vec![0u8; buffer_len];
    out_buffer
        .write(&zeros)
        .map_err(AudioError::WritingOutput)?;
    Ok(())
}

// Runs, playing back audio from the guest to `output_stream` until stopped or an error occurs.
fn audio_out_thread(
    regs: Arc<Mutex<Ac97BusMasterRegs>>,
    mem: GuestMemory,
    thread_run: &AtomicBool,
    output_stream: Arc<Mutex<Box<dyn PlaybackBufferStream>>>,
    mut intermediate_resampler_buffer: IntermediateResamplerBuffer,
    mute: Arc<AtomicBool>,
    guest_num_channels: usize,
) -> AudioResult<()> {
    while thread_run.load(Ordering::Relaxed) {
        // If the intermediate buffer length + the next guest period isn't enough to fill the
        // next Windows audio engine period, then read from the guest again.
        // The period values are multiplied by 2 in order to convert their units from # of frames to
        // # of samples (since there are 2 channels). This is because
        // `intermediate_resampler_buffer.ring_buf.len()` is in samples.
        if intermediate_resampler_buffer.ring_buf.len()
            + (intermediate_resampler_buffer.guest_period_in_target_sample_rate_frames
                * guest_num_channels)
            <= intermediate_resampler_buffer.shared_audio_engine_period_in_frames
                * guest_num_channels
        {
            // When reading audio frames from shm, it will take some time for the guest to update
            // it's state properly. Therefore, when reading from the shm twice without a sleep or
            // wait, a race condition will happen and most likely the second read will read the
            // same audio frames as the last (This is an educated guess that I'm somewhat certain
            // of). This is why we sleep before and after `fill_intermeditate_buffer`, since this
            // will give time for the state on the guest to update.
            //
            // This is a hack. The better solution is to just have ac97 write to the intermediate
            // buffer and then have another thread, or process (just like CRAS) read from the
            // intermediate buffer. However, this will take a lot more work.
            //
            // The sleep time should be fine, because `output_stream.next_playback_buffer()` will
            // block until Windows is ready to read in more samples, which should take ~10ms. If
            // for some reason the period is <10ms, there may be problems.
            std::thread::sleep(std::time::Duration::from_millis(4));
            fill_intermediate_buffer(&mut regs.lock(), &mem, &mut intermediate_resampler_buffer)?;
            std::thread::sleep(std::time::Duration::from_millis(4));
        }
        output_stream
            .lock()
            .next_playback_buffer()
            .map_err(AudioError::StreamError)
            .and_then(|mut pb_buf| {
                let res = play_buffer(
                    &mut regs.lock(),
                    &mem,
                    &mut pb_buf,
                    &mut intermediate_resampler_buffer,
                    &mute,
                );
                pb_buf.commit();
                res
            })?;
    }
    Ok(())
}

fn fill_intermediate_buffer(
    regs: &mut Ac97BusMasterRegs,
    mem: &GuestMemory,
    intermediate_resampler_buffer: &mut IntermediateResamplerBuffer,
) -> AudioResult<()> {
    if regs.func_regs_mut(Ac97Function::Output).picb > 0 {
        buffer_completed(regs, mem, Ac97Function::Output)?
    }
    let func_regs = regs.func_regs_mut(Ac97Function::Output);
    if let Some(buffer) = next_guest_buffer(func_regs, mem).unwrap() {
        let buffer_slice = unsafe { slice::from_raw_parts(buffer.as_ptr(), buffer.size()) };
        intermediate_resampler_buffer.convert_and_add(buffer_slice);
    }

    Ok(())
}

// Reads samples from `in_buffer` and writes it to the next buffer from guest memory.
fn capture_buffer(
    regs: &mut Ac97BusMasterRegs,
    mem: &GuestMemory,
    in_buffer: &mut CaptureBuffer,
) -> AudioResult<()> {
    // If the current buffer had any samples in it, mark it as done.
    if regs.func_regs_mut(Ac97Function::Input).picb > 0 {
        buffer_completed(regs, mem, Ac97Function::Input)?
    }
    let func_regs = regs.func_regs_mut(Ac97Function::Input);
    if let Some(buffer) = next_guest_buffer(func_regs, mem)? {
        in_buffer
            .copy_cb(buffer.size(), |inb| buffer.copy_from(inb))
            .map_err(AudioError::CaptureCopyFailure)?;
    }
    Ok(())
}

// Runs, capturing audio from `input_stream` to the guest until stopped or an error occurs.
fn audio_in_thread(
    regs: Arc<Mutex<Ac97BusMasterRegs>>,
    mem: GuestMemory,
    thread_run: &AtomicBool,
    mut input_stream: Box<dyn CaptureBufferStream>,
) -> AudioResult<()> {
    while thread_run.load(Ordering::Relaxed) {
        input_stream
            .next_capture_buffer()
            .map_err(AudioError::StreamError)
            .and_then(|mut cp_buf| capture_buffer(&mut regs.lock(), &mem, &mut cp_buf))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time;

    use audio_streams::NoopStreamSource;

    use super::*;
    use crate::pci::ac97_bus_master::tests::capture_release_cold_reset_and_setup_ping_pong_buffers;
    use crate::pci::ac97_bus_master::tests::check_buffer_set_and_clear_bcis;
    use crate::pci::ac97_bus_master::tests::clear_lvb_and_reset_lvi;
    use crate::pci::ac97_bus_master::tests::playback_release_cold_reset_and_setup_ping_pong_buffers;
    use crate::pci::ac97_bus_master::tests::stop;

    #[test]
    #[ignore] // flaky - see crbug.com/1058881
    fn start_playback() {
        const LVI_MASK: u8 = 0x1f; // Five bits for 32 total entries.
        const IOC_MASK: u32 = 0x8000_0000; // Interrupt on completion.
        let num_buffers = LVI_MASK as usize + 1;
        const BUFFER_SIZE: usize = 32768;
        const FRAGMENT_SIZE: usize = BUFFER_SIZE / 2;

        const GUEST_ADDR_BASE: u32 = 0x100_0000;
        let mem = GuestMemory::new(&[(GuestAddress(GUEST_ADDR_BASE as u64), 1024 * 1024 * 1024)])
            .expect("Creating guest memory failed.");
        let mut bm = Ac97BusMaster::new(
            mem.clone(),
            Arc::new(Mutex::new(NoopStreamSource::new())),
            None,
        );
        let mut mixer = Ac97Mixer::new();

        playback_release_cold_reset_and_setup_ping_pong_buffers(
            PO_BASE_10,
            &mut mixer,
            &mut bm,
            &mem,
            num_buffers,
            GUEST_ADDR_BASE,
            FRAGMENT_SIZE,
            LVI_MASK,
            IOC_MASK,
        );

        // Start.
        bm.writeb(PO_CR_1B, CR_IOCE | CR_RPBM, &mixer);

        std::thread::sleep(time::Duration::from_millis(50));
        let picb = bm.readw(PO_PICB_18, &mixer);
        let mut civ = bm.readb(PO_CIV_14);
        assert_eq!(civ, 0);
        let pos = (FRAGMENT_SIZE - (picb as usize * 2)) / 4;

        // Check that frames are consumed at least at a reasonable rate.
        // This wont be exact as during unit tests the thread scheduling is highly variable, so the
        // test only checks that some samples are consumed.
        assert!(pos > 1000);

        assert!(bm.readw(PO_SR_16, &mixer) & SR_DCH == 0); // DMA is running.

        // civ should move eventually.
        for _i in 0..30 {
            if civ != 0 {
                break;
            }
            std::thread::sleep(time::Duration::from_millis(20));
            civ = bm.readb(PO_CIV_14);
        }

        assert_ne!(0, civ);

        check_buffer_set_and_clear_bcis(PO_BASE_10, &mixer, &mut bm);

        // Set last valid to the next and wait until it is hit.
        bm.writeb(PO_LVI_15, civ + 1, &mixer);
        std::thread::sleep(time::Duration::from_millis(500));
        assert!(bm.readw(PO_SR_16, &mixer) & SR_LVBCI != 0); // Hit last buffer
        assert!(bm.readw(PO_SR_16, &mixer) & SR_DCH == SR_DCH); // DMA stopped because of lack of buffers.
        assert_eq!(bm.readw(PO_SR_16, &mixer) & SR_CELV, SR_CELV);
        assert_eq!(bm.readb(PO_LVI_15), bm.readb(PO_CIV_14));
        assert!(
            bm.readl(GLOB_STA_30) & GS_POINT != 0,
            "POINT bit should be set."
        );

        clear_lvb_and_reset_lvi(PO_BASE_10, &mixer, &mut bm, LVI_MASK);

        let (restart_civ, restart_picb) = (bm.readb(PO_CIV_14), bm.readw(PO_PICB_18, &mixer));
        std::thread::sleep(time::Duration::from_millis(20));
        assert!(bm.readw(PO_PICB_18, &mixer) != restart_picb || bm.readb(PO_CIV_14) != restart_civ);

        stop(PO_BASE_10, GS_POINT, &mixer, &mut bm);
    }

    #[test]
    #[ignore] // Test is flaky b/216306206
    fn start_capture() {
        const LVI_MASK: u8 = 0x1f; // Five bits for 32 total entries.
        const IOC_MASK: u32 = 0x8000_0000; // Interrupt on completion.
        let num_buffers = LVI_MASK as usize + 1;
        const BUFFER_SIZE: usize = 32768;
        const FRAGMENT_SIZE: usize = BUFFER_SIZE / 2;

        const GUEST_ADDR_BASE: u32 = 0x100_0000;
        let mem = GuestMemory::new(&[(GuestAddress(GUEST_ADDR_BASE as u64), 1024 * 1024 * 1024)])
            .expect("Creating guest memory failed.");
        let mut bm = Ac97BusMaster::new(
            mem.clone(),
            Arc::new(Mutex::new(NoopStreamSource::new())),
            None,
        );
        let mut mixer = Ac97Mixer::new();

        capture_release_cold_reset_and_setup_ping_pong_buffers(
            PI_BDBAR_00,
            &mut mixer,
            &mut bm,
            &mem,
            num_buffers,
            GUEST_ADDR_BASE,
            FRAGMENT_SIZE,
            LVI_MASK,
            IOC_MASK,
        );

        // Start.
        bm.writeb(PI_CR_0B, CR_IOCE | CR_RPBM, &mixer);
        assert_eq!(bm.readw(PI_PICB_08, &mixer), 0);

        std::thread::sleep(time::Duration::from_millis(50));
        let picb = bm.readw(PI_PICB_08, &mixer);
        assert!(picb > 1000);
        assert!(bm.readw(PI_SR_06, &mixer) & SR_DCH == 0); // DMA is running.

        // civ should move eventually.
        for _i in 0..10 {
            let civ = bm.readb(PI_CIV_04);
            if civ != 0 {
                break;
            }
            std::thread::sleep(time::Duration::from_millis(20));
        }
        assert_ne!(bm.readb(PI_CIV_04), 0);

        let civ = bm.readb(PI_CIV_04);
        // Sets LVI to CIV + 1 to trigger last buffer hit
        bm.writeb(PI_LVI_05, civ + 1, &mixer);
        std::thread::sleep(time::Duration::from_millis(5000));
        assert_ne!(bm.readw(PI_SR_06, &mixer) & SR_LVBCI, 0); // Hit last buffer
                                                              // DMA stopped because of lack of buffers.
        assert_eq!(bm.readw(PI_SR_06, &mixer) & SR_DCH, SR_DCH);
        assert_eq!(bm.readw(PI_SR_06, &mixer) & SR_CELV, SR_CELV);
        assert_eq!(bm.readb(PI_LVI_05), bm.readb(PI_CIV_04));
        assert!(
            bm.readl(GLOB_STA_30) & GS_PIINT != 0,
            "PIINT bit should be set."
        );

        clear_lvb_and_reset_lvi(PI_BASE_00, &mixer, &mut bm, LVI_MASK);

        let restart_civ = bm.readb(PI_CIV_04);
        std::thread::sleep(time::Duration::from_millis(200));
        assert_ne!(bm.readb(PI_CIV_04), restart_civ);

        stop(PO_BASE_10, GS_PIINT, &mixer, &mut bm);
    }
}
