// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use audio_streams::shm_streams::ShmStream;
use audio_streams::BoxError;
use audio_streams::NoopStreamControl;
use audio_streams::SampleFormat;
use audio_streams::StreamDirection;
use audio_streams::StreamEffect;
use base::error;
use base::set_rt_prio_limit;
use base::set_rt_round_robin;
use base::warn;
use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::FromRawDescriptor;
use base::RawDescriptor;
use remain::sorted;
use sync::Condvar;
use sync::Mutex;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::pci::ac97::sys::AudioStreamSource;
use crate::pci::ac97_bus_master::buffer_completed;
use crate::pci::ac97_bus_master::current_buffer_size;
use crate::pci::ac97_bus_master::get_buffer_samples;
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
    // Failed to clone a descriptor.
    #[error("Failed to clone a descriptor: {0}")]
    CloneDescriptor(base::Error),
    // Failed to create a shared memory.
    #[error("Failed to create a shared memory: {0}.")]
    CreateSharedMemory(base::Error),
    // Failed to create a new stream.
    #[error("Failed to create audio stream: {0}.")]
    CreateStream(BoxError),
    // Failure to get regions from guest memory.
    #[error("Failed to get guest memory region: {0}.")]
    GuestRegion(GuestMemoryError),
    // Invalid buffer offset received from the audio server.
    #[error("Offset > max usize")]
    InvalidBufferOffset,
    // Guest did not provide a buffer when needed.
    #[error("No buffer was available from the Guest")]
    NoBufferAvailable,
    // Failure to read guest memory.
    #[error("Failed to read guest memory: {0}.")]
    ReadingGuestError(GuestMemoryError),
    // Failure to respond to the ServerRequest.
    #[error("Failed to respond to the ServerRequest: {0}")]
    RespondRequest(BoxError),
    // Failure to wait for a request from the stream.
    #[error("Failed to wait for a message from the stream: {0}")]
    WaitForAction(BoxError),
}

// Unix specific members of Ac97BusMaster - a placeholder.
#[derive(Default)]
pub struct Ac97BusMasterSys {}

impl AudioThreadInfo {
    fn start(&mut self, mut worker: AudioWorker) {
        const AUDIO_THREAD_RTPRIO: u16 = 10; // Matches other cros audio clients.
        self.thread_run.store(true, Ordering::Relaxed);
        self.thread = Some(thread::spawn(move || {
            if let Err(e) = set_rt_prio_limit(u64::from(AUDIO_THREAD_RTPRIO))
                .and_then(|_| set_rt_round_robin(i32::from(AUDIO_THREAD_RTPRIO)))
            {
                warn!("Failed to set audio thread to real time: {}", e);
            }

            if let Err(e) = worker.run() {
                error!("{:?} error: {}", worker.func, e);
            }

            worker.thread_run.store(false, Ordering::Relaxed);
        }));

        self.stream_control = Some(Box::new(NoopStreamControl::new()));
    }
}

impl Ac97BusMaster {
    /// Creates an Ac97BusMaster` object that plays audio from `mem` to streams provided by
    /// `audio_server`.
    pub(crate) fn new(mem: GuestMemory, audio_server: AudioStreamSource) -> Self {
        Ac97BusMaster {
            mem,
            regs: Arc::new(Mutex::new(Ac97BusMasterRegs::new())),
            acc_sema: 0,

            po_info: AudioThreadInfo::new(),
            pi_info: AudioThreadInfo::new(),
            pmic_info: AudioThreadInfo::new(),
            audio_server,

            irq_resample_thread: None,
            sys: Default::default(),
        }
    }

    /// Returns any file descriptors that need to be kept open when entering a jail.
    pub fn keep_rds(&self) -> Option<Vec<RawDescriptor>> {
        let mut rds = self.audio_server.keep_fds();
        rds.append(&mut self.mem.as_raw_descriptors());
        Some(rds)
    }

    pub(in crate::pci::ac97_bus_master) fn check_and_move_to_next_buffer(
        func_regs: &mut Ac97FunctionRegs,
    ) {
        if func_regs.sr & SR_CELV != 0 {
            // CELV means we'd already processed the buffer at CIV.
            // Move CIV to the next buffer now that LVI has moved.
            func_regs.move_to_next_buffer();
        }
    }

    pub(in crate::pci::ac97_bus_master) fn thread_semaphore_notify(&self, func: Ac97Function) {
        match func {
            Ac97Function::Input => self.pi_info.thread_semaphore.notify_one(),
            Ac97Function::Output => self.po_info.thread_semaphore.notify_one(),
            Ac97Function::Microphone => self.pmic_info.thread_semaphore.notify_one(),
        }
    }

    fn stream_effects(func: Ac97Function) -> Vec<StreamEffect> {
        match func {
            Ac97Function::Microphone => vec![StreamEffect::EchoCancellation],
            _ => vec![StreamEffect::NoEffect],
        }
    }

    fn create_audio_worker(
        &mut self,
        mixer: &Ac97Mixer,
        func: Ac97Function,
    ) -> AudioResult<AudioWorker> {
        let direction = match func {
            Ac97Function::Microphone => StreamDirection::Capture,
            Ac97Function::Input => StreamDirection::Capture,
            Ac97Function::Output => StreamDirection::Playback,
        };

        let locked_regs = self.regs.lock();
        let sample_rate = self.current_sample_rate(func, mixer);
        let buffer_samples = current_buffer_size(locked_regs.func_regs(func), &self.mem)?;
        let num_channels = locked_regs.tube_count(func);
        let buffer_frames = buffer_samples / num_channels;

        let mut pending_buffers = VecDeque::with_capacity(2);
        let starting_offsets = match direction {
            StreamDirection::Capture => {
                let mut offsets = [0, 0];
                for offset in &mut offsets {
                    let buffer = next_guest_buffer(&locked_regs, &self.mem, func, 0)?
                        .ok_or(AudioError::NoBufferAvailable)?;
                    *offset = buffer.offset as u64;
                    pending_buffers.push_back(Some(buffer));
                }
                offsets
            }
            StreamDirection::Playback => [0, 0],
        };

        // Create a `base::SharedMemory` object from a descriptor backing `self.mem`.
        // This creation is expected to succeed because we can assume that `self.mem` was created
        // from a `SharedMemory` object and its type was generalized to `dyn AsRawDescriptor`.
        let desc: &dyn AsRawDescriptor = self
            .mem
            .offset_region(starting_offsets[0])
            .map_err(|e| AudioError::GuestRegion(GuestMemoryError::ReadingGuestBufferAddress(e)))?;
        let shm = {
            let rd = base::clone_descriptor(desc).map_err(AudioError::CloneDescriptor)?;
            // Safe because the fd is owned.
            let sd = unsafe { base::SafeDescriptor::from_raw_descriptor(rd) };
            base::SharedMemory::from_safe_descriptor(sd, None)
                .map_err(AudioError::CreateSharedMemory)?
        };

        let stream = self
            .audio_server
            .new_stream(
                direction,
                num_channels,
                SampleFormat::S16LE,
                sample_rate,
                buffer_frames,
                &Self::stream_effects(func),
                &shm,
                starting_offsets,
            )
            .map_err(AudioError::CreateStream)?;

        let params = AudioWorkerParams {
            func,
            stream,
            pending_buffers,
            message_interval: Duration::from_secs_f64(buffer_frames as f64 / sample_rate as f64),
        };
        Ok(AudioWorker::new(self, params))
    }

    pub(in crate::pci::ac97_bus_master) fn start_audio(
        &mut self,
        func: Ac97Function,
        mixer: &Ac97Mixer,
    ) -> AudioResult<()> {
        let audio_worker = self.create_audio_worker(mixer, func)?;
        self.thread_info_mut(func).start(audio_worker);
        self.update_mixer_settings(mixer);
        Ok(())
    }
}

#[derive(Debug)]
struct GuestBuffer {
    offset: usize,
    frames: usize,
}

fn get_buffer_offset(
    func_regs: &Ac97FunctionRegs,
    mem: &GuestMemory,
    index: u8,
) -> GuestMemoryResult<u64> {
    let descriptor_addr = func_regs.bdbar + u32::from(index) * DESCRIPTOR_LENGTH as u32;
    let buffer_addr_reg: u32 = mem
        .read_obj_from_addr(GuestAddress(u64::from(descriptor_addr)))
        .map_err(GuestMemoryError::ReadingGuestBufferAddress)?;
    let buffer_addr = GuestAddress((buffer_addr_reg & !0x03u32) as u64); // The address must be aligned to four bytes.

    mem.offset_from_base(buffer_addr)
        .map_err(GuestMemoryError::ReadingGuestBufferAddress)
}

// Gets the start address and length of the buffer at `civ + offset` from the
// guest.
// This will return `None` if `civ + offset` is past LVI; if the DMA controlled
// stopped bit is set, such as after an underrun where CIV hits LVI; or if
// `civ + offset == LVI and the CELV flag is set.
fn next_guest_buffer(
    regs: &Ac97BusMasterRegs,
    mem: &GuestMemory,
    func: Ac97Function,
    offset: usize,
) -> AudioResult<Option<GuestBuffer>> {
    let func_regs = regs.func_regs(func);
    let offset = (offset % 32) as u8;
    let index = (func_regs.civ + offset) % 32;

    // Check that value is between `low` and `high` modulo some `n`.
    fn check_between(low: u8, high: u8, value: u8) -> bool {
        // If low <= high, value must be in the interval between them:
        // 0     l     h     n
        // ......+++++++......
        (low <= high && (low <= value && value <= high)) ||
            // If low > high, value must not be in the interval between them:
            // 0       h      l  n
            // +++++++++......++++
            (low > high && (low <= value || value <= high))
    }

    // Check if
    //  * we're halted
    //  * `index` is not between CIV and LVI (mod 32)
    //  * `index is LVI and we've already processed LVI (SR_CELV is set)
    //  if any of these are true `index` isn't valid.
    if func_regs.sr & SR_DCH != 0
        || !check_between(func_regs.civ, func_regs.lvi, index)
        || func_regs.sr & SR_CELV != 0
    {
        return Ok(None);
    }

    let offset = get_buffer_offset(func_regs, mem, index)?
        .try_into()
        .map_err(|_| AudioError::InvalidBufferOffset)?;
    let frames = get_buffer_samples(func_regs, mem, index)? / regs.tube_count(func);

    Ok(Some(GuestBuffer { offset, frames }))
}

// Runs and updates the offset within the stream shm where samples can be
// found/placed for shm playback/capture streams, respectively
struct AudioWorker {
    func: Ac97Function,
    regs: Arc<Mutex<Ac97BusMasterRegs>>,
    mem: GuestMemory,
    thread_run: Arc<AtomicBool>,
    lvi_semaphore: Arc<Condvar>,
    message_interval: Duration,
    stream: Box<dyn ShmStream>,
    pending_buffers: VecDeque<Option<GuestBuffer>>,
}

struct AudioWorkerParams {
    func: Ac97Function,
    stream: Box<dyn ShmStream>,
    pending_buffers: VecDeque<Option<GuestBuffer>>,
    message_interval: Duration,
}

impl AudioWorker {
    fn new(bus_master: &Ac97BusMaster, args: AudioWorkerParams) -> Self {
        Self {
            func: args.func,
            regs: bus_master.regs.clone(),
            mem: bus_master.mem.clone(),
            thread_run: bus_master.thread_info(args.func).thread_run.clone(),
            lvi_semaphore: bus_master.thread_info(args.func).thread_semaphore.clone(),
            message_interval: args.message_interval,
            stream: args.stream,
            pending_buffers: args.pending_buffers,
        }
    }

    // Runs and updates the offset within the stream shm where samples can be
    // found/placed for shm playback/capture streams, respectively
    fn run(&mut self) -> AudioResult<()> {
        let func = self.func;
        let message_interval = self.message_interval;
        // Set up picb.
        {
            let mut locked_regs = self.regs.lock();
            locked_regs.func_regs_mut(func).picb =
                current_buffer_size(locked_regs.func_regs(func), &self.mem)? as u16;
        }

        'audio_loop: while self.thread_run.load(Ordering::Relaxed) {
            {
                let mut locked_regs = self.regs.lock();
                while locked_regs.func_regs(func).sr & SR_DCH != 0 {
                    locked_regs = self.lvi_semaphore.wait(locked_regs);
                    if !self.thread_run.load(Ordering::Relaxed) {
                        break 'audio_loop;
                    }
                }
            }

            let timeout = Duration::from_secs(1);
            let action = self
                .stream
                .wait_for_next_action_with_timeout(timeout)
                .map_err(AudioError::WaitForAction)?;

            let request = match action {
                None => {
                    warn!("No audio message received within timeout of {:?}", timeout);
                    continue;
                }
                Some(request) => request,
            };
            let start = Instant::now();

            let next_buffer = {
                let mut locked_regs = self.regs.lock();
                if self.pending_buffers.len() == 2 {
                    // When we have two pending buffers and receive a request for
                    // another, we know that oldest buffer has been completed.
                    // However, if that old buffer was an empty buffer we sent
                    // because the guest driver had no available buffers, we don't
                    // want to mark a buffer complete.
                    if let Some(Some(_)) = self.pending_buffers.pop_front() {
                        buffer_completed(&mut locked_regs, &self.mem, self.func)?;
                    }
                }

                // We count the number of pending, real buffers at the server, and
                // then use that as our offset from CIV.
                let offset = self.pending_buffers.iter().filter(|e| e.is_some()).count();

                // Get a buffer to respond to our request. If there's no buffer
                // available, we'll wait one buffer interval and check again.
                loop {
                    if let Some(buffer) = next_guest_buffer(&locked_regs, &self.mem, func, offset)?
                    {
                        break Some(buffer);
                    }
                    let elapsed = start.elapsed();
                    if elapsed > message_interval {
                        break None;
                    }
                    locked_regs = self
                        .lvi_semaphore
                        .wait_timeout(locked_regs, message_interval - elapsed)
                        .0;
                }
            };

            match next_buffer {
                Some(ref buffer) => {
                    let requested_frames = request.requested_frames();
                    if requested_frames != buffer.frames {
                        // We should be able to handle when the number of frames in
                        // the buffer doesn't match the number of frames requested,
                        // but we don't yet.
                        warn!(
                            "Stream requested {} frames but buffer had {} frames: {:?}",
                            requested_frames, buffer.frames, buffer
                        );
                    }

                    request
                        .set_buffer_offset_and_frames(
                            buffer.offset,
                            std::cmp::min(requested_frames, buffer.frames),
                        )
                        .map_err(AudioError::RespondRequest)?;
                }
                None => {
                    request
                        .ignore_request()
                        .map_err(AudioError::RespondRequest)?;
                }
            }
            self.pending_buffers.push_back(next_buffer);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use audio_streams::shm_streams::MockShmStreamSource;

    use super::*;
    use crate::pci::ac97_bus_master::tests::capture_release_cold_reset_and_setup_ping_pong_buffers;
    use crate::pci::ac97_bus_master::tests::check_buffer_set_and_clear_bcis;
    use crate::pci::ac97_bus_master::tests::clear_lvb_and_reset_lvi;
    use crate::pci::ac97_bus_master::tests::playback_release_cold_reset_and_setup_ping_pong_buffers;
    use crate::pci::ac97_bus_master::tests::stop;

    #[test]
    fn run_multi_tube_playback_2() {
        start_playback(2, 48000);
    }

    #[test]
    fn run_multi_tube_playback_4() {
        start_playback(4, 48000);
    }

    #[test]
    fn run_multi_tube_playback_6() {
        start_playback(6, 48000);
    }

    #[test]
    fn run_multi_rate_playback_32() {
        start_playback(2, 32000);
    }

    #[test]
    fn run_multi_rate_playback_44() {
        start_playback(2, 44100);
    }

    #[test]
    fn run_multi_rate_playback_48() {
        start_playback(2, 32000);
    }

    fn start_playback(num_channels: usize, rate: u16) {
        const TIMEOUT: Duration = Duration::from_millis(500);
        const LVI_MASK: u8 = 0x1f; // Five bits for 32 total entries.
        const IOC_MASK: u32 = 0x8000_0000; // Interrupt on completion.
        let num_buffers = LVI_MASK as usize + 1;
        const BUFFER_SIZE: usize = 32768;
        const FRAGMENT_SIZE: usize = BUFFER_SIZE / 2;

        const GUEST_ADDR_BASE: u32 = 0x100_0000;
        let mem = GuestMemory::new(&[(GuestAddress(GUEST_ADDR_BASE as u64), 1024 * 1024 * 8)])
            .expect("Creating guest memory failed.");
        let stream_source = MockShmStreamSource::new();
        let mut bm = Ac97BusMaster::new(mem.clone(), Box::new(stream_source.clone()));
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

        assert_eq!(bm.readb(PO_CIV_14), 0);

        // Set tube count and sample rate.
        let mut cnt = bm.readl(GLOB_CNT_2C);
        cnt &= !GLOB_CNT_PCM_246_MASK;
        mixer.writew(MIXER_PCM_FRONT_DAC_RATE_2C, rate);
        if num_channels == 4 {
            cnt |= GLOB_CNT_PCM_4;
            mixer.writew(MIXER_PCM_SURR_DAC_RATE_2E, rate);
        } else if num_channels == 6 {
            cnt |= GLOB_CNT_PCM_6;
            mixer.writew(MIXER_PCM_LFE_DAC_RATE_30, rate);
        }
        bm.writel(GLOB_CNT_2C, cnt, &mut mixer);

        // Start.
        bm.writeb(PO_CR_1B, CR_IOCE | CR_RPBM, &mixer);
        // TODO(crbug.com/1058881): The test is flaky in builder.
        // assert_eq!(bm.readw(PO_PICB_18), 0);

        let mut stream = stream_source.get_last_stream();
        // Trigger callback and see that CIV has not changed, since only 1
        // buffer has been sent.
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));

        assert_eq!(stream.num_channels(), num_channels);
        assert_eq!(stream.frame_rate(), rate as u32);

        let mut civ = bm.readb(PO_CIV_14);
        assert_eq!(civ, 0);

        // After two more callbacks, CIV should now be 1 since we know that the
        // first buffer must have been played.
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        civ = bm.readb(PO_CIV_14);
        assert_eq!(civ, 1);

        check_buffer_set_and_clear_bcis(PO_BASE_10, &mixer, &mut bm);

        std::thread::sleep(Duration::from_millis(50));
        let picb = bm.readw(PO_PICB_18, &mixer);
        let pos = (FRAGMENT_SIZE - (picb as usize * 2)) / 4;

        // Check that frames are consumed at least at a reasonable rate.
        // This can't be exact as during unit tests the thread scheduling is highly variable, so the
        // test only checks that some samples are consumed.
        assert!(pos > 0);
        assert!(bm.readw(PO_SR_16, &mixer) & SR_DCH == 0); // DMA is running.

        // Set last valid to next buffer to be sent and trigger callback so we hit it.
        bm.writeb(PO_LVI_15, civ + 2, &mixer);
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(bm.readw(PO_SR_16, &mixer) & SR_LVBCI != 0); // Hit last buffer
        assert!(bm.readw(PO_SR_16, &mixer) & SR_DCH == SR_DCH); // DMA stopped because of lack of buffers.
        assert!(bm.readw(PO_SR_16, &mixer) & SR_CELV == SR_CELV); // Processed the last buffer
        assert_eq!(bm.readb(PO_LVI_15), bm.readb(PO_CIV_14));
        assert!(
            bm.readl(GLOB_STA_30) & GS_POINT != 0,
            "POINT bit should be set."
        );

        clear_lvb_and_reset_lvi(PO_BASE_10, &mixer, &mut bm, LVI_MASK);

        let restart_civ = bm.readb(PO_CIV_14);
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(bm.readb(PO_CIV_14) != restart_civ);

        stop(PO_BASE_10, GS_POINT, &mixer, &mut bm);
    }

    #[test]
    fn run_capture_input() {
        start_capture(Ac97Function::Input);
    }

    #[test]
    fn run_capture_microphone() {
        start_capture(Ac97Function::Microphone);
    }

    fn start_capture(func: Ac97Function) {
        const TIMEOUT: Duration = Duration::from_millis(500);
        const LVI_MASK: u8 = 0x1f; // Five bits for 32 total entries.
        const IOC_MASK: u32 = 0x8000_0000; // Interrupt on completion.
        let num_buffers = LVI_MASK as usize + 1;
        const BUFFER_SIZE: usize = 32768;
        const FRAGMENT_SIZE: usize = BUFFER_SIZE / 2;

        const GUEST_ADDR_BASE: u32 = 0x100_0000;
        let mem = GuestMemory::new(&[(GuestAddress(GUEST_ADDR_BASE as u64), 1024 * 1024 * 8)])
            .expect("Creating guest memory failed.");
        let stream_source = MockShmStreamSource::new();
        let mut bm = Ac97BusMaster::new(mem.clone(), Box::new(stream_source.clone()));
        let mut mixer = Ac97Mixer::new();

        let (base, bdbar_addr, lvi_addr, cr_addr, civ_addr, pcib_addr, sr_addr, int_mask) =
            match func {
                Ac97Function::Input => (
                    PI_BASE_00,
                    PI_BDBAR_00,
                    PI_LVI_05,
                    PI_CR_0B,
                    PI_CIV_04,
                    PI_PICB_08,
                    PI_SR_06,
                    GS_PIINT,
                ),
                Ac97Function::Microphone => (
                    MC_BASE_20,
                    MC_BDBAR_20,
                    MC_LVI_25,
                    MC_CR_2B,
                    MC_CIV_24,
                    MC_PICB_28,
                    MC_SR_26,
                    GS_MINT,
                ),
                _ => {
                    panic!("Invalid Ac97Function.");
                }
            };

        capture_release_cold_reset_and_setup_ping_pong_buffers(
            bdbar_addr,
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
        bm.writeb(cr_addr, CR_IOCE | CR_RPBM, &mixer);
        // TODO(crbug.com/1086337): Test flakiness in build time.
        // assert_eq!(bm.readw(PI_PICB_08), 0);

        let mut stream = stream_source.get_last_stream();
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));

        // CIV is 1 here since we preemptively sent two buffer indices to the
        // server before creating the stream. When we triggered the callback
        // above, that means the first of those buffers was filled, so CIV
        // increments to 1.
        let civ = bm.readb(civ_addr);
        assert_eq!(civ, 1);
        std::thread::sleep(Duration::from_millis(20));
        let picb = bm.readw(pcib_addr, &mixer);
        assert!(picb > 0);
        assert!(bm.readw(sr_addr, &mixer) & SR_DCH == 0); // DMA is running.

        // Trigger 2 callbacks so that we'll move to buffer 3 since at that
        // point we can be certain that buffers 1 and 2 have been captured to.
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert_eq!(bm.readb(civ_addr), 3);

        let civ = bm.readb(civ_addr);
        // Sets LVI to CIV + 2 to trigger last buffer hit
        bm.writeb(lvi_addr, civ + 2, &mixer);
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert_ne!(bm.readw(sr_addr, &mixer) & SR_LVBCI, 0); // Hit last buffer
        assert_eq!(bm.readw(sr_addr, &mixer) & SR_DCH, SR_DCH); // DMA stopped because of lack of buffers.
        assert_eq!(bm.readw(sr_addr, &mixer) & SR_CELV, SR_CELV);
        assert_eq!(bm.readb(lvi_addr), bm.readb(civ_addr));
        assert!(
            bm.readl(GLOB_STA_30) & int_mask != 0,
            "int_mask bit should be set."
        );

        clear_lvb_and_reset_lvi(base, &mixer, &mut bm, LVI_MASK);

        let restart_civ = bm.readb(civ_addr);
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert_ne!(bm.readb(civ_addr), restart_civ);

        stop(base, int_mask, &mixer, &mut bm);
    }
}
