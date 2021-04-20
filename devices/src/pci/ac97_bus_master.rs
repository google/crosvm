// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::convert::TryInto;
use std::fmt::{self, Display};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use audio_streams::{
    shm_streams::{ShmStream, ShmStreamSource},
    BoxError, NoopStreamControl, SampleFormat, StreamControl, StreamDirection, StreamEffect,
};
use base::{
    self, error, set_rt_prio_limit, set_rt_round_robin, warn, AsRawDescriptors, Event,
    RawDescriptor,
};
use sync::{Condvar, Mutex};
use vm_memory::{GuestAddress, GuestMemory};

use crate::pci::ac97_mixer::Ac97Mixer;
use crate::pci::ac97_regs::*;

const INPUT_SAMPLE_RATE: u32 = 48000;
const DEVICE_INPUT_CHANNEL_COUNT: usize = 2;

// Bus Master registers. Keeps the state of the bus master register values. Used to share the state
// between the main and audio threads.
struct Ac97BusMasterRegs {
    pi_regs: Ac97FunctionRegs,       // Input
    po_regs: Ac97FunctionRegs,       // Output
    po_pointer_update_time: Instant, // Time the picb and civ regs were last updated.
    mc_regs: Ac97FunctionRegs,       // Microphone
    glob_cnt: u32,
    glob_sta: u32,

    // IRQ event - driven by the glob_sta register.
    irq_evt: Option<Event>,
}

impl Ac97BusMasterRegs {
    fn new() -> Ac97BusMasterRegs {
        Ac97BusMasterRegs {
            pi_regs: Ac97FunctionRegs::new(),
            po_regs: Ac97FunctionRegs::new(),
            po_pointer_update_time: Instant::now(),
            mc_regs: Ac97FunctionRegs::new(),
            glob_cnt: 0,
            glob_sta: GLOB_STA_RESET_VAL,
            irq_evt: None,
        }
    }

    fn func_regs(&self, func: Ac97Function) -> &Ac97FunctionRegs {
        match func {
            Ac97Function::Input => &self.pi_regs,
            Ac97Function::Output => &self.po_regs,
            Ac97Function::Microphone => &self.mc_regs,
        }
    }

    fn func_regs_mut(&mut self, func: Ac97Function) -> &mut Ac97FunctionRegs {
        match func {
            Ac97Function::Input => &mut self.pi_regs,
            Ac97Function::Output => &mut self.po_regs,
            Ac97Function::Microphone => &mut self.mc_regs,
        }
    }

    fn tube_count(&self, func: Ac97Function) -> usize {
        fn output_tube_count(glob_cnt: u32) -> usize {
            let val = (glob_cnt & GLOB_CNT_PCM_246_MASK) >> 20;
            match val {
                0 => 2,
                1 => 4,
                2 => 6,
                _ => {
                    warn!("unknown tube_count: 0x{:x}", val);
                    2
                }
            }
        }

        match func {
            Ac97Function::Output => output_tube_count(self.glob_cnt),
            _ => DEVICE_INPUT_CHANNEL_COUNT,
        }
    }

    /// Returns whether the irq is set for any one of the bus master function registers.
    pub fn has_irq(&self) -> bool {
        self.pi_regs.has_irq() || self.po_regs.has_irq() || self.mc_regs.has_irq()
    }
}

// Internal error type used for reporting errors from guest memory reading.
#[derive(Debug)]
enum GuestMemoryError {
    // Failure getting the address of the audio buffer.
    ReadingGuestBufferAddress(vm_memory::GuestMemoryError),
}

impl std::error::Error for GuestMemoryError {}

impl Display for GuestMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::GuestMemoryError::*;

        match self {
            ReadingGuestBufferAddress(e) => {
                write!(f, "Failed to get the address of the audio buffer: {}.", e)
            }
        }
    }
}

impl From<GuestMemoryError> for AudioError {
    fn from(err: GuestMemoryError) -> Self {
        AudioError::ReadingGuestError(err)
    }
}

type GuestMemoryResult<T> = std::result::Result<T, GuestMemoryError>;

// Internal error type used for reporting errors from the audio thread.
#[derive(Debug)]
enum AudioError {
    // Failed to create a new stream.
    CreateStream(BoxError),
    // Failure to get regions from guest memory.
    GuestRegion(GuestMemoryError),
    // Invalid buffer offset received from the audio server.
    InvalidBufferOffset,
    // Guest did not provide a buffer when needed.
    NoBufferAvailable,
    // Failure to read guest memory.
    ReadingGuestError(GuestMemoryError),
    // Failure to respond to the ServerRequest.
    RespondRequest(BoxError),
    // Failure to wait for a request from the stream.
    WaitForAction(BoxError),
}

impl std::error::Error for AudioError {}

impl Display for AudioError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::AudioError::*;

        match self {
            CreateStream(e) => write!(f, "Failed to create audio stream: {}.", e),
            GuestRegion(e) => write!(f, "Failed to get guest memory region: {}.", e),
            InvalidBufferOffset => write!(f, "Offset > max usize"),
            NoBufferAvailable => write!(f, "No buffer was available from the Guest"),
            ReadingGuestError(e) => write!(f, "Failed to read guest memory: {}.", e),
            RespondRequest(e) => write!(f, "Failed to respond to the ServerRequest: {}", e),
            WaitForAction(e) => write!(f, "Failed to wait for a message from the stream: {}", e),
        }
    }
}

type AudioResult<T> = std::result::Result<T, AudioError>;

// Audio thread book-keeping data
struct AudioThreadInfo {
    thread: Option<thread::JoinHandle<()>>,
    thread_run: Arc<AtomicBool>,
    thread_semaphore: Arc<Condvar>,
    stream_control: Option<Box<dyn StreamControl>>,
}

impl AudioThreadInfo {
    fn new() -> Self {
        Self {
            thread: None,
            thread_run: Arc::new(AtomicBool::new(false)),
            thread_semaphore: Arc::new(Condvar::new()),
            stream_control: None,
        }
    }

    fn is_running(&self) -> bool {
        self.thread_run.load(Ordering::Relaxed)
    }

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

    fn stop(&mut self) {
        self.thread_run.store(false, Ordering::Relaxed);
        self.thread_semaphore.notify_one();
        if let Some(thread) = self.thread.take() {
            if let Err(e) = thread.join() {
                error!("Failed to join thread: {:?}.", e);
            }
        }
    }
}

/// `Ac97BusMaster` emulates the bus master portion of AC97. It exposes a register read/write
/// interface compliant with the ICH bus master.
pub struct Ac97BusMaster {
    // Keep guest memory as each function will use it for buffer descriptors.
    mem: GuestMemory,
    regs: Arc<Mutex<Ac97BusMasterRegs>>,
    acc_sema: u8,

    // Bookkeeping info for playback and capture stream.
    po_info: AudioThreadInfo,
    pi_info: AudioThreadInfo,
    pmic_info: AudioThreadInfo,

    // Audio server used to create playback or capture streams.
    audio_server: Box<dyn ShmStreamSource>,

    // Thread for hadlind IRQ resample events from the guest.
    irq_resample_thread: Option<thread::JoinHandle<()>>,
}

impl Ac97BusMaster {
    /// Creates an Ac97BusMaster` object that plays audio from `mem` to streams provided by
    /// `audio_server`.
    pub fn new(mem: GuestMemory, audio_server: Box<dyn ShmStreamSource>) -> Self {
        Ac97BusMaster {
            mem,
            regs: Arc::new(Mutex::new(Ac97BusMasterRegs::new())),
            acc_sema: 0,

            po_info: AudioThreadInfo::new(),
            pi_info: AudioThreadInfo::new(),
            pmic_info: AudioThreadInfo::new(),
            audio_server,

            irq_resample_thread: None,
        }
    }

    /// Returns any file descriptors that need to be kept open when entering a jail.
    pub fn keep_rds(&self) -> Option<Vec<RawDescriptor>> {
        let mut rds = self.audio_server.keep_fds();
        rds.append(&mut self.mem.as_raw_descriptors());
        Some(rds)
    }

    /// Provides the events needed to raise interrupts in the guest.
    pub fn set_irq_event(&mut self, irq_evt: Event, irq_resample_evt: Event) {
        let thread_regs = self.regs.clone();
        self.regs.lock().irq_evt = Some(irq_evt);
        self.irq_resample_thread = Some(thread::spawn(move || {
            loop {
                if let Err(e) = irq_resample_evt.read() {
                    error!(
                        "Failed to read the irq event from the resample thread: {}.",
                        e,
                    );
                    break;
                }
                {
                    // Scope for the lock on thread_regs.
                    let regs = thread_regs.lock();
                    if regs.has_irq() {
                        if let Some(irq_evt) = regs.irq_evt.as_ref() {
                            if let Err(e) = irq_evt.write(1) {
                                error!("Failed to set the irq from the resample thread: {}.", e);
                                break;
                            }
                        }
                    }
                }
            }
        }));
    }

    /// Called when `mixer` has been changed and the new values should be applied to currently
    /// active streams.
    pub fn update_mixer_settings(&mut self, mixer: &Ac97Mixer) {
        if let Some(control) = self.po_info.stream_control.as_mut() {
            // The audio server only supports one volume, not separate left and right.
            let (muted, left_volume, _right_volume) = mixer.get_master_volume();
            control.set_volume(left_volume);
            control.set_mute(muted);
        }
    }

    /// Checks if the bus master is in the cold reset state.
    pub fn is_cold_reset(&self) -> bool {
        self.regs.lock().glob_cnt & GLOB_CNT_COLD_RESET == 0
    }

    /// Reads a byte from the given `offset`.
    pub fn readb(&mut self, offset: u64) -> u8 {
        fn readb_func_regs(func_regs: &Ac97FunctionRegs, offset: u64) -> u8 {
            match offset {
                CIV_OFFSET => func_regs.civ,
                LVI_OFFSET => func_regs.lvi,
                SR_OFFSET => func_regs.sr as u8,
                PIV_OFFSET => func_regs.piv,
                CR_OFFSET => func_regs.cr,
                _ => 0,
            }
        }

        let regs = self.regs.lock();
        match offset {
            PI_BASE_00..=PI_CR_0B => readb_func_regs(&regs.pi_regs, offset - PI_BASE_00),
            PO_BASE_10..=PO_CR_1B => readb_func_regs(&regs.po_regs, offset - PO_BASE_10),
            MC_BASE_20..=MC_CR_2B => readb_func_regs(&regs.mc_regs, offset - MC_BASE_20),
            ACC_SEMA_34 => self.acc_sema,
            _ => 0,
        }
    }

    /// Reads a word from the given `offset`.
    pub fn readw(&mut self, offset: u64, mixer: &Ac97Mixer) -> u16 {
        let regs = self.regs.lock();
        match offset {
            PI_SR_06 => regs.pi_regs.sr,
            PI_PICB_08 => regs.pi_regs.picb,
            PO_SR_16 => regs.po_regs.sr,
            PO_PICB_18 => {
                // PO PICB
                if !self.thread_info(Ac97Function::Output).is_running() {
                    // Not running, no need to estimate what has been consumed.
                    regs.po_regs.picb
                } else {
                    // Estimate how many samples have been played since the last audio callback.
                    let num_channels = regs.tube_count(Ac97Function::Output) as u64;
                    let micros = regs.po_pointer_update_time.elapsed().subsec_micros();
                    // Round down to the next 10 millisecond boundary. The linux driver often
                    // assumes that two rapid reads from picb will return the same value.
                    let millis = micros / 1000 / 10 * 10;
                    let sample_rate = self.current_sample_rate(Ac97Function::Output, mixer);
                    let frames_consumed = sample_rate as u64 * u64::from(millis) / 1000;

                    regs.po_regs
                        .picb
                        .saturating_sub((num_channels * frames_consumed) as u16)
                }
            }
            MC_SR_26 => regs.mc_regs.sr,
            MC_PICB_28 => regs.mc_regs.picb,
            _ => 0,
        }
    }

    /// Reads a 32-bit word from the given `offset`.
    pub fn readl(&mut self, offset: u64) -> u32 {
        let regs = self.regs.lock();
        match offset {
            PI_BDBAR_00 => regs.pi_regs.bdbar,
            PI_CIV_04 => regs.pi_regs.atomic_status_regs(),
            PO_BDBAR_10 => regs.po_regs.bdbar,
            PO_CIV_14 => regs.po_regs.atomic_status_regs(),
            MC_BDBAR_20 => regs.mc_regs.bdbar,
            MC_CIV_24 => regs.mc_regs.atomic_status_regs(),
            GLOB_CNT_2C => regs.glob_cnt,
            GLOB_STA_30 => regs.glob_sta,
            _ => 0,
        }
    }

    /// Writes the byte `val` to the register specified by `offset`.
    pub fn writeb(&mut self, offset: u64, val: u8, mixer: &Ac97Mixer) {
        // Only process writes to the control register when cold reset is set.
        if self.is_cold_reset() {
            return;
        }

        match offset {
            PI_CIV_04 => (), // RO
            PI_LVI_05 => self.set_lvi(Ac97Function::Input, val),
            PI_SR_06 => self.set_sr(Ac97Function::Input, u16::from(val)),
            PI_PIV_0A => (), // RO
            PI_CR_0B => self.set_cr(Ac97Function::Input, val, mixer),
            PO_CIV_14 => (), // RO
            PO_LVI_15 => self.set_lvi(Ac97Function::Output, val),
            PO_SR_16 => self.set_sr(Ac97Function::Output, u16::from(val)),
            PO_PIV_1A => (), // RO
            PO_CR_1B => self.set_cr(Ac97Function::Output, val, mixer),
            MC_CIV_24 => (), // RO
            MC_LVI_25 => self.set_lvi(Ac97Function::Microphone, val),
            MC_SR_26 => self.set_sr(Ac97Function::Microphone, u16::from(val)),
            MC_PIV_2A => (), // RO
            MC_CR_2B => self.set_cr(Ac97Function::Microphone, val, mixer),
            ACC_SEMA_34 => self.acc_sema = val,
            o => warn!("write byte to 0x{:x}", o),
        }
    }

    /// Writes the word `val` to the register specified by `offset`.
    pub fn writew(&mut self, offset: u64, val: u16) {
        // Only process writes to the control register when cold reset is set.
        if self.is_cold_reset() {
            return;
        }
        match offset {
            PI_SR_06 => self.set_sr(Ac97Function::Input, val),
            PI_PICB_08 => (), // RO
            PO_SR_16 => self.set_sr(Ac97Function::Output, val),
            PO_PICB_18 => (), // RO
            MC_SR_26 => self.set_sr(Ac97Function::Microphone, val),
            MC_PICB_28 => (), // RO
            o => warn!("write word to 0x{:x}", o),
        }
    }

    /// Writes the 32-bit `val` to the register specified by `offset`.
    pub fn writel(&mut self, offset: u64, val: u32, mixer: &mut Ac97Mixer) {
        // Only process writes to the control register when cold reset is set.
        if self.is_cold_reset() && offset != 0x2c {
            return;
        }
        match offset {
            PI_BDBAR_00 => self.set_bdbar(Ac97Function::Input, val),
            PO_BDBAR_10 => self.set_bdbar(Ac97Function::Output, val),
            MC_BDBAR_20 => self.set_bdbar(Ac97Function::Microphone, val),
            GLOB_CNT_2C => self.set_glob_cnt(val, mixer),
            GLOB_STA_30 => (), // RO
            o => warn!("write long to 0x{:x}", o),
        }
    }

    fn set_bdbar(&mut self, func: Ac97Function, val: u32) {
        self.regs.lock().func_regs_mut(func).bdbar = val & !0x07;
    }

    fn set_lvi(&mut self, func: Ac97Function, val: u8) {
        let mut regs = self.regs.lock();
        let func_regs = regs.func_regs_mut(func);
        func_regs.lvi = val % 32; // LVI wraps at 32.

        // If running and stalled waiting for more valid buffers, restart by clearing the "DMA
        // stopped" bit.
        if func_regs.cr & CR_RPBM == CR_RPBM
            && func_regs.sr & SR_DCH == SR_DCH
            && func_regs.civ != func_regs.lvi
        {
            if func_regs.sr & SR_CELV != 0 {
                // CELV means we'd already processed the buffer at CIV.
                // Move CIV to the next buffer now that LVI has moved.
                func_regs.move_to_next_buffer();
            }
            func_regs.sr &= !(SR_DCH | SR_CELV);

            match func {
                Ac97Function::Input => self.pi_info.thread_semaphore.notify_one(),
                Ac97Function::Output => self.po_info.thread_semaphore.notify_one(),
                Ac97Function::Microphone => self.pmic_info.thread_semaphore.notify_one(),
            }
        }
    }

    fn set_sr(&mut self, func: Ac97Function, val: u16) {
        let mut sr = self.regs.lock().func_regs(func).sr;
        if val & SR_FIFOE != 0 {
            sr &= !SR_FIFOE;
        }
        if val & SR_LVBCI != 0 {
            sr &= !SR_LVBCI;
        }
        if val & SR_BCIS != 0 {
            sr &= !SR_BCIS;
        }
        update_sr(&mut self.regs.lock(), func, sr);
    }

    fn set_cr(&mut self, func: Ac97Function, val: u8, mixer: &Ac97Mixer) {
        if val & CR_RR != 0 {
            let mut regs = self.regs.lock();
            Self::reset_func_regs(&mut regs, func);
        } else {
            let cr = self.regs.lock().func_regs(func).cr;
            if val & CR_RPBM == 0 {
                // Run/Pause set to pause.
                self.thread_info_mut(func).stop();
                let mut regs = self.regs.lock();
                regs.func_regs_mut(func).sr |= SR_DCH;
            } else if cr & CR_RPBM == 0 {
                // Not already running.
                // Run/Pause set to run.
                {
                    let mut regs = self.regs.lock();
                    let func_regs = regs.func_regs_mut(func);
                    func_regs.piv = 1;
                    func_regs.civ = 0;
                    func_regs.sr &= !SR_DCH;
                }
                if let Err(e) = self.start_audio(func, mixer) {
                    warn!("Failed to start audio: {}", e);
                }
            }
            let mut regs = self.regs.lock();
            regs.func_regs_mut(func).cr = val & CR_VALID_MASK;
        }
    }

    fn set_glob_cnt(&mut self, new_glob_cnt: u32, mixer: &mut Ac97Mixer) {
        // Only the reset bits are emulated, the GPI and PCM formatting are not supported.
        if new_glob_cnt & GLOB_CNT_COLD_RESET == 0 {
            self.reset_audio_regs();
            mixer.reset();
            let mut regs = self.regs.lock();
            regs.glob_cnt = new_glob_cnt & GLOB_CNT_STABLE_BITS;
            self.acc_sema = 0;
            return;
        }
        if new_glob_cnt & GLOB_CNT_WARM_RESET != 0 {
            // Check if running and if so, ignore. Warm reset is specified to no-op when the device
            // is playing or recording audio.
            if !self.is_audio_running() {
                self.stop_all_audio();
                let mut regs = self.regs.lock();
                regs.glob_cnt = new_glob_cnt & !GLOB_CNT_WARM_RESET; // Auto-cleared reset bit.
                return;
            }
        }
        self.regs.lock().glob_cnt = new_glob_cnt;
    }

    fn stream_effects(func: Ac97Function) -> Vec<StreamEffect> {
        match func {
            Ac97Function::Microphone => vec![StreamEffect::EchoCancellation],
            _ => vec![StreamEffect::NoEffect],
        }
    }

    fn current_sample_rate(&self, func: Ac97Function, mixer: &Ac97Mixer) -> u32 {
        match func {
            Ac97Function::Output => mixer.get_sample_rate().into(),
            _ => INPUT_SAMPLE_RATE,
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
        let stream = self
            .audio_server
            .new_stream(
                direction,
                num_channels,
                SampleFormat::S16LE,
                sample_rate,
                buffer_frames,
                &Self::stream_effects(func),
                self.mem
                    .offset_region(starting_offsets[0])
                    .map_err(|e| {
                        AudioError::GuestRegion(GuestMemoryError::ReadingGuestBufferAddress(e))
                    })?
                    .inner(),
                starting_offsets,
            )
            .map_err(AudioError::CreateStream)?;

        let params = AudioWorkerParams {
            func,
            stream,
            pending_buffers,
            message_interval: Duration::from_secs_f64(buffer_frames as f64 / sample_rate as f64),
        };
        Ok(AudioWorker::new(&self, params))
    }

    fn thread_info(&self, func: Ac97Function) -> &AudioThreadInfo {
        match func {
            Ac97Function::Microphone => &self.pmic_info,
            Ac97Function::Input => &self.pi_info,
            Ac97Function::Output => &self.po_info,
        }
    }

    fn thread_info_mut(&mut self, func: Ac97Function) -> &mut AudioThreadInfo {
        match func {
            Ac97Function::Microphone => &mut self.pmic_info,
            Ac97Function::Input => &mut self.pi_info,
            Ac97Function::Output => &mut self.po_info,
        }
    }

    fn is_audio_running(&self) -> bool {
        self.thread_info(Ac97Function::Output).is_running()
            || self.thread_info(Ac97Function::Input).is_running()
            || self.thread_info(Ac97Function::Microphone).is_running()
    }

    fn start_audio(&mut self, func: Ac97Function, mixer: &Ac97Mixer) -> AudioResult<()> {
        let audio_worker = self.create_audio_worker(mixer, func)?;
        self.thread_info_mut(func).start(audio_worker);
        self.update_mixer_settings(mixer);
        Ok(())
    }

    fn stop_all_audio(&mut self) {
        self.thread_info_mut(Ac97Function::Input).stop();
        self.thread_info_mut(Ac97Function::Output).stop();
        self.thread_info_mut(Ac97Function::Microphone).stop();
    }

    // Helper function for resetting function registers.
    fn reset_func_regs(regs: &mut Ac97BusMasterRegs, func: Ac97Function) {
        regs.func_regs_mut(func).do_reset();
        update_sr(regs, func, SR_DCH);
    }

    fn reset_audio_regs(&mut self) {
        self.stop_all_audio();
        let mut regs = self.regs.lock();
        Self::reset_func_regs(&mut regs, Ac97Function::Input);
        Self::reset_func_regs(&mut regs, Ac97Function::Output);
        Self::reset_func_regs(&mut regs, Ac97Function::Microphone);
    }
}

#[derive(Debug)]
struct GuestBuffer {
    index: u8,
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

fn get_buffer_samples(
    func_regs: &Ac97FunctionRegs,
    mem: &GuestMemory,
    index: u8,
) -> GuestMemoryResult<usize> {
    let descriptor_addr = func_regs.bdbar + u32::from(index) * DESCRIPTOR_LENGTH as u32;
    let control_reg: u32 = mem
        .read_obj_from_addr(GuestAddress(u64::from(descriptor_addr) + 4))
        .map_err(GuestMemoryError::ReadingGuestBufferAddress)?;
    let buffer_samples = control_reg as usize & 0x0000_ffff;
    Ok(buffer_samples)
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

    Ok(Some(GuestBuffer {
        index,
        offset,
        frames,
    }))
}

// Marks the current buffer completed and moves to the next buffer for the given
// function and registers.
fn buffer_completed(
    regs: &mut Ac97BusMasterRegs,
    mem: &GuestMemory,
    func: Ac97Function,
) -> AudioResult<()> {
    // check if the completed descriptor wanted an interrupt on completion.
    let civ = regs.func_regs(func).civ;
    let descriptor_addr = regs.func_regs(func).bdbar + u32::from(civ) * DESCRIPTOR_LENGTH as u32;
    let control_reg: u32 = mem
        .read_obj_from_addr(GuestAddress(u64::from(descriptor_addr) + 4))
        .map_err(GuestMemoryError::ReadingGuestBufferAddress)?;

    let mut new_sr = regs.func_regs(func).sr & !SR_CELV;
    if control_reg & BD_IOC != 0 {
        new_sr |= SR_BCIS;
    }

    let lvi = regs.func_regs(func).lvi;
    // if the current buffer was the last valid buffer, then update the status register to
    // indicate that the end of audio was hit and possibly raise an interrupt.
    if civ == lvi {
        new_sr |= SR_DCH | SR_CELV | SR_LVBCI;
    } else {
        regs.func_regs_mut(func).move_to_next_buffer();
    }

    update_sr(regs, func, new_sr);

    regs.func_regs_mut(func).picb = current_buffer_size(regs.func_regs(func), &mem)? as u16;
    if func == Ac97Function::Output {
        regs.po_pointer_update_time = Instant::now();
    }

    Ok(())
}

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

// Update the status register and if any interrupts need to fire, raise them.
fn update_sr(regs: &mut Ac97BusMasterRegs, func: Ac97Function, val: u16) {
    let int_mask = match func {
        Ac97Function::Input => GS_PIINT,
        Ac97Function::Output => GS_POINT,
        Ac97Function::Microphone => GS_MINT,
    };

    let mut interrupt_high = false;

    {
        let func_regs = regs.func_regs_mut(func);
        let old_sr = func_regs.sr;
        func_regs.sr = val;
        if (old_sr ^ val) & SR_INT_MASK != 0 {
            if (val & SR_LVBCI) != 0 && (func_regs.cr & CR_LVBIE) != 0 {
                interrupt_high = true;
            }
            if (val & SR_BCIS) != 0 && (func_regs.cr & CR_IOCE) != 0 {
                interrupt_high = true;
            }
        } else {
            return;
        }
    }

    if interrupt_high {
        regs.glob_sta |= int_mask;
        if let Some(irq_evt) = regs.irq_evt.as_ref() {
            // Ignore write failure, nothing can be done about it from here.
            let _ = irq_evt.write(1);
        }
    } else {
        regs.glob_sta &= !int_mask;
    }
}

// Returns the size in samples of the buffer pointed to by the CIV register.
fn current_buffer_size(
    func_regs: &Ac97FunctionRegs,
    mem: &GuestMemory,
) -> GuestMemoryResult<usize> {
    let civ = func_regs.civ;
    get_buffer_samples(func_regs, mem, civ)
}

#[cfg(test)]
mod test {
    use super::*;

    use audio_streams::shm_streams::MockShmStreamSource;

    #[test]
    fn bm_bdbar() {
        let mut bm = Ac97BusMaster::new(
            GuestMemory::new(&[]).expect("Creating guest memory failed."),
            Box::new(MockShmStreamSource::new()),
        );
        let mut mixer = Ac97Mixer::new();

        let bdbars = [0x00u64, 0x10, 0x20];

        // Make sure writes have no affect during cold reset.
        bm.writel(0x00, 0x5555_555f, &mut mixer);
        assert_eq!(bm.readl(0x00), 0x0000_0000);

        // Relesase cold reset.
        bm.writel(GLOB_CNT_2C, 0x0000_0002, &mut mixer);

        // Tests that the base address is writable and that the bottom three bits are read only.
        for bdbar in &bdbars {
            assert_eq!(bm.readl(*bdbar), 0x0000_0000);
            bm.writel(*bdbar, 0x5555_555f, &mut mixer);
            assert_eq!(bm.readl(*bdbar), 0x5555_5558);
        }
    }

    #[test]
    fn bm_status_reg() {
        let mut bm = Ac97BusMaster::new(
            GuestMemory::new(&[]).expect("Creating guest memory failed."),
            Box::new(MockShmStreamSource::new()),
        );
        let mixer = Ac97Mixer::new();

        let sr_addrs = [0x06u64, 0x16, 0x26];

        for sr in &sr_addrs {
            assert_eq!(bm.readw(*sr, &mixer), 0x0001);
            bm.writew(*sr, 0xffff);
            assert_eq!(bm.readw(*sr, &mixer), 0x0001);
        }
    }

    #[test]
    fn bm_global_control() {
        let mut bm = Ac97BusMaster::new(
            GuestMemory::new(&[]).expect("Creating guest memory failed."),
            Box::new(MockShmStreamSource::new()),
        );
        let mut mixer = Ac97Mixer::new();

        assert_eq!(bm.readl(GLOB_CNT_2C), 0x0000_0000);

        // Relesase cold reset.
        bm.writel(GLOB_CNT_2C, 0x0000_0002, &mut mixer);

        // Check interrupt enable bits are writable.
        bm.writel(GLOB_CNT_2C, 0x0000_0072, &mut mixer);
        assert_eq!(bm.readl(GLOB_CNT_2C), 0x0000_0072);

        // A Warm reset should doesn't affect register state and is auto cleared.
        bm.writel(0x00, 0x5555_5558, &mut mixer);
        bm.writel(GLOB_CNT_2C, 0x0000_0076, &mut mixer);
        assert_eq!(bm.readl(GLOB_CNT_2C), 0x0000_0072);
        assert_eq!(bm.readl(0x00), 0x5555_5558);
        // Check that a cold reset works, but setting bdbar and checking it is zeroed.
        bm.writel(0x00, 0x5555_555f, &mut mixer);
        bm.writel(GLOB_CNT_2C, 0x000_0070, &mut mixer);
        assert_eq!(bm.readl(GLOB_CNT_2C), 0x0000_0070);
        assert_eq!(bm.readl(0x00), 0x0000_0000);
    }

    #[test]
    fn run_multi_tube_playback() {
        start_playback(2, 48000);
        start_playback(4, 48000);
        start_playback(6, 48000);
    }

    #[test]
    fn run_multi_rate_playback() {
        start_playback(2, 32000);
        start_playback(2, 44100);
        start_playback(2, 48000);
    }

    fn start_playback(num_channels: usize, rate: u16) {
        const TIMEOUT: Duration = Duration::from_millis(500);
        const LVI_MASK: u8 = 0x1f; // Five bits for 32 total entries.
        const IOC_MASK: u32 = 0x8000_0000; // Interrupt on completion.
        let num_buffers = LVI_MASK as usize + 1;
        const BUFFER_SIZE: usize = 32768;
        const FRAGMENT_SIZE: usize = BUFFER_SIZE / 2;

        const GUEST_ADDR_BASE: u32 = 0x100_0000;
        let mem = GuestMemory::new(&[(GuestAddress(GUEST_ADDR_BASE as u64), 1024 * 1024 * 1024)])
            .expect("Creating guest memory failed.");
        let stream_source = MockShmStreamSource::new();
        let mut bm = Ac97BusMaster::new(mem.clone(), Box::new(stream_source.clone()));
        let mut mixer = Ac97Mixer::new();

        // Release cold reset.
        bm.writel(GLOB_CNT_2C, 0x0000_0002, &mut mixer);

        // Setup ping-pong buffers. A and B repeating for every possible index.
        bm.writel(PO_BDBAR_10, GUEST_ADDR_BASE, &mut mixer);
        for i in 0..num_buffers {
            let pointer_addr = GuestAddress(GUEST_ADDR_BASE as u64 + i as u64 * 8);
            let control_addr = GuestAddress(GUEST_ADDR_BASE as u64 + i as u64 * 8 + 4);
            if i % 2 == 0 {
                mem.write_obj_at_addr(GUEST_ADDR_BASE, pointer_addr)
                    .expect("Writing guest memory failed.");
            } else {
                mem.write_obj_at_addr(GUEST_ADDR_BASE + FRAGMENT_SIZE as u32, pointer_addr)
                    .expect("Writing guest memory failed.");
            };
            mem.write_obj_at_addr(IOC_MASK | (FRAGMENT_SIZE as u32) / 2, control_addr)
                .expect("Writing guest memory failed.");
        }

        bm.writeb(PO_LVI_15, LVI_MASK, &mixer);
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

        // Buffer complete should be set as the IOC bit was set in the descriptor.
        assert!(bm.readw(PO_SR_16, &mixer) & SR_BCIS != 0);
        // Clear the BCIS bit
        bm.writew(PO_SR_16, SR_BCIS);
        assert!(bm.readw(PO_SR_16, &mixer) & SR_BCIS == 0);

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

        // Clear the LVB bit
        bm.writeb(PO_SR_16, SR_LVBCI as u8, &mixer);
        assert!(bm.readw(PO_SR_16, &mixer) & SR_LVBCI == 0);
        // Reset the LVI to the last buffer and check that playback resumes
        bm.writeb(PO_LVI_15, LVI_MASK, &mixer);
        assert!(bm.readw(PO_SR_16, &mixer) & SR_DCH == 0); // DMA restarts.
        assert_eq!(bm.readw(PO_SR_16, &mixer) & SR_CELV, 0);

        let restart_civ = bm.readb(PO_CIV_14);
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(bm.readb(PO_CIV_14) != restart_civ);

        // Stop.
        bm.writeb(PO_CR_1B, 0, &mixer);
        assert!(bm.readw(PO_SR_16, &mixer) & 0x01 != 0); // DMA is not running.
        bm.writeb(PO_CR_1B, CR_RR, &mixer);
        assert!(
            bm.readl(GLOB_STA_30) & GS_POINT == 0,
            "POINT bit should be disabled."
        );
    }

    #[test]
    fn run_capture() {
        start_capture(Ac97Function::Input);
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
        let mem = GuestMemory::new(&[(GuestAddress(GUEST_ADDR_BASE as u64), 1024 * 1024 * 1024)])
            .expect("Creating guest memory failed.");
        let stream_source = MockShmStreamSource::new();
        let mut bm = Ac97BusMaster::new(mem.clone(), Box::new(stream_source.clone()));
        let mut mixer = Ac97Mixer::new();

        let (bdbar_addr, lvi_addr, cr_addr, civ_addr, pcib_addr, sr_addr, int_mask) = match func {
            Ac97Function::Input => (
                PI_BDBAR_00,
                PI_LVI_05,
                PI_CR_0B,
                PI_CIV_04,
                PI_PICB_08,
                PI_SR_06,
                GS_PIINT,
            ),
            Ac97Function::Microphone => (
                MC_BDBAR_20,
                MC_LVI_25,
                MC_CR_2B,
                MC_CIV_24,
                MC_PICB_28,
                MC_SR_26,
                GS_MINT,
            ),
            _ => {
                assert!(false, "Invalid Ac97Function.");
                (0, 0, 0, 0, 0, 0, 0)
            }
        };

        // Release cold reset.
        bm.writel(GLOB_CNT_2C, 0x0000_0002, &mut mixer);

        // Setup ping-pong buffers.
        bm.writel(bdbar_addr, GUEST_ADDR_BASE, &mut mixer);
        for i in 0..num_buffers {
            let pointer_addr = GuestAddress(GUEST_ADDR_BASE as u64 + i as u64 * 8);
            let control_addr = GuestAddress(GUEST_ADDR_BASE as u64 + i as u64 * 8 + 4);
            mem.write_obj_at_addr(GUEST_ADDR_BASE + FRAGMENT_SIZE as u32, pointer_addr)
                .expect("Writing guest memory failed.");
            mem.write_obj_at_addr(IOC_MASK | (FRAGMENT_SIZE as u32) / 2, control_addr)
                .expect("Writing guest memory failed.");
        }

        bm.writeb(lvi_addr, LVI_MASK, &mixer);

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

        // Clear the LVB bit
        bm.writeb(sr_addr, SR_LVBCI as u8, &mixer);
        assert!(bm.readw(sr_addr, &mixer) & SR_LVBCI == 0);
        // Reset the LVI to the last buffer and check that playback resumes
        bm.writeb(lvi_addr, LVI_MASK, &mixer);
        assert!(bm.readw(sr_addr, &mixer) & SR_DCH == 0); // DMA restarts.
        assert_eq!(bm.readw(sr_addr, &mixer) & SR_CELV, 0);

        let restart_civ = bm.readb(civ_addr);
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert!(stream.trigger_callback_with_timeout(TIMEOUT));
        assert_ne!(bm.readb(civ_addr), restart_civ);

        // Stop.
        bm.writeb(cr_addr, 0, &mixer);
        assert!(bm.readw(sr_addr, &mixer) & 0x01 != 0); // DMA is not running.
        bm.writeb(cr_addr, CR_RR, &mixer);
        assert!(
            bm.readl(GLOB_STA_30) & int_mask == 0,
            "int_mask bit should be disabled."
        );
    }
}
