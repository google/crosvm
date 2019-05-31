// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::error::Error;
use std::fmt::{self, Display};
use std::io::Write;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use audio_streams::{
    capture::{CaptureBuffer, CaptureBufferStream},
    PlaybackBuffer, PlaybackBufferStream, StreamControl, StreamSource,
};
use data_model::{VolatileMemory, VolatileSlice};
use sync::Mutex;
use sys_util::{
    self, error, set_rt_prio_limit, set_rt_round_robin, warn, EventFd, GuestAddress, GuestMemory,
};

use crate::pci::ac97_mixer::Ac97Mixer;
use crate::pci::ac97_regs::*;

const DEVICE_SAMPLE_RATE: usize = 48000;

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
    irq_evt: Option<EventFd>,
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
}

// Internal error type used for reporting errors from guest memory reading.
#[derive(Debug)]
enum GuestMemoryError {
    // Failure getting the address of the audio buffer.
    ReadingGuestBufferAddress(sys_util::GuestMemoryError),
    // Failure reading samples from guest memory.
    ReadingGuestSamples(data_model::VolatileMemoryError),
}

impl std::error::Error for GuestMemoryError {}

impl Display for GuestMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::GuestMemoryError::*;

        match self {
            ReadingGuestBufferAddress(e) => {
                write!(f, "Failed to get the address of the audio buffer: {}.", e)
            }
            ReadingGuestSamples(e) => write!(f, "Failed to read samples from guest memory: {}.", e),
        }
    }
}

impl From<GuestMemoryError> for PlaybackError {
    fn from(err: GuestMemoryError) -> Self {
        PlaybackError::ReadingGuestError(err)
    }
}

impl From<GuestMemoryError> for CaptureError {
    fn from(err: GuestMemoryError) -> Self {
        CaptureError::ReadingGuestError(err)
    }
}

type GuestMemoryResult<T> = std::result::Result<T, GuestMemoryError>;

// Internal error type used for reporting errors from the audio playback thread.
#[derive(Debug)]
enum PlaybackError {
    // Failure to read guest memory.
    ReadingGuestError(GuestMemoryError),
    // Failure to get an buffer from the stream.
    StreamError(Box<dyn Error>),
    // Failure writing to the audio output.
    WritingOutput(std::io::Error),
}

impl std::error::Error for PlaybackError {}

impl Display for PlaybackError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::PlaybackError::*;

        match self {
            ReadingGuestError(e) => write!(f, "Failed to read guest memory: {}.", e),
            StreamError(e) => write!(f, "Failed to get a buffer from the stream: {}", e),
            WritingOutput(e) => write!(f, "Failed to write audio output: {}.", e),
        }
    }
}

type PlaybackResult<T> = std::result::Result<T, PlaybackError>;

// Internal error type used for reporting errors from the audio capture thread.
#[derive(Debug)]
enum CaptureError {
    // Failure to read guest memory.
    ReadingGuestError(GuestMemoryError),
    // Failure to get an buffer from the stream.
    StreamError(Box<dyn Error>),
}

impl std::error::Error for CaptureError {}

impl Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::CaptureError::*;

        match self {
            ReadingGuestError(e) => write!(f, "Failed to read guest memory: {}.", e),
            StreamError(e) => write!(f, "Failed to get a buffer from the stream: {}", e),
        }
    }
}

type CaptureResult<T> = std::result::Result<T, CaptureError>;

/// `Ac97BusMaster` emulates the bus master portion of AC97. It exposes a register read/write
/// interface compliant with the ICH bus master.
pub struct Ac97BusMaster {
    // Keep guest memory as each function will use it for buffer descriptors.
    mem: GuestMemory,
    regs: Arc<Mutex<Ac97BusMasterRegs>>,
    acc_sema: u8,

    // Audio thread for capture stream.
    audio_thread_pi: Option<thread::JoinHandle<()>>,
    audio_thread_pi_run: Arc<AtomicBool>,
    pi_stream_control: Option<Box<dyn StreamControl>>,

    // Audio thread book keeping.
    audio_thread_po: Option<thread::JoinHandle<()>>,
    audio_thread_po_run: Arc<AtomicBool>,
    po_stream_control: Option<Box<dyn StreamControl>>,

    // Audio server used to create playback or capture streams.
    audio_server: Box<dyn StreamSource>,

    // Thread for hadlind IRQ resample events from the guest.
    irq_resample_thread: Option<thread::JoinHandle<()>>,
}

impl Ac97BusMaster {
    /// Creates an Ac97BusMaster` object that plays audio from `mem` to streams provided by
    /// `audio_server`.
    pub fn new(mem: GuestMemory, audio_server: Box<dyn StreamSource>) -> Self {
        Ac97BusMaster {
            mem,
            regs: Arc::new(Mutex::new(Ac97BusMasterRegs::new())),
            acc_sema: 0,

            audio_thread_pi: None,
            audio_thread_pi_run: Arc::new(AtomicBool::new(false)),
            pi_stream_control: None,

            audio_thread_po: None,
            audio_thread_po_run: Arc::new(AtomicBool::new(false)),
            po_stream_control: None,

            audio_server,

            irq_resample_thread: None,
        }
    }

    /// Returns any file descriptors that need to be kept open when entering a jail.
    pub fn keep_fds(&self) -> Option<Vec<RawFd>> {
        self.audio_server.keep_fds()
    }

    /// Provides the events needed to raise interrupts in the guest.
    pub fn set_irq_event_fd(&mut self, irq_evt: EventFd, irq_resample_evt: EventFd) {
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
                    // Check output irq
                    let po_int_mask = regs.func_regs(Ac97Function::Output).int_mask();
                    if regs.func_regs(Ac97Function::Output).sr & po_int_mask != 0 {
                        if let Some(irq_evt) = regs.irq_evt.as_ref() {
                            if let Err(e) = irq_evt.write(1) {
                                error!("Failed to set the irq from the resample thread: {}.", e);
                                break;
                            }
                        }
                    }
                    // Check input irq
                    let pi_int_mask = regs.func_regs(Ac97Function::Input).int_mask();
                    if regs.func_regs(Ac97Function::Input).sr & pi_int_mask != 0 {
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
        if let Some(control) = self.po_stream_control.as_mut() {
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
            PI_BASE_00...PI_CR_0B => readb_func_regs(&regs.pi_regs, offset - PI_BASE_00),
            PO_BASE_10...PO_CR_1B => readb_func_regs(&regs.po_regs, offset - PO_BASE_10),
            MC_BASE_20...MC_CR_2B => readb_func_regs(&regs.mc_regs, offset - MC_BASE_20),
            ACC_SEMA_34 => self.acc_sema,
            _ => 0,
        }
    }

    /// Reads a word from the given `offset`.
    pub fn readw(&mut self, offset: u64) -> u16 {
        let regs = self.regs.lock();
        match offset {
            PI_SR_06 => regs.pi_regs.sr,
            PI_PICB_08 => regs.pi_regs.picb,
            PO_SR_16 => regs.po_regs.sr,
            PO_PICB_18 => {
                // PO PICB
                if !self.audio_thread_po_run.load(Ordering::Relaxed) {
                    // Not running, no need to estimate what has been consumed.
                    regs.po_regs.picb
                } else {
                    // Estimate how many samples have been played since the last audio callback.
                    let num_channels = 2;
                    let micros = regs.po_pointer_update_time.elapsed().subsec_micros();
                    // Round down to the next 10 millisecond boundary. The linux driver often
                    // assumes that two rapid reads from picb will return the same value.
                    let millis = micros / 1000 / 10 * 10;

                    let frames_consumed = DEVICE_SAMPLE_RATE as u64 * u64::from(millis) / 1000;

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
    pub fn writel(&mut self, offset: u64, val: u32) {
        // Only process writes to the control register when cold reset is set.
        if self.is_cold_reset() && offset != 0x2c {
            return;
        }
        match offset {
            PI_BDBAR_00 => self.set_bdbar(Ac97Function::Input, val),
            PO_BDBAR_10 => self.set_bdbar(Ac97Function::Output, val),
            MC_BDBAR_20 => self.set_bdbar(Ac97Function::Microphone, val),
            GLOB_CNT_2C => self.set_glob_cnt(val),
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
            func_regs.sr &= !SR_DCH;
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
            self.stop_audio(func);
            let mut regs = self.regs.lock();
            regs.func_regs_mut(func).do_reset();
        } else {
            let cr = self.regs.lock().func_regs(func).cr;
            if val & CR_RPBM == 0 {
                // Run/Pause set to pause.
                self.stop_audio(func);
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
                if self.start_audio(func, mixer).is_err() {
                    warn!("Failed to start audio");
                }
            }
            let mut regs = self.regs.lock();
            regs.func_regs_mut(func).cr = val & CR_VALID_MASK;
        }
    }

    fn set_glob_cnt(&mut self, new_glob_cnt: u32) {
        // Only the reset bits are emulated, the GPI and PCM formatting are not supported.
        if new_glob_cnt & GLOB_CNT_COLD_RESET == 0 {
            self.reset_audio_regs();

            let mut regs = self.regs.lock();
            regs.glob_cnt = new_glob_cnt & GLOB_CNT_STABLE_BITS;
            self.acc_sema = 0;
            return;
        }
        if new_glob_cnt & GLOB_CNT_WARM_RESET != 0 {
            // Check if running and if so, ignore. Warm reset is specified to no-op when the device
            // is playing or recording audio.
            if !self.audio_thread_po_run.load(Ordering::Relaxed) {
                self.stop_all_audio();
                let mut regs = self.regs.lock();
                regs.glob_cnt = new_glob_cnt & !GLOB_CNT_WARM_RESET; // Auto-cleared reset bit.
                return;
            }
        }
        self.regs.lock().glob_cnt = new_glob_cnt;
    }

    fn start_audio(&mut self, func: Ac97Function, mixer: &Ac97Mixer) -> Result<(), Box<dyn Error>> {
        const AUDIO_THREAD_RTPRIO: u16 = 12; // Matches other cros audio clients.

        match func {
            Ac97Function::Input => {
                let num_channels = 2;
                let buffer_samples =
                    current_buffer_size(self.regs.lock().func_regs(func), &self.mem)?;
                let buffer_frames = buffer_samples / num_channels;
                let (stream_control, input_stream) = self.audio_server.new_capture_stream(
                    num_channels,
                    DEVICE_SAMPLE_RATE,
                    buffer_frames,
                )?;
                self.pi_stream_control = Some(stream_control);
                self.update_mixer_settings(mixer);

                self.audio_thread_pi_run.store(true, Ordering::Relaxed);
                let thread_run = self.audio_thread_pi_run.clone();
                let thread_mem = self.mem.clone();
                let thread_regs = self.regs.clone();

                self.audio_thread_pi = Some(thread::spawn(move || {
                    if set_rt_prio_limit(u64::from(AUDIO_THREAD_RTPRIO)).is_err()
                        || set_rt_round_robin(i32::from(AUDIO_THREAD_RTPRIO)).is_err()
                    {
                        warn!("Failed to set audio thread to real time.");
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
                let num_channels = 2;

                let buffer_samples =
                    current_buffer_size(self.regs.lock().func_regs(func), &self.mem)?;

                let buffer_frames = buffer_samples / num_channels;
                let (stream_control, output_stream) = self.audio_server.new_playback_stream(
                    num_channels,
                    DEVICE_SAMPLE_RATE,
                    buffer_frames,
                )?;
                self.po_stream_control = Some(stream_control);

                self.update_mixer_settings(mixer);

                self.audio_thread_po_run.store(true, Ordering::Relaxed);
                let thread_run = self.audio_thread_po_run.clone();
                let thread_mem = self.mem.clone();
                let thread_regs = self.regs.clone();

                self.audio_thread_po = Some(thread::spawn(move || {
                    if set_rt_prio_limit(u64::from(AUDIO_THREAD_RTPRIO)).is_err()
                        || set_rt_round_robin(i32::from(AUDIO_THREAD_RTPRIO)).is_err()
                    {
                        warn!("Failed to set audio thread to real time.");
                    }
                    if let Err(e) =
                        audio_out_thread(thread_regs, thread_mem, &thread_run, output_stream)
                    {
                        error!("Playback error: {}", e);
                    }
                    thread_run.store(false, Ordering::Relaxed);
                }));
            }
            Ac97Function::Microphone => (),
        }
        Ok(())
    }

    fn stop_audio(&mut self, func: Ac97Function) {
        match func {
            Ac97Function::Input => {
                self.audio_thread_pi_run.store(false, Ordering::Relaxed);
                if let Some(thread) = self.audio_thread_pi.take() {
                    if let Err(e) = thread.join() {
                        error!("Failed to join the capture thread: {:?}.", e);
                    }
                }
            }
            Ac97Function::Output => {
                self.audio_thread_po_run.store(false, Ordering::Relaxed);
                if let Some(thread) = self.audio_thread_po.take() {
                    if let Err(e) = thread.join() {
                        error!("Failed to join the playback thread: {:?}.", e);
                    }
                }
            }
            Ac97Function::Microphone => (),
        };
    }

    fn stop_all_audio(&mut self) {
        self.stop_audio(Ac97Function::Input);
        self.stop_audio(Ac97Function::Output);
        self.stop_audio(Ac97Function::Microphone);
    }

    fn reset_audio_regs(&mut self) {
        self.stop_all_audio();
        let mut regs = self.regs.lock();
        regs.pi_regs.do_reset();
        regs.po_regs.do_reset();
        regs.mc_regs.do_reset();
    }
}

// Gets the next buffer from the guest. This will return `None` if the DMA controlled stopped bit is
// set, such as after an underrun where CIV hits LVI.
fn next_guest_buffer<'a>(
    func_regs: &mut Ac97FunctionRegs,
    mem: &'a GuestMemory,
) -> GuestMemoryResult<Option<VolatileSlice<'a>>> {
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
    let read_pos = u64::from(buffer_addr);
    Ok(Some(
        mem.get_slice(read_pos, samples_remaining as u64 * sample_size)
            .map_err(GuestMemoryError::ReadingGuestSamples)?,
    ))
}

// Reads the next buffer from guest memory and writes it to `out_buffer`.
fn play_buffer(
    regs: &mut Ac97BusMasterRegs,
    mem: &GuestMemory,
    out_buffer: &mut PlaybackBuffer,
) -> PlaybackResult<()> {
    // If the current buffer had any samples in it, mark it as done.
    if regs.func_regs_mut(Ac97Function::Output).picb > 0 {
        buffer_completed(regs, mem, Ac97Function::Output)?
    }
    let func_regs = regs.func_regs_mut(Ac97Function::Output);
    let buffer_len = func_regs.picb * 2;
    if let Some(buffer) = next_guest_buffer(func_regs, mem)? {
        out_buffer.copy_cb(buffer.size() as usize, |out| buffer.copy_to(out));
    } else {
        let zeros = vec![0u8; buffer_len as usize];
        out_buffer
            .write(&zeros)
            .map_err(PlaybackError::WritingOutput)?;
    }
    Ok(())
}

// Moves to the next buffer for the given function and registers.
fn buffer_completed(
    regs: &mut Ac97BusMasterRegs,
    mem: &GuestMemory,
    func: Ac97Function,
) -> GuestMemoryResult<()> {
    // check if the completed descriptor wanted an interrupt on completion.
    let civ = regs.func_regs(func).civ;
    let descriptor_addr = regs.func_regs(func).bdbar + u32::from(civ) * DESCRIPTOR_LENGTH as u32;
    let control_reg: u32 = mem
        .read_obj_from_addr(GuestAddress(u64::from(descriptor_addr) + 4))
        .map_err(GuestMemoryError::ReadingGuestBufferAddress)?;

    let mut new_sr = regs.func_regs(func).sr;

    if control_reg & BD_IOC != 0 {
        new_sr |= SR_BCIS;
    }

    let lvi = regs.func_regs(func).lvi;
    // if the current buffer was the last valid buffer, then update the status register to
    // indicate that the end of audio was hit and possibly raise an interrupt.
    if civ == lvi {
        new_sr |= SR_DCH | SR_CELV | SR_LVBCI;
    } else {
        let func_regs = regs.func_regs_mut(func);
        func_regs.civ = func_regs.piv;
        func_regs.piv = (func_regs.piv + 1) % 32; // move piv to the next buffer.
    }

    if new_sr != regs.func_regs(func).sr {
        update_sr(regs, func, new_sr);
    }

    regs.po_pointer_update_time = Instant::now();

    Ok(())
}

// Runs, playing back audio from the guest to `output_stream` until stopped or an error occurs.
fn audio_out_thread(
    regs: Arc<Mutex<Ac97BusMasterRegs>>,
    mem: GuestMemory,
    thread_run: &AtomicBool,
    mut output_stream: Box<dyn PlaybackBufferStream>,
) -> PlaybackResult<()> {
    while thread_run.load(Ordering::Relaxed) {
        output_stream
            .next_playback_buffer()
            .map_err(PlaybackError::StreamError)
            .and_then(|mut pb_buf| play_buffer(&mut regs.lock(), &mem, &mut pb_buf))?;
    }
    Ok(())
}

// Reads samples from `in_buffer` and writes it to the next buffer from guest memory.
fn capture_buffer(
    regs: &mut Ac97BusMasterRegs,
    mem: &GuestMemory,
    in_buffer: &mut CaptureBuffer,
) -> CaptureResult<()> {
    // If the current buffer had any samples in it, mark it as done.
    if regs.func_regs_mut(Ac97Function::Input).picb > 0 {
        buffer_completed(regs, mem, Ac97Function::Input)?
    }
    let func_regs = regs.func_regs_mut(Ac97Function::Input);
    if let Some(buffer) = next_guest_buffer(func_regs, mem)? {
        in_buffer.copy_cb(buffer.size() as usize, |inb| buffer.copy_from(inb))
    }
    Ok(())
}

// Runs, capturing audio from `input_stream` to the guest until stopped or an error occurs.
fn audio_in_thread(
    regs: Arc<Mutex<Ac97BusMasterRegs>>,
    mem: GuestMemory,
    thread_run: &AtomicBool,
    mut input_stream: Box<dyn CaptureBufferStream>,
) -> CaptureResult<()> {
    while thread_run.load(Ordering::Relaxed) {
        input_stream
            .next_capture_buffer()
            .map_err(CaptureError::StreamError)
            .and_then(|mut cp_buf| capture_buffer(&mut regs.lock(), &mem, &mut cp_buf))?;
    }
    Ok(())
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
        func_regs.sr = val;
        if val & SR_INT_MASK != 0 {
            if (val & SR_LVBCI) != 0 && (func_regs.cr & CR_LVBIE) != 0 {
                interrupt_high = true;
            }
            if (val & SR_BCIS) != 0 && (func_regs.cr & CR_IOCE) != 0 {
                interrupt_high = true;
            }
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
        if regs.glob_sta & (GS_PIINT | GS_POINT | GS_MINT) == 0 {
            if let Some(irq_evt) = regs.irq_evt.as_ref() {
                // Ignore write failure, nothing can be done about it from here.
                let _ = irq_evt.write(0);
            }
        }
    }
}

// Returns the size in samples of the buffer pointed to by the CIV register.
fn current_buffer_size(
    func_regs: &Ac97FunctionRegs,
    mem: &GuestMemory,
) -> GuestMemoryResult<usize> {
    let civ = func_regs.civ;
    let descriptor_addr = func_regs.bdbar + u32::from(civ) * DESCRIPTOR_LENGTH as u32;
    let control_reg: u32 = mem
        .read_obj_from_addr(GuestAddress(u64::from(descriptor_addr) + 4))
        .map_err(GuestMemoryError::ReadingGuestBufferAddress)?;
    let buffer_len: usize = control_reg as usize & 0x0000_ffff;
    Ok(buffer_len)
}

#[cfg(test)]
mod test {
    use super::*;

    use std::time;

    use audio_streams::DummyStreamSource;

    #[test]
    fn bm_bdbar() {
        let mut bm = Ac97BusMaster::new(
            GuestMemory::new(&[]).expect("Creating guest memory failed."),
            Box::new(DummyStreamSource::new()),
        );

        let bdbars = [0x00u64, 0x10, 0x20];

        // Make sure writes have no affect during cold reset.
        bm.writel(0x00, 0x5555_555f);
        assert_eq!(bm.readl(0x00), 0x0000_0000);

        // Relesase cold reset.
        bm.writel(GLOB_CNT_2C, 0x0000_0002);

        // Tests that the base address is writable and that the bottom three bits are read only.
        for bdbar in &bdbars {
            assert_eq!(bm.readl(*bdbar), 0x0000_0000);
            bm.writel(*bdbar, 0x5555_555f);
            assert_eq!(bm.readl(*bdbar), 0x5555_5558);
        }
    }

    #[test]
    fn bm_status_reg() {
        let mut bm = Ac97BusMaster::new(
            GuestMemory::new(&[]).expect("Creating guest memory failed."),
            Box::new(DummyStreamSource::new()),
        );

        let sr_addrs = [0x06u64, 0x16, 0x26];

        for sr in &sr_addrs {
            assert_eq!(bm.readw(*sr), 0x0001);
            bm.writew(*sr, 0xffff);
            assert_eq!(bm.readw(*sr), 0x0001);
        }
    }

    #[test]
    fn bm_global_control() {
        let mut bm = Ac97BusMaster::new(
            GuestMemory::new(&[]).expect("Creating guest memory failed."),
            Box::new(DummyStreamSource::new()),
        );

        assert_eq!(bm.readl(GLOB_CNT_2C), 0x0000_0000);

        // Relesase cold reset.
        bm.writel(GLOB_CNT_2C, 0x0000_0002);

        // Check interrupt enable bits are writable.
        bm.writel(GLOB_CNT_2C, 0x0000_0072);
        assert_eq!(bm.readl(GLOB_CNT_2C), 0x0000_0072);

        // A Warm reset should doesn't affect register state and is auto cleared.
        bm.writel(0x00, 0x5555_5558);
        bm.writel(GLOB_CNT_2C, 0x0000_0076);
        assert_eq!(bm.readl(GLOB_CNT_2C), 0x0000_0072);
        assert_eq!(bm.readl(0x00), 0x5555_5558);
        // Check that a cold reset works, but setting bdbar and checking it is zeroed.
        bm.writel(0x00, 0x5555_555f);
        bm.writel(GLOB_CNT_2C, 0x000_0070);
        assert_eq!(bm.readl(GLOB_CNT_2C), 0x0000_0070);
        assert_eq!(bm.readl(0x00), 0x0000_0000);
    }

    #[test]
    fn start_playback() {
        const LVI_MASK: u8 = 0x1f; // Five bits for 32 total entries.
        const IOC_MASK: u32 = 0x8000_0000; // Interrupt on completion.
        let num_buffers = LVI_MASK as usize + 1;
        const BUFFER_SIZE: usize = 32768;
        const FRAGMENT_SIZE: usize = BUFFER_SIZE / 2;

        const GUEST_ADDR_BASE: u32 = 0x100_0000;
        let mem = GuestMemory::new(&[(GuestAddress(GUEST_ADDR_BASE as u64), 1024 * 1024 * 1024)])
            .expect("Creating guest memory failed.");
        let mut bm = Ac97BusMaster::new(mem.clone(), Box::new(DummyStreamSource::new()));
        let mixer = Ac97Mixer::new();

        // Release cold reset.
        bm.writel(GLOB_CNT_2C, 0x0000_0002);

        // Setup ping-pong buffers. A and B repeating for every possible index.
        bm.writel(PO_BDBAR_10, GUEST_ADDR_BASE);
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

        // Start.
        bm.writeb(PO_CR_1B, CR_RPBM, &mixer);

        std::thread::sleep(time::Duration::from_millis(50));
        let picb = bm.readw(PO_PICB_18);
        let mut civ = bm.readb(PO_CIV_14);
        assert_eq!(civ, 0);
        let pos = (FRAGMENT_SIZE - (picb as usize * 2)) / 4;

        // Check that frames are consumed at least at a reasonable rate.
        // This wont be exact as during unit tests the thread scheduling is highly variable, so the
        // test only checks that some samples are consumed.
        assert!(pos > 1000);

        assert!(bm.readw(PO_SR_16) & SR_DCH == 0); // DMA is running.

        // civ should move eventually.
        for _i in 0..30 {
            if civ != 0 {
                break;
            }
            std::thread::sleep(time::Duration::from_millis(20));
            civ = bm.readb(PO_CIV_14);
        }

        assert_ne!(0, civ);

        // Buffer complete should be set as the IOC bit was set in the descriptor.
        assert!(bm.readw(PO_SR_16) & SR_BCIS != 0);
        // Clear the BCIS bit
        bm.writew(PO_SR_16, SR_BCIS);
        assert!(bm.readw(PO_SR_16) & SR_BCIS == 0);

        // Set last valid to the next and wait until it is hit.
        bm.writeb(PO_LVI_15, civ + 1, &mixer);
        std::thread::sleep(time::Duration::from_millis(500));
        assert!(bm.readw(PO_SR_16) & SR_LVBCI != 0); // Hit last buffer
        assert!(bm.readw(PO_SR_16) & SR_DCH == SR_DCH); // DMA stopped because of lack of buffers.
        assert_eq!(bm.readb(PO_LVI_15), bm.readb(PO_CIV_14));
        // Clear the LVB bit
        bm.writeb(PO_SR_16, SR_LVBCI as u8, &mixer);
        assert!(bm.readw(PO_SR_16) & SR_LVBCI == 0);
        // Reset the LVI to the last buffer and check that playback resumes
        bm.writeb(PO_LVI_15, LVI_MASK, &mixer);
        assert!(bm.readw(PO_SR_16) & SR_DCH == 0); // DMA restarts.

        let (restart_civ, restart_picb) = (bm.readb(PO_CIV_14), bm.readw(PO_PICB_18));
        std::thread::sleep(time::Duration::from_millis(20));
        assert!(bm.readw(PO_PICB_18) != restart_picb || bm.readb(PO_CIV_14) != restart_civ);

        // Stop.
        bm.writeb(PO_CR_1B, 0, &mixer);
        assert!(bm.readw(PO_SR_16) & 0x01 != 0); // DMA is not running.
    }

    #[test]
    fn start_capture() {
        const LVI_MASK: u8 = 0x1f; // Five bits for 32 total entries.
        const IOC_MASK: u32 = 0x8000_0000; // Interrupt on completion.
        let num_buffers = LVI_MASK as usize + 1;
        const BUFFER_SIZE: usize = 32768;
        const FRAGMENT_SIZE: usize = BUFFER_SIZE / 2;

        const GUEST_ADDR_BASE: u32 = 0x100_0000;
        let mem = GuestMemory::new(&[(GuestAddress(GUEST_ADDR_BASE as u64), 1024 * 1024 * 1024)])
            .expect("Creating guest memory failed.");
        let mut bm = Ac97BusMaster::new(mem.clone(), Box::new(DummyStreamSource::new()));
        let mixer = Ac97Mixer::new();

        // Release cold reset.
        bm.writel(GLOB_CNT_2C, 0x0000_0002);

        // Setup ping-pong buffers.
        bm.writel(PI_BDBAR_00, GUEST_ADDR_BASE);
        for i in 0..num_buffers {
            let pointer_addr = GuestAddress(GUEST_ADDR_BASE as u64 + i as u64 * 8);
            let control_addr = GuestAddress(GUEST_ADDR_BASE as u64 + i as u64 * 8 + 4);
            mem.write_obj_at_addr(GUEST_ADDR_BASE + FRAGMENT_SIZE as u32, pointer_addr)
                .expect("Writing guest memory failed.");
            mem.write_obj_at_addr(IOC_MASK | (FRAGMENT_SIZE as u32) / 2, control_addr)
                .expect("Writing guest memory failed.");
        }

        bm.writeb(PI_LVI_05, LVI_MASK, &mixer);

        // Start.
        bm.writeb(PI_CR_0B, CR_RPBM, &mixer);
        assert_eq!(bm.readw(PI_PICB_08), 0);

        std::thread::sleep(time::Duration::from_millis(50));
        let picb = bm.readw(PI_PICB_08);
        assert!(picb > 1000);
        assert!(bm.readw(PI_SR_06) & SR_DCH == 0); // DMA is running.

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
        assert_ne!(bm.readw(PI_SR_06) & SR_LVBCI, 0); // Hit last buffer
        assert_eq!(bm.readw(PI_SR_06) & SR_DCH, SR_DCH); // DMA stopped because of lack of buffers.
        assert_eq!(bm.readb(PI_LVI_05), bm.readb(PI_CIV_04));

        // Clear the LVB bit
        bm.writeb(PI_SR_06, SR_LVBCI as u8, &mixer);
        assert!(bm.readw(PI_SR_06) & SR_LVBCI == 0);
        // Reset the LVI to the last buffer and check that playback resumes
        bm.writeb(PI_LVI_05, LVI_MASK, &mixer);
        assert!(bm.readw(PI_SR_06) & SR_DCH == 0); // DMA restarts.

        let restart_civ = bm.readb(PI_CIV_04);
        std::thread::sleep(time::Duration::from_millis(200));
        assert_ne!(bm.readb(PI_CIV_04), restart_civ);

        // Stop.
        bm.writeb(PI_CR_0B, 0, &mixer);
        assert!(bm.readw(PI_SR_06) & 0x01 != 0); // DMA is not running.
    }
}
