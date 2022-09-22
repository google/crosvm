// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod sys;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use audio_streams::StreamControl;
use base::error;
use base::warn;
use remain::sorted;
use sync::Condvar;
use sync::Mutex;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::pci::ac97::sys::AudioStreamSource;
use crate::pci::ac97_bus_master::sys::Ac97BusMasterSys;
pub(crate) use crate::pci::ac97_bus_master::sys::AudioError;
use crate::pci::ac97_mixer::Ac97Mixer;
use crate::pci::ac97_regs::*;
use crate::IrqLevelEvent;

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
    irq_evt: Option<IrqLevelEvent>,
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
#[sorted]
#[derive(Error, Debug)]
pub(crate) enum GuestMemoryError {
    // Failure getting the address of the audio buffer.
    #[error("Failed to get the address of the audio buffer: {0}.")]
    ReadingGuestBufferAddress(vm_memory::GuestMemoryError),
}

impl From<GuestMemoryError> for AudioError {
    fn from(err: GuestMemoryError) -> Self {
        AudioError::ReadingGuestError(err)
    }
}

type GuestMemoryResult<T> = std::result::Result<T, GuestMemoryError>;

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
    audio_server: AudioStreamSource,

    // Thread for hadlind IRQ resample events from the guest.
    irq_resample_thread: Option<thread::JoinHandle<()>>,
    #[cfg_attr(unix, allow(dead_code))]
    sys: Ac97BusMasterSys,
}

impl Ac97BusMaster {
    /// Provides the events needed to raise interrupts in the guest.
    pub fn set_irq_event(&mut self, irq_evt: IrqLevelEvent) {
        let thread_regs = self.regs.clone();
        self.regs.lock().irq_evt = Some(irq_evt.try_clone().expect("cloning irq_evt failed"));
        self.irq_resample_thread = Some(thread::spawn(move || {
            loop {
                if let Err(e) = irq_evt.get_resample().wait() {
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
                        if let Err(e) = irq_evt.trigger() {
                            error!("Failed to set the irq from the resample thread: {}.", e);
                            break;
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
            #[cfg(unix)]
            Ac97BusMaster::check_and_move_to_next_buffer(func_regs);

            func_regs.sr &= !(SR_DCH | SR_CELV);

            #[cfg(unix)]
            self.thread_semaphore_notify(func);
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

    fn current_sample_rate(&self, func: Ac97Function, mixer: &Ac97Mixer) -> u32 {
        match func {
            Ac97Function::Output => mixer.get_sample_rate().into(),
            _ => INPUT_SAMPLE_RATE,
        }
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

    regs.func_regs_mut(func).picb = current_buffer_size(regs.func_regs(func), mem)? as u16;
    if func == Ac97Function::Output {
        regs.po_pointer_update_time = Instant::now();
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
        if let Some(ref irq_evt) = regs.irq_evt {
            // Ignore write failure, nothing can be done about it from here.
            let _ = irq_evt.trigger();
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
mod tests {

    use super::*;

    #[cfg(unix)]
    fn new_mock_ac97_bus_master() -> Ac97BusMaster {
        Ac97BusMaster::new(
            GuestMemory::new(&[]).expect("Creating guest memory failed."),
            Box::new(audio_streams::shm_streams::MockShmStreamSource::new()),
        )
    }

    #[cfg(windows)]
    fn new_mock_ac97_bus_master() -> Ac97BusMaster {
        let memory_start_addr = GuestAddress(0x0);
        Ac97BusMaster::new(
            GuestMemory::new(&[(memory_start_addr, 0x1000)])
                .expect("Creating guest memory failed."),
            Arc::new(Mutex::new(audio_streams::NoopStreamSource::new())),
            None,
        )
    }

    #[test]
    fn bm_bdbar() {
        let mut bm = new_mock_ac97_bus_master();
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
        let mut bm = new_mock_ac97_bus_master();
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
        let mut bm = new_mock_ac97_bus_master();
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

    pub(super) fn playback_release_cold_reset_and_setup_ping_pong_buffers(
        bdbar: u64,
        mixer: &mut Ac97Mixer,
        bm: &mut Ac97BusMaster,
        mem: &GuestMemory,
        num_buffers: usize,
        guest_addr_base: u32,
        fragment_size: usize,
        lvi_mask: u8,
        ioc_mask: u32,
    ) {
        // Release cold reset.
        bm.writel(GLOB_CNT_2C, 0x0000_0002, mixer);
        // Setup ping-pong buffers. A and B repeating for every possible index.
        bm.writel(bdbar, guest_addr_base, mixer);
        for i in 0..num_buffers {
            let pointer_addr = GuestAddress(guest_addr_base as u64 + i as u64 * 8);
            let control_addr = GuestAddress(guest_addr_base as u64 + i as u64 * 8 + 4);
            if i % 2 == 0 {
                mem.write_obj_at_addr(guest_addr_base, pointer_addr)
                    .expect("Writing guest memory failed.");
            } else {
                mem.write_obj_at_addr(guest_addr_base + fragment_size as u32, pointer_addr)
                    .expect("Writing guest memory failed.");
            };
            mem.write_obj_at_addr(ioc_mask | ((fragment_size as u32) / 2), control_addr)
                .expect("Writing guest memory failed.");
        }
        bm.writeb(bdbar + LVI_OFFSET, lvi_mask, mixer);
    }

    pub(super) fn capture_release_cold_reset_and_setup_ping_pong_buffers(
        base: u64,
        mixer: &mut Ac97Mixer,
        bm: &mut Ac97BusMaster,
        mem: &GuestMemory,
        num_buffers: usize,
        guest_addr_base: u32,
        fragment_size: usize,
        lvi_mask: u8,
        ioc_mask: u32,
    ) {
        // Release cold reset.
        bm.writel(GLOB_CNT_2C, 0x0000_0002, mixer);

        // Setup ping-pong buffers.
        bm.writel(base, guest_addr_base, mixer);
        for i in 0..num_buffers {
            let pointer_addr = GuestAddress(guest_addr_base as u64 + i as u64 * 8);
            let control_addr = GuestAddress(guest_addr_base as u64 + i as u64 * 8 + 4);
            mem.write_obj_at_addr(guest_addr_base + fragment_size as u32, pointer_addr)
                .expect("Writing guest memory failed.");
            mem.write_obj_at_addr(ioc_mask | ((fragment_size as u32) / 2), control_addr)
                .expect("Writing guest memory failed.");
        }

        bm.writeb(base + LVI_OFFSET, lvi_mask, mixer);
    }

    pub(super) fn check_buffer_set_and_clear_bcis(
        base: u64,
        mixer: &Ac97Mixer,
        bm: &mut Ac97BusMaster,
    ) {
        // Buffer complete should be set as the IOC bit was set in the descriptor.
        assert!(bm.readw(base + SR_OFFSET, mixer) & SR_BCIS != 0);
        // Clear the BCIS bit
        bm.writew(base + SR_OFFSET, SR_BCIS);
        assert!(bm.readw(base + SR_OFFSET, mixer) & SR_BCIS == 0);
    }

    pub(super) fn clear_lvb_and_reset_lvi(
        base: u64,
        mixer: &Ac97Mixer,
        bm: &mut Ac97BusMaster,
        lvi_mask: u8,
    ) {
        // Clear the LVB bit
        bm.writeb(base + SR_OFFSET, SR_LVBCI as u8, mixer);
        assert!(bm.readw(base + SR_OFFSET, mixer) & SR_LVBCI == 0);
        // Reset the LVI to the last buffer and check that playback resumes
        bm.writeb(base + LVI_OFFSET, lvi_mask, mixer);
        assert!(bm.readw(base + SR_OFFSET, mixer) & SR_DCH == 0); // DMA restarts.
        assert_eq!(bm.readw(base + SR_OFFSET, mixer) & SR_CELV, 0);
    }

    pub(super) fn stop(base: u64, int_mask: u32, mixer: &Ac97Mixer, bm: &mut Ac97BusMaster) {
        // Stop.
        bm.writeb(base + CR_OFFSET, 0, mixer);
        assert!(bm.readw(base + SR_OFFSET, mixer) & 0x01 != 0); // DMA is not running.
        bm.writeb(base + CR_OFFSET, CR_RR, mixer);
        assert!(
            bm.readl(GLOB_STA_30) & int_mask == 0,
            "POINT bit should be disabled."
        );
    }
}
