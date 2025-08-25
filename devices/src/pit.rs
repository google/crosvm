// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Based heavily on GCE VMM's pit.cc.

use std::io::Error as IoError;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use base::error;
use base::warn;
use base::Descriptor;
use base::Error as SysError;
use base::Event;
use base::EventToken;
use base::WaitContext;
use bit_field::BitField1;
use bit_field::*;
use hypervisor::PitChannelState;
use hypervisor::PitRWMode;
use hypervisor::PitRWState;
use hypervisor::PitState;
use remain::sorted;
use sync::Mutex;
use thiserror::Error;

cfg_if::cfg_if! {
    if #[cfg(test)] {
        use base::FakeClock as Clock;
        use base::FakeTimer as Timer;
    } else {
        use base::Clock;
        use base::Timer;
    }
}
use base::TimerTrait;
use base::WorkerThread;
use snapshot::AnySnapshot;

use crate::bus::BusAccessInfo;
use crate::pci::CrosvmDeviceId;
use crate::BusDevice;
use crate::DeviceId;
use crate::IrqEdgeEvent;
use crate::Suspendable;

// Bitmask for areas of standard (non-ReadBack) Control Word Format. Constant
// names are kept the same as Intel PIT data sheet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, enumn::N)]
enum CommandBit {
    CommandBCD = 0x01,  // Binary/BCD input. x86 only uses binary mode.
    CommandMode = 0x0e, // Operating Mode (mode 0-5).
    CommandRW = 0x30,   // Access mode: Choose high/low byte(s) to Read/Write.
    CommandSC = 0xc0,   // Select Counter/Read-back command.
}

// Selects which counter is to be used by the associated command in the lower
// six bits of the byte. However, if 0xc0 is specified, it indicates that the
// command is a "Read-Back", which can latch count and/or status of the
// counters selected in the lower bits. See Intel 8254 data sheet for details.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, enumn::N)]
enum CommandCounter {
    CommandCounter0 = 0x00, // Select counter 0.
    CommandCounter1 = 0x40, // Select counter 1.
    CommandCounter2 = 0x80, // Select counter 2.
    CommandReadBack = 0xc0, // Execute Read-Back.
}

// Used for both CommandRW and ReadBackAccess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, enumn::N)]
enum CommandAccess {
    CommandLatch = 0x00,   // Latch specified counter.
    CommandRWLeast = 0x10, // Read/Write least significant byte.
    CommandRWMost = 0x20,  // Read/Write most significant byte.
    CommandRWBoth = 0x30,  // Read/Write both bytes.
}

// Used for both CommandMode and ReadBackMode.
// For mode 2 & 3, bit 3 is don't care bit (does not matter to be 0 or 1) but
// per 8254 spec, should be 0 to insure compatibility with future Intel
// products.
#[derive(Debug, Clone, Copy, PartialEq, Eq, enumn::N)]
enum CommandMode {
    // NOTE:  No h/w modes are currently implemented.
    CommandInterrupt = 0x00,     // Mode 0, interrupt on terminal count.
    CommandHWOneShot = 0x02,     // Mode 1, h/w re-triggerable one-shot.
    CommandRateGen = 0x04,       // Mode 2, rate generator.
    CommandSquareWaveGen = 0x06, // Mode 3, square wave generator.
    CommandSWStrobe = 0x08,      // Mode 4, s/w triggered strobe.
    CommandHWStrobe = 0x0a,      // Mode 5, h/w triggered strobe.
}

// Bitmask for the latch portion of the ReadBack command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, enumn::N)]
#[rustfmt::skip]  // rustfmt mangles comment indentation for trailing line comments.
enum CommandReadBackLatch {
    CommandRBLatchBits = 0x30,   // Mask bits that determine latching.
    CommandRBLatchBoth = 0x00,   // Latch both count and status. This should
                                 // never happen in device, since bit 4 and 5 in
                                 // read back command are inverted.
    CommandRBLatchCount = 0x10,  // Latch count.
    CommandRBLatchStatus = 0x20, // Latch status.
}

// Bitmask for the counter portion of the ReadBack command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, enumn::N)]
enum CommandReadBackCounters {
    //CommandRBCounters = 0x0e, // Counters for which to provide ReadBack info.
    CommandRBCounter2 = 0x08,
    CommandRBCounter1 = 0x04,
    CommandRBCounter0 = 0x02,
}

// Bitmask for the ReadBack status command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, enumn::N)]
#[rustfmt::skip]  // rustfmt mangles comment indentation for last line of this enum.
enum ReadBackData {
    // Output format for ReadBack command.
    ReadBackOutput = 0x80, // Output pin status.
    ReadBackNullCount = 0x40, // Whether counter has value.
    // ReadBackAccess, ReadBackMode, and ReadBackBCD intentionally omitted.
}

// I/O Port mappings in I/O bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, enumn::N)]
enum PortIOSpace {
    PortCounter0Data = 0x40, // Read/write.
    PortCounter1Data = 0x41, // Read/write.
    PortCounter2Data = 0x42, // Read/write.
    PortCommand = 0x43,      // Write only.
    PortSpeaker = 0x61,      // Read/write.
}

#[bitfield]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SpeakerPortFields {
    // This field is documented in the chipset spec as NMI status and control
    // register.  Bits 2, 3, 6, 7 and low level hardware bits that need no
    // emulation for virtualized environments.  We call it speaker port because
    // kvm, qemu, linux, and plan9 still call it speaker port, even though it
    // has these other uses and is called something differently in the spec.
    gate: BitField1,
    speaker_on: BitField1,
    pic_serr: BitField1,
    iochk_enable: BitField1,
    // This value changes as part of the refresh frequency of the board for
    // piix4, this is about 1/15us.
    refresh_clock: BitField1,
    output: BitField1,
    iochk_nmi: BitField1,
    serr_nmi: BitField1,
}

// PIT frequency (in Hertz). See http://wiki.osdev.org/pit.
const FREQUENCY_HZ: u64 = 1193182;

const NUM_OF_COUNTERS: usize = 3;

const NANOS_PER_SEC: u64 = 1_000_000_000;

const MAX_TIMER_FREQ: u32 = 65536;

#[derive(EventToken)]
enum Token {
    // The timer expired.
    TimerExpire,
    // The parent thread requested an exit.
    Kill,
}

#[sorted]
#[derive(Error, Debug)]
pub enum PitError {
    /// Error while cloning event for worker thread.
    #[error("failed to clone event: {0}")]
    CloneEvent(SysError),
    /// Error while creating event.
    #[error("failed to create event: {0}")]
    CreateEvent(SysError),
    /// Creating WaitContext failed.
    #[error("failed to create poll context: {0}")]
    CreateWaitContext(SysError),
    /// Error while trying to create worker thread.
    #[error("failed to spawn thread: {0}")]
    SpawnThread(IoError),
    /// Error while trying to create timer.
    #[error("failed to create pit counter due to timer fd: {0}")]
    TimerCreateError(SysError),
    /// Error while waiting for events.
    #[error("failed to wait for events: {0}")]
    WaitError(SysError),
}

type PitResult<T> = std::result::Result<T, PitError>;

pub struct Pit {
    // Structs that store each counter's state.
    counters: Vec<Arc<Mutex<PitCounter>>>,
    // Worker thread to update counter 0's state asynchronously. Counter 0 needs to send interrupts
    // when timers expire, so it needs asynchronous updates. All other counters need only update
    // when queried directly by the guest.
    worker_thread: Option<WorkerThread<()>>,
    activated: bool,
}

impl BusDevice for Pit {
    fn debug_label(&self) -> String {
        "userspace PIT".to_string()
    }

    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::Pit.into()
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        self.ensure_started();

        if data.len() != 1 {
            warn!("Bad write size for Pit: {}", data.len());
            return;
        }
        match PortIOSpace::n(info.address as i64) {
            Some(PortIOSpace::PortCounter0Data) => self.counters[0].lock().write_counter(data[0]),
            Some(PortIOSpace::PortCounter1Data) => self.counters[1].lock().write_counter(data[0]),
            Some(PortIOSpace::PortCounter2Data) => self.counters[2].lock().write_counter(data[0]),
            Some(PortIOSpace::PortCommand) => self.command_write(data[0]),
            Some(PortIOSpace::PortSpeaker) => self.counters[2].lock().write_speaker(data[0]),
            None => warn!("PIT: bad write to {}", info),
        }
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        self.ensure_started();

        if data.len() != 1 {
            warn!("Bad read size for Pit: {}", data.len());
            return;
        }
        data[0] = match PortIOSpace::n(info.address as i64) {
            Some(PortIOSpace::PortCounter0Data) => self.counters[0].lock().read_counter(),
            Some(PortIOSpace::PortCounter1Data) => self.counters[1].lock().read_counter(),
            Some(PortIOSpace::PortCounter2Data) => self.counters[2].lock().read_counter(),
            // This should function as a no-op, since the specification doesn't allow the
            // command register to be read. However, software is free to ask for it to
            // to be read.
            Some(PortIOSpace::PortCommand) => {
                warn!("Ignoring read to command reg");
                0
            }
            Some(PortIOSpace::PortSpeaker) => self.counters[2].lock().read_speaker(),
            None => {
                warn!("PIT: bad read from {}", info);
                return;
            }
        };
    }
}

impl Pit {
    pub fn new(interrupt_evt: IrqEdgeEvent, clock: Arc<Mutex<Clock>>) -> PitResult<Pit> {
        let mut counters = Vec::new();
        let mut interrupt = Some(interrupt_evt);
        for i in 0..NUM_OF_COUNTERS {
            let pit_counter = PitCounter::new(i, interrupt, clock.clone())?;
            counters.push(Arc::new(Mutex::new(pit_counter)));
            // pass interrupt IrqFd ONLY to counter 0; the rest do not deliver interrupts.
            interrupt = None;
        }
        // We asssert here because:
        // (a) this code only gets invoked at VM startup
        // (b) the assert is very loud and would be easy to notice in tests
        // (c) if we have the wrong number of counters, something is very wrong with the PIT and it
        // may not make sense to continue operation.
        assert_eq!(counters.len(), NUM_OF_COUNTERS);

        Ok(Pit {
            counters,
            worker_thread: None,
            activated: false,
        })
    }

    fn ensure_started(&mut self) {
        if self.worker_thread.is_some() {
            return;
        }
        if let Err(e) = self.start() {
            error!("failed to start PIT: {}", e);
        }
    }

    fn start(&mut self) -> PitResult<()> {
        let pit_counter = self.counters[0].clone();
        self.worker_thread = Some(WorkerThread::start("pit counter worker", move |kill_evt| {
            if let Err(e) = worker_run(kill_evt, pit_counter) {
                error!("pit worker failed: {e:#}");
            }
        }));
        self.activated = true;
        Ok(())
    }

    fn command_write(&mut self, control_word: u8) {
        let command: u16 = (control_word & CommandBit::CommandSC as u8).into();
        let counter_index: usize = (command >> 6).into();
        if command == (CommandCounter::CommandReadBack as u16) {
            // ReadBack commands can apply to multiple counters.
            if (control_word & (CommandReadBackCounters::CommandRBCounter0 as u8)) != 0 {
                self.counters[0].lock().read_back_command(control_word);
            }
            if (control_word & (CommandReadBackCounters::CommandRBCounter1 as u8)) != 0 {
                self.counters[1].lock().read_back_command(control_word);
            }
            if (control_word & (CommandReadBackCounters::CommandRBCounter2 as u8)) != 0 {
                self.counters[2].lock().read_back_command(control_word);
            }
        } else if (control_word & (CommandBit::CommandRW as u8))
            == (CommandAccess::CommandLatch as u8)
        {
            self.counters[counter_index].lock().latch_counter();
        } else {
            self.counters[counter_index]
                .lock()
                .store_command(control_word);
        }
    }

    pub fn get_pit_state(&self) -> PitState {
        PitState {
            channels: [
                self.counters[0].lock().get_channel_state(),
                self.counters[1].lock().get_channel_state(),
                self.counters[2].lock().get_channel_state(),
            ],
            flags: 0,
        }
    }

    pub fn set_pit_state(&mut self, state: &PitState) {
        self.counters[0]
            .lock()
            .set_channel_state(&state.channels[0]);
        self.counters[1]
            .lock()
            .set_channel_state(&state.channels[1]);
        self.counters[2]
            .lock()
            .set_channel_state(&state.channels[2]);
    }
}

impl Suspendable for Pit {
    fn sleep(&mut self) -> anyhow::Result<()> {
        if let Some(thread) = self.worker_thread.take() {
            thread.stop();
        }
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        if self.activated {
            if let Err(e) = self.start() {
                error!("failed to start PIT: {}", e);
            }
        }
        Ok(())
    }

    /// The PIT is only used in very early boot on x86_64, and snapshots are not
    /// generally taken during that time, so we can safely skip the PIT for now.
    fn snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        AnySnapshot::to_any(())
    }

    /// The PIT is only used in very early boot on x86_64, and snapshots are not
    /// generally taken during that time, so we can safely skip the PIT for now.
    fn restore(&mut self, _data: AnySnapshot) -> anyhow::Result<()> {
        Ok(())
    }
}

// Each instance of this represents one of the PIT counters. They are used to
// implement one-shot and repeating timer alarms. An 8254 has three counters.
struct PitCounter {
    // Event to write when asserting an interrupt.
    interrupt_evt: Option<IrqEdgeEvent>,
    // Stores the value with which the counter was initialized. Counters are 16-
    // bit values with an effective range of 1-65536 (65536 represented by 0).
    reload_value: u16,
    // Stores value when latch was called.
    latched_value: u16,
    // Stores last command from command register.
    command: u8,
    // Stores status from readback command
    status: u8,
    // Stores time of starting timer. Used for calculating remaining count, if an alarm is
    // scheduled.
    start: Option<Instant>,
    // Current time.
    clock: Arc<Mutex<Clock>>,
    // Time when object was created. Used for a 15us counter.
    creation_time: Instant,
    // The number of the counter. The behavior for each counter is slightly different.
    // Note that once a PitCounter is created, this value should never change.
    counter_id: usize,
    // Indicates if the low byte has been written in RWBoth.
    wrote_low_byte: bool,
    // Indicates if the low byte has been read in RWBoth.
    read_low_byte: bool,
    // Indicates whether counter has been latched.
    latched: bool,
    // Indicates whether ReadBack status has been latched.
    status_latched: bool,
    // Only should be used for counter 2. See http://wiki.osdev.org/PIT.
    gate: bool,
    speaker_on: bool,
    // The starting value for the counter.
    count: u32,
    // Indicates whether the current timer is valid.
    timer_valid: bool,
    // Timer to set and receive periodic notifications.
    timer: Box<dyn TimerTrait>,
}

impl Drop for PitCounter {
    fn drop(&mut self) {
        if self.timer_valid {
            // This should not fail - timer.clear() only fails if timerfd_settime fails, which
            // only happens due to invalid arguments or bad file descriptors. The arguments to
            // timerfd_settime are constant, so its arguments won't be invalid, and it manages
            // the file descriptor safely (we don't use the unsafe FromRawDescriptor) so its file
            // descriptor will be valid.
            self.timer.clear().unwrap();
        }
    }
}

fn adjust_count(count: u32) -> u32 {
    // As per spec 0 means max.
    if count == 0 {
        MAX_TIMER_FREQ
    } else {
        count
    }
}

impl PitCounter {
    fn new(
        counter_id: usize,
        interrupt_evt: Option<IrqEdgeEvent>,
        clock: Arc<Mutex<Clock>>,
    ) -> PitResult<PitCounter> {
        #[cfg(not(test))]
        let timer = Timer::new().map_err(PitError::TimerCreateError)?;
        #[cfg(test)]
        let timer = Timer::new(clock.clone());
        Ok(PitCounter {
            interrupt_evt,
            reload_value: 0,
            latched_value: 0,
            command: 0,
            status: 0,
            start: None,
            clock: clock.clone(),
            creation_time: clock.lock().now(),
            counter_id,
            wrote_low_byte: false,
            read_low_byte: false,
            latched: false,
            status_latched: false,
            gate: false,
            speaker_on: false,
            // `count` is undefined in real hardware and can't ever be programmed to 0, so we
            // initialize it to max to prevent a misbehaving guest from triggering a divide by 0.
            count: MAX_TIMER_FREQ,
            timer_valid: false,
            timer: Box::new(timer),
        })
    }

    fn get_channel_state(&self) -> PitChannelState {
        let load_time = match &self.start {
            Some(t) => t.saturating_duration_since(self.creation_time).as_nanos() as u64,
            None => 0,
        };

        let mut state = PitChannelState {
            count: self.count,
            latched_count: self.latched_value,
            status_latched: self.status_latched,
            status: self.status,
            reload_value: self.reload_value,
            mode: (self.command & CommandBit::CommandMode as u8) >> 1,
            bcd: false,
            gate: self.gate,
            count_load_time: load_time,
            rw_mode: PitRWMode::None,
            read_state: PitRWState::None,
            write_state: PitRWState::None,
            count_latched: PitRWState::None,
        };

        match self.get_access_mode() {
            Some(CommandAccess::CommandRWLeast) => {
                // If access mode is least, RWStates are always LSB
                state.rw_mode = PitRWMode::Least;
                state.read_state = PitRWState::LSB;
                state.write_state = PitRWState::LSB;
            }
            Some(CommandAccess::CommandRWMost) => {
                // If access mode is most, RWStates are always MSB
                state.rw_mode = PitRWMode::Most;
                state.read_state = PitRWState::MSB;
                state.write_state = PitRWState::MSB;
            }
            Some(CommandAccess::CommandRWBoth) => {
                state.rw_mode = PitRWMode::Both;
                // read_state depends on whether or not we've read the low byte already
                state.read_state = if self.read_low_byte {
                    PitRWState::Word1
                } else {
                    PitRWState::Word0
                };
                // write_state depends on whether or not we've written the low byte already
                state.write_state = if self.wrote_low_byte {
                    PitRWState::Word1
                } else {
                    PitRWState::Word0
                };
            }
            _ => {}
        };

        // Count_latched should be PitRWSTate::None unless we're latched
        if self.latched {
            state.count_latched = state.read_state;
        }

        state
    }

    fn set_channel_state(&mut self, state: &PitChannelState) {
        self.count = state.count;
        self.latched_value = state.latched_count;
        self.status_latched = state.status_latched;
        self.status = state.status;
        self.reload_value = state.reload_value;

        // the command consists of:
        //  - 1 bcd bit, which we don't care about because we don't support non-binary mode
        //  - 3 mode bits
        //  - 2 access mode bits
        //  - 2 counter select bits, which aren't used by the counter/channel itself
        self.command = (state.mode << 1) | ((state.rw_mode as u8) << 4);
        self.gate = state.gate;
        self.latched = state.count_latched != PitRWState::None;
        self.read_low_byte = state.read_state == PitRWState::Word1;
        self.wrote_low_byte = state.write_state == PitRWState::Word1;

        self.start = self
            .creation_time
            .checked_add(Duration::from_nanos(state.count_load_time));
    }

    fn get_access_mode(&self) -> Option<CommandAccess> {
        CommandAccess::n(self.command & (CommandBit::CommandRW as u8))
    }

    fn get_command_mode(&self) -> Option<CommandMode> {
        CommandMode::n(self.command & CommandBit::CommandMode as u8)
    }

    fn read_counter(&mut self) -> u8 {
        if self.status_latched {
            self.status_latched = false;
            return self.status;
        };
        let data_value: u16 = if self.latched {
            self.latched_value
        } else {
            self.get_read_value()
        };

        let access_mode = self.get_access_mode();
        // Latch may be true without being indicated by the access mode if
        // a ReadBack was issued.
        match (access_mode, self.read_low_byte) {
            (Some(CommandAccess::CommandRWLeast), _) => {
                self.latched = false; // Unlatch if only reading the low byte.
                (data_value & 0xff) as u8
            }
            (Some(CommandAccess::CommandRWBoth), false) => {
                self.read_low_byte = true;
                (data_value & 0xff) as u8
            }
            (Some(CommandAccess::CommandRWBoth), true)
            | (Some(CommandAccess::CommandRWMost), _) => {
                self.read_low_byte = false; // Allow for future reads for RWBoth.
                self.latched = false;
                (data_value >> 8) as u8
            }
            (_, _) => 0, // Default for erroneous call
        }
    }

    fn write_counter(&mut self, written_datum: u8) {
        let access_mode = self.get_access_mode();
        let datum: u16 = written_datum.into();
        let mut should_start_timer = true;
        self.reload_value = match access_mode {
            Some(CommandAccess::CommandRWLeast) => datum,
            Some(CommandAccess::CommandRWMost) => datum << 8,
            Some(CommandAccess::CommandRWBoth) => {
                // In kCommandRWBoth mode, the first guest write is the low byte and the
                // the second guest write is the high byte.  The timer isn't started
                // until after the second byte is written.
                if self.wrote_low_byte {
                    self.wrote_low_byte = false;
                    self.reload_value | (datum << 8)
                } else {
                    self.wrote_low_byte = true;
                    should_start_timer = false; // Don't start until high byte written.
                    datum
                }
            }
            _ => {
                should_start_timer = false;
                self.reload_value
            }
        };
        if should_start_timer {
            let reload: u32 = self.reload_value.into();
            self.load_and_start_timer(reload);
        }
    }

    fn get_output(&self) -> bool {
        let ticks_passed = self.get_ticks_passed();
        let count: u64 = self.count.into();
        match self.get_command_mode() {
            Some(CommandMode::CommandInterrupt) => ticks_passed >= count,
            Some(CommandMode::CommandHWOneShot) => ticks_passed < count,
            Some(CommandMode::CommandRateGen) => ticks_passed != 0 && ticks_passed % count == 0,
            Some(CommandMode::CommandSquareWaveGen) => ticks_passed < (count + 1) / 2,
            Some(CommandMode::CommandSWStrobe) | Some(CommandMode::CommandHWStrobe) => {
                ticks_passed == count
            }
            None => {
                warn!("Invalid command mode based on command: {:#x}", self.command);
                false
            }
        }
    }

    fn read_speaker(&self) -> u8 {
        // Refresh clock is a value independent of the actual
        // counter that goes up and down approx every 15 us (~66000/s).
        let us = self
            .clock
            .lock()
            .now()
            .duration_since(self.creation_time)
            .subsec_micros();
        let refresh_clock = us % 15 == 0;
        let mut speaker = SpeakerPortFields::new();
        speaker.set_gate(self.gate.into());
        speaker.set_speaker_on(self.speaker_on.into());
        speaker.set_iochk_enable(0);
        speaker.set_refresh_clock(refresh_clock.into());
        speaker.set_output(self.get_output().into());
        speaker.set_iochk_nmi(0);
        speaker.set_serr_nmi(0);
        speaker.get(/* offset= */ 0, /* width= */ 8) as u8
    }

    fn write_speaker(&mut self, datum: u8) {
        let mut speaker = SpeakerPortFields::new();
        speaker.set(/* offset= */ 0, /* width= */ 8, datum.into());
        let new_gate = speaker.get_gate() != 0;
        match self.get_command_mode() {
            Some(CommandMode::CommandInterrupt) | Some(CommandMode::CommandSWStrobe) => (),
            Some(_) => {
                if new_gate && !self.gate {
                    self.start = Some(self.clock.lock().now());
                }
            }
            None => {
                warn!("Invalid command mode based on command {:#x}", self.command);
                return;
            }
        }
        self.speaker_on = speaker.get_speaker_on() != 0;
        self.gate = new_gate;
    }

    fn load_and_start_timer(&mut self, initial_count: u32) {
        self.count = adjust_count(initial_count);
        self.start_timer();
    }

    fn start_timer(&mut self) {
        self.start = Some(self.clock.lock().now());

        // Counter 0 is the only counter that generates interrupts, so we
        // don't need to set a timer for the other two counters.
        if self.counter_id != 0 {
            return;
        }

        let timer_len = Duration::from_nanos(u64::from(self.count) * NANOS_PER_SEC / FREQUENCY_HZ);
        let safe_timer_len = if timer_len == Duration::new(0, 0) {
            Duration::from_nanos(1)
        } else {
            timer_len
        };

        match self.get_command_mode() {
            Some(CommandMode::CommandInterrupt)
            | Some(CommandMode::CommandHWOneShot)
            | Some(CommandMode::CommandSWStrobe)
            | Some(CommandMode::CommandHWStrobe) => {
                if let Err(e) = self.timer.reset_oneshot(safe_timer_len) {
                    error!("failed to reset oneshot timer: {}", e);
                }
            }
            Some(CommandMode::CommandRateGen) | Some(CommandMode::CommandSquareWaveGen) => {
                if let Err(e) = self.timer.reset_repeating(safe_timer_len) {
                    error!("failed to reset repeating timer: {}", e);
                }
            }
            // Don't arm timer if invalid mode.
            None => {
                // This will still result in start being set to the current time.
                // Per spec:
                //   A new initial count may be written to a Counter at any time without affecting
                //   the Counter’s programmed Mode in any way. Counting will be affected as
                //   described in the Mode definitions. The new count must follow the programmed
                //   count format
                // It's unclear whether setting `self.start` in this case is entirely compliant,
                // but the spec is fairly quiet on expected behavior in error cases, so OSs
                // shouldn't enter invalid modes in the first place.  If they do, and then try to
                // get out of it by first setting the counter then the command, this behavior will
                // (perhaps) be minimally surprising, but arguments can be made for other behavior.
                // It's uncertain if this behavior matches real PIT hardware.
                warn!("Invalid command mode based on command {:#x}", self.command);
                return;
            }
        }

        self.timer_valid = true;
    }

    fn read_back_command(&mut self, control_word: u8) {
        let latch_cmd =
            CommandReadBackLatch::n(control_word & CommandReadBackLatch::CommandRBLatchBits as u8);
        match latch_cmd {
            Some(CommandReadBackLatch::CommandRBLatchCount) => {
                self.latch_counter();
            }
            Some(CommandReadBackLatch::CommandRBLatchStatus) => {
                self.latch_status();
            }
            _ => warn!(
                "Unexpected ReadBackLatch. control_word: {:#x}",
                control_word
            ),
        };
    }

    fn latch_counter(&mut self) {
        if self.latched {
            return;
        }

        self.latched_value = self.get_read_value();
        self.latched = true;
        self.read_low_byte = false;
    }

    fn latch_status(&mut self) {
        // Including BCD here, even though it currently never gets used.
        self.status = self.command
            & (CommandBit::CommandRW as u8
                | CommandBit::CommandMode as u8
                | CommandBit::CommandBCD as u8);
        if self.start.is_none() {
            self.status |= ReadBackData::ReadBackNullCount as u8;
        }
        if self.get_output() {
            self.status |= ReadBackData::ReadBackOutput as u8;
        }
        self.status_latched = true;
    }

    fn store_command(&mut self, datum: u8) {
        self.command = datum;
        self.latched = false;

        // If a new RW command is written, cancel the current timer.
        if self.timer_valid {
            self.start = None;
            self.timer_valid = false;
            // See the comment in the impl of Drop for PitCounter for justification of the unwrap()
            self.timer.clear().unwrap();
        }

        self.wrote_low_byte = false;
        self.read_low_byte = false;
    }

    fn timer_handler(&mut self) {
        if let Err(e) = self.timer.mark_waited() {
            // Under the current Timer implementation (as of Jan 2019), this failure shouldn't
            // happen but implementation details may change in the future, and the failure
            // cases are complex to reason about. Because of this, avoid unwrap().
            error!("pit: timer wait unexpectedly failed: {}", e);
            return;
        }
        let mode = self.get_command_mode();
        if mode == Some(CommandMode::CommandRateGen)
            || mode == Some(CommandMode::CommandSquareWaveGen)
        {
            // Reset the start time for timer modes that repeat.
            self.start = Some(self.clock.lock().now());
        }

        // For square wave mode, this isn't quite accurate to the spec, but the
        // difference isn't meaningfully visible to the guest in any important way,
        // and the code is simpler without the special case.
        if let Some(interrupt) = &mut self.interrupt_evt {
            // This is safe because the file descriptor is nonblocking and we're writing 1.
            interrupt.trigger().unwrap();
        }
    }

    fn get_ticks_passed(&self) -> u64 {
        match self.start {
            None => 0,
            Some(t) => {
                let dur = self.clock.lock().now().duration_since(t);
                let dur_ns: u64 = dur.as_secs() * NANOS_PER_SEC + u64::from(dur.subsec_nanos());
                dur_ns * FREQUENCY_HZ / NANOS_PER_SEC
            }
        }
    }

    fn get_read_value(&self) -> u16 {
        match self.start {
            None => 0,
            Some(_) => {
                let count: u64 = adjust_count(self.reload_value.into()).into();
                let ticks_passed = self.get_ticks_passed();
                match self.get_command_mode() {
                    Some(CommandMode::CommandInterrupt)
                    | Some(CommandMode::CommandHWOneShot)
                    | Some(CommandMode::CommandSWStrobe)
                    | Some(CommandMode::CommandHWStrobe) => {
                        if ticks_passed > count {
                            // Some risk of raciness here in that the count may return a value
                            // indicating that the count has expired when the interrupt hasn't
                            // yet been injected.
                            0
                        } else {
                            ((count - ticks_passed) & 0xFFFF) as u16
                        }
                    }
                    Some(CommandMode::CommandRateGen) => (count - (ticks_passed % count)) as u16,
                    Some(CommandMode::CommandSquareWaveGen) => {
                        (count - ((ticks_passed * 2) % count)) as u16
                    }
                    None => {
                        warn!("Invalid command mode: command = {:#x}", self.command);
                        0
                    }
                }
            }
        }
    }
}

fn worker_run(kill_evt: Event, pit_counter: Arc<Mutex<PitCounter>>) -> PitResult<()> {
    let timer_descriptor = Descriptor(pit_counter.lock().timer.as_raw_descriptor());
    let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
        (&timer_descriptor, Token::TimerExpire),
        (&kill_evt, Token::Kill),
    ])
    .map_err(PitError::CreateWaitContext)?;

    loop {
        let events = wait_ctx.wait().map_err(PitError::WaitError)?;
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::TimerExpire => {
                    let mut pit = pit_counter.lock();
                    pit.timer_handler();
                }
                Token::Kill => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use base::Event;

    use super::*;

    struct TestData {
        pit: Pit,
        irqfd: Event,
        clock: Arc<Mutex<Clock>>,
    }

    fn pit_bus_address(address: PortIOSpace) -> BusAccessInfo {
        // The PIT is added to the io_bus in two locations, so the offset depends on which
        // address range the address is in. The PIT implementation currently does not use the
        // offset, but we're setting it accurately here in case it does in the future.
        let offset = match address as u64 {
            x if x >= PortIOSpace::PortCounter0Data as u64
                && x < PortIOSpace::PortCounter0Data as u64 + 0x8 =>
            {
                address as u64 - PortIOSpace::PortCounter0Data as u64
            }
            x if x == PortIOSpace::PortSpeaker as u64 => 0,
            _ => panic!("invalid PIT address: {:#x}", address as u64),
        };

        BusAccessInfo {
            offset,
            address: address as u64,
            id: 0,
        }
    }

    /// Utility method for writing a command word to a command register.
    fn write_command(pit: &mut Pit, command: u8) {
        pit.write(pit_bus_address(PortIOSpace::PortCommand), &[command])
    }

    /// Utility method for writing a command word to the speaker register.
    fn write_speaker(pit: &mut Pit, command: u8) {
        pit.write(pit_bus_address(PortIOSpace::PortSpeaker), &[command])
    }

    /// Utility method for writing to a counter.
    fn write_counter(pit: &mut Pit, counter_idx: usize, data: u16, access_mode: CommandAccess) {
        let port = match counter_idx {
            0 => PortIOSpace::PortCounter0Data,
            1 => PortIOSpace::PortCounter1Data,
            2 => PortIOSpace::PortCounter2Data,
            _ => panic!("Invalid counter_idx: {}", counter_idx),
        };
        // Write the least, then the most, significant byte.
        if access_mode == CommandAccess::CommandRWLeast
            || access_mode == CommandAccess::CommandRWBoth
        {
            pit.write(pit_bus_address(port), &[(data & 0xff) as u8]);
        }
        if access_mode == CommandAccess::CommandRWMost
            || access_mode == CommandAccess::CommandRWBoth
        {
            pit.write(pit_bus_address(port), &[(data >> 8) as u8]);
        }
    }

    /// Utility method for reading a counter. Check if the read value matches expected_value.
    fn read_counter(pit: &mut Pit, counter_idx: usize, expected: u16, access_mode: CommandAccess) {
        let port = match counter_idx {
            0 => PortIOSpace::PortCounter0Data,
            1 => PortIOSpace::PortCounter1Data,
            2 => PortIOSpace::PortCounter2Data,
            _ => panic!("Invalid counter_idx: {}", counter_idx),
        };
        let mut result: u16 = 0;
        if access_mode == CommandAccess::CommandRWLeast
            || access_mode == CommandAccess::CommandRWBoth
        {
            let mut buffer = [0];
            pit.read(pit_bus_address(port), &mut buffer);
            result = buffer[0].into();
        }
        if access_mode == CommandAccess::CommandRWMost
            || access_mode == CommandAccess::CommandRWBoth
        {
            let mut buffer = [0];
            pit.read(pit_bus_address(port), &mut buffer);
            result |= u16::from(buffer[0]) << 8;
        }
        assert_eq!(result, expected);
    }

    fn set_up() -> TestData {
        let evt = IrqEdgeEvent::new().unwrap();
        let clock = Arc::new(Mutex::new(Clock::new()));
        TestData {
            irqfd: evt.get_trigger().try_clone().unwrap(),
            pit: Pit::new(evt, clock.clone()).unwrap(),
            clock,
        }
    }

    fn advance_by_tick(data: &mut TestData) {
        advance_by_ticks(data, 1);
    }

    fn advance_by_ticks(data: &mut TestData, ticks: u64) {
        println!(
            "Advancing by {:#x} ticks ({} ns)",
            ticks,
            (NANOS_PER_SEC * ticks) / FREQUENCY_HZ + 1
        );
        let mut lock = data.clock.lock();
        lock.add_ns((NANOS_PER_SEC * ticks) / FREQUENCY_HZ + 1);
    }

    /// Tests the ability to write a command and data and read the data back using latch.
    #[test]
    fn write_and_latch() {
        let mut data = set_up();
        let both_interrupt =
            CommandAccess::CommandRWBoth as u8 | CommandMode::CommandInterrupt as u8;
        // Issue a command to write both digits of counter 0 in interrupt mode.
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8 | both_interrupt,
        );
        write_counter(&mut data.pit, 0, 24, CommandAccess::CommandRWBoth);
        // Advance time by one tick -- value read back should decrease.
        advance_by_tick(&mut data);

        // Latch and read back the value written.
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8 | CommandAccess::CommandLatch as u8,
        );
        // Advance again after latching to verify that value read back doesn't change.
        advance_by_tick(&mut data);
        read_counter(&mut data.pit, 0, 23, CommandAccess::CommandRWBoth);

        // Repeat with counter 1.
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter1 as u8 | both_interrupt,
        );
        write_counter(&mut data.pit, 1, 314, CommandAccess::CommandRWBoth);
        advance_by_tick(&mut data);
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter1 as u8 | CommandAccess::CommandLatch as u8,
        );
        advance_by_tick(&mut data);
        read_counter(&mut data.pit, 1, 313, CommandAccess::CommandRWBoth);

        // Repeat with counter 2.
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter2 as u8 | both_interrupt,
        );
        write_counter(&mut data.pit, 2, 0xffff, CommandAccess::CommandRWBoth);
        advance_by_tick(&mut data);
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter2 as u8 | CommandAccess::CommandLatch as u8,
        );
        advance_by_tick(&mut data);
        read_counter(&mut data.pit, 2, 0xfffe, CommandAccess::CommandRWBoth);
    }

    /// Tests the ability to read only the least significant byte.
    #[test]
    fn write_and_read_least() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8
                | CommandAccess::CommandRWLeast as u8
                | CommandMode::CommandInterrupt as u8,
        );
        write_counter(&mut data.pit, 0, 0x3424, CommandAccess::CommandRWLeast);
        read_counter(&mut data.pit, 0, 0x0024, CommandAccess::CommandRWLeast);
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8 | CommandAccess::CommandLatch as u8,
        );
        advance_by_tick(&mut data);
        read_counter(&mut data.pit, 0, 0x0024, CommandAccess::CommandRWLeast);
    }

    /// Tests the ability to read only the most significant byte.
    #[test]
    fn write_and_read_most() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8
                | CommandAccess::CommandRWMost as u8
                | CommandMode::CommandInterrupt as u8,
        );
        write_counter(&mut data.pit, 0, 0x3424, CommandAccess::CommandRWMost);
        read_counter(&mut data.pit, 0, 0x3400, CommandAccess::CommandRWMost);
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8 | CommandAccess::CommandLatch as u8,
        );
        advance_by_tick(&mut data);
        read_counter(&mut data.pit, 0, 0x3400, CommandAccess::CommandRWMost);
    }

    /// Tests that reading the command register does nothing.
    #[test]
    fn read_command() {
        let mut data = set_up();
        let mut buf = [0];
        data.pit
            .read(pit_bus_address(PortIOSpace::PortCommand), &mut buf);
        assert_eq!(buf, [0]);
    }

    /// Tests that latching prevents the read time from actually advancing.
    #[test]
    fn test_timed_latch() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8
                | CommandAccess::CommandRWBoth as u8
                | CommandMode::CommandInterrupt as u8,
        );
        write_counter(&mut data.pit, 0, 0xffff, CommandAccess::CommandRWBoth);
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8 | CommandAccess::CommandLatch as u8,
        );
        data.clock.lock().add_ns(25_000_000);
        // The counter should ignore this second latch.
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8 | CommandAccess::CommandLatch as u8,
        );
        read_counter(&mut data.pit, 0, 0xffff, CommandAccess::CommandRWBoth);
        // It should, however, store the count for this latch.
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8 | CommandAccess::CommandLatch as u8,
        );
        read_counter(
            &mut data.pit,
            0,
            0xffff - ((25_000_000 * FREQUENCY_HZ) / NANOS_PER_SEC) as u16,
            CommandAccess::CommandRWBoth,
        );
    }

    /// Tests Mode 0 (Interrupt on terminal count); checks whether IRQ has been asserted.
    #[test]
    fn interrupt_mode() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8
                | CommandAccess::CommandRWBoth as u8
                | CommandMode::CommandInterrupt as u8,
        );
        write_counter(&mut data.pit, 0, 0xffff, CommandAccess::CommandRWBoth);
        // Advance clock enough to trigger interrupt.
        advance_by_ticks(&mut data, 0xffff);
        data.irqfd.wait().unwrap();
    }

    /// Tests that Rate Generator mode (mode 2) handls the interrupt properly when the timer
    /// expires and that it resets the timer properly.
    #[test]
    fn rate_gen_mode() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8
                | CommandAccess::CommandRWBoth as u8
                | CommandMode::CommandRateGen as u8,
        );
        write_counter(&mut data.pit, 0, 0xffff, CommandAccess::CommandRWBoth);
        // Repatedly advance clock and expect interrupt.
        advance_by_ticks(&mut data, 0xffff);
        data.irqfd.wait().unwrap();

        // Repatedly advance clock and expect interrupt.
        advance_by_ticks(&mut data, 0xffff);
        data.irqfd.wait().unwrap();

        // Repatedly advance clock and expect interrupt.
        advance_by_ticks(&mut data, 0xffff);
        data.irqfd.wait().unwrap();
    }

    /// Tests that square wave mode advances the counter correctly.
    #[test]
    fn square_wave_counter_read() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8
                | CommandAccess::CommandRWBoth as u8
                | CommandMode::CommandSquareWaveGen as u8,
        );
        write_counter(&mut data.pit, 0, 0xffff, CommandAccess::CommandRWBoth);

        advance_by_ticks(&mut data, 10_000);
        read_counter(
            &mut data.pit,
            0,
            0xffff - 10_000 * 2,
            CommandAccess::CommandRWBoth,
        );
    }

    /// Tests that rategen mode updates the counter correctly.
    #[test]
    fn rate_gen_counter_read() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8
                | CommandAccess::CommandRWBoth as u8
                | CommandMode::CommandRateGen as u8,
        );
        write_counter(&mut data.pit, 0, 0xffff, CommandAccess::CommandRWBoth);

        advance_by_ticks(&mut data, 10_000);
        read_counter(
            &mut data.pit,
            0,
            0xffff - 10_000,
            CommandAccess::CommandRWBoth,
        );
    }

    /// Tests that interrupt counter mode updates the counter correctly.
    #[test]
    fn interrupt_counter_read() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8
                | CommandAccess::CommandRWBoth as u8
                | CommandMode::CommandInterrupt as u8,
        );
        write_counter(&mut data.pit, 0, 0xffff, CommandAccess::CommandRWBoth);

        advance_by_ticks(&mut data, 10_000);
        read_counter(
            &mut data.pit,
            0,
            0xffff - 10_000,
            CommandAccess::CommandRWBoth,
        );

        advance_by_ticks(&mut data, 3 * FREQUENCY_HZ);
        read_counter(&mut data.pit, 0, 0, CommandAccess::CommandRWBoth);
    }

    /// Tests that ReadBack count works properly for `low` access mode.
    #[test]
    fn read_back_count_access_low() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8
                | CommandAccess::CommandRWLeast as u8
                | CommandMode::CommandInterrupt as u8,
        );
        write_counter(&mut data.pit, 0, 0xffff, CommandAccess::CommandRWLeast);
        write_command(
            &mut data.pit,
            CommandCounter::CommandReadBack as u8
                | CommandReadBackLatch::CommandRBLatchCount as u8
                | CommandReadBackCounters::CommandRBCounter0 as u8,
        );

        // Advance 100 ticks and verify that low byte of counter is appropriately updated.
        advance_by_ticks(&mut data, 100);
        write_command(
            &mut data.pit,
            CommandCounter::CommandReadBack as u8
                | CommandReadBackLatch::CommandRBLatchCount as u8
                | CommandReadBackCounters::CommandRBCounter0 as u8,
        );
        read_counter(&mut data.pit, 0, 0x00ff, CommandAccess::CommandRWLeast);
        write_command(
            &mut data.pit,
            CommandCounter::CommandReadBack as u8
                | CommandReadBackLatch::CommandRBLatchCount as u8
                | CommandReadBackCounters::CommandRBCounter0 as u8,
        );
        read_counter(
            &mut data.pit,
            0,
            (0xffff - 100) & 0x00ff,
            CommandAccess::CommandRWLeast,
        );
    }

    /// Tests that ReadBack count works properly for `high` access mode.
    #[test]
    fn read_back_count_access_high() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8
                | CommandAccess::CommandRWMost as u8
                | CommandMode::CommandInterrupt as u8,
        );
        write_counter(&mut data.pit, 0, 0xffff, CommandAccess::CommandRWLeast);
        write_command(
            &mut data.pit,
            CommandCounter::CommandReadBack as u8
                | CommandReadBackLatch::CommandRBLatchCount as u8
                | CommandReadBackCounters::CommandRBCounter0 as u8,
        );

        // Advance 100 ticks and verify that low byte of counter is appropriately updated.
        advance_by_ticks(&mut data, 512);
        write_command(
            &mut data.pit,
            CommandCounter::CommandReadBack as u8
                | CommandReadBackLatch::CommandRBLatchCount as u8
                | CommandReadBackCounters::CommandRBCounter0 as u8,
        );
        read_counter(&mut data.pit, 0, 0xff00, CommandAccess::CommandRWMost);
        write_command(
            &mut data.pit,
            CommandCounter::CommandReadBack as u8
                | CommandReadBackLatch::CommandRBLatchCount as u8
                | CommandReadBackCounters::CommandRBCounter0 as u8,
        );
        read_counter(
            &mut data.pit,
            0,
            (0xffff - 512) & 0xff00,
            CommandAccess::CommandRWMost,
        );
    }

    /// Tests that ReadBack status returns the expected values.
    #[test]
    fn read_back_status() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter0 as u8
                | CommandAccess::CommandRWBoth as u8
                | CommandMode::CommandSWStrobe as u8,
        );
        write_counter(&mut data.pit, 0, 0xffff, CommandAccess::CommandRWBoth);
        write_command(
            &mut data.pit,
            CommandCounter::CommandReadBack as u8
                | CommandReadBackLatch::CommandRBLatchStatus as u8
                | CommandReadBackCounters::CommandRBCounter0 as u8,
        );

        read_counter(
            &mut data.pit,
            0,
            CommandAccess::CommandRWBoth as u16 | CommandMode::CommandSWStrobe as u16,
            CommandAccess::CommandRWLeast,
        );
    }

    #[test]
    fn speaker_square_wave() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter2 as u8
                | CommandAccess::CommandRWBoth as u8
                | CommandMode::CommandSquareWaveGen as u8,
        );
        write_counter(&mut data.pit, 2, 0xffff, CommandAccess::CommandRWBoth);

        advance_by_ticks(&mut data, 128);
        read_counter(
            &mut data.pit,
            2,
            0xffff - 128 * 2,
            CommandAccess::CommandRWBoth,
        );
    }

    #[test]
    fn speaker_rate_gen() {
        let mut data = set_up();
        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter2 as u8
                | CommandAccess::CommandRWBoth as u8
                | CommandMode::CommandRateGen as u8,
        );
        write_counter(&mut data.pit, 2, 0xffff, CommandAccess::CommandRWBoth);

        // In Rate Gen mode, the counter should start over when the gate is
        // set to high using SpeakerWrite.
        advance_by_ticks(&mut data, 128);
        read_counter(&mut data.pit, 2, 0xffff - 128, CommandAccess::CommandRWBoth);

        write_speaker(&mut data.pit, 0x1);
        advance_by_ticks(&mut data, 128);
        read_counter(&mut data.pit, 2, 0xffff - 128, CommandAccess::CommandRWBoth);
    }

    #[test]
    fn speaker_interrupt() {
        let mut data = set_up();

        write_command(
            &mut data.pit,
            CommandCounter::CommandCounter2 as u8
                | CommandAccess::CommandRWBoth as u8
                | CommandMode::CommandInterrupt as u8,
        );
        write_counter(&mut data.pit, 2, 0xffff, CommandAccess::CommandRWBoth);

        // In Interrupt mode, the counter should NOT start over when the gate is
        // set to high using SpeakerWrite.
        advance_by_ticks(&mut data, 128);
        read_counter(&mut data.pit, 2, 0xffff - 128, CommandAccess::CommandRWBoth);

        write_speaker(&mut data.pit, 0x1);
        advance_by_ticks(&mut data, 128);
        read_counter(&mut data.pit, 2, 0xffff - 256, CommandAccess::CommandRWBoth);
    }

    /// Verify that invalid reads and writes do not cause crashes.
    #[test]
    fn invalid_write_and_read() {
        let mut data = set_up();
        data.pit.write(
            BusAccessInfo {
                address: 0x44,
                offset: 0x4,
                id: 0,
            },
            &[0],
        );
        data.pit.read(
            BusAccessInfo {
                address: 0x55,
                offset: 0x15,
                id: 0,
            },
            &mut [0],
        );
    }
}
