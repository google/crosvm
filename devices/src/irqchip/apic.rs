// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implementation of an xAPIC Local Advanced Programmable Interrupt Controller (LAPIC, aka APIC).
// See Intel Software Developer's Manual, Volume 3A, chapter 10 for a specification.
//
// Some features from the spec aren't supported:
//   * setting TPR with cr8 register
//   * changing MMIO base address
//   * enabling/disabling the APIC with IA32_APIC_BASE MSR
//   * TSC-deadline timer mode
//   * cluster-mode logical addressing
//   * external interrupts -- these are handled by querying `Pic` separately in
//     `UserspaceIrqChip::inject_interrupts`

use std::convert::TryFrom;
use std::convert::TryInto;
use std::time::Duration;
use std::time::Instant;

use base::error;
use base::warn;
use base::TimerTrait;
use bit_field::*;
use hypervisor::DeliveryMode;
use hypervisor::DeliveryStatus;
use hypervisor::DestinationMode;
use hypervisor::LapicState;
use hypervisor::Level;
use hypervisor::MPState;
use hypervisor::MsiAddressMessage;
use hypervisor::MsiDataMessage;
use hypervisor::TriggerMode;

pub type Vector = u8;

/// Address of the start of APIC MMIO region.
pub const APIC_BASE_ADDRESS: u64 = 0xFEE00000;
/// Length in bytes of APIC MMIO region.
pub const APIC_MEM_LENGTH_BYTES: u64 = 0x1000;

// We try to set the APIC timer frequency to the TSC frequency, but if TSC frequency can't be
// determined, we use this cycle length as a fallback.
const CYCLE_LENGTH_FALLBACK: Duration = Duration::from_nanos(10);
// Size (alignment) of each register is 16 bytes.  Only the first 4 bytes are actually used.
const REG_ALIGN_BYTES: usize = 16;
// APIC ID of the processor that starts executing instructions at power on (BSP).
const BOOTSTRAP_PROCESSOR: u8 = 0;
// 14 is the version for Xeon processors
const VERSION: u8 = 0x14;
// There are 6 local vector table entries in this version, so the max entry is offset 5.
const MAX_LVT: u8 = 5;
// Register value to mask an interrupt in the local vector table.
const LOCAL_VECTOR_MASKED: u32 = 1 << 16;
// Flat-model logical destinations.
const DESTINATION_FORMAT_FLAT: u8 = 0xF;
// Cluster-model logical destinations.
const DESTINATION_FORMAT_CLUSTER: u8 = 0x0;
// Physical destination address that goes to all CPUs.
const PHYSICAL_BROADCAST_ADDRESS: u8 = 0xFF;
// Bitmask for the APIC software enable bit in the Spurious Int register.
const SOFTWARE_ENABLE: u32 = 1 << 8;
// Bitmask for timer mode bits in the Local Timer register.
const TIMER_MODE_MASK: u32 = 3 << 17;
const TIMER_MODE_ONE_SHOT: u32 = 0 << 17;
const TIMER_MODE_PERIODIC: u32 = 1 << 17;
const TIMER_MODE_TSC_DEADLINE: u32 = 2 << 17;
// Table for mapping Divide Configuration Register values to timer divisors.  The APIC's timer
// frequency is the base frequency divided by the value from this table.
const TIMER_DIVIDE_TABLE: [u32; 16] = [
    2, 4, 8, 16, //
    1, 1, 1, 1, // Values with bit 2 are reserved and shouldn't be set
    32, 64, 128, 1, //
    1, 1, 1, 1, // Values with bit 2 are reserved and shouldn't be set
];
const ZERO_DURATION: Duration = Duration::from_nanos(0);

pub struct Apic {
    // Local APIC ID.
    id: u8,
    /// Base duration for the APIC timer.  A timer set with initial count = 1 and timer frequency
    /// divide = 1 runs for this long.
    cycle_length: Duration,
    // Register state bytes.  Each register is 16-byte aligned, but only its first 4 bytes are
    // used. The register MMIO space is 4 KiB, but only the first 1 KiB (64 registers * 16
    // bytes) is used.
    regs: [u8; APIC_MEM_LENGTH_BYTES as usize],
    // Multiprocessing initialization state: running, waiting for SIPI, etc.
    mp_state: MPState,
    // Timer for one-shot and periodic timer interrupts.
    timer: Box<dyn TimerTrait>,
    // How long the timer was set for.  If the timer is not set (not running), it's None.  For
    // one-shot timers, it's the duration from start until expiration.  For periodic timers, it's
    //the timer interval.
    timer_length: Option<Duration>,
    // When the timer started or last ticked.  For one-shot timers, this is the Instant when the
    // timer started.  For periodic timers, it's the Instant when it started or last expired.
    last_tick: Instant,
    // Pending startup interrupt vector.  There can only be one pending startup interrupt at a
    // time.
    sipi: Option<Vector>,
    // True if there's a pending INIT interrupt to send to the CPU.
    init: bool,
    // The number of pending non-maskable interrupts to be injected into the CPU.  The architecture
    // specifies that multiple NMIs can be sent concurrently and will be processed in order.
    // Unlike fixed interrupts there's no architecturally defined place where the NMIs are
    // queued or stored, we need to store them separately.
    nmis: u32,
}

impl Apic {
    /// Constructs a new APIC with local APIC ID `id`.
    pub fn new(id: u8, timer: Box<dyn TimerTrait>) -> Self {
        let cycle_length = Duration::from_nanos(1_000_000_000 / Self::frequency() as u64);
        let mp_state = if id == BOOTSTRAP_PROCESSOR {
            MPState::Runnable
        } else {
            MPState::Uninitialized
        };
        let mut apic = Apic {
            id,
            cycle_length,
            regs: [0; APIC_MEM_LENGTH_BYTES as usize],
            mp_state,
            timer,
            timer_length: None,
            last_tick: Instant::now(),
            sipi: None,
            init: false,
            nmis: 0,
        };
        apic.load_reset_state();
        apic
    }

    /// Get the Apic frequency in Hz
    pub fn frequency() -> u32 {
        // Our Apic implementation will try to use the host's bus frequency if it
        // can be determined from cpuid, otherwise it uses 100MHz (cycle length of 10 nanos)
        match crate::tsc::bus_freq_hz(std::arch::x86_64::__cpuid_count) {
            Some(hz) => hz,
            None => (1_000_000_000u128 / CYCLE_LENGTH_FALLBACK.as_nanos()) as u32,
        }
    }

    /// Returns the local APIC ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the base duration for the APIC timer.  A timer set with initial count = 1 and timer
    /// frequency divide = 1 runs for this long.
    pub fn get_cycle_length(&self) -> Duration {
        self.cycle_length
    }

    /// Returns the state of the APIC registers.
    pub fn get_state(&self) -> LapicState {
        let mut state = LapicState { regs: [0; 64] };
        for reg in 0..state.regs.len() {
            state.regs[reg] = self.get_reg(reg * REG_ALIGN_BYTES);
        }
        state
    }

    /// Sets the state of the APIC registers.
    pub fn set_state(&mut self, state: &LapicState) {
        for (reg, val) in state.regs.iter().enumerate() {
            self.set_reg(reg * REG_ALIGN_BYTES, *val);
        }

        // This has the same timer semantics as KVM.  Timers that are in-progress during get_state
        // are ignored and during set_state timers are restarted regardless of how much of the timer
        // has already expired.
        self.start_timer();
    }

    /// Gets the multi-processing state.
    pub fn get_mp_state(&self) -> MPState {
        self.mp_state
    }

    /// Sets the multi-processing state.
    pub fn set_mp_state(&mut self, state: &MPState) {
        self.mp_state = *state;
    }

    /// Checks that `offset` is 16-byte aligned and `data` is 4 bytes.
    fn valid_mmio(offset: u64, data: &[u8]) -> bool {
        if offset.trailing_zeros() >= 4 && data.len() == 4 {
            true
        } else {
            error!(
                "Invalid offset {} or size {} for apic mmio",
                offset,
                data.len()
            );
            false
        }
    }

    /// Handles an MMIO read forwarded from the IRQ chip.  Reads data from the APIC's register at
    /// `offset` into `data`.
    pub fn read(&self, offset: u64, data: &mut [u8]) {
        if !Self::valid_mmio(offset, data) {
            return;
        }
        let offset = offset as usize;
        let val = match offset {
            Reg::PPR => self.get_processor_priority() as u32,
            Reg::TIMER_CURRENT_COUNT => {
                let count_remaining = self.next_timer_expiration().as_nanos()
                    / self.cycle_length.as_nanos()
                    / self.get_timer_divide_control() as u128;
                count_remaining.try_into().unwrap_or_else(|_| {
                    warn!("APIC time remaining overflow");
                    u32::MAX
                })
            }
            _ => self.get_reg(offset),
        };
        data.copy_from_slice(&val.to_le_bytes());
    }

    /// Handles an MMIO write forwarded from the IRQ chip.  Writes `data` into the APIC's register
    /// at `offset`, optionally returning a command back to the IRQ chip.
    pub fn write(&mut self, offset: u64, data: &[u8]) -> Option<ApicBusMsg> {
        if !Self::valid_mmio(offset, data) {
            return None;
        }
        let offset = offset as usize;
        let data = u32::from_le_bytes(data.try_into().unwrap());
        let mut msg: Option<ApicBusMsg> = None;
        match offset {
            Reg::ID => {}
            Reg::TPR => self.set_reg(Reg::TPR, data & 0xFF), // Top 24 bits are reserved.
            Reg::EOI => {
                // TODO(srichman): Implement eoi broadcast suppression.
                if let Some(vector) = self.highest_bit_in_vector(VectorReg::Isr) {
                    self.clear_vector_bit(VectorReg::Isr, vector);
                    msg = Some(ApicBusMsg::Eoi(vector));
                    // The next call to UserspaceIrqChip::inject_interrupts() at end of the vcpu run
                    // loop will finish the EOI steps by injecting the highest vector in IRR, if
                    // any.
                }
            }
            Reg::INTERRUPT_COMMAND_LO => {
                // When handling writes to the ICR, we clear the pending bit.
                self.set_reg(Reg::INTERRUPT_COMMAND_LO, data & !(1 << 12));
                let interrupt = self.decode_icr();
                msg = Some(ApicBusMsg::Ipi(interrupt));
            }

            // TODO(srichman): Many of these have reserved bits which are not supposed to be set.
            // Currently we allow a guest to set them.
            // TODO(srichman): Handle software disable closer to spec: set LVT mask bits and don't
            // accept new irqs.
            Reg::TIMER_DIVIDE_CONTROL
            | Reg::LOCAL_CMCI
            | Reg::INTERRUPT_COMMAND_HI
            | Reg::SPURIOUS_INT
            | Reg::LOGICAL_DESTINATION
            | Reg::DESTINATION_FORMAT => self.set_reg(offset, data),

            Reg::LOCAL_INT_0
            | Reg::LOCAL_INT_1
            | Reg::LOCAL_THERMAL
            | Reg::LOCAL_PERF
            | Reg::LOCAL_ERROR => {
                if self.enabled() {
                    self.set_reg(offset, data);
                } else {
                    // If the APIC is software disabled then the Masked bit can not be unset.
                    self.set_reg(offset, data | LOCAL_VECTOR_MASKED);
                }
            }

            Reg::TIMER_INITIAL_COUNT => {
                self.set_reg(Reg::TIMER_INITIAL_COUNT, data);
                self.start_timer();
            }
            Reg::LOCAL_TIMER => {
                let old_mode = self.get_reg(Reg::LOCAL_TIMER) & TIMER_MODE_MASK;
                let new_mode = data & TIMER_MODE_MASK;
                if old_mode != new_mode {
                    self.clear_timer();
                }
                self.set_reg(Reg::LOCAL_TIMER, data);
            }
            _ => {
                // TODO(srichman): Inject a GP into the guest.
            }
        }
        msg
    }

    /// If `dest` specifies a single destination APIC that can be determined quickly without calling
    /// `match_dest` on each APIC, then return the destination APIC ID, otherwise return None.
    pub fn single_dest_fast(dest: &InterruptDestination) -> Option<u8> {
        if dest.shorthand == DestinationShorthand::Self_ {
            Some(dest.source_id)
        } else if dest.shorthand == DestinationShorthand::None
            && dest.mode == DestinationMode::Physical
            && dest.dest_id != PHYSICAL_BROADCAST_ADDRESS
        {
            Some(dest.dest_id)
        } else {
            None
        }
    }

    /// Returns true if this APIC is one of the destinations of the interrupt `dest`.
    pub fn match_dest(&self, dest: &InterruptDestination) -> bool {
        match dest.shorthand {
            DestinationShorthand::All => true,
            DestinationShorthand::AllExcludingSelf => dest.source_id != self.id,
            DestinationShorthand::Self_ => dest.source_id == self.id,
            DestinationShorthand::None => match dest.mode {
                DestinationMode::Physical => {
                    dest.dest_id == PHYSICAL_BROADCAST_ADDRESS || dest.dest_id == self.id
                }
                DestinationMode::Logical => self.matches_logical_address(dest.dest_id),
            },
        }
    }

    /// Returns the processor priority register.
    pub fn get_processor_priority(&self) -> u8 {
        // From 10.8 in the manual:
        // "PPR[7:4] (the processor-priority class) the maximum of TPR[7:4] (the task-priority
        // class) and ISRV[7:4] (the priority of the highest priority interrupt in service).
        // PPR[3:0] (the processor-priority sub-class) is determined as follows:
        //   - If TPR[7:4] > ISRV[7:4], PPR[3:0] is TPR[3:0] (the task-priority sub-class).
        //   - If TPR[7:4] < ISRV[7:4], PPR[3:0] is 0.
        //   - If TPR[7:4] = ISRV[7:4], PPR[3:0] may be either TPR[3:0] or 0.  The actual behavior
        //     is model-specific."
        let tpr = self.regs[Reg::TPR];
        let isrv = self.highest_bit_in_vector(VectorReg::Isr).unwrap_or(0);
        if tpr >> 4 >= isrv >> 4 {
            tpr
        } else {
            isrv & !0xF
        }
    }

    /// Enqueues an interrupt to be delivered to this APIC's vcpu.
    pub fn accept_irq(&mut self, i: &InterruptData) {
        match i.delivery {
            DeliveryMode::Fixed | DeliveryMode::Lowest => {
                self.set_vector_bit(VectorReg::Irr, i.vector);
                if i.trigger == TriggerMode::Level {
                    self.set_vector_bit(VectorReg::Tmr, i.vector);
                } else {
                    self.clear_vector_bit(VectorReg::Tmr, i.vector);
                }
                self.mp_state = MPState::Runnable;
            }
            DeliveryMode::Startup => self.sipi = Some(i.vector),
            DeliveryMode::Init => {
                if i.level == Level::Assert {
                    self.init = true;
                }
            }
            DeliveryMode::NMI => self.nmis += 1,
            DeliveryMode::External => warn!("APIC doesn't handle external interrupts, dropping"),
            DeliveryMode::RemoteRead => {
                // This type of interrupt is no longer supported or documented by Intel, but Windows
                // still issues it, and we ignore it.
            }
            DeliveryMode::SMI => warn!("APIC doesn't handle SMIs, dropping interrupt"),
        }
    }

    /// Returns the highest-priority vector in the IRR that has high enough priority to be serviced
    /// (i.e., its priority class is greater than the current processor priority class).  If `clear`
    /// is true, the IRR bit for that vector is cleared and the ISR bit is set.
    fn inject_interrupt(&mut self, clear: bool) -> Option<Vector> {
        let irrv = self.highest_bit_in_vector(VectorReg::Irr).unwrap_or(0);
        // Only the processor priority class bits (PPR[7:4]) are used to decide if the vector has
        // priority to interrupt.
        if irrv >> 4 > self.get_processor_priority() >> 4 {
            if clear {
                self.clear_vector_bit(VectorReg::Irr, irrv);
                self.set_vector_bit(VectorReg::Isr, irrv);
            }
            Some(irrv)
        } else {
            None
        }
    }

    /// Parses data from the Interrupt Command Register into an interrupt.
    fn decode_icr(&mut self) -> Interrupt {
        let hi = self.get_reg(Reg::INTERRUPT_COMMAND_HI) as u64;
        let lo = self.get_reg(Reg::INTERRUPT_COMMAND_LO) as u64;
        let icr = hi << 32 | lo;
        let mut command = InterruptCommand::new();
        command.set(0, 64, icr);
        Interrupt {
            dest: InterruptDestination {
                source_id: self.id,
                dest_id: command.get_destination(),
                shorthand: command.get_shorthand(),
                mode: command.get_destination_mode(),
            },
            data: InterruptData {
                vector: command.get_vector(),
                delivery: command.get_delivery(),
                trigger: command.get_trigger(),
                level: command.get_level(),
            },
        }
    }

    /// Returns true if the APIC is software-enabled, false if it's software-disabled.
    fn enabled(&self) -> bool {
        self.get_reg(Reg::SPURIOUS_INT) & SOFTWARE_ENABLE != 0
    }

    /// Sets or unsets the software enabled bit in the Spurious Int register.
    pub fn set_enabled(&mut self, enable: bool) {
        let mut val = self.get_reg(Reg::SPURIOUS_INT);
        if enable {
            val |= SOFTWARE_ENABLE;
        } else {
            val &= !SOFTWARE_ENABLE;
        }
        self.set_reg(Reg::SPURIOUS_INT, val);
    }

    /// Gets pending interrupts to be injected into this APIC's vcpu.  The interrupts returned are
    /// cleared from the APIC.  `vcpu_ready` indicates if the vcpu is ready to receive fixed
    /// interrupts (i.e., if the vcpu's interrupt window is open, IF flag is set, and the PIC hasn't
    /// already injected an interrupt).
    pub fn get_pending_irqs(&mut self, vcpu_ready: bool) -> PendingInterrupts {
        let (fixed, needs_window) = if !self.enabled() {
            (None, false)
        } else {
            match self.inject_interrupt(vcpu_ready) {
                Some(vector) if vcpu_ready => {
                    let has_second_interrupt = self.inject_interrupt(false).is_some();
                    (Some(vector), has_second_interrupt)
                }
                Some(_) if !vcpu_ready => (None, true),
                None => (None, false),
                _ => unreachable!(),
            }
        };

        let nmis = self.nmis;
        self.nmis = 0;

        let init = self.init;
        self.init = false;

        let startup = self.sipi;
        self.sipi = None;

        PendingInterrupts {
            fixed,
            nmis,
            init,
            startup,
            needs_window,
        }
    }

    /// Resets the APIC to its initial state.  Used for initializing a new APIC and when the vcpu
    /// receives an INIT.
    pub fn load_reset_state(&mut self) {
        for reg in self.regs.iter_mut() {
            *reg = 0;
        }
        self.set_reg(Reg::DESTINATION_FORMAT, 0xFFFFFFFF);

        // All local interrupts start out masked.
        self.set_reg(Reg::LOCAL_INT_0, LOCAL_VECTOR_MASKED);
        self.set_reg(Reg::LOCAL_INT_1, LOCAL_VECTOR_MASKED);
        self.set_reg(Reg::LOCAL_THERMAL, LOCAL_VECTOR_MASKED);
        self.set_reg(Reg::LOCAL_PERF, LOCAL_VECTOR_MASKED);
        self.set_reg(Reg::LOCAL_ERROR, LOCAL_VECTOR_MASKED);
        self.set_reg(Reg::LOCAL_TIMER, LOCAL_VECTOR_MASKED);
        self.clear_timer();

        let mut version = VersionRegister::new();
        version.set_version(VERSION);
        version.set_max_lvt(MAX_LVT);
        version.set_eoi_broadcast_suppression(1);
        let bits = version.get(0, 32) as u32;
        self.set_reg(Reg::VERSION, bits);

        self.set_reg(Reg::ID, (self.id as u32) << 24);

        // The apic starts out software disabled (Spurious Int bit 8 is unset).
        self.set_reg(Reg::SPURIOUS_INT, 0xFF);
    }

    pub fn debug_status(&self) -> String {
        let mut irr = [0u32; 8];
        let mut isr = [0u32; 8];
        for i in 0..8 {
            irr[i] = self.get_reg(Reg::IRR + i * REG_ALIGN_BYTES);
            isr[i] = self.get_reg(Reg::ISR + i * REG_ALIGN_BYTES);
        }
        let irrv = self.highest_bit_in_vector(VectorReg::Irr).unwrap_or(0);
        let isrv = self.highest_bit_in_vector(VectorReg::Isr).unwrap_or(0);
        let timer = self
            .timer_length
            .map(|d| format!("{}ns", d.as_nanos()))
            .unwrap_or("None".to_string());

        format!(
            "enabled={} irr={:?} irrv={} isr={:?} isrv={} irrv_prio={} proc_prio={}, timer={}",
            self.enabled(),
            irr,
            irrv,
            isr,
            isrv,
            irrv >> 4,
            self.get_processor_priority() >> 4,
            timer,
        )
    }

    /// Callback to be called by a timer worker when the timer expires.
    pub fn handle_timer_expiration(&mut self) {
        if let Err(e) = self.timer.mark_waited() {
            error!("APIC timer wait unexpectedly failed: {}", e);
            return;
        }
        self.last_tick = Instant::now();
        let local_timer = self.get_reg(Reg::LOCAL_TIMER);
        let is_masked = local_timer & LOCAL_VECTOR_MASKED != 0;
        if is_masked || self.timer_length.is_none() {
            return;
        }
        // Low 8 bits are the vector.
        let vector = local_timer as u8;
        self.accept_irq(&InterruptData {
            vector,
            delivery: DeliveryMode::Fixed,
            trigger: TriggerMode::Edge,
            level: Level::Deassert,
        });
    }

    /// Returns the first 4 bytes of the register that starts at `offset`.
    fn get_reg(&self, offset: usize) -> u32 {
        let bytes = &self.regs[offset..offset + 4];
        u32::from_le_bytes(bytes.try_into().unwrap())
    }

    /// Sets the first 4 bytes of the register that starts at `offset` to `val`.
    fn set_reg(&mut self, offset: usize, val: u32) {
        self.regs[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
    }

    /// Finds the bit for `vector` in vector bitmap register `reg`.
    /// Returns `(index, bitmask)` where `index` is the index of the register byte for `vector`, and
    /// `bitmask` has one bit set for the `vector` bit within that byte.
    fn reg_bit_for_vector(reg: VectorReg, vector: Vector) -> (usize, u8) {
        let vector = vector as usize;
        // First 3 bits indicate which 16-byte aligned register
        // Next 2 bits indicate which byte in that register
        // Last 3 bits indicate which bit in that byte.
        let index = (reg as usize) + 0x10 * (vector >> 5) + ((vector >> 3) & 0x3);
        let bitmask = 1 << (vector & 0x7);
        (index, bitmask)
    }

    fn set_vector_bit(&mut self, reg: VectorReg, vector: Vector) {
        let (reg, bitmask) = Self::reg_bit_for_vector(reg, vector);
        self.regs[reg] |= bitmask;
    }

    fn clear_vector_bit(&mut self, reg: VectorReg, vector: Vector) {
        let (reg, bitmask) = Self::reg_bit_for_vector(reg, vector);
        self.regs[reg] &= !bitmask;
    }

    /// Returns the vector of the highest bit set in `reg`.
    fn highest_bit_in_vector(&self, reg: VectorReg) -> Option<Vector> {
        let reg = reg as usize;
        for i in (0..8).rev() {
            let val = self.get_reg(reg + i * REG_ALIGN_BYTES);
            if val != 0 {
                let msb_set = 31 - val.leading_zeros() as u8;
                return Some(msb_set + 32 * i as u8);
            }
        }
        None
    }

    /// Returns true if this apic is a possible destination for the logical address `dest`.
    fn matches_logical_address(&self, dest: u8) -> bool {
        let bits = self.get_reg(Reg::DESTINATION_FORMAT) as u64;
        let mut format = DestinationFormat::new();
        format.set(0, 32, bits);
        let model = format.get_model();

        let bits = self.get_reg(Reg::LOGICAL_DESTINATION) as u64;
        let mut logical_dest = LogicalDestination::new();
        logical_dest.set(0, 32, bits);
        let local_logical_id = logical_dest.get_logical_id();

        match model {
            DESTINATION_FORMAT_FLAT => dest & local_logical_id != 0,
            DESTINATION_FORMAT_CLUSTER => {
                error!("Cluster-mode APIC logical destinations unsupported");
                false
            }
            _ => {
                error!("Invalid APIC logical destination format {}", model);
                false
            }
        }
    }

    fn get_timer_divide_control(&self) -> u32 {
        let div_control = self.get_reg(Reg::TIMER_DIVIDE_CONTROL) as usize & 0xF;
        TIMER_DIVIDE_TABLE[div_control]
    }

    fn start_timer(&mut self) {
        self.clear_timer();
        let initial_count = self.get_reg(Reg::TIMER_INITIAL_COUNT);
        if initial_count == 0 {
            return;
        }
        let length = self.cycle_length * initial_count * self.get_timer_divide_control();
        let mode = self.get_reg(Reg::LOCAL_TIMER) & TIMER_MODE_MASK;
        match mode {
            TIMER_MODE_ONE_SHOT => {
                if let Err(e) = self.timer.reset_oneshot(length) {
                    error!("Failed to reset APIC timer to one-shot({:?}) {}", length, e);
                    return;
                }
            }
            TIMER_MODE_PERIODIC => {
                if let Err(e) = self.timer.reset_repeating(length) {
                    error!(
                        "Failed to reset APIC timer to repeating({:?}) {}",
                        length, e
                    );
                    return;
                }
            }
            TIMER_MODE_TSC_DEADLINE => {
                warn!("APIC TSC-deadline timer not supported");
                return;
            }
            _ => {
                error!("Invalid APIC timer mode 0x{:X}", mode);
                return;
            }
        };

        self.last_tick = Instant::now();
        self.timer_length = Some(length);
    }

    fn clear_timer(&mut self) {
        if self.timer_length.is_some() {
            if let Err(e) = self.timer.clear() {
                error!("Failed to clear APIC timer: {}", e);
            }
            self.timer_length = None;
        }
    }

    /// Returns the duration remaining until the next timer expiration.
    fn next_timer_expiration(&self) -> Duration {
        if let Some(length) = self.timer_length {
            let elapsed = self.last_tick.elapsed();
            length.checked_sub(elapsed).unwrap_or(ZERO_DURATION)
        } else {
            ZERO_DURATION
        }
    }
}

impl Drop for Apic {
    fn drop(&mut self) {
        self.clear_timer();
    }
}

/// A message from an `Apic` to the `UserspaceIrqChip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApicBusMsg {
    /// Broadcasts end-of-interrupt for the specified vector.
    Eoi(Vector),
    /// Sends an IPI.
    Ipi(Interrupt),
}

/// Pending `Apic` interrupts to be injected into a vcpu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PendingInterrupts {
    /// Vector of a pending fixed interrupt.
    pub fixed: Option<Vector>,
    /// Number of pending non-maskable interrupts.
    pub nmis: u32,
    /// True if there is a pending INIT IPI.
    pub init: bool,
    /// Vector of a pending startup IPI (SIPI).
    pub startup: Option<Vector>,
    /// True if there are additional pending interrupts to delivered in the future, so an interrupt
    /// window should be requested for the vcpu.
    pub needs_window: bool,
}

/// A quick method of specifying all processors, all excluding self, or self as the destination.
#[bitfield]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationShorthand {
    None = 0b00,
    Self_ = 0b01,
    All = 0b10,
    AllExcludingSelf = 0b11,
}

/// An interrupt to be sent to one or more `Apic`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interrupt {
    /// Specifies the destination processors for this interrupt.
    pub dest: InterruptDestination,
    /// The vector and type of this interrupt.
    pub data: InterruptData,
}

/// Specifies the destination processors for an `Interrupt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptDestination {
    /// The APIC ID that sent this interrupt.
    pub source_id: u8,
    /// In physical destination mode, used to specify the APIC ID of the destination processor.
    /// In logical destination mode, used to specify a message destination address (MDA) that can
    /// be used to select specific processors in clusters.  Only used if shorthand is None.
    pub dest_id: u8,
    /// Specifies a quick destination of all processors, all excluding self, or self.  If None,
    /// then dest_id and mode are used to find the destinations.
    pub shorthand: DestinationShorthand,
    /// Specifies if physical or logical addressing is used for matching dest_id.
    pub mode: DestinationMode,
}

/// The vector and type of an `Interrupt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptData {
    /// The index in the OS's interrupt descriptor table for this interrupt.
    pub vector: Vector,
    /// The type of interrupt: fixed (regular IDT vector), NMI, startup IPI, etc.
    pub delivery: DeliveryMode,
    /// Edge- or level-triggered.
    pub trigger: TriggerMode,
    /// For level-triggered interrupts, specifies whether the line should be asserted or
    /// deasserted.
    pub level: Level,
}

impl TryFrom<&MsiAddressMessage> for InterruptDestination {
    type Error = String;

    fn try_from(msi: &MsiAddressMessage) -> std::result::Result<Self, Self::Error> {
        if msi.get_always_0xfee() != 0xFEE {
            return Err(format!(
                "top 12 bits must be 0xFEE but are 0x{:X}",
                msi.get_always_0xfee()
            ));
        }
        // TODO(srichman): Handle redirection hint?
        Ok(InterruptDestination {
            source_id: 0,
            dest_id: msi.get_destination_id(),
            shorthand: DestinationShorthand::None,
            mode: msi.get_destination_mode(),
        })
    }
}

impl From<&MsiDataMessage> for InterruptData {
    fn from(msi: &MsiDataMessage) -> Self {
        InterruptData {
            vector: msi.get_vector(),
            delivery: msi.get_delivery_mode(),
            trigger: msi.get_trigger(),
            level: msi.get_level(),
        }
    }
}

#[bitfield]
#[derive(Clone, Copy)]
struct LocalInterrupt {
    vector: BitField8,
    #[bits = 3]
    delivery_mode: DeliveryMode,
    reserved1: BitField1,
    #[bits = 1]
    delivery_status: DeliveryStatus,
    polarity: BitField1,
    remote_irr: BitField1,
    #[bits = 1]
    trigger: TriggerMode,
    masked: BitField1,
    reserved2: BitField7,
    reserved3: BitField8,
}

#[bitfield]
#[derive(Clone, Copy)]
struct VersionRegister {
    version: BitField8,
    reserved1: BitField8,
    max_lvt: BitField8,
    eoi_broadcast_suppression: BitField1,
    reserved2: BitField7,
}

#[bitfield]
#[derive(Clone, Copy)]
struct DestinationFormat {
    reserved: BitField28,
    model: BitField4,
}

#[bitfield]
#[derive(Clone, Copy)]
struct LogicalDestination {
    reserved: BitField24,
    logical_id: BitField8,
}

#[bitfield]
#[derive(Clone, Copy)]
struct InterruptCommand {
    vector: BitField8,
    #[bits = 3]
    delivery: DeliveryMode,
    #[bits = 1]
    destination_mode: DestinationMode,
    #[bits = 1]
    delivery_status: DeliveryStatus,
    reserved1: BitField1,
    #[bits = 1]
    level: Level,
    #[bits = 1]
    trigger: TriggerMode,
    reserved2: BitField2,
    #[bits = 2]
    shorthand: DestinationShorthand,
    reserved3: BitField36,
    destination: BitField8,
}

struct Reg;

impl Reg {
    const ID: usize = 0x20;
    const VERSION: usize = 0x30;
    const TPR: usize = 0x80;
    const PPR: usize = 0xA0;
    const EOI: usize = 0xB0;
    const LOGICAL_DESTINATION: usize = 0xD0;
    const DESTINATION_FORMAT: usize = 0xE0;
    const SPURIOUS_INT: usize = 0xF0;
    // In-service register is 0x100-0x170
    const ISR: usize = 0x100;
    // Trigger mode register is 0x180-0x1F0
    const TMR: usize = 0x180;
    // Interrupt request regsiter is 0x200-0x270
    const IRR: usize = 0x200;
    const LOCAL_CMCI: usize = 0x2F0;
    const INTERRUPT_COMMAND_LO: usize = 0x300;
    const INTERRUPT_COMMAND_HI: usize = 0x310;
    const LOCAL_TIMER: usize = 0x320;
    const LOCAL_THERMAL: usize = 0x330;
    const LOCAL_PERF: usize = 0x340;
    const LOCAL_INT_0: usize = 0x350;
    const LOCAL_INT_1: usize = 0x360;
    const LOCAL_ERROR: usize = 0x370;
    const TIMER_INITIAL_COUNT: usize = 0x380;
    const TIMER_CURRENT_COUNT: usize = 0x390;
    const TIMER_DIVIDE_CONTROL: usize = 0x3E0;
}

/// The APIC registers that store interrupt vector bitmaps.  Each has 256 bit flags, one for each
/// interrupt vector.  The flags are spread across the first 32 bits of each of eight 16-byte APIC
/// register slots.
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VectorReg {
    /// In-service register.  A bit is set for each interrupt vector currently being serviced by
    /// the processor.
    Isr = Reg::ISR,
    /// Trigger mode register.  Records whether interrupts are edge-triggered (bit is clear) or
    /// level-triggered (bit is set).
    Tmr = Reg::TMR,
    /// Interrupt request register.  A bit is set for each interrupt vector received by the APIC
    /// but not yet serviced by the processor.
    Irr = Reg::IRR,
}

#[cfg(test)]
mod tests {
    use std::mem;
    use std::sync::Arc;

    use base::FakeClock;
    use base::FakeTimer;
    use sync::Mutex;

    use super::*;

    #[test]
    fn struct_size() {
        assert_eq!(4, mem::size_of::<LocalInterrupt>());
        assert_eq!(4, mem::size_of::<VersionRegister>());
        assert_eq!(4, mem::size_of::<DestinationFormat>());
        assert_eq!(4, mem::size_of::<LogicalDestination>());
        assert_eq!(8, mem::size_of::<InterruptCommand>());
    }

    #[test]
    fn get_reg() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        a.regs[0..4].copy_from_slice(&[0xFE, 0xCA, 0xAD, 0xAB]);
        assert_eq!(a.get_reg(0), 0xABADCAFE);
        a.regs[4092..4096].copy_from_slice(&[0x0D, 0xF0, 0x1D, 0xC0]);
        assert_eq!(a.get_reg(4092), 0xC01DF00D);
    }

    #[test]
    fn set_reg() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        a.set_reg(0, 0xABADCAFE);
        assert_eq!(a.regs[0..4], [0xFE, 0xCA, 0xAD, 0xAB]);
        a.set_reg(4092, 0xC01DF00D);
        assert_eq!(a.regs[4092..4096], [0x0D, 0xF0, 0x1D, 0xC0]);
    }

    #[test]
    fn lapic_state() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);

        a.set_reg(0, 0xABADCAFE);
        assert_eq!(a.get_state().regs[0], 0xABADCAFE);

        let mut state = LapicState { regs: [0; 64] };
        state.regs[63] = 0xC01DF00D;
        a.set_state(&state);
        assert_eq!(a.regs[1008..1012], [0x0D, 0xF0, 0x1D, 0xC0]);
    }

    #[test]
    fn valid_mmio() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(42, timer);

        let mut data = [0u8; 4];
        a.read(Reg::ID as u64, &mut data);
        assert_eq!(data, [0, 0, 0, 42]);
        a.write(Reg::INTERRUPT_COMMAND_HI as u64, &[0xFE, 0xCA, 0xAD, 0xAB]);
        assert_eq!(a.get_reg(Reg::INTERRUPT_COMMAND_HI), 0xABADCAFE);
        let mut data = [0u8; 4];
        a.read(Reg::INTERRUPT_COMMAND_HI as u64, &mut data);
        assert_eq!(data, [0xFE, 0xCA, 0xAD, 0xAB]);
    }

    #[test]
    fn invalid_mmio() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        a.set_reg(Reg::INTERRUPT_COMMAND_HI, 0xABADCAFE);

        let mut data = [0u8; 5];
        a.read(Reg::INTERRUPT_COMMAND_HI as u64, &mut data);
        assert_eq!(data, [0; 5]);
        let mut data = [0u8; 4];
        a.read(Reg::INTERRUPT_COMMAND_HI as u64 + 1, &mut data);
        assert_eq!(data, [0; 4]);
        a.write(Reg::INTERRUPT_COMMAND_HI as u64, &[0; 3]);
        assert_eq!(a.get_reg(Reg::INTERRUPT_COMMAND_HI), 0xABADCAFE);
        a.write(Reg::INTERRUPT_COMMAND_HI as u64 + 1, &[0; 4]);
        assert_eq!(a.get_reg(Reg::INTERRUPT_COMMAND_HI), 0xABADCAFE);
    }

    #[test]
    fn vector_reg() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);

        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), None);
        a.set_vector_bit(VectorReg::Irr, 0);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(0));
        a.set_vector_bit(VectorReg::Irr, 7);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(7));
        a.set_vector_bit(VectorReg::Irr, 8);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(8));
        a.set_vector_bit(VectorReg::Irr, 31);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(31));
        a.set_vector_bit(VectorReg::Irr, 32);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(32));
        a.set_vector_bit(VectorReg::Irr, 74);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(74));
        a.set_vector_bit(VectorReg::Irr, 66);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(74));
        a.set_vector_bit(VectorReg::Irr, 255);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(255));
        assert_eq!(
            a.get_reg(Reg::IRR),
            0b1000_0000_0000_0000_0000_0001_1000_0001
        );
        assert_eq!(
            a.get_reg(Reg::IRR + 1 * REG_ALIGN_BYTES),
            0b0000_0000_0000_0000_0000_0000_0000_0001
        );
        assert_eq!(
            a.get_reg(Reg::IRR + 2 * REG_ALIGN_BYTES),
            0b0000_0000_0000_0000_0000_0100_0000_0100
        );
        assert_eq!(a.get_reg(Reg::IRR + 3 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 4 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 5 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 6 * REG_ALIGN_BYTES), 0);
        assert_eq!(
            a.get_reg(Reg::IRR + 7 * REG_ALIGN_BYTES),
            0b1000_0000_0000_0000_0000_0000_0000_0000
        );

        a.clear_vector_bit(VectorReg::Irr, 255);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(74));
        a.clear_vector_bit(VectorReg::Irr, 74);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(66));
        a.clear_vector_bit(VectorReg::Irr, 32);
        a.clear_vector_bit(VectorReg::Irr, 66);
        a.clear_vector_bit(VectorReg::Irr, 31);
        a.clear_vector_bit(VectorReg::Irr, 200);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(8));
        assert_eq!(
            a.get_reg(Reg::IRR),
            0b0000_0000_0000_0000_0000_0001_1000_0001
        );
        assert_eq!(a.get_reg(Reg::IRR + 1 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 2 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 3 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 4 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 5 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 6 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 7 * REG_ALIGN_BYTES), 0);
    }

    #[test]
    fn single_dest() {
        assert_eq!(
            Apic::single_dest_fast(&InterruptDestination {
                source_id: 0,
                dest_id: 254,
                shorthand: DestinationShorthand::None,
                mode: DestinationMode::Physical,
            }),
            Some(254)
        );
        assert_eq!(
            Apic::single_dest_fast(&InterruptDestination {
                source_id: 0,
                dest_id: 254,
                shorthand: DestinationShorthand::Self_,
                mode: DestinationMode::Physical,
            }),
            Some(0)
        );
        assert_eq!(
            Apic::single_dest_fast(&InterruptDestination {
                source_id: 0,
                dest_id: PHYSICAL_BROADCAST_ADDRESS,
                shorthand: DestinationShorthand::None,
                mode: DestinationMode::Physical,
            }),
            None
        );
        assert_eq!(
            Apic::single_dest_fast(&InterruptDestination {
                source_id: 0,
                dest_id: 254,
                shorthand: DestinationShorthand::All,
                mode: DestinationMode::Physical,
            }),
            None
        );
        assert_eq!(
            Apic::single_dest_fast(&InterruptDestination {
                source_id: 0,
                dest_id: 254,
                shorthand: DestinationShorthand::AllExcludingSelf,
                mode: DestinationMode::Physical,
            }),
            None
        );
        assert_eq!(
            Apic::single_dest_fast(&InterruptDestination {
                source_id: 0,
                dest_id: 254,
                shorthand: DestinationShorthand::None,
                mode: DestinationMode::Logical,
            }),
            None
        );
    }

    #[test]
    fn match_dest() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(254, timer);
        a.set_reg(Reg::LOGICAL_DESTINATION, 0b11001001 << 24);

        assert!(a.match_dest(&InterruptDestination {
            source_id: 0,
            dest_id: 254,
            shorthand: DestinationShorthand::None,
            mode: DestinationMode::Physical,
        }));
        assert!(a.match_dest(&InterruptDestination {
            source_id: 0,
            dest_id: PHYSICAL_BROADCAST_ADDRESS,
            shorthand: DestinationShorthand::None,
            mode: DestinationMode::Physical,
        }));
        assert!(!a.match_dest(&InterruptDestination {
            source_id: 0,
            dest_id: 77,
            shorthand: DestinationShorthand::None,
            mode: DestinationMode::Physical,
        }));
        assert!(a.match_dest(&InterruptDestination {
            source_id: 0,
            dest_id: 0b01001000,
            shorthand: DestinationShorthand::None,
            mode: DestinationMode::Logical,
        }));
        assert!(!a.match_dest(&InterruptDestination {
            source_id: 0,
            dest_id: 0b00010010,
            shorthand: DestinationShorthand::None,
            mode: DestinationMode::Logical,
        }));
        assert!(a.match_dest(&InterruptDestination {
            source_id: 0,
            dest_id: 0,
            shorthand: DestinationShorthand::All,
            mode: DestinationMode::Physical,
        }));
        assert!(a.match_dest(&InterruptDestination {
            source_id: 254,
            dest_id: 0,
            shorthand: DestinationShorthand::Self_,
            mode: DestinationMode::Physical,
        }));
        assert!(!a.match_dest(&InterruptDestination {
            source_id: 0,
            dest_id: 0,
            shorthand: DestinationShorthand::Self_,
            mode: DestinationMode::Physical,
        }));
        assert!(a.match_dest(&InterruptDestination {
            source_id: 0,
            dest_id: 0,
            shorthand: DestinationShorthand::AllExcludingSelf,
            mode: DestinationMode::Physical,
        }));
        assert!(!a.match_dest(&InterruptDestination {
            source_id: 254,
            dest_id: 0,
            shorthand: DestinationShorthand::AllExcludingSelf,
            mode: DestinationMode::Physical,
        }));
    }

    #[test]
    fn processor_priority() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        assert_eq!(a.get_processor_priority(), 0);
        a.set_reg(Reg::TPR, 0xF);
        let prio = a.get_processor_priority();
        // When TPR[7:4] == ISRV[7:4], the manual allows either 0 or TPR[3:0] for PPR[3:0].
        assert!(
            prio == 0 || prio == 0xF,
            "Expected priority 0 or 0xF, got {}",
            prio
        );
        a.set_reg(Reg::TPR, 0x10);
        assert_eq!(a.get_processor_priority(), 0x10);
        a.set_reg(Reg::TPR, 0);
        assert_eq!(a.get_processor_priority(), 0);

        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        a.set_vector_bit(VectorReg::Isr, 0xF);
        assert_eq!(a.get_processor_priority(), 0);
        a.set_vector_bit(VectorReg::Isr, 0x11);
        assert_eq!(a.get_processor_priority(), 0x10);
        a.clear_vector_bit(VectorReg::Isr, 0x11);
        assert_eq!(a.get_processor_priority(), 0);

        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        a.set_vector_bit(VectorReg::Isr, 0x25);
        a.set_vector_bit(VectorReg::Isr, 0x11);
        a.set_reg(Reg::TPR, 0x31);
        assert_eq!(a.get_processor_priority(), 0x31);
        a.set_reg(Reg::TPR, 0x19);
        assert_eq!(a.get_processor_priority(), 0x20);
        a.clear_vector_bit(VectorReg::Isr, 0x25);
        let prio = a.get_processor_priority();
        assert!(
            prio == 0x10 || prio == 0x19,
            "Expected priority 0x10 or 0x19, got {}",
            prio
        );
    }

    #[test]
    fn accept_irq() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        assert_eq!(a.init, false);
        assert_eq!(a.sipi, None);
        assert_eq!(a.nmis, 0);
        a.accept_irq(&InterruptData {
            vector: 20,
            delivery: DeliveryMode::Fixed,
            trigger: TriggerMode::Level,
            level: Level::Assert,
        });
        a.accept_irq(&InterruptData {
            vector: 20,
            delivery: DeliveryMode::Fixed,
            trigger: TriggerMode::Level,
            level: Level::Assert,
        });
        a.accept_irq(&InterruptData {
            vector: 21,
            delivery: DeliveryMode::Fixed,
            trigger: TriggerMode::Edge,
            level: Level::Assert,
        });
        a.accept_irq(&InterruptData {
            vector: 255,
            delivery: DeliveryMode::Lowest,
            trigger: TriggerMode::Level,
            level: Level::Assert,
        });
        a.accept_irq(&InterruptData {
            vector: 0,
            delivery: DeliveryMode::Init,
            trigger: TriggerMode::Level,
            level: Level::Assert,
        });
        a.accept_irq(&InterruptData {
            vector: 7,
            delivery: DeliveryMode::Startup,
            trigger: TriggerMode::Edge,
            level: Level::Assert,
        });
        a.accept_irq(&InterruptData {
            vector: 8,
            delivery: DeliveryMode::Startup,
            trigger: TriggerMode::Edge,
            level: Level::Assert,
        });
        a.accept_irq(&InterruptData {
            vector: 0,
            delivery: DeliveryMode::NMI,
            trigger: TriggerMode::Edge,
            level: Level::Assert,
        });
        a.accept_irq(&InterruptData {
            vector: 0,
            delivery: DeliveryMode::NMI,
            trigger: TriggerMode::Edge,
            level: Level::Assert,
        });
        assert_eq!(a.init, true);
        assert_eq!(a.sipi, Some(8));
        assert_eq!(a.nmis, 2);
        // IRR should be set for 20, 21, and 255.
        assert_eq!(
            a.get_reg(Reg::IRR),
            0b0000_0000_0011_0000_0000_0000_0000_0000
        );
        assert_eq!(a.get_reg(Reg::IRR + 1 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 2 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 3 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 4 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 5 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::IRR + 6 * REG_ALIGN_BYTES), 0);
        assert_eq!(
            a.get_reg(Reg::IRR + 7 * REG_ALIGN_BYTES),
            0b1000_0000_0000_0000_0000_0000_0000_0000
        );
        // ISR should be unset.
        assert_eq!(a.get_reg(Reg::ISR), 0);
        assert_eq!(a.get_reg(Reg::ISR + 1 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::ISR + 2 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::ISR + 3 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::ISR + 4 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::ISR + 5 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::ISR + 6 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::ISR + 7 * REG_ALIGN_BYTES), 0);
        // TMR should be set for 20 and 255.
        assert_eq!(
            a.get_reg(Reg::TMR),
            0b0000_0000_0001_0000_0000_0000_0000_0000
        );
        assert_eq!(a.get_reg(Reg::TMR + 1 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::TMR + 2 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::TMR + 3 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::TMR + 4 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::TMR + 5 * REG_ALIGN_BYTES), 0);
        assert_eq!(a.get_reg(Reg::TMR + 6 * REG_ALIGN_BYTES), 0);
        assert_eq!(
            a.get_reg(Reg::TMR + 7 * REG_ALIGN_BYTES),
            0b1000_0000_0000_0000_0000_0000_0000_0000
        );
    }

    #[test]
    fn icr_write_sends_ipi() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(229, timer);

        // Top 8 bits of ICR high are the destination.
        a.write(Reg::INTERRUPT_COMMAND_HI as u64, &[0, 0, 0, 42]);
        #[rustfmt::skip]
        let msg = a.write(
            Reg::INTERRUPT_COMMAND_LO as u64,
            &[
                123,        // vector
                0b11001001, // level 1, assert 1, reserved 0, idle 0, logical 1, lowest priority 001
                0b00001100, // reserved 0000, all excluding self 11, reserved 00
                0,          // reserved
            ],
        );
        let msg = msg.unwrap();
        assert_eq!(
            msg,
            ApicBusMsg::Ipi(Interrupt {
                dest: InterruptDestination {
                    source_id: 229,
                    dest_id: 42,
                    shorthand: DestinationShorthand::AllExcludingSelf,
                    mode: DestinationMode::Logical,
                },
                data: InterruptData {
                    vector: 123,
                    delivery: DeliveryMode::Lowest,
                    trigger: TriggerMode::Level,
                    level: Level::Assert,
                },
            })
        );

        a.write(Reg::INTERRUPT_COMMAND_HI as u64, &[0, 0, 0, 161]);
        let msg = a.write(
            Reg::INTERRUPT_COMMAND_LO as u64,
            &[
                255,        // vector
                0b00010110, // edge 0, deassert 0, reserved 0, pending 1, physical 0, sipi 110
                0b00000000, // reserved 0000, no shorthand 00, reserved 00
                0,          // reserved
            ],
        );
        let msg = msg.unwrap();
        assert_eq!(
            msg,
            ApicBusMsg::Ipi(Interrupt {
                dest: InterruptDestination {
                    source_id: 229,
                    dest_id: 161,
                    shorthand: DestinationShorthand::None,
                    mode: DestinationMode::Physical,
                },
                data: InterruptData {
                    vector: 255,
                    delivery: DeliveryMode::Startup,
                    trigger: TriggerMode::Edge,
                    level: Level::Deassert,
                },
            })
        );
    }

    #[test]
    fn end_of_interrupt() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        let msg = a.write(Reg::EOI as u64, &[0; 4]);
        assert_eq!(msg, None); // Spurious EOIs (no interrupt being serviced) should be ignored.
        a.set_vector_bit(VectorReg::Isr, 39);
        a.set_vector_bit(VectorReg::Isr, 255);
        let msg = a.write(Reg::EOI as u64, &[0; 4]).unwrap();
        assert_eq!(msg, ApicBusMsg::Eoi(255));
        assert_eq!(a.highest_bit_in_vector(VectorReg::Isr), Some(39));
        a.set_vector_bit(VectorReg::Isr, 40);
        let msg = a.write(Reg::EOI as u64, &[0; 4]).unwrap();
        assert_eq!(msg, ApicBusMsg::Eoi(40));
        assert_eq!(a.highest_bit_in_vector(VectorReg::Isr), Some(39));
        let msg = a.write(Reg::EOI as u64, &[0; 4]).unwrap();
        assert_eq!(msg, ApicBusMsg::Eoi(39));
        assert_eq!(a.highest_bit_in_vector(VectorReg::Isr), None);
        let msg = a.write(Reg::EOI as u64, &[0; 4]);
        assert_eq!(msg, None);
    }

    #[test]
    fn non_fixed_irqs_injected() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        a.set_enabled(true);

        a.accept_irq(&InterruptData {
            vector: 0,
            delivery: DeliveryMode::Init,
            trigger: TriggerMode::Level,
            level: Level::Assert,
        });
        a.accept_irq(&InterruptData {
            vector: 7,
            delivery: DeliveryMode::Startup,
            trigger: TriggerMode::Edge,
            level: Level::Assert,
        });
        a.accept_irq(&InterruptData {
            vector: 0,
            delivery: DeliveryMode::NMI,
            trigger: TriggerMode::Edge,
            level: Level::Assert,
        });
        a.accept_irq(&InterruptData {
            vector: 0,
            delivery: DeliveryMode::NMI,
            trigger: TriggerMode::Edge,
            level: Level::Assert,
        });
        // Non-fixed irqs should be injected even if vcpu_ready is false. */
        let irqs = a.get_pending_irqs(/* vcpu_ready= */ false);
        assert_eq!(
            irqs,
            PendingInterrupts {
                fixed: None,
                nmis: 2,
                init: true,
                startup: Some(7),
                needs_window: false,
            }
        );
        assert_eq!(a.nmis, 0);
        assert_eq!(a.init, false);
        assert_eq!(a.sipi, None);

        a.accept_irq(&InterruptData {
            vector: 0,
            delivery: DeliveryMode::NMI,
            trigger: TriggerMode::Edge,
            level: Level::Assert,
        });
        let irqs = a.get_pending_irqs(/* vcpu_ready= */ true);
        assert_eq!(
            irqs,
            PendingInterrupts {
                nmis: 1,
                ..Default::default()
            }
        );
        assert_eq!(a.nmis, 0);

        let irqs = a.get_pending_irqs(/* vcpu_ready= */ true);
        assert_eq!(
            irqs,
            PendingInterrupts {
                ..Default::default()
            }
        );
    }

    #[test]
    fn fixed_irq_injected() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        a.set_enabled(true);

        a.accept_irq(&InterruptData {
            vector: 0x10,
            delivery: DeliveryMode::Fixed,
            trigger: TriggerMode::Level,
            level: Level::Assert,
        });
        let irqs = a.get_pending_irqs(/* vcpu_ready= */ false);
        assert_eq!(
            irqs,
            PendingInterrupts {
                fixed: None,
                needs_window: true,
                ..Default::default()
            }
        );
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(0x10));
        assert_eq!(a.highest_bit_in_vector(VectorReg::Isr), None);
        let irqs = a.get_pending_irqs(/* vcpu_ready= */ true);
        assert_eq!(
            irqs,
            PendingInterrupts {
                fixed: Some(0x10),
                needs_window: false,
                ..Default::default()
            }
        );
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), None);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Isr), Some(0x10));
    }

    #[test]
    fn high_priority_irq_injected() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        a.set_enabled(true);

        a.accept_irq(&InterruptData {
            vector: 0x10,
            delivery: DeliveryMode::Fixed,
            trigger: TriggerMode::Level,
            level: Level::Assert,
        });
        let _ = a.get_pending_irqs(/* vcpu_ready= */ true);

        // An interrupt in a higher priority class should be injected immediately if the window is
        // open.
        a.accept_irq(&InterruptData {
            vector: 0x20,
            delivery: DeliveryMode::Fixed,
            trigger: TriggerMode::Level,
            level: Level::Assert,
        });
        let irqs = a.get_pending_irqs(/* vcpu_ready= */ false);
        assert_eq!(
            irqs,
            PendingInterrupts {
                fixed: None,
                needs_window: true,
                ..Default::default()
            }
        );
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(0x20));
        assert_eq!(a.highest_bit_in_vector(VectorReg::Isr), Some(0x10));
        let irqs = a.get_pending_irqs(/* vcpu_ready= */ true);
        assert_eq!(
            irqs,
            PendingInterrupts {
                fixed: Some(0x20),
                needs_window: false,
                ..Default::default()
            }
        );
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), None);
        assert_eq!(a.highest_bit_in_vector(VectorReg::Isr), Some(0x20));
    }

    #[test]
    fn low_priority_irq_deferred() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        a.set_enabled(true);

        a.accept_irq(&InterruptData {
            vector: 0x10,
            delivery: DeliveryMode::Fixed,
            trigger: TriggerMode::Level,
            level: Level::Assert,
        });
        let _ = a.get_pending_irqs(/* vcpu_ready= */ true);

        // An interrupt in the same or lower priority class should be deferred.
        a.accept_irq(&InterruptData {
            vector: 0x15,
            delivery: DeliveryMode::Fixed,
            trigger: TriggerMode::Level,
            level: Level::Assert,
        });
        let irqs = a.get_pending_irqs(/* vcpu_ready= */ true);
        assert_eq!(
            irqs,
            PendingInterrupts {
                fixed: None,
                // Not injectable due to higher priority ISRV, so no window needed.
                needs_window: false,
                ..Default::default()
            }
        );
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(0x15));
        assert_eq!(a.highest_bit_in_vector(VectorReg::Isr), Some(0x10));

        // EOI lets it be injected.
        let msg = a.write(Reg::EOI as u64, &[0; 4]).unwrap();
        assert_eq!(msg, ApicBusMsg::Eoi(0x10));
        let irqs = a.get_pending_irqs(/* vcpu_ready= */ true);
        assert_eq!(
            irqs,
            PendingInterrupts {
                fixed: Some(0x15),
                needs_window: false,
                ..Default::default()
            }
        );
    }

    #[test]
    fn tpr_defers_injection() {
        let timer = Box::new(FakeTimer::new(Arc::new(Mutex::new(FakeClock::new()))));
        let mut a = Apic::new(0, timer);
        a.set_enabled(true);

        a.accept_irq(&InterruptData {
            vector: 0x25,
            delivery: DeliveryMode::Fixed,
            trigger: TriggerMode::Level,
            level: Level::Assert,
        });
        a.set_reg(Reg::TPR, 0x20);
        let irqs = a.get_pending_irqs(/* vcpu_ready= */ true);
        assert_eq!(
            irqs,
            PendingInterrupts {
                fixed: None,
                needs_window: false,
                ..Default::default()
            }
        );
        a.set_reg(Reg::TPR, 0x19);
        let irqs = a.get_pending_irqs(/* vcpu_ready= */ true);
        assert_eq!(
            irqs,
            PendingInterrupts {
                fixed: Some(0x25),
                needs_window: false,
                ..Default::default()
            }
        );
    }

    #[test]
    fn timer_starts() {
        let clock = Arc::new(Mutex::new(FakeClock::new()));
        let mut a = Apic::new(0, Box::new(FakeTimer::new(clock.clone())));
        a.set_enabled(true);

        a.write(Reg::LOCAL_TIMER as u64, &TIMER_MODE_ONE_SHOT.to_le_bytes());
        a.write(Reg::TIMER_DIVIDE_CONTROL as u64, &[1, 0, 0, 0]); // Frequency divided by 4.
        a.write(Reg::TIMER_INITIAL_COUNT as u64, &500_000_u32.to_le_bytes());

        let timer_ns = u64::try_from(4 * 500_000 * a.get_cycle_length().as_nanos()).unwrap();
        clock.lock().add_ns(timer_ns - 1);
        assert_eq!(a.timer.mark_waited(), Ok(true));
        clock.lock().add_ns(1);
        assert_eq!(a.timer.mark_waited(), Ok(false));
        // One-shot timer shouldn't fire again.
        clock.lock().add_ns(timer_ns);
        assert_eq!(a.timer.mark_waited(), Ok(true));

        a.write(Reg::TIMER_DIVIDE_CONTROL as u64, &[0b1011, 0, 0, 0]); // Frequency divided by 1.
        a.write(Reg::LOCAL_TIMER as u64, &TIMER_MODE_PERIODIC.to_le_bytes());
        a.write(
            Reg::TIMER_INITIAL_COUNT as u64,
            &1_000_000_u32.to_le_bytes(),
        );

        let timer_ns = u64::try_from(1 * 1_000_000 * a.get_cycle_length().as_nanos()).unwrap();
        clock.lock().add_ns(timer_ns - 1);
        assert_eq!(a.timer.mark_waited(), Ok(true));
        clock.lock().add_ns(1);
        assert_eq!(a.timer.mark_waited(), Ok(false));
        clock.lock().add_ns(timer_ns - 1);
        assert_eq!(a.timer.mark_waited(), Ok(true));
        clock.lock().add_ns(1);
        assert_eq!(a.timer.mark_waited(), Ok(false));
    }

    #[test]
    fn timer_interrupts() {
        let clock = Arc::new(Mutex::new(FakeClock::new()));
        let mut a = Apic::new(0, Box::new(FakeTimer::new(clock.clone())));
        a.set_enabled(true);

        // Masked timer shouldn't interrupt.
        let val = TIMER_MODE_PERIODIC | LOCAL_VECTOR_MASKED | 123;
        a.write(Reg::LOCAL_TIMER as u64, &val.to_le_bytes());
        a.write(Reg::TIMER_DIVIDE_CONTROL as u64, &[0b1011, 0, 0, 0]); // Frequency divided by 1.
        a.write(Reg::TIMER_INITIAL_COUNT as u64, &500_000_u32.to_le_bytes());
        clock
            .lock()
            .add_ns(500_000 * a.get_cycle_length().as_nanos() as u64);
        a.handle_timer_expiration();
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), None);

        // Unmasked timer should interrupt on the vector in LOCAL_TIMER & 0xFF.
        let val = TIMER_MODE_PERIODIC | 123;
        a.write(Reg::LOCAL_TIMER as u64, &val.to_le_bytes());
        clock
            .lock()
            .add_ns(500_000 * a.get_cycle_length().as_nanos() as u64);
        a.handle_timer_expiration();
        assert_eq!(a.highest_bit_in_vector(VectorReg::Irr), Some(123));
    }
}
