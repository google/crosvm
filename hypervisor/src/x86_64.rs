// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::{Deserialize, Serialize};

use base::{error, Result};
use bit_field::*;
use downcast_rs::impl_downcast;

use vm_memory::GuestAddress;

use crate::{Hypervisor, IrqRoute, IrqSource, IrqSourceChip, Vcpu, Vm};

/// A trait for managing cpuids for an x86_64 hypervisor and for checking its capabilities.
pub trait HypervisorX86_64: Hypervisor {
    /// Get the system supported CPUID values.
    fn get_supported_cpuid(&self) -> Result<CpuId>;

    /// Get the system emulated CPUID values.
    fn get_emulated_cpuid(&self) -> Result<CpuId>;

    /// Gets the list of supported MSRs.
    fn get_msr_index_list(&self) -> Result<Vec<u32>>;
}

/// A wrapper for using a VM on x86_64 and getting/setting its state.
pub trait VmX86_64: Vm {
    /// Gets the `HypervisorX86_64` that created this VM.
    fn get_hypervisor(&self) -> &dyn HypervisorX86_64;

    /// Create a Vcpu with the specified Vcpu ID.
    fn create_vcpu(&self, id: usize) -> Result<Box<dyn VcpuX86_64>>;

    /// Sets the address of the three-page region in the VM's address space.
    fn set_tss_addr(&self, addr: GuestAddress) -> Result<()>;

    /// Sets the address of a one-page region in the VM's address space.
    fn set_identity_map_addr(&self, addr: GuestAddress) -> Result<()>;
}

/// A wrapper around creating and using a VCPU on x86_64.
pub trait VcpuX86_64: Vcpu {
    /// Sets or clears the flag that requests the VCPU to exit when it becomes possible to inject
    /// interrupts into the guest.
    fn set_interrupt_window_requested(&self, requested: bool);

    /// Checks if we can inject an interrupt into the VCPU.
    fn ready_for_interrupt(&self) -> bool;

    /// Injects interrupt vector `irq` into the VCPU.
    fn interrupt(&self, irq: u32) -> Result<()>;

    /// Injects a non-maskable interrupt into the VCPU.
    fn inject_nmi(&self) -> Result<()>;

    /// Gets the VCPU general purpose registers.
    fn get_regs(&self) -> Result<Regs>;

    /// Sets the VCPU general purpose registers.
    fn set_regs(&self, regs: &Regs) -> Result<()>;

    /// Gets the VCPU special registers.
    fn get_sregs(&self) -> Result<Sregs>;

    /// Sets the VCPU special registers.
    fn set_sregs(&self, sregs: &Sregs) -> Result<()>;

    /// Gets the VCPU FPU registers.
    fn get_fpu(&self) -> Result<Fpu>;

    /// Sets the VCPU FPU registers.
    fn set_fpu(&self, fpu: &Fpu) -> Result<()>;

    /// Gets the VCPU debug registers.
    fn get_debugregs(&self) -> Result<DebugRegs>;

    /// Sets the VCPU debug registers.
    fn set_debugregs(&self, debugregs: &DebugRegs) -> Result<()>;

    /// Gets the VCPU extended control registers.
    fn get_xcrs(&self) -> Result<Vec<Register>>;

    /// Sets the VCPU extended control registers.
    fn set_xcrs(&self, xcrs: &[Register]) -> Result<()>;

    /// Gets the model-specific registers.  `msrs` specifies the MSR indexes to be queried, and
    /// on success contains their indexes and values.
    fn get_msrs(&self, msrs: &mut Vec<Register>) -> Result<()>;

    /// Sets the model-specific registers.
    fn set_msrs(&self, msrs: &[Register]) -> Result<()>;

    /// Sets up the data returned by the CPUID instruction.
    fn set_cpuid(&self, cpuid: &CpuId) -> Result<()>;

    /// Gets the system emulated hyper-v CPUID values.
    fn get_hyperv_cpuid(&self) -> Result<CpuId>;

    /// Sets up debug registers and configure vcpu for handling guest debug events.
    fn set_guest_debug(&self, addrs: &[GuestAddress], enable_singlestep: bool) -> Result<()>;
}

impl_downcast!(VcpuX86_64);

/// A CpuId Entry contains supported feature information for the given processor.
/// This can be modified by the hypervisor to pass additional information to the guest kernel
/// about the hypervisor or vm. Information is returned in the eax, ebx, ecx and edx registers
/// by the cpu for a given function and index/subfunction (passed into the cpu via the eax and ecx
/// register respectively).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuIdEntry {
    pub function: u32,
    pub index: u32,
    // flags is needed for KVM.  We store it on CpuIdEntry to preserve the flags across
    // get_supported_cpuids() -> kvm_cpuid2 -> CpuId -> kvm_cpuid2 -> set_cpuid().
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// A container for the list of cpu id entries for the hypervisor and underlying cpu.
pub struct CpuId {
    pub cpu_id_entries: Vec<CpuIdEntry>,
}

impl CpuId {
    /// Constructs a new CpuId, with space allocated for `initial_capacity` CpuIdEntries.
    pub fn new(initial_capacity: usize) -> Self {
        CpuId {
            cpu_id_entries: Vec::with_capacity(initial_capacity),
        }
    }
}

#[bitfield]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationMode {
    Physical = 0,
    Logical = 1,
}

#[bitfield]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerMode {
    Edge = 0,
    Level = 1,
}

#[bitfield]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    Fixed = 0b000,
    Lowest = 0b001,
    SMI = 0b010,        // System management interrupt
    RemoteRead = 0b011, // This is no longer supported by intel.
    NMI = 0b100,        // Non maskable interrupt
    Init = 0b101,
    Startup = 0b110,
    External = 0b111,
}

// These MSI structures are for Intel's implementation of MSI.  The PCI spec defines most of MSI,
// but the Intel spec defines the format of messages for raising interrupts.  The PCI spec defines
// three u32s -- the address, address_high, and data -- but Intel only makes use of the address and
// data.  The Intel portion of the specification is in Volume 3 section 10.11.
#[bitfield]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MsiAddressMessage {
    pub reserved: BitField2,
    #[bits = 1]
    pub destination_mode: DestinationMode,
    pub redirection_hint: BitField1,
    pub reserved_2: BitField8,
    pub destination_id: BitField8,
    // According to Intel's implementation of MSI, these bits must always be 0xfee.
    pub always_0xfee: BitField12,
}

#[bitfield]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MsiDataMessage {
    pub vector: BitField8,
    #[bits = 3]
    pub delivery_mode: DeliveryMode,
    pub reserved: BitField3,
    #[bits = 1]
    pub level: Level,
    #[bits = 1]
    pub trigger: TriggerMode,
    pub reserved2: BitField16,
}

#[bitfield]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    Idle = 0,
    Pending = 1,
}

/// The level of a level-triggered interrupt: asserted or deasserted.
#[bitfield]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Deassert = 0,
    Assert = 1,
}

/// Represents a IOAPIC redirection table entry.
#[bitfield]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct IoapicRedirectionTableEntry {
    vector: BitField8,
    #[bits = 3]
    delivery_mode: DeliveryMode,
    #[bits = 1]
    dest_mode: DestinationMode,
    #[bits = 1]
    delivery_status: DeliveryStatus,
    polarity: BitField1,
    remote_irr: bool,
    #[bits = 1]
    trigger_mode: TriggerMode,
    interrupt_mask: bool, // true iff interrupts are masked.
    reserved: BitField39,
    dest_id: BitField8,
}

/// Number of pins on the IOAPIC.
pub const NUM_IOAPIC_PINS: usize = 24;

/// Represents the state of the IOAPIC.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoapicState {
    /// base_address is the memory base address for this IOAPIC. It cannot be changed.
    pub base_address: u64,
    /// ioregsel register. Used for selecting which entry of the redirect table to read/write.
    pub ioregsel: u8,
    /// ioapicid register. Bits 24 - 27 contain the APIC ID for this device.
    pub ioapicid: u32,
    /// current_interrupt_level_bitmap represents a bitmap of the state of all of the irq lines
    pub current_interrupt_level_bitmap: u32,
    /// redirect_table contains the irq settings for each irq line
    pub redirect_table: [IoapicRedirectionTableEntry; 24],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PicSelect {
    Primary = 0,
    Secondary = 1,
}

#[repr(C)]
#[derive(enumn::N, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PicInitState {
    Icw1 = 0,
    Icw2 = 1,
    Icw3 = 2,
    Icw4 = 3,
}

/// Convenience implementation for converting from a u8
impl From<u8> for PicInitState {
    fn from(item: u8) -> Self {
        PicInitState::n(item).unwrap_or_else(|| {
            error!("Invalid PicInitState {}, setting to 0", item);
            PicInitState::Icw1
        })
    }
}

impl Default for PicInitState {
    fn default() -> Self {
        PicInitState::Icw1
    }
}

/// Represents the state of the PIC.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct PicState {
    /// Edge detection.
    pub last_irr: u8,
    /// Interrupt Request Register.
    pub irr: u8,
    /// Interrupt Mask Register.
    pub imr: u8,
    /// Interrupt Service Register.
    pub isr: u8,
    /// Highest priority, for priority rotation.
    pub priority_add: u8,
    pub irq_base: u8,
    pub read_reg_select: bool,
    pub poll: bool,
    pub special_mask: bool,
    pub init_state: PicInitState,
    pub auto_eoi: bool,
    pub rotate_on_auto_eoi: bool,
    pub special_fully_nested_mode: bool,
    /// PIC takes either 3 or 4 bytes of initialization command word during
    /// initialization. use_4_byte_icw is true if 4 bytes of ICW are needed.
    pub use_4_byte_icw: bool,
    /// "Edge/Level Control Registers", for edge trigger selection.
    /// When a particular bit is set, the corresponding IRQ is in level-triggered mode. Otherwise it
    /// is in edge-triggered mode.
    pub elcr: u8,
    pub elcr_mask: u8,
}

/// The LapicState represents the state of an x86 CPU's Local APIC.
/// The Local APIC consists of 64 128-bit registers, but only the first 32-bits of each register
/// can be used, so this structure only stores the first 32-bits of each register.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LapicState {
    pub regs: [LapicRegister; 64],
}

pub type LapicRegister = u32;

// rust arrays longer than 32 need custom implementations of Debug
impl std::fmt::Debug for LapicState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.regs[..].fmt(formatter)
    }
}

// rust arrays longer than 32 need custom implementations of PartialEq
impl PartialEq for LapicState {
    fn eq(&self, other: &LapicState) -> bool {
        self.regs[..] == other.regs[..]
    }
}

// Lapic equality is reflexive, so we impl Eq
impl Eq for LapicState {}

/// The PitState represents the state of the PIT (aka the Programmable Interval Timer).
/// The state is simply the state of it's three channels.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PitState {
    pub channels: [PitChannelState; 3],
    /// Hypervisor-specific flags for setting the pit state.
    pub flags: u32,
}

/// The PitRWMode enum represents the access mode of a PIT channel.
/// Reads and writes to the Pit happen over Port-mapped I/O, which happens one byte at a time,
/// but the count values and latch values are two bytes. So the access mode controls which of the
/// two bytes will be read when.
#[repr(C)]
#[derive(enumn::N, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PitRWMode {
    /// None mode means that no access mode has been set.
    None = 0,
    /// Least mode means all reads/writes will read/write the least significant byte.
    Least = 1,
    /// Most mode means all reads/writes will read/write the most significant byte.
    Most = 2,
    /// Both mode means first the least significant byte will be read/written, then the
    /// next read/write will read/write the most significant byte.
    Both = 3,
}

/// Convenience implementation for converting from a u8
impl From<u8> for PitRWMode {
    fn from(item: u8) -> Self {
        PitRWMode::n(item).unwrap_or_else(|| {
            error!("Invalid PitRWMode value {}, setting to 0", item);
            PitRWMode::None
        })
    }
}

/// The PitRWState enum represents the state of reading to or writing from a channel.
/// This is related to the PitRWMode, it mainly gives more detail about the state of the channel
/// with respect to PitRWMode::Both.
#[repr(C)]
#[derive(enumn::N, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PitRWState {
    /// None mode means that no access mode has been set.
    None = 0,
    /// LSB means that the channel is in PitRWMode::Least access mode.
    LSB = 1,
    /// MSB means that the channel is in PitRWMode::Most access mode.
    MSB = 2,
    /// Word0 means that the channel is in PitRWMode::Both mode, and the least sginificant byte
    /// has not been read/written yet.
    Word0 = 3,
    /// Word1 means that the channel is in PitRWMode::Both mode and the least significant byte
    /// has already been read/written, and the next byte to be read/written will be the most
    /// significant byte.
    Word1 = 4,
}

/// Convenience implementation for converting from a u8
impl From<u8> for PitRWState {
    fn from(item: u8) -> Self {
        PitRWState::n(item).unwrap_or_else(|| {
            error!("Invalid PitRWState value {}, setting to 0", item);
            PitRWState::None
        })
    }
}

/// The PitChannelState represents the state of one of the PIT's three counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PitChannelState {
    /// The starting value for the counter.
    pub count: u32,
    /// Stores the channel count from the last time the count was latched.
    pub latched_count: u16,
    /// Indicates the PitRWState state of reading the latch value.
    pub count_latched: PitRWState,
    /// Indicates whether ReadBack status has been latched.
    pub status_latched: bool,
    /// Stores the channel status from the last time the status was latched. The status contains
    /// information about the access mode of this channel, but changing those bits in the status
    /// will not change the behavior of the pit.
    pub status: u8,
    /// Indicates the PitRWState state of reading the counter.
    pub read_state: PitRWState,
    /// Indicates the PitRWState state of writing the counter.
    pub write_state: PitRWState,
    /// Stores the value with which the counter was initialized. Counters are 16-
    /// bit values with an effective range of 1-65536 (65536 represented by 0).
    pub reload_value: u16,
    /// The command access mode of this channel.
    pub rw_mode: PitRWMode,
    /// The operation mode of this channel.
    pub mode: u8,
    /// Whether or not we are in bcd mode. Not supported by KVM or crosvm's PIT implementation.
    pub bcd: bool,
    /// Value of the gate input pin. This only applies to channel 2.
    pub gate: bool,
    /// Nanosecond timestamp of when the count value was loaded.
    pub count_load_time: u64,
}

// Convenience constructors for IrqRoutes
impl IrqRoute {
    pub fn ioapic_irq_route(irq_num: u32) -> IrqRoute {
        IrqRoute {
            gsi: irq_num,
            source: IrqSource::Irqchip {
                chip: IrqSourceChip::Ioapic,
                pin: irq_num,
            },
        }
    }

    pub fn pic_irq_route(id: IrqSourceChip, irq_num: u32) -> IrqRoute {
        IrqRoute {
            gsi: irq_num,
            source: IrqSource::Irqchip {
                chip: id,
                pin: irq_num % 8,
            },
        }
    }
}

/// State of a VCPU's general purpose registers.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Regs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// State of a memory segment.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Segment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
}

/// State of a global descriptor table or interrupt descriptor table.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct DescriptorTable {
    pub base: u64,
    pub limit: u16,
}

/// State of a VCPU's special registers.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Sregs {
    pub cs: Segment,
    pub ds: Segment,
    pub es: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub ss: Segment,
    pub tr: Segment,
    pub ldt: Segment,
    pub gdt: DescriptorTable,
    pub idt: DescriptorTable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,

    /// A bitmap of pending external interrupts.  At most one bit may be set.  This interrupt has
    /// been acknowledged by the APIC but not yet injected into the cpu core.
    pub interrupt_bitmap: [u64; 4usize],
}

/// State of a VCPU's floating point unit.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Fpu {
    pub fpr: [[u8; 16usize]; 8usize],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16usize]; 16usize],
    pub mxcsr: u32,
}

/// State of a VCPU's debug registers.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct DebugRegs {
    pub db: [u64; 4usize],
    pub dr6: u64,
    pub dr7: u64,
}

/// State of one VCPU register.  Currently used for MSRs and XCRs.
#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize)]
pub struct Register {
    pub id: u32,
    pub value: u64,
}
