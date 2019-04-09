// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use bit_field::Error as BitFieldError;
use bit_field::*;
use data_model::DataInit;
use std::fmt::{self, Display};
use sys_util::GuestAddress;

use std;

#[derive(Debug)]
pub enum Error {
    UnknownTrbType(BitFieldError),
    CannotCastTrb,
}

type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            UnknownTrbType(e) => write!(f, "we got an unknown trb type value: {}", e),
            CannotCastTrb => write!(f, "cannot cast trb from raw memory"),
        }
    }
}

// Fixed size of all TRB types.
const TRB_SIZE: usize = 16;

// Size of segment table.
const SEGMENT_TABLE_SIZE: usize = 16;

/// All kinds of trb.
#[bitfield]
#[bits = 6]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum TrbType {
    Reserved = 0,
    Normal = 1,
    SetupStage = 2,
    DataStage = 3,
    StatusStage = 4,
    Isoch = 5,
    Link = 6,
    EventData = 7,
    Noop = 8,
    EnableSlotCommand = 9,
    DisableSlotCommand = 10,
    AddressDeviceCommand = 11,
    ConfigureEndpointCommand = 12,
    EvaluateContextCommand = 13,
    ResetEndpointCommand = 14,
    StopEndpointCommand = 15,
    SetTRDequeuePointerCommand = 16,
    ResetDeviceCommand = 17,
    NoopCommand = 23,
    TransferEvent = 32,
    CommandCompletionEvent = 33,
    PortStatusChangeEvent = 34,
}

/// Completion code of trb types.
#[bitfield]
#[bits = 8]
#[derive(PartialEq, Debug)]
pub enum TrbCompletionCode {
    Success = 1,
    TransactionError = 4,
    TrbError = 5,
    NoSlotsAvailableError = 9,
    SlotNotEnabledError = 11,
    ShortPacket = 13,
    ContextStateError = 19,
}

/// State of device slot.
#[bitfield]
#[bits = 5]
#[derive(PartialEq, Debug)]
pub enum DeviceSlotState {
    // The same value (0) is used for both the enabled and disabled states. See
    // xhci spec table 60.
    DisabledOrEnabled = 0,
    Default = 1,
    Addressed = 2,
    Configured = 3,
}

/// State of endpoint.
#[bitfield]
#[bits = 3]
#[derive(PartialEq, Debug)]
pub enum EndpointState {
    Disabled = 0,
    Running = 1,
}

#[bitfield]
#[bits = 60]
#[derive(PartialEq, Debug)]
pub struct DequeuePtr(u64);

impl DequeuePtr {
    pub fn new(addr: GuestAddress) -> Self {
        DequeuePtr(addr.0 >> 4)
    }

    // Get the guest physical address.
    pub fn get_gpa(&self) -> GuestAddress {
        GuestAddress(self.0 << 4)
    }
}

// Generic TRB struct containing only fields common to all types.
#[bitfield]
#[derive(Clone, Copy, PartialEq)]
pub struct Trb {
    parameter: B64,
    status: B32,
    cycle: bool,
    flags: B9,
    trb_type: TrbType,
    control: B16,
}

impl Trb {
    fn fmt_helper(&self, f: &mut fmt::Formatter) -> Result<fmt::Result> {
        match self.get_trb_type().map_err(Error::UnknownTrbType)? {
            TrbType::Reserved => Ok(write!(f, "reserved trb type")),
            TrbType::Normal => {
                let t = self.cast::<NormalTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::SetupStage => {
                let t = self.cast::<SetupStageTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::DataStage => {
                let t = self.cast::<DataStageTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::StatusStage => {
                let t = self.cast::<StatusStageTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::Isoch => {
                let t = self.cast::<IsochTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::Link => {
                let t = self.cast::<LinkTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::EventData => {
                let t = self.cast::<EventDataTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::Noop => {
                let t = self.cast::<NoopTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::EnableSlotCommand => Ok(write!(f, "trb: enable slot command {:?}", self)),
            TrbType::DisableSlotCommand => {
                let t = self.cast::<DisableSlotCommandTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::AddressDeviceCommand => {
                let t = self.cast::<AddressDeviceCommandTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::ConfigureEndpointCommand => {
                let t = self.cast::<ConfigureEndpointCommandTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::EvaluateContextCommand => {
                let t = self.cast::<EvaluateContextCommandTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::ResetEndpointCommand => {
                let t = self.cast::<ResetEndpointCommandTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::StopEndpointCommand => {
                let t = self.cast::<StopEndpointCommandTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::SetTRDequeuePointerCommand => {
                let t = self.cast::<SetTRDequeuePointerCommandTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::ResetDeviceCommand => {
                let t = self.cast::<ResetDeviceCommandTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::NoopCommand => Ok(write!(f, "trb: noop command {:?}", self)),
            TrbType::TransferEvent => {
                let t = self.cast::<TransferEventTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::CommandCompletionEvent => {
                let t = self.cast::<CommandCompletionEventTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
            TrbType::PortStatusChangeEvent => {
                let t = self.cast::<PortStatusChangeEventTrb>()?;
                Ok(write!(f, "trb: {:?}", t))
            }
        }
    }
}

impl Display for Trb {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.fmt_helper(f) {
            Ok(f) => f,
            Err(e) => write!(f, "fail to format trb {}", e),
        }
    }
}

impl Trb {
    /// Get chain bit.
    pub fn get_chain_bit(&self) -> Result<bool> {
        Ok(match self.get_trb_type() {
            Ok(TrbType::Normal) => self.cast::<NormalTrb>()?.get_chain(),
            Ok(TrbType::DataStage) => self.cast::<DataStageTrb>()?.get_chain(),
            Ok(TrbType::StatusStage) => self.cast::<StatusStageTrb>()?.get_chain(),
            Ok(TrbType::Isoch) => self.cast::<IsochTrb>()?.get_chain(),
            Ok(TrbType::Noop) => self.cast::<NoopTrb>()?.get_chain(),
            Ok(TrbType::Link) => self.cast::<LinkTrb>()?.get_chain(),
            Ok(TrbType::EventData) => self.cast::<EventDataTrb>()?.get_chain(),
            _ => false,
        })
    }

    /// Get interrupt target.
    pub fn interrupter_target(&self) -> u8 {
        const STATUS_INTERRUPTER_TARGET_OFFSET: u8 = 22;
        (self.get_status() >> STATUS_INTERRUPTER_TARGET_OFFSET) as u8
    }

    /// Only some of trb types could appear in transfer ring.
    pub fn can_be_in_transfer_ring(&self) -> Result<bool> {
        match self.get_trb_type().map_err(Error::UnknownTrbType)? {
            TrbType::Normal
            | TrbType::SetupStage
            | TrbType::DataStage
            | TrbType::StatusStage
            | TrbType::Isoch
            | TrbType::Link
            | TrbType::EventData
            | TrbType::Noop => Ok(true),
            _ => Ok(false),
        }
    }

    /// Length of this transfer.
    pub fn transfer_length(&self) -> Result<u32> {
        const STATUS_TRANSFER_LENGTH_MASK: u32 = 0x1ffff;
        match self.get_trb_type().map_err(Error::UnknownTrbType)? {
            TrbType::Normal | TrbType::SetupStage | TrbType::DataStage | TrbType::Isoch => {
                Ok(self.get_status() & STATUS_TRANSFER_LENGTH_MASK)
            }
            _ => Ok(0),
        }
    }

    /// Returns true if interrupt is required on completion.
    pub fn interrupt_on_completion(&self) -> bool {
        const FLAGS_INTERRUPT_ON_COMPLETION_MASK: u16 = 0x10;
        (self.get_flags() & FLAGS_INTERRUPT_ON_COMPLETION_MASK) > 0
    }

    /// Returns true if interrupt is required on transfer of short packet.
    pub fn interrupt_on_short_packet(&self) -> bool {
        const FLAGS_INTERRUPT_ON_SHORT_PACKET: u16 = 0x2;
        (self.get_flags() & FLAGS_INTERRUPT_ON_SHORT_PACKET) > 0
    }

    /// Returns true if this trb is immediate data.
    pub fn immediate_data(&self) -> Result<bool> {
        const FLAGS_IMMEDIATE_DATA_MASK: u16 = 0x20;
        match self.get_trb_type().map_err(Error::UnknownTrbType)? {
            TrbType::Normal | TrbType::SetupStage | TrbType::DataStage | TrbType::Isoch => {
                Ok((self.get_flags() & FLAGS_IMMEDIATE_DATA_MASK) != 0)
            }
            _ => Ok(false),
        }
    }
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct NormalTrb {
    data_buffer: B64,
    trb_transfer_length: B17,
    td_size: B5,
    interrupter_target: B10,
    cycle: bool,
    evaluate_next_trb: B1,
    interrupt_on_short_packet: B1,
    no_snoop: B1,
    chain: bool,
    interrupt_on_completion: B1,
    immediate_data: B1,
    reserved: B2,
    block_event_interrupt: B1,
    trb_type: TrbType,
    reserved1: B16,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct SetupStageTrb {
    request_type: B8,
    request: B8,
    value: B16,
    index: B16,
    length: B16,
    trb_transfer_length: B17,
    reserved0: B5,
    interrupter_target: B10,
    cycle: bool,
    reserved1: B4,
    interrupt_on_completion: B1,
    immediate_data: B1,
    reserved2: B3,
    trb_type: TrbType,
    transfer_type: B2,
    reserved3: B14,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct DataStageTrb {
    data_buffer_pointer: B64,
    trb_transfer_length: B17,
    td_size: B5,
    interrupter_target: B10,
    cycle: bool,
    evaluate_next_trb: B1,
    interrupt_on_short_packet: B1,
    no_snoop: B1,
    chain: bool,
    interrupt_on_completion: B1,
    immediate_data: B1,
    reserved0: B3,
    trb_type: TrbType,
    direction: B1,
    reserved1: B15,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct StatusStageTrb {
    reserved0: B64,
    reserved1: B22,
    interrupter_target: B10,
    cycle: bool,
    evaluate_next_trb: B1,
    reserved2: B2,
    chain: bool,
    interrupt_on_completion: B1,
    reserved3: B4,
    trb_type: TrbType,
    direction: B1,
    reserved4: B15,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct IsochTrb {
    data_buffer_pointer: B64,
    trb_transfer_length: B17,
    td_size: B5,
    interrupter_target: B10,
    cycle: bool,
    evaulate_nex_trb: B1,
    interrupt_on_short_packet: B1,
    no_snoop: B1,
    chain: bool,
    interrupt_on_completion: B1,
    immediate_data: B1,
    transfer_burst_count: B2,
    block_event_interrupt: B1,
    trb_type: TrbType,
    tlbpc: B4,
    frame_id: B11,
    sia: B1,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct LinkTrb {
    ring_segment_pointer: B64,
    reserved0: B22,
    interrupter_target: B10,
    cycle: bool,
    toggle_cycle: bool,
    reserved1: B2,
    chain: bool,
    interrupt_on_completion: bool,
    reserved2: B4,
    trb_type: TrbType,
    reserved3: B16,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct EventDataTrb {
    event_data: B64,
    reserved0: B22,
    interrupter_target: B10,
    cycle: bool,
    evaluate_next_trb: B1,
    reserved1: B2,
    chain: bool,
    interrupt_on_completion: B1,
    reserved2: B3,
    block_event_interrupt: B1,
    trb_type: TrbType,
    reserved3: B16,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct NoopTrb {
    reserved0: B64,
    reserved1: B22,
    interrupter_target: B10,
    cycle: bool,
    evaluate_next_trb: B1,
    reserved2: B2,
    chain: bool,
    interrupt_on_completion: B1,
    reserved3: B4,
    trb_type: TrbType,
    reserved4: B16,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct DisableSlotCommandTrb {
    reserved0: B32,
    reserved1: B32,
    reserved2: B32,
    cycle: bool,
    reserved3: B9,
    trb_type: TrbType,
    reserved4: B8,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct AddressDeviceCommandTrb {
    input_context_pointer: B64,
    reserved: B32,
    cycle: bool,
    reserved2: B8,
    block_set_address_request: bool,
    trb_type: TrbType,
    reserved3: B8,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct ConfigureEndpointCommandTrb {
    input_context_pointer: B64,
    reserved0: B32,
    cycle: bool,
    reserved1: B8,
    deconfigure: bool,
    trb_type: TrbType,
    reserved2: B8,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct EvaluateContextCommandTrb {
    input_context_pointer: B64,
    reserved0: B32,
    cycle: bool,
    reserved1: B9,
    trb_type: TrbType,
    reserved2: B8,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct ResetEndpointCommandTrb {
    reserved0: B32,
    reserved1: B32,
    reserved2: B32,
    cycle: bool,
    reserved3: B8,
    transfer_state_preserve: B1,
    trb_type: TrbType,
    endpoint_id: B5,
    reserved4: B3,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct StopEndpointCommandTrb {
    reserved0: B32,
    reserved1: B32,
    reserved2: B32,
    cycle: bool,
    reserved3: B9,
    trb_type: TrbType,
    endpoint_id: B5,
    reserved4: B2,
    suspend: B1,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct SetTRDequeuePointerCommandTrb {
    dequeue_cycle_state: bool,
    stream_context_type: B3,
    dequeue_ptr: DequeuePtr,
    reserved0: B16,
    stream_id: B16,
    cycle: bool,
    reserved1: B9,
    trb_type: TrbType,
    endpoint_id: B5,
    reserved3: B2,
    suspend: B1,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct ResetDeviceCommandTrb {
    reserved0: B32,
    reserved1: B32,
    reserved2: B32,
    cycle: bool,
    reserved3: B9,
    trb_type: TrbType,
    reserved4: B8,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct TransferEventTrb {
    trb_pointer: B64,
    trb_transfer_length: B24,
    completion_code: TrbCompletionCode,
    cycle: bool,
    reserved0: B1,
    event_data: B1,
    reserved1: B7,
    trb_type: TrbType,
    endpoint_id: B5,
    reserved2: B3,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct CommandCompletionEventTrb {
    trb_pointer: B64,
    command_completion_parameter: B24,
    completion_code: TrbCompletionCode,
    cycle: bool,
    reserved: B9,
    trb_type: TrbType,
    vf_id: B8,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct PortStatusChangeEventTrb {
    reserved0: B24,
    port_id: B8,
    reserved1: B32,
    reserved2: B24,
    completion_code: TrbCompletionCode,
    cycle: bool,
    reserved3: B9,
    trb_type: TrbType,
    reserved4: B16,
}

/// Associate real type of trb.
pub trait TypedTrb {
    const TY: TrbType;
}

impl TypedTrb for Trb {
    const TY: TrbType = TrbType::Reserved;
}

impl TypedTrb for NormalTrb {
    const TY: TrbType = TrbType::Normal;
}

impl TypedTrb for SetupStageTrb {
    const TY: TrbType = TrbType::SetupStage;
}

impl TypedTrb for DataStageTrb {
    const TY: TrbType = TrbType::DataStage;
}

impl TypedTrb for StatusStageTrb {
    const TY: TrbType = TrbType::StatusStage;
}

impl TypedTrb for IsochTrb {
    const TY: TrbType = TrbType::Isoch;
}

impl TypedTrb for LinkTrb {
    const TY: TrbType = TrbType::Link;
}

impl TypedTrb for EventDataTrb {
    const TY: TrbType = TrbType::EventData;
}

impl TypedTrb for NoopTrb {
    const TY: TrbType = TrbType::Noop;
}

impl TypedTrb for DisableSlotCommandTrb {
    const TY: TrbType = TrbType::DisableSlotCommand;
}

impl TypedTrb for AddressDeviceCommandTrb {
    const TY: TrbType = TrbType::AddressDeviceCommand;
}

impl TypedTrb for ConfigureEndpointCommandTrb {
    const TY: TrbType = TrbType::ConfigureEndpointCommand;
}

impl TypedTrb for EvaluateContextCommandTrb {
    const TY: TrbType = TrbType::EvaluateContextCommand;
}

impl TypedTrb for ResetEndpointCommandTrb {
    const TY: TrbType = TrbType::ResetEndpointCommand;
}

impl TypedTrb for StopEndpointCommandTrb {
    const TY: TrbType = TrbType::StopEndpointCommand;
}

impl TypedTrb for SetTRDequeuePointerCommandTrb {
    const TY: TrbType = TrbType::SetTRDequeuePointerCommand;
}

impl TypedTrb for ResetDeviceCommandTrb {
    const TY: TrbType = TrbType::ResetDeviceCommand;
}

impl TypedTrb for TransferEventTrb {
    const TY: TrbType = TrbType::TransferEvent;
}

impl TypedTrb for CommandCompletionEventTrb {
    const TY: TrbType = TrbType::CommandCompletionEvent;
}

impl TypedTrb for PortStatusChangeEventTrb {
    const TY: TrbType = TrbType::PortStatusChangeEvent;
}

/// All trb structs have the same size. One trb could be safely casted to another, though the
/// values might be invalid.
pub unsafe trait TrbCast: DataInit + TypedTrb {
    fn cast<T: TrbCast>(&self) -> Result<&T> {
        T::from_slice(self.as_slice()).ok_or(Error::CannotCastTrb)
    }

    fn cast_mut<T: TrbCast>(&mut self) -> Result<&mut T> {
        T::from_mut_slice(self.as_mut_slice()).ok_or(Error::CannotCastTrb)
    }

    fn checked_cast<T: TrbCast>(&self) -> Result<&T> {
        if Trb::from_slice(self.as_slice())
            .ok_or(Error::CannotCastTrb)?
            .get_trb_type()
            .map_err(Error::UnknownTrbType)?
            != T::TY
        {
            return Err(Error::CannotCastTrb);
        }
        T::from_slice(self.as_slice()).ok_or(Error::CannotCastTrb)
    }

    fn checked_mut_cast<T: TrbCast>(&mut self) -> Result<&mut T> {
        if Trb::from_slice(self.as_slice())
            .ok_or(Error::CannotCastTrb)?
            .get_trb_type()
            .map_err(Error::UnknownTrbType)?
            != T::TY
        {
            return Err(Error::CannotCastTrb);
        }
        T::from_mut_slice(self.as_mut_slice()).ok_or(Error::CannotCastTrb)
    }
}

unsafe impl DataInit for Trb {}
unsafe impl DataInit for NormalTrb {}
unsafe impl DataInit for SetupStageTrb {}
unsafe impl DataInit for DataStageTrb {}
unsafe impl DataInit for StatusStageTrb {}
unsafe impl DataInit for IsochTrb {}
unsafe impl DataInit for LinkTrb {}
unsafe impl DataInit for EventDataTrb {}
unsafe impl DataInit for NoopTrb {}
unsafe impl DataInit for DisableSlotCommandTrb {}
unsafe impl DataInit for AddressDeviceCommandTrb {}
unsafe impl DataInit for ConfigureEndpointCommandTrb {}
unsafe impl DataInit for EvaluateContextCommandTrb {}
unsafe impl DataInit for ResetEndpointCommandTrb {}
unsafe impl DataInit for StopEndpointCommandTrb {}
unsafe impl DataInit for SetTRDequeuePointerCommandTrb {}
unsafe impl DataInit for ResetDeviceCommandTrb {}
unsafe impl DataInit for TransferEventTrb {}
unsafe impl DataInit for CommandCompletionEventTrb {}
unsafe impl DataInit for PortStatusChangeEventTrb {}
unsafe impl DataInit for EventRingSegmentTableEntry {}
unsafe impl DataInit for InputControlContext {}
unsafe impl DataInit for SlotContext {}
unsafe impl DataInit for EndpointContext {}

unsafe impl DataInit for DeviceContext {}
unsafe impl DataInit for AddressedTrb {}

unsafe impl TrbCast for Trb {}
unsafe impl TrbCast for NormalTrb {}
unsafe impl TrbCast for SetupStageTrb {}
unsafe impl TrbCast for DataStageTrb {}
unsafe impl TrbCast for StatusStageTrb {}
unsafe impl TrbCast for IsochTrb {}
unsafe impl TrbCast for LinkTrb {}
unsafe impl TrbCast for EventDataTrb {}
unsafe impl TrbCast for NoopTrb {}
unsafe impl TrbCast for DisableSlotCommandTrb {}
unsafe impl TrbCast for AddressDeviceCommandTrb {}
unsafe impl TrbCast for ConfigureEndpointCommandTrb {}
unsafe impl TrbCast for EvaluateContextCommandTrb {}
unsafe impl TrbCast for ResetEndpointCommandTrb {}
unsafe impl TrbCast for StopEndpointCommandTrb {}
unsafe impl TrbCast for SetTRDequeuePointerCommandTrb {}
unsafe impl TrbCast for ResetDeviceCommandTrb {}
unsafe impl TrbCast for TransferEventTrb {}
unsafe impl TrbCast for CommandCompletionEventTrb {}
unsafe impl TrbCast for PortStatusChangeEventTrb {}

#[bitfield]
#[derive(Clone, Copy)]
pub struct EventRingSegmentTableEntry {
    ring_segment_base_address: B64,
    ring_segment_size: B16,
    reserved2: B48,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct InputControlContext {
    // Xhci spec 6.2.5.1.
    drop_context_flags: B32,
    add_context_flags: B32,
    reserved0: B32,
    reserved1: B32,
    reserved2: B32,
    reserved3: B32,
    reserved4: B32,
    configuration_value: B8,
    interface_number: B8,
    alternate_setting: B8,
    reserved5: B8,
}

impl InputControlContext {
    /// Get drop context flag.
    pub fn drop_context_flag(&self, idx: u8) -> bool {
        (self.get_drop_context_flags() & (1 << idx)) != 0
    }

    /// Get add context flag.
    pub fn add_context_flag(&self, idx: u8) -> bool {
        (self.get_add_context_flags() & (1 << idx)) != 0
    }
}

// Size of device context entries (SlotContext and EndpointContext).
pub const DEVICE_CONTEXT_ENTRY_SIZE: usize = 32usize;

#[bitfield]
#[derive(Clone, Copy)]
pub struct SlotContext {
    route_string: B20,
    speed: B4,
    reserved1: B1,
    mtt: B1,
    hub: B1,
    context_entries: B5,
    max_exit_latency: B16,
    root_hub_port_number: B8,
    num_ports: B8,
    tt_hub_slot_id: B8,
    tt_port_number: B8,
    tt_think_time: B2,
    reserved2: B4,
    interrupter_target: B10,
    usb_device_address: B8,
    reserved3: B19,
    slot_state: DeviceSlotState,
    reserved4: B32,
    reserved5: B32,
    reserved6: B32,
    reserved7: B32,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct EndpointContext {
    endpoint_state: EndpointState,
    reserved1: B5,
    mult: B2,
    max_primary_streams: B5,
    linear_stream_array: B1,
    interval: B8,
    max_esit_payload_hi: B8,
    reserved2: B1,
    error_count: B2,
    endpoint_type: B3,
    reserved3: B1,
    host_initiate_disable: B1,
    max_burst_size: B8,
    max_packet_size: B16,
    dequeue_cycle_state: bool,
    reserved4: B3,
    tr_dequeue_pointer: DequeuePtr,
    average_trb_length: B16,
    max_esit_payload_lo: B16,
    reserved5: B32,
    reserved6: B32,
    reserved7: B32,
}

/// Device context.
#[derive(Clone, Copy, Debug)]
pub struct DeviceContext {
    pub slot_context: SlotContext,
    pub endpoint_context: [EndpointContext; 31],
}

/// POD struct associates a TRB with its address in guest memory.  This is
/// useful because transfer and command completion event TRBs must contain
/// pointers to the original TRB that generated the event.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AddressedTrb {
    pub trb: Trb,
    pub gpa: u64,
}

pub type TransferDescriptor = Vec<AddressedTrb>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_struct_sizes() {
        assert_eq!(std::mem::size_of::<Trb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<NormalTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<SetupStageTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<DataStageTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<StatusStageTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<IsochTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<LinkTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<EventDataTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<NoopTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<DisableSlotCommandTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<AddressDeviceCommandTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<ConfigureEndpointCommandTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<EvaluateContextCommandTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<ResetEndpointCommandTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<StopEndpointCommandTrb>(), TRB_SIZE);
        assert_eq!(
            std::mem::size_of::<SetTRDequeuePointerCommandTrb>(),
            TRB_SIZE
        );
        assert_eq!(std::mem::size_of::<ResetDeviceCommandTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<TransferEventTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<CommandCompletionEventTrb>(), TRB_SIZE);
        assert_eq!(std::mem::size_of::<PortStatusChangeEventTrb>(), TRB_SIZE);

        assert_eq!(
            std::mem::size_of::<EventRingSegmentTableEntry>(),
            SEGMENT_TABLE_SIZE
        );
        assert_eq!(std::mem::size_of::<InputControlContext>(), 32);
        assert_eq!(
            std::mem::size_of::<SlotContext>(),
            DEVICE_CONTEXT_ENTRY_SIZE
        );
        assert_eq!(
            std::mem::size_of::<EndpointContext>(),
            DEVICE_CONTEXT_ENTRY_SIZE
        );
        assert_eq!(
            std::mem::size_of::<DeviceContext>(),
            32 * DEVICE_CONTEXT_ENTRY_SIZE
        );
    }
}
