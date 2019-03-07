// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use super::xhci_abi_schema::*;
use data_model::DataInit;
use std::fmt::{self, Display};

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

#[derive(Debug, PartialEq)]
pub enum Error {
    UnknownTrbType(u8),
    UnknownCompletionCode(u8),
    UnknownDeviceSlotState(u8),
    UnknownEndpointState(u8),
    CannotCastTrb,
}

type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            UnknownTrbType(v) => write!(f, "we got an unknown trb type value: {}", v),
            UnknownCompletionCode(v) => write!(f, "we got an unknown trb completion code: {}", v),
            UnknownDeviceSlotState(v) => write!(f, "we got and unknown device slot state: {}", v),
            UnknownEndpointState(v) => write!(f, "we got and unknown endpoint state: {}", v),
            CannotCastTrb => write!(f, "cannot cast trb from raw memory"),
        }
    }
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
            .trb_type()?
            != T::TY
        {
            return Err(Error::CannotCastTrb);
        }
        T::from_slice(self.as_slice()).ok_or(Error::CannotCastTrb)
    }

    fn checked_mut_cast<T: TrbCast>(&mut self) -> Result<&mut T> {
        if Trb::from_slice(self.as_slice())
            .ok_or(Error::CannotCastTrb)?
            .trb_type()?
            != T::TY
        {
            return Err(Error::CannotCastTrb);
        }
        T::from_mut_slice(self.as_mut_slice()).ok_or(Error::CannotCastTrb)
    }
}

impl Trb {
    fn fmt_helper(&self, f: &mut fmt::Formatter) -> Result<fmt::Result> {
        match self.trb_type()? {
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
    /// Get trb type.
    pub fn trb_type(&self) -> Result<TrbType> {
        TrbType::from_raw(self.get_trb_type())
    }

    /// Get cycle bit.
    pub fn get_cycle_bit(&self) -> bool {
        self.get_cycle() != 0
    }

    /// Set cyle bit.
    pub fn set_cycle_bit(&mut self, b: bool) {
        match b {
            true => self.set_cycle(1u8),
            false => self.set_cycle(0u8),
        }
    }

    /// Get chain bit.
    pub fn get_chain_bit(&self) -> Result<bool> {
        Ok(match self.trb_type() {
            Ok(TrbType::Normal) => self.cast::<NormalTrb>()?.get_chain() != 0,
            Ok(TrbType::DataStage) => self.cast::<DataStageTrb>()?.get_chain() != 0,
            Ok(TrbType::StatusStage) => self.cast::<StatusStageTrb>()?.get_chain() != 0,
            Ok(TrbType::Isoch) => self.cast::<IsochTrb>()?.get_chain() != 0,
            Ok(TrbType::Noop) => self.cast::<NoopTrb>()?.get_chain() != 0,
            Ok(TrbType::Link) => self.cast::<LinkTrb>()?.get_chain() != 0,
            Ok(TrbType::EventData) => self.cast::<EventDataTrb>()?.get_chain() != 0,
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
        match self.trb_type()? {
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
        match self.trb_type()? {
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

    /// Returns true if this trb is immediate data.
    pub fn immediate_data(&self) -> Result<bool> {
        const FLAGS_IMMEDIATE_DATA_MASK: u16 = 0x20;
        match self.trb_type()? {
            TrbType::Normal | TrbType::SetupStage | TrbType::DataStage | TrbType::Isoch => {
                Ok((self.get_flags() & FLAGS_IMMEDIATE_DATA_MASK) != 0)
            }
            _ => Ok(false),
        }
    }
}

impl LinkTrb {
    /// Get cycle.
    pub fn get_cycle_bit(&self) -> bool {
        self.get_cycle() != 0
    }

    /// Get toggle cycle.
    pub fn get_toggle_cycle_bit(&self) -> bool {
        self.get_toggle_cycle() != 0
    }

    /// set chain status.
    pub fn set_chain_bit(&mut self, v: bool) {
        self.set_chain(v as u8);
    }

    /// Get chain status.
    pub fn get_chain_bit(&self) -> bool {
        self.get_chain() != 0
    }

    /// Get interrupt on completion.
    pub fn interrupt_on_completion(&self) -> bool {
        self.get_interrupt_on_completion() != 0
    }
}

/// Trait for enum that could be converted from raw u8.
pub trait PrimitiveTrbEnum: Sized {
    fn from_raw(val: u8) -> Result<Self>;
}

/// All kinds of trb.
#[derive(PartialEq, Debug)]
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

impl PrimitiveTrbEnum for TrbType {
    fn from_raw(val: u8) -> Result<Self> {
        match val {
            0 => Ok(TrbType::Reserved),
            1 => Ok(TrbType::Normal),
            2 => Ok(TrbType::SetupStage),
            3 => Ok(TrbType::DataStage),
            4 => Ok(TrbType::StatusStage),
            5 => Ok(TrbType::Isoch),
            6 => Ok(TrbType::Link),
            7 => Ok(TrbType::EventData),
            8 => Ok(TrbType::Noop),
            9 => Ok(TrbType::EnableSlotCommand),
            10 => Ok(TrbType::DisableSlotCommand),
            11 => Ok(TrbType::AddressDeviceCommand),
            12 => Ok(TrbType::ConfigureEndpointCommand),
            13 => Ok(TrbType::EvaluateContextCommand),
            14 => Ok(TrbType::ResetEndpointCommand),
            15 => Ok(TrbType::StopEndpointCommand),
            16 => Ok(TrbType::SetTRDequeuePointerCommand),
            17 => Ok(TrbType::ResetDeviceCommand),
            23 => Ok(TrbType::NoopCommand),
            32 => Ok(TrbType::TransferEvent),
            33 => Ok(TrbType::CommandCompletionEvent),
            34 => Ok(TrbType::PortStatusChangeEvent),
            v => Err(Error::UnknownTrbType(v)),
        }
    }
}

/// Completion code of trb types.
pub enum TrbCompletionCode {
    Success = 1,
    TransactionError = 4,
    TrbError = 5,
    NoSlotsAvailableError = 9,
    SlotNotEnabledError = 11,
    ShortPacket = 13,
    ContextStateError = 19,
}

impl PrimitiveTrbEnum for TrbCompletionCode {
    fn from_raw(val: u8) -> Result<Self> {
        match val {
            1 => Ok(TrbCompletionCode::Success),
            4 => Ok(TrbCompletionCode::TransactionError),
            5 => Ok(TrbCompletionCode::TrbError),
            9 => Ok(TrbCompletionCode::NoSlotsAvailableError),
            11 => Ok(TrbCompletionCode::SlotNotEnabledError),
            13 => Ok(TrbCompletionCode::ShortPacket),
            19 => Ok(TrbCompletionCode::ContextStateError),
            v => Err(Error::UnknownCompletionCode(v)),
        }
    }
}

/// State of device slot.
#[derive(PartialEq, Debug)]
pub enum DeviceSlotState {
    // The same value (0) is used for both the enabled and disabled states. See
    // xhci spec table 60.
    DisabledOrEnabled = 0,
    Default = 1,
    Addressed = 2,
    Configured = 3,
}

impl PrimitiveTrbEnum for DeviceSlotState {
    fn from_raw(val: u8) -> Result<Self> {
        match val {
            0 => Ok(DeviceSlotState::DisabledOrEnabled),
            1 => Ok(DeviceSlotState::Default),
            2 => Ok(DeviceSlotState::Addressed),
            3 => Ok(DeviceSlotState::Configured),
            v => Err(Error::UnknownDeviceSlotState(v)),
        }
    }
}

impl SlotContext {
    /// Set slot context state.
    pub fn state(&self) -> Result<DeviceSlotState> {
        DeviceSlotState::from_raw(self.get_slot_state())
    }

    /// Get slot context state.
    pub fn set_state(&mut self, state: DeviceSlotState) {
        self.set_slot_state(state as u8);
    }
}

/// State of endpoint.
pub enum EndpointState {
    Disabled = 0,
    Running = 1,
}

impl PrimitiveTrbEnum for EndpointState {
    fn from_raw(val: u8) -> Result<Self> {
        match val {
            0 => Ok(EndpointState::Disabled),
            1 => Ok(EndpointState::Running),
            v => Err(Error::UnknownEndpointState(v)),
        }
    }
}

impl EndpointContext {
    /// Get endpoint context state.
    pub fn state(&self) -> Result<EndpointState> {
        EndpointState::from_raw(self.get_endpoint_state())
    }

    /// Set endpoint context state.
    pub fn set_state(&mut self, state: EndpointState) {
        self.set_endpoint_state(state as u8);
    }
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
