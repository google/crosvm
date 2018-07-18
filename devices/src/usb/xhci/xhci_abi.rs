// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use super::xhci_abi_schema::*;
use data_model::DataInit;
use std;

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

/// All trb structs have the same size. One trb could be safely casted to another, though the
/// values might be invalid.
pub unsafe trait TrbCast: DataInit + TypedTrb {
    fn cast<T: TrbCast>(&self) -> &T {
        T::from_slice(self.as_slice()).unwrap()
    }

    fn cast_mut<T: TrbCast>(&mut self) -> &mut T {
        T::from_mut_slice(self.as_mut_slice()).unwrap()
    }

    fn checked_cast<T: TrbCast>(&self) -> Option<&T> {
        if Trb::from_slice(self.as_slice())
            .unwrap()
            .trb_type()
            .unwrap()
            != T::TY
        {
            return None;
        }
        Some(T::from_slice(self.as_slice()).unwrap())
    }

    fn checked_mut_cast<T: TrbCast>(&mut self) -> Option<&mut T> {
        if Trb::from_slice(self.as_slice())
            .unwrap()
            .trb_type()
            .unwrap()
            != T::TY
        {
            return None;
        }
        Some(T::from_mut_slice(self.as_mut_slice()).unwrap())
    }
}

impl Trb {
    /// Get trb type.
    pub fn trb_type(&self) -> Option<TrbType> {
        TrbType::from_raw(self.get_trb_type())
    }

    /// Get debug string, the string will be printed with correct trb type and
    /// fields.
    pub fn debug_str(&self) -> String {
        let trb_type = match self.trb_type() {
            None => return format!("unexpected trb type: {:?}", self),
            Some(t) => t,
        };
        match trb_type {
            TrbType::Reserved => format!("reserved trb type"),
            TrbType::Normal => {
                let t = self.cast::<NormalTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::SetupStage => {
                let t = self.cast::<SetupStageTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::DataStage => {
                let t = self.cast::<DataStageTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::StatusStage => {
                let t = self.cast::<StatusStageTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::Isoch => {
                let t = self.cast::<IsochTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::Link => {
                let t = self.cast::<LinkTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::EventData => {
                let t = self.cast::<EventDataTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::Noop => {
                let t = self.cast::<NoopTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::EnableSlotCommand => format!("trb: enable slot command {:?}", self),
            TrbType::DisableSlotCommand => {
                let t = self.cast::<DisableSlotCommandTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::AddressDeviceCommand => {
                let t = self.cast::<AddressDeviceCommandTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::ConfigureEndpointCommand => {
                let t = self.cast::<ConfigureEndpointCommandTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::EvaluateContextCommand => {
                let t = self.cast::<EvaluateContextCommandTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::ResetEndpointCommand => {
                let t = self.cast::<ResetEndpointCommandTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::StopEndpointCommand => {
                let t = self.cast::<StopEndpointCommandTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::SetTRDequeuePointerCommand => {
                let t = self.cast::<SetTRDequeuePointerCommandTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::ResetDeviceCommand => {
                let t = self.cast::<ResetDeviceCommandTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::NoopCommand => format!("trb: noop command {:?}", self),
            TrbType::TransferEvent => {
                let t = self.cast::<TransferEventTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::CommandCompletionEvent => {
                let t = self.cast::<CommandCompletionEventTrb>();
                format!("trb: {:?}", t)
            }
            TrbType::PortStatusChangeEvent => {
                let t = self.cast::<PortStatusChangeEventTrb>();
                format!("trb: {:?}", t)
            }
        }
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
    pub fn get_chain_bit(&self) -> bool {
        match self.trb_type() {
            Some(TrbType::Normal) => self.cast::<NormalTrb>().get_chain() != 0,
            Some(TrbType::DataStage) => self.cast::<DataStageTrb>().get_chain() != 0,
            Some(TrbType::StatusStage) => self.cast::<StatusStageTrb>().get_chain() != 0,
            Some(TrbType::Isoch) => self.cast::<IsochTrb>().get_chain() != 0,
            Some(TrbType::Noop) => self.cast::<NoopTrb>().get_chain() != 0,
            Some(TrbType::Link) => self.cast::<LinkTrb>().get_chain() != 0,
            Some(TrbType::EventData) => self.cast::<EventDataTrb>().get_chain() != 0,
            _ => false,
        }
    }

    /// Get interrupt target.
    pub fn interrupter_target(&self) -> u8 {
        const STATUS_INTERRUPTER_TARGET_OFFSET: u8 = 22;
        (self.get_status() >> STATUS_INTERRUPTER_TARGET_OFFSET) as u8
    }

    /// Only some of trb types could appear in transfer ring.
    pub fn can_be_in_transfer_ring(&self) -> bool {
        match self.trb_type().unwrap() {
            TrbType::Normal
            | TrbType::SetupStage
            | TrbType::DataStage
            | TrbType::StatusStage
            | TrbType::Isoch
            | TrbType::Link
            | TrbType::EventData
            | TrbType::Noop => true,
            _ => false,
        }
    }

    /// Length of this transfer.
    pub fn transfer_length(&self) -> u32 {
        const STATUS_TRANSFER_LENGTH_MASK: u32 = 0x1ffff;
        match self.trb_type().unwrap() {
            TrbType::Normal | TrbType::SetupStage | TrbType::DataStage | TrbType::Isoch => {
                self.get_status() & STATUS_TRANSFER_LENGTH_MASK
            }
            _ => 0,
        }
    }

    /// Returns true if interrupt is required on completion.
    pub fn interrupt_on_completion(&self) -> bool {
        const FLAGS_INTERRUPT_ON_COMPLETION_MASK: u16 = 0x10;
        (self.get_flags() & FLAGS_INTERRUPT_ON_COMPLETION_MASK) > 0
    }

    /// Returns true if this trb is immediate data.
    pub fn immediate_data(&self) -> bool {
        const FLAGS_IMMEDIATE_DATA_MASK: u16 = 0x20;
        match self.trb_type().unwrap() {
            TrbType::Normal | TrbType::SetupStage | TrbType::DataStage | TrbType::Isoch => {
                (self.get_flags() & FLAGS_IMMEDIATE_DATA_MASK) != 0
            }
            _ => false,
        }
    }
}

/// Trait for enum that could be converted from raw u8.
pub trait PrimitiveEnum: Sized {
    fn from_raw(val: u8) -> Option<Self>;
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

impl PrimitiveEnum for TrbType {
    fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(TrbType::Reserved),
            1 => Some(TrbType::Normal),
            2 => Some(TrbType::SetupStage),
            3 => Some(TrbType::DataStage),
            4 => Some(TrbType::StatusStage),
            5 => Some(TrbType::Isoch),
            6 => Some(TrbType::Link),
            7 => Some(TrbType::EventData),
            8 => Some(TrbType::Noop),
            9 => Some(TrbType::EnableSlotCommand),
            10 => Some(TrbType::DisableSlotCommand),
            11 => Some(TrbType::AddressDeviceCommand),
            12 => Some(TrbType::ConfigureEndpointCommand),
            13 => Some(TrbType::EvaluateContextCommand),
            14 => Some(TrbType::ResetEndpointCommand),
            15 => Some(TrbType::StopEndpointCommand),
            16 => Some(TrbType::SetTRDequeuePointerCommand),
            17 => Some(TrbType::ResetDeviceCommand),
            23 => Some(TrbType::NoopCommand),
            32 => Some(TrbType::TransferEvent),
            33 => Some(TrbType::CommandCompletionEvent),
            34 => Some(TrbType::PortStatusChangeEvent),
            _ => None,
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

impl PrimitiveEnum for TrbCompletionCode {
    fn from_raw(val: u8) -> Option<Self> {
        match val {
            1 => Some(TrbCompletionCode::Success),
            4 => Some(TrbCompletionCode::TransactionError),
            5 => Some(TrbCompletionCode::TrbError),
            9 => Some(TrbCompletionCode::NoSlotsAvailableError),
            11 => Some(TrbCompletionCode::SlotNotEnabledError),
            13 => Some(TrbCompletionCode::ShortPacket),
            19 => Some(TrbCompletionCode::ContextStateError),
            _ => None,
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

impl PrimitiveEnum for DeviceSlotState {
    fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(DeviceSlotState::DisabledOrEnabled),
            1 => Some(DeviceSlotState::Default),
            2 => Some(DeviceSlotState::Addressed),
            3 => Some(DeviceSlotState::Configured),
            _ => None,
        }
    }
}

impl SlotContext {
    /// Set slot context state.
    pub fn state(&self) -> Option<DeviceSlotState> {
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

impl PrimitiveEnum for EndpointState {
    fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(EndpointState::Disabled),
            1 => Some(EndpointState::Running),
            _ => None,
        }
    }
}

impl EndpointContext {
    /// Get endpoint context state.
    pub fn state(&self) -> Option<EndpointState> {
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
