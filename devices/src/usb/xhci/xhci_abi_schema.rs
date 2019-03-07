// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use bit_field::*;
use std;

// TODO(jkwang) move these to bitfield crate.
type B0 = BitField0;
type B1 = BitField1;
type B2 = BitField2;
type B3 = BitField3;
type B4 = BitField4;
type B5 = BitField5;
type B6 = BitField6;
type B7 = BitField7;
type B8 = BitField8;
type B9 = BitField9;
type B10 = BitField10;
type B11 = BitField11;
type B12 = BitField12;
type B13 = BitField13;
type B14 = BitField14;
type B15 = BitField15;
type B16 = BitField16;
type B17 = BitField17;
type B18 = BitField18;
type B19 = BitField19;
type B20 = BitField20;
type B21 = BitField21;
type B22 = BitField22;
type B23 = BitField23;
type B24 = BitField24;
type B25 = BitField25;
type B26 = BitField26;
type B27 = BitField27;
type B28 = BitField28;
type B29 = BitField29;
type B30 = BitField30;
type B31 = BitField31;
type B32 = BitField32;
type B33 = BitField33;
type B34 = BitField34;
type B35 = BitField35;
type B36 = BitField36;
type B37 = BitField37;
type B38 = BitField38;
type B39 = BitField39;
type B40 = BitField40;
type B41 = BitField41;
type B42 = BitField42;
type B43 = BitField43;
type B44 = BitField44;
type B45 = BitField45;
type B46 = BitField46;
type B47 = BitField47;
type B48 = BitField48;
type B49 = BitField49;
type B50 = BitField50;
type B51 = BitField51;
type B52 = BitField52;
type B53 = BitField53;
type B54 = BitField54;
type B55 = BitField55;
type B56 = BitField56;
type B57 = BitField57;
type B58 = BitField58;
type B59 = BitField59;
type B60 = BitField60;
type B61 = BitField61;
type B62 = BitField62;
type B63 = BitField63;
type B64 = BitField64;

// Fixed size of all TRB types.
const TRB_SIZE: usize = 16;

// Size of segment table.
const SEGMENT_TABLE_SIZE: usize = 16;

// Generic TRB struct containing only fields common to all types.
#[bitfield]
#[derive(Clone, Copy, PartialEq)]
pub struct Trb {
    parameter: B64,
    status: B32,
    cycle: B1,
    flags: B9,
    trb_type: B6,
    control: B16,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct NormalTrb {
    data_buffer: B64,
    trb_transfer_length: B17,
    td_size: B5,
    interrupter_target: B10,
    cycle: B1,
    evaluate_next_trb: B1,
    interrupt_on_short_packet: B1,
    no_snoop: B1,
    chain: B1,
    interrupt_on_completion: B1,
    immediate_data: B1,
    reserved: B2,
    block_event_interrupt: B1,
    trb_type: B6,
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
    cycle: B1,
    reserved1: B4,
    interrupt_on_completion: B1,
    immediate_data: B1,
    reserved2: B3,
    trb_type: B6,
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
    cycle: B1,
    evaluate_next_trb: B1,
    interrupt_on_short_packet: B1,
    no_snoop: B1,
    chain: B1,
    interrupt_on_completion: B1,
    immediate_data: B1,
    reserved0: B3,
    trb_type: B6,
    direction: B1,
    reserved1: B15,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct StatusStageTrb {
    reserved0: B64,
    reserved1: B22,
    interrupter_target: B10,
    cycle: B1,
    evaluate_next_trb: B1,
    reserved2: B2,
    chain: B1,
    interrupt_on_completion: B1,
    reserved3: B4,
    trb_type: B6,
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
    cycle: B1,
    evaulate_nex_trb: B1,
    interrupt_on_short_packet: B1,
    no_snoop: B1,
    chain: B1,
    interrupt_on_completion: B1,
    immediate_data: B1,
    transfer_burst_count: B2,
    block_event_interrupt: B1,
    trb_type: B6,
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
    cycle: B1,
    toggle_cycle: B1,
    reserved1: B2,
    chain: B1,
    interrupt_on_completion: B1,
    reserved2: B4,
    trb_type: B6,
    reserved3: B16,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct EventDataTrb {
    event_data: B64,
    reserved0: B22,
    interrupter_target: B10,
    cycle: B1,
    evaluate_next_trb: B1,
    reserved1: B2,
    chain: B1,
    interrupt_on_completion: B1,
    reserved2: B3,
    block_event_interrupt: B1,
    trb_type: B6,
    reserved3: B16,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct NoopTrb {
    reserved0: B64,
    reserved1: B22,
    interrupter_target: B10,
    cycle: B1,
    evaluate_next_trb: B1,
    reserved2: B2,
    chain: B1,
    interrupt_on_completion: B1,
    reserved3: B4,
    trb_type: B6,
    reserved4: B16,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct DisableSlotCommandTrb {
    reserved0: B32,
    reserved1: B32,
    reserved2: B32,
    cycle: B1,
    reserved3: B9,
    trb_type: B6,
    reserved4: B8,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct AddressDeviceCommandTrb {
    input_context_pointer: B64,
    reserved: B32,
    cycle: B1,
    reserved2: B8,
    block_set_address_request: B1,
    trb_type: B6,
    reserved3: B8,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct ConfigureEndpointCommandTrb {
    input_context_pointer: B64,
    reserved0: B32,
    cycle: B1,
    reserved1: B8,
    deconfigure: B1,
    trb_type: B6,
    reserved2: B8,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct EvaluateContextCommandTrb {
    input_context_pointer: B64,
    reserved0: B32,
    cycle: B1,
    reserved1: B9,
    trb_type: B6,
    reserved2: B8,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct ResetEndpointCommandTrb {
    reserved0: B32,
    reserved1: B32,
    reserved2: B32,
    cycle: B1,
    reserved3: B8,
    transfer_state_preserve: B1,
    trb_type: B6,
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
    cycle: B1,
    reserved3: B9,
    trb_type: B6,
    endpoint_id: B5,
    reserved4: B2,
    suspend: B1,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct SetTRDequeuePointerCommandTrb {
    dequeue_cycle_state: B1,
    stream_context_type: B3,
    dequeue_ptr: B60,
    reserved0: B16,
    stream_id: B16,
    cycle: B1,
    reserved1: B9,
    trb_type: B6,
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
    cycle: B1,
    reserved3: B9,
    trb_type: B6,
    reserved4: B8,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct TransferEventTrb {
    trb_pointer: B64,
    trb_transfer_length: B24,
    completion_code: B8,
    cycle: B1,
    reserved0: B1,
    event_data: B1,
    reserved1: B7,
    trb_type: B6,
    endpoint_id: B5,
    reserved2: B3,
    slot_id: B8,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct CommandCompletionEventTrb {
    trb_pointer: B64,
    command_completion_parameter: B24,
    completion_code: B8,
    cycle: B1,
    reserved: B9,
    trb_type: B6,
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
    completion_code: B8,
    cycle: B1,
    reserved3: B9,
    trb_type: B6,
    reserved4: B16,
}

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
    slot_state: B5,
    reserved4: B32,
    reserved5: B32,
    reserved6: B32,
    reserved7: B32,
}

#[bitfield]
#[derive(Clone, Copy)]
pub struct EndpointContext {
    endpoint_state: B3,
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
    dequeue_cycle_state: B1,
    reserved4: B3,
    tr_dequeue_pointer: B60,
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
