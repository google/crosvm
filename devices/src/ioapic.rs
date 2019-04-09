// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implementation of an intel 82093AA Input/Output Advanced Programmable Interrupt Controller
// See https://pdos.csail.mit.edu/6.828/2016/readings/ia32/ioapic.pdf for a specification.

use crate::BusDevice;
use bit_field::*;

// TODO(mutexlox): once https://crrev.com/c/1519686 has landed, refactor these bitfields to use
// better types where applicable.
#[bitfield]
#[derive(Clone, Copy, PartialEq)]
pub struct RedirectionTableEntry {
    vector: BitField8,
    delivery_mode: BitField3,
    dest_mode: BitField1,
    delivery_status: BitField1,
    polarity: BitField1,
    remote_irr: BitField1,
    trigger_mode: BitField1,
    interrupt_mask: BitField1,
    reserved: BitField39,
    dest_id: BitField8,
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq)]
pub enum DeliveryStatus {
    Idle = 0,
    Pending = 1,
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq)]
pub enum InterruptRemappingFormat {
    Compatibility = 0,
    Remappable = 1,
}

#[allow(dead_code)]
const IOAPIC_VERSION_ID: u32 = 0x00170011;
#[allow(dead_code)]
const IOAPIC_BASE_ADDRESS: u32 = 0xfec00000;
// The Intel manual does not specify this size, but KVM uses it.
#[allow(dead_code)]
const IOAPIC_MEM_LENGTH_BYTES: usize = 0x100;

// Constants for IOAPIC direct register offset.
#[allow(dead_code)]
const IOAPIC_REG_ID: u32 = 0x00;
#[allow(dead_code)]
const IOAPIC_REG_VERSION: u32 = 0x01;
#[allow(dead_code)]
const IOAPIC_REG_ARBITRATION_ID: u32 = 0x02;

// Register offsets
pub const IOREGSEL_OFF: u64 = 0x0;
pub const IOREGSEL_DUMMY_UPPER_32_BITS_OFF: u64 = 0x4;
pub const IOWIN_OFF: u64 = 0x10;

// The RTC needs special treatment to work properly for Windows (or other OSs that use tick
// stuffing). In order to avoid time drift, we need to guarantee that the correct number of RTC
// interrupts are injected into the guest. This hack essentialy treats RTC interrupts as level
// triggered, which allows the IOAPIC to be responsible for interrupt coalescing and allows the
// IOAPIC to pass back whether or not the interrupt was coalesced to the CMOS (which allows the
// CMOS to perform tick stuffing). This deviates from the IOAPIC spec in ways very similar to (but
// not exactly the same as) KVM's IOAPIC.
#[allow(dead_code)]
const RTC_IRQ: u32 = 0x8;

#[allow(dead_code)]
pub struct Ioapic {
    id: usize,
    // Remote IRR for Edge Triggered Real Time Clock interrupts, which allows the CMOS to know when
    // one of its interrupts is being coalesced.
    rtc_remote_irr: bool,
    current_interrupt_level_bitmap: u32,
    redirect_table: [RedirectionTableEntry; kvm::NUM_IOAPIC_PINS],
    ioregsel: u8,
}

impl BusDevice for Ioapic {
    fn debug_label(&self) -> String {
        "userspace IOAPIC".to_string()
    }

    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() > 8 || data.len() == 0 {
            warn!("IOAPIC: Bad read size: {}", data.len());
            return;
        }
        let out = match offset {
            IOREGSEL_OFF => self.ioregsel.into(),
            IOREGSEL_DUMMY_UPPER_32_BITS_OFF => 0,
            IOWIN_OFF => self.ioapic_read(),
            _ => {
                warn!("IOAPIC: Bad read from offset {}", offset);
                return;
            }
        };
        let out_arr = out.to_ne_bytes();
        for i in 0..4 {
            if i < data.len() {
                data[i] = out_arr[i];
            }
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() > 8 || data.len() == 0 {
            warn!("IOAPIC: Bad write size: {}", data.len());
            return;
        }
        match offset {
            IOREGSEL_OFF => self.ioregsel = data[0],
            IOREGSEL_DUMMY_UPPER_32_BITS_OFF => {} // Ignored.
            IOWIN_OFF => {
                if data.len() != 4 {
                    warn!("IOAPIC: Bad write size for iowin: {}", data.len());
                    return;
                }
                let data_arr = [data[0], data[1], data[2], data[3]];
                let val = u32::from_ne_bytes(data_arr);
                self.ioapic_write(val);
            }
            _ => {
                warn!("IOAPIC: Bad write to offset {}", offset);
                return;
            }
        }
    }
}

impl Ioapic {
    pub fn new() -> Ioapic {
        let mut entry = RedirectionTableEntry::new();
        entry.set_interrupt_mask(1);
        let entries = [entry; kvm::NUM_IOAPIC_PINS];
        Ioapic {
            id: 0,
            rtc_remote_irr: false,
            current_interrupt_level_bitmap: 0,
            redirect_table: entries,
            ioregsel: 0,
        }
    }

    // The ioapic must be informed about EOIs in order to avoid sending multiple interrupts of the
    // same type at the same time.
    pub fn end_of_interrupt(&mut self, _vector: u8) {
        unimplemented!();
    }

    pub fn service_irq(&mut self, _irq: u32, _level: bool) -> bool {
        unimplemented!();
    }

    fn ioapic_write(&mut self, _val: u32) {
        unimplemented!();
    }

    fn ioapic_read(&mut self) -> u32 {
        unimplemented!();
    }
}
