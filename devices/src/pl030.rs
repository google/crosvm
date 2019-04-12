// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::{SystemTime, UNIX_EPOCH};
use sys_util::{warn, EventFd};

use crate::BusDevice;

// Register offsets
// Data register
const RTCDR: u64 = 0x0;
// Match register
const RTCMR: u64 = 0x4;
// Interrupt status register
const RTCSTAT: u64 = 0x8;
// Interrupt clear register
const RTCEOI: u64 = 0x8;
// Counter load register
const RTCLR: u64 = 0xC;
// Counter register
const RTCCR: u64 = 0x10;

// A single 4K page is mapped for this device
pub const PL030_AMBA_IOMEM_SIZE: u64 = 0x1000;

// AMBA id registers are at the end of the allocated memory space
const AMBA_ID_OFFSET: u64 = PL030_AMBA_IOMEM_SIZE - 0x20;
const AMBA_MASK_OFFSET: u64 = PL030_AMBA_IOMEM_SIZE - 0x28;

// This is the AMBA id for this device
pub const PL030_AMBA_ID: u32 = 0x00041030;
pub const PL030_AMBA_MASK: u32 = 0x000FFFFF;

/// An emulated ARM pl030 RTC
pub struct Pl030 {
    // EventFD to be used to interrupt the guest for an alarm event
    alarm_evt: EventFd,

    // This is the delta we subtract from current time to get the
    // counter value
    counter_delta_time: u32,

    // This is the value that triggers an alarm interrupt when it
    // matches with the rtc time
    match_value: u32,

    // status flag to keep track of whether the interrupt is cleared
    // or not
    interrupt_active: bool,
}

fn get_epoch_time() -> u32 {
    let epoch_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime::duration_since failed");
    epoch_time.as_secs() as u32
}

impl Pl030 {
    /// Constructs a Pl030 device
    pub fn new(evt: EventFd) -> Pl030 {
        Pl030 {
            alarm_evt: evt,
            counter_delta_time: get_epoch_time(),
            match_value: 0,
            interrupt_active: false,
        }
    }
}

impl BusDevice for Pl030 {
    fn debug_label(&self) -> String {
        "Pl030".to_owned()
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() != 4 {
            warn!("bad write size: {} for pl030", data.len());
            return;
        }

        let reg_val: u32 = (data[0] as u32) << 24
            | (data[1] as u32) << 16
            | (data[2] as u32) << 8
            | (data[3] as u32);
        match offset {
            RTCDR => {
                warn!("invalid write to read-only RTCDR register");
            }
            RTCMR => {
                self.match_value = reg_val;
                // TODO(sonnyrao): here we need to set up a timer for
                // when host time equals the value written here and
                // fire the interrupt
                warn!("Not implemented: VM tried to set an RTC alarm");
            }
            RTCEOI => {
                if reg_val == 0 {
                    self.interrupt_active = false;
                } else {
                    self.alarm_evt.write(1).unwrap();
                    self.interrupt_active = true;
                }
            }
            RTCLR => {
                // TODO(sonnyrao): if we ever need to let the VM set it's own time
                // then we'll need to keep track of the delta between
                // the rtc time it sets and the host's rtc time and
                // record that here
                warn!("Not implemented: VM tried to set the RTC");
            }
            RTCCR => {
                self.counter_delta_time = get_epoch_time();
            }
            o => panic!("pl030: bad write offset {}", o),
        }
    }

    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() != 4 {
            warn!("bad read size: {} for pl030", data.len());
            return;
        }

        let reg_content: u32 = match offset {
            RTCDR => get_epoch_time(),
            RTCMR => self.match_value,
            RTCSTAT => self.interrupt_active as u32,
            RTCLR => {
                warn!("invalid read of RTCLR register");
                0
            }
            RTCCR => get_epoch_time() - self.counter_delta_time,
            AMBA_ID_OFFSET => PL030_AMBA_ID,
            AMBA_MASK_OFFSET => PL030_AMBA_MASK,

            o => panic!("pl030: bad read offset {}", o),
        };
        data[0] = reg_content as u8;
        data[1] = (reg_content >> 8) as u8;
        data[2] = (reg_content >> 16) as u8;
        data[3] = (reg_content >> 24) as u8;
    }
}
