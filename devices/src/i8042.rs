// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::{error, Event};

use crate::{BusAccessInfo, BusDevice};

/// A i8042 PS/2 controller that emulates just enough to shutdown the machine.
pub struct I8042Device {
    reset_evt: Event,
}

impl I8042Device {
    /// Constructs a i8042 device that will signal the given event when the guest requests it.
    pub fn new(reset_evt: Event) -> I8042Device {
        I8042Device { reset_evt }
    }
}

// i8042 device is mapped I/O address 0x61. We partially implement two 8-bit
// registers: port 0x61 (I8042_PORT_B_REG), and port 0x64 (I8042_COMMAND_REG).
impl BusDevice for I8042Device {
    fn debug_label(&self) -> String {
        "i8042".to_owned()
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        if data.len() == 1 && info.address == 0x64 {
            data[0] = 0x0;
        } else if data.len() == 1 && info.address == 0x61 {
            // Like kvmtool, we return bit 5 set in I8042_PORT_B_REG to
            // avoid hang in pit_calibrate_tsc() in Linux kernel.
            data[0] = 0x20;
        }
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        if data.len() == 1 && data[0] == 0xfe && info.address == 0x64 {
            if let Err(e) = self.reset_evt.write(1) {
                error!("failed to trigger i8042 reset event: {}", e);
            }
        }
    }
}
