// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::error;
use base::SendTube;
use base::VmEventType;

use crate::pci::CrosvmDeviceId;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;
use crate::Suspendable;

/// A i8042 PS/2 controller that emulates just enough to shutdown the machine.
pub struct I8042Device {
    reset_evt_wrtube: SendTube,
}

impl I8042Device {
    /// Constructs a i8042 device that will signal the given event when the guest requests it.
    pub fn new(reset_evt_wrtube: SendTube) -> I8042Device {
        I8042Device { reset_evt_wrtube }
    }
}

// i8042 device is mapped I/O address 0x61. We partially implement two 8-bit
// registers: port 0x61 (I8042_PORT_B_REG), and port 0x64 (I8042_COMMAND_REG).
impl BusDevice for I8042Device {
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::I8042.into()
    }

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
            if let Err(e) = self
                .reset_evt_wrtube
                .send::<VmEventType>(&VmEventType::Reset)
            {
                error!("failed to trigger i8042 reset event: {}", e);
            }
        }
    }
}

impl Suspendable for I8042Device {}
