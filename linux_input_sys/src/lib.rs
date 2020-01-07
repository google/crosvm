// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use data_model::DataInit;
use std::mem::size_of;

const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
#[allow(dead_code)]
const EV_REL: u16 = 0x02;
const EV_ABS: u16 = 0x03;
const SYN_REPORT: u16 = 0;
#[allow(dead_code)]
const REL_X: u16 = 0x00;
#[allow(dead_code)]
const REL_Y: u16 = 0x01;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;
const BTN_TOUCH: u16 = 0x14a;
const BTN_TOOL_FINGER: u16 = 0x145;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct input_event {
    pub timestamp_fields: [u64; 2],
    pub type_: u16,
    pub code: u16,
    pub value: u32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for input_event {}

impl input_event {
    pub const EVENT_SIZE: usize = size_of::<input_event>();

    #[inline]
    pub fn syn() -> input_event {
        input_event {
            timestamp_fields: [0, 0],
            type_: EV_SYN,
            code: SYN_REPORT,
            value: 0,
        }
    }

    #[inline]
    pub fn absolute(code: u16, value: u32) -> input_event {
        input_event {
            timestamp_fields: [0, 0],
            type_: EV_ABS,
            code,
            value,
        }
    }

    #[inline]
    pub fn absolute_x(x: u32) -> input_event {
        Self::absolute(ABS_X, x)
    }

    #[inline]
    pub fn absolute_y(y: u32) -> input_event {
        Self::absolute(ABS_Y, y)
    }

    #[inline]
    pub fn touch(has_contact: bool) -> input_event {
        Self::key(BTN_TOUCH, has_contact)
    }

    #[inline]
    pub fn finger_tool(active: bool) -> input_event {
        Self::key(BTN_TOOL_FINGER, active)
    }

    #[inline]
    pub fn key(code: u16, pressed: bool) -> input_event {
        input_event {
            timestamp_fields: [0, 0],
            type_: EV_KEY,
            code,
            value: if pressed { 1 } else { 0 },
        }
    }
}
