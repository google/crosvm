// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use data_model::{DataInit, Le16, Le32};
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

/// Allows a raw input event of the implementor's type to be decoded into
/// a virtio_input_event.
pub trait InputEventDecoder {
    const SIZE: usize;
    fn decode(data: &[u8]) -> virtio_input_event;
}

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
    pub fn from_virtio_input_event(other: &virtio_input_event) -> input_event {
        input_event {
            timestamp_fields: [0, 0],
            type_: other.type_.into(),
            code: other.code.into(),
            value: other.value.into(),
        }
    }
}

impl InputEventDecoder for input_event {
    const SIZE: usize = size_of::<Self>();

    fn decode(data: &[u8]) -> virtio_input_event {
        #[repr(align(8))]
        struct Aligner([u8; input_event::SIZE]);
        let data_aligned = Aligner(*<[u8; input_event::SIZE]>::from_slice(data).unwrap());
        let e = Self::from_slice(&data_aligned.0).unwrap();
        virtio_input_event {
            type_: Le16::from(e.type_),
            code: Le16::from(e.code),
            value: Le32::from(e.value),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct virtio_input_event {
    pub type_: Le16,
    pub code: Le16,
    pub value: Le32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_input_event {}

impl InputEventDecoder for virtio_input_event {
    const SIZE: usize = size_of::<Self>();

    fn decode(data: &[u8]) -> virtio_input_event {
        #[repr(align(4))]
        struct Aligner([u8; virtio_input_event::SIZE]);
        let data_aligned = Aligner(*<[u8; virtio_input_event::SIZE]>::from_slice(data).unwrap());
        *Self::from_slice(&data_aligned.0).unwrap()
    }
}

impl virtio_input_event {
    #[inline]
    pub fn syn() -> virtio_input_event {
        virtio_input_event {
            type_: Le16::from(EV_SYN),
            code: Le16::from(SYN_REPORT),
            value: Le32::from(0),
        }
    }

    #[inline]
    pub fn absolute(code: u16, value: u32) -> virtio_input_event {
        virtio_input_event {
            type_: Le16::from(EV_ABS),
            code: Le16::from(code),
            value: Le32::from(value),
        }
    }

    #[inline]
    pub fn absolute_x(x: u32) -> virtio_input_event {
        Self::absolute(ABS_X, x)
    }

    #[inline]
    pub fn absolute_y(y: u32) -> virtio_input_event {
        Self::absolute(ABS_Y, y)
    }

    #[inline]
    pub fn touch(has_contact: bool) -> virtio_input_event {
        Self::key(BTN_TOUCH, has_contact)
    }

    #[inline]
    pub fn finger_tool(active: bool) -> virtio_input_event {
        Self::key(BTN_TOOL_FINGER, active)
    }

    #[inline]
    pub fn key(code: u16, pressed: bool) -> virtio_input_event {
        virtio_input_event {
            type_: Le16::from(EV_KEY),
            code: Le16::from(code),
            value: Le32::from(if pressed { 1 } else { 0 }),
        }
    }
}
