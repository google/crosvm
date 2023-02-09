// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Linux input system bindings.

use std::mem::size_of;

use data_model::DataInit;
use data_model::Le16;
use data_model::SLe32;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const SYN_REPORT: u16 = 0;
pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
pub const ABS_PRESSURE: u16 = 0x18;
pub const ABS_TILT_X: u16 = 0x1a;
pub const ABS_TILT_Y: u16 = 0x1b;
pub const ABS_TOOL_WIDTH: u16 = 0x1c;
pub const BTN_TOUCH: u16 = 0x14a;
pub const BTN_TOOL_FINGER: u16 = 0x145;
pub const ABS_MT_SLOT: u16 = 0x2f;
pub const ABS_MT_TOUCH_MAJOR: u16 = 0x30;
pub const ABS_MT_TOUCH_MINOR: u16 = 0x31;
pub const ABS_MT_WIDTH_MAJOR: u16 = 0x32;
pub const ABS_MT_WIDTH_MINOR: u16 = 0x33;
pub const ABS_MT_ORIENTATION: u16 = 0x34;
pub const ABS_MT_POSITION_X: u16 = 0x35;
pub const ABS_MT_POSITION_Y: u16 = 0x36;
pub const ABS_MT_TOOL_TYPE: u16 = 0x37;
pub const ABS_MT_BLOB_ID: u16 = 0x38;
pub const ABS_MT_TRACKING_ID: u16 = 0x39;
pub const ABS_MT_PRESSURE: u16 = 0x3a;
pub const ABS_MT_DISTANCE: u16 = 0x3b;
pub const ABS_MT_TOOL_X: u16 = 0x3c;
pub const ABS_MT_TOOL_Y: u16 = 0x3d;

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
    pub value: i32,
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
            value: SLe32::from(e.value),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_input_event {
    pub type_: Le16,
    pub code: Le16,
    pub value: SLe32,
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
            value: SLe32::from(0),
        }
    }

    #[inline]
    pub fn absolute(code: u16, value: i32) -> virtio_input_event {
        virtio_input_event {
            type_: Le16::from(EV_ABS),
            code: Le16::from(code),
            value: SLe32::from(value),
        }
    }

    #[inline]
    pub fn relative(code: u16, value: i32) -> virtio_input_event {
        virtio_input_event {
            type_: Le16::from(EV_REL),
            code: Le16::from(code),
            value: SLe32::from(value),
        }
    }

    #[inline]
    pub fn multitouch_tracking_id(id: i32) -> virtio_input_event {
        Self::absolute(ABS_MT_TRACKING_ID, id)
    }

    #[inline]
    pub fn multitouch_slot(slot: i32) -> virtio_input_event {
        Self::absolute(ABS_MT_SLOT, slot)
    }

    #[inline]
    pub fn multitouch_absolute_x(x: i32) -> virtio_input_event {
        Self::absolute(ABS_MT_POSITION_X, x)
    }

    #[inline]
    pub fn multitouch_absolute_y(y: i32) -> virtio_input_event {
        Self::absolute(ABS_MT_POSITION_Y, y)
    }

    #[inline]
    pub fn absolute_x(x: i32) -> virtio_input_event {
        Self::absolute(ABS_X, x)
    }

    #[inline]
    pub fn absolute_y(y: i32) -> virtio_input_event {
        Self::absolute(ABS_Y, y)
    }

    #[inline]
    pub fn relative_x(x: i32) -> virtio_input_event {
        Self::relative(REL_X, x)
    }

    #[inline]
    pub fn relative_y(y: i32) -> virtio_input_event {
        Self::relative(REL_Y, y)
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
            value: SLe32::from(i32::from(pressed)),
        }
    }
}
