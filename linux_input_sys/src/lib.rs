// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Linux input system bindings.

pub mod constants;

use std::mem::size_of;

use constants::*;
use data_model::zerocopy_from_slice;
use data_model::Le16;
use data_model::SLe32;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

/// Allows a raw input event of the implementor's type to be decoded into
/// a virtio_input_event.
pub trait InputEventDecoder {
    const SIZE: usize;
    fn decode(data: &[u8]) -> virtio_input_event;
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
pub struct input_event {
    pub timestamp_fields: [u64; 2],
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

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
        #[derive(FromZeroes, FromBytes)]
        struct Aligner([u8; input_event::SIZE]);
        let data_aligned = zerocopy_from_slice::<Aligner>(data).unwrap();
        let e: &input_event = zerocopy_from_slice(data_aligned.0.as_bytes()).unwrap();
        virtio_input_event {
            type_: Le16::from(e.type_),
            code: Le16::from(e.code),
            value: SLe32::from(e.value),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct virtio_input_event {
    pub type_: Le16,
    pub code: Le16,
    pub value: SLe32,
}

impl InputEventDecoder for virtio_input_event {
    const SIZE: usize = size_of::<Self>();

    fn decode(data: &[u8]) -> virtio_input_event {
        #[repr(align(4))]
        #[derive(FromZeroes, FromBytes)]
        struct Aligner([u8; virtio_input_event::SIZE]);
        let data_aligned = zerocopy_from_slice::<Aligner>(data).unwrap();
        *zerocopy_from_slice(data_aligned.0.as_bytes()).unwrap()
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
        Self::key(BTN_TOUCH, has_contact, false)
    }

    #[inline]
    pub fn finger_tool(active: bool) -> virtio_input_event {
        Self::key(BTN_TOOL_FINGER, active, false)
    }

    /// Repeated keys must set the `repeat` option if the key was already down, or repeated keys
    /// will not be seen correctly by the guest.
    #[inline]
    pub fn key(code: u16, down: bool, repeat: bool) -> virtio_input_event {
        virtio_input_event {
            type_: Le16::from(EV_KEY),
            code: Le16::from(code),
            value: SLe32::from(match (down, repeat) {
                (true, true) => 2,
                (true, false) => 1,
                // repeat is not meaningful for key up events.
                _ => 0,
            }),
        }
    }

    /// If the event is EV_LED for the given LED code, return if it is on.
    pub fn get_led_state(&self, led_code: u16) -> Option<bool> {
        if self.type_ == EV_LED && self.code == led_code {
            return match self.value.to_native() {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            };
        }
        None
    }
}
