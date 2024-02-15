// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

use linux_input_sys::constants::*;

use super::virtio_input_absinfo;
use super::virtio_input_bitmap;
use super::virtio_input_device_ids;
use super::VirtioInputConfig;

fn name_with_index(device_name: &[u8], idx: u32) -> Vec<u8> {
    let mut ret = device_name.to_vec();
    ret.extend_from_slice(idx.to_string().as_bytes());
    ret
}

/// Instantiates a VirtioInputConfig object with the default configuration for a trackpad. It
/// supports touch, left button and right button events, as well as X and Y axis.
pub fn new_trackpad_config(
    idx: u32,
    width: u32,
    height: u32,
    name: Option<&str>,
) -> VirtioInputConfig {
    let name = name
        .map(|name| name.as_bytes().to_vec())
        .unwrap_or(name_with_index(b"Crosvm Virtio Trackpad ", idx));
    VirtioInputConfig::new(
        virtio_input_device_ids::new(0, 0, 0, 0),
        name,
        name_with_index(b"virtio-trackpad-", idx),
        virtio_input_bitmap::new([0u8; 128]),
        default_trackpad_events(),
        default_trackpad_absinfo(width, height),
    )
}

/// Instantiates a VirtioInputConfig object with the default configuration for a mouse.
/// It supports left, right and middle buttons, as wel as X, Y and wheel relative axes.
pub fn new_mouse_config(idx: u32) -> VirtioInputConfig {
    VirtioInputConfig::new(
        virtio_input_device_ids::new(0, 0, 0, 0),
        name_with_index(b"Crosvm Virtio Mouse ", idx),
        name_with_index(b"virtio-mouse-", idx),
        virtio_input_bitmap::new([0u8; 128]),
        default_mouse_events(),
        BTreeMap::new(),
    )
}

/// Instantiates a VirtioInputConfig object with the default configuration for a keyboard.
/// It supports the same keys as a en-us keyboard and the CAPSLOCK, NUMLOCK and SCROLLLOCK leds.
pub fn new_keyboard_config(idx: u32) -> VirtioInputConfig {
    VirtioInputConfig::new(
        virtio_input_device_ids::new(0, 0, 0, 0),
        name_with_index(b"Crosvm Virtio Keyboard ", idx),
        name_with_index(b"virtio-keyboard-", idx),
        virtio_input_bitmap::new([0u8; 128]),
        default_keyboard_events(),
        BTreeMap::new(),
    )
}

/// Instantiates a VirtioInputConfig object with the default configuration for a collection of
/// switches.
pub fn new_switches_config(idx: u32) -> VirtioInputConfig {
    VirtioInputConfig::new(
        virtio_input_device_ids::new(0, 0, 0, 0),
        name_with_index(b"Crosvm Virtio Switches ", idx),
        name_with_index(b"virtio-switches-", idx),
        virtio_input_bitmap::new([0u8; 128]),
        default_switch_events(),
        BTreeMap::new(),
    )
}

/// Instantiates a VirtioInputConfig object with the default configuration for a collection of
/// rotary.
pub fn new_rotary_config(idx: u32) -> VirtioInputConfig {
    VirtioInputConfig::new(
        virtio_input_device_ids::new(0, 0, 0, 0),
        name_with_index(b"Crosvm Virtio Rotary ", idx),
        name_with_index(b"virtio-rotary-", idx),
        virtio_input_bitmap::new([0u8; 128]),
        default_rotary_events(),
        BTreeMap::new(),
    )
}

/// Instantiates a VirtioInputConfig object with the default configuration for a touchscreen (no
/// multitouch support).
pub fn new_single_touch_config(
    idx: u32,
    width: u32,
    height: u32,
    name: Option<&str>,
) -> VirtioInputConfig {
    let name = name
        .map(|name| name.as_bytes().to_vec())
        .unwrap_or(name_with_index(b"Crosvm Virtio Touchscreen ", idx));
    VirtioInputConfig::new(
        virtio_input_device_ids::new(0, 0, 0, 0),
        name,
        name_with_index(b"virtio-touchscreen-", idx),
        virtio_input_bitmap::from_bits(&[INPUT_PROP_DIRECT]),
        default_touchscreen_events(),
        default_touchscreen_absinfo(width, height),
    )
}

/// Instantiates a VirtioInputConfig object with the default configuration for a multitouch
/// touchscreen.
pub fn new_multi_touch_config(
    idx: u32,
    width: u32,
    height: u32,
    name: Option<&str>,
) -> VirtioInputConfig {
    let name = name
        .map(|name| name.as_bytes().to_vec())
        .unwrap_or(name_with_index(
            b"Crosvm Virtio Multitouch Touchscreen ",
            idx,
        ));
    VirtioInputConfig::new(
        virtio_input_device_ids::new(0, 0, 0, 0),
        name,
        name_with_index(b"virtio-touchscreen-", idx),
        virtio_input_bitmap::from_bits(&[INPUT_PROP_DIRECT]),
        default_multitouchscreen_events(),
        default_multitouchscreen_absinfo(width, height, 10, 10),
    )
}

fn default_touchscreen_absinfo(width: u32, height: u32) -> BTreeMap<u16, virtio_input_absinfo> {
    let mut absinfo: BTreeMap<u16, virtio_input_absinfo> = BTreeMap::new();
    absinfo.insert(ABS_X, virtio_input_absinfo::new(0, width, 0, 0));
    absinfo.insert(ABS_Y, virtio_input_absinfo::new(0, height, 0, 0));
    absinfo
}

fn default_touchscreen_events() -> BTreeMap<u16, virtio_input_bitmap> {
    let mut supported_events: BTreeMap<u16, virtio_input_bitmap> = BTreeMap::new();
    supported_events.insert(EV_KEY, virtio_input_bitmap::from_bits(&[BTN_TOUCH]));
    supported_events.insert(EV_ABS, virtio_input_bitmap::from_bits(&[ABS_X, ABS_Y]));
    supported_events
}

fn default_multitouchscreen_absinfo(
    width: u32,
    height: u32,
    slot: u32,
    id: u32,
) -> BTreeMap<u16, virtio_input_absinfo> {
    let mut absinfo: BTreeMap<u16, virtio_input_absinfo> = BTreeMap::new();
    absinfo.insert(ABS_MT_SLOT, virtio_input_absinfo::new(0, slot, 0, 0));
    absinfo.insert(ABS_MT_TRACKING_ID, virtio_input_absinfo::new(0, id, 0, 0));
    absinfo.insert(ABS_MT_POSITION_X, virtio_input_absinfo::new(0, width, 0, 0));
    absinfo.insert(
        ABS_MT_POSITION_Y,
        virtio_input_absinfo::new(0, height, 0, 0),
    );
    absinfo
}

fn default_multitouchscreen_events() -> BTreeMap<u16, virtio_input_bitmap> {
    let mut supported_events: BTreeMap<u16, virtio_input_bitmap> = BTreeMap::new();
    supported_events.insert(EV_KEY, virtio_input_bitmap::from_bits(&[BTN_TOUCH]));
    supported_events.insert(
        EV_ABS,
        virtio_input_bitmap::from_bits(&[
            ABS_MT_SLOT,
            ABS_MT_TRACKING_ID,
            ABS_MT_POSITION_X,
            ABS_MT_POSITION_Y,
        ]),
    );
    supported_events
}

fn default_trackpad_absinfo(width: u32, height: u32) -> BTreeMap<u16, virtio_input_absinfo> {
    let mut absinfo: BTreeMap<u16, virtio_input_absinfo> = BTreeMap::new();
    absinfo.insert(ABS_X, virtio_input_absinfo::new(0, width, 0, 0));
    absinfo.insert(ABS_Y, virtio_input_absinfo::new(0, height, 0, 0));
    absinfo
}

fn default_trackpad_events() -> BTreeMap<u16, virtio_input_bitmap> {
    let mut supported_events: BTreeMap<u16, virtio_input_bitmap> = BTreeMap::new();
    supported_events.insert(
        EV_KEY,
        virtio_input_bitmap::from_bits(&[BTN_TOOL_FINGER, BTN_TOUCH, BTN_LEFT, BTN_RIGHT]),
    );
    supported_events.insert(EV_ABS, virtio_input_bitmap::from_bits(&[ABS_X, ABS_Y]));
    supported_events
}

fn default_mouse_events() -> BTreeMap<u16, virtio_input_bitmap> {
    let mut supported_events: BTreeMap<u16, virtio_input_bitmap> = BTreeMap::new();
    supported_events.insert(
        EV_KEY,
        virtio_input_bitmap::from_bits(&[BTN_LEFT, BTN_RIGHT, BTN_MIDDLE]),
    );
    supported_events.insert(
        EV_REL,
        virtio_input_bitmap::from_bits(&[REL_X, REL_Y, REL_WHEEL]),
    );
    supported_events
}

fn default_keyboard_events() -> BTreeMap<u16, virtio_input_bitmap> {
    let mut supported_events: BTreeMap<u16, virtio_input_bitmap> = BTreeMap::new();
    supported_events.insert(
        EV_KEY,
        virtio_input_bitmap::from_bits(&[
            KEY_ESC,
            KEY_1,
            KEY_2,
            KEY_3,
            KEY_4,
            KEY_5,
            KEY_6,
            KEY_7,
            KEY_8,
            KEY_9,
            KEY_0,
            KEY_MINUS,
            KEY_EQUAL,
            KEY_BACKSPACE,
            KEY_TAB,
            KEY_Q,
            KEY_W,
            KEY_E,
            KEY_R,
            KEY_T,
            KEY_Y,
            KEY_U,
            KEY_I,
            KEY_O,
            KEY_P,
            KEY_LEFTBRACE,
            KEY_RIGHTBRACE,
            KEY_ENTER,
            KEY_LEFTCTRL,
            KEY_A,
            KEY_S,
            KEY_D,
            KEY_F,
            KEY_G,
            KEY_H,
            KEY_J,
            KEY_K,
            KEY_L,
            KEY_SEMICOLON,
            KEY_APOSTROPHE,
            KEY_GRAVE,
            KEY_LEFTSHIFT,
            KEY_BACKSLASH,
            KEY_Z,
            KEY_X,
            KEY_C,
            KEY_V,
            KEY_B,
            KEY_N,
            KEY_M,
            KEY_COMMA,
            KEY_DOT,
            KEY_SLASH,
            KEY_RIGHTSHIFT,
            KEY_KPASTERISK,
            KEY_LEFTALT,
            KEY_SPACE,
            KEY_CAPSLOCK,
            KEY_F1,
            KEY_F2,
            KEY_F3,
            KEY_F4,
            KEY_F5,
            KEY_F6,
            KEY_F7,
            KEY_F8,
            KEY_F9,
            KEY_F10,
            KEY_NUMLOCK,
            KEY_SCROLLLOCK,
            KEY_KP7,
            KEY_KP8,
            KEY_KP9,
            KEY_KPMINUS,
            KEY_KP4,
            KEY_KP5,
            KEY_KP6,
            KEY_KPPLUS,
            KEY_KP1,
            KEY_KP2,
            KEY_KP3,
            KEY_KP0,
            KEY_KPDOT,
            KEY_F11,
            KEY_F12,
            KEY_KPENTER,
            KEY_RIGHTCTRL,
            KEY_KPSLASH,
            KEY_SYSRQ,
            KEY_RIGHTALT,
            KEY_HOME,
            KEY_UP,
            KEY_PAGEUP,
            KEY_LEFT,
            KEY_RIGHT,
            KEY_END,
            KEY_DOWN,
            KEY_PAGEDOWN,
            KEY_INSERT,
            KEY_DELETE,
            KEY_PAUSE,
            KEY_MENU,
            KEY_PRINT,
            KEY_POWER,
            KEY_HOMEPAGE,
            KEY_MUTE,
            KEY_VOLUMEDOWN,
            KEY_VOLUMEUP,
            KEY_BACK,
        ]),
    );
    supported_events.insert(
        EV_REP,
        virtio_input_bitmap::from_bits(&[REP_DELAY, REP_PERIOD]),
    );
    supported_events.insert(
        EV_LED,
        virtio_input_bitmap::from_bits(&[LED_CAPSL, LED_NUML, LED_SCROLLL]),
    );
    supported_events
}

fn default_switch_events() -> BTreeMap<u16, virtio_input_bitmap> {
    let mut supported_events: BTreeMap<u16, virtio_input_bitmap> = BTreeMap::new();
    supported_events.insert(
        EV_SW,
        virtio_input_bitmap::from_bits(&[
            SW_LID,
            SW_TABLET_MODE,
            SW_HEADPHONE_INSERT,
            SW_RFKILL_ALL,
            SW_MICROPHONE_INSERT,
            SW_DOCK,
            SW_LINEOUT_INSERT,
            SW_JACK_PHYSICAL_INSERT,
            SW_VIDEOOUT_INSERT,
            SW_CAMERA_LENS_COVER,
            SW_KEYPAD_SLIDE,
            SW_FRONT_PROXIMITY,
            SW_ROTATE_LOCK,
            SW_LINEIN_INSERT,
            SW_MUTE_DEVICE,
            SW_PEN_INSERTED,
            SW_MACHINE_COVER,
        ]),
    );
    supported_events
}

fn default_rotary_events() -> BTreeMap<u16, virtio_input_bitmap> {
    let mut supported_events: BTreeMap<u16, virtio_input_bitmap> = BTreeMap::new();
    supported_events.insert(EV_REL, virtio_input_bitmap::from_bits(&[REL_WHEEL]));
    supported_events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_switches_config() {
        let config = new_switches_config(0);
        assert_eq!(config.serial_name, b"virtio-switches-0".to_vec());

        let events = config.supported_events;
        assert_eq!(events.len(), 1);
        assert_eq!(events.contains_key(&EV_SW), true);

        // The bitmap should contain SW_CNT=0x10+1=17 ones,
        // where each one is packed into the u8 bitmap.
        let mut expected_bitmap = [0_u8; 128];
        expected_bitmap[0] = 0b11111111u8;
        expected_bitmap[1] = 0b11111111u8;
        expected_bitmap[2] = 0b1u8;
        assert_eq!(events[&EV_SW].bitmap, expected_bitmap);
    }
}
