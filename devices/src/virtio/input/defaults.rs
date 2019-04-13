// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

use super::constants::*;
use super::virtio_input_absinfo;
use super::virtio_input_bitmap;
use super::virtio_input_device_ids;
use super::VirtioInputConfig;

/// Instantiates a VirtioInputConfig object with the default configuration for a trackpad. It
/// supports touch, left button and right button events, as well as X and Y axis.
pub fn new_trackpad_config(width: u32, height: u32) -> VirtioInputConfig {
    VirtioInputConfig::new(
        virtio_input_device_ids::new(0, 0, 0, 0),
        b"Crosvm Virtio Trackpad".to_vec(),
        b"virtio-trackpad".to_vec(),
        virtio_input_bitmap::new([0u8; 128]),
        default_trackpad_events(),
        default_trackpad_absinfo(width, height),
    )
}

/// Instantiates a VirtioInputConfig object with the default configuration for a mouse.
/// It supports left, right and middle buttons, as wel as X, Y and wheel relative axes.
pub fn new_mouse_config() -> VirtioInputConfig {
    VirtioInputConfig::new(
        virtio_input_device_ids::new(0, 0, 0, 0),
        b"Crosvm Virtio Mouse".to_vec(),
        b"virtio-mouse".to_vec(),
        virtio_input_bitmap::new([0u8; 128]),
        default_mouse_events(),
        BTreeMap::new(),
    )
}

/// Instantiates a VirtioInputConfig object with the default configuration for a keyboard.
/// It supports the same keys as a en-us keyboard and the CAPSLOCK, NUMLOCK and SCROLLLOCK leds.
pub fn new_keyboard_config() -> VirtioInputConfig {
    VirtioInputConfig::new(
        virtio_input_device_ids::new(0, 0, 0, 0),
        b"Crosvm Virtio Keyboard".to_vec(),
        b"virtio-keyboard".to_vec(),
        virtio_input_bitmap::new([0u8; 128]),
        default_keyboard_events(),
        BTreeMap::new(),
    )
}

/// Instantiates a VirtioInputConfig object with the default configuration for a touchscreen (no
/// multitouch support).
pub fn new_single_touch_config(width: u32, height: u32) -> VirtioInputConfig {
    VirtioInputConfig::new(
        virtio_input_device_ids::new(0, 0, 0, 0),
        b"Crosvm Virtio Touchscreen".to_vec(),
        b"virtio-touchscreen".to_vec(),
        virtio_input_bitmap::from_bits(&[INPUT_PROP_DIRECT]),
        default_touchscreen_events(),
        default_touchscreen_absinfo(width, height),
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
