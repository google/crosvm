// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::error;
use base::warn;
use linux_input_sys::constants::LED_CAPSL;
use linux_input_sys::constants::LED_NUML;
use linux_input_sys::virtio_input_event;
use sync::Mutex;
use winapi::shared::minwindef::BYTE;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::minwindef::WPARAM;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winuser::GetKeyboardState;
use winapi::um::winuser::MapVirtualKeyW;
use winapi::um::winuser::MAPVK_VK_TO_VSC;
use winapi::um::winuser::VK_CAPITAL;
use winapi::um::winuser::VK_NUMLOCK;
use winapi::um::winuser::VK_SCROLL;

use super::window::GuiWindow;
use super::window_message_dispatcher::DisplayEventDispatcher;
use crate::gpu_display_win::window_message_processor::WindowMessage;
use crate::keycode_converter::KeycodeTranslator;
use crate::keycode_converter::KeycodeTypes;
use crate::EventDeviceKind;

// From linux/include/uapi/linux/input-event-codes.h.
const LINUX_CAPS_LOCK_KEY: u16 = 58;
const LINUX_NUM_LOCK_KEY: u16 = 69;

pub(crate) struct KeyboardInputManager {
    display_event_dispatcher: DisplayEventDispatcher,
    keycode_translator: KeycodeTranslator,
    guest_key_states: Mutex<KeyStates>,
}

impl KeyboardInputManager {
    pub fn new(display_event_dispatcher: DisplayEventDispatcher) -> KeyboardInputManager {
        Self {
            display_event_dispatcher,
            keycode_translator: KeycodeTranslator::new(KeycodeTypes::WindowsScancode),
            guest_key_states: Mutex::new(KeyStates {
                caps_lock_state: false,
                num_lock_state: false,
            }),
        }
    }

    pub fn handle_window_message(&self, window: &GuiWindow, message: &WindowMessage) {
        match message {
            WindowMessage::WindowActivate { is_activated } => {
                self.handle_window_activate(window, *is_activated)
            }
            WindowMessage::KeyboardFocus => self.sync_key_states(window),
            WindowMessage::Key {
                is_sys_key: _,
                is_down,
                w_param,
                l_param,
            } => self.handle_host_key_event(window, *is_down, *w_param, *l_param),
            _ => (),
        }
    }

    pub fn handle_guest_event(&self, window: &GuiWindow, event: virtio_input_event) {
        if let Some(numlock_on) = event.get_led_state(LED_NUML) {
            self.guest_key_states.lock().num_lock_state = numlock_on;
            self.sync_key_states(window);
        } else if let Some(capslock_on) = event.get_led_state(LED_CAPSL) {
            self.guest_key_states.lock().caps_lock_state = capslock_on;
            self.sync_key_states(window);
        }
    }

    #[inline]
    fn handle_window_activate(&self, window: &GuiWindow, is_activated: bool) {
        if !is_activated {
            // To avoid sticky keys, we release keys when our window is deactivated. This prevents
            // common shortcuts like Alt+Tab from leaving a stuck alt key in the guest.
            self.release_any_down_keys(window);
        }
        // If either caps lock or num lock is set, reflect that change in the guest.
        self.sync_key_states(window);
    }

    #[inline]
    fn handle_host_key_event(
        &self,
        window: &GuiWindow,
        key_down: bool,
        _w_param: WPARAM,
        l_param: LPARAM,
    ) {
        let scancode = win_util::scancode_from_lparam(l_param);
        let is_repeat = key_down && get_previous_key_down_from_lparam(l_param);
        if let Some(linux_keycode) = self.keycode_translator.translate(scancode) {
            self.dispatch_linux_key_event(window, linux_keycode, key_down, is_repeat)
        } else {
            error!("Unhandled scancode while handling key event.");
        }
    }

    /// Checks if the caps lock and num lock key states differ between the guest & host. If they do,
    /// send keys to the guest to resync it with the host.
    fn sync_key_states(&self, window: &GuiWindow) {
        if let Some(host_key_states) = get_host_key_states() {
            let mut toggle_caps_lock = false;
            let mut toggle_num_lock = false;
            {
                let states = self.guest_key_states.lock();
                if states.caps_lock_state != host_key_states.caps_lock_state {
                    toggle_caps_lock = true;
                }
                if states.num_lock_state != host_key_states.num_lock_state {
                    toggle_num_lock = true;
                }
            }
            if toggle_caps_lock {
                self.press_and_release_key(window, LINUX_CAPS_LOCK_KEY);
            }
            if toggle_num_lock {
                self.press_and_release_key(window, LINUX_NUM_LOCK_KEY);
            }
        }
    }

    /// Releases any keys that are down when the surface is no longer active. Should be called when
    /// the display window becomes inactive to avoid sticky keys.
    #[inline]
    fn release_any_down_keys(&self, window: &GuiWindow) {
        let mut events = Vec::with_capacity(256);
        let mut keyboard_state: [u8; 256] = [0; 256];
        // SAFETY:
        // Safe because `keyboard_state` is guaranteed to exist, and is of the expected size.
        if unsafe { GetKeyboardState(keyboard_state.as_mut_ptr()) } == 0 {
            error!(
                "Failed in GetKeyboardState: {}",
                // SAFETY: trivially safe
                unsafe { GetLastError() }
            );
            return;
        }

        for (virtual_keycode, key_state) in keyboard_state.iter().enumerate() {
            // Safe because virtual_keycode < 256.
            let virtual_keycode = virtual_keycode as i32;

            // Ignore toggle keys.
            if virtual_keycode == VK_CAPITAL
                || virtual_keycode == VK_NUMLOCK
                || virtual_keycode == VK_SCROLL
            {
                continue;
            }
            if key_state >> 7 == 0u8 {
                // Key is already up.
                continue;
            }

            // SAFETY:
            // Trivially safe (no pointers or errors to check).
            let scancode = unsafe { MapVirtualKeyW(virtual_keycode as u32, MAPVK_VK_TO_VSC) };
            if let Some(linux_keycode) = self.keycode_translator.translate(scancode) {
                events.push(virtio_input_event::key(linux_keycode, false, false));
            } else {
                error!("Failed to translate key while releasing down keys.");
            }
        }

        if !events.is_empty() {
            self.display_event_dispatcher.dispatch(
                window,
                events.as_slice(),
                EventDeviceKind::Keyboard,
            );
        }
    }

    /// Sends a key press and release event to Linux/Android.
    fn press_and_release_key(&self, window: &GuiWindow, key: u16) {
        self.dispatch_linux_key_event(
            window, key, /* key_down= */ true, /* is_repeat= */ false,
        );
        self.dispatch_linux_key_event(
            window, key, /* key_down= */ false, /* is_repeat= */ false,
        );
    }

    /// Directly dispatches a Linux input keycode to the guest.
    fn dispatch_linux_key_event(
        &self,
        window: &GuiWindow,
        linux_keycode: u16,
        key_down: bool,
        is_repeat: bool,
    ) {
        self.display_event_dispatcher.dispatch(
            window,
            &[virtio_input_event::key(linux_keycode, key_down, is_repeat)],
            EventDeviceKind::Keyboard,
        );
    }
}

struct KeyStates {
    caps_lock_state: bool,
    num_lock_state: bool,
}

/// On success, returns a tuple containing current state of caps lock and num lock keys.
fn get_host_key_states() -> Option<KeyStates> {
    let mut keyboard_state: [BYTE; 256] = [0; 256];
    // SAFETY:
    // Safe because `keyboard_state` is guaranteed to exist, and is of the expected size.
    if unsafe { GetKeyboardState(keyboard_state.as_mut_ptr()) } != 0 {
        Some(KeyStates {
            caps_lock_state: toggle_to_bool(keyboard_state[VK_CAPITAL as usize]),
            num_lock_state: toggle_to_bool(keyboard_state[VK_NUMLOCK as usize]),
        })
    } else {
        warn!(
            "Failed in GetKeyboardState: {}",
            // SAFETY: trivially safe
            unsafe { GetLastError() }
        );
        None
    }
}

/// Returns whether the given toggle key state indicates the key is toggled/on (true).
fn toggle_to_bool(key_state: BYTE) -> bool {
    key_state & 0x1 == 0x1
}

/// Extracts the previous key up/down state from the l_param of a WM_KEY/WM_SYSKEY DOWN event.
/// The previous key state is bit #30.
fn get_previous_key_down_from_lparam(l_param: isize) -> bool {
    ((l_param >> 30) & 1) == 1
}
