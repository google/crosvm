// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use windows::Win32::UI::Input::KeyboardAndMouse::GetKeyState;

/// Extracts the scancode (scancode set #1 / IBM PC XT) from the l_param of a WM_KEY/WM_SYSKEY
/// event.
pub fn scancode_from_lparam(l_param: isize) -> u32 {
    // Bits 16 - 23 of l_param contain the lower 8 bits of the scancode.
    // https://docs.microsoft.com/en-us/windows/win32/inputdev/wm-keyup
    //
    // Note: conversion from isize to u32 is safe because the bitwise &.
    let lower_scancode = (l_param as u32 >> 16) & 0xFF;

    let is_extended_key = (l_param as u32 >> 24) & 1 == 1;
    if is_extended_key {
        // Extended keys have 16 bit scancodes of the form 0xe0YY, where YY is the
        // lower_scancode extracted above.
        lower_scancode | 0xe000
    } else {
        // Regular keys only use the lower 8 bits of the scancode.
        lower_scancode
    }
}

/// Similar to keys_state, but returns false if any of the specified keys are up.
#[inline]
pub fn keys_down(keys: &[i32]) -> bool {
    keys_state(keys).unwrap_or(false)
}

/// Returns whether a list of keys are all down or all up, or None if they do not match.
/// Note that this does NOT work for toggle keys like the caps lock.
#[inline]
fn keys_state(keys: &[i32]) -> Option<bool> {
    let mut all_down: Option<bool> = None;
    for key in keys {
        // If the high order bit is set, the key is down
        // SAFETY: Trivially safe (no pointers, return code is checked).
        let key_down = unsafe { GetKeyState(*key) } >> 15 & 0x1 == 0x1;
        match all_down {
            Some(other_keys_down) => {
                if other_keys_down != key_down {
                    return None;
                }
            }
            None => all_down = Some(key_down),
        }
    }
    all_down
}
