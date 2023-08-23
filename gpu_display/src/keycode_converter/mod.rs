// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod data;

use std::collections::HashMap;

use data::MapEntry;
use data::KEYCODE_MAP;

/// Specifies which type of scancode to convert *from* in the KeycodeTranslator.
#[allow(dead_code)]
pub enum KeycodeTypes {
    XkbScancode,
    WindowsScancode,
    MacScancode,
}

/// Translates scancodes of a particular type into Linux keycodes.
#[cfg_attr(windows, allow(dead_code))]
pub struct KeycodeTranslator {
    keycode_map: HashMap<u32, MapEntry>,
}

#[cfg_attr(windows, allow(dead_code))]
impl KeycodeTranslator {
    /// Create a new KeycodeTranslator that translates from the `from_type` type to Linux keycodes.
    pub fn new(from_type: KeycodeTypes) -> KeycodeTranslator {
        let mut kcm: HashMap<u32, MapEntry> = HashMap::new();
        for entry in KEYCODE_MAP.iter() {
            kcm.insert(
                match from_type {
                    KeycodeTypes::XkbScancode => entry.xkb,
                    KeycodeTypes::WindowsScancode => entry.win,
                    KeycodeTypes::MacScancode => entry.mac,
                },
                *entry,
            );
        }
        KeycodeTranslator { keycode_map: kcm }
    }

    /// Translates the scancode in `from_code` into a Linux keycode.
    pub fn translate(&self, from_code: u32) -> Option<u16> {
        Some(self.keycode_map.get(&from_code)?.linux_keycode)
    }
}

#[cfg(test)]
mod tests {
    use crate::keycode_converter::KeycodeTranslator;
    use crate::keycode_converter::KeycodeTypes;

    #[test]
    fn test_translate_win_lin() {
        let translator = KeycodeTranslator::new(KeycodeTypes::WindowsScancode);
        let translated_code = translator.translate(0x47);
        assert!(translated_code.is_some());
        assert_eq!(translated_code.unwrap(), 71);
    }

    #[test]
    fn test_translate_missing_entry() {
        let translator = KeycodeTranslator::new(KeycodeTypes::WindowsScancode);

        // No keycodes are this large.
        let translated_code = translator.translate(0x9999999);
        assert!(translated_code.is_none());
    }
}
