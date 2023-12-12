// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Stdin;

use winapi::shared::minwindef::DWORD;
use winapi::um::consoleapi::GetConsoleMode;
use winapi::um::consoleapi::SetConsoleMode;
use winapi::um::wincon::ENABLE_ECHO_INPUT;
use winapi::um::wincon::ENABLE_LINE_INPUT;
use winapi::um::wincon::ENABLE_PROCESSED_INPUT;
use winapi::um::wincon::ENABLE_VIRTUAL_TERMINAL_INPUT;

use crate::AsRawDescriptor;
use crate::Error;
use crate::RawDescriptor;
use crate::Result;

/// Trait for file descriptors that are terminals.
///
/// # Safety
/// This is marked unsafe because the implementation must promise that the returned RawDescriptor is
/// a valid descriptor and that the lifetime of the returned descriptor is at least that of the
/// trait object.
pub unsafe trait Terminal {
    /// Gets the file descriptor of the terminal.
    fn terminal_descriptor(&self) -> RawDescriptor;

    /// Set this terminal's mode to raw mode.
    ///
    /// Returns the original mode, which can be passed to `restore_mode()` to reset the terminal to
    /// its previous state.
    fn set_raw_mode(&self) -> Result<DWORD> {
        let descriptor = self.terminal_descriptor();
        let mut orig_mode = 0;

        // SAFETY:
        // Safe because we provide a valid descriptor and pointer and we check the return result.
        if unsafe { GetConsoleMode(descriptor, &mut orig_mode) } == 0 {
            return Err(Error::last());
        }

        let new_mode = (orig_mode | ENABLE_VIRTUAL_TERMINAL_INPUT)
            & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);

        // SAFETY:
        // Safe because the syscall will only read the extent of mode and we check the return result.
        if unsafe { SetConsoleMode(descriptor, new_mode) } == 0 {
            return Err(Error::last());
        }

        Ok(orig_mode)
    }

    /// Set this terminal's mode to a previous state returned by `set_raw_mode()`.
    fn restore_mode(&self, mode: DWORD) -> Result<()> {
        // SAFETY:
        // Safe because the syscall will only read the extent of mode and we check the return result.
        if unsafe { SetConsoleMode(self.terminal_descriptor(), mode) } == 0 {
            Err(Error::last())
        } else {
            Ok(())
        }
    }
}

// SAFETY:
// Safe because we return a genuine terminal descriptor that never changes and shares our lifetime.
unsafe impl Terminal for Stdin {
    fn terminal_descriptor(&self) -> RawDescriptor {
        self.as_raw_descriptor()
    }
}
