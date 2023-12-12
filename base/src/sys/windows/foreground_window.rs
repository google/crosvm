// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use winapi::shared::minwindef::DWORD;
use winapi::um::winuser::AllowSetForegroundWindow;

use crate::errno_result;
use crate::Result;

/// Grants the given process id temporary permission to foreground another window. This succeeds
/// only when the emulator is in the foreground, and will persist only until the next user
/// interaction with the window
pub fn give_foregrounding_permission(process_id: DWORD) -> Result<()> {
    // SAFETY:
    // Safe because this API does not modify memory, and process_id remains in scope for
    // the duration of the call.
    match unsafe { AllowSetForegroundWindow(process_id) } {
        0 => errno_result(),
        _ => Ok(()),
    }
}
