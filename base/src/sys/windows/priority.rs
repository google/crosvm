// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::windows::raw::HANDLE;

use log::warn;
use winapi::shared::minwindef::FALSE;
use winapi::um::avrt::AvRevertMmThreadCharacteristics;
use winapi::um::avrt::AvSetMmThreadCharacteristicsA;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::processthreadsapi::GetCurrentThread;
use winapi::um::processthreadsapi::SetThreadPriority;

use super::errno_result;
use super::Result;

pub fn set_audio_thread_priority() -> Result<SafeMultimediaHandle> {
    // SAFETY:
    // Safe because we know Pro Audio is part of windows and we down task_index.
    let multimedia_handle = unsafe {
        let mut task_index: u32 = 0;
        // "Pro Audio" is defined in:
        // HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio
        let pro_audio = std::ffi::CString::new("Pro Audio").unwrap();
        AvSetMmThreadCharacteristicsA(pro_audio.as_ptr(), &mut task_index)
    };

    if multimedia_handle.is_null() {
        warn!(
            "Failed to set audio thread to Pro Audio. Error: {}",
            // SAFETY: trivially safe
            unsafe { GetLastError() }
        );
        errno_result()
    } else {
        Ok(SafeMultimediaHandle { multimedia_handle })
    }
}

pub fn set_thread_priority(thread_priority: i32) -> Result<()> {
    let res =
    // SAFETY:
        // Safe because priority level value is valid and a valid thread handle will be passed in
        unsafe { SetThreadPriority(GetCurrentThread(), thread_priority) };
    if res == 0 {
        errno_result()
    } else {
        Ok(())
    }
}

pub struct SafeMultimediaHandle {
    multimedia_handle: HANDLE,
}

impl Drop for SafeMultimediaHandle {
    fn drop(&mut self) {
        // SAFETY:
        // Safe because we `multimedia_handle` is defined in the same thread and is created in the
        // function above. `multimedia_handle` needs be created from `AvSetMmThreadCharacteristicsA`.
        // This will also drop the `mulitmedia_handle`.
        if unsafe { AvRevertMmThreadCharacteristics(self.multimedia_handle) } == FALSE {
            warn!(
                "Failed to revert audio thread. Error: {}",
                // SAFETY: trivially safe
                unsafe { GetLastError() }
            );
        }
    }
}

#[cfg(test)]
mod test {
    use winapi::um::processthreadsapi::GetCurrentThread;
    use winapi::um::processthreadsapi::GetThreadPriority;
    use winapi::um::winbase::THREAD_PRIORITY_NORMAL;
    use winapi::um::winbase::THREAD_PRIORITY_TIME_CRITICAL;

    use super::*;

    // TODO(b/223733375): Enable ignored flaky tests.
    #[test]
    #[ignore]
    fn test_mm_handle_is_dropped() {
        // SAFETY:
        // Safe because the only the only unsafe functions called are to get the thread
        // priority.
        unsafe {
            let thread_priority = GetThreadPriority(GetCurrentThread());
            assert_eq!(thread_priority, THREAD_PRIORITY_NORMAL as i32);
            {
                let _handle = set_audio_thread_priority();
                let thread_priority = GetThreadPriority(GetCurrentThread());
                assert_eq!(thread_priority, THREAD_PRIORITY_TIME_CRITICAL as i32);
            }
            let thread_priority = GetThreadPriority(GetCurrentThread());
            assert_eq!(thread_priority, THREAD_PRIORITY_NORMAL as i32);
        }
    }
}
