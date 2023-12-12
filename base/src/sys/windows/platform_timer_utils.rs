// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::mem::MaybeUninit;
use std::sync::Once;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;

use win_util::win32_string;
use win_util::win32_wide_string;
use winapi::shared::minwindef;
use winapi::shared::minwindef::HINSTANCE;
use winapi::shared::minwindef::HMODULE;
use winapi::shared::minwindef::PULONG;
use winapi::shared::ntdef::NTSTATUS;
use winapi::shared::ntdef::ULONG;
use winapi::shared::ntstatus::STATUS_SUCCESS;
use winapi::um::libloaderapi;
use winapi::um::mmsystem::TIMERR_NOERROR;
use winapi::um::timeapi::timeBeginPeriod;
use winapi::um::timeapi::timeEndPeriod;
use winapi::um::winnt::BOOLEAN;

use crate::warn;
use crate::Error;
use crate::Result;

static NT_INIT: Once = Once::new();
static mut NT_LIBRARY: MaybeUninit<HMODULE> = MaybeUninit::uninit();

#[inline]
fn init_ntdll() -> Result<HINSTANCE> {
    NT_INIT.call_once(|| {
        // SAFETY: return value is checked.
        unsafe {
            *NT_LIBRARY.as_mut_ptr() =
                libloaderapi::LoadLibraryW(win32_wide_string("ntdll").as_ptr());

            if NT_LIBRARY.assume_init().is_null() {
                warn!("Failed to load ntdll: {}", Error::last());
            }
        };
    });

    // SAFETY: NT_LIBRARY initialized above.
    let handle = unsafe { NT_LIBRARY.assume_init() };
    if handle.is_null() {
        Err(Error::from(io::Error::new(
            io::ErrorKind::NotFound,
            "ntdll failed to load",
        )))
    } else {
        Ok(handle)
    }
}

fn get_symbol(handle: HMODULE, proc_name: &str) -> Result<*mut minwindef::__some_function> {
    // SAFETY: return value is checked.
    let symbol = unsafe { libloaderapi::GetProcAddress(handle, win32_string(proc_name).as_ptr()) };
    if symbol.is_null() {
        Err(Error::last())
    } else {
        Ok(symbol)
    }
}

/// Returns the resolution of timers on the host (current_res, max_res).
pub fn nt_query_timer_resolution() -> Result<(Duration, Duration)> {
    let handle = init_ntdll()?;

    // SAFETY: trivially safe
    let func = unsafe {
        std::mem::transmute::<
            *mut minwindef::__some_function,
            extern "system" fn(PULONG, PULONG, PULONG) -> NTSTATUS,
        >(get_symbol(handle, "NtQueryTimerResolution")?)
    };

    let mut min_res: u32 = 0;
    let mut max_res: u32 = 0;
    let mut current_res: u32 = 0;
    let ret = func(
        &mut min_res as *mut u32,
        &mut max_res as *mut u32,
        &mut current_res as *mut u32,
    );

    if ret != STATUS_SUCCESS {
        Err(Error::from(io::Error::new(
            io::ErrorKind::Other,
            "NtQueryTimerResolution failed",
        )))
    } else {
        Ok((
            Duration::from_nanos((current_res as u64) * 100),
            Duration::from_nanos((max_res as u64) * 100),
        ))
    }
}

pub fn nt_set_timer_resolution(resolution: Duration) -> Result<()> {
    let handle = init_ntdll()?;
    // SAFETY: trivially safe
    let func = unsafe {
        std::mem::transmute::<
            *mut minwindef::__some_function,
            extern "system" fn(ULONG, BOOLEAN, PULONG) -> NTSTATUS,
        >(get_symbol(handle, "NtSetTimerResolution")?)
    };

    let requested_res: u32 = (resolution.as_nanos() / 100) as u32;
    let mut current_res: u32 = 0;
    let ret = func(
        requested_res,
        1, /* true */
        &mut current_res as *mut u32,
    );

    if ret != STATUS_SUCCESS {
        Err(Error::from(io::Error::new(
            io::ErrorKind::Other,
            "NtSetTimerResolution failed",
        )))
    } else {
        Ok(())
    }
}

/// Measures the timer resolution by taking the 90th percentile wall time of 1ms sleeps.
pub fn measure_timer_resolution() -> Duration {
    let mut durations = Vec::with_capacity(100);
    for _ in 0..100 {
        let start = Instant::now();
        // Windows cannot support sleeps shorter than 1ms.
        sleep(Duration::from_millis(1));
        durations.push(Instant::now() - start);
    }

    durations.sort();
    durations[89]
}

/// Note that Durations below 1ms are not supported and will panic.
pub fn set_time_period(res: Duration, begin: bool) -> Result<()> {
    if res.as_millis() < 1 {
        panic!(
            "time(Begin|End)Period does not support values below 1ms, but {:?} was requested.",
            res
        );
    }
    if res.as_millis() > u32::MAX as u128 {
        panic!("time(Begin|End)Period does not support values above u32::MAX.",);
    }

    let ret = if begin {
        // SAFETY: Trivially safe. Note that the casts are safe because we know res is within u32's range.
        unsafe { timeBeginPeriod(res.as_millis() as u32) }
    } else {
        // SAFETY: Trivially safe. Note that the casts are safe because we know res is within u32's range.
        unsafe { timeEndPeriod(res.as_millis() as u32) }
    };
    if ret != TIMERR_NOERROR {
        // These functions only have two return codes: NOERROR and NOCANDO.
        Err(Error::from(io::Error::new(
            io::ErrorKind::InvalidInput,
            "timeBegin/EndPeriod failed",
        )))
    } else {
        Ok(())
    }
}

/// Note that these tests cannot run on Kokoro due to random slowness in that environment.
#[cfg(test)]
mod tests {
    use super::*;

    /// We're testing whether NtSetTimerResolution does what it says on the tin.
    #[test]
    #[ignore]
    fn setting_nt_timer_resolution_changes_resolution() {
        let (old_res, _) = nt_query_timer_resolution().unwrap();

        nt_set_timer_resolution(Duration::from_millis(1)).unwrap();
        assert_res_within_bound(measure_timer_resolution());
        nt_set_timer_resolution(old_res).unwrap();
    }

    #[test]
    #[ignore]
    fn setting_timer_resolution_changes_resolution() {
        let res = Duration::from_millis(1);

        set_time_period(res, true).unwrap();
        assert_res_within_bound(measure_timer_resolution());
        set_time_period(res, false).unwrap();
    }

    fn assert_res_within_bound(actual_res: Duration) {
        assert!(
            actual_res <= Duration::from_millis(2),
            "actual_res was {:?}, expected <= 2ms",
            actual_res
        );
    }
}
