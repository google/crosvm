// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(target_os = "android")]

use std::ffi::CStr;
use std::ffi::CString;

use anyhow::anyhow;
use anyhow::Result;
use libc;

#[link(name = "processgroup")]
extern "C" {
    fn android_set_process_profiles(
        uid: libc::uid_t,
        pid: libc::pid_t,
        num_profiles: libc::size_t,
        profiles: *const *const libc::c_char,
    ) -> bool;
}

// Apply the listed task profiles to all tasks (current and future) in this process.
pub fn set_process_profiles(profiles: &Vec<String>) -> Result<()> {
    if (profiles.is_empty()) {
        return Ok(());
    }
    let owned: Vec<CString> = profiles
        .iter()
        .map(|s| CString::new(s.clone()).unwrap())
        .collect();
    let ptrs: Vec<*const libc::c_char> = owned.iter().map(|s| s.as_ptr()).collect();
    // SAFETY: the ownership of the array of string is not passed. The function copies it
    // internally.
    unsafe {
        if (android_set_process_profiles(libc::getuid(), libc::getpid(), ptrs.len(), ptrs.as_ptr()))
        {
            Ok(())
        } else {
            Err(anyhow!("failed to set task profiles"))
        }
    }
}
