// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::c_void;
use std::io;
use std::os::raw::c_int;

#[allow(non_camel_case_types)]
type cap_t = *mut c_void;

#[allow(non_camel_case_types)]
pub type cap_value_t = u32;

#[allow(non_camel_case_types)]
type cap_flag_t = u32;

#[allow(non_camel_case_types)]
type cap_flag_value_t = i32;

#[link(name = "cap")]
extern "C" {
    fn cap_free(ptr: *mut c_void) -> c_int;

    fn cap_set_flag(
        c: cap_t,
        f: cap_flag_t,
        ncap: c_int,
        caps: *const cap_value_t,
        val: cap_flag_value_t,
    ) -> c_int;

    fn cap_get_proc() -> cap_t;
    fn cap_set_proc(cap: cap_t) -> c_int;
}

#[repr(u32)]
pub enum Capability {
    Chown = 0,
    DacOverride = 1,
    DacReadSearch = 2,
    Fowner = 3,
    Fsetid = 4,
    Kill = 5,
    Setgid = 6,
    Setuid = 7,
    Setpcap = 8,
    LinuxImmutable = 9,
    NetBindService = 10,
    NetBroadcast = 11,
    NetAdmin = 12,
    NetRaw = 13,
    IpcLock = 14,
    IpcOwner = 15,
    SysModule = 16,
    SysRawio = 17,
    SysChroot = 18,
    SysPtrace = 19,
    SysPacct = 20,
    SysAdmin = 21,
    SysBoot = 22,
    SysNice = 23,
    SysResource = 24,
    SysTime = 25,
    SysTtyConfig = 26,
    Mknod = 27,
    Lease = 28,
    AuditWrite = 29,
    AuditControl = 30,
    Setfcap = 31,
    MacOverride = 32,
    MacAdmin = 33,
    Syslog = 34,
    WakeAlarm = 35,
    BlockSuspend = 36,
    AuditRead = 37,
    Last,
}

impl From<Capability> for cap_value_t {
    fn from(c: Capability) -> cap_value_t {
        c as cap_value_t
    }
}

#[repr(u32)]
pub enum Set {
    Effective = 0,
    Permitted = 1,
    Inheritable = 2,
}

impl From<Set> for cap_flag_t {
    fn from(s: Set) -> cap_flag_t {
        s as cap_flag_t
    }
}

#[repr(i32)]
pub enum Value {
    Clear = 0,
    Set = 1,
}

impl From<Value> for cap_flag_value_t {
    fn from(v: Value) -> cap_flag_value_t {
        v as cap_flag_value_t
    }
}

pub struct Caps(cap_t);

impl Caps {
    /// Get the capabilities for the current thread.
    pub fn for_current_thread() -> io::Result<Caps> {
        // SAFETY:
        // Safe because this doesn't modify any memory and we check the return value.
        let caps = unsafe { cap_get_proc() };
        if caps.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Caps(caps))
        }
    }

    /// Update the capabilities described by `self` by setting or clearing `caps` in `set`.
    pub fn update(&mut self, caps: &[Capability], set: Set, value: Value) -> io::Result<()> {
        // SAFETY:
        // Safe because this only modifies the memory pointed to by `self.0` and we check the return
        // value.
        let ret = unsafe {
            cap_set_flag(
                self.0,
                set.into(),
                caps.len() as c_int,
                // It's safe to cast this pointer because `Capability` is #[repr(u32)]
                caps.as_ptr() as *const cap_value_t,
                value.into(),
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Apply the capabilities described by `self` to the current thread.
    pub fn apply(&self) -> io::Result<()> {
        // SAFETY: trivially safe
        if unsafe { cap_set_proc(self.0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for Caps {
    fn drop(&mut self) {
        // SAFETY: cap_t is allocated from `Self`
        unsafe {
            cap_free(self.0);
        }
    }
}
