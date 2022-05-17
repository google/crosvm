use libslirp_sys::*;

use std::ffi::CStr;
use std::str;

pub fn version() -> &'static str {
    str::from_utf8(unsafe { CStr::from_ptr(slirp_version_string()) }.to_bytes()).unwrap_or("")
}

pub fn state_version() -> i32 {
    unsafe { slirp_state_version() }
}
