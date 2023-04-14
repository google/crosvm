// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::upper_case_acronyms)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

pub const __bool_true_false_are_defined: u32 = 1;
pub const true_: u32 = 1;
pub const false_: u32 = 0;
pub const _VCRT_COMPILER_PREPROCESSOR: u32 = 1;
pub const _SAL_VERSION: u32 = 20;
pub const __SAL_H_VERSION: u32 = 180000000;
pub const _USE_DECLSPECS_FOR_SAL: u32 = 0;
pub const _USE_ATTRIBUTES_FOR_SAL: u32 = 0;
pub const _CRT_PACKING: u32 = 8;
pub const _HAS_EXCEPTIONS: u32 = 1;
pub const _STL_LANG: u32 = 0;
pub const _HAS_CXX17: u32 = 0;
pub const _HAS_CXX20: u32 = 0;
pub const _HAS_NODISCARD: u32 = 0;
pub const WCHAR_MIN: u32 = 0;
pub const WCHAR_MAX: u32 = 65535;
pub const WINT_MIN: u32 = 0;
pub const WINT_MAX: u32 = 65535;
pub const CTRACE_API_VERSION: u32 = 1;
pub const _CTRACE_TYPE_SLICE_BEGIN: u32 = 1;
pub const _CTRACE_TYPE_SLICE_END: u32 = 2;
pub type wchar_t = ::std::os::raw::c_ushort;
pub type max_align_t = f64;
pub type va_list = *mut ::std::os::raw::c_char;
extern "C" {
    pub fn __va_start(arg1: *mut *mut ::std::os::raw::c_char, ...);
}
pub type __vcrt_bool = bool;
extern "C" {
    pub fn __security_init_cookie();
}
extern "C" {
    pub fn __security_check_cookie(_StackCookie: usize);
}
extern "C" {
    pub fn __report_gsfailure(_StackCookie: usize) -> !;
}
extern "C" {
    pub static mut __security_cookie: usize;
}
pub type int_least8_t = ::std::os::raw::c_schar;
pub type int_least16_t = ::std::os::raw::c_short;
pub type int_least32_t = ::std::os::raw::c_int;
pub type int_least64_t = ::std::os::raw::c_longlong;
pub type uint_least8_t = ::std::os::raw::c_uchar;
pub type uint_least16_t = ::std::os::raw::c_ushort;
pub type uint_least32_t = ::std::os::raw::c_uint;
pub type uint_least64_t = ::std::os::raw::c_ulonglong;
pub type int_fast8_t = ::std::os::raw::c_schar;
pub type int_fast16_t = ::std::os::raw::c_int;
pub type int_fast32_t = ::std::os::raw::c_int;
pub type int_fast64_t = ::std::os::raw::c_longlong;
pub type uint_fast8_t = ::std::os::raw::c_uchar;
pub type uint_fast16_t = ::std::os::raw::c_uint;
pub type uint_fast32_t = ::std::os::raw::c_uint;
pub type uint_fast64_t = ::std::os::raw::c_ulonglong;
pub type intmax_t = ::std::os::raw::c_longlong;
pub type uintmax_t = ::std::os::raw::c_ulonglong;
pub const BackendType_CTRACE_UNSPECIFIED_BACKEND: BackendType = 0;
pub const BackendType_CTRACE_IN_PROCESS_BACKEND: BackendType = 1;
pub const BackendType_CTRACE_SYSTEM_BACKEND: BackendType = 2;
pub type BackendType = ::std::os::raw::c_int;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ctrace_category {
    pub client_index: u64,
    pub instances_callback:
        ::std::option::Option<unsafe extern "C" fn(instances: u32, client_index: u64)>,
    pub name: *const ::std::os::raw::c_char,
    pub description: *const ::std::os::raw::c_char,
    pub tags: [*const ::std::os::raw::c_char; 4usize],
}
impl Default for ctrace_category {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ctrace_clock {
    pub clock_id: u32,
    pub timestamp: u64,
    pub is_incremental: bool,
    pub unit_multiplier_ns: u64,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ctrace_clock_snapshot {
    pub clocks: [ctrace_clock; 2usize],
}
extern "C" {
    pub fn ctrace_register_categories(c_cats: *const *const ctrace_category, max: u64) -> u64;
}
extern "C" {
    pub fn ctrace_add_clock_snapshot(snapshot: *mut ctrace_clock_snapshot);
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ctrace_init_args {
    pub api_version: u32,
    pub backend: u32,
    pub shmem_size_hint_kb: u32,
    pub shmem_page_size_hint_kb: u32,
    pub shmem_batch_commits_duration_ms: u32,
}
extern "C" {
    pub fn ctrace_init(arg1: *const ctrace_init_args);
}
extern "C" {
    pub fn trace_event_begin(
        category_index: u64,
        instances: u32,
        name: *const ::std::os::raw::c_char,
    );
}
extern "C" {
    pub fn trace_event_end(category_index: u64, instances: u32);
}
extern "C" {
    pub fn trace_event_instant(
        category_index: u64,
        instances: u32,
        name: *const ::std::os::raw::c_char,
    );
}
extern "C" {
    pub fn trace_counter(
        category_index: u64,
        instances: u32,
        track: *const ::std::os::raw::c_char,
        value: i64,
    );
}
extern "C" {
    pub fn trace_create_async(
        category_index: u64,
        instances: u32,
        name: *const ::std::os::raw::c_char,
    ) -> u64;
}
extern "C" {
    pub fn trace_begin_async(
        category_index: u64,
        instances: u32,
        name: *const ::std::os::raw::c_char,
        terminating_flow_id: u64,
    );
}
extern "C" {
    pub fn trace_pause_async(category_index: u64, instances: u32) -> u64;
}
extern "C" {
    pub fn trace_end_async(category_index: u64, instances: u32);
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ctrace_trace_config {
    pub duration_ms: u32,
    pub buffer_size_kb: u32,
}
pub type ctrace_trace_session_handle = *mut ::std::os::raw::c_void;
extern "C" {
    pub fn ctrace_trace_start(arg1: *const ctrace_trace_config) -> ctrace_trace_session_handle;
}
extern "C" {
    pub fn ctrace_trace_start_from_config_proto(
        arg1: *mut ::std::os::raw::c_void,
        arg2: u64,
    ) -> ctrace_trace_session_handle;
}
extern "C" {
    pub fn ctrace_trace_stop(
        arg1: ctrace_trace_session_handle,
        arg2: *const ::std::os::raw::c_char,
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ctrace_trace_buffer {
    pub std_vec: *mut ::std::os::raw::c_void,
    pub data: *mut ::std::os::raw::c_void,
    pub size: u64,
}
impl Default for ctrace_trace_buffer {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
extern "C" {
    pub fn ctrace_free_trace_buffer(arg1: *mut ctrace_trace_buffer);
}
extern "C" {
    pub fn ctrace_trace_stop_to_buffer(arg1: ctrace_trace_session_handle) -> ctrace_trace_buffer;
}
