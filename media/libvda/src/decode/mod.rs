// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod bindings;
mod event;
mod format;
mod session;
mod vda_instance;

pub use event::*;
pub use format::*;
pub use session::*;
pub use vda_instance::*;

/// libvda only exists on ChromeOS, so we cannot link against it in a regular environment, which
/// limits our build coverage. These stubs are built if the "chromeos" feature is not specified,
/// which allows build to complete successfully, although the video device will just badly crash if
/// it is ever used.
#[cfg(feature = "libvda-stub")]
mod native_stubs {
    use super::bindings::*;

    #[no_mangle]
    extern "C" fn initialize(_impl_type: vda_impl_type_t) -> *mut ::std::os::raw::c_void {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn deinitialize(_impl_: *mut ::std::os::raw::c_void) {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn get_vda_capabilities(
        _impl_: *mut ::std::os::raw::c_void,
    ) -> *const vda_capabilities_t {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn init_decode_session(
        _impl_: *mut ::std::os::raw::c_void,
        _profile: vda_profile_t,
    ) -> *mut vda_session_info_t {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn close_decode_session(
        _impl_: *mut ::std::os::raw::c_void,
        _session_info: *mut vda_session_info_t,
    ) {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn vda_decode(
        _ctx: *mut ::std::os::raw::c_void,
        _bitstream_id: i32,
        _fd: ::std::os::raw::c_int,
        _offset: u32,
        _bytes_used: u32,
    ) -> vda_result_t {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn vda_set_output_buffer_count(
        _ctx: *mut ::std::os::raw::c_void,
        _num_output_buffers: usize,
    ) -> vda_result_t {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn vda_use_output_buffer(
        _ctx: *mut ::std::os::raw::c_void,
        _picture_buffer_id: i32,
        _format: vda_pixel_format_t,
        _fd: ::std::os::raw::c_int,
        _num_planes: usize,
        _planes: *mut video_frame_plane_t,
        _modifier: u64,
    ) -> vda_result_t {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn vda_reuse_output_buffer(
        _ctx: *mut ::std::os::raw::c_void,
        _picture_buffer_id: i32,
    ) -> vda_result_t {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn vda_flush(_ctx: *mut ::std::os::raw::c_void) -> vda_result_t {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn vda_reset(_ctx: *mut ::std::os::raw::c_void) -> vda_result_t {
        unimplemented!()
    }
}
