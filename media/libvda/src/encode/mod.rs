// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod bindings;
mod event;
mod format;
mod session;
mod vea_instance;

pub use event::*;
pub use format::*;
pub use session::*;
pub use vea_instance::*;

/// libvda only exists on ChromeOS, so we cannot link against it in a regular environment, which
/// limits our build coverage. These stubs are built if the "chromeos" feature is not specified,
/// which allows build to complete successfully, although the video device will just badly crash if
/// it is ever used.
#[cfg(feature = "libvda-stub")]
mod native_stubs {
    use super::bindings::*;

    #[no_mangle]
    extern "C" fn initialize_encode(_type_: vea_impl_type_t) -> *mut ::std::os::raw::c_void {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn deinitialize_encode(_impl_: *mut ::std::os::raw::c_void) {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn get_vea_capabilities(
        _impl_: *mut ::std::os::raw::c_void,
    ) -> *const vea_capabilities_t {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn init_encode_session(
        _impl_: *mut ::std::os::raw::c_void,
        _config: *mut vea_config_t,
    ) -> *mut vea_session_info_t {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn close_encode_session(
        _impl_: *mut ::std::os::raw::c_void,
        _session_info: *mut vea_session_info_t,
    ) {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn vea_encode(
        _ctx: *mut ::std::os::raw::c_void,
        _input_buffer_id: vea_input_buffer_id_t,
        _fd: ::std::os::raw::c_int,
        _num_planes: usize,
        _planes: *mut video_frame_plane_t,
        _timestamp: i64,
        _force_keyframe: u8,
    ) -> ::std::os::raw::c_int {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn vea_use_output_buffer(
        _ctx: *mut ::std::os::raw::c_void,
        _output_buffer_id: vea_output_buffer_id_t,
        _fd: ::std::os::raw::c_int,
        _offset: u32,
        _size: u32,
    ) -> ::std::os::raw::c_int {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn vea_request_encoding_params_change(
        _ctx: *mut ::std::os::raw::c_void,
        _bitrate: vea_bitrate_t,
        _framerate: u32,
    ) -> ::std::os::raw::c_int {
        unimplemented!()
    }

    #[no_mangle]
    extern "C" fn vea_flush(_ctx: *mut ::std::os::raw::c_void) -> ::std::os::raw::c_int {
        unimplemented!()
    }
}
