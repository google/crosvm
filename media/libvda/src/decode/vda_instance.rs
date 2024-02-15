// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module provides type safe interfaces for each operation exposed by Chrome's
//! VideoDecodeAccelerator.

use std::os::raw::c_void;
use std::rc::Rc;

use super::bindings;
use super::format::*;
use super::session::*;
use crate::error::*;
use crate::format::*;

/// Represents a backend implementation of libvda.
pub enum VdaImplType {
    Fake,
    Gavda, // GpuArcVideoDecodeAccelerator
    Gavd,  // GpuArcVideoDecoder
}

/// Represents decoding capabilities of libvda instances.
pub struct Capabilities {
    pub input_formats: Vec<InputFormat>,
    pub output_formats: Vec<PixelFormat>,
}

// An active connection to the VDA, which closes automatically as it is dropped.
pub struct VdaConnection {
    // `conn_ptr` must be a valid pointer obtained from `decode_bindings::initialize`.
    conn_ptr: *mut c_void,
}

impl VdaConnection {
    fn new(typ: VdaImplType) -> Result<Self> {
        let impl_type = match typ {
            VdaImplType::Fake => bindings::vda_impl_type_FAKE,
            VdaImplType::Gavda => bindings::vda_impl_type_GAVDA,
            VdaImplType::Gavd => bindings::vda_impl_type_GAVD,
        };

        // Safe because libvda's API is called properly.
        match unsafe { bindings::initialize(impl_type) } {
            ptr if ptr.is_null() => Err(Error::InstanceInitFailure),
            conn_ptr => Ok(VdaConnection { conn_ptr }),
        }
    }

    // Returns the raw pointer to the VDA connection instance that can be passed
    // to bindings functions that require it.
    pub(super) fn conn_ptr(&self) -> *mut c_void {
        self.conn_ptr
    }
}

impl Drop for VdaConnection {
    fn drop(&mut self) {
        // Safe because libvda's API is called properly.
        unsafe { bindings::deinitialize(self.conn_ptr) }
    }
}

/// Represents a libvda instance.
pub struct VdaInstance {
    connection: Rc<VdaConnection>,
    caps: Capabilities,
}

impl VdaInstance {
    /// Creates VdaInstance. `typ` specifies which backend will be used.
    pub fn new(typ: VdaImplType) -> Result<Self> {
        let connection = VdaConnection::new(typ)?;

        // Get available input/output formats.
        // Safe because `conn_ptr` is valid and `get_vda_capabilities()` won't invalidate it.
        let vda_cap_ptr = unsafe { bindings::get_vda_capabilities(connection.conn_ptr) };
        if vda_cap_ptr.is_null() {
            return Err(Error::GetCapabilitiesFailure);
        }
        // Safe because `vda_cap_ptr` is not NULL.
        let vda_cap = unsafe { *vda_cap_ptr };

        // Safe because `input_formats` is valid for |`num_input_formats`| elements if both are
        // valid.
        let input_formats = unsafe {
            InputFormat::from_raw_parts(vda_cap.input_formats, vda_cap.num_input_formats)?
        };

        // Output formats
        // Safe because `output_formats` is valid for |`num_output_formats`| elements if both are
        // valid.
        let output_formats = unsafe {
            PixelFormat::from_raw_parts(vda_cap.output_formats, vda_cap.num_output_formats)?
        };

        Ok(VdaInstance {
            connection: Rc::new(connection),
            caps: Capabilities {
                input_formats,
                output_formats,
            },
        })
    }

    /// Get media capabilities.
    pub fn get_capabilities(&self) -> &Capabilities {
        &self.caps
    }

    /// Opens a new `Session` for a given `Profile`.
    pub fn open_session(&self, profile: Profile) -> Result<Session> {
        Session::new(&self.connection, profile).ok_or(Error::SessionInitFailure(profile))
    }
}
