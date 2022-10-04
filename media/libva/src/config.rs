// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::rc::Rc;

use anyhow::Result;
use base::error;

use crate::bindings;
use crate::display::Display;
use crate::generic_value::GenericValue;
use crate::status::Status;

/// A configuration for a given [`Display`].
pub struct Config {
    display: Rc<Display>,
    id: bindings::VAConfigID,
}

impl Config {
    /// Creates a Config by wrapping around the `vaCreateConfig` call. This is just a helper for
    /// [`Display::create_config`].
    pub(crate) fn new(
        display: Rc<Display>,
        mut attrs: Vec<bindings::VAConfigAttrib>,
        profile: bindings::VAProfile::Type,
        entrypoint: bindings::VAEntrypoint::Type,
    ) -> Result<Self> {
        let mut config_id = 0u32;

        // Safe because `self` represents a valid `VADisplay`.
        //
        // The `attrs` vector is also properly initialized and its actual size is passed to
        // `vaCreateConfig`, so it is impossible to write past the end of its storage by mistake.
        Status(unsafe {
            bindings::vaCreateConfig(
                display.handle(),
                profile,
                entrypoint,
                attrs.as_mut_ptr(),
                attrs.len() as i32,
                &mut config_id,
            )
        })
        .check()?;

        Ok(Self {
            display,
            id: config_id,
        })
    }

    /// Returns the ID of this config.
    pub(crate) fn id(&self) -> bindings::VAConfigID {
        self.id
    }

    // Queries surface attributes for this config.
    //
    // This function queries for all supported attributes for this configuration. In particular, if
    // the underlying hardware supports the creation of VA surfaces in various formats, then this
    // function will enumerate all pixel formats that are supported.
    fn query_surface_attributes(&mut self) -> Result<Vec<bindings::VASurfaceAttrib>> {
        // Safe because `self` represents a valid VAConfig. We first query how
        // much space is needed by the C API by passing in NULL in the first
        // call to `vaQuerySurfaceAttributes`.
        let attrs_len: std::os::raw::c_uint = 0;
        Status(unsafe {
            bindings::vaQuerySurfaceAttributes(
                self.display.handle(),
                self.id,
                std::ptr::null_mut(),
                &attrs_len as *const _ as *mut std::os::raw::c_uint,
            )
        })
        .check()?;

        let mut attrs = Vec::with_capacity(attrs_len as usize);
        // Safe because we allocate a vector with the required capacity as
        // returned by the initial call to vaQuerySurfaceAttributes. We then
        // pass a valid pointer to it.
        Status(unsafe {
            bindings::vaQuerySurfaceAttributes(
                self.display.handle(),
                self.id,
                attrs.as_mut_ptr(),
                &attrs_len as *const _ as *mut std::os::raw::c_uint,
            )
        })
        .check()?;

        // Safe because vaQuerySurfaceAttributes will have written to
        // exactly attrs_len entries in the vector.
        unsafe {
            attrs.set_len(attrs_len as usize);
        }

        Ok(attrs)
    }

    /// Query the surface attributes of type `attr_type`. The attribute may or may not be defined by
    /// the driver.
    pub fn query_surface_attributes_by_type(
        &mut self,
        attr_type: bindings::VASurfaceAttribType::Type,
    ) -> Result<Vec<GenericValue>> {
        let surface_attributes = self.query_surface_attributes()?;

        surface_attributes
            .into_iter()
            .filter(|attr| attr.type_ == attr_type)
            .map(|attrib| GenericValue::try_from(attrib.value))
            .collect()
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        // Safe because `self` represents a valid Config.
        let status =
            Status(unsafe { bindings::vaDestroyConfig(self.display.handle(), self.id) }).check();
        if status.is_err() {
            error!("vaDestroyConfig failed: {}", status.unwrap_err());
        }
    }
}
