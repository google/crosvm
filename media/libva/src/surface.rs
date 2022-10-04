// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::rc::Rc;

use anyhow::Result;

use crate::bindings;
use crate::display::Display;
use crate::status::Status;
use crate::UsageHint;

/// An owned VA surface that is tied to the lifetime of a particular VADisplay
pub struct Surface {
    display: Rc<Display>,
    id: bindings::VASurfaceID,
}

impl Surface {
    /// Create `Surfaces` by wrapping around a `vaCreateSurfaces` call. This is just a helper for
    /// [`Display::create_surfaces`].
    pub(crate) fn new(
        display: Rc<Display>,
        rt_format: u32,
        va_fourcc: Option<u32>,
        width: u32,
        height: u32,
        usage_hint: Option<UsageHint>,
        num_surfaces: u32,
    ) -> Result<Vec<Self>> {
        let mut attrs = vec![];

        if let Some(usage_hint) = usage_hint {
            let attr = bindings::VASurfaceAttrib {
                type_: bindings::VASurfaceAttribType::VASurfaceAttribUsageHint,
                flags: bindings::constants::VA_SURFACE_ATTRIB_SETTABLE,
                value: bindings::VAGenericValue {
                    type_: bindings::VAGenericValueType::VAGenericValueTypeInteger,
                    value: bindings::_VAGenericValue__bindgen_ty_1 {
                        i: usage_hint.bits() as i32,
                    },
                },
            };

            attrs.push(attr);
        }

        if let Some(fourcc) = va_fourcc {
            let attr = bindings::VASurfaceAttrib {
                type_: bindings::VASurfaceAttribType::VASurfaceAttribPixelFormat,
                flags: bindings::constants::VA_DISPLAY_ATTRIB_SETTABLE,
                value: bindings::VAGenericValue {
                    type_: bindings::VAGenericValueType::VAGenericValueTypeInteger,
                    value: bindings::_VAGenericValue__bindgen_ty_1 { i: fourcc as i32 },
                },
            };

            attrs.push(attr);
        }

        let mut surfaces = Vec::with_capacity(num_surfaces as usize);

        // Safe because `self` represents a valid VADisplay. The `surface` and `attrs` vectors are
        // properly initialized and valid sizes are passed to the C function, so it is impossible to
        // write past the end of their storage by mistake.
        Status(unsafe {
            bindings::vaCreateSurfaces(
                display.handle(),
                rt_format,
                width,
                height,
                surfaces.as_mut_ptr(),
                num_surfaces,
                attrs.as_mut_ptr(),
                attrs.len() as u32,
            )
        })
        .check()?;

        // Safe because the C function will have written to exactly `num_surfaces` entries, which is
        // known to be within the vector's capacity.
        unsafe {
            surfaces.set_len(num_surfaces as usize);
        }

        let va_surfaces = surfaces
            .iter()
            .map(|&id| Self {
                display: Rc::clone(&display),
                id,
            })
            .collect();

        Ok(va_surfaces)
    }

    /// Blocks until all pending operations on the render target have been completed. Upon return it
    /// is safe to use the render target for a different picture.
    pub fn sync(&self) -> Result<()> {
        // Safe because `self` represents a valid VASurface.
        Status(unsafe { bindings::vaSyncSurface(self.display.handle(), self.id) }).check()
    }

    /// Convenience function to return a VASurfaceID vector. Useful to interface with the C API
    /// where a surface array might be needed.
    pub fn as_id_vec(surfaces: &[Self]) -> Vec<bindings::VASurfaceID> {
        surfaces.iter().map(|surface| surface.id).collect()
    }

    /// Wrapper over `vaQuerySurfaceStatus` to find out any pending ops on the render target.
    pub fn query_status(&self) -> Result<bindings::VASurfaceStatus::Type> {
        let mut status: bindings::VASurfaceStatus::Type = 0;
        // Safe because `self` represents a valid VASurface.
        Status(unsafe {
            bindings::vaQuerySurfaceStatus(self.display.handle(), self.id, &mut status)
        })
        .check()?;
        Ok(status)
    }

    /// Returns the ID of this surface.
    pub fn id(&self) -> bindings::VASurfaceID {
        self.id
    }
}

impl Drop for Surface {
    fn drop(&mut self) {
        // Safe because `self` represents a valid VASurface.
        unsafe { bindings::vaDestroySurfaces(self.display.handle(), &mut self.id, 1) };
    }
}
