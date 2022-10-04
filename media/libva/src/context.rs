// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::rc::Rc;

use anyhow::Result;
use base::error;

use crate::bindings;
use crate::buffer::Buffer;
use crate::buffer_type::BufferType;
use crate::display::Display;
use crate::status::Status;
use crate::Config;
use crate::Surface;

/// An owned Context that is tied to the lifetime of a particular Display
pub struct Context {
    display: Rc<Display>,
    id: bindings::VAContextID,
}

impl Context {
    /// Create a Context by wrapping around a vaCreateContext call.
    ///  `config` is the configuration for the context
    ///  `coded_width` is the coded picture width
    ///  `coded_height` is the coded picture height
    ///  `progressive` is whether only progressive frame pictures are present in the sequence
    ///  `surfaces` are a hint for the amount of surfaces tied to the context
    pub(crate) fn new(
        display: Rc<Display>,
        config: &Config,
        coded_width: i32,
        coded_height: i32,
        surfaces: Option<&Vec<Surface>>,
        progressive: bool,
    ) -> Result<Rc<Self>> {
        let mut context_id = 0;
        let flags = if progressive {
            bindings::constants::VA_PROGRESSIVE as i32
        } else {
            0
        };

        let mut render_targets = match surfaces {
            Some(surfaces) => Surface::as_id_vec(surfaces),
            None => Default::default(),
        };

        // Safe because `self` represents a valid VADisplay and render_targets
        // and ntargets are properly initialized. Note that render_targets==NULL
        // is valid so long as ntargets==0.
        Status(unsafe {
            bindings::vaCreateContext(
                display.handle(),
                config.id(),
                coded_width,
                coded_height,
                flags,
                render_targets.as_mut_ptr(),
                render_targets.len() as i32,
                &mut context_id,
            )
        })
        .check()?;

        Ok(Rc::new(Self {
            display,
            id: context_id,
        }))
    }

    /// Returns the inner VADisplay
    pub fn display(&self) -> Rc<Display> {
        Rc::clone(&self.display)
    }

    /// Returns the VAContextID for this Context
    pub(crate) fn id(&self) -> bindings::VAContextID {
        self.id
    }

    /// Create a buffer by wrapping a vaCreateBuffer call. `type_` describes the
    /// underlying data to libva.
    pub fn create_buffer(self: &Rc<Self>, type_: BufferType) -> Result<Buffer> {
        Buffer::new(Rc::clone(self), type_)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // Safe because `self` represents a valid VAContext.
        let status =
            Status(unsafe { bindings::vaDestroyContext(self.display.handle(), self.id) }).check();
        if status.is_err() {
            error!("vaDestroyContext failed: {}", status.unwrap_err());
        }
    }
}
