// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::rc::Rc;

use anyhow::Result;
use log::error;

use crate::bindings;
use crate::buffer_type::BufferType;
use crate::status::Status;
use crate::Context;
use crate::IQMatrix;
use crate::PictureParameter;
use crate::SliceParameter;

/// Wrapper type representing a buffer created with `vaCreateBuffer`.
pub struct Buffer {
    context: Rc<Context>,
    id: bindings::VABufferID,
}

impl Buffer {
    /// Creates a new buffer by wrapping a `vaCreateBuffer` call. This is just a helper for
    /// [`Context::create_buffer`].
    pub(crate) fn new(context: Rc<Context>, mut type_: BufferType) -> Result<Self> {
        let mut buffer_id = 0;

        let (ptr, size) = match type_ {
            BufferType::PictureParameter(ref mut picture_param) => match picture_param {
                PictureParameter::MPEG2(ref mut wrapper) => (
                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of_val(wrapper.inner_mut()),
                ),
                PictureParameter::VP8(ref mut wrapper) => (
                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of_val(wrapper.inner_mut()),
                ),
                PictureParameter::VP9(ref mut wrapper) => (
                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of_val(wrapper.inner_mut()),
                ),
                PictureParameter::H264(ref mut wrapper) => (
                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of_val(wrapper.inner_mut()),
                ),
            },

            BufferType::SliceParameter(ref mut slice_param) => match slice_param {
                SliceParameter::MPEG2(ref mut wrapper) => (
                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of_val(wrapper.inner_mut()),
                ),
                SliceParameter::VP8(ref mut wrapper) => (
                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of_val(wrapper.inner_mut()),
                ),
                SliceParameter::VP9(ref mut wrapper) => (
                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of_val(wrapper.inner_mut()),
                ),
                SliceParameter::H264(ref mut wrapper) => (
                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of_val(wrapper.inner_mut()),
                ),
            },

            BufferType::IQMatrix(ref mut iq_matrix) => match iq_matrix {
                IQMatrix::MPEG2(ref mut wrapper) => (
                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of_val(wrapper.inner_mut()),
                ),
                IQMatrix::VP8(ref mut wrapper) => (
                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of_val(wrapper.inner_mut()),
                ),
                IQMatrix::H264(ref mut wrapper) => (
                    wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of_val(wrapper.inner_mut()),
                ),
            },

            BufferType::Probability(ref mut wrapper) => (
                wrapper.inner_mut() as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of_val(wrapper.inner_mut()),
            ),

            BufferType::SliceData(ref mut data) => {
                (data.as_mut_ptr() as *mut std::ffi::c_void, data.len())
            }
        };

        // Safe because `self` represents a valid `VAContext`. `ptr` and `size` are also ensured to
        // be correct, as `ptr` is just a cast to `*c_void` from a Rust struct, and `size` is
        // computed from `std::mem::size_of_val`.
        Status(unsafe {
            bindings::vaCreateBuffer(
                context.display().handle(),
                context.id(),
                type_.inner(),
                size as u32,
                1,
                ptr,
                &mut buffer_id,
            )
        })
        .check()?;

        Ok(Self {
            context,
            id: buffer_id,
        })
    }

    /// Convenience function to return a `VABufferID` vector from a slice of `Buffer`s in order to
    /// easily interface with the C API where a buffer array might be needed.
    pub fn as_id_vec(buffers: &[Self]) -> Vec<bindings::VABufferID> {
        buffers.iter().map(|buffer| buffer.id).collect()
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // Safe because `self` represents a valid buffer, created with
        // vaCreateBuffers.
        let status =
            Status(unsafe { bindings::vaDestroyBuffer(self.context.display().handle(), self.id) })
                .check();
        if status.is_err() {
            error!("vaDestroyBuffer failed: {}", status.unwrap_err());
        }
    }
}
