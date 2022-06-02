// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements a lightweight and safe interface over the conversion functions of
//! `libswscale`. It is designed to concentrate all calls to unsafe methods in one place, while
//! providing a higher-level interface for converting decoded frames from one format to another.

use base::{MappedRegion, MemoryMappingArena, MmapError};
use thiserror::Error as ThisError;

use crate::avcodec::AvFrame;
use crate::ffi;

const MAX_FFMPEG_PLANES: usize = 4;

pub trait SwConverterTarget {
    fn stride(&self) -> Option<usize>;
    fn num_planes(&self) -> usize;
    fn get_mapping(
        &mut self,
        plane: usize,
        required_size: usize,
    ) -> Result<MemoryMappingArena, MmapError>;
}

/// A struct able to copy a decoded `AvFrame` into an `OutputBuffer`'s memory, converting the pixel
/// format if needed.
pub struct SwConverter {
    sws_context: *mut ffi::SwsContext,
    dst_pix_format: ffi::AVPixelFormat,
}

#[derive(Debug, ThisError)]
pub enum ConversionError {
    #[error("cannot map destination buffer: {0}")]
    CannotMapBuffer(base::MmapError),
    #[error("resource has no plane description, at least 1 is required")]
    NoPlanesInResource,
    #[error(
        "resource has more planes ({0}) than ffmpeg can handle ({})",
        MAX_FFMPEG_PLANES
    )]
    TooManyPlanesInTarget(usize),
}

impl Drop for SwConverter {
    fn drop(&mut self) {
        // Safe because `sws_context` is valid through the life of this object.
        unsafe { ffi::sws_freeContext(self.sws_context) };
    }
}

impl SwConverter {
    /// Create a new format converter that will convert frames from `src_format` to `dst_format`.
    ///
    /// `width` and `height` are the coded size of the frames to be converted. The source and target
    /// must have the same size in pixels.
    pub fn new(
        width: usize,
        height: usize,
        src_pix_format: ffi::AVPixelFormat,
        dst_pix_format: ffi::AVPixelFormat,
    ) -> anyhow::Result<Self> {
        // Safe because we don't pass any non-null pointer to this function.
        let sws_context = unsafe {
            ffi::sws_getContext(
                width as i32,
                height as i32,
                src_pix_format,
                width as i32,
                height as i32,
                dst_pix_format,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if sws_context.is_null() {
            anyhow::bail!("error while creating the SWS context")
        }

        Ok(Self {
            sws_context,
            dst_pix_format,
        })
    }

    /// Copy `src` into `dst` while converting its pixel format according to the parameters the
    /// frame converter was created with.
    pub fn convert<T: SwConverterTarget>(
        &mut self,
        src: &AvFrame,
        dst: &mut T,
    ) -> Result<(), ConversionError> {
        let stride = dst.stride().ok_or(ConversionError::NoPlanesInResource)? as i32;

        let required_mapping_size =
            // Safe because this function does not take any pointer, it just performs a size
            // calculation.
            unsafe { ffi::av_image_get_buffer_size(self.dst_pix_format, stride, src.height, 1) }
                as usize;

        // Map the destination resource so the conversion function can write into it.
        let mapping = dst
            .get_mapping(0, required_mapping_size)
            .map_err(ConversionError::CannotMapBuffer)?;

        let mut dst_stride = [0i32; MAX_FFMPEG_PLANES];
        let mut dst_data = [std::ptr::null_mut(); MAX_FFMPEG_PLANES];
        if dst.num_planes() > MAX_FFMPEG_PLANES {
            return Err(ConversionError::TooManyPlanesInTarget(dst.num_planes()));
        }

        // crosvm currently only supports single-buffer frames, so we just need to compute the
        // destination address of each plane according to the destination format.
        // Safe because `dst_data` and `dst_stride` are of the expected size for this function and
        // the mapping is large enough to cover the whole frame.
        unsafe {
            ffi::av_image_fill_arrays(
                dst_data.as_mut_ptr(),
                dst_stride.as_mut_ptr(),
                mapping.as_ptr(),
                self.dst_pix_format,
                stride,
                src.height,
                1,
            )
        };

        // Safe because `sws_context`, `src_ref.data` and `dst_data` are all valid pointers, and
        // we made sure the sizes provided are within the bounds of the buffers.
        unsafe {
            ffi::sws_scale(
                self.sws_context,
                src.data.as_ptr() as *const *const u8,
                src.linesize.as_ptr(),
                0,
                src.height,
                dst_data.as_ptr(),
                dst_stride.as_ptr(),
            );
        }

        Ok(())
    }
}
