// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements a lightweight and safe interface over the conversion functions of
//! `libswscale`. It is designed to concentrate all calls to unsafe methods in one place, while
//! providing a higher-level interface for converting decoded frames from one format to another.

use thiserror::Error as ThisError;

use crate::avcodec::AvError;
use crate::avcodec::AvFrame;
use crate::ffi;

/// A struct able to copy a decoded `AvFrame` into an `OutputBuffer`'s memory, converting the pixel
/// format if needed.
pub struct SwConverter {
    sws_context: *mut ffi::SwsContext,
    src_pix_format: ffi::AVPixelFormat,
    dst_pix_format: ffi::AVPixelFormat,
}

#[derive(Debug, ThisError)]
pub enum ConversionError {
    #[error("AvFrame's format {frame} does not match converter {converter} configuration")]
    FormatMismatch {
        frame: ffi::AVPixelFormat,
        converter: ffi::AVPixelFormat,
    },
    #[error("source AvFrame's dimension does not match destination's")]
    DimensionMismatch,
    #[error("destination AvFrame needs to be refcounted with refcount=1")]
    NotWritable,
    #[error("error during conversion with libswscale: {0}")]
    AvError(#[from] AvError),
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
            src_pix_format,
            dst_pix_format,
        })
    }

    /// Copy `src` into `dst` while converting its pixel format according to the parameters the
    /// frame converter was created with.
    ///
    /// `dst` must be a [writable] frame with the same dimensions as `src` and the same format as
    /// `dst_pix_format` passed to the constructor.
    ///
    /// Note that empty `dst` is not currently allowed as this function does not handle allocation.
    ///
    /// [writable]: AvFrame::is_writable
    pub fn convert(&mut self, src: &AvFrame, dst: &mut AvFrame) -> Result<(), ConversionError> {
        if src.format != self.src_pix_format {
            return Err(ConversionError::FormatMismatch {
                frame: src.format,
                converter: self.src_pix_format,
            });
        }

        if dst.format != self.dst_pix_format {
            return Err(ConversionError::FormatMismatch {
                frame: dst.format,
                converter: self.dst_pix_format,
            });
        }

        if src.dimensions() != dst.dimensions() {
            return Err(ConversionError::DimensionMismatch);
        }

        if !dst.is_writable() {
            return Err(ConversionError::NotWritable);
        }

        // Safe because `sws_context`, `src_ref.data` and `dst_data` are all valid pointers, and
        // we made sure the sizes provided are within the bounds of the buffers.
        AvError::result(unsafe {
            ffi::sws_scale(
                self.sws_context,
                src.data.as_ptr() as *const *const u8,
                src.linesize.as_ptr(),
                0,
                src.height,
                dst.data.as_ptr(),
                dst.linesize.as_ptr(),
            )
        })
        .map_err(Into::into)
    }
}
