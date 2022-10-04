// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Result;

use crate::bindings;
use crate::picture::Picture;
use crate::picture::PictureSync;
use crate::status::Status;

/// Wrapper around `VAImage` that is tied to the lifetime of a given `Picture`.
///
/// An image is used to either get the surface data to client memory, or to copy image data in
/// client memory to a surface.
pub struct Image<'a> {
    /// The picture whose `Surface` we use as the source of pixel data.
    picture: &'a Picture<PictureSync>,
    /// The `VAImage` returned by libva.
    image: bindings::VAImage,
    /// The mapped surface data.
    data: &'a mut [u8],
    /// Whether the image was derived using the `vaDeriveImage` API or created using the
    /// `vaCreateImage` API.
    derived: bool,
    /// Tracks whether the underlying data has possibly been written to, i.e. an encoder will create
    /// an image and map its buffer in order to write to it, so we must writeback later.
    dirty: bool,
}

impl<'a> Image<'a> {
    /// Creates a new `Image` either by calling `vaCreateImage` or
    /// `vaDeriveImage`. Creating an Image depends on acquiring a ready Surface
    /// from an underlying Picture. Note that Image has a borrowed Picture, so
    /// it will be dropped before the underlying Surface is dropped, as mandated
    /// by VAAPI.
    ///
    /// # Arguments
    ///
    /// * `picture` - The [`Picture`] that owns the Surface this image will be created from.
    /// * `format` - A `VAImageFormat` returned by [`crate::Display::query_image_formats`].
    /// * `width` - The image's desired width.
    /// * `height` - The image's desired height.
    /// * `derive` - Whether to try deriving the image from `picture`, which allows zero-copy access
    ///    to the surface data. Deriving may fail, in which case vaCreateImage will be used instead,
    ///    incurring an extra data copy.
    pub fn new(
        picture: &'a mut Picture<PictureSync>,
        mut format: bindings::VAImageFormat,
        width: u32,
        height: u32,
        derive: bool,
    ) -> Result<Self> {
        // An all-zero byte-pattern is a valid initial value for `VAImage`.
        let mut image: bindings::VAImage = Default::default();
        let mut addr = std::ptr::null_mut();
        let mut derived = false;

        if derive {
            derived = Image::derive_image(picture, &mut image)?;
        }

        if !derived {
            Image::create_image(picture, &mut image, &mut format, width, height)?;
        }

        // Safe since `picture.inner.context` represents a valid `VAContext` and `image` has been
        // successfully created at this point.
        match Status(unsafe {
            bindings::vaMapBuffer(
                picture.inner().context().display().handle(),
                image.buf,
                &mut addr,
            )
        })
        .check()
        {
            Ok(_) => {
                // Safe since `addr` points to data mapped onto our address space since we called
                // `vaMapBuffer` above, which also guarantees that the data is valid for
                // `image.data_size`.
                let data =
                    unsafe { std::slice::from_raw_parts_mut(addr as _, image.data_size as usize) };
                Ok(Self {
                    picture,
                    image,
                    data,
                    derived,
                    dirty: false,
                })
            }
            Err(e) => {
                // Safe because `picture.inner.context` represents a valid `VAContext` and `image`
                // represents a valid `VAImage`.
                unsafe {
                    bindings::vaDestroyImage(
                        picture.inner().context().display().handle(),
                        image.image_id,
                    );
                }
                Err(e)
            }
        }
    }

    /// Creates `image` from `picture` using `vaCreateImage` and `vaGetImage` in order to copy the
    /// surface data into the image buffer.
    fn create_image(
        picture: &'a mut Picture<PictureSync>,
        image: &mut bindings::VAImage,
        format: &mut bindings::VAImageFormat,
        width: u32,
        height: u32,
    ) -> Result<()> {
        let dpy = picture.inner().context().display().handle();

        // Safe because `picture.inner.context` represents a valid
        // VAContext.
        Status(unsafe { bindings::vaCreateImage(dpy, format, width as i32, height as i32, image) })
            .check()?;

        // Safe because `picture.inner.context` represents a valid VAContext,
        // `picture.surface` represents a valid VASurface and `image` represents
        // a valid `VAImage`.
        if let Err(e) = Status(unsafe {
            bindings::vaGetImage(
                dpy,
                picture.surface_mut().id(),
                0,
                0,
                width,
                height,
                image.image_id,
            )
        })
        .check()
        {
            // Safe since `image` represents a valid `VAImage`.
            unsafe {
                bindings::vaDestroyImage(dpy, image.image_id);
            }
            return Err(e);
        }

        Ok(())
    }

    /// Tries to derive `image` from `picture` to access the raw surface data without copy.
    ///
    /// Returns `Ok(true)` if the image has been successfully derived, `Ok(false)` if deriving is
    /// not possible and `create_image` should be used as a fallback, or an error if an error
    /// occurred.
    fn derive_image(
        picture: &'a mut Picture<PictureSync>,
        image: &mut bindings::VAImage,
    ) -> Result<bool> {
        let status = Status(unsafe {
            bindings::vaDeriveImage(
                picture.inner().context().display().handle(),
                picture.surface_mut().id(),
                image,
            )
        });

        if status.0 == bindings::constants::VA_STATUS_ERROR_OPERATION_FAILED as i32 {
            // The implementation can't derive, try the create API instead.
            return Ok(false);
        } else {
            status.check()?;
            Ok(true)
        }
    }

    /// Get a reference to the underlying `VAImage` that describes this image.
    pub fn image(&self) -> &bindings::VAImage {
        &self.image
    }
}

impl<'a> AsRef<[u8]> for Image<'a> {
    fn as_ref(&self) -> &[u8] {
        self.data
    }
}

impl<'a> AsMut<[u8]> for Image<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.dirty = true;
        self.data
    }
}

impl<'a> Drop for Image<'a> {
    fn drop(&mut self) {
        if !self.derived && self.dirty {
            // Safe because `picture.inner.context` represents a valid `VAContext`,
            // `picture.surface` represents a valid `VASurface` and `image` represents a valid
            // `VAImage`.
            unsafe {
                bindings::vaPutImage(
                    self.picture.inner().context().display().handle(),
                    self.picture.surface().id(),
                    self.image.image_id,
                    0,
                    0,
                    self.image.width as u32,
                    self.image.height as u32,
                    0,
                    0,
                    self.image.width as u32,
                    self.image.height as u32,
                );
            }
        }
        unsafe {
            // Safe since the buffer is mapped in `Image::new`, so `self.image.buf` points to a
            // valid `VABufferID`.
            bindings::vaUnmapBuffer(
                self.picture.inner().context().display().handle(),
                self.image.buf,
            );
            // Safe since `self.image` represents a valid `VAImage`.
            bindings::vaDestroyImage(
                self.picture.inner().context().display().handle(),
                self.image.image_id,
            );
        }
    }
}
