// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Result;

use crate::{
    bindings,
    picture::{Picture, PictureSync},
    status::Status,
};

/// An owned VAImage that is tied to the lifetime of a given Picture.
/// A VAImage is used to either get the surface data to client memory, or
/// to copy image data in client memory to a surface.
pub struct Image<'a> {
    /// The picture whose Surface we use in the vaGetImage call.
    picture: &'a Picture<PictureSync>,
    /// The VAImage returned by libva.
    image: bindings::VAImage,
    /// The mapped surface data.
    data: &'a mut [u8],
    /// Whether the image was derived using the `vaDeriveImage` API or created
    /// using the `vaCreateImage` API.
    derived: bool,
    /// Tracks whether the underlying data has possibly been written to, i.e. an
    /// encoder will create an Image and map its buffer in order to write to it,
    /// so we must writeback later.
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
    /// * `picture` is the Picture that owns the Surface this Image will be created from.
    /// * `format` is a VAImageFormat returned by the vaQueryImageFormats wrapper.
    /// * `width` is the Image's desired width.
    /// * `height` is the Image's desired height.
    /// * `derive` whether to try deriving the image. Deriving may fail, in
    ///    which case vaCreateImage will be used instead.
    pub fn new(
        picture: &'a mut Picture<PictureSync>,
        mut format: bindings::VAImageFormat,
        width: u32,
        height: u32,
        derive: bool,
    ) -> Result<Self> {
        // Safe because an all-zero byte-pattern represent a valid value for
        // bindings::VAImage. Note that this is a FFI type and that it does not have
        // any references in it.
        let mut image: bindings::VAImage = Default::default();
        let mut addr = std::ptr::null_mut();
        let mut derived = false;

        if derive {
            derived = Image::derive_image(picture, &mut image)?;
        }

        if !derived {
            Image::create_image(picture, &mut image, &mut format, width, height)?;
        }

        // Safe since `picture.inner.context` represents a valid VAContext.
        // Image creation is ensured by either the vaDeriveImage or
        // vaCreateImage APIs and vaGetImage is called if the VAImage was not
        // derived, as mandated by VAAPI.
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
                // Safe since addr will point to data mapped onto our address
                // space since we call vaGetImage above, which also guarantees
                // that the data is valid for len * mem::size_of<u8>().
                // Furthermore, we can only access the underlying memory using
                // the slice below.
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
                // Safe because `picture.inner.context` represents a valid
                // VAContext and `image` represents a valid VAImage.
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

    /// Get a reference to the underlying VAImage that describes this Image.
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
        // Safe because `picture.inner.context` represents a valid VAContext,
        // `picture.surface` represents a valid VASurface and `image` represents
        // a valid `VAImage`. Lastly, the buffer is mapped in Image::new, so
        // self.image.buf points to a valid VABufferID.
        let surface = self.picture.surface();

        if !self.derived && self.dirty {
            unsafe {
                bindings::vaPutImage(
                    self.picture.inner().context().display().handle(),
                    surface.id(),
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
            // Safe since the buffer is mapped in Image::new, so self.image.buf
            // points to a valid VABufferID.
            bindings::vaUnmapBuffer(
                self.picture.inner().context().display().handle(),
                self.image.buf,
            );
        }
        unsafe {
            // Safe since `self.image` represents a valid VAImage.
            bindings::vaDestroyImage(
                self.picture.inner().context().display().handle(),
                self.image.image_id,
            );
        }
    }
}
