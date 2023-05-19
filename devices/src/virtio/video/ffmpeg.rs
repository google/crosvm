// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;

use base::MappedRegion;
use base::MemoryMappingArena;
use base::MmapError;
use ffmpeg::avcodec::AvBuffer;
use ffmpeg::avcodec::AvBufferSource;
use ffmpeg::avcodec::AvError;
use ffmpeg::avcodec::AvFrame;
use ffmpeg::avcodec::AvFrameError;
use ffmpeg::avcodec::AvPixelFormat;
use ffmpeg::avcodec::Dimensions;
use ffmpeg::avcodec::PlaneDescriptor;
use thiserror::Error as ThisError;

use crate::virtio::video::format::Format;
use crate::virtio::video::resource::BufferHandle;
use crate::virtio::video::resource::GuestResource;

/// A simple wrapper that turns a [`MemoryMappingArena`] into an [`AvBufferSource`].
///
/// **Note:** Only use this if you can reasonably assume the mapped memory won't be written to from
/// another thread or the VM! The reason [`AvBufferSource`] is not directly implemented on
/// [`MemoryMappingArena`] is exactly due to this unsafety: If the guest or someone else writes to
/// the buffer FFmpeg is currently reading from or writing to, undefined behavior might occur. This
/// struct acts as an opt-in mechanism for this potential unsafety.
pub struct MemoryMappingAvBufferSource(MemoryMappingArena);

impl From<MemoryMappingArena> for MemoryMappingAvBufferSource {
    fn from(inner: MemoryMappingArena) -> Self {
        Self(inner)
    }
}
impl AvBufferSource for MemoryMappingAvBufferSource {
    fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr() as _
    }

    fn len(&self) -> usize {
        self.0.size()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub trait TryAsAvFrameExt {
    type BufferSource;
    type Error: Error;

    /// Try to create an [`AvFrame`] from `self`.
    ///
    /// `wrapper` is a constructor for `T` that wraps `Self::BufferSource` and implement the
    /// `AvBufferSource` functionality. This can be used to provide a custom destructor
    /// implementation: for example, sending a virtio message signaling the buffer source is no
    /// longer used and it can be recycled by the guest.
    ///
    /// Note that `Self::BufferSource` might not always implement `AvBufferSource`. For instance,
    /// it's not guaranteed that a `MemoryMappingArena` created from `GuestResource` will be always
    /// immutable, and the backend need to explicit acknowledge the potential unsoundness by
    /// wrapping it in [`MemoryMappingAvBufferSource`].
    fn try_as_av_frame<T: AvBufferSource + 'static>(
        &self,
        wrapper: impl FnOnce(Self::BufferSource) -> T,
    ) -> Result<AvFrame, Self::Error>;
}

#[derive(Debug, ThisError)]
pub enum GuestResourceToAvFrameError {
    #[error("error while creating the AvFrame: {0}")]
    AvFrameError(#[from] AvFrameError),
    #[error("cannot mmap guest resource: {0}")]
    MappingResource(#[from] MmapError),
    #[error("virtio resource format is not convertible to AvPixelFormat")]
    InvalidFormat,
    #[error("out of memory while allocating AVBuffer")]
    CannotAllocateAvBuffer,
}

impl From<AvError> for GuestResourceToAvFrameError {
    fn from(e: AvError) -> Self {
        GuestResourceToAvFrameError::AvFrameError(AvFrameError::AvError(e))
    }
}

impl TryAsAvFrameExt for GuestResource {
    type BufferSource = MemoryMappingArena;
    type Error = GuestResourceToAvFrameError;

    fn try_as_av_frame<T: AvBufferSource + 'static>(
        &self,
        wrapper: impl FnOnce(MemoryMappingArena) -> T,
    ) -> Result<AvFrame, Self::Error> {
        let mut builder = AvFrame::builder()?;
        builder.set_dimensions(Dimensions {
            width: self.width,
            height: self.height,
        })?;
        let format = self
            .format
            .try_into()
            .map_err(|_| GuestResourceToAvFrameError::InvalidFormat)?;
        builder.set_format(format)?;
        let planes = &self.planes;
        // We have at least one plane, so we can unwrap below.
        let len = format.plane_sizes(planes.iter().map(|p| p.stride as _), self.height)?;
        let start = planes.iter().map(|p| p.offset).min().unwrap();
        let end = planes
            .iter()
            .enumerate()
            .map(|(i, p)| p.offset + len[i])
            .max()
            .unwrap();
        let mapping = self.handle.get_mapping(start, end - start)?;
        Ok(builder.build_owned(
            [AvBuffer::new(wrapper(mapping))
                .ok_or(GuestResourceToAvFrameError::CannotAllocateAvBuffer)?],
            planes.iter().map(|p| PlaneDescriptor {
                buffer_index: 0,
                offset: p.offset - start,
                stride: p.stride,
            }),
        )?)
    }
}

/// The error returned when converting between `AvPixelFormat` and `Format` and there's no
/// applicable format.
// The empty field prevents constructing this and allows extending it in the future.
#[derive(Debug)]
pub struct TryFromFormatError(());

impl Display for TryFromFormatError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "No matching format to convert between AvPixelFormat and Format"
        )
    }
}

impl Error for TryFromFormatError {}

impl TryFrom<Format> for AvPixelFormat {
    type Error = TryFromFormatError;

    fn try_from(value: Format) -> Result<Self, Self::Error> {
        use ffmpeg::*;
        AvPixelFormat::try_from(match value {
            Format::NV12 => AVPixelFormat_AV_PIX_FMT_NV12,
            Format::YUV420 => AVPixelFormat_AV_PIX_FMT_YUV420P,
            _ => return Err(TryFromFormatError(())),
        })
        .map_err(|_|
            // The error case should never happen as long as we use valid constant values, but
            // don't panic in case something goes wrong.
            TryFromFormatError(()))
    }
}

impl TryFrom<AvPixelFormat> for Format {
    type Error = TryFromFormatError;

    fn try_from(fmt: AvPixelFormat) -> Result<Self, Self::Error> {
        // https://github.com/rust-lang/rust/issues/39371 Lint wrongly warns the consumer
        #![allow(non_upper_case_globals)]
        use ffmpeg::*;
        Ok(match fmt.pix_fmt() {
            AVPixelFormat_AV_PIX_FMT_NV12 => Format::NV12,
            AVPixelFormat_AV_PIX_FMT_YUV420P => Format::YUV420,
            _ => return Err(TryFromFormatError(())),
        })
    }
}
