// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Result;
use libva::Config;
use libva::Context;
use libva::Display;
use libva::Image;
use libva::Picture;
use libva::PictureSync;
use libva::Surface;
use libva::VAConfigAttrib;
use libva::VAConfigAttribType;

use crate::decoders::Error as VideoDecoderError;
use crate::decoders::MappableHandle;
use crate::decoders::Result as VideoDecoderResult;
use crate::decoders::StatelessBackendError;
use crate::i420_copy;
use crate::nv12_copy;
use crate::DecodedFormat;
use crate::Resolution;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct FormatMap {
    pub rt_format: u32,
    pub va_fourcc: u32,
    pub decoded_format: DecodedFormat,
}

/// Maps a given VA_RT_FORMAT to a compatible decoded format in an arbitrary
/// preferred order.
pub const FORMAT_MAP: [FormatMap; 2] = [
    FormatMap {
        rt_format: libva::constants::VA_RT_FORMAT_YUV420,
        va_fourcc: libva::constants::VA_FOURCC_NV12,
        decoded_format: DecodedFormat::NV12,
    },
    FormatMap {
        rt_format: libva::constants::VA_RT_FORMAT_YUV420,
        va_fourcc: libva::constants::VA_FOURCC_I420,
        decoded_format: DecodedFormat::I420,
    },
];

/// Returns a set of supported decoded formats given `rt_format`
pub fn supported_formats_for_rt_format(
    display: Rc<Display>,
    rt_format: u32,
    profile: i32,
    entrypoint: u32,
    image_formats: &[libva::VAImageFormat],
) -> Result<HashSet<FormatMap>> {
    let mut attrs = vec![VAConfigAttrib {
        type_: VAConfigAttribType::VAConfigAttribRTFormat,
        value: 0,
    }];

    display.get_config_attributes(profile, entrypoint, &mut attrs)?;

    // See whether this RT_FORMAT is supported by the given VAProfile and
    // VAEntrypoint pair.
    if attrs[0].value == libva::constants::VA_ATTRIB_NOT_SUPPORTED
        || attrs[0].value & rt_format == 0
    {
        return Err(anyhow!(
            "rt_format {:?} not supported for profile {:?} and entrypoint {:?}",
            rt_format,
            profile,
            entrypoint
        ));
    }

    let mut supported_formats = HashSet::new();

    for format in FORMAT_MAP {
        if format.rt_format == rt_format {
            supported_formats.insert(format);
        }
    }

    // Only retain those that the hardware can actually map into.
    supported_formats.retain(|&entry| {
        image_formats
            .iter()
            .any(|fmt| fmt.fourcc == entry.va_fourcc)
    });

    Ok(supported_formats)
}

/// A trait for objects that hold a Surface.
pub trait SurfaceContainer {
    /// Return the inner surface.
    fn into_surface(self) -> Result<Option<Surface>>;
}

/// A decoded frame handle.
pub struct DecodedHandle<T: SurfaceContainer> {
    /// The actual object backing the handle.
    inner: Option<Rc<T>>,
    /// The decoder resolution when this frame was processed. Not all codecs
    /// send resolution data in every frame header.
    resolution: Resolution,
    /// A handle to the surface pool.
    surface_pool: SurfacePoolHandle,
    /// A monotonically increasing counter that denotes the display order of
    /// this handle in comparison with other handles.
    pub display_order: Option<u64>,
}

impl<T: SurfaceContainer> Clone for DecodedHandle<T> {
    // See https://stegosaurusdormant.com/understanding-derive-clone/ on why
    // this cannot be derived. Note that T probably doesn't implement Clone, but
    // it's not a problem, since Rc is Clone.
    fn clone(&self) -> Self {
        DecodedHandle {
            inner: self.inner.clone(),
            resolution: self.resolution,
            surface_pool: self.surface_pool.clone(),
            display_order: self.display_order,
        }
    }
}

impl<T: SurfaceContainer> DecodedHandle<T> {
    /// Creates a new handle
    pub fn new(inner: Rc<T>, resolution: Resolution, surface_pool: SurfacePoolHandle) -> Self {
        Self {
            inner: Some(inner),
            resolution,
            surface_pool,
            display_order: None,
        }
    }

    pub fn inner(&self) -> &Rc<T> {
        // The Option is used as a well known strategy to move out of a field
        // when dropping. This is needed for the surface pool to be able to
        // retrieve the surface from the handle.
        self.inner.as_ref().unwrap()
    }
}

impl<T: SurfaceContainer> Drop for DecodedHandle<T> {
    fn drop(&mut self) {
        if let Ok(inner) = Rc::try_unwrap(self.inner.take().unwrap()) {
            let pool = &mut self.surface_pool;

            // Only retrieve if the resolutions match, otherwise let the stale Surface drop.
            if *pool.current_resolution() == self.resolution {
                // Retrieve if not currently used by another field.
                if let Ok(Some(surface)) = inner.into_surface() {
                    pool.add_surface(surface);
                }
            }
        }
    }
}

/// A surface pool handle to reduce the number of costly Surface allocations.
#[derive(Clone)]
pub struct SurfacePoolHandle {
    surfaces: Rc<RefCell<VecDeque<Surface>>>,
    current_resolution: Resolution,
}

impl SurfacePoolHandle {
    /// Creates a new pool
    pub fn new(surfaces: Vec<Surface>, resolution: Resolution) -> Self {
        Self {
            surfaces: Rc::new(RefCell::new(VecDeque::from(surfaces))),
            current_resolution: resolution,
        }
    }

    /// Retrieve the current resolution for the pool
    pub fn current_resolution(&self) -> &Resolution {
        &self.current_resolution
    }

    /// Sets the current resolution for the pool
    pub fn set_current_resolution(&mut self, resolution: Resolution) {
        self.current_resolution = resolution;
    }

    /// Adds a new surface to the pool
    pub fn add_surface(&mut self, surface: Surface) {
        self.surfaces.borrow_mut().push_back(surface)
    }

    /// Gets a free surface from the pool
    pub fn get_surface(&mut self) -> Option<Surface> {
        let mut vec = self.surfaces.borrow_mut();
        vec.pop_front()
    }

    /// Drops all surfaces from the pool
    pub fn drop_surfaces(&mut self) {
        self.surfaces = Default::default();
    }

    /// Returns new number of surfaces left.
    pub fn num_surfaces_left(&self) -> usize {
        self.surfaces.borrow().len()
    }
}

/// State of the input stream, which can be either unparsed (we don't know the stream properties
/// yet) or parsed (we know the stream properties and are ready to decode).
pub(crate) enum StreamMetadataState {
    /// The metadata for the current stream has not yet been parsed.
    Unparsed { display: Rc<Display> },

    /// The metadata for the current stream has been parsed and a suitable
    /// VAContext has been created to accomodate it.
    Parsed {
        /// A VAContext from which we can decode from.
        context: Rc<Context>,
        /// The VAConfig that created the context. It must kept here so that
        /// it does not get dropped while it is in use.
        #[allow(dead_code)]
        config: Config,
        /// A pool of surfaces. We reuse surfaces as they are expensive to allocate.
        surface_pool: SurfacePoolHandle,
        /// The decoder current coded resolution.
        coded_resolution: Resolution,
        /// The decoder current display resolution.
        display_resolution: Resolution,
        /// The image format we will use to map the surfaces. This is usually the
        /// same as the surface's internal format, but occasionally we can try
        /// mapping in a different format if requested and if the VA-API driver can
        /// do it.
        map_format: Rc<libva::VAImageFormat>,
        /// The rt_format parsed from the stream.
        rt_format: u32,
        /// The profile parsed from the stream.
        profile: i32,
    },
}

impl StreamMetadataState {
    pub(crate) fn display(&self) -> Rc<libva::Display> {
        match self {
            StreamMetadataState::Unparsed { display } => Rc::clone(display),
            StreamMetadataState::Parsed { context, .. } => context.display(),
        }
    }

    pub(crate) fn context(&self) -> Result<Rc<libva::Context>> {
        match self {
            StreamMetadataState::Unparsed { .. } => Err(anyhow!("Stream metadata not parsed yet")),
            StreamMetadataState::Parsed { context, .. } => Ok(Rc::clone(context)),
        }
    }

    pub(crate) fn coded_resolution(&self) -> Result<Resolution> {
        match self {
            StreamMetadataState::Unparsed { .. } => Err(anyhow!("Stream metadata not parsed yet")),
            StreamMetadataState::Parsed {
                coded_resolution, ..
            } => Ok(*coded_resolution),
        }
    }

    pub(crate) fn display_resolution(&self) -> Result<Resolution> {
        match self {
            StreamMetadataState::Unparsed { .. } => Err(anyhow!("Stream metadata not parsed yet")),
            StreamMetadataState::Parsed {
                display_resolution, ..
            } => Ok(*display_resolution),
        }
    }

    pub(crate) fn map_format(&self) -> Result<&Rc<libva::VAImageFormat>> {
        match self {
            StreamMetadataState::Unparsed { .. } => Err(anyhow!("Stream metadata not parsed yet")),
            StreamMetadataState::Parsed { map_format, .. } => Ok(map_format),
        }
    }

    pub(crate) fn rt_format(&self) -> Result<u32> {
        match self {
            StreamMetadataState::Unparsed { .. } => Err(anyhow!("Stream metadata not parsed yet")),
            StreamMetadataState::Parsed { rt_format, .. } => Ok(*rt_format),
        }
    }

    pub(crate) fn profile(&self) -> Result<i32> {
        match self {
            StreamMetadataState::Unparsed { .. } => Err(anyhow!("Stream metadata not parsed yet")),
            StreamMetadataState::Parsed { profile, .. } => Ok(*profile),
        }
    }

    pub(crate) fn surface_pool(&self) -> Result<SurfacePoolHandle> {
        match self {
            StreamMetadataState::Unparsed { .. } => Err(anyhow!("Invalid state")),
            StreamMetadataState::Parsed { surface_pool, .. } => Ok(surface_pool.clone()),
        }
    }

    pub(crate) fn get_surface(&mut self) -> Result<Option<Surface>> {
        let mut surface_pool = self.surface_pool()?;
        Ok(surface_pool.get_surface())
    }
}

/// The VA-API backend handle.
pub struct GenericBackendHandle {
    pub(crate) inner: GenericBackendHandleInner,
}

impl GenericBackendHandle {
    pub(crate) fn new(inner: GenericBackendHandleInner) -> Self {
        Self { inner }
    }

    /// Returns a mapped VAImage. this maps the VASurface onto our address space.
    /// This can be used in place of "DynMappableHandle::map()" if the client
    /// wants to access the backend mapping directly for any reason.
    ///
    /// Note that DynMappableHandle is downcastable.
    pub fn image(&mut self) -> Result<Image> {
        match &mut self.inner {
            GenericBackendHandleInner::Ready {
                map_format,
                picture,
                display_resolution,
                ..
            } => {
                // Get the associated VAImage, which will map the
                // VASurface onto our address space.
                let image = libva::Image::new(
                    picture,
                    *map_format.clone(),
                    display_resolution.width,
                    display_resolution.height,
                    false,
                )?;

                Ok(image)
            }
            GenericBackendHandleInner::Pending(_) => Err(anyhow!("Mapping failed")),
        }
    }
}

/// A type so we do not expose the enum in the public interface, as enum members
/// are inherently public.
pub(crate) enum GenericBackendHandleInner {
    Ready {
        context: Rc<Context>,
        map_format: Rc<libva::VAImageFormat>,
        picture: Picture<PictureSync>,
        display_resolution: Resolution,
    },
    Pending(libva::VASurfaceID),
}

impl MappableHandle for GenericBackendHandle {
    fn map(&mut self) -> VideoDecoderResult<Box<dyn AsRef<[u8]> + '_>> {
        let image = self.image()?;
        Ok(Box::new(image))
    }

    fn read(&mut self, buffer: &mut [u8]) -> VideoDecoderResult<()> {
        let map_format = match &self.inner {
            GenericBackendHandleInner::Ready { map_format, .. } => Rc::clone(map_format),
            GenericBackendHandleInner::Pending(_) => {
                return Err(VideoDecoderError::StatelessBackendError(
                    StatelessBackendError::ResourceNotReady,
                ))
            }
        };

        let image = self.image()?;
        let image_inner = image.image();

        let width = image_inner.width as u32;
        let height = image_inner.height as u32;

        match map_format.fourcc {
            libva::constants::VA_FOURCC_NV12 => {
                if buffer.len() < (width * height * 3 / 2) as usize {
                    return Err(VideoDecoderError::StatelessBackendError(
                        StatelessBackendError::Other(anyhow!("Buffer is too small")),
                    ));
                }

                nv12_copy(
                    image.as_ref(),
                    buffer,
                    width,
                    height,
                    image_inner.pitches,
                    image_inner.offsets,
                );
            }
            libva::constants::VA_FOURCC_I420 => {
                if buffer.len() < (width * height * 3 / 2) as usize {
                    return Err(VideoDecoderError::StatelessBackendError(
                        StatelessBackendError::Other(anyhow!("Buffer is too small")),
                    ));
                }

                i420_copy(
                    image.as_ref(),
                    buffer,
                    width,
                    height,
                    image_inner.pitches,
                    image_inner.offsets,
                );
            }
            _ => {
                return Err(crate::decoders::Error::StatelessBackendError(
                    StatelessBackendError::UnsupportedFormat,
                ))
            }
        }

        Ok(())
    }

    fn mapped_resolution(&mut self) -> VideoDecoderResult<Resolution> {
        let image = self.image()?;
        let image = image.image();

        Ok(Resolution {
            width: u32::from(image.width),
            height: u32::from(image.height),
        })
    }
}

impl TryFrom<&libva::VAImageFormat> for DecodedFormat {
    type Error = anyhow::Error;

    fn try_from(value: &libva::VAImageFormat) -> Result<Self, Self::Error> {
        match value.fourcc {
            libva::constants::VA_FOURCC_NV12 => Ok(DecodedFormat::NV12),
            libva::constants::VA_FOURCC_I420 => Ok(DecodedFormat::I420),
            _ => return Err(anyhow!("Unsupported format")),
        }
    }
}
