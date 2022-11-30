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
use libva::PictureSync;
use libva::Surface;
use libva::VAConfigAttrib;
use libva::VAConfigAttribType;

use crate::decoders::DecodedHandle as DecodedHandleTrait;
use crate::decoders::DynPicture;
use crate::decoders::Error as VideoDecoderError;
use crate::decoders::FrameInfo;
use crate::decoders::MappableHandle;
use crate::decoders::Picture;
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

pub trait IntoSurface: TryInto<Option<Surface>> {}

impl<T: FrameInfo> TryInto<Option<Surface>> for crate::decoders::Picture<T, GenericBackendHandle> {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Option<Surface>, Self::Error> {
        let backend_handle = self.backend_handle;

        let backend_handle = match backend_handle {
            Some(backend_handle) => backend_handle,
            None => return Ok(None),
        };

        match backend_handle.0 {
            GenericBackendHandleInner::Ready { picture, .. } => picture.take_surface().map(Some),
            GenericBackendHandleInner::Pending(id) => Err(anyhow!(
                "Attempting to retrieve a surface (id: {:?}) that might have operations pending.",
                id
            )),
        }
    }
}

impl<T: FrameInfo> IntoSurface for crate::decoders::Picture<T, GenericBackendHandle> {}

/// A decoded frame handle.
pub struct DecodedHandle<T: IntoSurface> {
    /// The actual object backing the handle.
    inner: Option<Rc<RefCell<T>>>,
    /// The decoder resolution when this frame was processed. Not all codecs
    /// send resolution data in every frame header.
    resolution: Resolution,
    /// A handle to the surface pool.
    surface_pool: SurfacePoolHandle,
    /// A monotonically increasing counter that denotes the display order of
    /// this handle in comparison with other handles.
    pub display_order: Option<u64>,
}

impl<T: IntoSurface> Clone for DecodedHandle<T> {
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

impl<T: IntoSurface> DecodedHandle<T> {
    /// Creates a new handle
    pub fn new(
        inner: Rc<RefCell<T>>,
        resolution: Resolution,
        surface_pool: SurfacePoolHandle,
    ) -> Self {
        Self {
            inner: Some(inner),
            resolution,
            surface_pool,
            display_order: None,
        }
    }

    pub fn inner(&self) -> &Rc<RefCell<T>> {
        // The Option is used as a well known strategy to move out of a field
        // when dropping. This is needed for the surface pool to be able to
        // retrieve the surface from the handle.
        self.inner.as_ref().unwrap()
    }
}

impl<T: IntoSurface> Drop for DecodedHandle<T> {
    fn drop(&mut self) {
        if let Ok(inner) = Rc::try_unwrap(self.inner.take().unwrap()).map(|i| i.into_inner()) {
            let pool = &mut self.surface_pool;

            // Only retrieve if the resolutions match, otherwise let the stale Surface drop.
            if *pool.current_resolution() == self.resolution {
                // Retrieve if not currently used by another field.
                if let Ok(Some(surface)) = inner.try_into() {
                    pool.add_surface(surface);
                }
            }
        }
    }
}

impl<CodecData: FrameInfo> DecodedHandleTrait
    for DecodedHandle<Picture<CodecData, GenericBackendHandle>>
{
    type CodecData = CodecData;
    type BackendHandle = GenericBackendHandle;

    fn picture_container(&self) -> &Rc<RefCell<Picture<Self::CodecData, Self::BackendHandle>>> {
        self.inner()
    }

    fn display_order(&self) -> Option<u64> {
        self.display_order
    }

    fn set_display_order(&mut self, display_order: u64) {
        self.display_order = Some(display_order)
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

    /// Adds a new surface to the pool
    pub fn add_surface(&mut self, surface: Surface) {
        self.surfaces.borrow_mut().push_back(surface)
    }

    /// Gets a free surface from the pool
    pub fn get_surface(&mut self) -> Option<Surface> {
        let mut vec = self.surfaces.borrow_mut();
        vec.pop_front()
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
///
/// This is just a wrapper around the `GenericBackendHandleInner` enum in order to make its variants
/// private.
pub struct GenericBackendHandle(GenericBackendHandleInner);

impl GenericBackendHandle {
    /// Creates a new pending handle on `surface_id`.
    pub(crate) fn new_pending(surface_id: u32) -> Self {
        Self(GenericBackendHandleInner::Pending(surface_id))
    }

    /// Creates a new ready handle on a completed `picture`.
    pub(crate) fn new_ready(
        picture: libva::Picture<PictureSync>,
        map_format: Rc<libva::VAImageFormat>,
        display_resolution: Resolution,
    ) -> Self {
        Self(GenericBackendHandleInner::Ready {
            map_format,
            picture,
            display_resolution,
        })
    }

    /// Returns a mapped VAImage. this maps the VASurface onto our address space.
    /// This can be used in place of "DynMappableHandle::map()" if the client
    /// wants to access the backend mapping directly for any reason.
    ///
    /// Note that DynMappableHandle is downcastable.
    pub fn image(&mut self) -> Result<Image> {
        match &mut self.0 {
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

    /// Returns the picture of this handle.
    pub fn picture(&self) -> Option<&libva::Picture<PictureSync>> {
        match &self.0 {
            GenericBackendHandleInner::Ready { picture, .. } => Some(picture),
            GenericBackendHandleInner::Pending(_) => None,
        }
    }

    /// Returns the id of the VA surface backing this handle.
    pub fn surface_id(&self) -> libva::VASurfaceID {
        match &self.0 {
            GenericBackendHandleInner::Ready { picture, .. } => picture.surface().id(),
            GenericBackendHandleInner::Pending(id) => *id,
        }
    }

    /// Returns `true` if this handle is ready.
    pub fn is_ready(&self) -> bool {
        matches!(self.0, GenericBackendHandleInner::Ready { .. })
    }
}

impl Clone for GenericBackendHandle {
    fn clone(&self) -> Self {
        match &self.0 {
            GenericBackendHandleInner::Ready {
                map_format,
                picture,
                display_resolution: resolution,
            } => GenericBackendHandle::new_ready(
                libva::Picture::new_from_same_surface(picture.timestamp(), picture),
                Rc::clone(map_format),
                *resolution,
            ),
            GenericBackendHandleInner::Pending(id) => GenericBackendHandle::new_pending(*id),
        }
    }
}

/// A type so we do not expose the enum in the public interface, as enum members
/// are inherently public.
enum GenericBackendHandleInner {
    Ready {
        map_format: Rc<libva::VAImageFormat>,
        picture: libva::Picture<PictureSync>,
        display_resolution: Resolution,
    },
    Pending(libva::VASurfaceID),
}

impl<'a> MappableHandle for Image<'a> {
    fn read(&mut self, buffer: &mut [u8]) -> VideoDecoderResult<()> {
        let image_size = self.image_size();
        let image_inner = self.image();

        let width = image_inner.width as u32;
        let height = image_inner.height as u32;

        if buffer.len() != image_size {
            return Err(VideoDecoderError::StatelessBackendError(
                StatelessBackendError::Other(anyhow!(
                    "buffer size is {} while image size is {}",
                    buffer.len(),
                    image_size
                )),
            ));
        }

        match image_inner.format.fourcc {
            libva::constants::VA_FOURCC_NV12 => {
                nv12_copy(
                    self.as_ref(),
                    buffer,
                    width,
                    height,
                    image_inner.pitches,
                    image_inner.offsets,
                );
            }
            libva::constants::VA_FOURCC_I420 => {
                i420_copy(
                    self.as_ref(),
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

    fn image_size(&mut self) -> usize {
        let image = self.image();

        crate::decoded_frame_size(
            (&image.format).try_into().unwrap(),
            image.width,
            image.height,
        )
    }
}

impl<CodecData: FrameInfo> DynPicture for Picture<CodecData, GenericBackendHandle> {
    fn dyn_mappable_handle_mut<'a>(&'a mut self) -> Box<dyn MappableHandle + 'a> {
        Box::new(self.backend_handle.as_mut().unwrap().image().unwrap())
    }
}

impl TryFrom<&libva::VAImageFormat> for DecodedFormat {
    type Error = anyhow::Error;

    fn try_from(value: &libva::VAImageFormat) -> Result<Self, Self::Error> {
        match value.fourcc {
            libva::constants::VA_FOURCC_NV12 => Ok(DecodedFormat::NV12),
            libva::constants::VA_FOURCC_I420 => Ok(DecodedFormat::I420),
            _ => Err(anyhow!("Unsupported format")),
        }
    }
}
