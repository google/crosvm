// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Result;
use libva::Config;
use libva::Context;
use libva::Display;
use libva::Image;
use libva::PictureEnd;
use libva::PictureNew;
use libva::PictureSync;
use libva::Surface;
use libva::VAConfigAttrib;
use libva::VAConfigAttribType;

use crate::decoders::BlockingMode;
use crate::decoders::DecodedHandle as DecodedHandleTrait;
use crate::decoders::DynHandle;
use crate::decoders::Error as VideoDecoderError;
use crate::decoders::MappableHandle;
use crate::decoders::Result as VideoDecoderResult;
use crate::decoders::StatelessBackendError;
use crate::decoders::StatelessBackendResult;
use crate::decoders::VideoDecoderBackend;
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
fn supported_formats_for_rt_format(
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

impl TryInto<Option<Surface>> for PictureState {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Option<Surface>, Self::Error> {
        match self {
            PictureState::Ready { picture, .. } => picture.take_surface().map(Some),
            PictureState::Pending { surface_id, .. } => Err(anyhow!(
                "Attempting to retrieve a surface (id: {:?}) that might have operations pending.",
                surface_id
            )),
            PictureState::Invalid => unreachable!(),
        }
    }
}

/// A decoded frame handle.
pub struct DecodedHandle {
    /// The actual object backing the handle.
    inner: Rc<RefCell<GenericBackendHandle>>,
    /// The timestamp of the input buffer that produced this frame.
    timestamp: u64,
    /// A monotonically increasing counter that denotes the display order of
    /// this handle in comparison with other handles.
    pub display_order: Option<u64>,
}

impl Clone for DecodedHandle {
    // See https://stegosaurusdormant.com/understanding-derive-clone/ on why
    // this cannot be derived. Note that T probably doesn't implement Clone, but
    // it's not a problem, since Rc is Clone.
    fn clone(&self) -> Self {
        DecodedHandle {
            inner: self.inner.clone(),
            timestamp: self.timestamp,
            display_order: self.display_order,
        }
    }
}

impl DecodedHandle {
    /// Creates a new handle
    pub fn new(inner: Rc<RefCell<GenericBackendHandle>>, timestamp: u64) -> Self {
        Self {
            inner,
            timestamp,
            display_order: None,
        }
    }
}

impl DecodedHandleTrait for DecodedHandle {
    type BackendHandle = GenericBackendHandle;

    fn handle_rc(&self) -> &Rc<RefCell<Self::BackendHandle>> {
        &self.inner
    }

    fn display_order(&self) -> Option<u64> {
        self.display_order
    }

    fn set_display_order(&mut self, display_order: u64) {
        self.display_order = Some(display_order)
    }

    fn display_resolution(&self) -> Resolution {
        self.handle().resolution
    }

    fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

/// A surface pool handle to reduce the number of costly Surface allocations.
#[derive(Clone)]
pub struct SurfacePoolHandle {
    surfaces: Rc<RefCell<VecDeque<Surface>>>,
    coded_resolution: Resolution,
}

impl SurfacePoolHandle {
    /// Creates a new pool
    pub fn new(surfaces: Vec<Surface>, resolution: Resolution) -> Self {
        Self {
            surfaces: Rc::new(RefCell::new(VecDeque::from(surfaces))),
            coded_resolution: resolution,
        }
    }

    /// Retrieve the current coded resolution of the pool
    pub fn coded_resolution(&self) -> Resolution {
        self.coded_resolution
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

/// A trait for providing the basic information needed to setup libva for decoding.
pub(crate) trait StreamInfo {
    /// Returns the VA profile of the stream.
    fn va_profile(&self) -> anyhow::Result<i32>;
    /// Returns the RT format of the stream.
    fn rt_format(&self) -> anyhow::Result<u32>;
    /// Returns the minimum number of surfaces required to decode the stream.
    fn min_num_surfaces(&self) -> usize;
    /// Returns the coded size of the surfaces required to decode the stream.
    fn coded_size(&self) -> (u32, u32);
    /// Returns the visible rectangle within the coded size for the stream.
    fn visible_rect(&self) -> ((u32, u32), (u32, u32));
}

pub(crate) struct ParsedStreamMetadata {
    /// A VAContext from which we can decode from.
    pub(crate) context: Rc<Context>,
    /// The VAConfig that created the context. It must kept here so that
    /// it does not get dropped while it is in use.
    #[allow(dead_code)]
    config: Config,
    /// A pool of surfaces. We reuse surfaces as they are expensive to allocate.
    pub(crate) surface_pool: SurfacePoolHandle,
    /// The number of surfaces required to parse the stream.
    pub(crate) min_num_surfaces: usize,
    /// The decoder current display resolution.
    pub(crate) display_resolution: Resolution,
    /// The image format we will use to map the surfaces. This is usually the
    /// same as the surface's internal format, but occasionally we can try
    /// mapping in a different format if requested and if the VA-API driver can
    /// do it.
    pub(crate) map_format: Rc<libva::VAImageFormat>,
    /// The rt_format parsed from the stream.
    pub(crate) rt_format: u32,
    /// The profile parsed from the stream.
    pub(crate) profile: i32,
}

/// State of the input stream, which can be either unparsed (we don't know the stream properties
/// yet) or parsed (we know the stream properties and are ready to decode).
pub(crate) enum StreamMetadataState {
    /// The metadata for the current stream has not yet been parsed.
    Unparsed { display: Rc<Display> },
    /// The metadata for the current stream has been parsed and a suitable
    /// VAContext has been created to accomodate it.
    Parsed(ParsedStreamMetadata),
}

impl StreamMetadataState {
    pub(crate) fn display(&self) -> Rc<libva::Display> {
        match self {
            StreamMetadataState::Unparsed { display } => Rc::clone(display),
            StreamMetadataState::Parsed(ParsedStreamMetadata { context, .. }) => context.display(),
        }
    }

    /// Returns a reference to the parsed metadata state or an error if we haven't reached that
    /// state yet.
    pub(crate) fn get_parsed(&self) -> Result<&ParsedStreamMetadata> {
        match self {
            StreamMetadataState::Unparsed { .. } => Err(anyhow!("Stream metadata not parsed yet")),
            StreamMetadataState::Parsed(parsed_metadata) => Ok(parsed_metadata),
        }
    }

    /// Returns a mutable reference to the parsed metadata state or an error if we haven't reached
    /// that state yet.
    pub(crate) fn get_parsed_mut(&mut self) -> Result<&mut ParsedStreamMetadata> {
        match self {
            StreamMetadataState::Unparsed { .. } => Err(anyhow!("Stream metadata not parsed yet")),
            StreamMetadataState::Parsed(parsed_metadata) => Ok(parsed_metadata),
        }
    }

    /// Gets a set of supported formats for the particular stream being
    /// processed. This requires that some buffers be processed before this call
    /// is made. Only formats that are compatible with the current color space,
    /// bit depth, and chroma format are returned such that no conversion is
    /// needed.
    pub(crate) fn supported_formats_for_stream(&self) -> Result<HashSet<DecodedFormat>> {
        let metadata = self.get_parsed()?;
        let display = self.display();

        let image_formats = display.query_image_formats()?;

        let formats = supported_formats_for_rt_format(
            display,
            metadata.rt_format,
            metadata.profile,
            libva::VAEntrypoint::VAEntrypointVLD,
            &image_formats,
        )?;

        Ok(formats.into_iter().map(|f| f.decoded_format).collect())
    }

    /// Initializes or reinitializes the codec state.
    pub(crate) fn open<S: StreamInfo>(
        &mut self,
        hdr: S,
        format_map: Option<&FormatMap>,
    ) -> Result<()> {
        let display = self.display();
        let va_profile = hdr.va_profile()?;
        let rt_format = hdr.rt_format()?;
        let (frame_w, frame_h) = hdr.coded_size();

        let attrs = vec![libva::VAConfigAttrib {
            type_: libva::VAConfigAttribType::VAConfigAttribRTFormat,
            value: rt_format,
        }];

        let config =
            display.create_config(attrs, va_profile, libva::VAEntrypoint::VAEntrypointVLD)?;

        let format_map = if let Some(format_map) = format_map {
            format_map
        } else {
            // Pick the first one that fits
            FORMAT_MAP
                .iter()
                .find(|&map| map.rt_format == rt_format)
                .ok_or(anyhow!("Unsupported format {}", rt_format))?
        };

        let map_format = display
            .query_image_formats()?
            .iter()
            .find(|f| f.fourcc == format_map.va_fourcc)
            .cloned()
            .unwrap();

        let min_num_surfaces = hdr.min_num_surfaces();

        let surfaces = display.create_surfaces(
            rt_format,
            Some(map_format.fourcc),
            frame_w,
            frame_h,
            Some(libva::UsageHint::USAGE_HINT_DECODER),
            min_num_surfaces as u32,
        )?;

        let context = display.create_context(
            &config,
            i32::try_from(frame_w)?,
            i32::try_from(frame_h)?,
            Some(&surfaces),
            true,
        )?;

        let coded_resolution = Resolution {
            width: frame_w,
            height: frame_h,
        };

        let visible_rect = hdr.visible_rect();

        let display_resolution = Resolution {
            width: visible_rect.1 .0 - visible_rect.0 .0,
            height: visible_rect.1 .1 - visible_rect.0 .1,
        };

        let surface_pool = SurfacePoolHandle::new(surfaces, coded_resolution);

        *self = StreamMetadataState::Parsed(ParsedStreamMetadata {
            context,
            config,
            surface_pool,
            min_num_surfaces,
            display_resolution,
            map_format: Rc::new(map_format),
            rt_format,
            profile: va_profile,
        });

        Ok(())
    }
}

/// VA-API backend handle.
///
/// This includes the VA picture which can be pending rendering or complete, as well as useful
/// meta-information.
pub struct GenericBackendHandle {
    state: PictureState,
    /// The decoder resolution when this frame was processed. Not all codecs
    /// send resolution data in every frame header.
    resolution: Resolution,
    /// A handle to the surface pool from which the backing surface originates.
    surface_pool: SurfacePoolHandle,
}

impl Drop for GenericBackendHandle {
    fn drop(&mut self) {
        // Take ownership of the internal state.
        let state = std::mem::replace(&mut self.state, PictureState::Invalid);
        if self.surface_pool.coded_resolution() == self.resolution {
            if let Ok(Some(surface)) = state.try_into() {
                self.surface_pool.add_surface(surface);
            }
        }
    }
}

impl GenericBackendHandle {
    /// Creates a new pending handle on `surface_id`.
    pub(crate) fn new_pending(
        picture: libva::Picture<PictureNew>,
        surface_pool: SurfacePoolHandle,
    ) -> Result<Self> {
        let surface_id = picture.surface().id();
        let picture = picture.begin()?.render()?.end()?;
        Ok(Self {
            state: PictureState::Pending {
                picture,
                surface_id,
            },
            resolution: surface_pool.coded_resolution(),
            surface_pool,
        })
    }

    pub(crate) fn sync(&mut self, metadata: &ParsedStreamMetadata) -> Result<()> {
        match std::mem::replace(&mut self.state, PictureState::Invalid) {
            state @ PictureState::Ready { .. } => self.state = state,
            PictureState::Pending { picture, .. } => {
                let picture = picture.sync()?;
                self.state = PictureState::Ready {
                    map_format: Rc::clone(&metadata.map_format),
                    picture,
                    display_resolution: metadata.display_resolution,
                };
            }
            PictureState::Invalid => unreachable!(),
        }

        Ok(())
    }

    /// Returns a mapped VAImage. this maps the VASurface onto our address space.
    /// This can be used in place of "DynMappableHandle::map()" if the client
    /// wants to access the backend mapping directly for any reason.
    ///
    /// Note that DynMappableHandle is downcastable.
    pub fn image(&mut self) -> Result<Image> {
        match &mut self.state {
            PictureState::Ready {
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
            PictureState::Pending { .. } => Err(anyhow!("Mapping failed")),
            PictureState::Invalid => unreachable!(),
        }
    }

    /// Returns the picture of this handle.
    pub fn picture(&self) -> Option<&libva::Picture<PictureSync>> {
        match &self.state {
            PictureState::Ready { picture, .. } => Some(picture),
            PictureState::Pending { .. } => None,
            PictureState::Invalid => unreachable!(),
        }
    }

    /// Returns the id of the VA surface backing this handle.
    pub fn surface_id(&self) -> libva::VASurfaceID {
        match &self.state {
            PictureState::Ready { picture, .. } => picture.surface().id(),
            PictureState::Pending { surface_id, .. } => *surface_id,
            PictureState::Invalid => unreachable!(),
        }
    }

    /// Returns `true` if this handle is ready.
    pub fn is_ready(&self) -> bool {
        matches!(self.state, PictureState::Ready { .. })
    }

    pub fn is_va_ready(&self) -> Result<bool> {
        match &self.state {
            PictureState::Ready { .. } => Ok(true),
            PictureState::Pending { picture, .. } => picture
                .query_status()
                .map(|s| s == libva::VASurfaceStatus::VASurfaceReady),
            PictureState::Invalid => unreachable!(),
        }
    }
}

/// Rendering state of a VA picture.
enum PictureState {
    Ready {
        map_format: Rc<libva::VAImageFormat>,
        picture: libva::Picture<PictureSync>,
        display_resolution: Resolution,
    },
    Pending {
        /// Submitted VA picture pending completion.
        picture: libva::Picture<PictureEnd>,
        /// VA surface ID for `picture`.
        surface_id: u32,
    },
    // Only set in the destructor when we take ownership of the VA picture.
    Invalid,
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

impl DynHandle for GenericBackendHandle {
    fn dyn_mappable_handle_mut<'a>(&'a mut self) -> Box<dyn MappableHandle + 'a> {
        Box::new(self.image().unwrap())
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

/// Keeps track of where the backend is in the negotiation process.
///
/// The generic parameter is the data that the decoder wishes to pass from the `Possible` to the
/// `Negotiated` state - typically, the properties of the stream like its resolution as they have
/// been parsed.
#[derive(Clone)]
pub(crate) enum NegotiationStatus<T> {
    /// No property about the stream has been parsed yet.
    NonNegotiated,
    /// Properties of the stream have been parsed and the client may query and change them.
    Possible(T),
    /// Stream is actively decoding and its properties cannot be changed by the client.
    Negotiated,
}

impl<T> Default for NegotiationStatus<T> {
    fn default() -> Self {
        NegotiationStatus::NonNegotiated
    }
}

impl<T> Debug for NegotiationStatus<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NegotiationStatus::NonNegotiated => write!(f, "NonNegotiated"),
            NegotiationStatus::Possible(_) => write!(f, "Possible"),
            NegotiationStatus::Negotiated => write!(f, "Negotiated"),
        }
    }
}

pub(crate) struct VaapiBackend<StreamData>
where
    for<'a> &'a StreamData: StreamInfo,
{
    /// The metadata state. Updated whenever the decoder reads new data from the stream.
    pub(crate) metadata_state: StreamMetadataState,
    /// The negotiation status
    pub(crate) negotiation_status: NegotiationStatus<Box<StreamData>>,
    /// The FIFO for all pending pictures, in the order they were submitted.
    pub(crate) pending_jobs: VecDeque<Rc<RefCell<GenericBackendHandle>>>,
}

impl<StreamData> VaapiBackend<StreamData>
where
    for<'a> &'a StreamData: StreamInfo,
{
    pub(crate) fn new(display: Rc<libva::Display>) -> Self {
        Self {
            metadata_state: StreamMetadataState::Unparsed { display },
            pending_jobs: Default::default(),
            negotiation_status: Default::default(),
        }
    }

    pub(crate) fn process_picture(
        &mut self,
        picture: libva::Picture<PictureNew>,
        block: BlockingMode,
    ) -> StatelessBackendResult<<Self as VideoDecoderBackend>::Handle> {
        let metadata = self.metadata_state.get_parsed()?;
        let timestamp = picture.timestamp();

        let handle = Rc::new(RefCell::new(GenericBackendHandle::new_pending(
            picture,
            metadata.surface_pool.clone(),
        )?));

        match block {
            BlockingMode::Blocking => handle.borrow_mut().sync(metadata)?,
            BlockingMode::NonBlocking => self.pending_jobs.push_back(Rc::clone(&handle)),
        }

        Ok(self.build_va_decoded_handle(handle, timestamp))
    }

    fn build_va_decoded_handle(
        &self,
        picture: Rc<RefCell<GenericBackendHandle>>,
        timestamp: u64,
    ) -> <Self as VideoDecoderBackend>::Handle {
        DecodedHandle::new(picture, timestamp)
    }
}

impl<StreamData> VideoDecoderBackend for VaapiBackend<StreamData>
where
    for<'a> &'a StreamData: StreamInfo,
{
    type Handle = DecodedHandle;

    fn coded_resolution(&self) -> Option<Resolution> {
        self.metadata_state
            .get_parsed()
            .map(|m| m.surface_pool.coded_resolution)
            .ok()
    }

    fn display_resolution(&self) -> Option<Resolution> {
        self.metadata_state
            .get_parsed()
            .map(|m| m.display_resolution)
            .ok()
    }

    fn num_resources_total(&self) -> usize {
        self.metadata_state
            .get_parsed()
            .map(|m| m.min_num_surfaces)
            .unwrap_or(0)
    }

    fn num_resources_left(&self) -> usize {
        self.metadata_state
            .get_parsed()
            .map(|m| m.surface_pool.num_surfaces_left())
            .unwrap_or(0)
    }

    fn format(&self) -> Option<crate::DecodedFormat> {
        let map_format = self
            .metadata_state
            .get_parsed()
            .map(|m| &m.map_format)
            .ok()?;
        DecodedFormat::try_from(map_format.as_ref()).ok()
    }

    fn try_format(&mut self, format: crate::DecodedFormat) -> VideoDecoderResult<()> {
        let header = match &self.negotiation_status {
            NegotiationStatus::Possible(header) => header,
            _ => {
                return Err(VideoDecoderError::StatelessBackendError(
                    StatelessBackendError::NegotiationFailed(anyhow!(
                        "Negotiation is not possible at this stage {:?}",
                        self.negotiation_status
                    )),
                ))
            }
        };

        let supported_formats_for_stream = self.metadata_state.supported_formats_for_stream()?;

        if supported_formats_for_stream.contains(&format) {
            let map_format = FORMAT_MAP
                .iter()
                .find(|&map| map.decoded_format == format)
                .unwrap();

            self.metadata_state
                .open(header.as_ref(), Some(map_format))?;

            Ok(())
        } else {
            Err(VideoDecoderError::StatelessBackendError(
                StatelessBackendError::NegotiationFailed(anyhow!(
                    "Format {:?} is unsupported.",
                    format
                )),
            ))
        }
    }

    fn poll(&mut self, blocking_mode: BlockingMode) -> VideoDecoderResult<VecDeque<Self::Handle>> {
        let mut completed = VecDeque::new();
        let candidates = self.pending_jobs.drain(..).collect::<VecDeque<_>>();

        for job in candidates {
            if matches!(blocking_mode, BlockingMode::NonBlocking) {
                if !job.borrow().is_va_ready()? {
                    self.pending_jobs.push_back(job);
                    continue;
                }
            }

            let metadata = self.metadata_state.get_parsed()?;

            job.borrow_mut().sync(metadata)?;
            completed.push_back(job);
        }

        let completed = completed.into_iter().map(|picture| {
            // Safe because the backend handle has been turned into a ready one.
            let timestamp = picture.borrow().picture().unwrap().timestamp();
            Ok(self.build_va_decoded_handle(picture, timestamp))
        });

        completed.collect::<Result<VecDeque<_>, _>>()
    }

    fn handle_is_ready(&self, handle: &Self::Handle) -> bool {
        handle.handle().is_ready()
    }

    fn block_on_handle(&mut self, handle: &Self::Handle) -> StatelessBackendResult<()> {
        for i in 0..self.pending_jobs.len() {
            // Remove from the queue in order.
            let job = &self.pending_jobs[i];

            if Rc::ptr_eq(job, handle.handle_rc()) {
                let job = self.pending_jobs.remove(i).unwrap();
                let metadata = self.metadata_state.get_parsed()?;

                job.borrow_mut().sync(metadata)?;
                return Ok(());
            }
        }

        Err(StatelessBackendError::Other(anyhow!(
            "Asked to block on a pending job that doesn't exist"
        )))
    }
}
