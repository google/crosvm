// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

use std::any::Any;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Result;
use base::MappedRegion;
use base::MemoryMappingArena;
use libva::Config;
use libva::Context;
use libva::Display;
use libva::Image;
use libva::Picture;
use libva::PictureSync;
use libva::Surface;
use libva::UsageHint;

use crate::virtio::video::decoder::Capability;
use crate::virtio::video::decoder::DecoderBackend;
use crate::virtio::video::decoder::DecoderEvent;
use crate::virtio::video::decoder::DecoderSession;
use crate::virtio::video::error::VideoError;
use crate::virtio::video::error::VideoResult;
use crate::virtio::video::format::Format;
use crate::virtio::video::format::FormatDesc;
use crate::virtio::video::format::FormatRange;
use crate::virtio::video::format::FrameFormat;
use crate::virtio::video::format::Level;
use crate::virtio::video::format::Profile;
use crate::virtio::video::format::Rect;
use crate::virtio::video::resource::BufferHandle;
use crate::virtio::video::resource::GuestResource;
use crate::virtio::video::resource::GuestResourceHandle;
use crate::virtio::video::utils::EventQueue;
use crate::virtio::video::utils::OutputQueue;

mod vp8;

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
    pub fn get_surface(&mut self) -> Result<Surface> {
        let mut vec = self.surfaces.borrow_mut();
        vec.pop_front().ok_or(anyhow!("Out of surfaces"))
    }

    /// Drops all surfaces from the pool
    pub fn drop_surfaces(&mut self) {
        self.surfaces = Default::default();
    }
}

/// A decoded frame handle.
#[derive(Clone)]
pub struct DecodedFrameHandle {
    /// The actual picture backing the handle.
    picture: Option<Rc<RefCell<Picture<PictureSync>>>>,
    /// The bitstream header parsed for this frame
    header: Rc<dyn Any>,
    /// The decoder resolution when this frame was processed. Not all codecs
    /// send resolution data in every frame header.
    resolution: Resolution,
    /// A handle to the surface pool.
    surface_pool: SurfacePoolHandle,
}

impl DecodedFrameHandle {
    /// Creates a new handle
    pub fn new(
        picture: Rc<RefCell<Picture<PictureSync>>>,
        header: Rc<dyn Any>,
        resolution: Resolution,
        surface_pool: SurfacePoolHandle,
    ) -> Self {
        Self {
            picture: Some(picture),
            header,
            resolution,
            surface_pool,
        }
    }

    /// Retrieves a reference into the picture backing the handle
    pub fn picture(&self) -> Rc<RefCell<Picture<PictureSync>>> {
        Rc::clone(self.picture.as_ref().unwrap())
    }

    // Returns the resolution when this frame was processed
    pub fn resolution(&self) -> &Resolution {
        &self.resolution
    }
}

impl Drop for DecodedFrameHandle {
    fn drop(&mut self) {
        if let Ok(picture) = Rc::try_unwrap(self.picture.take().unwrap()) {
            let pool = &mut self.surface_pool;

            // Only retrieve if the resolutions match, otherwise let the stale Surface drop.
            if *pool.current_resolution() == self.resolution {
                // Retrieve if not currently used by another field.
                if let Ok(surface) = picture.into_inner().take_surface() {
                    pool.add_surface(surface);
                }
            }
        }
    }
}

/// A set of params returned when a dynamic resolution change is found in the
/// bitstream.
pub struct DrcParams {
    /// The minimum amount of buffers needed to decode the stream.
    min_num_buffers: usize,
    /// The stream's new width.
    width: u32,
    /// The stream's new height.
    height: u32,
    /// The visible resolution.
    visible_rect: Rect,
}

impl TryFrom<libva::VAProfile::Type> for Profile {
    type Error = anyhow::Error;

    fn try_from(value: libva::VAProfile::Type) -> Result<Self, Self::Error> {
        match value {
            libva::VAProfile::VAProfileH264Baseline => Ok(Self::H264Baseline),
            libva::VAProfile::VAProfileH264Main => Ok(Self::H264Main),
            libva::VAProfile::VAProfileH264High => Ok(Self::H264High),
            libva::VAProfile::VAProfileH264StereoHigh => Ok(Self::H264StereoHigh),
            libva::VAProfile::VAProfileH264MultiviewHigh => Ok(Self::H264MultiviewHigh),
            libva::VAProfile::VAProfileHEVCMain => Ok(Self::HevcMain),
            libva::VAProfile::VAProfileHEVCMain10 => Ok(Self::HevcMain10),
            // (VP8Version0_3, VP8Profile0),
            libva::VAProfile::VAProfileVP9Profile0 => Ok(Self::VP9Profile0),
            libva::VAProfile::VAProfileVP9Profile1 => Ok(Self::VP9Profile1),
            libva::VAProfile::VAProfileVP9Profile2 => Ok(Self::VP9Profile2),
            libva::VAProfile::VAProfileVP9Profile3 => Ok(Self::VP9Profile3),
            _ => Err(anyhow!(
                "Conversion failed for unexpected VAProfile: {}",
                value
            )),
        }
    }
}

/// State of the input stream, which can be either unparsed (we don't know the stream properties
/// yet) or parsed (we know the stream properties and are ready to decode).
pub enum StreamMetadataState {
    /// The metadata for the current stream has not yet been parsed.
    Unparsed { display: Rc<Display> },

    /// The metadata for the current stream has been parsed and a suitable
    /// VAContext has been created to accomodate it.
    Parsed {
        /// A VAContext from which we can decode from.
        context: Rc<Context>,
        /// The VAConfig that created the context.
        config: Config,
        /// A pool of surfaces. We reuse surfaces as they are expensive to allocate.
        surface_pool: SurfacePoolHandle,
    },
}

impl StreamMetadataState {
    fn display(&self) -> Rc<libva::Display> {
        match self {
            StreamMetadataState::Unparsed { display } => Rc::clone(display),
            StreamMetadataState::Parsed { context, .. } => context.display(),
        }
    }

    fn context(&self) -> Result<Rc<libva::Context>> {
        match self {
            StreamMetadataState::Unparsed { .. } => Err(anyhow!("Stream metadata not parsed yet")),
            StreamMetadataState::Parsed { context, .. } => Ok(Rc::clone(context)),
        }
    }

    fn surface_pool(&self) -> Result<SurfacePoolHandle> {
        match self {
            StreamMetadataState::Unparsed { .. } => Err(anyhow!("Invalid state")),
            StreamMetadataState::Parsed { surface_pool, .. } => Ok(surface_pool.clone()),
        }
    }

    fn get_surface(&mut self) -> Result<Surface> {
        let mut surface_pool = self.surface_pool()?;
        surface_pool.get_surface()
    }
}

/// The state for the output queue containing the buffers that will receive the
/// decoded data.
enum OutputQueueState {
    /// Waiting for the client to call `set_output_buffer_count`.
    AwaitingBufferCount,
    /// Codec is capable of decoding frames.
    Decoding {
        /// The output queue which indirectly contains the output buffers given by crosvm
        output_queue: OutputQueue,
    },
    /// Dynamic Resolution Change - we can still accept buffers in the old
    /// format, but are waiting for new parameters before doing any decoding.
    Drc,
}

impl OutputQueueState {
    fn output_queue_mut(&mut self) -> Result<&mut OutputQueue> {
        match self {
            OutputQueueState::Decoding { output_queue } => Ok(output_queue),
            _ => Err(anyhow!("Invalid state")),
        }
    }
}

///A safe decoder abstraction over libva for a single vaContext
pub struct VaapiDecoder {
    /// The capabilities for the decoder
    caps: Capability,
}

// The VA capabilities for the coded side
struct CodedCap {
    profile: libva::VAProfile::Type,
    max_width: u32,
    max_height: u32,
    // bitmask containing the OR'd supported raw formats
    rt_fmts: u32,
}

// The VA capabilities for the raw side
struct RawCap {
    fourcc: u32,
    min_width: u32,
    min_height: u32,
    max_width: u32,
    max_height: u32,
}

impl VaapiDecoder {
    // Query the capabilities for the coded format
    fn get_coded_cap(
        display: &libva::Display,
        profile: libva::VAProfile::Type,
    ) -> Result<CodedCap> {
        let mut attrs = vec![
            libva::VAConfigAttrib {
                type_: libva::VAConfigAttribType::VAConfigAttribMaxPictureWidth,
                value: 0,
            },
            libva::VAConfigAttrib {
                type_: libva::VAConfigAttribType::VAConfigAttribMaxPictureHeight,
                value: 0,
            },
            libva::VAConfigAttrib {
                type_: libva::VAConfigAttribType::VAConfigAttribRTFormat,
                value: 0,
            },
        ];

        display.get_config_attributes(profile, libva::VAEntrypoint::VAEntrypointVLD, &mut attrs)?;

        let mut max_width = 1u32;
        let mut max_height = 1u32;
        let mut rt_fmts = 0u32;

        for attr in &attrs {
            if attr.value == libva::constants::VA_ATTRIB_NOT_SUPPORTED {
                continue;
            }

            match attr.type_ {
                libva::VAConfigAttribType::VAConfigAttribMaxPictureWidth => max_width = attr.value,
                libva::VAConfigAttribType::VAConfigAttribMaxPictureHeight => {
                    max_height = attr.value
                }
                libva::VAConfigAttribType::VAConfigAttribRTFormat => rt_fmts = attr.value,

                _ => panic!("Unexpected VAConfigAttribType {}", attr.type_),
            }
        }

        Ok(CodedCap {
            profile,
            max_width,
            max_height,
            rt_fmts,
        })
    }

    // Query the capabilities for the raw format
    fn get_raw_caps(display: Rc<libva::Display>, coded_cap: &CodedCap) -> Result<Vec<RawCap>> {
        const RT_FMTS: [u32; 18] = [
            libva::constants::VA_RT_FORMAT_YUV420,
            libva::constants::VA_RT_FORMAT_YUV422,
            libva::constants::VA_RT_FORMAT_YUV444,
            libva::constants::VA_RT_FORMAT_YUV411,
            libva::constants::VA_RT_FORMAT_YUV400,
            libva::constants::VA_RT_FORMAT_YUV420_10,
            libva::constants::VA_RT_FORMAT_YUV422_10,
            libva::constants::VA_RT_FORMAT_YUV444_10,
            libva::constants::VA_RT_FORMAT_YUV420_12,
            libva::constants::VA_RT_FORMAT_YUV422_12,
            libva::constants::VA_RT_FORMAT_YUV444_12,
            libva::constants::VA_RT_FORMAT_RGB16,
            libva::constants::VA_RT_FORMAT_RGB32,
            libva::constants::VA_RT_FORMAT_RGBP,
            libva::constants::VA_RT_FORMAT_RGB32_10,
            libva::constants::VA_RT_FORMAT_PROTECTED,
            libva::constants::VA_RT_FORMAT_RGB32_10BPP,
            libva::constants::VA_RT_FORMAT_YUV420_10BPP,
        ];

        let mut raw_caps = Vec::new();

        for rt_fmt in RT_FMTS {
            if coded_cap.rt_fmts & rt_fmt == 0 {
                continue;
            }

            // Create a config with this RTFormat, so we can query surface
            // attributes
            let attrs = vec![libva::VAConfigAttrib {
                type_: libva::VAConfigAttribType::VAConfigAttribRTFormat,
                value: rt_fmt,
            }];

            let mut config = display.create_config(
                Some(attrs),
                coded_cap.profile,
                libva::VAEntrypoint::VAEntrypointVLD,
            )?;

            let fourcc = match config
                .query_surface_attribute(libva::VASurfaceAttribType::VASurfaceAttribPixelFormat)?
            {
                Some(libva::GenericValue::Integer(i)) => i as u32,
                Some(other) => panic!("Unexpected VAGenericValue {:?}", other),
                None => continue,
            };

            let min_width = match config
                .query_surface_attribute(libva::VASurfaceAttribType::VASurfaceAttribMinWidth)?
            {
                Some(libva::GenericValue::Integer(i)) => i as u32,
                Some(other) => panic!("Unexpected VAGenericValue {:?}", other),
                None => 1,
            };

            let min_height = match config
                .query_surface_attribute(libva::VASurfaceAttribType::VASurfaceAttribMinHeight)?
            {
                Some(libva::GenericValue::Integer(i)) => i as u32,
                Some(other) => panic!("Unexpected VAGenericValue {:?}", other),
                None => 1,
            };
            let max_width = match config
                .query_surface_attribute(libva::VASurfaceAttribType::VASurfaceAttribMaxWidth)?
            {
                Some(libva::GenericValue::Integer(i)) => i as u32,
                Some(other) => panic!("Unexpected VAGenericValue {:?}", other),
                None => 1,
            };

            let max_height = match config
                .query_surface_attribute(libva::VASurfaceAttribType::VASurfaceAttribMaxHeight)?
            {
                Some(libva::GenericValue::Integer(i)) => i as u32,
                Some(other) => panic!("Unexpected VAGenericValue {:?}", other),
                None => 1,
            };

            raw_caps.push(RawCap {
                fourcc,
                min_width,
                min_height,
                max_width,
                max_height,
            });
        }

        Ok(raw_caps)
    }

    /// Creates a new instance of the Vaapi decoder.
    pub fn new() -> Result<Self> {
        let display = Rc::new(libva::Display::open()?);

        let va_profiles = display.query_config_profiles()?;

        let mut profiles = Vec::new();
        let mut in_fmts = Vec::new();
        let mut out_fmts = Vec::new();
        let mut profiles_map: BTreeMap<Format, Vec<Profile>> = Default::default();

        // VA has no API for querying the levels supported by the driver.
        // vaQueryProcessingRate is close, but not quite a solution here
        // for all codecs.
        let levels: BTreeMap<Format, Vec<Level>> = Default::default();

        for va_profile in va_profiles {
            let entrypoints = display.query_config_entrypoints(va_profile)?;
            if !entrypoints
                .iter()
                .any(|e| *e == libva::VAEntrypoint::VAEntrypointVLD)
            {
                // All formats we are aiming to support require
                // VAEntrypointVLD.
                continue;
            }
            // Manually push all VP8 profiles, since VA exposes only a single
            // VP8 profile for all of these
            if va_profile == libva::VAProfile::VAProfileVP8Version0_3 {
                profiles.push(Profile::VP8Profile0);
                profiles.push(Profile::VP8Profile1);
                profiles.push(Profile::VP8Profile2);
                profiles.push(Profile::VP8Profile3);
            }

            let profile = match Profile::try_from(va_profile) {
                Ok(p) => p,
                // Skip if we cannot convert to a valid virtio format
                Err(_) => continue,
            };

            let coded_cap = VaapiDecoder::get_coded_cap(display.as_ref(), va_profile)?;
            let raw_caps = VaapiDecoder::get_raw_caps(Rc::clone(&display), &coded_cap)?;

            let coded_frame_fmt = FrameFormat {
                width: FormatRange {
                    min: 1,
                    max: coded_cap.max_width,
                    step: 1,
                },

                height: FormatRange {
                    min: 1,
                    max: coded_cap.max_height,
                    step: 1,
                },

                bitrates: Default::default(),
            };

            let coded_format = profile.to_format();
            match profiles_map.entry(coded_format) {
                Entry::Vacant(e) => {
                    e.insert(vec![profile]);
                }
                Entry::Occupied(mut ps) => {
                    ps.get_mut().push(profile);
                }
            }

            let mut n_out = 0;
            for raw_cap in raw_caps {
                if raw_cap.fourcc != libva::constants::VA_FOURCC_NV12 {
                    // Apparently only NV12 is currently supported by virtio video
                    continue;
                }

                let raw_frame_fmt = FrameFormat {
                    width: FormatRange {
                        min: raw_cap.min_width,
                        max: raw_cap.max_width,
                        step: 1,
                    },

                    height: FormatRange {
                        min: raw_cap.min_height,
                        max: raw_cap.max_height,
                        step: 1,
                    },

                    bitrates: Default::default(),
                };

                out_fmts.push(FormatDesc {
                    mask: 0,
                    format: Format::NV12,
                    frame_formats: vec![raw_frame_fmt],
                    plane_align: 1,
                });

                n_out += 1;
            }

            in_fmts.push(FormatDesc {
                mask: !(u64::MAX << n_out) << (out_fmts.len() - n_out),
                format: coded_format,
                frame_formats: vec![coded_frame_fmt],
                plane_align: 1,
            });
        }

        Ok(Self {
            caps: Capability::new(in_fmts, out_fmts, profiles_map, levels),
        })
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolution {
    width: u32,
    height: u32,
}

/// A decoder session for the libva backend
pub struct VaapiDecoderSession {
    /// The implementation for the codec specific logic.
    codec: Box<dyn VaapiCodec>,
    /// The state for the output queue. Updated when `set_output_buffer_count`
    /// is called or when we detect a dynamic resolution change.
    output_queue_state: OutputQueueState,
    /// Queue containing decoded pictures.
    ready_queue: VecDeque<DecodedFrameHandle>,
    /// The event queue we can use to signal new events.
    event_queue: EventQueue<DecoderEvent>,
    /// Whether the decoder is currently flushing.
    flushing: bool,
    /// The coded format we are decoding.
    coded_format: Format,
}

/// A convenience type implementing persistent slice access for BufferHandles.
pub struct BufferMapping<T: Borrow<U>, U: BufferHandle> {
    #[allow(dead_code)]
    /// The underlying resource. Must be kept so as not to drop the BufferHandle
    resource: T,
    /// The mapping that backs the underlying slices returned by AsRef and AsMut
    mapping: MemoryMappingArena,
    /// A phantom so that the U parameter is used.
    phantom: PhantomData<U>,
}

impl<T: Borrow<U>, U: BufferHandle> BufferMapping<T, U> {
    /// Creates a new BufferMap
    pub fn new(resource: T, offset: usize, size: usize) -> Result<Self> {
        let mapping = resource.borrow().get_mapping(offset, size)?;

        Ok(Self {
            resource,
            mapping,
            phantom: PhantomData,
        })
    }
}

impl<T: Borrow<U>, U: BufferHandle> AsRef<[u8]> for BufferMapping<T, U> {
    fn as_ref(&self) -> &[u8] {
        let mapping = &self.mapping;
        // Safe because the mapping is linear and we own it, so it will not be unmapped during
        // the lifetime of this slice.
        unsafe { std::slice::from_raw_parts(mapping.as_ptr(), mapping.size()) }
    }
}

impl<T: Borrow<U>, U: BufferHandle> AsMut<[u8]> for BufferMapping<T, U> {
    fn as_mut(&mut self) -> &mut [u8] {
        let mapping = &self.mapping;
        // Safe because the mapping is linear and we own it, so it will not be unmapped during
        // the lifetime of this slice.
        unsafe { std::slice::from_raw_parts_mut(mapping.as_ptr(), mapping.size()) }
    }
}

impl VaapiDecoderSession {
    /// Create the `num_surfaces` surfaces for a combination of `width`,
    /// `height` and `rt_format`.
    fn create_surfaces(
        display: Rc<Display>,
        width: u32,
        height: u32,
        rt_format: u32,
        num_surfaces: usize,
    ) -> Result<Vec<Surface>> {
        display.create_surfaces(
            rt_format,
            Some(libva::constants::VA_FOURCC_NV12), // NV12 is hardcoded for now
            width,
            height,
            Some(UsageHint::USAGE_HINT_DECODER),
            num_surfaces as u32,
        )
    }

    fn change_resolution(&mut self, new_params: DrcParams) -> Result<()> {
        // Ask the client for new buffers.
        self.event_queue
            .queue_event(DecoderEvent::ProvidePictureBuffers {
                min_num_buffers: u32::try_from(new_params.min_num_buffers)?,
                width: new_params.width as i32,
                height: new_params.height as i32,
                visible_rect: new_params.visible_rect,
            })?;

        // Drop our output queue and wait for the new number of output buffers.
        self.output_queue_state = match &self.output_queue_state {
            // If this is part of the initialization step, then do not switch states.
            OutputQueueState::AwaitingBufferCount => OutputQueueState::AwaitingBufferCount,
            OutputQueueState::Decoding { .. } => OutputQueueState::Drc,
            _ => return Err(anyhow!("Invalid state during DRC.")),
        };

        Ok(())
    }

    /// Copies `src` into `dst` as NV12, removing any extra padding.
    fn nv12_copy(
        mut src: &[u8],
        mut dst: &mut [u8],
        width: u32,
        height: u32,
        strides: [u32; 3],
        offsets: [u32; 3],
    ) {
        let width = width.try_into().unwrap();
        let height = height.try_into().unwrap();
        let data = src;

        // Copy luma
        for _ in 0..height {
            dst[..width].copy_from_slice(&src[..width]);
            dst = &mut dst[width..];
            src = &src[strides[0] as usize..];
        }

        // Advance to the offset of the chroma plane
        let mut src = &data[offsets[1] as usize..];

        // Copy chroma
        for _ in 0..height / 2 {
            dst[..width].copy_from_slice(&src[..width]);
            dst = &mut dst[width..];
            src = &src[strides[1_usize] as usize..];
        }
    }

    /// Copy the decoded `image` into `output_buffer`, removing any extra
    /// padding. This is hardcoded to NV12 for now.
    fn copy_image_to_output(image: &Image, output_buffer: &mut GuestResource) -> Result<()> {
        let va_img = image.image();

        if va_img.format.fourcc != libva::constants::VA_FOURCC_NV12 {
            panic!("Unsupported format")
        }

        // Get a mapping from the start of the buffer to the size of the
        // underlying decoded data in the Image.
        let mut output_map: BufferMapping<_, GuestResourceHandle> = BufferMapping::new(
            &mut output_buffer.handle,
            0,
            usize::from(va_img.width) * usize::from(va_img.height) * 3 / 2,
        )?;

        let output_bytes = output_map.as_mut();

        let decoded_bytes = image.as_ref();

        VaapiDecoderSession::nv12_copy(
            decoded_bytes,
            output_bytes,
            u32::from(va_img.width),
            u32::from(va_img.height),
            va_img.pitches,
            va_img.offsets,
        );

        Ok(())
    }

    /// Copy raw decoded data from `image` into the output buffer
    pub fn output_picture(
        &mut self,
        decoded_frame: DecodedFrameHandle,
        resolution: Resolution,
        image_format: &libva::VAImageFormat,
    ) -> Result<bool> {
        let output_queue = self.output_queue_state.output_queue_mut()?;

        // Output buffer to be used.
        let (picture_buffer_id, output_buffer) = match output_queue.try_get_ready_buffer() {
            Some(ready_buffer) => ready_buffer,
            None => {
                return Ok(false);
            }
        };

        let timestamp = RefCell::borrow(&decoded_frame.picture()).timestamp();
        let picture = decoded_frame.picture();
        let mut picture = picture.borrow_mut();

        // Get the associated VAImage, which will map the
        // VASurface onto our address space.
        let image = Image::new(
            &mut picture,
            *image_format,
            resolution.width,
            resolution.height,
            false,
        )?;

        VaapiDecoderSession::copy_image_to_output(&image, output_buffer)?;

        // The actual width and height. Note that The width and height fields
        // returned in the VAImage structure may get enlarged for some YUV
        // formats.
        let width = i32::from(image.image().width);
        let height = i32::from(image.image().height);
        let picture_buffer_id = picture_buffer_id as i32;

        // Say that we are done decoding this picture.
        self.event_queue
            .queue_event(DecoderEvent::PictureReady {
                picture_buffer_id,
                timestamp,
                visible_rect: Rect {
                    left: 0,
                    top: 0,
                    right: width as i32,
                    bottom: height as i32,
                },
            })
            .map_err(|e| {
                VideoError::BackendFailure(anyhow!("Can't queue the PictureReady event {}", e))
            })?;

        Ok(true)
    }

    fn drain_ready_queue(&mut self) -> Result<()> {
        let image_format = match self.codec.va_image_fmt() {
            Some(image_fmt) => *image_fmt,
            // No image format currently set means we have no output to drain.
            None => return Ok(()),
        };

        while let Some(decoded_frame) = self.ready_queue.pop_front() {
            let resolution = *decoded_frame.resolution();

            let outputted =
                self.output_picture(decoded_frame.clone(), resolution, &image_format)?;
            if !outputted {
                self.ready_queue.push_front(decoded_frame);
                break;
            }
        }

        Ok(())
    }

    /// Convenience function to get the test NV12 result. This can be used to,
    /// e.g.: dump it to disk or compute a CRC32
    #[cfg(test)]
    #[allow(dead_code)]
    fn get_test_nv12<T: Fn(&[u8]) -> U, U>(
        display: Rc<Display>,
        picture: Rc<RefCell<Picture<PictureSync>>>,
        width: u32,
        height: u32,
        action: T,
    ) -> U {
        let mut picture = picture.borrow_mut();

        let image_fmts = display.query_image_formats().unwrap();
        let image_fmt = image_fmts
            .into_iter()
            .find(|f| f.fourcc == libva::constants::VA_FOURCC_NV12)
            .expect("No valid VAImageFormat found for NV12");

        // Get the associated VAImage, which will map the
        // VASurface onto our address space.
        let image = Image::new(&mut picture, image_fmt, width, height, false).unwrap();

        let va_img = image.image();
        let mut out: Vec<u8> =
            vec![0; usize::from(va_img.width) * usize::from(va_img.height) * 3 / 2];

        VaapiDecoderSession::nv12_copy(
            image.as_ref(),
            &mut out,
            u32::from(va_img.width),
            u32::from(va_img.height),
            va_img.pitches,
            va_img.offsets,
        );

        action(&out)
    }

    fn try_emit_flush_completed(&mut self) -> Result<()> {
        let num_remaining = self.ready_queue.len();

        if num_remaining == 0 {
            self.flushing = false;

            let event_queue = &mut self.event_queue;

            event_queue
                .queue_event(DecoderEvent::FlushCompleted(Ok(())))
                .map_err(|e| anyhow!("Can't queue the PictureReady event {}", e))
        } else {
            Ok(())
        }
    }
}

impl DecoderSession for VaapiDecoderSession {
    fn set_output_parameters(&mut self, buffer_count: usize, format: Format) -> VideoResult<()> {
        let output_queue_state = &mut self.output_queue_state;

        match output_queue_state {
            OutputQueueState::AwaitingBufferCount | OutputQueueState::Drc => {
                self.codec
                    .set_raw_fmt(format)
                    .map_err(VideoError::BackendFailure)?;

                *output_queue_state = OutputQueueState::Decoding {
                    output_queue: OutputQueue::new(buffer_count),
                };

                Ok(())
            }
            _ => Err(VideoError::BackendFailure(anyhow!(
                "Invalid state while calling set_output_parameters"
            ))),
        }
    }

    fn decode(
        &mut self,
        resource_id: u32,
        timestamp: u64,
        resource: GuestResourceHandle,
        offset: u32,
        bytes_used: u32,
    ) -> VideoResult<()> {
        let frames = self.codec.decode(timestamp, &resource, offset, bytes_used);

        match frames {
            Ok(frames) => {
                self.event_queue
                    .queue_event(DecoderEvent::NotifyEndOfBitstreamBuffer(resource_id))
                    .map_err(|e| {
                        VideoError::BackendFailure(anyhow!(
                            "Can't queue the NotifyEndOfBitstream event {}",
                            e
                        ))
                    })?;

                if let Some(params) = self.codec.drc() {
                    self.change_resolution(params)
                        .map_err(VideoError::BackendFailure)?;
                }

                for decoded_frame in frames {
                    self.ready_queue.push_back(decoded_frame);
                }

                self.drain_ready_queue()
                    .map_err(VideoError::BackendFailure)?;

                Ok(())
            }

            Err(e) => {
                let event_queue = &mut self.event_queue;

                event_queue
                    .queue_event(DecoderEvent::NotifyError(VideoError::BackendFailure(
                        anyhow!("Decoding buffer {} failed", resource_id),
                    )))
                    .map_err(|e| {
                        VideoError::BackendFailure(anyhow!(
                            "Can't queue the NotifyError event {}",
                            e
                        ))
                    })?;

                Err(VideoError::BackendFailure(e))
            }
        }
    }

    fn flush(&mut self) -> VideoResult<()> {
        self.flushing = true;

        // Retrieve ready frames from the codec, if any.
        let pics = self.codec.flush().map_err(VideoError::BackendFailure)?;
        self.ready_queue.extend(pics);

        self.drain_ready_queue()
            .map_err(VideoError::BackendFailure)?;

        self.try_emit_flush_completed()
            .map_err(VideoError::BackendFailure)
    }

    fn reset(&mut self) -> VideoResult<()> {
        // Drop the queued output buffers.
        self.clear_output_buffers()?;

        // TODO(acourbot) IIUC we don't need to reset the resolution here, we can be optimistic
        // and assume that it won't change - if it does we will get a DRC event anyway.

        self.event_queue
            .queue_event(DecoderEvent::ResetCompleted(Ok(())))
            .map_err(|e| {
                VideoError::BackendFailure(anyhow!("Can't queue the ResetCompleted event {}", e))
            })?;

        let display = Rc::new(Display::open().map_err(VideoError::BackendFailure)?);
        let codec = match self.coded_format {
            Format::VP8 => Box::new(
                vp8::Vp8Codec::new(display).map_err(|e| VideoError::BackendFailure(anyhow!(e)))?,
            ),
            _ => return Err(VideoError::InvalidFormat),
        };

        *self = VaapiDecoderSession {
            codec,
            output_queue_state: OutputQueueState::AwaitingBufferCount,
            ready_queue: Default::default(),
            event_queue: EventQueue::new().map_err(|e| VideoError::BackendFailure(anyhow!(e)))?,
            flushing: Default::default(),
            coded_format: self.coded_format,
        };

        Ok(())
    }

    fn clear_output_buffers(&mut self) -> VideoResult<()> {
        // Cancel any ongoing flush.
        self.flushing = false;

        // Drop all output buffers we currently hold.
        if let OutputQueueState::Decoding { output_queue } = &mut self.output_queue_state {
            output_queue.clear_ready_buffers();
        }

        // Drop all decoded frames signaled as ready and cancel any reported flush.
        self.event_queue.retain(|event| {
            !matches!(
                event,
                DecoderEvent::PictureReady { .. } | DecoderEvent::FlushCompleted(_)
            )
        });

        Ok(())
    }

    fn event_pipe(&self) -> &dyn base::AsRawDescriptor {
        &self.event_queue
    }

    fn use_output_buffer(
        &mut self,
        picture_buffer_id: i32,
        resource: GuestResource,
    ) -> VideoResult<()> {
        let output_queue_state = &mut self.output_queue_state;
        if let OutputQueueState::Drc = output_queue_state {
            // Reusing buffers during DRC is valid, but we won't use them and can just drop them.
            return Ok(());
        }

        let output_queue = output_queue_state
            .output_queue_mut()
            .map_err(|e| VideoError::BackendFailure(anyhow!(e)))?;

        // TODO: there's a type mismatch here between the trait and the signature for `import_buffer`
        output_queue
            .import_buffer(picture_buffer_id as u32, resource)
            .map_err(|e| VideoError::BackendFailure(anyhow!(e)))?;

        self.drain_ready_queue()
            .map_err(VideoError::BackendFailure)?;

        Ok(())
    }

    fn reuse_output_buffer(&mut self, picture_buffer_id: i32) -> VideoResult<()> {
        let output_queue_state = &mut self.output_queue_state;
        if let OutputQueueState::Drc = output_queue_state {
            // Reusing buffers during DRC is valid, but we won't use them and can just drop them.
            return Ok(());
        }

        let output_queue = output_queue_state
            .output_queue_mut()
            .map_err(|e| VideoError::BackendFailure(anyhow!(e)))?;

        // TODO: there's a type mismatch here between the trait and the signature for `import_buffer`
        output_queue
            .reuse_buffer(picture_buffer_id as u32)
            .map_err(|e| VideoError::BackendFailure(anyhow!(e)))?;

        if self.flushing {
            // Try flushing again now that we have a new buffer. This might let
            // us progress further in the flush operation.
            self.flush()?;
        }
        Ok(())
    }

    fn read_event(&mut self) -> VideoResult<DecoderEvent> {
        self.event_queue
            .dequeue_event()
            .map_err(|e| VideoError::BackendFailure(anyhow!("Can't read event {}", e)))
    }
}

impl DecoderBackend for VaapiDecoder {
    type Session = VaapiDecoderSession;

    fn get_capabilities(&self) -> Capability {
        self.caps.clone()
    }

    fn new_session(&mut self, format: Format) -> VideoResult<Self::Session> {
        let display = Rc::new(Display::open().map_err(VideoError::BackendFailure)?);

        let codec = match format {
            Format::VP8 => Box::new(
                vp8::Vp8Codec::new(display).map_err(|e| VideoError::BackendFailure(anyhow!(e)))?,
            ),
            _ => return Err(VideoError::InvalidFormat),
        };

        Ok(VaapiDecoderSession {
            codec,
            output_queue_state: OutputQueueState::AwaitingBufferCount,
            ready_queue: Default::default(),
            event_queue: EventQueue::new().map_err(|e| VideoError::BackendFailure(anyhow!(e)))?,
            flushing: Default::default(),
            coded_format: format,
        })
    }
}

pub trait VaapiCodec: downcast_rs::Downcast {
    /// Decode the compressed stream contained in
    /// [`offset`..`offset`+`bytes_used`] of the shared memory in `resource`.
    /// `timestamp` is the timestamp for that part of the stream.
    /// Returns zero or more decoded pictures depending on the compressed
    /// stream, which might also be part of the codec's decoded picture buffer
    /// (DPB).
    fn decode(
        &mut self,
        timestamp: u64,
        resource: &GuestResourceHandle,
        offset: u32,
        bytes_used: u32,
    ) -> Result<Vec<DecodedFrameHandle>>;

    /// Flush the decoder i.e. finish processing all queued decode requests and
    /// emit frames for them.
    fn flush(&mut self) -> Result<Vec<DecodedFrameHandle>>;

    /// Returns the current VA image format
    fn va_image_fmt(&self) -> &Option<libva::VAImageFormat>;

    /// Set the raw picture format.
    fn set_raw_fmt(&mut self, format: Format) -> Result<()>;

    /// Whether the codec has encountered a dynamic resolution change, i.e.:
    /// Whether there were changes in coded resolution (OUTPUT width and
    /// height), in the visible resolution (selection rectangles), in the
    /// minimum number of buffers needed for decoding or in bit-depth of the
    /// bitstream. This function will be called at every frame by the session.
    fn drc(&mut self) -> Option<DrcParams>;
}
downcast_rs::impl_downcast!(VaapiCodec); // Used in unit tests.

#[cfg(test)]
mod tests {
    use base::FromRawDescriptor;
    use base::MemoryMappingBuilder;
    use base::SafeDescriptor;
    use base::SharedMemory;

    use super::*;
    use crate::virtio::video::resource::GuestMemArea;
    use crate::virtio::video::resource::GuestMemHandle;

    pub(crate) fn build_resource(slice: &[u8]) -> GuestResourceHandle {
        let input_shm = SharedMemory::new("", u64::try_from(slice.len()).unwrap()).unwrap();

        let input_mapping = MemoryMappingBuilder::new(input_shm.size() as usize)
            .from_shared_memory(&input_shm)
            .build()
            .unwrap();

        input_mapping
            .write_slice(slice, 0)
            .expect("Failed to write stream data into input buffer.");

        GuestResourceHandle::GuestPages(GuestMemHandle {
            // Safe because we are taking ownership of a just-duplicated FD.
            desc: unsafe {
                SafeDescriptor::from_raw_descriptor(base::clone_descriptor(&input_shm).unwrap())
            },
            mem_areas: vec![GuestMemArea {
                offset: 0,
                length: input_shm.size() as usize,
            }],
        })
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_get_capabilities() {
        let decoder = VaapiDecoder::new().unwrap();
        let caps = decoder.get_capabilities();
        assert!(!caps.input_formats().is_empty());
        assert!(!caps.output_formats().is_empty());
    }
}
