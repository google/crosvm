// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Result;
#[cfg(test)]
use libva::BufferType;
use libva::Display;
use libva::Picture as VaPicture;
use libva::PictureEnd;
use libva::SegmentParameterVP9;
use libva::UsageHint;

use crate::decoders::vp9::backends::AsBackendHandle;
use crate::decoders::vp9::backends::BlockingMode;
use crate::decoders::vp9::backends::ContainedPicture;
use crate::decoders::vp9::backends::DecodedHandle;
use crate::decoders::vp9::backends::Result as StatelessBackendResult;
use crate::decoders::vp9::backends::StatelessDecoderBackend;
use crate::decoders::vp9::backends::Vp9Picture;
use crate::decoders::vp9::decoder::Decoder;
use crate::decoders::vp9::lookups::AC_QLOOKUP;
use crate::decoders::vp9::lookups::AC_QLOOKUP_10;
use crate::decoders::vp9::lookups::AC_QLOOKUP_12;
use crate::decoders::vp9::lookups::DC_QLOOKUP;
use crate::decoders::vp9::lookups::DC_QLOOKUP_10;
use crate::decoders::vp9::lookups::DC_QLOOKUP_12;
use crate::decoders::vp9::parser::BitDepth;
use crate::decoders::vp9::parser::Header;
use crate::decoders::vp9::parser::Profile;
use crate::decoders::vp9::parser::ALTREF_FRAME;
use crate::decoders::vp9::parser::GOLDEN_FRAME;
use crate::decoders::vp9::parser::INTRA_FRAME;
use crate::decoders::vp9::parser::LAST_FRAME;
use crate::decoders::vp9::parser::MAX_LOOP_FILTER;
use crate::decoders::vp9::parser::MAX_MODE_LF_DELTAS;
use crate::decoders::vp9::parser::MAX_REF_FRAMES;
use crate::decoders::vp9::parser::MAX_SEGMENTS;
use crate::decoders::vp9::parser::NUM_REF_FRAMES;
use crate::decoders::vp9::parser::SEG_LVL_ALT_L;
use crate::decoders::vp9::parser::SEG_LVL_REF_FRAME;
use crate::decoders::vp9::parser::SEG_LVL_SKIP;
use crate::decoders::Error as DecoderError;
use crate::decoders::Result as DecoderResult;
use crate::decoders::StatelessBackendError;
use crate::decoders::VideoDecoderBackend;
use crate::utils;
use crate::utils::vaapi::DecodedHandle as VADecodedHandle;
use crate::utils::vaapi::FormatMap;
use crate::utils::vaapi::GenericBackendHandle;
use crate::utils::vaapi::NegotiationStatus;
use crate::utils::vaapi::StreamMetadataState;
use crate::utils::vaapi::SurfacePoolHandle;
use crate::DecodedFormat;
use crate::Resolution;

/// Resolves to the type used as Handle by the backend.
type AssociatedHandle = <Backend as StatelessDecoderBackend>::Handle;

/// The number of surfaces to allocate for this codec.
const NUM_SURFACES: usize = 12;

#[cfg(test)]
struct TestParams {
    pic_param: BufferType,
    slice_param: BufferType,
    slice_data: BufferType,
}

/// A type that keeps track of a pending decoding operation. The backend can
/// complete the job by either querying its status with VA-API or by blocking on
/// it at some point in the future.
///
/// Once the backend is sure that the operation went through, it can assign the
/// handle to `vp9_picture` and dequeue this object from the pending queue.
struct PendingJob<BackendHandle> {
    /// A picture that was already sent to VA-API. It is unclear whether it has
    /// been decoded yet because we have been asked not to block on it.
    va_picture: VaPicture<PictureEnd>,
    /// A handle to the picture passed in by the H264 decoder. It has no handle
    /// backing it yet, as we cannot be sure that the decoding operation went
    /// through.
    vp9_picture: ContainedPicture<BackendHandle>,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Segmentation {
    /// Loop filter level
    lvl_lookup: [[u8; MAX_MODE_LF_DELTAS]; MAX_REF_FRAMES],

    /// AC quant scale for luma component
    luma_ac_quant_scale: i16,
    /// DC quant scale for luma component
    luma_dc_quant_scale: i16,
    /// AC quant scale for chroma component
    chroma_ac_quant_scale: i16,
    /// DC quant scale for chroma component
    chroma_dc_quant_scale: i16,

    /// Whether the alternate reference frame segment feature is enabled (SEG_LVL_REF_FRAME)
    reference_frame_enabled: bool,
    /// The feature data for the reference frame featire
    reference_frame: i16,
    /// Whether the skip segment feature is enabled (SEG_LVL_SKIP)
    reference_skip_enabled: bool,
}

struct Backend {
    /// The metadata state. Updated whenever the decoder reads new data from the stream.
    metadata_state: StreamMetadataState,
    /// The FIFO for all pending pictures, in the order they were submitted.
    pending_jobs: VecDeque<PendingJob<GenericBackendHandle>>,
    /// The image formats we can decode into.
    image_formats: Rc<Vec<libva::VAImageFormat>>,
    /// The number of allocated surfaces.
    num_allocated_surfaces: usize,
    /// The negotiation status
    negotiation_status: NegotiationStatus<Box<Header>>,
    /// Per-segment data.
    segmentation: [Segmentation; MAX_SEGMENTS],

    #[cfg(test)]
    /// Test params. Saves the metadata sent to VA-API for the purposes of
    /// testing.
    test_params: Vec<TestParams>,
}

impl Backend {
    /// Create a new codec backend for VP8.
    fn new(display: Rc<libva::Display>) -> Result<Self> {
        let image_formats = Rc::new(display.query_image_formats()?);

        Ok(Self {
            metadata_state: StreamMetadataState::Unparsed { display },
            image_formats,
            pending_jobs: Default::default(),
            num_allocated_surfaces: Default::default(),
            negotiation_status: Default::default(),
            segmentation: Default::default(),

            #[cfg(test)]
            test_params: Default::default(),
        })
    }

    /// A clamp such that min <= x <= max
    fn clamp<U: PartialOrd>(x: U, low: U, high: U) -> U {
        if x > high {
            high
        } else if x < low {
            low
        } else {
            x
        }
    }

    fn get_profile(profile: Profile) -> libva::VAProfile::Type {
        match profile {
            Profile::Profile0 => libva::VAProfile::VAProfileVP9Profile0,
            Profile::Profile1 => libva::VAProfile::VAProfileVP9Profile1,
            Profile::Profile2 => libva::VAProfile::VAProfileVP9Profile2,
            Profile::Profile3 => libva::VAProfile::VAProfileVP9Profile3,
        }
    }

    fn get_rt_format(
        profile: Profile,
        bit_depth: BitDepth,
        subsampling_x: bool,
        subsampling_y: bool,
    ) -> Result<u32> {
        match profile {
            Profile::Profile0 => Ok(libva::constants::VA_RT_FORMAT_YUV420),
            Profile::Profile1 => {
                if subsampling_x && !subsampling_y {
                    Ok(libva::constants::VA_RT_FORMAT_YUV422)
                } else if !subsampling_x && !subsampling_y {
                    Ok(libva::constants::VA_RT_FORMAT_YUV444)
                } else {
                    Err(anyhow!(
                        "Unsupported subsampling for profile 1: X: {:?} Y: {:?}",
                        subsampling_x,
                        subsampling_y
                    ))
                }
            }
            Profile::Profile2 => match bit_depth {
                BitDepth::Depth8 => Err(anyhow!(
                    "Unsupported bit depth for profile 2: {:?}",
                    bit_depth
                )),
                BitDepth::Depth10 => Ok(libva::constants::VA_RT_FORMAT_YUV420_10),
                BitDepth::Depth12 => Ok(libva::constants::VA_RT_FORMAT_YUV420_12),
            },
            Profile::Profile3 => {
                if subsampling_x && !subsampling_y {
                    match bit_depth {
                        BitDepth::Depth8 => Err(anyhow!(
                            "Unsupported (subsampling_x, subsampling_y, bit depth) combination for profile 3: ({:?}, {:?}, {:?  })",
                            subsampling_x,
                            subsampling_y,
                            bit_depth
                        )),
                        BitDepth::Depth10 => Ok(libva::constants::VA_RT_FORMAT_YUV422_10),
                        BitDepth::Depth12 => Ok(libva::constants::VA_RT_FORMAT_YUV422_12),
                    }
                } else if !subsampling_x && !subsampling_y {
                    match bit_depth {
                        BitDepth::Depth8 => Err(anyhow!(
                            "Unsupported (subsampling_x, subsampling_y, bit depth) combination for profile 3: ({:?}, {:?}, {:?})",
                            subsampling_x,
                            subsampling_y,
                            bit_depth
                        )),
                        BitDepth::Depth10 => Ok(libva::constants::VA_RT_FORMAT_YUV444_10),
                        BitDepth::Depth12 => Ok(libva::constants::VA_RT_FORMAT_YUV444_12),
                    }
                } else {
                    Err(anyhow!(
                            "Unsupported (subsampling_x, subsampling_y, bit depth) combination for profile 3: ({:?}, {:?}, {:?})",
                            subsampling_x,
                            subsampling_y,
                            bit_depth
                        ))
                }
            }
        }
    }

    /// Initialize the codec state by reading some metadata from the current
    /// frame.
    fn open(&mut self, hdr: &Header, format_map: Option<&FormatMap>) -> Result<()> {
        let display = self.metadata_state.display();

        let hdr_profile = hdr.profile();

        let va_profile = Self::get_profile(hdr_profile);
        let rt_format = Self::get_rt_format(
            hdr_profile,
            hdr.bit_depth(),
            hdr.subsampling_x(),
            hdr.subsampling_y(),
        )?;

        let frame_w = hdr.width();
        let frame_h = hdr.height();

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
            utils::vaapi::FORMAT_MAP
                .iter()
                .find(|&map| map.rt_format == rt_format)
                .ok_or(anyhow!("Unsupported format {}", rt_format))?
        };

        let map_format = self
            .image_formats
            .iter()
            .find(|f| f.fourcc == format_map.va_fourcc)
            .cloned()
            .unwrap();

        let surfaces = display.create_surfaces(
            rt_format,
            Some(map_format.fourcc),
            frame_w,
            frame_h,
            Some(UsageHint::USAGE_HINT_DECODER),
            NUM_SURFACES as u32,
        )?;

        self.num_allocated_surfaces = NUM_SURFACES;

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

        let surface_pool = SurfacePoolHandle::new(surfaces, coded_resolution);

        self.metadata_state = StreamMetadataState::Parsed {
            context,
            config,
            surface_pool,
            coded_resolution,
            display_resolution: coded_resolution, // TODO(dwlsalmeida)
            map_format: Rc::new(map_format),
            rt_format,
            profile: va_profile,
        };

        Ok(())
    }

    /// Gets the VASurfaceID for the given `picture`.
    fn surface_id(picture: &Vp9Picture<GenericBackendHandle>) -> libva::VASurfaceID {
        picture.backend_handle.as_ref().unwrap().surface_id()
    }

    /// An implementation of seg_feature_active as per "6.4.9 Segmentation feature active syntax"
    fn seg_feature_active(hdr: &Header, segment_id: u8, feature: u8) -> bool {
        let seg = hdr.seg();
        let feature_enabled = seg.feature_enabled();
        seg.enabled() && feature_enabled[usize::from(segment_id)][usize::from(feature)]
    }

    /// An implementation of get_qindex as per "8.6.1 Dequantization functions"
    fn get_qindex(hdr: &Header, segment_id: u8) -> i32 {
        let q = hdr.quant();
        let base_q_idx = q.base_q_idx();
        let seg = hdr.seg();

        if Self::seg_feature_active(hdr, segment_id, 0) {
            let mut data = seg.feature_data()[usize::from(segment_id)][0] as i32;

            if !seg.abs_or_delta_update() {
                data += i32::from(base_q_idx);
            }

            Self::clamp(data, 0, 255)
        } else {
            i32::from(base_q_idx)
        }
    }

    /// An implementation of get_dc_quant as per "8.6.1 Dequantization functions"
    fn get_dc_quant(hdr: &Header, segment_id: u8, luma: bool) -> Result<i32> {
        let quant = hdr.quant();

        let delta_q_dc = if luma {
            quant.delta_q_y_dc()
        } else {
            quant.delta_q_uv_dc()
        };
        let qindex = Self::get_qindex(hdr, segment_id);
        let q_table_idx = Self::clamp(qindex + i32::from(delta_q_dc), 0, 255) as usize;
        match hdr.bit_depth() {
            BitDepth::Depth8 => Ok(i32::from(DC_QLOOKUP[q_table_idx])),
            BitDepth::Depth10 => Ok(i32::from(DC_QLOOKUP_10[q_table_idx])),
            BitDepth::Depth12 => Ok(i32::from(DC_QLOOKUP_12[q_table_idx])),
        }
    }

    /// An implementation of get_ac_quant as per "8.6.1 Dequantization functions"
    fn get_ac_quant(hdr: &Header, segment_id: u8, luma: bool) -> Result<i32> {
        let quant = hdr.quant();

        let delta_q_ac = if luma { 0 } else { quant.delta_q_uv_ac() };
        let qindex = Self::get_qindex(hdr, segment_id);
        let q_table_idx = usize::try_from(Self::clamp(qindex + i32::from(delta_q_ac), 0, 255))?;

        match hdr.bit_depth() {
            BitDepth::Depth8 => Ok(i32::from(AC_QLOOKUP[q_table_idx])),
            BitDepth::Depth10 => Ok(i32::from(AC_QLOOKUP_10[q_table_idx])),
            BitDepth::Depth12 => Ok(i32::from(AC_QLOOKUP_12[q_table_idx])),
        }
    }

    /// Update the state of the segmentation parameters after seeing a frame
    fn update_segmentation(hdr: &Header, segmentation: &mut [Segmentation; 8]) -> Result<()> {
        let lf = hdr.lf();
        let seg = hdr.seg();

        let n_shift = lf.level() >> 5;

        for segment_id in 0..MAX_SEGMENTS as u8 {
            let luma_dc_quant_scale = i16::try_from(Self::get_dc_quant(hdr, segment_id, true)?)?;
            let luma_ac_quant_scale = i16::try_from(Self::get_ac_quant(hdr, segment_id, true)?)?;
            let chroma_dc_quant_scale = i16::try_from(Self::get_dc_quant(hdr, segment_id, false)?)?;
            let chroma_ac_quant_scale = i16::try_from(Self::get_ac_quant(hdr, segment_id, false)?)?;

            let mut lvl_seg = i32::from(lf.level());
            let mut lvl_lookup: [[u8; MAX_MODE_LF_DELTAS]; MAX_REF_FRAMES];

            if lvl_seg == 0 {
                lvl_lookup = Default::default()
            } else {
                // 8.8.1 Loop filter frame init process
                if Self::seg_feature_active(hdr, segment_id, SEG_LVL_ALT_L as u8) {
                    if seg.abs_or_delta_update() {
                        lvl_seg =
                            i32::from(seg.feature_data()[usize::from(segment_id)][SEG_LVL_ALT_L]);
                    } else {
                        lvl_seg +=
                            i32::from(seg.feature_data()[usize::from(segment_id)][SEG_LVL_ALT_L]);
                    }

                    lvl_seg = Self::clamp(lvl_seg, 0, MAX_LOOP_FILTER as i32);
                }

                if !lf.delta_enabled() {
                    lvl_lookup = [[u8::try_from(lvl_seg)?; MAX_MODE_LF_DELTAS]; MAX_REF_FRAMES]
                } else {
                    let intra_delta = i32::from(lf.ref_deltas()[INTRA_FRAME]);
                    let mut intra_lvl = lvl_seg + (intra_delta << n_shift);

                    lvl_lookup = segmentation[usize::from(segment_id)].lvl_lookup;
                    lvl_lookup[INTRA_FRAME][0] =
                        u8::try_from(Self::clamp(intra_lvl, 0, MAX_LOOP_FILTER as i32))?;

                    // Note, this array has the [0] element unspecified/unused in
                    // VP9. Confusing, but we do start to index from 1.
                    #[allow(clippy::needless_range_loop)]
                    for ref_ in LAST_FRAME..MAX_REF_FRAMES {
                        for mode in 0..MAX_MODE_LF_DELTAS {
                            let ref_delta = i32::from(lf.ref_deltas()[ref_]);
                            let mode_delta = i32::from(lf.mode_deltas()[mode]);

                            intra_lvl = lvl_seg + (ref_delta << n_shift) + (mode_delta << n_shift);

                            lvl_lookup[ref_][mode] =
                                u8::try_from(Self::clamp(intra_lvl, 0, MAX_LOOP_FILTER as i32))?;
                        }
                    }
                }
            }

            segmentation[usize::from(segment_id)] = Segmentation {
                lvl_lookup,
                luma_ac_quant_scale,
                luma_dc_quant_scale,
                chroma_ac_quant_scale,
                chroma_dc_quant_scale,
                reference_frame_enabled: seg.feature_enabled()[usize::from(segment_id)]
                    [SEG_LVL_REF_FRAME],
                reference_frame: seg.feature_data()[usize::from(segment_id)][SEG_LVL_REF_FRAME],
                reference_skip_enabled: seg.feature_enabled()[usize::from(segment_id)]
                    [SEG_LVL_SKIP],
            }
        }

        Ok(())
    }

    fn build_pic_param(
        hdr: &Header,
        reference_frames: &[Option<AssociatedHandle>; NUM_REF_FRAMES],
    ) -> Result<libva::BufferType> {
        let reference_frames: [u32; 8] = reference_frames
            .iter()
            .map(|h| {
                if let Some(h) = h {
                    Self::surface_id(&h.picture())
                } else {
                    libva::constants::VA_INVALID_SURFACE
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let pic_fields = libva::VP9PicFields::new(
            hdr.subsampling_x() as u32,
            hdr.subsampling_y() as u32,
            hdr.frame_type() as u32,
            hdr.show_frame() as u32,
            hdr.error_resilient_mode() as u32,
            hdr.intra_only() as u32,
            hdr.allow_high_precision_mv() as u32,
            hdr.interpolation_filter() as u32,
            hdr.frame_parallel_decoding_mode() as u32,
            hdr.reset_frame_context() as u32,
            hdr.refresh_frame_context() as u32,
            hdr.frame_context_idx() as u32,
            hdr.seg().enabled() as u32,
            hdr.seg().temporal_update() as u32,
            hdr.seg().update_map() as u32,
            hdr.ref_frame_idx()[LAST_FRAME - 1] as u32,
            hdr.ref_frame_sign_bias()[LAST_FRAME] as u32,
            hdr.ref_frame_idx()[GOLDEN_FRAME - 1] as u32,
            hdr.ref_frame_sign_bias()[GOLDEN_FRAME] as u32,
            hdr.ref_frame_idx()[ALTREF_FRAME - 1] as u32,
            hdr.ref_frame_sign_bias()[ALTREF_FRAME] as u32,
            hdr.lossless() as u32,
        );

        let lf = hdr.lf();
        let seg = hdr.seg();

        let seg_pred_prob = if seg.temporal_update() {
            seg.pred_probs()
        } else {
            [0xff, 0xff, 0xff]
        };

        let pic_param = libva::PictureParameterBufferVP9::new(
            hdr.width().try_into().unwrap(),
            hdr.height().try_into().unwrap(),
            reference_frames,
            &pic_fields,
            lf.level(),
            lf.sharpness(),
            hdr.tile_rows_log2(),
            hdr.tile_cols_log2(),
            hdr.uncompressed_header_size_in_bytes().try_into().unwrap(),
            hdr.header_size_in_bytes(),
            seg.tree_probs(),
            seg_pred_prob,
            hdr.profile() as u8,
            hdr.bit_depth() as u8,
        );

        Ok(libva::BufferType::PictureParameter(
            libva::PictureParameter::VP9(pic_param),
        ))
    }

    fn build_slice_param(
        hdr: &Header,
        seg: &mut [Segmentation; MAX_SEGMENTS],
        slice_size: usize,
    ) -> Result<libva::BufferType> {
        Self::update_segmentation(hdr, seg)?;

        let seg_params: std::result::Result<[SegmentParameterVP9; MAX_SEGMENTS], _> = seg
            .iter()
            .map(|s| {
                let seg_flags = libva::VP9SegmentFlags::new(
                    s.reference_frame_enabled as u16,
                    s.reference_frame as u16,
                    s.reference_skip_enabled as u16,
                );

                libva::SegmentParameterVP9::new(
                    &seg_flags,
                    s.lvl_lookup,
                    s.luma_ac_quant_scale,
                    s.luma_dc_quant_scale,
                    s.chroma_ac_quant_scale,
                    s.chroma_dc_quant_scale,
                )
            })
            .collect::<Vec<_>>()
            .try_into();

        let seg_params = match seg_params {
            Ok(seg_params) => seg_params,

            // Impossible, this is just a detour to collect into a fixed-size
            // array whose size is the same size of the `seg` argument.
            Err(_) => panic!("Invalid segment parameters"),
        };

        Ok(libva::BufferType::SliceParameter(
            libva::SliceParameter::VP9(libva::SliceParameterBufferVP9::new(
                slice_size as u32,
                0,
                libva::constants::VA_SLICE_DATA_FLAG_ALL,
                seg_params,
            )),
        ))
    }

    #[cfg(test)]
    fn save_params(
        &mut self,
        pic_param: BufferType,
        slice_param: BufferType,
        slice_data: BufferType,
    ) {
        let test_params = TestParams {
            pic_param,
            slice_param,
            slice_data,
        };

        self.test_params.push(test_params);
    }

    fn build_va_decoded_handle(
        &self,
        picture: &ContainedPicture<GenericBackendHandle>,
    ) -> Result<AssociatedHandle> {
        Ok(VADecodedHandle::new(
            Rc::clone(picture),
            self.metadata_state.coded_resolution()?,
            self.metadata_state.surface_pool()?,
        ))
    }
}

impl StatelessDecoderBackend for Backend {
    type Handle = VADecodedHandle<Vp9Picture<GenericBackendHandle>>;

    fn new_sequence(&mut self, header: &Header) -> StatelessBackendResult<()> {
        let open = self
            .open(header, None)
            .map_err(|e| StatelessBackendError::Other(anyhow!(e)));

        if open.is_ok() {
            self.negotiation_status = NegotiationStatus::Possible(Box::new(header.clone()))
        }

        open
    }

    fn submit_picture(
        &mut self,
        picture: Vp9Picture<AsBackendHandle<Self::Handle>>,
        reference_frames: &[Option<Self::Handle>; NUM_REF_FRAMES],
        bitstream: &dyn AsRef<[u8]>,
        timestamp: u64,
        block: bool,
    ) -> StatelessBackendResult<Self::Handle> {
        if !matches!(self.negotiation_status, NegotiationStatus::Negotiated) {
            self.negotiation_status = NegotiationStatus::Negotiated;
        }

        let context = self.metadata_state.context()?;

        let pic_param =
            context.create_buffer(Backend::build_pic_param(&picture.data, reference_frames)?)?;

        #[cfg(test)]
        {
            let mut seg = self.segmentation.clone();
            self.save_params(
                Backend::build_pic_param(&picture.data, reference_frames)?,
                Backend::build_slice_param(&picture.data, &mut seg, bitstream.as_ref().len())?,
                libva::BufferType::SliceData(Vec::from(bitstream.as_ref())),
            );
        }

        let slice_param = context.create_buffer(Backend::build_slice_param(
            &picture.data,
            &mut self.segmentation,
            bitstream.as_ref().len(),
        )?)?;

        let slice_data =
            context.create_buffer(libva::BufferType::SliceData(Vec::from(bitstream.as_ref())))?;

        let context = self.metadata_state.context()?;

        let surface = self
            .metadata_state
            .get_surface()?
            .ok_or(StatelessBackendError::OutOfResources)?;

        let surface_id = surface.id();

        let mut va_picture = VaPicture::new(timestamp, Rc::clone(&context), surface);

        // Add buffers with the parsed data.
        va_picture.add_buffer(pic_param);
        va_picture.add_buffer(slice_param);
        va_picture.add_buffer(slice_data);

        let va_picture = va_picture.begin()?.render()?.end()?;

        let picture = Rc::new(RefCell::new(picture));

        if block {
            let va_picture = va_picture.sync()?;

            let map_format = self.metadata_state.map_format()?;

            let backend_handle = GenericBackendHandle::new_ready(
                va_picture,
                Rc::clone(map_format),
                self.metadata_state.display_resolution()?,
            );

            picture.borrow_mut().backend_handle = Some(backend_handle);
        } else {
            // Append to our queue of pending jobs
            let pending_job = PendingJob {
                va_picture,
                vp9_picture: Rc::clone(&picture),
            };

            self.pending_jobs.push_back(pending_job);

            picture.borrow_mut().backend_handle =
                Some(GenericBackendHandle::new_pending(surface_id));
        }

        self.build_va_decoded_handle(&picture)
            .map_err(|e| StatelessBackendError::Other(anyhow!(e)))
    }

    fn poll(
        &mut self,
        blocking_mode: super::BlockingMode,
    ) -> StatelessBackendResult<VecDeque<Self::Handle>> {
        let mut completed = VecDeque::new();
        let candidates = self.pending_jobs.drain(..).collect::<VecDeque<_>>();

        for job in candidates {
            if matches!(blocking_mode, BlockingMode::NonBlocking) {
                let status = job.va_picture.query_status()?;
                if status != libva::VASurfaceStatus::VASurfaceReady {
                    self.pending_jobs.push_back(job);
                    continue;
                }
            }

            let current_picture = job.va_picture.sync()?;

            let map_format = self.metadata_state.map_format()?;

            let backend_handle = GenericBackendHandle::new_ready(
                current_picture,
                Rc::clone(map_format),
                self.metadata_state.display_resolution()?,
            );

            job.vp9_picture.borrow_mut().backend_handle = Some(backend_handle);

            completed.push_back(job.vp9_picture);
        }

        let completed = completed.into_iter().map(|picture| {
            self.build_va_decoded_handle(&picture)
                .map_err(|e| StatelessBackendError::Other(anyhow!(e)))
        });

        completed.collect::<Result<VecDeque<_>, StatelessBackendError>>()
    }

    fn handle_is_ready(&self, handle: &Self::Handle) -> bool {
        match &handle.picture().backend_handle {
            Some(backend_handle) => backend_handle.is_ready(),
            None => true,
        }
    }

    fn block_on_handle(&mut self, handle: &Self::Handle) -> StatelessBackendResult<()> {
        for i in 0..self.pending_jobs.len() {
            // Remove from the queue in order.
            let job = &self.pending_jobs[i];

            if Vp9Picture::same(&job.vp9_picture, handle.picture_container()) {
                let job = self.pending_jobs.remove(i).unwrap();

                let current_picture = job.va_picture.sync()?;

                let map_format = self.metadata_state.map_format()?;

                let backend_handle = GenericBackendHandle::new_ready(
                    current_picture,
                    Rc::clone(map_format),
                    self.metadata_state.display_resolution()?,
                );

                job.vp9_picture.borrow_mut().backend_handle = Some(backend_handle);

                return Ok(());
            }
        }

        Err(StatelessBackendError::Other(anyhow!(
            "Asked to block on a pending job that doesn't exist"
        )))
    }

    #[cfg(test)]
    fn get_test_params(&self) -> &dyn std::any::Any {
        &self.test_params
    }
}

impl VideoDecoderBackend for Backend {
    fn coded_resolution(&self) -> Option<Resolution> {
        self.metadata_state.coded_resolution().ok()
    }

    fn display_resolution(&self) -> Option<Resolution> {
        self.metadata_state.display_resolution().ok()
    }

    fn num_resources_total(&self) -> usize {
        self.num_allocated_surfaces
    }

    fn num_resources_left(&self) -> usize {
        match self.metadata_state.surface_pool() {
            Ok(pool) => pool.num_surfaces_left(),
            Err(_) => 0,
        }
    }

    fn format(&self) -> Option<crate::DecodedFormat> {
        let map_format = self.metadata_state.map_format().ok()?;
        DecodedFormat::try_from(map_format.as_ref()).ok()
    }

    fn supported_formats_for_stream(
        &self,
    ) -> DecoderResult<std::collections::HashSet<crate::DecodedFormat>> {
        let rt_format = self.metadata_state.rt_format()?;
        let image_formats = &self.image_formats;
        let display = self.metadata_state.display();
        let profile = self.metadata_state.profile()?;

        let formats = utils::vaapi::supported_formats_for_rt_format(
            display,
            rt_format,
            profile,
            libva::VAEntrypoint::VAEntrypointVLD,
            image_formats,
        )?;

        Ok(formats.into_iter().map(|f| f.decoded_format).collect())
    }

    fn try_format(&mut self, format: crate::DecodedFormat) -> DecoderResult<()> {
        let header = match &self.negotiation_status {
            NegotiationStatus::Possible(header) => header.clone(),
            _ => {
                return Err(DecoderError::StatelessBackendError(
                    StatelessBackendError::NegotiationFailed(anyhow!(
                        "Negotiation is not possible at this stage {:?}",
                        self.negotiation_status
                    )),
                ))
            }
        };

        let supported_formats_for_stream = self.supported_formats_for_stream()?;

        if supported_formats_for_stream.contains(&format) {
            let map_format = utils::vaapi::FORMAT_MAP
                .iter()
                .find(|&map| map.decoded_format == format)
                .unwrap();

            self.open(&header, Some(map_format))?;

            Ok(())
        } else {
            Err(DecoderError::StatelessBackendError(
                StatelessBackendError::NegotiationFailed(anyhow!(
                    "Format {:?} is unsupported.",
                    format
                )),
            ))
        }
    }
}

impl Decoder<VADecodedHandle<Vp9Picture<GenericBackendHandle>>> {
    // Creates a new instance of the decoder using the VAAPI backend.
    pub fn new_vaapi(display: Rc<Display>, blocking_mode: BlockingMode) -> Result<Self> {
        Self::new(Box::new(Backend::new(display)?), blocking_mode)
    }
}

#[cfg(test)]
mod tests {

    use libva::BufferType;
    use libva::Display;
    use libva::PictureParameter;
    use libva::SliceParameter;

    use crate::decoders::vp9::backends::vaapi::AssociatedHandle;
    use crate::decoders::vp9::backends::vaapi::TestParams;
    use crate::decoders::vp9::backends::BlockingMode;
    use crate::decoders::vp9::backends::DecodedHandle;
    use crate::decoders::vp9::backends::StatelessDecoderBackend;
    use crate::decoders::vp9::decoder::tests::process_ready_frames;
    use crate::decoders::vp9::decoder::tests::run_decoding_loop;
    use crate::decoders::vp9::decoder::Decoder;
    use crate::decoders::vp9::parser::NUM_REF_FRAMES;
    use crate::decoders::DynPicture;

    fn get_test_params(
        backend: &dyn StatelessDecoderBackend<Handle = AssociatedHandle>,
    ) -> &Vec<TestParams> {
        backend.get_test_params().downcast_ref::<_>().unwrap()
    }

    fn process_handle(
        handle: &AssociatedHandle,
        dump_yuv: bool,
        expected_crcs: Option<&mut Vec<&str>>,
        frame_num: i32,
    ) {
        let mut picture = handle.picture_mut();
        let mut backend_handle = picture.dyn_mappable_handle_mut();

        let buffer_size = backend_handle.image_size();
        let mut nv12 = vec![0; buffer_size];

        backend_handle.read(&mut nv12).unwrap();

        if dump_yuv {
            std::fs::write(format!("/tmp/frame{}.yuv", frame_num), &nv12).unwrap();
        }

        let frame_crc = crc32fast::hash(&nv12);

        if let Some(expected_crcs) = expected_crcs {
            let frame_crc = format!("{:08x}", frame_crc);
            let contains = expected_crcs.contains(&frame_crc.as_ref());
            if !contains {
                panic!("CRC not found: {:?}, iteration: {:?}", frame_crc, frame_num);
            }
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_25fps_vp9() {
        const TEST_STREAM: &[u8] = include_bytes!("../test_data/test-25fps.vp9");
        const STREAM_CRCS: &str = include_str!("../test_data/test-25fps.vp9.crc");

        const TEST_25_FPS_VP9_STREAM_SLICE_DATA_0: &[u8] =
            include_bytes!("../test_data/test-25fps-vp9-slice-data-0.bin");
        const TEST_25_FPS_VP9_STREAM_SLICE_DATA_1: &[u8] =
            include_bytes!("../test_data/test-25fps-vp9-slice-data-1.bin");
        const TEST_25_FPS_VP9_STREAM_SLICE_DATA_2: &[u8] =
            include_bytes!("../test_data/test-25fps-vp9-slice-data-2.bin");

        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<Vec<_>>();
            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the params used to decode the picture. Useful if we want to
                    // write assertions against any particular value used therein.
                    let params = &get_test_params(decoder.backend())[frame_num as usize];

                    process_handle(handle, false, Some(&mut expected_crcs), frame_num);

                    let pic_param = match params.pic_param {
                        BufferType::PictureParameter(PictureParameter::VP9(ref pic_param)) => {
                            pic_param
                        }
                        _ => panic!(),
                    };

                    let slice_param = match params.slice_param {
                        BufferType::SliceParameter(SliceParameter::VP9(ref slice_param)) => {
                            slice_param
                        }
                        _ => panic!(),
                    };

                    let slice_data = match params.slice_data {
                        BufferType::SliceData(ref data) => data,
                        _ => panic!(),
                    };

                    if frame_num == 0 {
                        assert_eq!(pic_param.inner().frame_width, 320);
                        assert_eq!(pic_param.inner().frame_height, 240);
                        assert_eq!(
                            pic_param.inner().reference_frames,
                            [libva::constants::VA_INVALID_SURFACE; NUM_REF_FRAMES]
                        );

                        // Safe because this bitfield is initialized by the decoder.
                        assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                            libva::VP9PicFields::new(
                                1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            )
                            .inner()
                            .value
                        });

                        assert_eq!(pic_param.inner().filter_level, 9);
                        assert_eq!(pic_param.inner().sharpness_level, 0);
                        assert_eq!(pic_param.inner().log2_tile_rows, 0);
                        assert_eq!(pic_param.inner().log2_tile_columns, 0);
                        assert_eq!(pic_param.inner().frame_header_length_in_bytes, 18);
                        assert_eq!(pic_param.inner().first_partition_size, 120);
                        assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                        assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                        assert_eq!(pic_param.inner().profile, 0);
                        assert_eq!(pic_param.inner().bit_depth, 8);

                        assert_eq!(slice_param.inner().slice_data_size, 10674);
                        assert_eq!(slice_param.inner().slice_data_offset, 0);
                        assert_eq!(
                            slice_param.inner().slice_data_flag,
                            libva::constants::VA_SLICE_DATA_FLAG_ALL
                        );

                        for seg_param in &slice_param.inner().seg_param {
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                            assert_eq!(seg_param.filter_level, [[10, 0], [9, 9], [8, 8], [8, 8]]);
                            assert_eq!(seg_param.luma_ac_quant_scale, 72);
                            assert_eq!(seg_param.luma_dc_quant_scale, 62);
                            assert_eq!(seg_param.chroma_ac_quant_scale, 72);
                            assert_eq!(seg_param.chroma_dc_quant_scale, 62);
                        }

                        assert_eq!(&slice_data[..], TEST_25_FPS_VP9_STREAM_SLICE_DATA_0);
                    } else if frame_num == 1 {
                        assert_eq!(pic_param.inner().frame_width, 320);
                        assert_eq!(pic_param.inner().frame_height, 240);
                        assert_eq!(pic_param.inner().reference_frames, [0; NUM_REF_FRAMES]);
                        // Safe because this bitfield is initialized by the decoder.
                        assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                            libva::VP9PicFields::new(
                                1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 2, 0, 0,
                            )
                            .inner()
                            .value
                        });

                        assert_eq!(pic_param.inner().filter_level, 15);
                        assert_eq!(pic_param.inner().sharpness_level, 0);
                        assert_eq!(pic_param.inner().log2_tile_rows, 0);
                        assert_eq!(pic_param.inner().log2_tile_columns, 0);
                        assert_eq!(pic_param.inner().frame_header_length_in_bytes, 11);
                        assert_eq!(pic_param.inner().first_partition_size, 48);
                        assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                        assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                        assert_eq!(pic_param.inner().profile, 0);
                        assert_eq!(pic_param.inner().bit_depth, 8);

                        assert_eq!(slice_param.inner().slice_data_size, 2390);
                        assert_eq!(slice_param.inner().slice_data_offset, 0);
                        assert_eq!(
                            slice_param.inner().slice_data_flag,
                            libva::constants::VA_SLICE_DATA_FLAG_ALL
                        );

                        for seg_param in &slice_param.inner().seg_param {
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                            assert_eq!(
                                seg_param.filter_level,
                                [[16, 0], [15, 15], [14, 14], [14, 14]]
                            );
                            assert_eq!(seg_param.luma_ac_quant_scale, 136);
                            assert_eq!(seg_param.luma_dc_quant_scale, 111);
                            assert_eq!(seg_param.chroma_ac_quant_scale, 136);
                            assert_eq!(seg_param.chroma_dc_quant_scale, 111);
                        }

                        assert_eq!(&slice_data[..], TEST_25_FPS_VP9_STREAM_SLICE_DATA_1);
                    } else if frame_num == 2 {
                        assert_eq!(pic_param.inner().frame_width, 320);
                        assert_eq!(pic_param.inner().frame_height, 240);
                        assert_eq!(pic_param.inner().reference_frames, [0, 0, 1, 0, 0, 0, 0, 0]);

                        // Safe because this bitfield is initialized by the decoder.
                        assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                            libva::VP9PicFields::new(
                                1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 2, 1, 0,
                            )
                            .inner()
                            .value
                        });

                        assert_eq!(pic_param.inner().filter_level, 36);
                        assert_eq!(pic_param.inner().sharpness_level, 0);
                        assert_eq!(pic_param.inner().log2_tile_rows, 0);
                        assert_eq!(pic_param.inner().log2_tile_columns, 0);
                        assert_eq!(pic_param.inner().frame_header_length_in_bytes, 10);
                        assert_eq!(pic_param.inner().first_partition_size, 9);
                        assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                        assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                        assert_eq!(pic_param.inner().profile, 0);
                        assert_eq!(pic_param.inner().bit_depth, 8);

                        assert_eq!(slice_param.inner().slice_data_size, 108);
                        assert_eq!(slice_param.inner().slice_data_offset, 0);
                        assert_eq!(
                            slice_param.inner().slice_data_flag,
                            libva::constants::VA_SLICE_DATA_FLAG_ALL
                        );

                        for seg_param in &slice_param.inner().seg_param {
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                            assert_eq!(
                                seg_param.filter_level,
                                [[38, 0], [36, 36], [34, 34], [34, 34]]
                            );
                            assert_eq!(seg_param.luma_ac_quant_scale, 864);
                            assert_eq!(seg_param.luma_dc_quant_scale, 489);
                            assert_eq!(seg_param.chroma_ac_quant_scale, 864);
                            assert_eq!(seg_param.chroma_dc_quant_scale, 489);
                        }

                        assert_eq!(&slice_data[..], TEST_25_FPS_VP9_STREAM_SLICE_DATA_2);
                    }

                    frame_num += 1;
                });
            });
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_vp90_2_10_show_existing_frame2_vp9() {
        const TEST_STREAM: &[u8] =
            include_bytes!("../test_data/vp90_2_10_show_existing_frame2.vp9.ivf");
        const STREAM_CRCS: &str =
            include_str!("../test_data/vp90_2_10_show_existing_frame2.vp9.ivf.crc");

        const TEST_VP90_2_10_SHOW_EXISTING_FRAME2_STREAM_SLICE_DATA_0: &[u8] =
            include_bytes!("../test_data/vp90_2_10_show_existing_frame2-vp9-ivf-slice-data-0.bin");
        const TEST_VP90_2_10_SHOW_EXISTING_FRAME2_STREAM_SLICE_DATA_1: &[u8] =
            include_bytes!("../test_data/vp90_2_10_show_existing_frame2-vp9-ivf-slice-data-1.bin");
        const TEST_VP90_2_10_SHOW_EXISTING_FRAME2_STREAM_SLICE_DATA_2: &[u8] =
            include_bytes!("../test_data/vp90_2_10_show_existing_frame2-vp9-ivf-slice-data-2.bin");

        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<Vec<_>>();

            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the params used to decode the picture. Useful if we want to
                    // write assertions against any particular value used therein.
                    // Notice that the VP9 codec can choose to redisplay frames,
                    // in which case, no test parameters are recorded, because
                    // no decode operation is made.
                    let params = get_test_params(decoder.backend()).get(frame_num as usize);

                    process_handle(handle, false, Some(&mut expected_crcs), frame_num);

                    if let Some(params) = params {
                        let pic_param = match params.pic_param {
                            BufferType::PictureParameter(PictureParameter::VP9(ref pic_param)) => {
                                pic_param
                            }
                            _ => panic!(),
                        };

                        let slice_param = match params.slice_param {
                            BufferType::SliceParameter(SliceParameter::VP9(ref slice_param)) => {
                                slice_param
                            }
                            _ => panic!(),
                        };

                        let slice_data = match params.slice_data {
                            BufferType::SliceData(ref data) => data,
                            _ => panic!(),
                        };

                        if frame_num == 0 {
                            assert_eq!(pic_param.inner().frame_width, 352);
                            assert_eq!(pic_param.inner().frame_height, 288);
                            assert_eq!(
                                pic_param.inner().reference_frames,
                                [libva::constants::VA_INVALID_SURFACE; NUM_REF_FRAMES]
                            );
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                                libva::VP9PicFields::new(
                                    1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0,
                                )
                                .inner()
                                .value
                            });

                            assert_eq!(pic_param.inner().filter_level, 36);
                            assert_eq!(pic_param.inner().sharpness_level, 0);
                            assert_eq!(pic_param.inner().log2_tile_rows, 0);
                            assert_eq!(pic_param.inner().log2_tile_columns, 0);
                            assert_eq!(pic_param.inner().frame_header_length_in_bytes, 18);
                            assert_eq!(pic_param.inner().first_partition_size, 106);
                            assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                            assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                            assert_eq!(pic_param.inner().profile, 0);
                            assert_eq!(pic_param.inner().bit_depth, 8);

                            assert_eq!(slice_param.inner().slice_data_size, 4075);
                            assert_eq!(slice_param.inner().slice_data_offset, 0);
                            assert_eq!(
                                slice_param.inner().slice_data_flag,
                                libva::constants::VA_SLICE_DATA_FLAG_ALL
                            );

                            for seg_param in &slice_param.inner().seg_param {
                                // Safe because this bitfield is initialized by the decoder.
                                assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                                assert_eq!(
                                    seg_param.filter_level,
                                    [[38, 0], [36, 36], [34, 34], [34, 34]]
                                );
                                assert_eq!(seg_param.luma_ac_quant_scale, 593);
                                assert_eq!(seg_param.luma_dc_quant_scale, 369);
                                assert_eq!(seg_param.luma_ac_quant_scale, 593);
                                assert_eq!(seg_param.luma_dc_quant_scale, 369);
                            }

                            assert_eq!(
                                &slice_data[..],
                                TEST_VP90_2_10_SHOW_EXISTING_FRAME2_STREAM_SLICE_DATA_0
                            );
                        } else if frame_num == 1 {
                            assert_eq!(pic_param.inner().frame_width, 352);
                            assert_eq!(pic_param.inner().frame_height, 288);
                            assert_eq!(pic_param.inner().reference_frames, [0; NUM_REF_FRAMES]);
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                                libva::VP9PicFields::new(
                                    1, 1, 1, 0, 0, 0, 1, 4, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 2, 0,
                                    0,
                                )
                                .inner()
                                .value
                            });

                            assert_eq!(pic_param.inner().filter_level, 56);
                            assert_eq!(pic_param.inner().sharpness_level, 0);
                            assert_eq!(pic_param.inner().log2_tile_rows, 0);
                            assert_eq!(pic_param.inner().log2_tile_columns, 0);
                            assert_eq!(pic_param.inner().frame_header_length_in_bytes, 10);
                            assert_eq!(pic_param.inner().first_partition_size, 68);
                            assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                            assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                            assert_eq!(pic_param.inner().profile, 0);
                            assert_eq!(pic_param.inner().bit_depth, 8);

                            assert_eq!(slice_param.inner().slice_data_size, 2598);
                            assert_eq!(slice_param.inner().slice_data_offset, 0);
                            assert_eq!(
                                slice_param.inner().slice_data_flag,
                                libva::constants::VA_SLICE_DATA_FLAG_ALL
                            );

                            for seg_param in &slice_param.inner().seg_param {
                                // Safe because this bitfield is initialized by the decoder.
                                assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                                assert_eq!(
                                    seg_param.filter_level,
                                    [[58, 0], [56, 56], [54, 54], [54, 54]]
                                );
                                assert_eq!(seg_param.luma_ac_quant_scale, 663);
                                assert_eq!(seg_param.luma_dc_quant_scale, 400);
                                assert_eq!(seg_param.luma_ac_quant_scale, 663);
                                assert_eq!(seg_param.luma_dc_quant_scale, 400);
                            }

                            assert_eq!(
                                &slice_data[..],
                                TEST_VP90_2_10_SHOW_EXISTING_FRAME2_STREAM_SLICE_DATA_1
                            );
                        } else if frame_num == 2 {
                            assert_eq!(pic_param.inner().frame_width, 352);
                            assert_eq!(pic_param.inner().frame_height, 288);
                            assert_eq!(
                                pic_param.inner().reference_frames,
                                [0, 0, 1, 0, 1, 0, 0, 0]
                            );
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                                libva::VP9PicFields::new(
                                    1, 1, 1, 1, 0, 0, 0, 4, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 2, 1,
                                    0,
                                )
                                .inner()
                                .value
                            });

                            assert_eq!(pic_param.inner().filter_level, 42);
                            assert_eq!(pic_param.inner().sharpness_level, 0);
                            assert_eq!(pic_param.inner().log2_tile_rows, 0);
                            assert_eq!(pic_param.inner().log2_tile_columns, 0);
                            assert_eq!(pic_param.inner().frame_header_length_in_bytes, 10);
                            assert_eq!(pic_param.inner().first_partition_size, 18);
                            assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                            assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                            assert_eq!(pic_param.inner().profile, 0);
                            assert_eq!(pic_param.inner().bit_depth, 8);

                            assert_eq!(slice_param.inner().slice_data_size, 447);
                            assert_eq!(slice_param.inner().slice_data_offset, 0);
                            assert_eq!(
                                slice_param.inner().slice_data_flag,
                                libva::constants::VA_SLICE_DATA_FLAG_ALL
                            );

                            for seg_param in &slice_param.inner().seg_param {
                                // Safe because this bitfield is initialized by the decoder.
                                assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                                assert_eq!(
                                    seg_param.filter_level,
                                    [[44, 0], [42, 42], [40, 40], [40, 40]]
                                );
                                assert_eq!(seg_param.luma_ac_quant_scale, 1151);
                                assert_eq!(seg_param.luma_dc_quant_scale, 640);
                                assert_eq!(seg_param.luma_ac_quant_scale, 1151);
                                assert_eq!(seg_param.luma_dc_quant_scale, 640);
                            }

                            assert_eq!(
                                &slice_data[..],
                                TEST_VP90_2_10_SHOW_EXISTING_FRAME2_STREAM_SLICE_DATA_2
                            );
                        }
                    }

                    frame_num += 1;
                });
            });
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_vp90_2_10_show_existing_frame_vp9() {
        // Remuxed from the original matroska source in libvpx using ffmpeg:
        // ffmpeg -i vp90-2-10-show-existing-frame.webm/vp90-2-10-show-existing-frame.webm -c:v copy /tmp/vp90-2-10-show-existing-frame.vp9.ivf
        const TEST_STREAM: &[u8] =
            include_bytes!("../test_data/vp90-2-10-show-existing-frame.vp9.ivf");
        const STREAM_CRCS: &str =
            include_str!("../test_data/vp90-2-10-show-existing-frame.vp9.ivf.crc");

        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<Vec<_>>();

            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the params used to decode the picture. Useful if we want to
                    // write assertions against any particular value used therein.
                    // Notice that the VP9 codec can choose to redisplay frames,
                    // in which case, no test parameters are recorded, because
                    // no decode operation is made.
                    let _params = get_test_params(decoder.backend()).get(frame_num as usize);

                    process_handle(handle, false, Some(&mut expected_crcs), frame_num);

                    frame_num += 1;
                });
            });
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_resolution_change_500frames_vp9() {
        // Remuxed from the original matroska source in libvpx using ffmpeg:
        // ffmpeg -i vp90-2-10-show-existing-frame.webm/vp90-2-10-show-existing-frame.webm -c:v copy /tmp/vp90-2-10-show-existing-frame.vp9.ivf
        // There are some weird padding issues introduced by GStreamer for
        // resolutions that are not multiple of 4, so we're ignoring CRCs for
        // this one.
        const TEST_STREAM: &[u8] =
            include_bytes!("../test_data/resolution_change_500frames-vp9.ivf");
        const STREAM_CRCS: &str =
            include_str!("../test_data/resolution_change_500frames-vp9.ivf.crc");

        const TEST_RESOLUTION_CHANGE_500FRAMES_STREAM_SLICE_DATA_0: &[u8] =
            include_bytes!("../test_data/resolution_change_500frames-vp9-ivf-slice-data-0.bin");
        const TEST_RESOLUTION_CHANGE_500FRAMES_STREAM_SLICE_DATA_1: &[u8] =
            include_bytes!("../test_data/resolution_change_500frames-vp9-ivf-slice-data-1.bin");
        const TEST_RESOLUTION_CHANGE_500FRAMES_STREAM_SLICE_DATA_54: &[u8] =
            include_bytes!("../test_data/resolution_change_500frames-vp9-ivf-slice-data-54.bin");

        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<Vec<_>>();
            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the params used to decode the picture. Useful if we want to
                    // write assertions against any particular value used therein.
                    // Notice that the VP9 codec can choose to redisplay frames,
                    // in which case, no test parameters are recorded, because
                    // no decode operation is made.
                    let params = get_test_params(decoder.backend()).get(frame_num as usize);

                    // GStreamer adds padding otherwise, so we introduce this
                    // check so as to not fail because of that, as some of the
                    // intermediary resolutions in this file fail this
                    // condition.
                    let expected_crcs = if handle.picture().data.width() % 4 == 0 {
                        Some(&mut expected_crcs)
                    } else {
                        None
                    };

                    process_handle(handle, false, expected_crcs, frame_num);

                    if let Some(params) = params {
                        let pic_param = match params.pic_param {
                            BufferType::PictureParameter(PictureParameter::VP9(ref pic_param)) => {
                                pic_param
                            }
                            _ => panic!(),
                        };

                        let slice_param = match params.slice_param {
                            BufferType::SliceParameter(SliceParameter::VP9(ref slice_param)) => {
                                slice_param
                            }
                            _ => panic!(),
                        };

                        let slice_data = match params.slice_data {
                            BufferType::SliceData(ref data) => data,
                            _ => panic!(),
                        };

                        if frame_num == 0 {
                            assert_eq!(pic_param.inner().frame_width, 640);
                            assert_eq!(pic_param.inner().frame_height, 360);
                            assert_eq!(
                                pic_param.inner().reference_frames,
                                [libva::constants::VA_INVALID_SURFACE; NUM_REF_FRAMES]
                            );
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                                libva::VP9PicFields::new(
                                    1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0,
                                )
                                .inner()
                                .value
                            });

                            assert_eq!(pic_param.inner().filter_level, 0);
                            assert_eq!(pic_param.inner().sharpness_level, 0);
                            assert_eq!(pic_param.inner().log2_tile_rows, 0);
                            assert_eq!(pic_param.inner().log2_tile_columns, 1);
                            assert_eq!(pic_param.inner().frame_header_length_in_bytes, 18);
                            assert_eq!(pic_param.inner().first_partition_size, 134);
                            assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                            assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                            assert_eq!(pic_param.inner().profile, 0);
                            assert_eq!(pic_param.inner().bit_depth, 8);

                            assert_eq!(slice_param.inner().slice_data_size, 38676);
                            assert_eq!(slice_param.inner().slice_data_offset, 0);
                            assert_eq!(
                                slice_param.inner().slice_data_flag,
                                libva::constants::VA_SLICE_DATA_FLAG_ALL
                            );

                            for seg_param in &slice_param.inner().seg_param {
                                // Safe because this bitfield is initialized by the decoder.
                                assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                                assert_eq!(
                                    seg_param.filter_level,
                                    [[0, 0], [0, 0], [0, 0], [0, 0]]
                                );
                                assert_eq!(seg_param.luma_ac_quant_scale, 31);
                                assert_eq!(seg_param.luma_dc_quant_scale, 27);
                                assert_eq!(seg_param.luma_ac_quant_scale, 31);
                                assert_eq!(seg_param.luma_dc_quant_scale, 27);
                            }

                            assert_eq!(
                                &slice_data[..],
                                TEST_RESOLUTION_CHANGE_500FRAMES_STREAM_SLICE_DATA_0
                            );
                        } else if frame_num == 1 {
                            assert_eq!(pic_param.inner().frame_width, 640);
                            assert_eq!(pic_param.inner().frame_height, 360);
                            assert_eq!(pic_param.inner().reference_frames, [0; NUM_REF_FRAMES]);
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                                libva::VP9PicFields::new(
                                    1, 1, 1, 0, 0, 0, 1, 4, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 2, 0,
                                    0,
                                )
                                .inner()
                                .value
                            });

                            assert_eq!(pic_param.inner().filter_level, 3);
                            assert_eq!(pic_param.inner().sharpness_level, 0);
                            assert_eq!(pic_param.inner().log2_tile_rows, 0);
                            assert_eq!(pic_param.inner().log2_tile_columns, 1);
                            assert_eq!(pic_param.inner().frame_header_length_in_bytes, 10);
                            assert_eq!(pic_param.inner().first_partition_size, 74);
                            assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                            assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                            assert_eq!(pic_param.inner().profile, 0);
                            assert_eq!(pic_param.inner().bit_depth, 8);

                            assert_eq!(slice_param.inner().slice_data_size, 3866);
                            assert_eq!(slice_param.inner().slice_data_offset, 0);
                            assert_eq!(
                                slice_param.inner().slice_data_flag,
                                libva::constants::VA_SLICE_DATA_FLAG_ALL
                            );

                            for seg_param in &slice_param.inner().seg_param {
                                // Safe because this bitfield is initialized by the decoder.
                                assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                                assert_eq!(
                                    seg_param.filter_level,
                                    [[4, 0], [3, 3], [2, 2], [2, 2]]
                                );
                                assert_eq!(seg_param.luma_ac_quant_scale, 58);
                                assert_eq!(seg_param.luma_dc_quant_scale, 50);
                                assert_eq!(seg_param.luma_ac_quant_scale, 58);
                                assert_eq!(seg_param.luma_dc_quant_scale, 50);
                            }

                            assert_eq!(
                                &slice_data[..],
                                TEST_RESOLUTION_CHANGE_500FRAMES_STREAM_SLICE_DATA_1
                            );
                        } else if frame_num == 54 {
                            assert_eq!(pic_param.inner().frame_width, 426);
                            assert_eq!(pic_param.inner().frame_height, 240);
                            // GStreamer flushes before new_sequence, TODO:
                            // check whether this impacts the fluster score.
                            // assert_eq!(
                            //     pic_param.inner().reference_frames,
                            //     [libva::constants::VA_INVALID_SURFACE; NUM_REF_FRAMES]
                            // );
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                                libva::VP9PicFields::new(
                                    1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0,
                                )
                                .inner()
                                .value
                            });

                            assert_eq!(pic_param.inner().filter_level, 0);
                            assert_eq!(pic_param.inner().sharpness_level, 0);
                            assert_eq!(pic_param.inner().log2_tile_rows, 0);
                            assert_eq!(pic_param.inner().log2_tile_columns, 0);
                            assert_eq!(pic_param.inner().frame_header_length_in_bytes, 18);
                            assert_eq!(pic_param.inner().first_partition_size, 75);
                            assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                            assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                            assert_eq!(pic_param.inner().profile, 0);
                            assert_eq!(pic_param.inner().bit_depth, 8);

                            assert_eq!(slice_param.inner().slice_data_size, 19004);
                            assert_eq!(slice_param.inner().slice_data_offset, 0);
                            assert_eq!(
                                slice_param.inner().slice_data_flag,
                                libva::constants::VA_SLICE_DATA_FLAG_ALL
                            );

                            for seg_param in &slice_param.inner().seg_param {
                                // Safe because this bitfield is initialized by the decoder.
                                assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                                assert_eq!(
                                    seg_param.filter_level,
                                    [[0, 0], [0, 0], [0, 0], [0, 0]]
                                );
                                assert_eq!(seg_param.luma_ac_quant_scale, 33);
                                assert_eq!(seg_param.luma_dc_quant_scale, 29);
                                assert_eq!(seg_param.luma_ac_quant_scale, 33);
                                assert_eq!(seg_param.luma_dc_quant_scale, 29);
                            }

                            assert_eq!(
                                &slice_data[..],
                                TEST_RESOLUTION_CHANGE_500FRAMES_STREAM_SLICE_DATA_54
                            );
                        }
                    }

                    frame_num += 1;
                });
            });
        }
    }
}
