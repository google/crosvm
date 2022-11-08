// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Result;
use libva::BufferType;
use libva::IQMatrix;
use libva::IQMatrixBufferVP8;
use libva::Picture as VaPicture;
use libva::PictureEnd;
use libva::ProbabilityDataBufferVP8;
use libva::UsageHint;

use crate::decoders::h264::backends::stateless::Result as StatelessBackendResult;
use crate::decoders::vp8::backends::stateless::AsBackendHandle;
use crate::decoders::vp8::backends::stateless::BlockingMode;
use crate::decoders::vp8::backends::stateless::ContainedPicture;
use crate::decoders::vp8::backends::stateless::DecodedHandle;
use crate::decoders::vp8::backends::stateless::StatelessDecoderBackend;
use crate::decoders::vp8::backends::stateless::Vp8Picture;
use crate::decoders::vp8::parser::Header;
use crate::decoders::vp8::parser::MbLfAdjustments;
use crate::decoders::vp8::parser::Parser;
use crate::decoders::vp8::parser::Segmentation;
use crate::decoders::Error as DecoderError;
use crate::decoders::Result as DecoderResult;
use crate::decoders::StatelessBackendError;
use crate::decoders::VideoDecoderBackend;
use crate::utils;
use crate::utils::vaapi::DecodedHandle as VADecodedHandle;
use crate::utils::vaapi::FormatMap;
use crate::utils::vaapi::GenericBackendHandle;
use crate::utils::vaapi::StreamMetadataState;
use crate::utils::vaapi::SurfacePoolHandle;
use crate::DecodedFormat;
use crate::Resolution;

/// Resolves to the type used as Handle by the backend.
type AssociatedHandle = <Backend as StatelessDecoderBackend>::Handle;

/// The number of surfaces to allocate for this codec. Same as GStreamer's vavp8dec.
const NUM_SURFACES: usize = 7;

/// Keeps track of where the backend is in the negotiation process.
#[derive(Clone, Debug)]
enum NegotiationStatus {
    NonNegotiated,
    Possible { header: Box<Header> },
    Negotiated,
}

impl Default for NegotiationStatus {
    fn default() -> Self {
        NegotiationStatus::NonNegotiated
    }
}

#[cfg(test)]
struct TestParams {
    pic_param: BufferType,
    slice_param: BufferType,
    slice_data: BufferType,
    iq_matrix: BufferType,
    probability_table: BufferType,
}

/// A type that keeps track of a pending decoding operation. The backend can
/// complete the job by either querying its status with VA-API or by blocking on
/// it at some point in the future.
///
/// Once the backend is sure that the operation went through, it can assign the
/// handle to `h264_picture` and dequeue this object from the pending queue.
struct PendingJob<BackendHandle> {
    /// A picture that was already sent to VA-API. It is unclear whether it has
    /// been decoded yet because we have been asked not to block on it.
    va_picture: VaPicture<PictureEnd>,
    /// A handle to the picture passed in by the H264 decoder. It has no handle
    /// backing it yet, as we cannot be sure that the decoding operation went
    /// through.
    vp8_picture: ContainedPicture<BackendHandle>,
}

pub struct Backend {
    /// The metadata state. Updated whenever the decoder reads new data from the stream.
    metadata_state: StreamMetadataState,
    /// The FIFO for all pending pictures, in the order they were submitted.
    pending_jobs: VecDeque<PendingJob<GenericBackendHandle>>,
    /// The image formats we can decode into.
    image_formats: Rc<Vec<libva::VAImageFormat>>,
    /// The number of allocated surfaces.
    num_allocated_surfaces: usize,
    /// The negotiation status
    negotiation_status: NegotiationStatus,

    #[cfg(test)]
    /// Test params. Saves the metadata sent to VA-API for the purposes of
    /// testing.
    test_params: Vec<TestParams>,
}

impl Backend {
    /// Create a new codec backend for VP8.
    pub fn new(display: Rc<libva::Display>) -> Result<Self> {
        let image_formats = Rc::new(display.query_image_formats()?);

        Ok(Self {
            metadata_state: StreamMetadataState::Unparsed { display },
            image_formats,
            pending_jobs: Default::default(),
            num_allocated_surfaces: Default::default(),
            negotiation_status: Default::default(),

            #[cfg(test)]
            test_params: Default::default(),
        })
    }

    /// A clamp such that min <= x <= max
    fn clamp<T: PartialOrd>(x: T, low: T, high: T) -> T {
        if x > high {
            high
        } else if x < low {
            low
        } else {
            x
        }
    }

    /// Initialize the codec state by reading some metadata from the current
    /// frame.
    fn open(&mut self, frame_hdr: &Header, format_map: Option<&FormatMap>) -> Result<()> {
        let display = self.metadata_state.display();

        let va_profile = libva::VAProfile::VAProfileVP8Version0_3;
        let rt_format = libva::constants::VA_RT_FORMAT_YUV420;

        let frame_w = u32::from(frame_hdr.width());
        let frame_h = u32::from(frame_hdr.height());

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
    fn surface_id(picture: &Vp8Picture<GenericBackendHandle>) -> libva::VASurfaceID {
        picture.backend_handle.as_ref().unwrap().surface_id()
    }

    fn build_iq_matrix(frame_hdr: &Header, parser: &Parser) -> Result<libva::BufferType> {
        let mut quantization_index: [[u16; 6]; 4] = Default::default();
        let seg = parser.segmentation();

        for (i, quantization_index) in quantization_index.iter_mut().enumerate() {
            let mut qi_base: i16;

            if seg.segmentation_enabled {
                qi_base = i16::from(seg.quantizer_update_value[i]);
                if !seg.segment_feature_mode {
                    qi_base += i16::from(frame_hdr.quant_indices().y_ac_qi);
                }
            } else {
                qi_base = i16::from(frame_hdr.quant_indices().y_ac_qi);
            }

            let mut qi = qi_base;
            quantization_index[0] = u16::try_from(Backend::clamp(qi, 0, 127))?;
            qi = qi_base + i16::from(frame_hdr.quant_indices().y_dc_delta);
            quantization_index[1] = u16::try_from(Backend::clamp(qi, 0, 127))?;
            qi = qi_base + i16::from(frame_hdr.quant_indices().y2_dc_delta);
            quantization_index[2] = u16::try_from(Backend::clamp(qi, 0, 127))?;
            qi = qi_base + i16::from(frame_hdr.quant_indices().y2_ac_delta);
            quantization_index[3] = u16::try_from(Backend::clamp(qi, 0, 127))?;
            qi = qi_base + i16::from(frame_hdr.quant_indices().uv_dc_delta);
            quantization_index[4] = u16::try_from(Backend::clamp(qi, 0, 127))?;
            qi = qi_base + i16::from(frame_hdr.quant_indices().uv_ac_delta);
            quantization_index[5] = u16::try_from(Backend::clamp(qi, 0, 127))?;
        }

        Ok(BufferType::IQMatrix(IQMatrix::VP8(IQMatrixBufferVP8::new(
            quantization_index,
        ))))
    }

    fn build_probability_table(frame_hdr: &Header) -> libva::BufferType {
        BufferType::Probability(ProbabilityDataBufferVP8::new(frame_hdr.coeff_prob()))
    }

    fn build_pic_param(
        frame_hdr: &Header,
        resolution: &Resolution,
        seg: &Segmentation,
        adj: &MbLfAdjustments,
        last: Option<&AssociatedHandle>,
        golden: Option<&AssociatedHandle>,
        alt: Option<&AssociatedHandle>,
    ) -> Result<libva::BufferType> {
        let mut loop_filter_level: [u8; 4] = Default::default();
        let mut loop_filter_deltas_ref_frame: [i8; 4] = Default::default();
        let mut loop_filter_deltas_mode: [i8; 4] = Default::default();

        for i in 0..4 {
            let mut level;
            if seg.segmentation_enabled {
                level = seg.lf_update_value[i];
                if !seg.segment_feature_mode {
                    level += i8::try_from(frame_hdr.loop_filter_level())?;
                }
            } else {
                level = i8::try_from(frame_hdr.loop_filter_level())?;
            }

            loop_filter_level[i] = Backend::clamp(u8::try_from(level)?, 0, 63);
            loop_filter_deltas_ref_frame[i] = adj.ref_frame_delta[i];
            loop_filter_deltas_mode[i] = adj.mb_mode_delta[i];
        }

        let last_surface = if let Some(last_ref) = last {
            Self::surface_id(&last_ref.picture())
        } else {
            libva::constants::VA_INVALID_SURFACE
        };

        let golden_surface = if let Some(golden_ref) = golden {
            Self::surface_id(&golden_ref.picture())
        } else {
            libva::constants::VA_INVALID_SURFACE
        };

        let alt_surface = if let Some(alt_ref) = alt {
            Self::surface_id(&alt_ref.picture())
        } else {
            libva::constants::VA_INVALID_SURFACE
        };

        let pic_fields = libva::VP8PicFields::new(
            u32::from(!frame_hdr.key_frame()),
            u32::from(frame_hdr.version()),
            u32::from(seg.segmentation_enabled),
            u32::from(seg.update_mb_segmentation_map),
            u32::from(seg.update_segment_feature_data),
            u32::from(frame_hdr.filter_type()),
            u32::from(frame_hdr.sharpness_level()),
            u32::from(adj.loop_filter_adj_enable),
            u32::from(adj.mode_ref_lf_delta_update),
            u32::from(frame_hdr.sign_bias_golden()),
            u32::from(frame_hdr.sign_bias_alternate()),
            u32::from(frame_hdr.mb_no_coeff_skip()),
            u32::from(frame_hdr.loop_filter_level() == 0),
        );

        let bool_coder_ctx = libva::BoolCoderContextVPX::new(
            u8::try_from(frame_hdr.bd_range())?,
            u8::try_from(frame_hdr.bd_value())?,
            u8::try_from(frame_hdr.bd_count())?,
        );

        let pic_param = libva::PictureParameterBufferVP8::new(
            resolution.width,
            resolution.height,
            last_surface,
            golden_surface,
            alt_surface,
            &pic_fields,
            seg.segment_prob,
            loop_filter_level,
            loop_filter_deltas_ref_frame,
            loop_filter_deltas_mode,
            frame_hdr.prob_skip_false(),
            frame_hdr.prob_intra(),
            frame_hdr.prob_last(),
            frame_hdr.prob_golden(),
            frame_hdr.mode_probs().intra_16x16_prob,
            frame_hdr.mode_probs().intra_chroma_prob,
            frame_hdr.mv_prob(),
            &bool_coder_ctx,
        );

        Ok(libva::BufferType::PictureParameter(
            libva::PictureParameter::VP8(pic_param),
        ))
    }

    fn build_slice_param(frame_hdr: &Header, slice_size: usize) -> Result<libva::BufferType> {
        let mut partition_size: [u32; 9] = Default::default();
        let num_of_partitions = (1 << frame_hdr.log2_nbr_of_dct_partitions()) + 1;

        partition_size[0] = frame_hdr.first_part_size() - ((frame_hdr.header_size() + 7) >> 3);

        partition_size[1..num_of_partitions]
            .clone_from_slice(&frame_hdr.partition_size()[..(num_of_partitions - 1)]);

        Ok(libva::BufferType::SliceParameter(
            libva::SliceParameter::VP8(libva::SliceParameterBufferVP8::new(
                u32::try_from(slice_size)?,
                u32::from(frame_hdr.data_chunk_size()),
                0,
                frame_hdr.header_size(),
                u8::try_from(num_of_partitions)?,
                partition_size,
            )),
        ))
    }

    #[cfg(test)]
    fn save_params(
        &mut self,
        pic_param: BufferType,
        slice_param: BufferType,
        slice_data: BufferType,
        iq_matrix: BufferType,
        probability_table: BufferType,
    ) {
        let test_params = TestParams {
            pic_param,
            slice_param,
            slice_data,
            iq_matrix,
            probability_table,
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
    type Handle = VADecodedHandle<Vp8Picture<GenericBackendHandle>>;

    fn new_sequence(&mut self, header: &Header) -> StatelessBackendResult<()> {
        let open = self
            .open(header, None)
            .map_err(|e| StatelessBackendError::Other(anyhow!(e)));

        if open.is_ok() {
            self.negotiation_status = NegotiationStatus::Possible {
                header: Box::new(header.clone()),
            };
        }

        open
    }

    fn submit_picture(
        &mut self,
        picture: Vp8Picture<AsBackendHandle<Self::Handle>>,
        last_ref: Option<&Self::Handle>,
        golden_ref: Option<&Self::Handle>,
        alt_ref: Option<&Self::Handle>,
        bitstream: &dyn AsRef<[u8]>,
        parser: &Parser,
        timestamp: u64,
        block: bool,
    ) -> StatelessBackendResult<Self::Handle> {
        if !matches!(self.negotiation_status, NegotiationStatus::Negotiated) {
            self.negotiation_status = NegotiationStatus::Negotiated;
        }

        let context = self.metadata_state.context()?;

        let iq_buffer = context.create_buffer(Backend::build_iq_matrix(&picture.data, parser)?)?;

        let probs = context.create_buffer(Backend::build_probability_table(&picture.data))?;

        let coded_resolution = self.metadata_state.coded_resolution()?;

        let pic_param = context.create_buffer(Backend::build_pic_param(
            &picture.data,
            &coded_resolution,
            parser.segmentation(),
            parser.mb_lf_adjust(),
            last_ref,
            golden_ref,
            alt_ref,
        )?)?;

        let slice_param = context.create_buffer(Backend::build_slice_param(
            &picture.data,
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
        va_picture.add_buffer(iq_buffer);
        va_picture.add_buffer(probs);
        va_picture.add_buffer(pic_param);
        va_picture.add_buffer(slice_param);
        va_picture.add_buffer(slice_data);

        let va_picture = va_picture.begin()?.render()?.end()?;

        #[cfg(test)]
        self.save_params(
            Backend::build_pic_param(
                &picture.data,
                &coded_resolution,
                parser.segmentation(),
                parser.mb_lf_adjust(),
                last_ref,
                golden_ref,
                alt_ref,
            )?,
            Backend::build_slice_param(&picture.data, bitstream.as_ref().len())?,
            libva::BufferType::SliceData(Vec::from(bitstream.as_ref())),
            Backend::build_iq_matrix(&picture.data, parser)?,
            Backend::build_probability_table(&picture.data),
        );

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
                vp8_picture: Rc::clone(&picture),
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

            job.vp8_picture.borrow_mut().backend_handle = Some(backend_handle);

            completed.push_back(job.vp8_picture);
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

            if Vp8Picture::same(&job.vp8_picture, handle.picture_container()) {
                let job = self.pending_jobs.remove(i).unwrap();

                let current_picture = job.va_picture.sync()?;

                let map_format = self.metadata_state.map_format()?;

                let backend_handle = GenericBackendHandle::new_ready(
                    current_picture,
                    Rc::clone(map_format),
                    self.metadata_state.display_resolution()?,
                );

                job.vp8_picture.borrow_mut().backend_handle = Some(backend_handle);

                return Ok(());
            }
        }

        Err(StatelessBackendError::Other(anyhow!(
            "Asked to block on a pending job that doesn't exist"
        )))
    }

    fn as_video_decoder_backend_mut(&mut self) -> &mut dyn crate::decoders::VideoDecoderBackend {
        self
    }

    fn as_video_decoder_backend(&self) -> &dyn crate::decoders::VideoDecoderBackend {
        self
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
            NegotiationStatus::Possible { header } => header.clone(),
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::rc::Rc;

    use libva::BufferType;
    use libva::Display;
    use libva::IQMatrix;
    use libva::PictureParameter;
    use libva::SliceParameter;

    use crate::decoders::vp8::backends;
    use crate::decoders::vp8::backends::stateless::vaapi::AssociatedHandle;
    use crate::decoders::vp8::backends::stateless::vaapi::Backend;
    use crate::decoders::vp8::backends::stateless::BlockingMode;
    use crate::decoders::vp8::backends::stateless::DecodedHandle;
    use crate::decoders::vp8::backends::stateless::StatelessDecoderBackend;
    use crate::decoders::vp8::decoder::tests::process_ready_frames;
    use crate::decoders::vp8::decoder::tests::run_decoding_loop;
    use crate::decoders::vp8::decoder::Decoder;
    use crate::decoders::DynPicture;

    fn as_vaapi_backend(
        backend: &dyn StatelessDecoderBackend<Handle = AssociatedHandle>,
    ) -> &backends::stateless::vaapi::Backend {
        backend
            .downcast_ref::<backends::stateless::vaapi::Backend>()
            .unwrap()
    }

    fn process_handle(
        handle: &AssociatedHandle,
        dump_yuv: bool,
        expected_crcs: Option<&mut HashSet<&str>>,
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
            let removed = expected_crcs.remove(frame_crc.as_str());
            assert!(
                removed,
                "CRC not found: {:?}, iteration: {:?}",
                frame_crc, frame_num
            );
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_25fps_vp8() {
        const TEST_STREAM: &[u8] = include_bytes!("../../test_data/test-25fps.vp8");
        const STREAM_CRCS: &str = include_str!("../../test_data/test-25fps.vp8.crc");

        const TEST_25_FPS_VP8_STREAM_SLICE_DATA_0: &[u8] =
            include_bytes!("../../test_data/test-25fps-vp8-slice-data-0.bin");
        const TEST_25_FPS_VP8_STREAM_SLICE_DATA_1: &[u8] =
            include_bytes!("../../test_data/test-25fps-vp8-slice-data-1.bin");
        const TEST_25_FPS_VP8_STREAM_SLICE_DATA_2: &[u8] =
            include_bytes!("../../test_data/test-25fps-vp8-slice-data-2.bin");

        const TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_0: &[u8] =
            include_bytes!("../../test_data/test-25fps-vp8-probability-table-0.bin");
        const TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_1: &[u8] =
            include_bytes!("../../test_data/test-25fps-vp8-probability-table-1.bin");
        const TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_2: &[u8] =
            include_bytes!("../../test_data/test-25fps-vp8-probability-table-2.bin");

        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<HashSet<_>>();

            let mut frame_num = 0;
            let display = Rc::new(Display::open().unwrap());
            let backend = Box::new(Backend::new(Rc::clone(&display)).unwrap());

            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the params used to decode the picture. Useful if we want to
                    // write assertions against any particular value used therein.
                    let params =
                        &as_vaapi_backend(decoder.backend()).test_params[frame_num as usize];

                    process_handle(handle, false, Some(&mut expected_crcs), frame_num);

                    let pic_param = match params.pic_param {
                        BufferType::PictureParameter(PictureParameter::VP8(ref pic_param)) => {
                            pic_param
                        }
                        _ => panic!(),
                    };

                    let slice_param = match params.slice_param {
                        BufferType::SliceParameter(SliceParameter::VP8(ref slice_param)) => {
                            slice_param
                        }
                        _ => panic!(),
                    };

                    let slice_data = match params.slice_data {
                        BufferType::SliceData(ref data) => data,
                        _ => panic!(),
                    };

                    let iq_matrix = match params.iq_matrix {
                        BufferType::IQMatrix(IQMatrix::VP8(ref iq_matrix)) => iq_matrix,
                        _ => panic!(),
                    };

                    let probability_table = match params.probability_table {
                        BufferType::Probability(ref probability_table) => probability_table,
                        _ => panic!(),
                    };

                    if frame_num == 0 {
                        assert_eq!(iq_matrix.inner().quantization_index, [[4; 6]; 4]);
                        for i in 0..4 {
                            for j in 0..8 {
                                for k in 0..3 {
                                    for l in 0..11 {
                                        const OFF_I: usize = 8 * 3 * 11;
                                        const OFF_J: usize = 3 * 11;
                                        const OFF_K: usize = 11;
                                        // maybe std::transmute?
                                        assert_eq!(
                                            probability_table.inner().dct_coeff_probs[i][j][k][l],
                                            TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_0
                                                [(i * OFF_I) + (j * OFF_J) + (k * OFF_K) + l]
                                        );
                                    }
                                }
                            }
                        }

                        assert_eq!(pic_param.inner().frame_width, 320);
                        assert_eq!(pic_param.inner().frame_height, 240);
                        assert_eq!(
                            pic_param.inner().last_ref_frame,
                            libva::constants::VA_INVALID_SURFACE
                        );
                        assert_eq!(
                            pic_param.inner().golden_ref_frame,
                            libva::constants::VA_INVALID_SURFACE
                        );
                        assert_eq!(
                            pic_param.inner().alt_ref_frame,
                            libva::constants::VA_INVALID_SURFACE
                        );
                        assert_eq!(
                            pic_param.inner().out_of_loop_frame,
                            libva::constants::VA_INVALID_SURFACE
                        );

                        // Safe because this bitfield is initialized by the decoder.
                        assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                            libva::VP8PicFields::new(0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1)
                                .inner()
                                .value
                        });

                        assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 3]);
                        assert_eq!(pic_param.inner().loop_filter_level, [0; 4]);
                        assert_eq!(
                            pic_param.inner().loop_filter_deltas_ref_frame,
                            [2, 0, -2, -2]
                        );
                        assert_eq!(pic_param.inner().loop_filter_deltas_mode, [4, -2, 2, 4]);
                        assert_eq!(pic_param.inner().prob_skip_false, 0xbe);
                        assert_eq!(pic_param.inner().prob_intra, 0);
                        assert_eq!(pic_param.inner().prob_last, 0);
                        assert_eq!(pic_param.inner().prob_gf, 0);

                        assert_eq!(pic_param.inner().y_mode_probs, [0x91, 0x9c, 0xa3, 0x80]);
                        assert_eq!(pic_param.inner().uv_mode_probs, [0x8e, 0x72, 0xb7]);
                        assert_eq!(
                            pic_param.inner().mv_probs[0],
                            [
                                0xa2, 0x80, 0xe1, 0x92, 0xac, 0x93, 0xd6, 0x27, 0x9c, 0x80, 0x81,
                                0x84, 0x4b, 0x91, 0xb2, 0xce, 0xef, 0xfe, 0xfe
                            ]
                        );
                        assert_eq!(
                            pic_param.inner().mv_probs[1],
                            [
                                0xa4, 0x80, 0xcc, 0xaa, 0x77, 0xeb, 0x8c, 0xe6, 0xe4, 0x80, 0x82,
                                0x82, 0x4a, 0x94, 0xb4, 0xcb, 0xec, 0xfe, 0xfe,
                            ]
                        );

                        assert_eq!(pic_param.inner().bool_coder_ctx.range, 0xfc);
                        assert_eq!(pic_param.inner().bool_coder_ctx.value, 0x39);
                        assert_eq!(pic_param.inner().bool_coder_ctx.count, 0x0);

                        assert_eq!(
                            slice_param.inner(),
                            libva::SliceParameterBufferVP8::new(
                                14788,
                                10,
                                0,
                                3040,
                                2,
                                [926, 13472, 0, 0, 0, 0, 0, 0, 0],
                            )
                            .inner(),
                        );

                        assert_eq!(&slice_data[..], TEST_25_FPS_VP8_STREAM_SLICE_DATA_0);
                    } else if frame_num == 1 {
                        assert_eq!(iq_matrix.inner().quantization_index, [[0x7f; 6]; 4]);
                        for i in 0..4 {
                            for j in 0..8 {
                                for k in 0..3 {
                                    for l in 0..11 {
                                        const OFF_I: usize = 8 * 3 * 11;
                                        const OFF_J: usize = 3 * 11;
                                        const OFF_K: usize = 11;
                                        // maybe std::transmute?
                                        assert_eq!(
                                            probability_table.inner().dct_coeff_probs[i][j][k][l],
                                            TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_1
                                                [(i * OFF_I) + (j * OFF_J) + (k * OFF_K) + l]
                                        );
                                    }
                                }
                            }
                        }
                        assert_eq!(pic_param.inner().frame_width, 320);
                        assert_eq!(pic_param.inner().frame_height, 240);
                        assert_eq!(pic_param.inner().last_ref_frame, 0);
                        assert_eq!(pic_param.inner().golden_ref_frame, 0);
                        assert_eq!(pic_param.inner().alt_ref_frame, 0);
                        assert_eq!(
                            pic_param.inner().out_of_loop_frame,
                            libva::constants::VA_INVALID_SURFACE
                        );

                        // Safe because this bitfield is initialized by the decoder.
                        assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                            libva::VP8PicFields::new(1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0)
                                .inner()
                                .value
                        });

                        assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 3]);
                        assert_eq!(pic_param.inner().loop_filter_level, [44; 4]);
                        assert_eq!(
                            pic_param.inner().loop_filter_deltas_ref_frame,
                            [2, 0, -2, -2]
                        );
                        assert_eq!(pic_param.inner().loop_filter_deltas_mode, [4, -2, 2, 4]);
                        assert_eq!(pic_param.inner().prob_skip_false, 0x11);
                        assert_eq!(pic_param.inner().prob_intra, 0x2a);
                        assert_eq!(pic_param.inner().prob_last, 0xff);
                        assert_eq!(pic_param.inner().prob_gf, 0x80);

                        assert_eq!(pic_param.inner().y_mode_probs, [0x70, 0x56, 0x8c, 0x25]);
                        assert_eq!(pic_param.inner().uv_mode_probs, [0xa2, 0x65, 0xcc]);
                        assert_eq!(
                            pic_param.inner().mv_probs[0],
                            [
                                0xa2, 0x80, 0xe1, 0x92, 0xac, 0x93, 0xd6, 0x27, 0x9c, 0x80, 0x81,
                                0x84, 0x4b, 0x91, 0xb2, 0xce, 0xef, 0xfe, 0xfe,
                            ]
                        );
                        assert_eq!(
                            pic_param.inner().mv_probs[1],
                            [
                                0xa4, 0x80, 0xcc, 0xaa, 0x77, 0xeb, 0x8c, 0xe6, 0xe4, 0x80, 0x82,
                                0x82, 0x4a, 0x94, 0xb4, 0xcb, 0xec, 0xfe, 0xfe,
                            ]
                        );

                        assert_eq!(pic_param.inner().bool_coder_ctx.range, 0xde);
                        assert_eq!(pic_param.inner().bool_coder_ctx.value, 0x39);
                        assert_eq!(pic_param.inner().bool_coder_ctx.count, 0x7);

                        assert_eq!(
                            slice_param.inner(),
                            libva::SliceParameterBufferVP8::new(
                                257,
                                3,
                                0,
                                129,
                                2,
                                [143, 94, 0, 0, 0, 0, 0, 0, 0],
                            )
                            .inner()
                        );

                        assert_eq!(&slice_data[..], TEST_25_FPS_VP8_STREAM_SLICE_DATA_1);
                    } else if frame_num == 2 {
                        assert_eq!(iq_matrix.inner().quantization_index, [[0x7f; 6]; 4]);
                        for i in 0..4 {
                            for j in 0..8 {
                                for k in 0..3 {
                                    for l in 0..11 {
                                        const OFF_I: usize = 8 * 3 * 11;
                                        const OFF_J: usize = 3 * 11;
                                        const OFF_K: usize = 11;
                                        // maybe std::transmute?
                                        assert_eq!(
                                            probability_table.inner().dct_coeff_probs[i][j][k][l],
                                            TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_2
                                                [(i * OFF_I) + (j * OFF_J) + (k * OFF_K) + l]
                                        );
                                    }
                                }
                            }
                        }
                        assert_eq!(pic_param.inner().frame_width, 320);
                        assert_eq!(pic_param.inner().frame_height, 240);
                        assert_eq!(pic_param.inner().last_ref_frame, 1);
                        assert_eq!(pic_param.inner().golden_ref_frame, 0);
                        assert_eq!(pic_param.inner().alt_ref_frame, 0);
                        assert_eq!(
                            pic_param.inner().out_of_loop_frame,
                            libva::constants::VA_INVALID_SURFACE
                        );

                        // Safe because this bitfield is initialized by the decoder.
                        assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                            libva::VP8PicFields::new(1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0)
                                .inner()
                                .value
                        });

                        assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 3]);
                        assert_eq!(pic_param.inner().loop_filter_level, [28; 4]);
                        assert_eq!(
                            pic_param.inner().loop_filter_deltas_ref_frame,
                            [2, 0, -2, -2]
                        );
                        assert_eq!(pic_param.inner().loop_filter_deltas_mode, [4, -2, 2, 4]);
                        assert_eq!(pic_param.inner().prob_skip_false, 0x6);
                        assert_eq!(pic_param.inner().prob_intra, 0x1);
                        assert_eq!(pic_param.inner().prob_last, 0xf8);
                        assert_eq!(pic_param.inner().prob_gf, 0xff);

                        assert_eq!(pic_param.inner().y_mode_probs, [0x70, 0x56, 0x8c, 0x25]);
                        assert_eq!(pic_param.inner().uv_mode_probs, [0xa2, 0x65, 0xcc]);
                        assert_eq!(
                            pic_param.inner().mv_probs[0],
                            [
                                0xa2, 0x80, 0xe1, 0x92, 0xac, 0x93, 0xd6, 0x27, 0x9c, 0x80, 0x81,
                                0x84, 0x4b, 0x91, 0xb2, 0xce, 0xef, 0xfe, 0xfe,
                            ]
                        );
                        assert_eq!(
                            pic_param.inner().mv_probs[1],
                            [
                                0xa4, 0x80, 0xcc, 0xaa, 0x77, 0xeb, 0x8c, 0xe6, 0xe4, 0x80, 0x82,
                                0x82, 0x4a, 0x94, 0xb4, 0xcb, 0xec, 0xfe, 0xfe,
                            ]
                        );

                        assert_eq!(pic_param.inner().bool_coder_ctx.range, 0xb1);
                        assert_eq!(pic_param.inner().bool_coder_ctx.value, 0xd);
                        assert_eq!(pic_param.inner().bool_coder_ctx.count, 0x2);

                        assert_eq!(
                            slice_param.inner(),
                            libva::SliceParameterBufferVP8::new(
                                131,
                                3,
                                0,
                                86,
                                2,
                                [66, 51, 0, 0, 0, 0, 0, 0, 0],
                            )
                            .inner()
                        );

                        assert_eq!(&slice_data[..], TEST_25_FPS_VP8_STREAM_SLICE_DATA_2);
                    }

                    frame_num += 1;
                });
            });
        }
    }
}
