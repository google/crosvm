// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;

use audio_streams::BoxError;
use base::error;
use base::info;
use base::warn;
use winapi::shared::mmreg::SPEAKER_FRONT_LEFT;
use winapi::shared::mmreg::SPEAKER_FRONT_RIGHT;

use crate::r8b_create;
use crate::r8b_delete;
use crate::r8b_process;
use crate::win_audio_impl;
use crate::CR8BResampler;
use crate::ER8BResamplerRes_r8brr24;

// Increasing this constant won't do much now. In the future, we may want to read from the shm
// buffer mulitple times in a row to prevent the chance of us running out of audio frames to write
// to the Windows audio engine buffer.
const PERIOD_COUNT: usize = 4;
pub const STEREO_CHANNEL_COUNT: usize = win_audio_impl::STEREO_CHANNEL_COUNT as usize;
const MONO_CHANNEL_COUNT: usize = win_audio_impl::MONO_CHANNEL_COUNT as usize;
pub const BYTES_PER_32FLOAT: usize = 4;
/// Android audio capture accepts 16bit int, 2 channels.
pub const ANDROID_CAPTURE_FRAME_SIZE_BYTES: usize = 4;

trait BitDepth {
    fn extend_le_bytes_to_vec(&self, resampled_output_buffer: &mut Vec<u8>);
}

impl BitDepth for f32 {
    fn extend_le_bytes_to_vec(&self, resampled_output_buffer: &mut Vec<u8>) {
        resampled_output_buffer.extend_from_slice(&self.to_le_bytes());
    }
}

impl BitDepth for i16 {
    fn extend_le_bytes_to_vec(&self, resampled_output_buffer: &mut Vec<u8>) {
        resampled_output_buffer.extend_from_slice(&self.to_le_bytes());
    }
}

struct ResamplerContainer<T: BitDepth> {
    left_resampler: CR8BResampler,
    right_resampler: CR8BResampler,
    ring_buf: VecDeque<T>,
    resampled_output_buffer: Vec<u8>,
}

impl<T: BitDepth> ResamplerContainer<T> {
    fn new(
        from_sample_rate: usize,
        to_sample_rate: usize,
        guest_period_in_frames: usize,
        ring_buf_size: usize,
        resample_output_buffer_size: usize,
    ) -> Self {
        ResamplerContainer {
            // If the from and to sample rate is the same, there will be a no-op.
            //
            // SAFETY: `r8b_create` returns a pointer that will be freed when this struct is
            // dropped.
            left_resampler: unsafe {
                r8b_create(
                    from_sample_rate as f64,
                    to_sample_rate as f64,
                    guest_period_in_frames as i32,
                    /* ReqTransBand= */ 2.0,
                    ER8BResamplerRes_r8brr24,
                )
            },
            // SAFETY: see above
            right_resampler: unsafe {
                r8b_create(
                    from_sample_rate as f64,
                    to_sample_rate as f64,
                    guest_period_in_frames as i32,
                    /* ReqTransBand= */ 2.0,
                    ER8BResamplerRes_r8brr24,
                )
            },
            ring_buf: VecDeque::with_capacity(ring_buf_size),
            resampled_output_buffer: Vec::<u8>::with_capacity(resample_output_buffer_size),
        }
    }

    /// Returns true if the next period is available.
    fn get_next_period_internal(&mut self, sample_threshold: usize) -> bool {
        self.resampled_output_buffer.clear();

        if self.ring_buf.len() >= sample_threshold {
            for current_sample in self.ring_buf.drain(..sample_threshold) {
                current_sample.extend_le_bytes_to_vec(&mut self.resampled_output_buffer);
            }
            true
        } else {
            false
        }
    }

    pub fn get_next_period_mut(&mut self, sample_threshold: usize) -> Option<&mut Vec<u8>> {
        if self.get_next_period_internal(sample_threshold) {
            Some(&mut self.resampled_output_buffer)
        } else {
            None
        }
    }

    pub fn get_next_period(&mut self, sample_threshold: usize) -> Option<&Vec<u8>> {
        self.get_next_period_mut(sample_threshold).map(|r| &*r)
    }

    fn sample_rate_convert_2_channels<'a>(
        &mut self,
        left_channel: &'a mut Vec<f64>,
        right_channel: &'a mut Vec<f64>,
    ) -> Option<(&'a [f64], &'a [f64])> {
        let left_channel_converted = self.sample_rate_convert_left_channel(left_channel);
        let right_channel_converted = self.sample_rate_convert_right_channel(right_channel);

        let converted = left_channel_converted.zip(right_channel_converted);
        if let Some((left_channel_converted, right_channel_converted)) = converted {
            if left_channel_converted.len() != right_channel_converted.len() {
                warn!(
                    "left_samples_avialable: {}, does not match right_samples_avaiable: {}",
                    left_channel_converted.len(),
                    right_channel_converted.len(),
                );
            }
        } else {
            info!("Skipping adding samples to ring buffer because of SRC priming.");
        }
        converted
    }

    fn sample_rate_convert_left_channel<'a>(
        &mut self,
        channel: &'a mut Vec<f64>,
    ) -> Option<&'a [f64]> {
        // SAFETY: `left_sampler` is a valid `CR8Resampler` pointer.
        unsafe { Self::sample_rate_convert_one_channel(channel, self.left_resampler) }
    }

    fn sample_rate_convert_right_channel<'a>(
        &mut self,
        channel: &'a mut Vec<f64>,
    ) -> Option<&'a [f64]> {
        // SAFETY: `right_sampler` is a valid `CR8Resampler` pointer.
        unsafe { Self::sample_rate_convert_one_channel(channel, self.right_resampler) }
    }

    /// # Safety
    ///
    /// This is safe if:
    ///   1. `resampler` is a valid pointer to the resampler object.
    ///   2. `r8b_process` sets `converted_buffer_raw` to point to a valid buffer and
    ///      `samples_available` is accurate.
    ///   3. `channel` remains alive when `converted_buffer_raw` is being processed.
    ///      `converted_buffer_raw` could point to the input `channel.as_mut_ptr()`. This is why the
    ///      param `channel` is passed as a reference instead of the vector being moved in here.
    unsafe fn sample_rate_convert_one_channel(
        channel: &mut Vec<f64>,
        resampler: CR8BResampler,
    ) -> Option<&[f64]> {
        let mut converted_buffer_raw: *mut f64 = std::ptr::null_mut();

        let samples_available = r8b_process(
            resampler,
            channel.as_mut_ptr(),
            channel.len() as i32,
            &mut converted_buffer_raw,
        );
        if samples_available != 0 {
            let channel_converted =
                std::slice::from_raw_parts(converted_buffer_raw, samples_available as usize);
            Some(channel_converted)
        } else {
            None
        }
    }
}

impl<T: BitDepth> Drop for ResamplerContainer<T> {
    fn drop(&mut self) {
        // SAFETY: This is calling to a FFI that was binded properly. Also
        // `left_resampler` and `right_resampler` are instantiated in the contructor.
        unsafe {
            if !self.left_resampler.is_null() {
                r8b_delete(self.left_resampler);
            }
            if !self.right_resampler.is_null() {
                r8b_delete(self.right_resampler);
            }
        }
    }
}

/// Provides a ring buffer to hold audio samples coming from the guest. Also responsible for sample
/// rate conversion (src) if needed. We are assuming the guest's sample format is ALWAYS 16bit
/// ints, 48kHz, and 2 channels because this is defined in Kiwi's Android Audio HAL, which
/// we control. We are also assuming that the audio engine will always take 32bit
/// floats if we ask for the shared format through `GetMixFormat` since it will convert
/// to 32bit floats if it's not anyways.
pub struct PlaybackResamplerBuffer {
    resampler_container: ResamplerContainer<f32>,
    pub shared_audio_engine_period_in_frames: usize,
    // The guest period in frames when converted to the audio engine's sample rate.
    pub guest_period_in_target_sample_rate_frames: usize,
    num_channels: usize,
    // Set to true if the resampler is priming. Priming means that the resampler needs to read in
    // multiple periods of audio samples in order to determine how to best sample rate convert.
    pub is_priming: bool,
}

impl PlaybackResamplerBuffer {
    pub fn new(
        from_sample_rate: usize,
        to_sample_rate: usize,
        guest_period_in_frames: usize,
        shared_audio_engine_period_in_frames: usize,
        num_channels: usize,
        channel_mask: Option<u32>,
    ) -> Result<Self, BoxError> {
        // Convert the period to milliseconds. Even though rounding happens, it shouldn't distort
        // the result.
        // Unit would look like: (frames * 1000(milliseconds/second) / (frames/second))
        // so end units is in milliseconds.
        if (shared_audio_engine_period_in_frames * 1000) / to_sample_rate < 10 {
            warn!("Windows Audio Engine period is less than 10ms");
        }
        // Divide by 100 because we want to get the # of frames in 10ms since that is the guest's
        // period.
        let guest_period_in_target_sample_rate_frames = to_sample_rate / 100;

        soft_check_channel_mask(channel_mask);

        // Size chosen since it's a power of 2 minus 1. Anecdotally, this is the max capacity
        // the VecDeque has reached during runtime.
        let ring_buf_size = shared_audio_engine_period_in_frames * PERIOD_COUNT;
        // Each frame will have 64 bits, or 8 bytes.
        let resampled_output_buffer_size = shared_audio_engine_period_in_frames * 8;
        Ok(PlaybackResamplerBuffer {
            resampler_container: ResamplerContainer::<f32>::new(
                from_sample_rate,
                to_sample_rate,
                guest_period_in_frames,
                ring_buf_size,
                resampled_output_buffer_size,
            ),
            shared_audio_engine_period_in_frames,
            guest_period_in_target_sample_rate_frames,
            num_channels,
            is_priming: false,
        })
    }

    /// Converts the 16 bit int samples to the target sample rate and also add to the
    /// intermediate `ring_buf` if needed.
    ///
    /// Returns `true` if the resampler is priming.
    pub fn convert_and_add(&mut self, input_buffer: &[u8]) {
        if input_buffer.len() % 4 != 0 {
            warn!("input buffer len {} not divisible by 4", input_buffer.len());
        }
        let mut left_channel = vec![0.0; input_buffer.len() / 4];
        let mut right_channel = vec![0.0; input_buffer.len() / 4];
        self.copy_every_other_and_convert_to_float(input_buffer, &mut left_channel, 0);
        self.copy_every_other_and_convert_to_float(input_buffer, &mut right_channel, 2);

        let (left_channel_converted, right_channel_converted) = match self
            .resampler_container
            .sample_rate_convert_2_channels(&mut left_channel, &mut right_channel)
        {
            Some((left_channel_converted, right_channel_converted)) => {
                (left_channel_converted, right_channel_converted)
            }
            // If no audio samples are returned, then the resampler is priming.
            None => {
                self.is_priming = true;
                return;
            }
        };

        // As mentioned above, we are assuming that guest's format is 16bits int. A 16 bit int
        // format gives a range from −32,768 to 32,767. To convert audio samples from int to float,
        // we need to convert it to a range from -1.0 to 1.0, hence dividing by 32767 (2^15 - 1).
        for (left_sample, right_sample) in left_channel_converted
            .iter()
            .zip(right_channel_converted.iter())
        {
            let left_normalized_sample = *left_sample as f32 / i16::MAX as f32;
            let right_normalized_sample = *right_sample as f32 / i16::MAX as f32;

            self.perform_channel_conversion(left_normalized_sample, right_normalized_sample);
        }

        // The resampler is not priming, since audio samples were returned.
        self.is_priming = false;
    }

    fn perform_channel_conversion(
        &mut self,
        left_normalized_sample: f32,
        right_normalized_sample: f32,
    ) {
        match self.num_channels {
            STEREO_CHANNEL_COUNT => {
                self.resampler_container
                    .ring_buf
                    .push_back(left_normalized_sample);
                self.resampler_container
                    .ring_buf
                    .push_back(right_normalized_sample);
            }
            MONO_CHANNEL_COUNT => {
                self.resampler_container
                    .ring_buf
                    .push_back((left_normalized_sample + right_normalized_sample) / 2.0);
            }
            _ => {
                // This will put the `left_normalized_sample` in SPEAKER_FRONT_LEFT and the
                // `right_normalized_sample` in SPEAKER_FRONT_RIGHT and then zero out the rest.
                self.resampler_container
                    .ring_buf
                    .push_back(left_normalized_sample);
                self.resampler_container
                    .ring_buf
                    .push_back(right_normalized_sample);
                for _ in 0..self.num_channels - 2 {
                    self.resampler_container.ring_buf.push_back(0.0);
                }
            }
        }
    }

    pub fn get_next_period(&mut self) -> Option<&Vec<u8>> {
        // This value is equal to one full audio engine period of audio frames.
        let sample_threshold = self.shared_audio_engine_period_in_frames * self.num_channels;
        self.resampler_container.get_next_period(sample_threshold)
    }

    /// Seperates the audio samples by channels
    ///
    /// Audio samples coming from the guest are formatted similarly to how WAV files are formatted:
    /// http://soundfile.sapp.org/doc/WaveFormat/
    ///
    /// Audio samples from the guest are coming in as little endian format. Example:
    /// Channel: [  L  ] [  R  ] [ L   ] [   R   ]
    /// [u8]:    [14, 51, 45, 0, 23, 234, 123, 15]
    /// [i16]:   [13070] [ 45  ] [-5609] [ 3963  ]
    ///
    /// Sample rate conversion samples as floats.
    fn copy_every_other_and_convert_to_float(&self, source: &[u8], dest: &mut [f64], start: usize) {
        for (dest_index, x) in (start..source.len()).step_by(4).enumerate() {
            let sample_value = source[x] as i16 + ((source[x + 1] as i16) << 8);
            dest[dest_index] = sample_value.into();
        }
    }

    pub fn ring_buf_len(&self) -> usize {
        self.resampler_container.ring_buf.len()
    }
}

/// Similar to `ResamplerBuffer` except for audio capture. This structure assumes:
///
/// 1. That the format coming from the Window's audio enginer will be a 32bit float, any sample
///    rate, and any number of channels.
/// 2. The format Android requires is always 16bit int, 48kHz, and 2 channels.
pub struct CaptureResamplerBuffer {
    resampler_container: ResamplerContainer<i16>,
    // Minimum required size of samples in `ResamplerContainer` for it to be drained.
    pub sample_threshold: usize,
    pub shared_audio_engine_channels: usize,
}

impl CaptureResamplerBuffer {
    pub fn new_input_resampler(
        from_sample_rate: usize,
        to_sample_rate: usize,
        guest_period_in_frames: usize,
        shared_audio_engine_channels: usize,
        channel_mask: Option<u32>,
    ) -> Result<Self, BoxError> {
        // Arbitrarily chose ring_buf size. For audio capture, we will be draining the buffer
        // from Windows audio engine, so there can be many periods of audio samples in the
        // `ring_buf`.
        let ring_buf_size = guest_period_in_frames * 10;
        //  The `resampled_out_buffer` will hold the format that Android wants
        //  (16bit, 48kHz, 2 channels), so this will equal one guest period in bytes.
        let resampled_output_buffer_size =
            guest_period_in_frames * ANDROID_CAPTURE_FRAME_SIZE_BYTES;

        soft_check_channel_mask(channel_mask);

        Ok(CaptureResamplerBuffer {
            resampler_container: ResamplerContainer::<i16>::new(
                from_sample_rate,
                to_sample_rate,
                guest_period_in_frames,
                ring_buf_size,
                resampled_output_buffer_size,
            ),
            // This value is equal to one full audio engine period of audio frames.
            sample_threshold: guest_period_in_frames * 2,
            shared_audio_engine_channels,
        })
    }

    /// Assumes `input_buffer` is in a 32 bit float format and the final bytes pushed into the
    /// `ring_buf` will be a 16 bit int and 2 channels format.
    pub fn convert_and_add(&mut self, input_buffer: &[u8]) {
        match self.shared_audio_engine_channels {
            0 => {
                error!("`shared_audio_engine_channels` is 0, and that should never happen");
            }
            1 => {
                let mut converted_to_float = Self::convert_to_float(input_buffer);

                // For the mono channel case, since there are two sample rate converters in
                // `resampler_container`, the left one was arbitrarily chosen.
                let channel_converted = self
                    .resampler_container
                    .sample_rate_convert_left_channel(&mut converted_to_float);

                if let Some(channel_converted) = channel_converted {
                    for sample in channel_converted {
                        // SAFETY: `int_val` won't be infinity or NAN.
                        // Also its value can be represented by an int once their fractional
                        // parts are removed.
                        let int_val = unsafe { (*sample).to_int_unchecked() };

                        // Copy bytes to create 2 channel frames
                        self.resampler_container.ring_buf.push_back(int_val);
                        self.resampler_container.ring_buf.push_back(int_val);
                    }
                } else {
                    info!("Skipping adding samples to ring buffer because of SRC priming.");
                }
            }
            // If the format from the audio engine is >= 2 channels, then we only take the first
            // two channels in a frame and throw the rest out. This is because our Android audio
            // policy is hardcoded to only accept 2 channel formats.
            channels => {
                let mut left_channel =
                    vec![0.0; input_buffer.len() / (BYTES_PER_32FLOAT * channels)];
                let mut right_channel =
                    vec![0.0; input_buffer.len() / (BYTES_PER_32FLOAT * channels)];
                let bytes_per_frame = channels * BYTES_PER_32FLOAT;

                Self::copy_every_other(input_buffer, &mut left_channel, 0, bytes_per_frame);
                Self::copy_every_other(
                    input_buffer,
                    &mut right_channel,
                    BYTES_PER_32FLOAT,
                    bytes_per_frame,
                );

                let (left_channel_converted, right_channel_converted) = match self
                    .resampler_container
                    .sample_rate_convert_2_channels(&mut left_channel, &mut right_channel)
                {
                    Some((left_channel_converted, right_channel_converted)) => {
                        (left_channel_converted, right_channel_converted)
                    }
                    None => return,
                };

                for (left_sample, right_sample) in left_channel_converted
                    .iter()
                    .zip(right_channel_converted.iter())
                {
                    // SAFETY: `left_sample` and `right_sample` won't be infinity or NAN.
                    // Also their values can be represented by an int once their fractional
                    // parts are removed.
                    let left_val = unsafe { (*left_sample).to_int_unchecked() };
                    // SAFETY: ditto
                    let right_val = unsafe { (*right_sample).to_int_unchecked() };

                    self.resampler_container.ring_buf.push_back(left_val);
                    self.resampler_container.ring_buf.push_back(right_val);
                }
            }
        }
    }

    /// Since a stream of audio bytes will have their channels interleaved, this will separate
    /// a channel into its own slice.
    fn copy_every_other(source: &[u8], dest: &mut [f64], start: usize, bytes_per_frame: usize) {
        if (source.len() % BYTES_PER_32FLOAT) != 0 || (source.len() % bytes_per_frame != 0) {
            error!(
                "source length: {} isn't divisible by the 4 (bytes in a 32bit float) or \
                   bytes_per_frame: {}",
                source.len(),
                bytes_per_frame
            );
            return;
        }
        for (dest_index, x) in (start..source.len()).step_by(bytes_per_frame).enumerate() {
            let sample_value =
                f32::from_le_bytes([source[x], source[x + 1], source[x + 2], source[x + 3]]);
            dest[dest_index] = sample_value.into();
            dest[dest_index] *= i16::MAX as f64;
        }
    }

    fn convert_to_float(buffer: &[u8]) -> Vec<f64> {
        if buffer.len() % BYTES_PER_32FLOAT != 0 {
            error!("buffer of bytes length isn't divisible by the 4 (bytes in a 32bit float)");
            return vec![];
        }

        let mut result = vec![0.0; buffer.len() / BYTES_PER_32FLOAT];
        for (result_idx, i) in (0..buffer.len()).step_by(BYTES_PER_32FLOAT).enumerate() {
            result[result_idx] =
                (f32::from_le_bytes([buffer[i], buffer[i + 1], buffer[i + 2], buffer[i + 3]])
                    * i16::MAX as f32)
                    .into();
        }

        result
    }

    pub fn get_next_period(&mut self) -> Option<&mut Vec<u8>> {
        self.resampler_container
            .get_next_period_mut(self.sample_threshold)
    }

    pub fn is_next_period_available(&self) -> bool {
        self.ring_buf_len() >= self.sample_threshold
    }

    pub fn ring_buf_len(&self) -> usize {
        self.resampler_container.ring_buf.len()
    }
}

fn soft_check_channel_mask(channel_mask: Option<u32>) {
    if let Some(channel_mask) = channel_mask {
        if channel_mask & SPEAKER_FRONT_LEFT == 0 || channel_mask & SPEAKER_FRONT_RIGHT == 0 {
            warn!(
                "channel_mask: {} does not have both front left and front right channels set. \
                 Will proceed to populate the first 2 channels anyways.",
                channel_mask
            );
        }
    }
}

#[cfg(test)]
mod test {
    use winapi::shared::mmreg::SPEAKER_BACK_LEFT;
    use winapi::shared::mmreg::SPEAKER_BACK_RIGHT;
    use winapi::shared::mmreg::SPEAKER_FRONT_CENTER;
    use winapi::shared::mmreg::SPEAKER_LOW_FREQUENCY;
    use winapi::shared::mmreg::SPEAKER_SIDE_LEFT;
    use winapi::shared::mmreg::SPEAKER_SIDE_RIGHT;

    use super::*;

    #[test]
    fn test_copy_every_other_and_convert_to_float() {
        let intermediate_src_buffer = PlaybackResamplerBuffer::new(
            48000, 44100, 480, 448, /* num_channel */ 2, /* channel_mask */ None,
        )
        .unwrap();

        let left_channel_bytes: Vec<u8> = [25u16, 256, 1000, 2400]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect();

        let mut result = vec![0.0; 2];
        intermediate_src_buffer.copy_every_other_and_convert_to_float(
            &left_channel_bytes,
            &mut result,
            0,
        );
        assert_vec_float_eq(result, [25.0, 1000.0].to_vec());

        let mut result2 = vec![0.0; 2];
        intermediate_src_buffer.copy_every_other_and_convert_to_float(
            &left_channel_bytes,
            &mut result2,
            2,
        );
        assert_vec_float_eq(result2, [256.0, 2400.0].to_vec());
    }

    fn assert_vec_float_eq(vec1: Vec<f64>, vec2: Vec<f64>) {
        assert_eq!(vec1.len(), vec2.len());
        for (i, val) in vec1.into_iter().enumerate() {
            assert!((val - vec2[i]).abs() < f64::EPSILON);
        }
    }

    /// Used to account for floating point arithmitic precision loss.
    fn assert_vec_float_almost_eq(vec1: Vec<f64>, vec2: Vec<f64>) {
        assert_eq!(vec1.len(), vec2.len());
        for (i, val) in vec1.into_iter().enumerate() {
            assert!((val - vec2[i]).abs() < 0.00001);
        }
    }

    #[test]
    fn test_get_next_period() {
        // Create an intermediate buffer that won't require resampling
        let mut intermediate_src_buffer = PlaybackResamplerBuffer::new(
            48000, 48000, 480, 513, /* num_channel */ 2, /* channel_mask */ None,
        )
        .unwrap();

        assert!(intermediate_src_buffer.get_next_period().is_none());

        // 480 frames * 2 sample/frames * 2 bytes/sample = 1920 bytes
        let bytes_in_16bit_48k_hz = 1920;
        let buffer: Vec<u8> = vec![0; bytes_in_16bit_48k_hz];
        intermediate_src_buffer.convert_and_add(&buffer);

        assert!(intermediate_src_buffer.get_next_period().is_none());

        let buffer: Vec<u8> = vec![0; bytes_in_16bit_48k_hz];
        intermediate_src_buffer.convert_and_add(&buffer);

        assert!(intermediate_src_buffer.get_next_period().is_some());
    }

    #[test]
    fn test_perform_channel_conversion_mono() {
        let mut intermediate_src_buffer = PlaybackResamplerBuffer::new(
            /* from_sample_rate */ 48000, /* to_sample_rate */ 48000,
            /* guest_period_in_frames */ 480,
            /* shared_audio_engine_period_in_frames */ 513, /* num_channel */ 1,
            /* channel_mask */ None,
        )
        .unwrap();

        let two_channel_samples = [5.0, 5.0, 2.0, 8.0];

        for x in (0..two_channel_samples.len()).step_by(2) {
            let left = two_channel_samples[x];
            let right = two_channel_samples[x + 1];
            intermediate_src_buffer.perform_channel_conversion(left, right);
        }

        assert_eq!(intermediate_src_buffer.ring_buf_len(), 2);
        assert_eq!(
            intermediate_src_buffer.resampler_container.ring_buf,
            vec![5.0, 5.0]
        );
    }

    #[test]
    fn test_upmix_5_1() {
        let channel_mask = SPEAKER_FRONT_LEFT
            | SPEAKER_FRONT_RIGHT
            | SPEAKER_FRONT_CENTER
            | SPEAKER_LOW_FREQUENCY
            | SPEAKER_BACK_LEFT
            | SPEAKER_BACK_RIGHT;
        let mut intermediate_src_buffer = PlaybackResamplerBuffer::new(
            48000,
            44100,
            480,
            448,
            /* num_channel */ 6,
            /* channel_mask */ Some(channel_mask),
        )
        .unwrap();

        let two_channel_samples = [5.0, 5.0, 2.0, 8.0];
        for x in (0..two_channel_samples.len()).step_by(2) {
            let left = two_channel_samples[x];
            let right = two_channel_samples[x + 1];
            intermediate_src_buffer.perform_channel_conversion(left, right);
        }

        assert_eq!(intermediate_src_buffer.ring_buf_len(), 12);
        // Only populate FL and FR channels and zero out the rest.
        assert_eq!(
            intermediate_src_buffer.resampler_container.ring_buf,
            vec![5.0, 5.0, 0.0, 0.0, 0.0, 0.0, 2.0, 8.0, 0.0, 0.0, 0.0, 0.0]
        );
    }

    #[test]
    fn test_upmix_7_1() {
        let channel_mask = SPEAKER_FRONT_LEFT
            | SPEAKER_FRONT_RIGHT
            | SPEAKER_FRONT_CENTER
            | SPEAKER_LOW_FREQUENCY
            | SPEAKER_BACK_LEFT
            | SPEAKER_BACK_RIGHT
            | SPEAKER_SIDE_LEFT
            | SPEAKER_SIDE_RIGHT;
        let mut intermediate_src_buffer = PlaybackResamplerBuffer::new(
            48000,
            44100,
            480,
            448,
            /* num_channel */ 8,
            /* channel_mask */ Some(channel_mask),
        )
        .unwrap();

        let two_channel_samples = [5.0, 5.0, 2.0, 8.0];
        for x in (0..two_channel_samples.len()).step_by(2) {
            let left = two_channel_samples[x];
            let right = two_channel_samples[x + 1];
            intermediate_src_buffer.perform_channel_conversion(left, right);
        }

        assert_eq!(intermediate_src_buffer.ring_buf_len(), 16);
        // Only populate FL and FR channels and zero out the rest.
        assert_eq!(
            intermediate_src_buffer.resampler_container.ring_buf,
            vec![5.0, 5.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 8.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        );
    }

    #[test]
    fn test_capture_copy_every_other_2_channels_returns_samples_from_one_channel() {
        const CHANNEL_COUNT: usize = 2;

        let incoming_bytes: Vec<u8> = [25.0f32, 256.0, 1000.0, 2400.0]
            .iter()
            .flat_map(|x| {
                // Convert so range is between -1 and 1, which is how audio samples in float are
                // represented.
                let decimal = x / (i16::MAX as f32);
                decimal.to_le_bytes()
            })
            .collect();
        let mut result = vec![0.0; 2];
        CaptureResamplerBuffer::copy_every_other(
            &incoming_bytes,
            &mut result,
            0,
            BYTES_PER_32FLOAT * CHANNEL_COUNT,
        );
        // Verify first channel is retrieved.
        assert_vec_float_almost_eq(result, [25.0, 1000.0].to_vec());

        let mut result2 = vec![0.0; 2];
        CaptureResamplerBuffer::copy_every_other(
            &incoming_bytes,
            &mut result2,
            BYTES_PER_32FLOAT,
            BYTES_PER_32FLOAT * CHANNEL_COUNT,
        );
        // Verify second channel is retrieved.
        assert_vec_float_almost_eq(result2, [256.0, 2400.0].to_vec());
    }

    #[test]
    fn test_capture_copy_every_other_surround_sound_returns_samples_from_one_channel() {
        const CHANNEL_COUNT: usize = 6;

        // Only the first two channels per frame will be used. Each frame has 6 channels.
        let incoming_bytes: Vec<u8> = [
            25.0f32, 256.0, 92.0, 56.0, 123.0, 93.0, 1000.0, 2400.0, 9.0, 1298.0, 4000.0, 34.0,
        ]
        .iter()
        .flat_map(|x| {
            // Convert so range is between -1 and 1, which is how audio samples in float are
            // represented.
            let decimal = x / (i16::MAX as f32);
            decimal.to_le_bytes()
        })
        .collect();
        let mut result = vec![0.0; 2];
        CaptureResamplerBuffer::copy_every_other(
            &incoming_bytes,
            &mut result,
            0,
            BYTES_PER_32FLOAT * CHANNEL_COUNT,
        );
        // Verify first channel is retrieved.
        assert_vec_float_almost_eq(result, [25.0, 1000.0].to_vec());

        let mut result2 = vec![0.0; 2];
        CaptureResamplerBuffer::copy_every_other(
            &incoming_bytes,
            &mut result2,
            BYTES_PER_32FLOAT,
            BYTES_PER_32FLOAT * CHANNEL_COUNT,
        );
        // Verify second channel is retrieved.
        assert_vec_float_almost_eq(result2, [256.0, 2400.0].to_vec());
    }

    #[test]
    fn test_capture_mono_channel_returns_some_audio_samples() {
        const CHANNEL_COUNT: usize = 1;

        let guest_period_in_frames = 480;
        let mut input_resampler = CaptureResamplerBuffer::new_input_resampler(
            48000,
            48000,
            guest_period_in_frames,
            CHANNEL_COUNT,
            Some(SPEAKER_FRONT_CENTER),
        )
        .unwrap();
        // Make sure no samples are added to the resampler buffer.
        assert!(input_resampler.get_next_period().is_none());

        let bytes_in_32f_48k_hz_1_channel =
            guest_period_in_frames * BYTES_PER_32FLOAT * CHANNEL_COUNT;
        let buffer: Vec<u8> = vec![1; bytes_in_32f_48k_hz_1_channel];
        input_resampler.convert_and_add(&buffer);

        // Verify that `get_next_period` returns something after audio samples are added.
        assert!(input_resampler.get_next_period().is_some());
    }

    #[test]
    fn test_capture_stereo_channel_returns_some_audio_samples() {
        const CHANNEL_COUNT: usize = 2;

        let guest_period_in_frames = 480;
        let mut input_resampler = CaptureResamplerBuffer::new_input_resampler(
            48000,
            48000,
            guest_period_in_frames,
            CHANNEL_COUNT,
            Some(SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT),
        )
        .unwrap();
        // Make sure no samples are added to the resampler buffer.
        assert!(input_resampler.get_next_period().is_none());

        let bytes_in_32f_48k_hz_2_channel =
            guest_period_in_frames * BYTES_PER_32FLOAT * CHANNEL_COUNT;
        let buffer: Vec<u8> = vec![1; bytes_in_32f_48k_hz_2_channel];
        input_resampler.convert_and_add(&buffer);

        // Verify that `get_next_period` returns something after audio samples are added.
        assert!(input_resampler.get_next_period().is_some());
    }

    #[test]
    fn test_capture_surround_sound_returns_some_audio_samples() {
        const CHANNEL_COUNT: usize = 6;

        let guest_period_in_frames = 480;
        let mut input_resampler = CaptureResamplerBuffer::new_input_resampler(
            48000,
            48000,
            guest_period_in_frames,
            CHANNEL_COUNT,
            Some(SPEAKER_FRONT_CENTER),
        )
        .unwrap();
        // Make sure no samples are added to the resampler buffer.
        assert!(input_resampler.get_next_period().is_none());

        let bytes_in_32f_48k_hz_1_channel =
            guest_period_in_frames * BYTES_PER_32FLOAT * CHANNEL_COUNT;
        let buffer: Vec<u8> = vec![1; bytes_in_32f_48k_hz_1_channel];
        input_resampler.convert_and_add(&buffer);
        // Verify that `get_next_period` returns something after audio samples are added.
        assert!(input_resampler.get_next_period().is_some());
    }
}
