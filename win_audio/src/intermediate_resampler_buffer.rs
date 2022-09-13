// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;

use audio_streams::BoxError;
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

/// Provides a ring buffer to hold audio samples coming from the guest. Also responsible for sample
/// rate conversion (src) if needed. We are assuming the guest's sample format is ALWAYS 16bit
/// ints, 48kHz, and 2 channels because this is defined in Kiwi's Android Audio HAL, which
/// we control. We are also assuming that the audio engine will always take 32bit
/// floats if we ask for the shared format through `GetMixFormat` since it will convert
/// to 32bit floats if it's not anyways.
pub struct IntermediateResamplerBuffer {
    left_resampler: CR8BResampler,
    right_resampler: CR8BResampler,
    pub ring_buf: VecDeque<f32>,
    pub shared_audio_engine_period_in_frames: usize,
    // The guest period in frames when converted to the audio engine's sample rate.
    pub guest_period_in_target_sample_rate_frames: usize,
    resampled_output_buffer: Vec<u8>,
    num_channels: usize,
}

impl IntermediateResamplerBuffer {
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

        if let Some(channel_mask) = channel_mask {
            if channel_mask & SPEAKER_FRONT_LEFT == 0 || channel_mask & SPEAKER_FRONT_RIGHT == 0 {
                warn!(
                    "channel_mask: {} does not have both front left and front right channels set. \
                 Will proceed to populate the first 2 channels anyways.",
                    channel_mask
                );
            }
        }

        Ok(IntermediateResamplerBuffer {
            // If the from and to sample rate is the same, there will be a no-op.
            left_resampler: unsafe {
                r8b_create(
                    from_sample_rate as f64,
                    to_sample_rate as f64,
                    guest_period_in_frames as i32,
                    /* ReqTransBand= */ 2.0,
                    ER8BResamplerRes_r8brr24,
                )
            },
            right_resampler: unsafe {
                r8b_create(
                    from_sample_rate as f64,
                    to_sample_rate as f64,
                    guest_period_in_frames as i32,
                    /* ReqTransBand= */ 2.0,
                    ER8BResamplerRes_r8brr24,
                )
            },
            // Size chosen since it's a power of 2 minus 1. This is the max capacity I've
            // seen the VecDeque reach.
            ring_buf: VecDeque::with_capacity(shared_audio_engine_period_in_frames * PERIOD_COUNT),
            shared_audio_engine_period_in_frames,
            guest_period_in_target_sample_rate_frames,
            // Each frame will have 64 bits, or 8 bytes.
            resampled_output_buffer: Vec::<u8>::with_capacity(
                shared_audio_engine_period_in_frames * 8,
            ),
            num_channels,
        })
    }

    /// Converts the 16 bit int samples to the target sample rate and also add to the
    /// intermediate `ring_buf` if needed.
    pub fn convert_and_add(&mut self, input_buffer: &[u8]) {
        if input_buffer.len() % 4 != 0 {
            warn!("input buffer len {} not divisible by 4", input_buffer.len());
        }
        let mut left_channel = vec![0.0; input_buffer.len() / 4];
        let mut right_channel = vec![0.0; input_buffer.len() / 4];
        self.copy_every_other_and_convert_to_float(input_buffer, &mut left_channel, 0);
        self.copy_every_other_and_convert_to_float(input_buffer, &mut right_channel, 2);

        let mut left_converted_buffer_raw: *mut f64 = std::ptr::null_mut();
        let mut right_converted_buffer_raw: *mut f64 = std::ptr::null_mut();
        // Safe because the only part unsafe in calling `r8b_process` which is a FFI that
        // should be binded correctly.
        let (left_samples_available, right_samples_available) = unsafe {
            let left_samples_available = r8b_process(
                self.left_resampler,
                left_channel.as_mut_ptr(),
                left_channel.len() as i32,
                &mut left_converted_buffer_raw,
            );
            let right_samples_available = r8b_process(
                self.right_resampler,
                right_channel.as_mut_ptr(),
                right_channel.len() as i32,
                &mut right_converted_buffer_raw,
            );
            (left_samples_available, right_samples_available)
        };

        if left_samples_available != right_samples_available {
            warn!(
                "left_samples_avialable: {}, does not match right_samples_avaiable: {}",
                left_samples_available, right_samples_available,
            );
        }
        // `r8b_process` will need multiple guest periods before it will
        // return a converted buffer of audio samples.
        if left_samples_available != 0 && right_samples_available != 0 {
            let left_channel_converted = unsafe {
                std::slice::from_raw_parts(
                    left_converted_buffer_raw,
                    left_samples_available as usize,
                )
            };
            let right_channel_converted = unsafe {
                std::slice::from_raw_parts(
                    right_converted_buffer_raw,
                    right_samples_available as usize,
                )
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
        } else {
            info!(
                "Skipping adding samples to ring buffer because left samples available: {} and \
                right samples available: {}",
                left_samples_available, right_samples_available
            );
        }
    }

    fn perform_channel_conversion(
        &mut self,
        left_normalized_sample: f32,
        right_normalized_sample: f32,
    ) {
        match self.num_channels {
            STEREO_CHANNEL_COUNT => {
                self.ring_buf.push_back(left_normalized_sample);
                self.ring_buf.push_back(right_normalized_sample);
            }
            MONO_CHANNEL_COUNT => {
                self.ring_buf
                    .push_back((left_normalized_sample + right_normalized_sample) / 2.0);
            }
            _ => {
                // This will put the `left_normalized_sample` in SPEAKER_FRONT_LEFT and the
                // `right_normalized_sample` in SPEAKER_FRONT_RIGHT and then zero out the rest.
                self.ring_buf.push_back(left_normalized_sample);
                self.ring_buf.push_back(right_normalized_sample);
                for _ in 0..self.num_channels - 2 {
                    self.ring_buf.push_back(0.0);
                }
            }
        }
    }

    pub fn get_next_period(&mut self) -> Option<&Vec<u8>> {
        self.resampled_output_buffer.clear();
        // This value is equal to one full audio engine period of audio frames.
        let sample_threshold = self.shared_audio_engine_period_in_frames * self.num_channels;

        if self.ring_buf.len() >= sample_threshold {
            for current_sample in self.ring_buf.drain(..sample_threshold) {
                self.resampled_output_buffer
                    .extend_from_slice(&current_sample.to_le_bytes());
            }
            return Some(&self.resampled_output_buffer);
        } else {
            return None;
        }
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
}

impl Drop for IntermediateResamplerBuffer {
    fn drop(&mut self) {
        // Safe because this is calling to a FFI that was binded properly. Also
        // `left_resampler` and `right_resampler` are instantiated in the contructor.
        unsafe {
            r8b_delete(self.left_resampler);
            r8b_delete(self.right_resampler);
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
        let intermediate_src_buffer = IntermediateResamplerBuffer::new(
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

    #[test]
    fn test_get_next_period() {
        // Create an intermediate buffer that won't require resampling
        let mut intermediate_src_buffer = IntermediateResamplerBuffer::new(
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
        let mut intermediate_src_buffer = IntermediateResamplerBuffer::new(
            /* from_sample_rate */ 48000, /* to_sample_rate */ 48000,
            /* guest_period_in_frames */ 480,
            /* shared_audio_engine_period_in_frames */ 513, /* num_channel */ 1,
            /* channel_mask */ None,
        )
        .unwrap();

        let two_channel_samples = vec![5.0, 5.0, 2.0, 8.0];

        for x in (0..two_channel_samples.len()).step_by(2) {
            let left = two_channel_samples[x];
            let right = two_channel_samples[x + 1];
            intermediate_src_buffer.perform_channel_conversion(left, right);
        }

        assert_eq!(intermediate_src_buffer.ring_buf.len(), 2);
        assert_eq!(intermediate_src_buffer.ring_buf, vec![5.0, 5.0]);
    }

    #[test]
    fn test_upmix_5_1() {
        let channel_mask = SPEAKER_FRONT_LEFT
            | SPEAKER_FRONT_RIGHT
            | SPEAKER_FRONT_CENTER
            | SPEAKER_LOW_FREQUENCY
            | SPEAKER_BACK_LEFT
            | SPEAKER_BACK_RIGHT;
        let mut intermediate_src_buffer = IntermediateResamplerBuffer::new(
            48000,
            44100,
            480,
            448,
            /* num_channel */ 6,
            /* channel_mask */ Some(channel_mask),
        )
        .unwrap();

        let two_channel_samples = vec![5.0, 5.0, 2.0, 8.0];
        for x in (0..two_channel_samples.len()).step_by(2) {
            let left = two_channel_samples[x];
            let right = two_channel_samples[x + 1];
            intermediate_src_buffer.perform_channel_conversion(left, right);
        }

        assert_eq!(intermediate_src_buffer.ring_buf.len(), 12);
        // Only populate FL and FR channels and zero out the rest.
        assert_eq!(
            intermediate_src_buffer.ring_buf,
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
        let mut intermediate_src_buffer = IntermediateResamplerBuffer::new(
            48000,
            44100,
            480,
            448,
            /* num_channel */ 8,
            /* channel_mask */ Some(channel_mask),
        )
        .unwrap();

        let two_channel_samples = vec![5.0, 5.0, 2.0, 8.0];
        for x in (0..two_channel_samples.len()).step_by(2) {
            let left = two_channel_samples[x];
            let right = two_channel_samples[x + 1];
            intermediate_src_buffer.perform_channel_conversion(left, right);
        }

        assert_eq!(intermediate_src_buffer.ring_buf.len(), 16);
        // Only populate FL and FR channels and zero out the rest.
        assert_eq!(
            intermediate_src_buffer.ring_buf,
            vec![5.0, 5.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 8.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        );
    }
}
