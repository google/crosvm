// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WaveFormatDetails {
    // Format requested by WASAPI `GetMixFormat` system call.
    pub requested: Option<WaveFormat>,
    // Originally the requested wave format that's modified by the emulator. Only
    // populated if the emulator decides the requested wave format should not be
    // used.
    pub modified: Option<WaveFormat>,
    // Format that is valid and closest matching to the modified format, if the
    // modified was rejected. Should only be populated if modified is also
    // non-null and was rejected by WASAPI `IsFormatSupported` system call.
    pub closest_matched: Option<WaveFormat>,
}

// Defines the format of waveformat audio data. This information is used by
// WASAPI to determine how to process the audio playback data coming from the
// emulator.
//
// The fields in the structure come from WAVEFORMATEXTENSIBLE of win32 api.
// https://docs.microsoft.com/en-us/windows/win32/api/mmreg/ns-mmreg-waveformatextensible
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct WaveFormat {
    // Ex. 65534 (Maps to WAVE_FORMAT_EXTENSIBLE)
    pub format_tag: i32,
    // Number of channels.
    pub channels: i32,
    // Sample rate in Hz. Ex: 48000
    pub samples_per_sec: i32,
    // Required average data-transfer rate for the format tag. Usually this will
    // be samples_per_sec * block_align, since the format tag is usually
    // WAVE_FORMAT_IEEE_FLOAT or it's extensible and SubFormat is
    // KSDATAFORMAT_SUBTYPE_IEEE_FLOAT.
    pub avg_bytes_per_sec: i32,
    // Minimum atomic unit of data based on the format_tag. Usually this will
    // just be bits_per_samples * channels.
    pub block_align: i32,
    // Bits used per sample. Must be a multiple of 8.
    pub bits_per_sample: i32,
    // Size in bytes of extra information appended to WAVEFORMATEX struct.
    pub size_bytes: i32,

    // The next fields are part of the WAVEFORMATEXTENSIBLE struct. They will only
    // be non-null if format_tag is WAVE_FORMAT_EXTENSIBLE.

    // Bit depth. Can be any value. Ex. bits_per_sample is 24,
    // but samples is 20. Note: This value is a union, so it could mean something
    // slightly different, but most likely won't. Refer to doc for more info.
    pub samples: Option<i32>,
    // Bitmask mapping channels in stream to speaker positions.
    // Ex. 3 ( SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT )
    pub channel_mask: Option<i64>,
    // Similar to format_tag, but for WAVEFORMATEXTENSIBLE structs.
    pub sub_format: Option<WaveFormatSubFormat>,
}

// Subformat GUID mapping:
// https://github.com/retep998/winapi-rs/blob/2f76bdea3a79817ccfab496fbd1786d5a697387b/src/shared/ksmedia.rs
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum WaveFormatSubFormat {
    Invalid,
    Analog,
    Pcm,
    IeeeFloat,
    Drm,
    ALaw,
    MuLaw,
    Adpcm,
    Mpeg,
}
