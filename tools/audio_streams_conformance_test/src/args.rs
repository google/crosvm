// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{fmt, str::FromStr};

use argh::FromArgs;
use audio_streams::*;
use serde::Serialize;

use super::error::Error;

// maybe use StreamSourceGenerator directly
#[derive(Copy, Clone, Debug, PartialEq, Serialize)]
pub enum StreamSourceEnum {
    NoopStream,
}

impl fmt::Display for StreamSourceEnum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StreamSourceEnum::NoopStream => write!(f, "noop"),
        }
    }
}

impl FromStr for StreamSourceEnum {
    type Err = Error;
    fn from_str(s: &str) -> ::std::result::Result<StreamSourceEnum, Self::Err> {
        match s {
            "noop" => Ok(StreamSourceEnum::NoopStream),
            _ => Err(Error::InvalidStreamSuorce(s.to_owned())),
        }
    }
}

fn default_channels() -> usize {
    2
}

fn default_sample_format() -> SampleFormat {
    SampleFormat::S16LE
}

fn default_rate() -> u32 {
    48000
}

fn default_buffer_frames() -> usize {
    240
}

fn default_iterations() -> usize {
    10
}

fn default_stream_source() -> StreamSourceEnum {
    StreamSourceEnum::NoopStream
}

#[derive(Copy, Clone, Debug, FromArgs, Serialize)]
/// test test
pub struct Args {
    /// the StreamSource to use for playback. (default: noop).
    #[argh(
        option,
        short = 'P',
        default = "default_stream_source()",
        from_str_fn(StreamSourceEnum::from_str)
    )]
    pub playback_source: StreamSourceEnum,
    /// the channel numbers. (default: 2)
    #[argh(option, short = 'c', default = "default_channels()")]
    pub channels: usize,
    /// format. Must be in [U8, S16_LE, S24_LE, S32_LE]. (default:S16_LE)
    #[argh(
        option,
        short = 'f',
        default = "default_sample_format()",
        from_str_fn(SampleFormat::from_str)
    )]
    pub format: SampleFormat,
    /// sample rate. (default: 48000)
    #[argh(option, short = 'r', default = "default_rate()")]
    pub rate: u32,
    /// block buffer size (frames) of each write. (default: 240).
    #[argh(option, short = 'b', default = "default_buffer_frames()")]
    pub buffer_frames: usize,
    /// the iterations to fill in the audio buffer. default: 10)
    #[argh(option, default = "default_iterations()")]
    pub iterations: usize,
    /// whether or not to print in json format
    #[argh(switch)]
    pub json: bool,
}

impl fmt::Display for Args {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            r#"
Playback Source: {:?}
Channels: {}
Format: {:?}
Sample rate: {} frames/s
Buffer size: {} frames
Iterations: {}
          "#,
            self.playback_source,
            self.channels,
            self.format,
            self.rate,
            self.buffer_frames,
            self.iterations
        )
    }
}
