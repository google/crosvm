// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str::FromStr;

use audio_streams::StreamSourceGenerator;

use crate::virtio::snd::common_backend::SndData;
use crate::virtio::snd::parameters::Error;
use crate::virtio::snd::parameters::Parameters;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamSourceBackend {}

impl FromStr for StreamSourceBackend {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!();
    }
}

pub(crate) fn parse_args(_params: &mut Parameters, _k: &str, _v: &str) -> Result<(), Error> {
    todo!();
}

pub(crate) fn create_stream_source_generators(
    _backend: StreamSourceBackend,
    _params: &Parameters,
    _snd_data: &SndData,
) -> Vec<Box<dyn StreamSourceGenerator>> {
    todo!();
}

pub(crate) fn set_audio_thread_priority() {}
