// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use audio_streams::StreamSourceGenerator;

use crate::virtio::snd::common_backend::SndData;
use crate::virtio::snd::parameters::Error;
use crate::virtio::snd::parameters::Parameters;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSourceBackend {}

impl TryFrom<&str> for StreamSourceBackend {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        todo!();
    }
}

pub(crate) fn create_stream_source_generators(
    _backend: StreamSourceBackend,
    _params: &Parameters,
    _snd_data: &SndData,
) -> Vec<Box<dyn StreamSourceGenerator>> {
    todo!();
}

pub(crate) fn set_audio_thread_priority() {}
