// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use audio_streams::NoopStreamSourceGenerator;

use crate::virtio::snd::common_backend::SndData;
use crate::virtio::snd::sys::SysAudioStreamSourceGenerator;

pub(crate) fn create_null_stream_source_generators(
    snd_data: &SndData,
) -> Vec<SysAudioStreamSourceGenerator> {
    let mut generators: Vec<SysAudioStreamSourceGenerator> = Vec::new();
    generators.resize_with(snd_data.pcm_info_len(), || {
        Box::new(NoopStreamSourceGenerator::new())
    });
    generators
}
