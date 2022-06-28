// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use audio_streams::{NoopStreamSourceGenerator, StreamSourceGenerator};

use crate::virtio::snd::common_backend::SndData;

pub(crate) fn create_null_stream_source_generators(
    snd_data: &SndData,
) -> Vec<Box<dyn StreamSourceGenerator>> {
    let mut generators: Vec<Box<dyn StreamSourceGenerator>> = Vec::new();
    generators.resize_with(snd_data.pcm_info_len(), || {
        Box::new(NoopStreamSourceGenerator::new())
    });
    generators
}
