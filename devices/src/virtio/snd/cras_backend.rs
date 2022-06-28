// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use audio_streams::StreamSourceGenerator;
use libcras::CrasStreamSourceGenerator;

use crate::virtio::snd::common_backend::{Parameters, SndData};

pub(crate) fn create_cras_stream_source_generators(
    params: &Parameters,
    snd_data: &SndData,
) -> Vec<Box<dyn StreamSourceGenerator>> {
    let mut generators: Vec<Box<dyn StreamSourceGenerator>> = Vec::new();
    generators.resize_with(snd_data.pcm_info_len(), || {
        Box::new(CrasStreamSourceGenerator::new(
            params.capture,
            params.client_type,
            params.socket_type,
        ))
    });
    generators
}
