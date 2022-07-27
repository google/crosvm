// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str::FromStr;

use audio_streams::StreamSourceGenerator;
use base::set_rt_prio_limit;
use base::set_rt_round_robin;
use base::warn;
#[cfg(feature = "audio_cras")]
use libcras::CrasStreamSourceGenerator;

use crate::virtio::snd::common_backend::SndData;
use crate::virtio::snd::parameters::Error;
use crate::virtio::snd::parameters::Parameters;

const AUDIO_THREAD_RTPRIO: u16 = 10; // Matches other cros audio clients.

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamSourceBackend {
    #[cfg(feature = "audio_cras")]
    CRAS,
}

impl FromStr for StreamSourceBackend {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            #[cfg(feature = "audio_cras")]
            "cras" => Ok(StreamSourceBackend::CRAS),
            _ => Err(Error::InvalidBackend),
        }
    }
}

#[allow(unused_variables, unused_mut)]
pub(crate) fn parse_args(params: &mut Parameters, k: &str, v: &str) -> Result<(), Error> {
    #[cfg(feature = "audio_cras")]
    match k {
        "client_type" => {
            params.client_type = v.parse().map_err(|e: libcras::CrasSysError| {
                Error::InvalidParameterValue(v.to_string(), e.to_string())
            })?;
        }
        "socket_type" => {
            params.socket_type = v.parse().map_err(|e: libcras::Error| {
                Error::InvalidParameterValue(v.to_string(), e.to_string())
            })?;
        }
        _ => return Err(Error::UnknownParameter(k.to_string())),
    };
    Ok(())
}

#[cfg(feature = "audio_cras")]
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

#[allow(unused_variables)]
pub(crate) fn create_stream_source_generators(
    backend: StreamSourceBackend,
    params: &Parameters,
    snd_data: &SndData,
) -> Vec<Box<dyn StreamSourceGenerator>> {
    match backend {
        #[cfg(feature = "audio_cras")]
        StreamSourceBackend::CRAS => create_cras_stream_source_generators(params, snd_data),
    }
}

pub(crate) fn set_audio_thread_priority() {
    if let Err(e) = set_rt_prio_limit(u64::from(AUDIO_THREAD_RTPRIO))
        .and_then(|_| set_rt_round_robin(i32::from(AUDIO_THREAD_RTPRIO)))
    {
        warn!("Failed to set audio thread to real time: {}", e);
    }
}
