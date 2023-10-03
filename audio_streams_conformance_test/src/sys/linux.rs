// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;

use audio_streams::StreamSourceGenerator;
#[cfg(feature = "audio_cras")]
use libcras::CrasClientType;
#[cfg(feature = "audio_cras")]
use libcras::CrasSocketType;
#[cfg(feature = "audio_cras")]
use libcras::CrasStreamSourceGenerator;
use serde::Serialize;

use crate::args::*;
use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum StreamSource {
    #[cfg(feature = "audio_cras")]
    CRAS,
}

impl TryFrom<&str> for StreamSource {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            #[cfg(feature = "audio_cras")]
            "cras" => Ok(StreamSource::CRAS),
            _ => Err(Error::InvalidStreamSuorce(s.to_owned())),
        }
    }
}

impl fmt::Display for StreamSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            #[cfg(feature = "audio_cras")]
            StreamSource::CRAS => write!(f, "cras"),
            _ => write!(f, "unknow stream source"),
        }
    }
}

#[allow(unused_variables)]
#[cfg(feature = "audio_cras")]
fn create_cras_stream_source_generator(args: &Args) -> Box<dyn StreamSourceGenerator> {
    Box::new(CrasStreamSourceGenerator::new(
        false,
        CrasClientType::CRAS_CLIENT_TYPE_TEST,
        CrasSocketType::Legacy,
    ))
}

#[allow(unused_variables)]
pub(crate) fn create_stream_source_generator(
    stream_source: StreamSource,
    args: &Args,
) -> Box<dyn StreamSourceGenerator> {
    match stream_source {
        #[cfg(feature = "audio_cras")]
        StreamSource::CRAS => create_cras_stream_source_generator(args),
    }
}
