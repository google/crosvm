// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;

use audio_streams::StreamSourceGenerator;
use serde::Serialize;

use crate::args::*;
use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StreamSource {}

#[derive(Copy, Clone, Debug, Serialize)]
pub enum StreamSourceParam {}

impl TryFrom<&str> for StreamSource {
    type Error = Error;

    fn try_from(_s: &str) -> Result<Self, Self::Error> {
        todo!();
    }
}

impl fmt::Display for StreamSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "StreamSource")
    }
}

pub(crate) fn create_stream_source_generator(
    _stream_source: StreamSource,
    _args: &Args,
) -> Box<dyn StreamSourceGenerator> {
    todo!();
}
