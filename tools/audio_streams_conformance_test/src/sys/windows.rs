// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use audio_streams::StreamSourceGenerator;

use crate::args::*;
use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSource {}

#[derive(Copy, Clone, Debug, FromArgs, Serialize)]
pub enum StreamSourceParam {}

impl TryFrom<&str> for StreamSource {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        todo!();
    }
}

pub(crate) fn create_stream_source_generator(
    stream_source: StreamSource,
    args: &Args,
) -> Vec<Box<dyn StreamSourceGenerator>> {
    todo!();
}
