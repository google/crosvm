// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

use audio_streams::BoxError;
use remain::sorted;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// Creating stream failed.
    #[error(transparent)]
    CreateStream(BoxError),
    #[error(transparent)]
    FetchBuffer(BoxError),
    #[error("failed to generate stream source: {0}")]
    GenerateStreamSource(BoxError),
    #[allow(dead_code)]
    #[error("invalid stream source: `{0}`")]
    InvalidStreamSuorce(String),
    #[error("mismatched x[] and y[] for linear regression")]
    MismatchedSamples,
    #[error("do not have enough samples")]
    NotEnoughSamples,
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
    #[error(transparent)]
    WriteBuffer(io::Error),
}
