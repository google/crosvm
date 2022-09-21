// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Minimal implementation of interfaces in libcras for external builds.
//
// These just exist to allow us to build and clippy check the audio feature
// when building outside of ChromeOS. When building for ChromeOS, this stub
// will be replaced by the actual libcras implementation:
// https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/third_party/adhd/cras/client/libcras/
//
// Any changes to the libcras API used in crosvm needs to be reflected in this
// stub as well so as to have a successful crosvm build outside of ChromeOS.
//
// Instantiating a CrasClient using this will always panic!

use audio_streams::{
    shm_streams::{SharedMemory, ShmStream, ShmStreamSource},
    BoxError, SampleFormat, StreamDirection, StreamEffect, StreamSource, StreamSourceGenerator,
};
use std::error;
use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[allow(non_camel_case_types)]
pub enum CRAS_CLIENT_TYPE {
    CRAS_CLIENT_TYPE_ARCVM,
    CRAS_CLIENT_TYPE_CROSVM,
}

pub type CrasClientType = CRAS_CLIENT_TYPE;

#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CrasSocketType {
    Legacy,
    Unified,
}

#[derive(Debug)]
pub enum Error {
    InvalidClientType,
    InvalidSocketType,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "")
    }
}

impl error::Error for Error {}

pub type CrasSysError = Error;

impl FromStr for CrasClientType {
    type Err = CrasSysError;
    fn from_str(cras_type: &str) -> std::result::Result<Self, Self::Err> {
        match cras_type {
            "crosvm" => Ok(CrasClientType::CRAS_CLIENT_TYPE_CROSVM),
            "arcvm" => Ok(CrasClientType::CRAS_CLIENT_TYPE_ARCVM),
            _ => Err(Error::InvalidClientType),
        }
    }
}

impl FromStr for CrasSocketType {
    type Err = Error;
    fn from_str(sock_type: &str) -> std::result::Result<Self, Self::Err> {
        match sock_type {
            "legacy" => Ok(CrasSocketType::Legacy),
            "unified" => Ok(CrasSocketType::Unified),
            _ => Err(Error::InvalidSocketType),
        }
    }
}

pub struct CrasStreamSourceGenerator {}

impl CrasStreamSourceGenerator {
    pub fn new(_capture: bool, _client_type: CrasClientType, _socket_type: CrasSocketType) -> Self {
        panic!("Cannot create cras audio device on non-chromeos crosvm builds.")
    }
}

impl StreamSourceGenerator for CrasStreamSourceGenerator {
    fn generate(&self) -> std::result::Result<Box<dyn StreamSource>, BoxError> {
        panic!("Cannot create cras audio device on non-chromeos crosvm builds.")
    }
}

pub fn deserialize_cras_client_type<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<CRAS_CLIENT_TYPE, D::Error> {
    let s = String::deserialize(deserializer)?;

    match s.parse() {
        Ok(client_type) => Ok(client_type),
        Err(e) => Err(serde::de::Error::custom(e.to_string())),
    }
}

type Result<T> = std::result::Result<T, Error>;

pub struct CrasClient {}
impl CrasClient {
    pub fn with_type(_: CrasSocketType) -> Result<Self> {
        panic!("Cannot create cras audio device on non-chromeos crosvm builds.")
    }
    pub fn set_client_type(&mut self, _: CrasClientType) {}
    pub fn enable_cras_capture(&mut self) {}
}

impl<E: std::error::Error> ShmStreamSource<E> for CrasClient {
    fn new_stream(
        &mut self,
        _direction: StreamDirection,
        _num_channels: usize,
        _format: SampleFormat,
        _frame_rate: u32,
        _buffer_size: usize,
        _effects: &[StreamEffect],
        _client_shm: &dyn SharedMemory<Error = E>,
        _buffer_offsets: [u64; 2],
    ) -> std::result::Result<Box<dyn ShmStream>, BoxError> {
        panic!("Cannot create cras audio device on non-chromeos crosvm builds.")
    }
}
