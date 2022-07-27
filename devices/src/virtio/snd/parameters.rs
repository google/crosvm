// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::num::ParseIntError;
use std::str::FromStr;
use std::str::ParseBoolError;

#[cfg(all(unix, feature = "audio_cras"))]
use libcras::CrasClientType;
#[cfg(all(unix, feature = "audio_cras"))]
use libcras::CrasSocketType;
use thiserror::Error as ThisError;

use crate::virtio::snd::sys::parse_args;
use crate::virtio::snd::sys::StreamSourceBackend as SysStreamSourceBackend;

#[derive(ThisError, Debug)]
pub enum Error {
    /// Unknown snd parameter value.
    #[error("Invalid snd parameter value ({0}): {1}")]
    InvalidParameterValue(String, String),
    /// Failed to parse bool value.
    #[error("Invalid bool value: {0}")]
    InvalidBoolValue(ParseBoolError),
    /// Failed to parse int value.
    #[error("Invalid int value: {0}")]
    InvalidIntValue(ParseIntError),
    // Invalid backend.
    #[error("Backend is not implemented")]
    InvalidBackend,
    /// Failed to parse parameters.
    #[error("Invalid snd parameter: {0}")]
    UnknownParameter(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamSourceBackend {
    NULL,
    Sys(SysStreamSourceBackend),
}

impl FromStr for StreamSourceBackend {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "null" => Ok(StreamSourceBackend::NULL),
            _ => s
                .parse::<SysStreamSourceBackend>()
                .map(StreamSourceBackend::Sys),
        }
    }
}

/// Holds the parameters for a cras sound device
#[derive(Debug, Clone)]
pub struct Parameters {
    pub capture: bool,
    pub num_output_devices: u32,
    pub num_input_devices: u32,
    pub backend: StreamSourceBackend,
    pub num_output_streams: u32,
    pub num_input_streams: u32,
    #[cfg(all(unix, feature = "audio_cras"))]
    pub client_type: CrasClientType,
    #[cfg(all(unix, feature = "audio_cras"))]
    pub socket_type: CrasSocketType,
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters {
            capture: false,
            num_output_devices: 1,
            num_input_devices: 1,
            backend: StreamSourceBackend::NULL,
            num_output_streams: 1,
            num_input_streams: 1,
            #[cfg(all(unix, feature = "audio_cras"))]
            client_type: CrasClientType::CRAS_CLIENT_TYPE_CROSVM,
            #[cfg(all(unix, feature = "audio_cras"))]
            socket_type: CrasSocketType::Unified,
        }
    }
}

impl Parameters {
    pub(crate) fn get_total_output_streams(&self) -> u32 {
        self.num_output_devices * self.num_output_streams
    }

    pub(crate) fn get_total_input_streams(&self) -> u32 {
        self.num_input_devices * self.num_input_streams
    }

    pub(crate) fn get_total_streams(&self) -> u32 {
        self.get_total_output_streams() + self.get_total_input_streams()
    }
}

impl FromStr for Parameters {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut params: Parameters = Default::default();
        let opts = s
            .split(',')
            .map(|frag| frag.split('='))
            .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

        for (k, v) in opts {
            match k {
                "capture" => {
                    params.capture = v.parse::<bool>().map_err(Error::InvalidBoolValue)?;
                }
                "backend" => {
                    params.backend = v.parse().map_err(|e: Error| {
                        Error::InvalidParameterValue(v.to_string(), e.to_string())
                    })?;
                }
                "num_output_devices" => {
                    params.num_output_devices = v.parse::<u32>().map_err(Error::InvalidIntValue)?;
                }
                "num_input_devices" => {
                    params.num_input_devices = v.parse::<u32>().map_err(Error::InvalidIntValue)?;
                }
                "num_output_streams" => {
                    params.num_output_streams = v.parse::<u32>().map_err(Error::InvalidIntValue)?;
                }
                "num_input_streams" => {
                    params.num_input_streams = v.parse::<u32>().map_err(Error::InvalidIntValue)?;
                }
                _ => {
                    parse_args(&mut params, k, v)?;
                }
            }
        }

        Ok(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_failure(s: &str) {
        s.parse::<Parameters>()
            .expect_err("parse should have failed");
    }

    fn check_success(
        s: &str,
        capture: bool,
        backend: StreamSourceBackend,
        num_output_devices: u32,
        num_input_devices: u32,
        num_output_streams: u32,
        num_input_streams: u32,
    ) {
        let params = s.parse::<Parameters>().expect("parse should have succeded");
        assert_eq!(params.capture, capture);
        assert_eq!(params.backend, backend);
        assert_eq!(params.num_output_devices, num_output_devices);
        assert_eq!(params.num_input_devices, num_input_devices);
        assert_eq!(params.num_output_streams, num_output_streams);
        assert_eq!(params.num_input_streams, num_input_streams);
    }

    #[test]
    fn parameters_fromstr() {
        check_failure("capture=none");
        check_success(
            "capture=false",
            false,
            StreamSourceBackend::NULL,
            1,
            1,
            1,
            1,
        );
        check_success(
            "capture=true,num_output_streams=2,num_input_streams=3",
            true,
            StreamSourceBackend::NULL,
            1,
            1,
            2,
            3,
        );
        check_success(
            "capture=true,num_output_devices=3,num_input_devices=2",
            true,
            StreamSourceBackend::NULL,
            3,
            2,
            1,
            1,
        );
        check_success(
            "capture=true,num_output_devices=2,num_input_devices=3,\
            num_output_streams=3,num_input_streams=2",
            true,
            StreamSourceBackend::NULL,
            2,
            3,
            3,
            2,
        );
        check_success(
            "capture=true,backend=null,num_output_devices=2,num_input_devices=3,\
            num_output_streams=3,num_input_streams=2",
            true,
            StreamSourceBackend::NULL,
            2,
            3,
            3,
            2,
        );
    }

    #[test]
    #[cfg(all(unix, feature = "audio_cras"))]
    fn cras_parameters_fromstr() {
        fn cras_check_success(
            s: &str,
            backend: StreamSourceBackend,
            client_type: CrasClientType,
            socket_type: CrasSocketType,
        ) {
            let params = s.parse::<Parameters>().expect("parse should have succeded");
            assert_eq!(params.backend, backend);
            assert_eq!(params.client_type, client_type);
            assert_eq!(params.socket_type, socket_type);
        }

        cras_check_success(
            "backend=cras",
            StreamSourceBackend::Sys(SysStreamSourceBackend::CRAS),
            CrasClientType::CRAS_CLIENT_TYPE_CROSVM,
            CrasSocketType::Unified,
        );
        cras_check_success(
            "backend=cras,client_type=crosvm",
            StreamSourceBackend::Sys(SysStreamSourceBackend::CRAS),
            CrasClientType::CRAS_CLIENT_TYPE_CROSVM,
            CrasSocketType::Unified,
        );
        cras_check_success(
            "backend=cras,client_type=arcvm",
            StreamSourceBackend::Sys(SysStreamSourceBackend::CRAS),
            CrasClientType::CRAS_CLIENT_TYPE_ARCVM,
            CrasSocketType::Unified,
        );
        check_failure("backend=cras,client_type=none");
        cras_check_success(
            "backend=cras,socket_type=legacy",
            StreamSourceBackend::Sys(SysStreamSourceBackend::CRAS),
            CrasClientType::CRAS_CLIENT_TYPE_CROSVM,
            CrasSocketType::Legacy,
        );
        cras_check_success(
            "backend=cras,socket_type=unified",
            StreamSourceBackend::Sys(SysStreamSourceBackend::CRAS),
            CrasClientType::CRAS_CLIENT_TYPE_CROSVM,
            CrasSocketType::Unified,
        );
    }
}
