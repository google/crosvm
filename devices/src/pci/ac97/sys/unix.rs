// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use audio_streams::shm_streams::NullShmStreamSource;
use audio_streams::shm_streams::ShmStreamSource;
#[cfg(feature = "audio_cras")]
use base::error;
#[cfg(feature = "audio_cras")]
use libcras::CrasClient;
#[cfg(feature = "audio_cras")]
use libcras::CrasClientType;
#[cfg(feature = "audio_cras")]
use libcras::CrasSocketType;
use serde::Deserialize;
use serde::Serialize;
use vm_memory::GuestMemory;

use crate::pci::ac97::Ac97Dev;
use crate::pci::ac97::Ac97Error;
use crate::pci::ac97::Ac97Parameters;
#[cfg(feature = "audio_cras")]
use crate::pci::pci_device;
use crate::pci::pci_device::Result;

pub(crate) type AudioStreamSource = Box<dyn ShmStreamSource<base::Error>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ac97Backend {
    #[cfg(feature = "audio_cras")]
    Cras,
}

impl Ac97Dev {
    pub(in crate::pci::ac97) fn initialize_backend(
        ac97_backend: &Ac97Backend,
        #[allow(unused_variables)] mem: GuestMemory,
        #[allow(unused_variables)] param: &Ac97Parameters,
    ) -> Result<Self> {
        match *ac97_backend {
            #[cfg(feature = "audio_cras")]
            Ac97Backend::Cras => Self::create_cras_audio_device(param, mem.clone()).or_else(|e| {
                error!(
                    "Ac97Dev: create_cras_audio_device: {}. Fallback to null audio device",
                    e
                );
                Ok(Self::create_null_audio_device(mem))
            }),
        }
    }

    #[cfg(feature = "audio_cras")]
    fn create_cras_audio_device(params: &Ac97Parameters, mem: GuestMemory) -> Result<Self> {
        let mut server = Box::new(
            CrasClient::with_type(params.socket_type.unwrap_or(CrasSocketType::Unified))
                .map_err(pci_device::Error::CreateCrasClientFailed)?,
        );
        server.set_client_type(
            params
                .client_type
                .unwrap_or(CrasClientType::CRAS_CLIENT_TYPE_CROSVM),
        );
        if params.capture {
            server.enable_cras_capture();
        }

        let cras_audio = Self::new(
            mem,
            crate::pci::ac97::Ac97Backend::System(Ac97Backend::Cras),
            server,
        );
        Ok(cras_audio)
    }

    /// Return the minijail policy file path for the current Ac97Dev.
    pub fn minijail_policy(&self) -> &'static str {
        match &self.backend {
            crate::pci::ac97::Ac97Backend::System(backend) => match *backend {
                #[cfg(feature = "audio_cras")]
                Ac97Backend::Cras => "cras_audio_device",
            },
            crate::pci::ac97::Ac97Backend::NULL => "null_audio_device",
        }
    }
}

pub(in crate::pci::ac97) fn ac97_backend_from_str(
    s: &str,
) -> std::result::Result<crate::pci::ac97::Ac97Backend, Ac97Error> {
    match s {
        #[cfg(feature = "audio_cras")]
        "cras" => Ok(crate::pci::ac97::Ac97Backend::System(Ac97Backend::Cras)),
        _ => Err(Ac97Error::InvalidBackend),
    }
}

pub(in crate::pci::ac97) fn create_null_server() -> AudioStreamSource {
    Box::new(NullShmStreamSource::new())
}

#[cfg(test)]
pub(in crate::pci::ac97) mod tests {
    use audio_streams::shm_streams::MockShmStreamSource;

    use super::*;

    pub(in crate::pci::ac97) fn create_ac97_device(
        mem: GuestMemory,
        backend: crate::pci::ac97::Ac97Backend,
    ) -> Ac97Dev {
        Ac97Dev::new(mem, backend, Box::new(MockShmStreamSource::new()))
    }
}
