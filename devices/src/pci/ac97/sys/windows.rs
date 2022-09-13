// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use audio_streams::NoopStreamSource;
use base::Tube;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use vm_memory::GuestMemory;
use win_audio::create_win_audio_device;
use win_audio::WinAudioServer;

use crate::pci::ac97::Ac97Dev;
use crate::pci::ac97::Ac97Error;
use crate::pci::ac97::Ac97Parameters;
use crate::pci::pci_device::Result;

pub(crate) type AudioStreamSource = Arc<Mutex<dyn WinAudioServer>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ac97Backend {
    WinAudio,
}

impl Ac97Dev {
    pub(in crate::pci::ac97) fn initialize_backend(
        ac97_backend: &Ac97Backend,
        mem: GuestMemory,
        _param: &Ac97Parameters,
        ac97_device_tube: Tube,
    ) -> Result<Self> {
        match ac97_backend {
            Ac97Backend::WinAudio => {
                let win_audio = Arc::new(Mutex::new(create_win_audio_device().unwrap()));

                let win_audio_device = Self::new(
                    mem,
                    crate::pci::ac97::Ac97Backend::System(Ac97Backend::WinAudio),
                    win_audio,
                    Some(ac97_device_tube),
                );
                Ok(win_audio_device)
            }
        }
    }
}

pub(in crate::pci::ac97) fn ac97_backend_from_str(
    s: &str,
) -> std::result::Result<crate::pci::ac97::Ac97Backend, Ac97Error> {
    match s {
        "win_audio" => Ok(crate::pci::ac97::Ac97Backend::System(Ac97Backend::WinAudio)),
        _ => Err(Ac97Error::InvalidBackend),
    }
}

pub(in crate::pci::ac97) fn create_null_server() -> AudioStreamSource {
    Arc::new(Mutex::new(NoopStreamSource::new()))
}

#[cfg(test)]
pub(in crate::pci::ac97) mod tests {
    use std::sync::Arc;

    use audio_streams::NoopStreamSource;
    use sync::Mutex;

    use super::*;

    pub(in crate::pci::ac97) fn create_ac97_device(
        mem: GuestMemory,
        backend: crate::pci::ac97::Ac97Backend,
    ) -> Ac97Dev {
        Ac97Dev::new(
            mem,
            backend,
            Arc::new(Mutex::new(NoopStreamSource::new())),
            None,
        )
    }
}
