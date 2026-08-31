// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod common;
pub mod constants;
pub mod layout;
pub mod parameters;
pub mod sys;

pub mod common_backend;
pub mod file_backend;
pub mod null_backend;
pub mod vhost_user;

pub use vhost_user::run_snd_device;
pub use vhost_user::Options as SndOptions;

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        pub mod vios_backend;

        pub use vios_backend::new_sound;
        pub use vios_backend::SoundError;
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
use anyhow::Context;
use devices::virtio::VirtioDevice;
use devices::VirtioDeviceArgs;
use devices::VirtioDeviceModule;
use serde::Deserialize;
use serde::Serialize;
#[cfg(any(target_os = "android", target_os = "linux"))]
use vm_control::AnyControlTube;

use self::parameters::Parameters;

#[derive(Serialize, Deserialize)]
pub struct VirtioSndModule {
    pub params: Parameters,
}

impl VirtioSndModule {
    pub fn new(params: Parameters) -> Self {
        Self { params }
    }
}

impl VirtioDeviceModule for VirtioSndModule {
    fn sort_name(&self) -> &'static str {
        "snd"
    }

    fn create(&self, args: &mut VirtioDeviceArgs<'_>) -> anyhow::Result<Box<dyn VirtioDevice>> {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            let (snd_host_tube, snd_device_tube) =
                base::Tube::pair().context("failed to create tube for snd")?;

            let dev = common_backend::VirtioSnd::new(
                devices::virtio::base_features(args.protection_type),
                self.params.clone(),
                snd_device_tube,
            )
            .context("failed to create cras sound device")?;

            (args.add_control_tube)(AnyControlTube::Snd(snd_host_tube));

            Ok(Box::new(dev))
        }
        #[cfg(windows)]
        {
            let _ = args;
            anyhow::bail!("snd device not supported on Windows")
        }
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn create_jail(
        &self,
        jail_config: &jail::JailConfig,
    ) -> anyhow::Result<Option<minijail::Minijail>> {
        sys::linux::create_jail(&self.params, jail_config)
    }
}
