// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Serializable enum wrappers for all device module types. This is a workaround for the fact that
//! `Config` must be serde compatible, it can't contain `dyn VirtioDeviceModule`.

use anyhow::Result;
use devices::virtio::VirtioDevice;
use devices::VirtioDeviceArgs;
use devices::VirtioDeviceModule;
#[cfg(any(target_os = "android", target_os = "linux"))]
use jail::JailConfig;
#[cfg(any(target_os = "android", target_os = "linux"))]
use minijail::Minijail;
use serde::Deserialize;
use serde::Serialize;

macro_rules! declare_any_virtio_device_module {
    (
        $(#[$meta:meta])*
        pub enum $enum_name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident($module_type:ty),
            )*
        }
    ) => {
        $(#[$meta])*
        pub enum $enum_name {
            $(
                $(#[$variant_meta])*
                $variant($module_type),
            )*
        }

        $(
            $(#[$variant_meta])*
            impl From<$module_type> for $enum_name {
                fn from(m: $module_type) -> Self {
                    $enum_name::$variant(m)
                }
            }
        )*

        impl VirtioDeviceModule for $enum_name {
            fn sort_name(&self) -> &'static str {
                match self {
                    $(
                        $(#[$variant_meta])*
                        $enum_name::$variant(m) => m.sort_name(),
                    )*
                }
            }

            fn create(&self, cx: &mut VirtioDeviceArgs<'_>) -> Result<Box<dyn VirtioDevice>> {
                match self {
                    $(
                        $(#[$variant_meta])*
                        $enum_name::$variant(m) => m.create(cx),
                    )*
                }
            }

            #[cfg(any(target_os = "android", target_os = "linux"))]
            fn create_jail(&self, jail_config: &JailConfig) -> Result<Option<Minijail>> {
                match self {
                    $(
                        $(#[$variant_meta])*
                        $enum_name::$variant(m) => m.create_jail(jail_config),
                    )*
                }
            }
        }
    };
}

declare_any_virtio_device_module! {
    #[derive(Serialize, Deserialize)]
    pub enum AnyVirtioDeviceModule {
        Placeholder(PlaceholderModule),
    }
}

// TODO: Delete when the first real module is added.
#[derive(Serialize, Deserialize)]
pub struct PlaceholderModule;

impl VirtioDeviceModule for PlaceholderModule {
    fn sort_name(&self) -> &'static str {
        unreachable!()
    }
    fn create(&self, _cx: &mut VirtioDeviceArgs<'_>) -> Result<Box<dyn VirtioDevice>> {
        unreachable!()
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn create_jail(&self, _jail_config: &JailConfig) -> Result<Option<Minijail>> {
        unreachable!()
    }
}
