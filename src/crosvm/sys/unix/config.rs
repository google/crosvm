// Copyright 2022 The Chromium OS Authors. All rights reserved.,
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use devices::SerialParameters;

use crate::crosvm::config::Config;

#[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
pub fn parse_gpu_render_server_options(
    s: &str,
) -> Result<crate::crosvm::platform::GpuRenderServerParameters, String> {
    use std::{path::PathBuf, str::FromStr};

    use crate::crosvm::{config::invalid_value_err, platform::GpuRenderServerParameters};

    let mut path: Option<PathBuf> = None;
    let mut cache_path = None;
    let mut cache_size = None;

    let opts = s
        .split(',')
        .map(|frag| frag.split('='))
        .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

    for (k, v) in opts {
        match k {
            "path" => path = Some(PathBuf::from_str(v).map_err(|e| invalid_value_err(v, e))?),
            "cache-path" => cache_path = Some(v.to_string()),
            "cache-size" => cache_size = Some(v.to_string()),
            "" => {}
            _ => {
                return Err(format!("invalid gpu-render-server parameter {}", k));
            }
        }
    }

    if let Some(p) = path {
        Ok(GpuRenderServerParameters {
            path: p,
            cache_path,
            cache_size,
        })
    } else {
        Err(invalid_value_err(
            s,
            "gpu-render-server must include 'path'",
        ))
    }
}

#[cfg(feature = "audio")]
pub fn parse_ac97_options(
    ac97_params: &mut devices::Ac97Parameters,
    key: &str,
    #[allow(unused_variables)] value: &str,
) -> Result<(), String> {
    use std::{path::PathBuf, str::FromStr};

    match key {
        #[cfg(feature = "audio_cras")]
        "client_type" => {
            ac97_params
                .set_client_type(value)
                .map_err(|e| crate::crosvm::config::invalid_value_err(value, e))?;
        }
        #[cfg(feature = "audio_cras")]
        "socket_type" => {
            ac97_params
                .set_socket_type(value)
                .map_err(|e| crate::crosvm::config::invalid_value_err(value, e))?;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        "server" => {
            ac97_params.vios_server_path = Some(
                PathBuf::from_str(value)
                    .map_err(|e| crate::crosvm::config::invalid_value_err(value, e))?,
            );
        }
        _ => {
            return Err(format!("unknown ac97 parameter {}", key));
        }
    };
    Ok(())
}

#[cfg(feature = "audio")]
pub fn check_ac97_backend(
    #[allow(unused_variables)] ac97_params: &devices::Ac97Parameters,
) -> Result<(), String> {
    // server is required for and exclusive to vios backend
    #[cfg(target_os = "android")]
    match ac97_params.backend {
        Ac97Backend::VIOS => {
            if ac97_params.vios_server_path.is_none() {
                return Err(String::from("server argument is required for VIOS backend"));
            }
        }
        _ => {
            if ac97_params.vios_server_path.is_some() {
                return Err(String::from(
                    "server argument is exclusive to the VIOS backend",
                ));
            }
        }
    }

    Ok(())
}

pub fn parse_coiommu_params(value: &str) -> Result<devices::CoIommuParameters, String> {
    let mut params: devices::CoIommuParameters = Default::default();

    let opts = value
        .split(',')
        .map(|frag| frag.splitn(2, '='))
        .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

    for (k, v) in opts {
        match k {
            "unpin_policy" => {
                params.unpin_policy = v
                    .parse::<devices::CoIommuUnpinPolicy>()
                    .map_err(|e| format!("{}", e))?
            }
            "unpin_interval" => {
                params.unpin_interval =
                    Duration::from_secs(v.parse::<u64>().map_err(|e| format!("{}", e))?)
            }
            "unpin_limit" => {
                let limit = v.parse::<u64>().map_err(|e| format!("{}", e))?;

                if limit == 0 {
                    return Err(String::from("Please use non-zero unpin_limit value"));
                }

                params.unpin_limit = Some(limit)
            }
            "unpin_gen_threshold" => {
                params.unpin_gen_threshold = v
                    .parse::<u64>()
                    .map_err(|e| format!("unknown argument: {}", e))?
            }
            _ => {
                return Err(format!("coiommu parameter {}", k));
            }
        }
    }
    Ok(params)
}

#[cfg(feature = "gpu")]
pub fn is_gpu_backend_deprecated(_backend: &str) -> bool {
    false
}

#[cfg(feature = "gfxstream")]
pub fn use_vulkan() -> bool {
    true
}

// Doesn't do anything on unix.
pub fn check_serial_params(_serial_params: &SerialParameters) -> Result<(), String> {
    Ok(())
}

pub fn validate_config(cfg: &mut Config) -> std::result::Result<(), String> {
    crate::crosvm::check_opt_path!(cfg.vhost_vsock_device);
    if cfg.host_ip.is_some() || cfg.netmask.is_some() || cfg.mac_address.is_some() {
        if cfg.host_ip.is_none() {
            return Err("`host-ip` missing from network config".to_string());
        }
        if cfg.netmask.is_none() {
            return Err("`netmask` missing from network config".to_string());
        }
        if cfg.mac_address.is_none() {
            return Err("`mac` missing from network config".to_string());
        }
    }

    Ok(())
}
