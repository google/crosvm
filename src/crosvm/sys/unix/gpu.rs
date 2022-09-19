// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! GPU related things
//! depends on "gpu" feature

#[cfg(feature = "virgl_renderer_next")]
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use super::*;
use crate::crosvm::config::Config;

pub struct GpuCacheInfo<'a> {
    directory: Option<&'a str>,
    environment: Vec<(&'a str, &'a str)>,
}

pub fn get_gpu_cache_info<'a>(
    cache_dir: Option<&'a String>,
    cache_size: Option<&'a String>,
    sandbox: bool,
) -> GpuCacheInfo<'a> {
    let mut dir = None;
    let mut env = Vec::new();

    // TODO (renatopereyra): Remove deprecated env vars once all src/third_party/mesa* are updated.
    if let Some(cache_dir) = cache_dir {
        if !Path::new(cache_dir).exists() {
            warn!("shader caching dir {} does not exist", cache_dir);
            // Deprecated in https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/15390
            env.push(("MESA_GLSL_CACHE_DISABLE", "true"));

            env.push(("MESA_SHADER_CACHE_DISABLE", "true"));
        } else if cfg!(any(target_arch = "arm", target_arch = "aarch64")) && sandbox {
            warn!("shader caching not yet supported on ARM with sandbox enabled");
            // Deprecated in https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/15390
            env.push(("MESA_GLSL_CACHE_DISABLE", "true"));

            env.push(("MESA_SHADER_CACHE_DISABLE", "true"));
        } else {
            dir = Some(cache_dir.as_str());

            // Deprecated in https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/15390
            env.push(("MESA_GLSL_CACHE_DISABLE", "false"));
            env.push(("MESA_GLSL_CACHE_DIR", cache_dir.as_str()));

            env.push(("MESA_SHADER_CACHE_DISABLE", "false"));
            env.push(("MESA_SHADER_CACHE_DIR", cache_dir.as_str()));

            env.push(("MESA_DISK_CACHE_DATABASE", "1"));

            if let Some(cache_size) = cache_size {
                // Deprecated in https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/15390
                env.push(("MESA_GLSL_CACHE_MAX_SIZE", cache_size.as_str()));

                env.push(("MESA_SHADER_CACHE_MAX_SIZE", cache_size.as_str()));
            }
        }
    }

    GpuCacheInfo {
        directory: dir,
        environment: env,
    }
}

pub fn create_gpu_device(
    cfg: &Config,
    exit_evt_wrtube: &SendTube,
    gpu_control_tube: Tube,
    resource_bridges: Vec<Tube>,
    wayland_socket_path: Option<&PathBuf>,
    x_display: Option<String>,
    #[cfg(feature = "virgl_renderer_next")] render_server_fd: Option<SafeDescriptor>,
    event_devices: Vec<EventDevice>,
) -> DeviceResult {
    let mut display_backends = vec![
        virtio::DisplayBackend::X(x_display),
        virtio::DisplayBackend::Stub,
    ];

    let wayland_socket_dirs = cfg
        .wayland_socket_paths
        .iter()
        .map(|(_name, path)| path.parent())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| anyhow!("wayland socket path has no parent or file name"))?;

    if let Some(socket_path) = wayland_socket_path {
        display_backends.insert(
            0,
            virtio::DisplayBackend::Wayland(Some(socket_path.to_owned())),
        );
    }

    let dev = virtio::Gpu::new(
        exit_evt_wrtube
            .try_clone()
            .context("failed to clone tube")?,
        gpu_control_tube,
        resource_bridges,
        display_backends,
        cfg.gpu_parameters.as_ref().unwrap(),
        #[cfg(feature = "virgl_renderer_next")]
        render_server_fd,
        event_devices,
        cfg.jail_config.is_some(),
        virtio::base_features(cfg.protection_type),
        cfg.wayland_socket_paths.clone(),
    );

    let jail = match gpu_jail(&cfg.jail_config, "gpu_device")? {
        Some(mut jail) => {
            // Prepare GPU shader disk cache directory.
            let (cache_dir, cache_size) = cfg
                .gpu_parameters
                .as_ref()
                .map(|params| (params.cache_path.as_ref(), params.cache_size.as_ref()))
                .unwrap();
            let cache_info = get_gpu_cache_info(cache_dir, cache_size, cfg.jail_config.is_some());

            if let Some(dir) = cache_info.directory {
                jail.mount_bind(dir, dir, true)?;
            }
            for (key, val) in cache_info.environment {
                env::set_var(key, val);
            }

            // Bind mount the wayland socket's directory into jail's root. This is necessary since
            // each new wayland context must open() the socket. If the wayland socket is ever
            // destroyed and remade in the same host directory, new connections will be possible
            // without restarting the wayland device.
            for dir in &wayland_socket_dirs {
                jail.mount_bind(dir, dir, true)?;
            }

            add_current_user_to_jail(&mut jail)?;

            Some(jail)
        }
        None => None,
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct GpuRenderServerParameters {
    pub path: PathBuf,
    pub cache_path: Option<String>,
    pub cache_size: Option<String>,
}

#[cfg(feature = "virgl_renderer_next")]
fn get_gpu_render_server_environment(cache_info: Option<&GpuCacheInfo>) -> Result<Vec<String>> {
    let mut env = HashMap::<String, String>::new();
    let os_env_len = env::vars_os().count();

    if let Some(cache_info) = cache_info {
        env.reserve(os_env_len + cache_info.environment.len());
        for (key, val) in cache_info.environment.iter() {
            env.insert(key.to_string(), val.to_string());
        }
    } else {
        env.reserve(os_env_len);
    }

    for (key_os, val_os) in env::vars_os() {
        // minijail should accept OsStr rather than str...
        let into_string_err = |_| anyhow!("invalid environment key/val");
        let key = key_os.into_string().map_err(into_string_err)?;
        let val = val_os.into_string().map_err(into_string_err)?;
        env.entry(key).or_insert(val);
    }

    // TODO(b/237493180): workaround to enable ETC2 format emulation in RADV for ARCVM
    if !env.contains_key("radv_require_etc2") {
        env.insert("radv_require_etc2".to_string(), "true".to_string());
    }

    Ok(env.iter().map(|(k, v)| format!("{}={}", k, v)).collect())
}

#[cfg(feature = "virgl_renderer_next")]
pub fn start_gpu_render_server(
    cfg: &Config,
    render_server_parameters: &GpuRenderServerParameters,
) -> Result<(Minijail, SafeDescriptor)> {
    let (server_socket, client_socket) =
        UnixSeqpacket::pair().context("failed to create render server socket")?;

    let (jail, cache_info) = match gpu_jail(&cfg.jail_config, "gpu_render_server")? {
        Some(mut jail) => {
            let cache_info = get_gpu_cache_info(
                render_server_parameters.cache_path.as_ref(),
                render_server_parameters.cache_size.as_ref(),
                true,
            );

            if let Some(dir) = cache_info.directory {
                jail.mount_bind(dir, dir, true)?;
            }

            // bind mount /dev/log for syslog
            let log_path = Path::new("/dev/log");
            if log_path.exists() {
                jail.mount_bind(log_path, log_path, true)?;
            }

            // Run as root in the jail to keep capabilities after execve, which is needed for
            // mounting to work.  All capabilities will be dropped afterwards.
            add_current_user_as_root_to_jail(&mut jail)?;

            (jail, Some(cache_info))
        }
        None => (Minijail::new().context("failed to create jail")?, None),
    };

    let inheritable_fds = [
        server_socket.as_raw_descriptor(),
        libc::STDOUT_FILENO,
        libc::STDERR_FILENO,
    ];

    let cmd = &render_server_parameters.path;
    let cmd_str = cmd
        .to_str()
        .ok_or_else(|| anyhow!("invalid render server path"))?;
    let fd_str = server_socket.as_raw_descriptor().to_string();
    let args = [cmd_str, "--socket-fd", &fd_str];

    let env = Some(get_gpu_render_server_environment(cache_info.as_ref())?);
    let mut envp: Option<Vec<&str>> = None;
    if let Some(ref env) = env {
        envp = Some(env.iter().map(AsRef::as_ref).collect());
    }

    jail.run_command(minijail::Command::new_for_path(
        cmd,
        &inheritable_fds,
        &args,
        envp.as_deref(),
    )?)
    .context("failed to start gpu render server")?;

    Ok((jail, SafeDescriptor::from(client_socket)))
}
