// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! GPU related things
//! depends on "gpu" feature
static_assertions::assert_cfg!(feature = "gpu");

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use base::platform::move_proc_to_cgroup;
use jail::*;
use serde::Deserialize;
use serde::Serialize;
use serde_keyvalue::FromKeyValues;

use super::*;
use crate::crosvm::config::Config;

pub struct GpuCacheInfo<'a> {
    directory: Option<&'a str>,
    environment: Vec<(&'a str, &'a str)>,
}

pub fn get_gpu_cache_info<'a>(
    cache_dir: Option<&'a String>,
    cache_size: Option<&'a String>,
    foz_db_list_path: Option<&'a String>,
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

            if let Some(foz_db_list_path) = foz_db_list_path {
                env.push(("MESA_DISK_CACHE_COMBINE_RW_WITH_RO_FOZ", "1"));
                env.push((
                    "MESA_DISK_CACHE_READ_ONLY_FOZ_DBS_DYNAMIC_LIST",
                    foz_db_list_path,
                ));
            }

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
    render_server_fd: Option<SafeDescriptor>,
    event_devices: Vec<EventDevice>,
) -> DeviceResult {
    let is_sandboxed = cfg.jail_config.is_some();
    let mut gpu_params = cfg.gpu_parameters.clone().unwrap();
    gpu_params.external_blob = is_sandboxed;
    gpu_params.allow_implicit_render_server_exec = !is_sandboxed;

    let mut display_backends = vec![
        virtio::DisplayBackend::X(cfg.x_display.clone()),
        virtio::DisplayBackend::Stub,
    ];

    // Use the unnamed socket for GPU display screens.
    if let Some(socket_path) = cfg.wayland_socket_paths.get("") {
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
        &gpu_params,
        render_server_fd,
        event_devices,
        virtio::base_features(cfg.protection_type),
        &cfg.wayland_socket_paths,
        cfg.gpu_cgroup_path.as_ref(),
    );

    let jail = if let Some(jail_config) = &cfg.jail_config {
        let mut config = SandboxConfig::new(jail_config, "gpu_device");
        config.bind_mounts = true;
        // Allow changes made externally take effect immediately to allow shaders to be dynamically
        // added by external processes.
        config.remount_mode = Some(libc::MS_SLAVE);
        let mut jail = create_gpu_minijail(&jail_config.pivot_root, &config)?;

        // Prepare GPU shader disk cache directory.
        let cache_info = get_gpu_cache_info(
            gpu_params.cache_path.as_ref(),
            gpu_params.cache_size.as_ref(),
            None,
            cfg.jail_config.is_some(),
        );

        if let Some(dir) = cache_info.directory {
            // Manually bind mount recursively to allow DLC shader caches
            // to be propagated to the GPU process.
            jail.mount(dir, dir, "", (libc::MS_BIND | libc::MS_REC) as usize)?;
        }
        for (key, val) in cache_info.environment {
            env::set_var(key, val);
        }

        // Bind mount the wayland socket's directory into jail's root. This is necessary since
        // each new wayland context must open() the socket. If the wayland socket is ever
        // destroyed and remade in the same host directory, new connections will be possible
        // without restarting the wayland device.
        for socket_path in cfg.wayland_socket_paths.values() {
            let dir = socket_path.parent().with_context(|| {
                format!(
                    "wayland socket path '{}' has no parent",
                    socket_path.display(),
                )
            })?;
            jail.mount_bind(dir, dir, true)?;
        }

        Some(jail)
    } else {
        None
    };

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        jail,
    })
}

#[derive(Debug, Deserialize, Serialize, FromKeyValues, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct GpuRenderServerParameters {
    pub path: PathBuf,
    pub cache_path: Option<String>,
    pub cache_size: Option<String>,
    pub foz_db_list_path: Option<String>,
    pub precompiled_cache_path: Option<String>,
}

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

pub fn start_gpu_render_server(
    cfg: &Config,
    render_server_parameters: &GpuRenderServerParameters,
) -> Result<(Minijail, SafeDescriptor)> {
    let (server_socket, client_socket) =
        UnixSeqpacket::pair().context("failed to create render server socket")?;

    let (jail, cache_info) = if let Some(jail_config) = &cfg.jail_config {
        let mut config = SandboxConfig::new(jail_config, "gpu_render_server");
        // Allow changes made externally take effect immediately to allow shaders to be dynamically
        // added by external processes.
        config.remount_mode = Some(libc::MS_SLAVE);
        config.bind_mounts = true;
        // Run as root in the jail to keep capabilities after execve, which is needed for
        // mounting to work.  All capabilities will be dropped afterwards.
        config.run_as = RunAsUser::Root;
        let mut jail = create_gpu_minijail(&jail_config.pivot_root, &config)?;

        let cache_info = get_gpu_cache_info(
            render_server_parameters.cache_path.as_ref(),
            render_server_parameters.cache_size.as_ref(),
            render_server_parameters.foz_db_list_path.as_ref(),
            true,
        );

        if let Some(dir) = cache_info.directory {
            // Manually bind mount recursively to allow DLC shader caches
            // to be propagated to the GPU process.
            jail.mount(dir, dir, "", (libc::MS_BIND | libc::MS_REC) as usize)?;
        }
        if let Some(precompiled_cache_dir) = &render_server_parameters.precompiled_cache_path {
            jail.mount_bind(precompiled_cache_dir, precompiled_cache_dir, true)?;
        }

        // bind mount /dev/log for syslog
        let log_path = Path::new("/dev/log");
        if log_path.exists() {
            jail.mount_bind(log_path, log_path, true)?;
        }

        (jail, Some(cache_info))
    } else {
        (Minijail::new().context("failed to create jail")?, None)
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

    let render_server_pid = jail
        .run_command(minijail::Command::new_for_path(
            cmd,
            &inheritable_fds,
            &args,
            envp.as_deref(),
        )?)
        .context("failed to start gpu render server")?;

    if let Some(gpu_server_cgroup_path) = &cfg.gpu_server_cgroup_path {
        move_proc_to_cgroup(gpu_server_cgroup_path.to_path_buf(), render_server_pid)?;
    }

    Ok((jail, SafeDescriptor::from(client_socket)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crosvm::config::from_key_values;

    #[test]
    fn parse_gpu_render_server_parameters() {
        let res: GpuRenderServerParameters = from_key_values("path=/some/path").unwrap();
        assert_eq!(
            res,
            GpuRenderServerParameters {
                path: "/some/path".into(),
                cache_path: None,
                cache_size: None,
                foz_db_list_path: None,
                precompiled_cache_path: None,
            }
        );

        let res: GpuRenderServerParameters = from_key_values("/some/path").unwrap();
        assert_eq!(
            res,
            GpuRenderServerParameters {
                path: "/some/path".into(),
                cache_path: None,
                cache_size: None,
                foz_db_list_path: None,
                precompiled_cache_path: None,
            }
        );

        let res: GpuRenderServerParameters =
            from_key_values("path=/some/path,cache-path=/cache/path,cache-size=16M").unwrap();
        assert_eq!(
            res,
            GpuRenderServerParameters {
                path: "/some/path".into(),
                cache_path: Some("/cache/path".into()),
                cache_size: Some("16M".into()),
                foz_db_list_path: None,
                precompiled_cache_path: None,
            }
        );

        let res: GpuRenderServerParameters = from_key_values(
            "path=/some/path,cache-path=/cache/path,cache-size=16M,foz-db-list-path=/db/list/path,precompiled-cache-path=/precompiled/path",
        )
        .unwrap();
        assert_eq!(
            res,
            GpuRenderServerParameters {
                path: "/some/path".into(),
                cache_path: Some("/cache/path".into()),
                cache_size: Some("16M".into()),
                foz_db_list_path: Some("/db/list/path".into()),
                precompiled_cache_path: Some("/precompiled/path".into()),
            }
        );

        let res =
            from_key_values::<GpuRenderServerParameters>("cache-path=/cache/path,cache-size=16M");
        assert!(res.is_err());

        let res = from_key_values::<GpuRenderServerParameters>("");
        assert!(res.is_err());
    }
}
