// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! GPU related things
//! depends on "gpu" feature
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;

use devices::virtio::vhost::user::vmm::Gpu as VhostUserGpu;

use crate::{JailConfig, VhostUserOption};

use super::*;

pub fn create_vhost_user_gpu_device(
    cfg: &Config,
    opt: &VhostUserOption,
    gpu_tubes: (Tube, Tube),
    device_control_tube: Tube,
) -> DeviceResult {
    // The crosvm gpu device expects us to connect the tube before it will accept a vhost-user
    // connection.
    let dev = VhostUserGpu::new(
        virtio::base_features(cfg.protected_vm),
        &opt.socket,
        gpu_tubes,
        device_control_tube,
    )
    .context("failed to set up vhost-user gpu device")?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
        // no sandbox here because virtqueue handling is exported to a different process.
        jail: None,
    })
}

pub fn gpu_jail(jail_config: &Option<JailConfig>, policy: &str) -> Result<Option<Minijail>> {
    match simple_jail(jail_config, policy)? {
        Some(mut jail) => {
            // Create a tmpfs in the device's root directory so that we can bind mount the
            // dri directory into it.  The size=67108864 is size=64*1024*1024 or size=64MB.
            jail.mount_with_data(
                Path::new("none"),
                Path::new("/"),
                "tmpfs",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                "size=67108864",
            )?;

            // Device nodes required for DRM.
            let sys_dev_char_path = Path::new("/sys/dev/char");
            jail.mount_bind(sys_dev_char_path, sys_dev_char_path, false)?;
            let sys_devices_path = Path::new("/sys/devices");
            jail.mount_bind(sys_devices_path, sys_devices_path, false)?;

            let drm_dri_path = Path::new("/dev/dri");
            if drm_dri_path.exists() {
                jail.mount_bind(drm_dri_path, drm_dri_path, false)?;
            }

            // If the ARM specific devices exist on the host, bind mount them in.
            let mali0_path = Path::new("/dev/mali0");
            if mali0_path.exists() {
                jail.mount_bind(mali0_path, mali0_path, true)?;
            }

            let pvr_sync_path = Path::new("/dev/pvr_sync");
            if pvr_sync_path.exists() {
                jail.mount_bind(pvr_sync_path, pvr_sync_path, true)?;
            }

            // If the udmabuf driver exists on the host, bind mount it in.
            let udmabuf_path = Path::new("/dev/udmabuf");
            if udmabuf_path.exists() {
                jail.mount_bind(udmabuf_path, udmabuf_path, true)?;
            }

            // Libraries that are required when mesa drivers are dynamically loaded.
            jail_mount_bind_if_exists(
                &mut jail,
                &[
                    "/usr/lib",
                    "/usr/lib64",
                    "/lib",
                    "/lib64",
                    "/usr/share/drirc.d",
                    "/usr/share/glvnd",
                    "/usr/share/vulkan",
                ],
            )?;

            // pvr driver requires read access to /proc/self/task/*/comm.
            let proc_path = Path::new("/proc");
            jail.mount(
                proc_path,
                proc_path,
                "proc",
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY) as usize,
            )?;

            // To enable perfetto tracing, we need to give access to the perfetto service IPC
            // endpoints.
            let perfetto_path = Path::new("/run/perfetto");
            if perfetto_path.exists() {
                jail.mount_bind(perfetto_path, perfetto_path, true)?;
            }

            Ok(Some(jail))
        }
        None => Ok(None),
    }
}

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

    if let Some(cache_dir) = cache_dir {
        if !Path::new(cache_dir).exists() {
            warn!("shader caching dir {} does not exist", cache_dir);
            env.push(("MESA_GLSL_CACHE_DISABLE", "true"));
        } else if cfg!(any(target_arch = "arm", target_arch = "aarch64")) && sandbox {
            warn!("shader caching not yet supported on ARM with sandbox enabled");
            env.push(("MESA_GLSL_CACHE_DISABLE", "true"));
        } else {
            dir = Some(cache_dir.as_str());

            env.push(("MESA_GLSL_CACHE_DISABLE", "false"));
            env.push(("MESA_GLSL_CACHE_DIR", cache_dir.as_str()));
            if let Some(cache_size) = cache_size {
                env.push(("MESA_GLSL_CACHE_MAX_SIZE", cache_size.as_str()));
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
    exit_evt: &Event,
    gpu_device_tube: Tube,
    resource_bridges: Vec<Tube>,
    wayland_socket_path: Option<&PathBuf>,
    x_display: Option<String>,
    render_server_fd: Option<SafeDescriptor>,
    event_devices: Vec<EventDevice>,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
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
        exit_evt.try_clone().context("failed to clone event")?,
        Some(gpu_device_tube),
        resource_bridges,
        display_backends,
        cfg.gpu_parameters.as_ref().unwrap(),
        render_server_fd,
        event_devices,
        map_request,
        cfg.jail_config.is_some(),
        virtio::base_features(cfg.protected_vm),
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

#[derive(Debug)]
pub struct GpuRenderServerParameters {
    pub path: PathBuf,
    pub cache_path: Option<String>,
    pub cache_size: Option<String>,
}

fn get_gpu_render_server_environment(cache_info: &GpuCacheInfo) -> Result<Vec<String>> {
    let mut env = Vec::new();

    let mut cache_env_keys = HashSet::with_capacity(cache_info.environment.len());
    for (key, val) in cache_info.environment.iter() {
        env.push(format!("{}={}", key, val));
        cache_env_keys.insert(*key);
    }

    for (key_os, val_os) in env::vars_os() {
        // minijail should accept OsStr rather than str...
        let into_string_err = |_| anyhow!("invalid environment key/val");
        let key = key_os.into_string().map_err(into_string_err)?;
        let val = val_os.into_string().map_err(into_string_err)?;

        if !cache_env_keys.contains(key.as_str()) {
            env.push(format!("{}={}", key, val));
        }
    }

    Ok(env)
}

pub fn start_gpu_render_server(
    cfg: &Config,
    render_server_parameters: &GpuRenderServerParameters,
) -> Result<(Minijail, SafeDescriptor)> {
    let (server_socket, client_socket) =
        UnixSeqpacket::pair().context("failed to create render server socket")?;

    let mut env = None;
    let jail = match gpu_jail(&cfg.jail_config, "gpu_render_server")? {
        Some(mut jail) => {
            let cache_info = get_gpu_cache_info(
                render_server_parameters.cache_path.as_ref(),
                render_server_parameters.cache_size.as_ref(),
                true,
            );

            if let Some(dir) = cache_info.directory {
                jail.mount_bind(dir, dir, true)?;
            }

            if !cache_info.environment.is_empty() {
                env = Some(get_gpu_render_server_environment(&cache_info)?);
            }

            // bind mount /dev/log for syslog
            let log_path = Path::new("/dev/log");
            if log_path.exists() {
                jail.mount_bind(log_path, log_path, true)?;
            }

            // Run as root in the jail to keep capabilities after execve, which is needed for
            // mounting to work.  All capabilities will be dropped afterwards.
            add_current_user_as_root_to_jail(&mut jail)?;

            jail
        }
        None => Minijail::new().context("failed to create jail")?,
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
