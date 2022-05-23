// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(
    all(feature = "gpu", feature = "virgl_renderer_next"),
    feature = "audio"
))]
use std::str::FromStr;
use std::thread::sleep;
use std::{path::PathBuf, time::Duration};

use anyhow::{anyhow, Result};

use base::{kill_process_group, reap_child, warn};
#[cfg(feature = "gpu")]
use devices::virtio::gpu::{GpuDisplayParameters, GpuParameters};
#[cfg(feature = "gpu")]
use devices::virtio::vhost::user::device::run_gpu_device;
use devices::virtio::vhost::user::device::{
    run_console_device, run_fs_device, run_vsock_device, run_wl_device,
};
#[cfg(feature = "audio_cras")]
use devices::virtio::{
    snd::cras_backend::Error as CrasSndError, vhost::user::device::run_cras_snd_device,
};
#[cfg(target_os = "android")]
use devices::Ac97Backend;
#[cfg(feature = "audio")]
use devices::Ac97Parameters;
use devices::SerialParameters;

use crate::argument::{self, Argument};
#[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
use crate::platform::GpuRenderServerParameters;
use crosvm::{Config, SharedDir};

#[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
fn parse_gpu_render_server_options(s: Option<&str>) -> argument::Result<GpuRenderServerParameters> {
    let mut path: Option<PathBuf> = None;
    let mut cache_path = None;
    let mut cache_size = None;

    if let Some(s) = s {
        let opts = s
            .split(',')
            .map(|frag| frag.split('='))
            .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

        for (k, v) in opts {
            match k {
                "path" => {
                    path =
                        Some(
                            PathBuf::from_str(v).map_err(|e| argument::Error::InvalidValue {
                                value: v.to_string(),
                                expected: e.to_string(),
                            })?,
                        )
                }
                "cache-path" => cache_path = Some(v.to_string()),
                "cache-size" => cache_size = Some(v.to_string()),
                "" => {}
                _ => {
                    return Err(argument::Error::UnknownArgument(format!(
                        "gpu-render-server parameter {}",
                        k
                    )));
                }
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
        Err(argument::Error::InvalidValue {
            value: s.unwrap_or("").to_string(),
            expected: String::from("gpu-render-server must include 'path'"),
        })
    }
}

#[cfg(feature = "gpu")]
pub fn is_gpu_backend_deprecated(_backend: &str) -> bool {
    false
}

pub fn use_host_cpu_topology() -> bool {
    true
}

pub fn get_vcpu_count() -> argument::Result<usize> {
    // Safe because we pass a flag for this call and the host supports this system call
    Ok(unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) } as usize)
}

#[cfg(feature = "gfxstream")]
pub fn use_vulkan() -> bool {
    true
}

// Doesn't do anything on unix.
pub fn check_serial_params(_serial_params: &SerialParameters) -> argument::Result<()> {
    Ok(())
}

pub fn net_vq_pairs_expected() -> bool {
    true
}

pub fn get_arguments() -> Vec<Argument> {
    vec![
          #[cfg(feature = "audio_cras")]
          Argument::value("cras-snd",
          "[capture=true,client=crosvm,socket=unified,num_output_streams=1,num_input_streams=1]",
          "Comma separated key=value pairs for setting up cras snd devices.

              Possible key values:

              capture - Enable audio capture. Default to false.

              client_type - Set specific client type for cras backend.

              num_output_streams - Set number of output PCM streams

              num_input_streams - Set number of input PCM streams"),
          Argument::value("host_ip",
                          "IP",
                          "IP address to assign to host tap interface."),
          Argument::value("netmask", "NETMASK", "Netmask for VM subnet."),
          Argument::value("mac", "MAC", "MAC address for VM."),
          Argument::value("tap-name",
                          "NAME",
                          "Name of a configured persistent TAP interface to use for networking. A different virtual network card will be added each time this argument is given."),
          Argument::value("tap-fd",
                          "fd",
                          "File descriptor for configured tap device. A different virtual network card will be added each time this argument is given."),
          Argument::value("vhost-vsock-fd", "FD", "Open FD to the vhost-vsock device, mutually exclusive with vhost-vsock-device."),
          #[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
          Argument::flag_or_value("gpu-render-server",
                                  "[path=PATH]",
                                  "(EXPERIMENTAL) Comma separated key=value pairs for setting up a render server for the virtio-gpu device

                              Possible key values:

                              path=PATH - The path to the render server executable.

                              cache-path=PATH - The path to the render server shader cache.

                              cache-size=SIZE - The maximum size of the shader cache."),
          Argument::flag_or_value("coiommu",
                          "unpin_policy=POLICY,unpin_interval=NUM,unpin_limit=NUM,unpin_gen_threshold=NUM ",
                          "Comma separated key=value pairs for setting up coiommu devices.

                              Possible key values:

                              unpin_policy=lru - LRU unpin policy.

                              unpin_interval=NUM - Unpin interval time in seconds.

                              unpin_limit=NUM - Unpin limit for each unpin cycle, in unit of page count. 0 is invalid.

                              unpin_gen_threshold=NUM -  Number of unpin intervals a pinned page must be busy for to be aged into the older which is less frequently checked generation."),
          Argument::value("seccomp-policy-dir", "PATH", "Path to seccomp .policy files."),
          Argument::flag("seccomp-log-failures", "Instead of seccomp filter failures being fatal, they will be logged instead."),
          Argument::value("serial",
                          "type=TYPE,[hardware=HW,num=NUM,path=PATH,input=PATH,console,earlycon,stdin]",
                          "Comma separated key=value pairs for setting up serial devices. Can be given more than once.

                              Possible key values:

                              type=(stdout,syslog,sink,file) - Where to route the serial device

                              hardware=(serial,virtio-console) - Which type of serial hardware to emulate. Defaults to 8250 UART (serial).

                              num=(1,2,3,4) - Serial Device Number. If not provided, num will default to 1.

                              path=PATH - The path to the file to write to when type=file

                              input=PATH - The path to the file to read from when not stdin

                              console - Use this serial device as the guest console. Can only be given once. Will default to first serial port if not provided.

                              earlycon - Use this serial device as the early console. Can only be given once.

                              stdin - Direct standard input to this serial device. Can only be given once. Will default to first serial port if not provided.
                              "),
          #[cfg(feature = "gpu")]
          Argument::flag_or_value("gpu",
                                  "[width=INT,height=INT]",
                                  "(EXPERIMENTAL) Comma separated key=value pairs for setting up a virtio-gpu device

                              Possible key values:

                              backend=(2d|virglrenderer|gfxstream) - Which backend to use for virtio-gpu (determining rendering protocol)

                              context-types=LIST - The list of supported context types, separated by ':' (default: no contexts enabled)

                              width=INT - The width of the virtual display connected to the virtio-gpu.

                              height=INT - The height of the virtual display connected to the virtio-gpu.

                              egl[=true|=false] - If the backend should use a EGL context for rendering.

                              glx[=true|=false] - If the backend should use a GLX context for rendering.

                              surfaceless[=true|=false] - If the backend should use a surfaceless context for rendering.

                              angle[=true|=false] - If the gfxstream backend should use ANGLE (OpenGL on Vulkan) as its native OpenGL driver.

                              syncfd[=true|=false] - If the gfxstream backend should support EGL_ANDROID_native_fence_sync

                              vulkan[=true|=false] - If the backend should support vulkan

                              cache-path=PATH - The path to the virtio-gpu device shader cache.

                              cache-size=SIZE - The maximum size of the shader cache."),
          #[cfg(feature = "gpu")]
          Argument::flag_or_value("gpu-display",
                                  "[width=INT,height=INT]",
                                  "(EXPERIMENTAL) Comma separated key=value pairs for setting up a display on the virtio-gpu device

                              Possible key values:

                              width=INT - The width of the virtual display connected to the virtio-gpu.

                              height=INT - The height of the virtual display connected to the virtio-gpu."),
          Argument::flag("no-legacy", "Don't use legacy KBD/RTC devices emulation"),
    ]
}

pub fn set_arguments(cfg: &mut Config, name: &str, value: Option<&str>) -> argument::Result<()> {
    match name {
        #[cfg(feature = "audio_cras")]
        "cras-snd" => {
            cfg.cras_snds.push(
                value
                    .unwrap()
                    .parse()
                    .map_err(|e: CrasSndError| argument::Error::Syntax(e.to_string()))?,
            );
        }
        "vhost-vsock-fd" => {
            if cfg.vhost_vsock_device.is_some() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("A vhost-vsock device was already specified"),
                });
            }
            let fd: i32 = value
                .unwrap()
                .parse()
                .map_err(|_| argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("this value for `vhost-vsock-fd` needs to be integer"),
                })?;
            cfg.vhost_vsock_device = Some(PathBuf::from(format!("/proc/self/fd/{}", fd)));
        }
        "vhost-vsock-device" => {
            if cfg.vhost_vsock_device.is_some() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("A vhost-vsock device was already specified"),
                });
            }
            let vhost_vsock_device_path = PathBuf::from(value.unwrap());
            if !vhost_vsock_device_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("this vhost-vsock device path does not exist"),
                });
            }

            cfg.vhost_vsock_device = Some(vhost_vsock_device_path);
        }
        "shared-dir" => {
            // This is formatted as multiple fields, each separated by ":". The first 2 fields are
            // fixed (src:tag).  The rest may appear in any order:
            //
            // * type=TYPE - must be one of "p9" or "fs" (default: p9)
            // * uidmap=UIDMAP - a uid map in the format "inner outer count[,inner outer count]"
            //   (default: "0 <current euid> 1")
            // * gidmap=GIDMAP - a gid map in the same format as uidmap
            //   (default: "0 <current egid> 1")
            // * privileged_quota_uids=UIDS - Space-separated list of privileged uid values. When
            //   performing quota-related operations, these UIDs are treated as if they have
            //   CAP_FOWNER.
            // * timeout=TIMEOUT - a timeout value in seconds, which indicates how long attributes
            //   and directory contents should be considered valid (default: 5)
            // * cache=CACHE - one of "never", "always", or "auto" (default: auto)
            // * writeback=BOOL - indicates whether writeback caching should be enabled (default: false)
            let param = value.unwrap();
            let mut components = param.split(':');
            let src =
                PathBuf::from(
                    components
                        .next()
                        .ok_or_else(|| argument::Error::InvalidValue {
                            value: param.to_owned(),
                            expected: String::from("missing source path for `shared-dir`"),
                        })?,
                );
            let tag = components
                .next()
                .ok_or_else(|| argument::Error::InvalidValue {
                    value: param.to_owned(),
                    expected: String::from("missing tag for `shared-dir`"),
                })?
                .to_owned();

            if !src.is_dir() {
                return Err(argument::Error::InvalidValue {
                    value: param.to_owned(),
                    expected: String::from("source path for `shared-dir` must be a directory"),
                });
            }

            let mut shared_dir = SharedDir {
                src,
                tag,
                ..Default::default()
            };
            for opt in components {
                let mut o = opt.splitn(2, '=');
                let kind = o.next().ok_or_else(|| argument::Error::InvalidValue {
                    value: opt.to_owned(),
                    expected: String::from("`shared-dir` options must not be empty"),
                })?;
                let value = o.next().ok_or_else(|| argument::Error::InvalidValue {
                    value: opt.to_owned(),
                    expected: String::from("`shared-dir` options must be of the form `kind=value`"),
                })?;

                match kind {
                    "type" => {
                        shared_dir.kind =
                            value.parse().map_err(|_| argument::Error::InvalidValue {
                                value: value.to_owned(),
                                expected: String::from("`type` must be one of `fs` or `9p`"),
                            })?
                    }
                    "uidmap" => shared_dir.uid_map = value.into(),
                    "gidmap" => shared_dir.gid_map = value.into(),
                    #[cfg(feature = "chromeos")]
                    "privileged_quota_uids" => {
                        shared_dir.fs_cfg.privileged_quota_uids =
                            value.split(' ').map(|s| s.parse().unwrap()).collect();
                    }
                    "timeout" => {
                        let seconds = value.parse().map_err(|_| argument::Error::InvalidValue {
                            value: value.to_owned(),
                            expected: String::from("`timeout` must be an integer"),
                        })?;

                        let dur = Duration::from_secs(seconds);
                        shared_dir.fs_cfg.entry_timeout = dur;
                        shared_dir.fs_cfg.attr_timeout = dur;
                    }
                    "cache" => {
                        let policy = value.parse().map_err(|_| argument::Error::InvalidValue {
                            value: value.to_owned(),
                            expected: String::from(
                                "`cache` must be one of `never`, `always`, or `auto`",
                            ),
                        })?;
                        shared_dir.fs_cfg.cache_policy = policy;
                    }
                    "writeback" => {
                        let writeback =
                            value.parse().map_err(|_| argument::Error::InvalidValue {
                                value: value.to_owned(),
                                expected: String::from("`writeback` must be a boolean"),
                            })?;
                        shared_dir.fs_cfg.writeback = writeback;
                    }
                    "rewrite-security-xattrs" => {
                        let rewrite_security_xattrs =
                            value.parse().map_err(|_| argument::Error::InvalidValue {
                                value: value.to_owned(),
                                expected: String::from(
                                    "`rewrite-security-xattrs` must be a boolean",
                                ),
                            })?;
                        shared_dir.fs_cfg.rewrite_security_xattrs = rewrite_security_xattrs;
                    }
                    "ascii_casefold" => {
                        let ascii_casefold =
                            value.parse().map_err(|_| argument::Error::InvalidValue {
                                value: value.to_owned(),
                                expected: String::from("`ascii_casefold` must be a boolean"),
                            })?;
                        shared_dir.fs_cfg.ascii_casefold = ascii_casefold;
                        shared_dir.p9_cfg.ascii_casefold = ascii_casefold;
                    }
                    "dax" => {
                        let use_dax = value.parse().map_err(|_| argument::Error::InvalidValue {
                            value: value.to_owned(),
                            expected: String::from("`dax` must be a boolean"),
                        })?;
                        shared_dir.fs_cfg.use_dax = use_dax;
                    }
                    "posix_acl" => {
                        let posix_acl =
                            value.parse().map_err(|_| argument::Error::InvalidValue {
                                value: value.to_owned(),
                                expected: String::from("`posix_acl` must be a boolean"),
                            })?;
                        shared_dir.fs_cfg.posix_acl = posix_acl;
                    }
                    _ => {
                        return Err(argument::Error::InvalidValue {
                            value: kind.to_owned(),
                            expected: String::from("unrecognized option for `shared-dir`"),
                        })
                    }
                }
            }
            cfg.shared_dirs.push(shared_dir);
        }
        "host_ip" => {
            if cfg.host_ip.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`host_ip` already given".to_owned(),
                ));
            }
            cfg.host_ip =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from("`host_ip` needs to be in the form \"x.x.x.x\""),
                        })?,
                )
        }
        "netmask" => {
            if cfg.netmask.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`netmask` already given".to_owned(),
                ));
            }
            cfg.netmask =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from("`netmask` needs to be in the form \"x.x.x.x\""),
                        })?,
                )
        }
        "mac" => {
            if cfg.mac_address.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`mac` already given".to_owned(),
                ));
            }
            cfg.mac_address =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from(
                                "`mac` needs to be in the form \"XX:XX:XX:XX:XX:XX\"",
                            ),
                        })?,
                )
        }
        "tap-name" => {
            cfg.tap_name.push(value.unwrap().to_owned());
        }
        "tap-fd" => {
            cfg.tap_fd.push(
                value
                    .unwrap()
                    .parse()
                    .map_err(|_| argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: String::from(
                            "this value for `tap-fd` must be an unsigned integer",
                        ),
                    })?,
            );
        }
        "coiommu" => {
            let mut params: devices::CoIommuParameters = Default::default();
            if let Some(v) = value {
                let opts = v
                    .split(',')
                    .map(|frag| frag.splitn(2, '='))
                    .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

                for (k, v) in opts {
                    match k {
                        "unpin_policy" => {
                            params.unpin_policy = v
                                .parse::<devices::CoIommuUnpinPolicy>()
                                .map_err(|e| argument::Error::UnknownArgument(format!("{}", e)))?
                        }
                        "unpin_interval" => {
                            params.unpin_interval =
                                Duration::from_secs(v.parse::<u64>().map_err(|e| {
                                    argument::Error::UnknownArgument(format!("{}", e))
                                })?)
                        }
                        "unpin_limit" => {
                            let limit = v
                                .parse::<u64>()
                                .map_err(|e| argument::Error::UnknownArgument(format!("{}", e)))?;

                            if limit == 0 {
                                return Err(argument::Error::InvalidValue {
                                    value: v.to_owned(),
                                    expected: String::from("Please use non-zero unpin_limit value"),
                                });
                            }

                            params.unpin_limit = Some(limit)
                        }
                        "unpin_gen_threshold" => {
                            params.unpin_gen_threshold = v
                                .parse::<u64>()
                                .map_err(|e| argument::Error::UnknownArgument(format!("{}", e)))?
                        }
                        _ => {
                            return Err(argument::Error::UnknownArgument(format!(
                                "coiommu parameter {}",
                                k
                            )));
                        }
                    }
                }
            }

            if cfg.coiommu_param.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "coiommu param already given".to_owned(),
                ));
            }
            cfg.coiommu_param = Some(params);
        }
        #[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
        "gpu-render-server" => {
            cfg.gpu_render_server_parameters = Some(parse_gpu_render_server_options(value)?);
        }
        "seccomp-policy-dir" => {
            if let Some(jail_config) = &mut cfg.jail_config {
                // `value` is Some because we are in this match so it's safe to unwrap.
                jail_config.seccomp_policy_dir = PathBuf::from(value.unwrap());
            }
        }
        "seccomp-log-failures" => {
            // A side-effect of this flag is to force the use of .policy files
            // instead of .bpf files (.bpf files are expected and assumed to be
            // compiled to fail an unpermitted action with "trap").
            // Normally crosvm will first attempt to use a .bpf file, and if
            // not present it will then try to use a .policy file.  It's up
            // to the build to decide which of these files is present for
            // crosvm to use (for CrOS the build will use .bpf files for
            // x64 builds and .policy files for arm/arm64 builds).
            //
            // This flag will likely work as expected for builds that use
            // .policy files.  For builds that only use .bpf files the initial
            // result when using this flag is likely to be a file-not-found
            // error (since the .policy files are not present).
            // For .bpf builds you can either 1) manually add the .policy files,
            // or 2) do not use this command-line parameter and instead
            // temporarily change the build by passing "log" rather than
            // "trap" as the "--default-action" to compile_seccomp_policy.py.
            if let Some(jail_config) = &mut cfg.jail_config {
                jail_config.seccomp_log_failures = true;
            }
        }
        #[cfg(feature = "gpu")]
        "gpu-display" => {
            let gpu_parameters = cfg.gpu_parameters.get_or_insert_with(Default::default);
            parse_gpu_display_options(value, gpu_parameters)?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

pub(crate) fn start_device(program_name: &str, device_name: &str, args: &[&str]) -> Result<()> {
    match device_name {
        "console" => run_console_device(program_name, args),
        #[cfg(feature = "audio_cras")]
        "cras-snd" => run_cras_snd_device(program_name, args),
        "fs" => run_fs_device(program_name, args),
        #[cfg(feature = "gpu")]
        "gpu" => run_gpu_device(program_name, args),
        "vsock" => run_vsock_device(program_name, args),
        "wl" => run_wl_device(program_name, args),
        _ => Err(anyhow!("unknown device name: {}", device_name)),
    }
}

#[cfg(feature = "audio")]
pub(crate) fn check_ac97_backend(
    #[allow(unused_variables)] ac97_params: &Ac97Parameters,
) -> argument::Result<()> {
    // server is required for and exclusive to vios backend
    #[cfg(target_os = "android")]
    match ac97_params.backend {
        Ac97Backend::VIOS => {
            if ac97_params.vios_server_path.is_none() {
                return Err(argument::Error::ExpectedArgument(String::from(
                    "server argument is required for VIOS backend",
                )));
            }
        }
        _ => {
            if ac97_params.vios_server_path.is_some() {
                return Err(argument::Error::UnexpectedValue(String::from(
                    "server argument is exclusive to the VIOS backend",
                )));
            }
        }
    }

    Ok(())
}

#[cfg(feature = "audio")]
pub fn parse_ac97_options(
    ac97_params: &mut Ac97Parameters,
    key: &str,
    #[allow(unused_variables)] value: &str,
) -> argument::Result<()> {
    match key {
        #[cfg(feature = "audio_cras")]
        "client_type" => {
            ac97_params
                .set_client_type(value)
                .map_err(|e| argument::Error::InvalidValue {
                    value: value.to_string(),
                    expected: e.to_string(),
                })?;
        }
        #[cfg(feature = "audio_cras")]
        "socket_type" => {
            ac97_params
                .set_socket_type(value)
                .map_err(|e| argument::Error::InvalidValue {
                    value: value.to_string(),
                    expected: e.to_string(),
                })?;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        "server" => {
            ac97_params.vios_server_path =
                Some(
                    PathBuf::from_str(value).map_err(|e| argument::Error::InvalidValue {
                        value: value.to_string(),
                        expected: e.to_string(),
                    })?,
                );
        }
        _ => {
            return Err(argument::Error::UnknownArgument(format!(
                "unknown ac97 parameter {}",
                key
            )));
        }
    };
    Ok(())
}

// Wait for all children to exit. Return true if they have all exited, false
// otherwise.
fn wait_all_children() -> bool {
    const CHILD_WAIT_MAX_ITER: isize = 100;
    const CHILD_WAIT_MS: u64 = 10;
    for _ in 0..CHILD_WAIT_MAX_ITER {
        loop {
            match reap_child() {
                Ok(0) => break,
                // We expect ECHILD which indicates that there were no children left.
                Err(e) if e.errno() == libc::ECHILD => return true,
                Err(e) => {
                    warn!("error while waiting for children: {}", e);
                    return false;
                }
                // We reaped one child, so continue reaping.
                _ => {}
            }
        }
        // There's no timeout option for waitpid which reap_child calls internally, so our only
        // recourse is to sleep while waiting for the children to exit.
        sleep(Duration::from_millis(CHILD_WAIT_MS));
    }

    // If we've made it to this point, not all of the children have exited.
    false
}

pub(crate) fn cleanup() {
    // Reap exit status from any child device processes. At this point, all devices should have been
    // dropped in the main process and told to shutdown. Try over a period of 100ms, since it may
    // take some time for the processes to shut down.
    if !wait_all_children() {
        // We gave them a chance, and it's too late.
        warn!("not all child processes have exited; sending SIGKILL");
        if let Err(e) = kill_process_group() {
            // We're now at the mercy of the OS to clean up after us.
            warn!("unable to kill all child processes: {}", e);
        }
    }
}

#[cfg(feature = "gpu")]
fn parse_gpu_display_options(
    s: Option<&str>,
    gpu_params: &mut GpuParameters,
) -> argument::Result<()> {
    let mut display_w: Option<u32> = None;
    let mut display_h: Option<u32> = None;

    if let Some(s) = s {
        let opts = s
            .split(',')
            .map(|frag| frag.split('='))
            .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

        for (k, v) in opts {
            match k {
                "width" => {
                    let width = v
                        .parse::<u32>()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from("gpu parameter 'width' must be a valid integer"),
                        })?;
                    display_w = Some(width);
                }
                "height" => {
                    let height = v
                        .parse::<u32>()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from(
                                "gpu parameter 'height' must be a valid integer",
                            ),
                        })?;
                    display_h = Some(height);
                }
                "" => {}
                _ => {
                    return Err(argument::Error::UnknownArgument(format!(
                        "gpu-display parameter {}",
                        k
                    )));
                }
            }
        }
    }

    if display_w.is_none() || display_h.is_none() {
        return Err(argument::Error::InvalidValue {
            value: s.unwrap_or("").to_string(),
            expected: String::from("gpu-display must include both 'width' and 'height'"),
        });
    }

    gpu_params.displays.push(GpuDisplayParameters {
        width: display_w.unwrap(),
        height: display_h.unwrap(),
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_gpu_options;

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_valid() {
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(
                parse_gpu_display_options(Some("width=500,height=600"), &mut gpu_params).is_ok()
            );
            assert_eq!(gpu_params.displays.len(), 1);
            assert_eq!(gpu_params.displays[0].width, 500);
            assert_eq!(gpu_params.displays[0].height, 600);
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_invalid() {
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_display_options(Some("width=500"), &mut gpu_params).is_err());
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_display_options(Some("height=500"), &mut gpu_params).is_err());
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_display_options(Some("width"), &mut gpu_params).is_err());
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_display_options(Some("blah"), &mut gpu_params).is_err());
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_and_gpu_display_options_valid() {
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_options(Some("2D,width=500,height=600"), &mut gpu_params).is_ok());
            assert!(
                parse_gpu_display_options(Some("width=700,height=800"), &mut gpu_params).is_ok()
            );
            assert_eq!(gpu_params.displays.len(), 2);
            assert_eq!(gpu_params.displays[0].width, 500);
            assert_eq!(gpu_params.displays[0].height, 600);
            assert_eq!(gpu_params.displays[1].width, 700);
            assert_eq!(gpu_params.displays[1].height, 800);
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_options(Some("2D"), &mut gpu_params).is_ok());
            assert!(
                parse_gpu_display_options(Some("width=700,height=800"), &mut gpu_params).is_ok()
            );
            assert_eq!(gpu_params.displays.len(), 1);
            assert_eq!(gpu_params.displays[0].width, 700);
            assert_eq!(gpu_params.displays[0].height, 800);
        }
    }
}
