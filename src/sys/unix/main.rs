// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(
    all(feature = "gpu", feature = "virgl_renderer_next"),
    feature = "audio"
))]
use std::str::FromStr;
use std::{path::PathBuf, time::Duration};

use anyhow::{anyhow, Result};
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
