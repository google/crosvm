// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Runs a virtual machine

pub mod panic_hook;

use std::collections::BTreeMap;
use std::default::Default;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::string::String;
use std::thread::sleep;
use std::time::Duration;

use arch::{
    set_default_serial_parameters, Pstore, SerialHardware, SerialParameters, SerialType,
    VcpuAffinity,
};
use base::{debug, error, getpid, info, kill_process_group, reap_child, syslog, warn};
#[cfg(feature = "direct")]
use crosvm::DirectIoOption;
use crosvm::{
    argument::{self, print_help, set_arguments, Argument},
    platform, BindMount, Config, DiskOption, Executable, GidMap, SharedDir, TouchDeviceOption,
    VhostUserFsOption, VhostUserOption, DISK_ID_LEN,
};
#[cfg(feature = "gpu")]
use devices::virtio::gpu::{GpuMode, GpuParameters};
use devices::ProtectionType;
#[cfg(feature = "audio")]
use devices::{Ac97Backend, Ac97Parameters};
use disk::QcowFile;
use vm_control::{
    client::{
        do_modify_battery, do_usb_attach, do_usb_detach, do_usb_list, handle_request, vms_request,
        ModifyUsbError, ModifyUsbResult,
    },
    BalloonControlCommand, BatteryType, DiskControlCommand, UsbControlResult, VmRequest,
};

fn executable_is_plugin(executable: &Option<Executable>) -> bool {
    matches!(executable, Some(Executable::Plugin(_)))
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

/// Parse a comma-separated list of CPU numbers and ranges and convert it to a Vec of CPU numbers.
fn parse_cpu_set(s: &str) -> argument::Result<Vec<usize>> {
    let mut cpuset = Vec::new();
    for part in s.split(',') {
        let range: Vec<&str> = part.split('-').collect();
        if range.is_empty() || range.len() > 2 {
            return Err(argument::Error::InvalidValue {
                value: part.to_owned(),
                expected: String::from("invalid list syntax"),
            });
        }
        let first_cpu: usize = range[0]
            .parse()
            .map_err(|_| argument::Error::InvalidValue {
                value: part.to_owned(),
                expected: String::from("CPU index must be a non-negative integer"),
            })?;
        let last_cpu: usize = if range.len() == 2 {
            range[1]
                .parse()
                .map_err(|_| argument::Error::InvalidValue {
                    value: part.to_owned(),
                    expected: String::from("CPU index must be a non-negative integer"),
                })?
        } else {
            first_cpu
        };

        if last_cpu < first_cpu {
            return Err(argument::Error::InvalidValue {
                value: part.to_owned(),
                expected: String::from("CPU ranges must be from low to high"),
            });
        }

        for cpu in first_cpu..=last_cpu {
            cpuset.push(cpu);
        }
    }
    Ok(cpuset)
}

/// Parse a list of guest to host CPU mappings.
///
/// Each mapping consists of a single guest CPU index mapped to one or more host CPUs in the form
/// accepted by `parse_cpu_set`:
///
///  `<GUEST-CPU>=<HOST-CPU-SET>[:<GUEST-CPU>=<HOST-CPU-SET>[:...]]`
fn parse_cpu_affinity(s: &str) -> argument::Result<VcpuAffinity> {
    if s.contains('=') {
        let mut affinity_map = BTreeMap::new();
        for cpu_pair in s.split(':') {
            let assignment: Vec<&str> = cpu_pair.split('=').collect();
            if assignment.len() != 2 {
                return Err(argument::Error::InvalidValue {
                    value: cpu_pair.to_owned(),
                    expected: String::from("invalid VCPU assignment syntax"),
                });
            }
            let guest_cpu = assignment[0]
                .parse()
                .map_err(|_| argument::Error::InvalidValue {
                    value: assignment[0].to_owned(),
                    expected: String::from("CPU index must be a non-negative integer"),
                })?;
            let host_cpu_set = parse_cpu_set(assignment[1])?;
            if affinity_map.insert(guest_cpu, host_cpu_set).is_some() {
                return Err(argument::Error::InvalidValue {
                    value: cpu_pair.to_owned(),
                    expected: String::from("VCPU index must be unique"),
                });
            }
        }
        Ok(VcpuAffinity::PerVcpu(affinity_map))
    } else {
        Ok(VcpuAffinity::Global(parse_cpu_set(s)?))
    }
}

#[cfg(feature = "gpu")]
fn parse_gpu_options(s: Option<&str>) -> argument::Result<GpuParameters> {
    let mut gpu_params: GpuParameters = Default::default();
    #[cfg(feature = "gfxstream")]
    let mut vulkan_specified = false;
    #[cfg(feature = "gfxstream")]
    let mut syncfd_specified = false;
    #[cfg(feature = "gfxstream")]
    let mut angle_specified = false;

    if let Some(s) = s {
        let opts = s
            .split(',')
            .map(|frag| frag.split('='))
            .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

        for (k, v) in opts {
            match k {
                // Deprecated: Specifying --gpu=<mode> Not great as the mode can be set multiple
                // times if the user specifies several modes (--gpu=2d,virglrenderer,gfxstream)
                "2d" | "2D" => {
                    gpu_params.mode = GpuMode::Mode2D;
                }
                "3d" | "3D" | "virglrenderer" => {
                    gpu_params.mode = GpuMode::ModeVirglRenderer;
                }
                #[cfg(feature = "gfxstream")]
                "gfxstream" => {
                    gpu_params.mode = GpuMode::ModeGfxstream;
                }
                // Preferred: Specifying --gpu,backend=<mode>
                "backend" => match v {
                    "2d" | "2D" => {
                        gpu_params.mode = GpuMode::Mode2D;
                    }
                    "3d" | "3D" | "virglrenderer" => {
                        gpu_params.mode = GpuMode::ModeVirglRenderer;
                    }
                    #[cfg(feature = "gfxstream")]
                    "gfxstream" => {
                        gpu_params.mode = GpuMode::ModeGfxstream;
                    }
                    _ => {
                        return Err(argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from(
                                "gpu parameter 'backend' should be one of (2d|virglrenderer|gfxstream)",
                            ),
                        });
                    }
                },
                "egl" => match v {
                    "true" | "" => {
                        gpu_params.renderer_use_egl = true;
                    }
                    "false" => {
                        gpu_params.renderer_use_egl = false;
                    }
                    _ => {
                        return Err(argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from("gpu parameter 'egl' should be a boolean"),
                        });
                    }
                },
                "gles" => match v {
                    "true" | "" => {
                        gpu_params.renderer_use_gles = true;
                    }
                    "false" => {
                        gpu_params.renderer_use_gles = false;
                    }
                    _ => {
                        return Err(argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from("gpu parameter 'gles' should be a boolean"),
                        });
                    }
                },
                "glx" => match v {
                    "true" | "" => {
                        gpu_params.renderer_use_glx = true;
                    }
                    "false" => {
                        gpu_params.renderer_use_glx = false;
                    }
                    _ => {
                        return Err(argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from("gpu parameter 'glx' should be a boolean"),
                        });
                    }
                },
                "surfaceless" => match v {
                    "true" | "" => {
                        gpu_params.renderer_use_surfaceless = true;
                    }
                    "false" => {
                        gpu_params.renderer_use_surfaceless = false;
                    }
                    _ => {
                        return Err(argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from(
                                "gpu parameter 'surfaceless' should be a boolean",
                            ),
                        });
                    }
                },
                #[cfg(feature = "gfxstream")]
                "syncfd" => {
                    syncfd_specified = true;
                    match v {
                        "true" | "" => {
                            gpu_params.gfxstream_use_syncfd = true;
                        }
                        "false" => {
                            gpu_params.gfxstream_use_syncfd = false;
                        }
                        _ => {
                            return Err(argument::Error::InvalidValue {
                                value: v.to_string(),
                                expected: String::from(
                                    "gpu parameter 'syncfd' should be a boolean",
                                ),
                            });
                        }
                    }
                }
                #[cfg(feature = "gfxstream")]
                "angle" => {
                    angle_specified = true;
                    match v {
                        "true" | "" => {
                            gpu_params.gfxstream_use_guest_angle = true;
                        }
                        "false" => {
                            gpu_params.gfxstream_use_guest_angle = false;
                        }
                        _ => {
                            return Err(argument::Error::InvalidValue {
                                value: v.to_string(),
                                expected: String::from("gpu parameter 'angle' should be a boolean"),
                            });
                        }
                    }
                }
                "vulkan" => {
                    #[cfg(feature = "gfxstream")]
                    {
                        vulkan_specified = true;
                    }
                    match v {
                        "true" | "" => {
                            gpu_params.use_vulkan = true;
                        }
                        "false" => {
                            gpu_params.use_vulkan = false;
                        }
                        _ => {
                            return Err(argument::Error::InvalidValue {
                                value: v.to_string(),
                                expected: String::from(
                                    "gpu parameter 'vulkan' should be a boolean",
                                ),
                            });
                        }
                    }
                }
                "width" => {
                    gpu_params.display_width =
                        v.parse::<u32>()
                            .map_err(|_| argument::Error::InvalidValue {
                                value: v.to_string(),
                                expected: String::from(
                                    "gpu parameter 'width' must be a valid integer",
                                ),
                            })?;
                }
                "height" => {
                    gpu_params.display_height =
                        v.parse::<u32>()
                            .map_err(|_| argument::Error::InvalidValue {
                                value: v.to_string(),
                                expected: String::from(
                                    "gpu parameter 'height' must be a valid integer",
                                ),
                            })?;
                }
                "cache-path" => gpu_params.cache_path = Some(v.to_string()),
                "cache-size" => gpu_params.cache_size = Some(v.to_string()),
                "udmabuf" => match v {
                    "true" | "" => {
                        gpu_params.udmabuf = true;
                    }
                    "false" => {
                        gpu_params.udmabuf = false;
                    }
                    _ => {
                        return Err(argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from("gpu parameter 'udmabuf' should be a boolean"),
                        });
                    }
                },
                "" => {}
                _ => {
                    return Err(argument::Error::UnknownArgument(format!(
                        "gpu parameter {}",
                        k
                    )));
                }
            }
        }
    }

    #[cfg(feature = "gfxstream")]
    {
        if !vulkan_specified && gpu_params.mode == GpuMode::ModeGfxstream {
            gpu_params.use_vulkan = true;
        }

        if syncfd_specified || angle_specified {
            match gpu_params.mode {
                GpuMode::ModeGfxstream => {}
                _ => {
                    return Err(argument::Error::UnknownArgument(
                        "gpu parameter syncfd and angle are only supported for gfxstream backend"
                            .to_string(),
                    ));
                }
            }
        }
    }

    Ok(gpu_params)
}

#[cfg(feature = "audio")]
fn parse_ac97_options(s: &str) -> argument::Result<Ac97Parameters> {
    let mut ac97_params: Ac97Parameters = Default::default();

    let opts = s
        .split(',')
        .map(|frag| frag.split('='))
        .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

    for (k, v) in opts {
        match k {
            "backend" => {
                ac97_params.backend =
                    v.parse::<Ac97Backend>()
                        .map_err(|e| argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: e.to_string(),
                        })?;
            }
            "capture" => {
                ac97_params.capture = v.parse::<bool>().map_err(|e| {
                    argument::Error::Syntax(format!("invalid capture option: {}", e))
                })?;
            }
            "client_type" => {
                ac97_params
                    .set_client_type(v)
                    .map_err(|e| argument::Error::InvalidValue {
                        value: v.to_string(),
                        expected: e.to_string(),
                    })?;
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            "server" => {
                ac97_params.vios_server_path =
                    Some(
                        PathBuf::from_str(v).map_err(|e| argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: e.to_string(),
                        })?,
                    );
            }
            _ => {
                return Err(argument::Error::UnknownArgument(format!(
                    "unknown ac97 parameter {}",
                    k
                )));
            }
        }
    }

    // server is required for and exclusive to vios backend
    #[cfg(any(target_os = "linux", target_os = "android"))]
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

    Ok(ac97_params)
}

fn parse_serial_options(s: &str) -> argument::Result<SerialParameters> {
    let mut serial_setting = SerialParameters {
        type_: SerialType::Sink,
        hardware: SerialHardware::Serial,
        path: None,
        input: None,
        num: 1,
        console: false,
        earlycon: false,
        stdin: false,
    };

    let opts = s
        .split(',')
        .map(|frag| frag.splitn(2, '='))
        .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

    for (k, v) in opts {
        match k {
            "hardware" => {
                serial_setting.hardware = v
                    .parse::<SerialHardware>()
                    .map_err(|e| argument::Error::UnknownArgument(format!("{}", e)))?
            }
            "type" => {
                serial_setting.type_ = v
                    .parse::<SerialType>()
                    .map_err(|e| argument::Error::UnknownArgument(format!("{}", e)))?
            }
            "num" => {
                let num = v.parse::<u8>().map_err(|e| {
                    argument::Error::Syntax(format!("serial device number is not parsable: {}", e))
                })?;
                if num < 1 {
                    return Err(argument::Error::InvalidValue {
                        value: num.to_string(),
                        expected: String::from("Serial port num must be at least 1"),
                    });
                }
                serial_setting.num = num;
            }
            "console" => {
                serial_setting.console = v.parse::<bool>().map_err(|e| {
                    argument::Error::Syntax(format!(
                        "serial device console is not parseable: {}",
                        e
                    ))
                })?
            }
            "earlycon" => {
                serial_setting.earlycon = v.parse::<bool>().map_err(|e| {
                    argument::Error::Syntax(format!(
                        "serial device earlycon is not parseable: {}",
                        e,
                    ))
                })?
            }
            "stdin" => {
                serial_setting.stdin = v.parse::<bool>().map_err(|e| {
                    argument::Error::Syntax(format!("serial device stdin is not parseable: {}", e))
                })?;
                if serial_setting.stdin && serial_setting.input.is_some() {
                    return Err(argument::Error::TooManyArguments(
                        "Cannot specify both stdin and input options".to_string(),
                    ));
                }
            }
            "path" => serial_setting.path = Some(PathBuf::from(v)),
            "input" => {
                if serial_setting.stdin {
                    return Err(argument::Error::TooManyArguments(
                        "Cannot specify both stdin and input options".to_string(),
                    ));
                }
                serial_setting.input = Some(PathBuf::from(v));
            }
            _ => {
                return Err(argument::Error::UnknownArgument(format!(
                    "serial parameter {}",
                    k
                )));
            }
        }
    }

    if serial_setting.hardware == SerialHardware::Serial && serial_setting.num > 4 {
        return Err(argument::Error::InvalidValue {
            value: serial_setting.num.to_string(),
            expected: String::from("Serial port num must be 4 or less"),
        });
    }

    Ok(serial_setting)
}

fn parse_plugin_mount_option(value: &str) -> argument::Result<BindMount> {
    let components: Vec<&str> = value.split(':').collect();
    if components.is_empty() || components.len() > 3 || components[0].is_empty() {
        return Err(argument::Error::InvalidValue {
            value: value.to_owned(),
            expected: String::from(
                "`plugin-mount` should be in a form of: <src>[:[<dst>][:<writable>]]",
            ),
        });
    }

    let src = PathBuf::from(components[0]);
    if src.is_relative() {
        return Err(argument::Error::InvalidValue {
            value: components[0].to_owned(),
            expected: String::from("the source path for `plugin-mount` must be absolute"),
        });
    }
    if !src.exists() {
        return Err(argument::Error::InvalidValue {
            value: components[0].to_owned(),
            expected: String::from("the source path for `plugin-mount` does not exist"),
        });
    }

    let dst = PathBuf::from(match components.get(1) {
        None | Some(&"") => components[0],
        Some(path) => path,
    });
    if dst.is_relative() {
        return Err(argument::Error::InvalidValue {
            value: components[1].to_owned(),
            expected: String::from("the destination path for `plugin-mount` must be absolute"),
        });
    }

    let writable: bool = match components.get(2) {
        None => false,
        Some(s) => s.parse().map_err(|_| argument::Error::InvalidValue {
            value: components[2].to_owned(),
            expected: String::from("the <writable> component for `plugin-mount` is not valid bool"),
        })?,
    };

    Ok(BindMount { src, dst, writable })
}

fn parse_plugin_gid_map_option(value: &str) -> argument::Result<GidMap> {
    let components: Vec<&str> = value.split(':').collect();
    if components.is_empty() || components.len() > 3 || components[0].is_empty() {
        return Err(argument::Error::InvalidValue {
            value: value.to_owned(),
            expected: String::from(
                "`plugin-gid-map` must have exactly 3 components: <inner>[:[<outer>][:<count>]]",
            ),
        });
    }

    let inner: libc::gid_t = components[0]
        .parse()
        .map_err(|_| argument::Error::InvalidValue {
            value: components[0].to_owned(),
            expected: String::from("the <inner> component for `plugin-gid-map` is not valid gid"),
        })?;

    let outer: libc::gid_t = match components.get(1) {
        None | Some(&"") => inner,
        Some(s) => s.parse().map_err(|_| argument::Error::InvalidValue {
            value: components[1].to_owned(),
            expected: String::from("the <outer> component for `plugin-gid-map` is not valid gid"),
        })?,
    };

    let count: u32 = match components.get(2) {
        None => 1,
        Some(s) => s.parse().map_err(|_| argument::Error::InvalidValue {
            value: components[2].to_owned(),
            expected: String::from(
                "the <count> component for `plugin-gid-map` is not valid number",
            ),
        })?,
    };

    Ok(GidMap {
        inner,
        outer,
        count,
    })
}

fn parse_battery_options(s: Option<&str>) -> argument::Result<BatteryType> {
    let mut battery_type: BatteryType = Default::default();

    if let Some(s) = s {
        let opts = s
            .split(',')
            .map(|frag| frag.split('='))
            .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

        for (k, v) in opts {
            match k {
                "type" => match v.parse::<BatteryType>() {
                    Ok(type_) => battery_type = type_,
                    Err(e) => {
                        return Err(argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: e.to_string(),
                        });
                    }
                },
                "" => {}
                _ => {
                    return Err(argument::Error::UnknownArgument(format!(
                        "battery parameter {}",
                        k
                    )));
                }
            }
        }
    }

    Ok(battery_type)
}

#[cfg(feature = "direct")]
fn parse_direct_io_options(s: Option<&str>) -> argument::Result<DirectIoOption> {
    let s = s.ok_or(argument::Error::ExpectedValue(String::from(
        "expected path@range[,range] value",
    )))?;
    let parts: Vec<&str> = s.splitn(2, '@').collect();
    if parts.len() != 2 {
        return Err(argument::Error::InvalidValue {
            value: s.to_string(),
            expected: String::from("missing port range, use /path@X-Y,Z,.. syntax"),
        });
    }
    let path = PathBuf::from(parts[0]);
    if !path.exists() {
        return Err(argument::Error::InvalidValue {
            value: parts[0].to_owned(),
            expected: String::from("the path does not exist"),
        });
    };
    let ranges: argument::Result<Vec<(u64, u64)>> = parts[1]
        .split(',')
        .map(|frag| frag.split('-'))
        .map(|mut range| {
            let base = range
                .next()
                .map(|v| v.parse::<u64>())
                .map_or(Ok(None), |r| r.map(Some));
            let last = range
                .next()
                .map(|v| v.parse::<u64>())
                .map_or(Ok(None), |r| r.map(Some));
            (base, last)
        })
        .map(|range| match range {
            (Ok(Some(base)), Ok(None)) => Ok((base, 1)),
            (Ok(Some(base)), Ok(Some(last))) => {
                Ok((base, last.saturating_sub(base).saturating_add(1)))
            }
            (Err(e), _) => Err(argument::Error::InvalidValue {
                value: e.to_string(),
                expected: String::from("invalid base range value"),
            }),
            (_, Err(e)) => Err(argument::Error::InvalidValue {
                value: e.to_string(),
                expected: String::from("invalid last range value"),
            }),
            _ => Err(argument::Error::InvalidValue {
                value: s.to_owned(),
                expected: String::from("invalid range format"),
            }),
        })
        .collect();
    Ok(DirectIoOption {
        path,
        ranges: ranges?,
    })
}

fn set_argument(cfg: &mut Config, name: &str, value: Option<&str>) -> argument::Result<()> {
    match name {
        "" => {
            if cfg.executable_path.is_some() {
                return Err(argument::Error::TooManyArguments(format!(
                    "A VM executable was already specified: {:?}",
                    cfg.executable_path
                )));
            }
            let kernel_path = PathBuf::from(value.unwrap());
            if !kernel_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("this kernel path does not exist"),
                });
            }
            cfg.executable_path = Some(Executable::Kernel(kernel_path));
        }
        "kvm-device" => {
            let kvm_device_path = PathBuf::from(value.unwrap());
            if !kvm_device_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("this kvm device path does not exist"),
                });
            }

            cfg.kvm_device_path = kvm_device_path;
        }
        "vhost-vsock-device" => {
            let vhost_vsock_device_path = PathBuf::from(value.unwrap());
            if !vhost_vsock_device_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("this vhost-vsock device path does not exist"),
                });
            }

            cfg.vhost_vsock_device_path = vhost_vsock_device_path;
        }
        "vhost-net-device" => {
            let vhost_net_device_path = PathBuf::from(value.unwrap());
            if !vhost_net_device_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("this vhost-vsock device path does not exist"),
                });
            }

            cfg.vhost_net_device_path = vhost_net_device_path;
        }
        "android-fstab" => {
            if cfg.android_fstab.is_some()
                && !cfg.android_fstab.as_ref().unwrap().as_os_str().is_empty()
            {
                return Err(argument::Error::TooManyArguments(
                    "expected exactly one android fstab path".to_owned(),
                ));
            } else {
                let android_fstab = PathBuf::from(value.unwrap());
                if !android_fstab.exists() {
                    return Err(argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: String::from("this android fstab path does not exist"),
                    });
                }
                cfg.android_fstab = Some(android_fstab);
            }
        }
        "params" => {
            cfg.params.push(value.unwrap().to_owned());
        }
        "cpus" => {
            if cfg.vcpu_count.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`cpus` already given".to_owned(),
                ));
            }
            cfg.vcpu_count =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from("this value for `cpus` needs to be integer"),
                        })?,
                )
        }
        "cpu-affinity" => {
            if cfg.vcpu_affinity.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`cpu-affinity` already given".to_owned(),
                ));
            }
            cfg.vcpu_affinity = Some(parse_cpu_affinity(value.unwrap())?);
        }
        "no-smt" => {
            cfg.no_smt = true;
        }
        "rt-cpus" => {
            if !cfg.rt_cpus.is_empty() {
                return Err(argument::Error::TooManyArguments(
                    "`rt-cpus` already given".to_owned(),
                ));
            }
            cfg.rt_cpus = parse_cpu_set(value.unwrap())?;
        }
        "mem" => {
            if cfg.memory.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`mem` already given".to_owned(),
                ));
            }
            cfg.memory =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from("this value for `mem` needs to be integer"),
                        })?,
                )
        }
        "hugepages" => {
            cfg.hugepages = true;
        }
        #[cfg(feature = "audio")]
        "ac97" => {
            let ac97_params = parse_ac97_options(value.unwrap())?;
            // Add kernel parameters related to the intel8x0 driver for ac97 devices once.
            if cfg.ac97_parameters.is_empty() {
                // Set `inside_vm=1` to save some register read ops in the driver.
                cfg.params.push("snd_intel8x0.inside_vm=1".to_string());
                // Set `ac97_clock=48000` to save intel8x0_measure_ac97_clock call in the driver.
                cfg.params.push("snd_intel8x0.ac97_clock=48000".to_string());
            }
            cfg.ac97_parameters.push(ac97_params);
        }
        "serial" => {
            let serial_params = parse_serial_options(value.unwrap())?;
            let num = serial_params.num;
            let key = (serial_params.hardware, num);
            if cfg.serial_parameters.contains_key(&key) {
                return Err(argument::Error::TooManyArguments(format!(
                    "serial hardware {} num {}",
                    serial_params.hardware, num,
                )));
            }

            if serial_params.console {
                for params in cfg.serial_parameters.values() {
                    if params.console {
                        return Err(argument::Error::TooManyArguments(format!(
                            "{} device {} already set as console",
                            params.hardware, params.num,
                        )));
                    }
                }
            }

            if serial_params.earlycon {
                // Only SerialHardware::Serial supports earlycon= currently.
                match serial_params.hardware {
                    SerialHardware::Serial => {}
                    _ => {
                        return Err(argument::Error::InvalidValue {
                            value: serial_params.hardware.to_string(),
                            expected: String::from("earlycon not supported for hardware"),
                        });
                    }
                }
                for params in cfg.serial_parameters.values() {
                    if params.earlycon {
                        return Err(argument::Error::TooManyArguments(format!(
                            "{} device {} already set as earlycon",
                            params.hardware, params.num,
                        )));
                    }
                }
            }

            if serial_params.stdin {
                if let Some(previous_stdin) = cfg.serial_parameters.values().find(|sp| sp.stdin) {
                    return Err(argument::Error::TooManyArguments(format!(
                        "{} device {} already connected to standard input",
                        previous_stdin.hardware, previous_stdin.num,
                    )));
                }
            }

            cfg.serial_parameters.insert(key, serial_params);
        }
        "syslog-tag" => {
            if cfg.syslog_tag.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`syslog-tag` already given".to_owned(),
                ));
            }
            syslog::set_proc_name(value.unwrap());
            cfg.syslog_tag = Some(value.unwrap().to_owned());
        }
        "root" | "rwroot" | "disk" | "rwdisk" => {
            let param = value.unwrap();
            let mut components = param.split(',');
            let read_only = !name.starts_with("rw");
            let disk_path =
                PathBuf::from(
                    components
                        .next()
                        .ok_or_else(|| argument::Error::InvalidValue {
                            value: param.to_owned(),
                            expected: String::from("missing disk path"),
                        })?,
                );
            if !disk_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: param.to_owned(),
                    expected: String::from("this disk path does not exist"),
                });
            }
            if name.ends_with("root") {
                if cfg.disks.len() >= 26 {
                    return Err(argument::Error::TooManyArguments(
                        "ran out of letters for to assign to root disk".to_owned(),
                    ));
                }
                cfg.params.push(format!(
                    "root=/dev/vd{} {}",
                    char::from(b'a' + cfg.disks.len() as u8),
                    if read_only { "ro" } else { "rw" }
                ));
            }

            let mut disk = DiskOption {
                path: disk_path,
                read_only,
                sparse: true,
                block_size: 512,
                id: None,
            };

            for opt in components {
                let mut o = opt.splitn(2, '=');
                let kind = o.next().ok_or_else(|| argument::Error::InvalidValue {
                    value: opt.to_owned(),
                    expected: String::from("disk options must not be empty"),
                })?;
                let value = o.next().ok_or_else(|| argument::Error::InvalidValue {
                    value: opt.to_owned(),
                    expected: String::from("disk options must be of the form `kind=value`"),
                })?;

                match kind {
                    "sparse" => {
                        let sparse = value.parse().map_err(|_| argument::Error::InvalidValue {
                            value: value.to_owned(),
                            expected: String::from("`sparse` must be a boolean"),
                        })?;
                        disk.sparse = sparse;
                    }
                    "block_size" => {
                        let block_size =
                            value.parse().map_err(|_| argument::Error::InvalidValue {
                                value: value.to_owned(),
                                expected: String::from("`block_size` must be an integer"),
                            })?;
                        disk.block_size = block_size;
                    }
                    "id" => {
                        if value.len() > DISK_ID_LEN {
                            return Err(argument::Error::InvalidValue {
                                value: value.to_owned(),
                                expected: format!(
                                    "`id` must be {} or fewer characters",
                                    DISK_ID_LEN
                                ),
                            });
                        }
                        let mut id = [0u8; DISK_ID_LEN];
                        // Slicing id to value's length will never panic
                        // because we checked that value will fit into id above.
                        id[..value.len()].copy_from_slice(value.as_bytes());
                        disk.id = Some(id);
                    }
                    _ => {
                        return Err(argument::Error::InvalidValue {
                            value: kind.to_owned(),
                            expected: String::from("unrecognized disk option"),
                        });
                    }
                }
            }

            cfg.disks.push(disk);
        }
        "pmem-device" | "rw-pmem-device" => {
            let disk_path = PathBuf::from(value.unwrap());
            if !disk_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("this disk path does not exist"),
                });
            }

            cfg.pmem_devices.push(DiskOption {
                path: disk_path,
                read_only: !name.starts_with("rw"),
                sparse: false,
                block_size: base::pagesize() as u32,
                id: None,
            });
        }
        "pstore" => {
            if cfg.pstore.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`pstore` already given".to_owned(),
                ));
            }

            let value = value.unwrap();
            let components: Vec<&str> = value.split(',').collect();
            if components.len() != 2 {
                return Err(argument::Error::InvalidValue {
                    value: value.to_owned(),
                    expected: String::from(
                        "pstore must have exactly 2 components: path=<path>,size=<size>",
                    ),
                });
            }
            cfg.pstore = Some(Pstore {
                path: {
                    if components[0].len() <= 5 || !components[0].starts_with("path=") {
                        return Err(argument::Error::InvalidValue {
                            value: components[0].to_owned(),
                            expected: String::from("pstore path must follow with `path=`"),
                        });
                    };
                    PathBuf::from(&components[0][5..])
                },
                size: {
                    if components[1].len() <= 5 || !components[1].starts_with("size=") {
                        return Err(argument::Error::InvalidValue {
                            value: components[1].to_owned(),
                            expected: String::from("pstore size must follow with `size=`"),
                        });
                    };
                    components[1][5..]
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.to_owned(),
                            expected: String::from("pstore size must be an integer"),
                        })?
                },
            });
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
        "net-vq-pairs" => {
            if cfg.net_vq_pairs.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`net-vq-pairs` already given".to_owned(),
                ));
            }
            cfg.net_vq_pairs =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from(
                                "this value for `net-vq-pairs` needs to be integer",
                            ),
                        })?,
                )
        }

        "wayland-sock" => {
            let mut components = value.unwrap().split(',');
            let path =
                PathBuf::from(
                    components
                        .next()
                        .ok_or_else(|| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from("missing socket path"),
                        })?,
                );
            let mut name = "";
            for c in components {
                let mut kv = c.splitn(2, '=');
                let (kind, value) = match (kv.next(), kv.next()) {
                    (Some(kind), Some(value)) => (kind, value),
                    _ => {
                        return Err(argument::Error::InvalidValue {
                            value: c.to_owned(),
                            expected: String::from("option must be of the form `kind=value`"),
                        })
                    }
                };
                match kind {
                    "name" => name = value,
                    _ => {
                        return Err(argument::Error::InvalidValue {
                            value: kind.to_owned(),
                            expected: String::from("unrecognized option"),
                        })
                    }
                }
            }
            if cfg.wayland_socket_paths.contains_key(name) {
                return Err(argument::Error::TooManyArguments(format!(
                    "wayland socket name already used: '{}'",
                    name
                )));
            }
            cfg.wayland_socket_paths.insert(name.to_string(), path);
        }
        #[cfg(feature = "wl-dmabuf")]
        "wayland-dmabuf" => cfg.wayland_dmabuf = true,
        "x-display" => {
            if cfg.x_display.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`x-display` already given".to_owned(),
                ));
            }
            cfg.x_display = Some(value.unwrap().to_owned());
        }
        "display-window-keyboard" => {
            cfg.display_window_keyboard = true;
        }
        "display-window-mouse" => {
            cfg.display_window_mouse = true;
        }
        "socket" => {
            if cfg.socket_path.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`socket` already given".to_owned(),
                ));
            }
            let mut socket_path = PathBuf::from(value.unwrap());
            if socket_path.is_dir() {
                socket_path.push(format!("crosvm-{}.sock", getpid()));
            }
            if socket_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: socket_path.to_string_lossy().into_owned(),
                    expected: String::from("this socket path already exists"),
                });
            }
            cfg.socket_path = Some(socket_path);
        }
        "disable-sandbox" => {
            cfg.sandbox = false;
        }
        "cid" => {
            if cfg.cid.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`cid` alread given".to_owned(),
                ));
            }
            cfg.cid = Some(
                value
                    .unwrap()
                    .parse()
                    .map_err(|_| argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: String::from("this value for `cid` must be an unsigned integer"),
                    })?,
            );
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
        "seccomp-policy-dir" => {
            // `value` is Some because we are in this match so it's safe to unwrap.
            cfg.seccomp_policy_dir = PathBuf::from(value.unwrap());
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
            cfg.seccomp_log_failures = true;
        }
        "plugin" => {
            if cfg.executable_path.is_some() {
                return Err(argument::Error::TooManyArguments(format!(
                    "A VM executable was already specified: {:?}",
                    cfg.executable_path
                )));
            }
            let plugin = PathBuf::from(value.unwrap().to_owned());
            if plugin.is_relative() {
                return Err(argument::Error::InvalidValue {
                    value: plugin.to_string_lossy().into_owned(),
                    expected: String::from("the plugin path must be an absolute path"),
                });
            }
            cfg.executable_path = Some(Executable::Plugin(plugin));
        }
        "plugin-root" => {
            cfg.plugin_root = Some(PathBuf::from(value.unwrap().to_owned()));
        }
        "plugin-mount" => {
            let mount = parse_plugin_mount_option(value.unwrap())?;
            cfg.plugin_mounts.push(mount);
        }
        "plugin-mount-file" => {
            let file = File::open(value.unwrap()).map_err(|_| argument::Error::InvalidValue {
                value: value.unwrap().to_owned(),
                expected: String::from("unable to open `plugin-mount-file` file"),
            })?;
            let reader = BufReader::new(file);
            for l in reader.lines() {
                let line = l.unwrap();
                let trimmed_line = line.splitn(2, '#').next().unwrap().trim();
                if !trimmed_line.is_empty() {
                    let mount = parse_plugin_mount_option(trimmed_line)?;
                    cfg.plugin_mounts.push(mount);
                }
            }
        }
        "plugin-gid-map" => {
            let map = parse_plugin_gid_map_option(value.unwrap())?;
            cfg.plugin_gid_maps.push(map);
        }
        "plugin-gid-map-file" => {
            let file = File::open(value.unwrap()).map_err(|_| argument::Error::InvalidValue {
                value: value.unwrap().to_owned(),
                expected: String::from("unable to open `plugin-gid-map-file` file"),
            })?;
            let reader = BufReader::new(file);
            for l in reader.lines() {
                let line = l.unwrap();
                let trimmed_line = line.splitn(2, '#').next().unwrap().trim();
                if !trimmed_line.is_empty() {
                    let map = parse_plugin_gid_map_option(trimmed_line)?;
                    cfg.plugin_gid_maps.push(map);
                }
            }
        }
        "vhost-net" => cfg.vhost_net = true,
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
        #[cfg(feature = "gpu")]
        "gpu" => {
            let params = parse_gpu_options(value)?;
            cfg.gpu_parameters = Some(params);
        }
        "software-tpm" => {
            cfg.software_tpm = true;
        }
        "single-touch" => {
            if cfg.virtio_single_touch.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`single-touch` already given".to_owned(),
                ));
            }
            let mut it = value.unwrap().split(':');

            let mut single_touch_spec =
                TouchDeviceOption::new(PathBuf::from(it.next().unwrap().to_owned()));
            if let Some(width) = it.next() {
                single_touch_spec.set_width(width.trim().parse().unwrap());
            }
            if let Some(height) = it.next() {
                single_touch_spec.set_height(height.trim().parse().unwrap());
            }
            cfg.virtio_single_touch = Some(single_touch_spec);
        }
        "multi-touch" => {
            if cfg.virtio_multi_touch.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`multi-touch` already given".to_owned(),
                ));
            }
            let mut it = value.unwrap().split(':');

            let mut multi_touch_spec =
                TouchDeviceOption::new(PathBuf::from(it.next().unwrap().to_owned()));
            if let Some(width) = it.next() {
                multi_touch_spec.set_width(width.trim().parse().unwrap());
            }
            if let Some(height) = it.next() {
                multi_touch_spec.set_height(height.trim().parse().unwrap());
            }
            cfg.virtio_multi_touch = Some(multi_touch_spec);
        }
        "trackpad" => {
            if cfg.virtio_trackpad.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`trackpad` already given".to_owned(),
                ));
            }
            let mut it = value.unwrap().split(':');

            let mut trackpad_spec =
                TouchDeviceOption::new(PathBuf::from(it.next().unwrap().to_owned()));
            if let Some(width) = it.next() {
                trackpad_spec.set_width(width.trim().parse().unwrap());
            }
            if let Some(height) = it.next() {
                trackpad_spec.set_height(height.trim().parse().unwrap());
            }
            cfg.virtio_trackpad = Some(trackpad_spec);
        }
        "mouse" => {
            if cfg.virtio_mouse.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`mouse` already given".to_owned(),
                ));
            }
            cfg.virtio_mouse = Some(PathBuf::from(value.unwrap().to_owned()));
        }
        "keyboard" => {
            if cfg.virtio_keyboard.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`keyboard` already given".to_owned(),
                ));
            }
            cfg.virtio_keyboard = Some(PathBuf::from(value.unwrap().to_owned()));
        }
        "switches" => {
            if cfg.virtio_switches.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`switches` already given".to_owned(),
                ));
            }
            cfg.virtio_switches = Some(PathBuf::from(value.unwrap().to_owned()));
        }
        "evdev" => {
            let dev_path = PathBuf::from(value.unwrap());
            if !dev_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("this input device path does not exist"),
                });
            }
            cfg.virtio_input_evdevs.push(dev_path);
        }
        "split-irqchip" => {
            cfg.split_irqchip = true;
        }
        "initrd" => {
            cfg.initrd_path = Some(PathBuf::from(value.unwrap().to_owned()));
        }
        "bios" => {
            if cfg.executable_path.is_some() {
                return Err(argument::Error::TooManyArguments(format!(
                    "A VM executable was already specified: {:?}",
                    cfg.executable_path
                )));
            }
            cfg.executable_path = Some(Executable::Bios(PathBuf::from(value.unwrap().to_owned())));
        }
        "vfio" => {
            let vfio_path = PathBuf::from(value.unwrap());
            if !vfio_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("the vfio path does not exist"),
                });
            }
            if !vfio_path.is_dir() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("the vfio path should be directory"),
                });
            }

            cfg.vfio.push(vfio_path);
        }
        "video-decoder" => {
            cfg.video_dec = true;
        }
        "video-encoder" => {
            cfg.video_enc = true;
        }
        "acpi-table" => {
            let acpi_table = PathBuf::from(value.unwrap());
            if !acpi_table.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("the acpi-table path does not exist"),
                });
            }
            if !acpi_table.is_file() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("the acpi-table path should be a file"),
                });
            }

            cfg.acpi_tables.push(acpi_table);
        }
        "protected-vm" => {
            cfg.protected_vm = ProtectionType::Protected;
            cfg.params.push("swiotlb=force".to_string());
        }
        "battery" => {
            let params = parse_battery_options(value)?;
            cfg.battery_type = Some(params);
        }
        #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
        "gdb" => {
            let port = value
                .unwrap()
                .parse()
                .map_err(|_| argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("expected a valid port number"),
                })?;
            cfg.gdb = Some(port);
        }
        "balloon_bias_mib" => {
            cfg.balloon_bias =
                value
                    .unwrap()
                    .parse::<i64>()
                    .map_err(|_| argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: String::from("expected a valid ballon bias in MiB"),
                    })?
                    * 1024
                    * 1024; // cfg.balloon_bias is in bytes.
        }
        "vhost-user-blk" => cfg.vhost_user_blk.push(VhostUserOption {
            socket: PathBuf::from(value.unwrap()),
        }),
        "vhost-user-net" => cfg.vhost_user_net.push(VhostUserOption {
            socket: PathBuf::from(value.unwrap()),
        }),
        "vhost-user-fs" => {
            // (socket:tag)
            let param = value.unwrap();
            let mut components = param.split(':');
            let socket =
                PathBuf::from(
                    components
                        .next()
                        .ok_or_else(|| argument::Error::InvalidValue {
                            value: param.to_owned(),
                            expected: String::from("missing socket path for `vhost-user-fs`"),
                        })?,
                );
            let tag = components
                .next()
                .ok_or_else(|| argument::Error::InvalidValue {
                    value: param.to_owned(),
                    expected: String::from("missing tag for `vhost-user-fs`"),
                })?
                .to_owned();
            cfg.vhost_user_fs.push(VhostUserFsOption { socket, tag });
        }
        #[cfg(feature = "direct")]
        "direct-pmio" => {
            if cfg.direct_pmio.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`direct_pmio` already given".to_owned(),
                ));
            }
            cfg.direct_pmio = Some(parse_direct_io_options(value)?);
        }
        #[cfg(feature = "direct")]
        "direct-level-irq" => {
            cfg.direct_level_irq
                .push(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from(
                                "this value for `direct-level-irq` must be an unsigned integer",
                            ),
                        })?,
                );
        }
        #[cfg(feature = "direct")]
        "direct-edge-irq" => {
            cfg.direct_edge_irq
                .push(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from(
                                "this value for `direct-edge-irq` must be an unsigned integer",
                            ),
                        })?,
                );
        }
        "dmi" => {
            if cfg.dmi_path.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`dmi` already given".to_owned(),
                ));
            }
            let dmi_path = PathBuf::from(value.unwrap());
            if !dmi_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("the dmi path does not exist"),
                });
            }
            if !dmi_path.is_dir() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("the dmi path should be directory"),
                });
            }
            cfg.dmi_path = Some(dmi_path);
        }
        "help" => return Err(argument::Error::PrintHelp),
        _ => unreachable!(),
    }
    Ok(())
}

fn validate_arguments(cfg: &mut Config) -> std::result::Result<(), argument::Error> {
    if cfg.executable_path.is_none() {
        return Err(argument::Error::ExpectedArgument("`KERNEL`".to_owned()));
    }
    if cfg.host_ip.is_some() || cfg.netmask.is_some() || cfg.mac_address.is_some() {
        if cfg.host_ip.is_none() {
            return Err(argument::Error::ExpectedArgument(
                "`host_ip` missing from network config".to_owned(),
            ));
        }
        if cfg.netmask.is_none() {
            return Err(argument::Error::ExpectedArgument(
                "`netmask` missing from network config".to_owned(),
            ));
        }
        if cfg.mac_address.is_none() {
            return Err(argument::Error::ExpectedArgument(
                "`mac` missing from network config".to_owned(),
            ));
        }
    }
    if cfg.plugin_root.is_some() && !executable_is_plugin(&cfg.executable_path) {
        return Err(argument::Error::ExpectedArgument(
            "`plugin-root` requires `plugin`".to_owned(),
        ));
    }
    #[cfg(feature = "gpu")]
    {
        if let Some(gpu_parameters) = cfg.gpu_parameters.as_ref() {
            let (width, height) = (gpu_parameters.display_width, gpu_parameters.display_height);
            if let Some(virtio_multi_touch) = cfg.virtio_multi_touch.as_mut() {
                virtio_multi_touch.set_default_size(width, height);
            }
            if let Some(virtio_single_touch) = cfg.virtio_single_touch.as_mut() {
                virtio_single_touch.set_default_size(width, height);
            }
        }
    }
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    if cfg.gdb.is_some() {
        if cfg.vcpu_count.unwrap_or(1) != 1 {
            return Err(argument::Error::ExpectedArgument(
                "`gdb` requires the number of vCPU to be 1".to_owned(),
            ));
        }
    }
    set_default_serial_parameters(&mut cfg.serial_parameters);
    Ok(())
}

fn run_vm(args: std::env::Args) -> std::result::Result<(), ()> {
    let arguments =
        &[Argument::positional("KERNEL", "bzImage of kernel to run"),
          Argument::value("kvm-device", "PATH", "Path to the KVM device. (default /dev/kvm)"),
          Argument::value("vhost-vsock-device", "PATH", "Path to the vhost-vsock device. (default /dev/vhost-vsock)"),
          Argument::value("vhost-net-device", "PATH", "Path to the vhost-net device. (default /dev/vhost-net)"),
          Argument::value("android-fstab", "PATH", "Path to Android fstab"),
          Argument::short_value('i', "initrd", "PATH", "Initial ramdisk to load."),
          Argument::short_value('p',
                                "params",
                                "PARAMS",
                                "Extra kernel or plugin command line arguments. Can be given more than once."),
          Argument::short_value('c', "cpus", "N", "Number of VCPUs. (default: 1)"),
          Argument::value("cpu-affinity", "CPUSET", "Comma-separated list of CPUs or CPU ranges to run VCPUs on (e.g. 0,1-3,5)
                              or colon-separated list of assignments of guest to host CPU assignments (e.g. 0=0:1=1:2=2) (default: no mask)"),
          Argument::flag("no-smt", "Don't use SMT in the guest"),
          Argument::value("rt-cpus", "CPUSET", "Comma-separated list of CPUs or CPU ranges to run VCPUs on. (e.g. 0,1-3,5) (default: none)"),
          Argument::short_value('m',
                                "mem",
                                "N",
                                "Amount of guest memory in MiB. (default: 256)"),
          Argument::flag("hugepages", "Advise the kernel to use Huge Pages for guest memory mappings."),
          Argument::short_value('r',
                                "root",
                                "PATH[,key=value[,key=value[,...]]",
                                "Path to a root disk image followed by optional comma-separated options.
                              Like `--disk` but adds appropriate kernel command line option.
                              See --disk for valid options."),
          Argument::value("rwroot", "PATH[,key=value[,key=value[,...]]", "Path to a writable root disk image followed by optional comma-separated options.
                              See --disk for valid options."),
          Argument::short_value('d', "disk", "PATH[,key=value[,key=value[,...]]", "Path to a disk image followed by optional comma-separated options.
                              Valid keys:
                              sparse=BOOL - Indicates whether the disk should support the discard operation (default: true)
                              block_size=BYTES - Set the reported block size of the disk (default: 512)
                              id=STRING - Set the block device identifier to an ASCII string, up to 20 characters (default: no ID)"),
          Argument::value("rwdisk", "PATH[,key=value[,key=value[,...]]", "Path to a writable disk image followed by optional comma-separated options.
                              See --disk for valid options."),
          Argument::value("rw-pmem-device", "PATH", "Path to a writable disk image."),
          Argument::value("pmem-device", "PATH", "Path to a disk image."),
          Argument::value("pstore", "path=PATH,size=SIZE", "Path to pstore buffer backend file follewed by size."),
          Argument::value("host_ip",
                          "IP",
                          "IP address to assign to host tap interface."),
          Argument::value("netmask", "NETMASK", "Netmask for VM subnet."),
          Argument::value("mac", "MAC", "MAC address for VM."),
          Argument::value("net-vq-pairs", "N", "virtio net virtual queue paris. (default: 1)"),
          #[cfg(feature = "audio")]
          Argument::value("ac97",
                          "[backend=BACKEND,capture=true,capture_effect=EFFECT,client_type=TYPE,shm-fd=FD,client-fd=FD,server-fd=FD]",
                          "Comma separated key=value pairs for setting up Ac97 devices. Can be given more than once .
                          Possible key values:
                          backend=(null, cras, vios) - Where to route the audio device. If not provided, backend will default to null.
                          `null` for /dev/null, cras for CRAS server and vios for VioS server.
                          capture - Enable audio capture
                          capture_effects - | separated effects to be enabled for recording. The only supported effect value now is EchoCancellation or aec.
                          client_type - Set specific client type for cras backend.
                          server - The to the VIOS server (unix socket)."),
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
          Argument::value("syslog-tag", "TAG", "When logging to syslog, use the provided tag."),
          Argument::value("x-display", "DISPLAY", "X11 display name to use."),
          Argument::flag("display-window-keyboard", "Capture keyboard input from the display window."),
          Argument::flag("display-window-mouse", "Capture keyboard input from the display window."),
          Argument::value("wayland-sock", "PATH[,name=NAME]", "Path to the Wayland socket to use. The unnamed one is used for displaying virtual screens. Named ones are only for IPC."),
          #[cfg(feature = "wl-dmabuf")]
          Argument::flag("wayland-dmabuf", "Enable support for DMABufs in Wayland device."),
          Argument::short_value('s',
                                "socket",
                                "PATH",
                                "Path to put the control socket. If PATH is a directory, a name will be generated."),
          Argument::flag("disable-sandbox", "Run all devices in one, non-sandboxed process."),
          Argument::value("cid", "CID", "Context ID for virtual sockets."),
          Argument::value("shared-dir", "PATH:TAG[:type=TYPE:writeback=BOOL:timeout=SECONDS:uidmap=UIDMAP:gidmap=GIDMAP:cache=CACHE]",
                          "Colon-separated options for configuring a directory to be shared with the VM.
The first field is the directory to be shared and the second field is the tag that the VM can use to identify the device.
The remaining fields are key=value pairs that may appear in any order.  Valid keys are:
type=(p9, fs) - Indicates whether the directory should be shared via virtio-9p or virtio-fs (default: p9).
uidmap=UIDMAP - The uid map to use for the device's jail in the format \"inner outer count[,inner outer count]\" (default: 0 <current euid> 1).
gidmap=GIDMAP - The gid map to use for the device's jail in the format \"inner outer count[,inner outer count]\" (default: 0 <current egid> 1).
cache=(never, auto, always) - Indicates whether the VM can cache the contents of the shared directory (default: auto).  When set to \"auto\" and the type is \"fs\", the VM will use close-to-open consistency for file contents.
timeout=SECONDS - How long the VM should consider file attributes and directory entries to be valid (default: 5).  If the VM has exclusive access to the directory, then this should be a large value.  If the directory can be modified by other processes, then this should be 0.
writeback=BOOL - Indicates whether the VM can use writeback caching (default: false).  This is only safe to do when the VM has exclusive access to the files in a directory.  Additionally, the server should have read permission for all files as the VM may issue read requests even for files that are opened write-only.
"),
          Argument::value("seccomp-policy-dir", "PATH", "Path to seccomp .policy files."),
          Argument::flag("seccomp-log-failures", "Instead of seccomp filter failures being fatal, they will be logged instead."),
          #[cfg(feature = "plugin")]
          Argument::value("plugin", "PATH", "Absolute path to plugin process to run under crosvm."),
          #[cfg(feature = "plugin")]
          Argument::value("plugin-root", "PATH", "Absolute path to a directory that will become root filesystem for the plugin process."),
          #[cfg(feature = "plugin")]
          Argument::value("plugin-mount", "PATH:PATH:BOOL", "Path to be mounted into the plugin's root filesystem.  Can be given more than once."),
          #[cfg(feature = "plugin")]
          Argument::value("plugin-mount-file", "PATH", "Path to the file listing paths be mounted into the plugin's root filesystem.  Can be given more than once."),
          #[cfg(feature = "plugin")]
          Argument::value("plugin-gid-map", "GID:GID:INT", "Supplemental GIDs that should be mapped in plugin jail.  Can be given more than once."),
          #[cfg(feature = "plugin")]
          Argument::value("plugin-gid-map-file", "PATH", "Path to the file listing supplemental GIDs that should be mapped in plugin jail.  Can be given more than once."),
          Argument::flag("vhost-net", "Use vhost for networking."),
          Argument::value("tap-fd",
                          "fd",
                          "File descriptor for configured tap device. A different virtual network card will be added each time this argument is given."),
          #[cfg(feature = "gpu")]
          Argument::flag_or_value("gpu",
                                  "[width=INT,height=INT]",
                                  "(EXPERIMENTAL) Comma separated key=value pairs for setting up a virtio-gpu device
                                  Possible key values:
                                  backend=(2d|virglrenderer|gfxstream) - Which backend to use for virtio-gpu (determining rendering protocol)
                                  width=INT - The width of the virtual display connected to the virtio-gpu.
                                  height=INT - The height of the virtual display connected to the virtio-gpu.
                                  egl[=true|=false] - If the backend should use a EGL context for rendering.
                                  glx[=true|=false] - If the backend should use a GLX context for rendering.
                                  surfaceless[=true|=false] - If the backend should use a surfaceless context for rendering.
                                  angle[=true|=false] - If the gfxstream backend should use ANGLE (OpenGL on Vulkan) as its native OpenGL driver.
                                  syncfd[=true|=false] - If the gfxstream backend should support EGL_ANDROID_native_fence_sync
                                  vulkan[=true|=false] - If the backend should support vulkan
                                  "),
          #[cfg(feature = "tpm")]
          Argument::flag("software-tpm", "enable a software emulated trusted platform module device"),
          Argument::value("evdev", "PATH", "Path to an event device node. The device will be grabbed (unusable from the host) and made available to the guest with the same configuration it shows on the host"),
          Argument::value("single-touch", "PATH:WIDTH:HEIGHT", "Path to a socket from where to read single touch input events (such as those from a touchscreen) and write status updates to, optionally followed by width and height (defaults to 800x1280)."),
          Argument::value("multi-touch", "PATH:WIDTH:HEIGHT", "Path to a socket from where to read multi touch input events (such as those from a touchscreen) and write status updates to, optionally followed by width and height (defaults to 800x1280)."),
          Argument::value("trackpad", "PATH:WIDTH:HEIGHT", "Path to a socket from where to read trackpad input events and write status updates to, optionally followed by screen width and height (defaults to 800x1280)."),
          Argument::value("mouse", "PATH", "Path to a socket from where to read mouse input events and write status updates to."),
          Argument::value("keyboard", "PATH", "Path to a socket from where to read keyboard input events and write status updates to."),
          Argument::value("switches", "PATH", "Path to a socket from where to read switch input events and write status updates to."),
          #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
          Argument::flag("split-irqchip", "(EXPERIMENTAL) enable split-irqchip support"),
          Argument::value("bios", "PATH", "Path to BIOS/firmware ROM"),
          Argument::value("vfio", "PATH", "Path to sysfs of pass through or mdev device"),
          #[cfg(feature = "video-decoder")]
          Argument::flag("video-decoder", "(EXPERIMENTAL) enable virtio-video decoder device"),
          #[cfg(feature = "video-encoder")]
          Argument::flag("video-encoder", "(EXPERIMENTAL) enable virtio-video encoder device"),
          Argument::value("acpi-table", "PATH", "Path to user provided ACPI table"),
          Argument::flag("protected-vm", "(EXPERIMENTAL) prevent host access to guest memory"),
          Argument::flag_or_value("battery",
                                  "[type=TYPE]",
                                  "Comma separated key=value pairs for setting up battery device
                                  Possible key values:
                                  type=goldfish - type of battery emulation, defaults to goldfish
                                  "),
          Argument::value("gdb", "PORT", "(EXPERIMENTAL) gdb on the given port"),
          Argument::value("balloon_bias_mib", "N", "Amount to bias balance of memory between host and guest as the balloon inflates, in MiB."),
          Argument::value("vhost-user-blk", "SOCKET_PATH", "Path to a socket for vhost-user block"),
          Argument::value("vhost-user-net", "SOCKET_PATH", "Path to a socket for vhost-user net"),
          Argument::value("vhost-user-fs", "SOCKET_PATH:TAG",
                          "Path to a socket path for vhost-user fs, and tag for the shared dir"),
          #[cfg(feature = "direct")]
          Argument::value("direct-pmio", "PATH@RANGE[,RANGE[,...]]", "Path and ranges for direct port I/O access"),
          #[cfg(feature = "direct")]
          Argument::value("direct-level-irq", "irq", "Enable interrupt passthrough"),
          #[cfg(feature = "direct")]
          Argument::value("direct-edge-irq", "irq", "Enable interrupt passthrough"),
          Argument::value("dmi", "DIR", "Directory with smbios_entry_point/DMI files"),
          Argument::short_flag('h', "help", "Print help message.")];

    let mut cfg = Config::default();
    let match_res = set_arguments(args, &arguments[..], |name, value| {
        set_argument(&mut cfg, name, value)
    })
    .and_then(|_| validate_arguments(&mut cfg));

    match match_res {
        #[cfg(feature = "plugin")]
        Ok(()) if executable_is_plugin(&cfg.executable_path) => {
            match crosvm::plugin::run_config(cfg) {
                Ok(_) => {
                    info!("crosvm and plugin have exited normally");
                    Ok(())
                }
                Err(e) => {
                    error!("{}", e);
                    Err(())
                }
            }
        }
        Ok(()) => match platform::run_config(cfg) {
            Ok(_) => {
                info!("crosvm has exited normally");
                Ok(())
            }
            Err(e) => {
                error!("crosvm has exited with error: {}", e);
                Err(())
            }
        },
        Err(argument::Error::PrintHelp) => {
            print_help("crosvm run", "KERNEL", &arguments[..]);
            Ok(())
        }
        Err(e) => {
            error!("{}", e);
            Err(())
        }
    }
}

fn stop_vms(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() == 0 {
        print_help("crosvm stop", "VM_SOCKET...", &[]);
        println!("Stops the crosvm instance listening on each `VM_SOCKET` given.");
        return Err(());
    }
    let socket_path = &args.next().unwrap();
    let socket_path = Path::new(&socket_path);
    vms_request(&VmRequest::Exit, socket_path)
}

fn suspend_vms(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() == 0 {
        print_help("crosvm suspend", "VM_SOCKET...", &[]);
        println!("Suspends the crosvm instance listening on each `VM_SOCKET` given.");
        return Err(());
    }
    let socket_path = &args.next().unwrap();
    let socket_path = Path::new(&socket_path);
    vms_request(&VmRequest::Suspend, socket_path)
}

fn resume_vms(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() == 0 {
        print_help("crosvm resume", "VM_SOCKET...", &[]);
        println!("Resumes the crosvm instance listening on each `VM_SOCKET` given.");
        return Err(());
    }
    let socket_path = &args.next().unwrap();
    let socket_path = Path::new(&socket_path);
    vms_request(&VmRequest::Resume, socket_path)
}

fn balloon_vms(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() < 2 {
        print_help("crosvm balloon", "SIZE VM_SOCKET...", &[]);
        println!("Set the ballon size of the crosvm instance to `SIZE` bytes.");
        return Err(());
    }
    let num_bytes = match args.next().unwrap().parse::<u64>() {
        Ok(n) => n,
        Err(_) => {
            error!("Failed to parse number of bytes");
            return Err(());
        }
    };

    let command = BalloonControlCommand::Adjust { num_bytes };
    let socket_path = &args.next().unwrap();
    let socket_path = Path::new(&socket_path);
    vms_request(&VmRequest::BalloonCommand(command), socket_path)
}

fn balloon_stats(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() != 1 {
        print_help("crosvm balloon_stats", "VM_SOCKET", &[]);
        println!("Prints virtio balloon statistics for a `VM_SOCKET`.");
        return Err(());
    }
    let command = BalloonControlCommand::Stats {};
    let request = &VmRequest::BalloonCommand(command);
    let socket_path = &args.next().unwrap();
    let socket_path = Path::new(&socket_path);
    let response = handle_request(request, socket_path)?;
    println!("{}", response);
    Ok(())
}

fn create_qcow2(args: std::env::Args) -> std::result::Result<(), ()> {
    let arguments = [
        Argument::positional("PATH", "where to create the qcow2 image"),
        Argument::positional("[SIZE]", "the expanded size of the image"),
        Argument::value(
            "backing_file",
            "path/to/file",
            " the file to back the image",
        ),
    ];
    let mut positional_index = 0;
    let mut file_path = String::from("");
    let mut size: Option<u64> = None;
    let mut backing_file: Option<String> = None;
    set_arguments(args, &arguments[..], |name, value| {
        match (name, positional_index) {
            ("", 0) => {
                // NAME
                positional_index += 1;
                file_path = value.unwrap().to_owned();
            }
            ("", 1) => {
                // [SIZE]
                positional_index += 1;
                size = Some(value.unwrap().parse::<u64>().map_err(|_| {
                    argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: String::from("SIZE should be a nonnegative integer"),
                    }
                })?);
            }
            ("", _) => {
                return Err(argument::Error::TooManyArguments(
                    "Expected at most 2 positional arguments".to_owned(),
                ));
            }
            ("backing_file", _) => {
                backing_file = value.map(|x| x.to_owned());
            }
            _ => unreachable!(),
        };
        Ok(())
    })
    .map_err(|e| {
        error!("Unable to parse command line arguments: {}", e);
    })?;
    if file_path.is_empty() || !(size.is_some() ^ backing_file.is_some()) {
        print_help("crosvm create_qcow2", "PATH [SIZE]", &arguments);
        println!(
            "Create a new QCOW2 image at `PATH` of either the specified `SIZE` in bytes or
with a '--backing_file'."
        );
        return Err(());
    }

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&file_path)
        .map_err(|e| {
            error!("Failed opening qcow file at '{}': {}", file_path, e);
        })?;

    match (size, backing_file) {
        (Some(size), None) => QcowFile::new(file, size).map_err(|e| {
            error!("Failed to create qcow file at '{}': {}", file_path, e);
        })?,
        (None, Some(backing_file)) => {
            QcowFile::new_from_backing(file, &backing_file).map_err(|e| {
                error!("Failed to create qcow file at '{}': {}", file_path, e);
            })?
        }
        _ => unreachable!(),
    };
    Ok(())
}

fn disk_cmd(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() < 2 {
        print_help("crosvm disk", "SUBCOMMAND VM_SOCKET...", &[]);
        println!("Manage attached virtual disk devices.");
        println!("Subcommands:");
        println!("  resize DISK_INDEX NEW_SIZE VM_SOCKET");
        return Err(());
    }
    let subcommand: &str = &args.next().unwrap();

    let request = match subcommand {
        "resize" => {
            let disk_index = match args.next().unwrap().parse::<usize>() {
                Ok(n) => n,
                Err(_) => {
                    error!("Failed to parse disk index");
                    return Err(());
                }
            };

            let new_size = match args.next().unwrap().parse::<u64>() {
                Ok(n) => n,
                Err(_) => {
                    error!("Failed to parse disk size");
                    return Err(());
                }
            };

            VmRequest::DiskCommand {
                disk_index,
                command: DiskControlCommand::Resize { new_size },
            }
        }
        _ => {
            error!("Unknown disk subcommand '{}'", subcommand);
            return Err(());
        }
    };

    let socket_path = &args.next().unwrap();
    let socket_path = Path::new(&socket_path);
    vms_request(&request, socket_path)
}

fn parse_bus_id_addr(v: &str) -> ModifyUsbResult<(u8, u8, u16, u16)> {
    debug!("parse_bus_id_addr: {}", v);
    let mut ids = v.split(':');
    match (ids.next(), ids.next(), ids.next(), ids.next()) {
        (Some(bus_id), Some(addr), Some(vid), Some(pid)) => {
            let bus_id = bus_id
                .parse::<u8>()
                .map_err(|e| ModifyUsbError::ArgParseInt("bus_id", bus_id.to_owned(), e))?;
            let addr = addr
                .parse::<u8>()
                .map_err(|e| ModifyUsbError::ArgParseInt("addr", addr.to_owned(), e))?;
            let vid = u16::from_str_radix(&vid, 16)
                .map_err(|e| ModifyUsbError::ArgParseInt("vid", vid.to_owned(), e))?;
            let pid = u16::from_str_radix(&pid, 16)
                .map_err(|e| ModifyUsbError::ArgParseInt("pid", pid.to_owned(), e))?;
            Ok((bus_id, addr, vid, pid))
        }
        _ => Err(ModifyUsbError::ArgParse(
            "BUS_ID_ADDR_BUS_NUM_DEV_NUM",
            v.to_owned(),
        )),
    }
}

fn usb_attach(mut args: std::env::Args) -> ModifyUsbResult<UsbControlResult> {
    let val = args
        .next()
        .ok_or(ModifyUsbError::ArgMissing("BUS_ID_ADDR_BUS_NUM_DEV_NUM"))?;
    let (bus, addr, vid, pid) = parse_bus_id_addr(&val)?;
    let dev_path = PathBuf::from(
        args.next()
            .ok_or(ModifyUsbError::ArgMissing("usb device path"))?,
    );

    let socket_path = args
        .next()
        .ok_or(ModifyUsbError::ArgMissing("control socket path"))?;
    let socket_path = Path::new(&socket_path);

    do_usb_attach(&socket_path, bus, addr, vid, pid, &dev_path)
}

fn usb_detach(mut args: std::env::Args) -> ModifyUsbResult<UsbControlResult> {
    let port: u8 = args
        .next()
        .map_or(Err(ModifyUsbError::ArgMissing("PORT")), |p| {
            p.parse::<u8>()
                .map_err(|e| ModifyUsbError::ArgParseInt("PORT", p.to_owned(), e))
        })?;
    let socket_path = args
        .next()
        .ok_or(ModifyUsbError::ArgMissing("control socket path"))?;
    let socket_path = Path::new(&socket_path);
    do_usb_detach(&socket_path, port)
}

fn usb_list(mut args: std::env::Args) -> ModifyUsbResult<UsbControlResult> {
    let socket_path = args
        .next()
        .ok_or(ModifyUsbError::ArgMissing("control socket path"))?;
    let socket_path = Path::new(&socket_path);
    do_usb_list(&socket_path)
}

fn modify_usb(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() < 2 {
        print_help("crosvm usb",
                   "[attach BUS_ID:ADDR:VENDOR_ID:PRODUCT_ID [USB_DEVICE_PATH|-] | detach PORT | list] VM_SOCKET...", &[]);
        return Err(());
    }

    // This unwrap will not panic because of the above length check.
    let command = &args.next().unwrap();
    let result = match command.as_ref() {
        "attach" => usb_attach(args),
        "detach" => usb_detach(args),
        "list" => usb_list(args),
        other => Err(ModifyUsbError::UnknownCommand(other.to_owned())),
    };
    match result {
        Ok(response) => {
            println!("{}", response);
            Ok(())
        }
        Err(e) => {
            println!("error {}", e);
            Err(())
        }
    }
}

fn print_usage() {
    print_help("crosvm", "[command]", &[]);
    println!("Commands:");
    println!("    balloon - Set balloon size of the crosvm instance.");
    println!("    balloon_stats - Prints virtio balloon statistics.");
    println!("    battery - Modify battery.");
    println!("    create_qcow2  - Create a new qcow2 disk image file.");
    println!("    disk - Manage attached virtual disk devices.");
    println!("    resume - Resumes the crosvm instance.");
    println!("    run - Start a new crosvm instance.");
    println!("    stop - Stops crosvm instances via their control sockets.");
    println!("    suspend - Suspends the crosvm instance.");
    println!("    usb - Manage attached virtual USB devices.");
    println!("    version - Show package version.");
}

#[allow(clippy::unnecessary_wraps)]
fn pkg_version() -> std::result::Result<(), ()> {
    const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
    const PKG_VERSION: Option<&'static str> = option_env!("PKG_VERSION");

    print!("crosvm {}", VERSION.unwrap_or("UNKNOWN"));
    match PKG_VERSION {
        Some(v) => println!("-{}", v),
        None => println!(),
    }
    Ok(())
}

fn modify_battery(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() < 4 {
        print_help("crosvm battery BATTERY_TYPE ",
                   "[status STATUS | present PRESENT | health HEALTH | capacity CAPACITY | aconline ACONLINE ] VM_SOCKET...", &[]);
        return Err(());
    }

    // This unwrap will not panic because of the above length check.
    let battery_type = args.next().unwrap();
    let property = args.next().unwrap();
    let target = args.next().unwrap();

    let socket_path = args.next().unwrap();
    let socket_path = Path::new(&socket_path);

    do_modify_battery(&socket_path, &*battery_type, &*property, &*target)
}

fn crosvm_main() -> std::result::Result<(), ()> {
    if let Err(e) = syslog::init() {
        println!("failed to initialize syslog: {}", e);
        return Err(());
    }

    panic_hook::set_panic_hook();

    let mut args = std::env::args();
    if args.next().is_none() {
        error!("expected executable name");
        return Err(());
    }

    // Past this point, usage of exit is in danger of leaking zombie processes.
    let ret = match args.next().as_ref().map(|a| a.as_ref()) {
        None => {
            print_usage();
            Ok(())
        }
        Some("stop") => stop_vms(args),
        Some("suspend") => suspend_vms(args),
        Some("resume") => resume_vms(args),
        Some("run") => run_vm(args),
        Some("balloon") => balloon_vms(args),
        Some("balloon_stats") => balloon_stats(args),
        Some("create_qcow2") => create_qcow2(args),
        Some("disk") => disk_cmd(args),
        Some("usb") => modify_usb(args),
        Some("version") => pkg_version(),
        Some("battery") => modify_battery(args),
        Some(c) => {
            println!("invalid subcommand: {:?}", c);
            print_usage();
            Err(())
        }
    };

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

    // WARNING: Any code added after this point is not guaranteed to run
    // since we may forcibly kill this process (and its children) above.
    ret
}

fn main() {
    std::process::exit(if crosvm_main().is_ok() { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crosvm::{DEFAULT_TOUCH_DEVICE_HEIGHT, DEFAULT_TOUCH_DEVICE_WIDTH};

    #[test]
    fn parse_cpu_set_single() {
        assert_eq!(parse_cpu_set("123").expect("parse failed"), vec![123]);
    }

    #[test]
    fn parse_cpu_set_list() {
        assert_eq!(
            parse_cpu_set("0,1,2,3").expect("parse failed"),
            vec![0, 1, 2, 3]
        );
    }

    #[test]
    fn parse_cpu_set_range() {
        assert_eq!(
            parse_cpu_set("0-3").expect("parse failed"),
            vec![0, 1, 2, 3]
        );
    }

    #[test]
    fn parse_cpu_set_list_of_ranges() {
        assert_eq!(
            parse_cpu_set("3-4,7-9,18").expect("parse failed"),
            vec![3, 4, 7, 8, 9, 18]
        );
    }

    #[test]
    fn parse_cpu_set_repeated() {
        // For now, allow duplicates - they will be handled gracefully by the vec to cpu_set_t conversion.
        assert_eq!(parse_cpu_set("1,1,1").expect("parse failed"), vec![1, 1, 1]);
    }

    #[test]
    fn parse_cpu_set_negative() {
        // Negative CPU numbers are not allowed.
        parse_cpu_set("-3").expect_err("parse should have failed");
    }

    #[test]
    fn parse_cpu_set_reverse_range() {
        // Ranges must be from low to high.
        parse_cpu_set("5-2").expect_err("parse should have failed");
    }

    #[test]
    fn parse_cpu_set_open_range() {
        parse_cpu_set("3-").expect_err("parse should have failed");
    }

    #[test]
    fn parse_cpu_set_extra_comma() {
        parse_cpu_set("0,1,2,").expect_err("parse should have failed");
    }

    #[test]
    fn parse_cpu_affinity_global() {
        assert_eq!(
            parse_cpu_affinity("0,5-7,9").expect("parse failed"),
            VcpuAffinity::Global(vec![0, 5, 6, 7, 9]),
        );
    }

    #[test]
    fn parse_cpu_affinity_per_vcpu_one_to_one() {
        let mut expected_map = BTreeMap::new();
        expected_map.insert(0, vec![0]);
        expected_map.insert(1, vec![1]);
        expected_map.insert(2, vec![2]);
        expected_map.insert(3, vec![3]);
        assert_eq!(
            parse_cpu_affinity("0=0:1=1:2=2:3=3").expect("parse failed"),
            VcpuAffinity::PerVcpu(expected_map),
        );
    }

    #[test]
    fn parse_cpu_affinity_per_vcpu_sets() {
        let mut expected_map = BTreeMap::new();
        expected_map.insert(0, vec![0, 1, 2]);
        expected_map.insert(1, vec![3, 4, 5]);
        expected_map.insert(2, vec![6, 7, 8]);
        assert_eq!(
            parse_cpu_affinity("0=0,1,2:1=3-5:2=6,7-8").expect("parse failed"),
            VcpuAffinity::PerVcpu(expected_map),
        );
    }

    #[cfg(feature = "audio")]
    #[test]
    fn parse_ac97_vaild() {
        parse_ac97_options("backend=cras").expect("parse should have succeded");
    }

    #[cfg(feature = "audio")]
    #[test]
    fn parse_ac97_null_vaild() {
        parse_ac97_options("backend=null").expect("parse should have succeded");
    }

    #[cfg(feature = "audio")]
    #[test]
    fn parse_ac97_capture_vaild() {
        parse_ac97_options("backend=cras,capture=true").expect("parse should have succeded");
    }

    #[cfg(feature = "audio")]
    #[test]
    fn parse_ac97_client_type() {
        parse_ac97_options("backend=cras,capture=true,client_type=crosvm")
            .expect("parse should have succeded");
        parse_ac97_options("backend=cras,capture=true,client_type=arcvm")
            .expect("parse should have succeded");
        parse_ac97_options("backend=cras,capture=true,client_type=none")
            .expect_err("parse should have failed");
    }

    #[cfg(feature = "audio")]
    #[test]
    fn parse_ac97_vios_valid() {
        parse_ac97_options("backend=vios,server=/path/to/server")
            .expect("parse should have succeded");
    }

    #[test]
    fn parse_serial_vaild() {
        parse_serial_options("type=syslog,num=1,console=true,stdin=true")
            .expect("parse should have succeded");
    }

    #[test]
    fn parse_serial_virtio_console_vaild() {
        parse_serial_options("type=syslog,num=5,console=true,stdin=true,hardware=virtio-console")
            .expect("parse should have succeded");
    }

    #[test]
    fn parse_serial_valid_no_num() {
        parse_serial_options("type=syslog").expect("parse should have succeded");
    }

    #[test]
    fn parse_serial_equals_in_value() {
        let parsed = parse_serial_options("type=syslog,path=foo=bar==.log")
            .expect("parse should have succeded");
        assert_eq!(parsed.path, Some(PathBuf::from("foo=bar==.log")));
    }

    #[test]
    fn parse_serial_invalid_type() {
        parse_serial_options("type=wormhole,num=1").expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_invalid_num_upper() {
        parse_serial_options("type=syslog,num=5").expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_invalid_num_lower() {
        parse_serial_options("type=syslog,num=0").expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_virtio_console_invalid_num_lower() {
        parse_serial_options("type=syslog,hardware=virtio-console,num=0")
            .expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_invalid_num_string() {
        parse_serial_options("type=syslog,num=number3").expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_invalid_option() {
        parse_serial_options("type=syslog,speed=lightspeed").expect_err("parse should have failed");
    }

    #[test]
    fn parse_serial_invalid_two_stdin() {
        let mut config = Config::default();
        set_argument(&mut config, "serial", Some("num=1,type=stdout,stdin=true"))
            .expect("should parse the first serial argument");
        set_argument(&mut config, "serial", Some("num=2,type=stdout,stdin=true"))
            .expect_err("should fail to parse a second serial port connected to stdin");
    }

    #[test]
    fn parse_plugin_mount_valid() {
        let mut config = Config::default();
        set_argument(
            &mut config,
            "plugin-mount",
            Some("/dev/null:/dev/zero:true"),
        )
        .expect("parse should succeed");
        assert_eq!(config.plugin_mounts[0].src, PathBuf::from("/dev/null"));
        assert_eq!(config.plugin_mounts[0].dst, PathBuf::from("/dev/zero"));
        assert_eq!(config.plugin_mounts[0].writable, true);
    }

    #[test]
    fn parse_plugin_mount_valid_shorthand() {
        let mut config = Config::default();
        set_argument(&mut config, "plugin-mount", Some("/dev/null")).expect("parse should succeed");
        assert_eq!(config.plugin_mounts[0].dst, PathBuf::from("/dev/null"));
        assert_eq!(config.plugin_mounts[0].writable, false);
        set_argument(&mut config, "plugin-mount", Some("/dev/null:/dev/zero"))
            .expect("parse should succeed");
        assert_eq!(config.plugin_mounts[1].dst, PathBuf::from("/dev/zero"));
        assert_eq!(config.plugin_mounts[1].writable, false);
        set_argument(&mut config, "plugin-mount", Some("/dev/null::true"))
            .expect("parse should succeed");
        assert_eq!(config.plugin_mounts[2].dst, PathBuf::from("/dev/null"));
        assert_eq!(config.plugin_mounts[2].writable, true);
    }

    #[test]
    fn parse_plugin_mount_invalid() {
        let mut config = Config::default();
        set_argument(&mut config, "plugin-mount", Some("")).expect_err("parse should fail");
        set_argument(
            &mut config,
            "plugin-mount",
            Some("/dev/null:/dev/null:true:false"),
        )
        .expect_err("parse should fail because too many arguments");
        set_argument(&mut config, "plugin-mount", Some("null:/dev/null:true"))
            .expect_err("parse should fail because source is not absolute");
        set_argument(&mut config, "plugin-mount", Some("/dev/null:null:true"))
            .expect_err("parse should fail because source is not absolute");
        set_argument(&mut config, "plugin-mount", Some("/dev/null:null:blah"))
            .expect_err("parse should fail because flag is not boolean");
    }

    #[test]
    fn parse_plugin_gid_map_valid() {
        let mut config = Config::default();
        set_argument(&mut config, "plugin-gid-map", Some("1:2:3")).expect("parse should succeed");
        assert_eq!(config.plugin_gid_maps[0].inner, 1);
        assert_eq!(config.plugin_gid_maps[0].outer, 2);
        assert_eq!(config.plugin_gid_maps[0].count, 3);
    }

    #[test]
    fn parse_plugin_gid_map_valid_shorthand() {
        let mut config = Config::default();
        set_argument(&mut config, "plugin-gid-map", Some("1")).expect("parse should succeed");
        assert_eq!(config.plugin_gid_maps[0].inner, 1);
        assert_eq!(config.plugin_gid_maps[0].outer, 1);
        assert_eq!(config.plugin_gid_maps[0].count, 1);
        set_argument(&mut config, "plugin-gid-map", Some("1:2")).expect("parse should succeed");
        assert_eq!(config.plugin_gid_maps[1].inner, 1);
        assert_eq!(config.plugin_gid_maps[1].outer, 2);
        assert_eq!(config.plugin_gid_maps[1].count, 1);
        set_argument(&mut config, "plugin-gid-map", Some("1::3")).expect("parse should succeed");
        assert_eq!(config.plugin_gid_maps[2].inner, 1);
        assert_eq!(config.plugin_gid_maps[2].outer, 1);
        assert_eq!(config.plugin_gid_maps[2].count, 3);
    }

    #[test]
    fn parse_plugin_gid_map_invalid() {
        let mut config = Config::default();
        set_argument(&mut config, "plugin-gid-map", Some("")).expect_err("parse should fail");
        set_argument(&mut config, "plugin-gid-map", Some("1:2:3:4"))
            .expect_err("parse should fail because too many arguments");
        set_argument(&mut config, "plugin-gid-map", Some("blah:2:3"))
            .expect_err("parse should fail because inner is not a number");
        set_argument(&mut config, "plugin-gid-map", Some("1:blah:3"))
            .expect_err("parse should fail because outer is not a number");
        set_argument(&mut config, "plugin-gid-map", Some("1:2:blah"))
            .expect_err("parse should fail because count is not a number");
    }

    #[test]
    fn single_touch_spec_and_track_pad_spec_default_size() {
        let mut config = Config::default();
        config
            .executable_path
            .replace(Executable::Kernel(PathBuf::from("kernel")));
        set_argument(&mut config, "single-touch", Some("/dev/single-touch-test")).unwrap();
        set_argument(&mut config, "trackpad", Some("/dev/single-touch-test")).unwrap();
        validate_arguments(&mut config).unwrap();
        assert_eq!(
            config.virtio_single_touch.unwrap().get_size(),
            (DEFAULT_TOUCH_DEVICE_WIDTH, DEFAULT_TOUCH_DEVICE_HEIGHT)
        );
        assert_eq!(
            config.virtio_trackpad.unwrap().get_size(),
            (DEFAULT_TOUCH_DEVICE_WIDTH, DEFAULT_TOUCH_DEVICE_HEIGHT)
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn single_touch_spec_default_size_from_gpu() {
        let width = 12345u32;
        let height = 54321u32;
        let mut config = Config::default();
        config
            .executable_path
            .replace(Executable::Kernel(PathBuf::from("kernel")));
        set_argument(&mut config, "single-touch", Some("/dev/single-touch-test")).unwrap();
        set_argument(
            &mut config,
            "gpu",
            Some(&format!("width={},height={}", width, height)),
        )
        .unwrap();
        validate_arguments(&mut config).unwrap();
        assert_eq!(
            config.virtio_single_touch.unwrap().get_size(),
            (width, height)
        );
    }

    #[test]
    fn single_touch_spec_and_track_pad_spec_with_size() {
        let width = 12345u32;
        let height = 54321u32;
        let mut config = Config::default();
        config
            .executable_path
            .replace(Executable::Kernel(PathBuf::from("kernel")));
        set_argument(
            &mut config,
            "single-touch",
            Some(&format!("/dev/single-touch-test:{}:{}", width, height)),
        )
        .unwrap();
        set_argument(
            &mut config,
            "trackpad",
            Some(&format!("/dev/single-touch-test:{}:{}", width, height)),
        )
        .unwrap();
        validate_arguments(&mut config).unwrap();
        assert_eq!(
            config.virtio_single_touch.unwrap().get_size(),
            (width, height)
        );
        assert_eq!(config.virtio_trackpad.unwrap().get_size(), (width, height));
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn single_touch_spec_with_size_independent_from_gpu() {
        let touch_width = 12345u32;
        let touch_height = 54321u32;
        let display_width = 1234u32;
        let display_height = 5432u32;
        let mut config = Config::default();
        config
            .executable_path
            .replace(Executable::Kernel(PathBuf::from("kernel")));
        set_argument(
            &mut config,
            "single-touch",
            Some(&format!(
                "/dev/single-touch-test:{}:{}",
                touch_width, touch_height
            )),
        )
        .unwrap();
        set_argument(
            &mut config,
            "gpu",
            Some(&format!(
                "width={},height={}",
                display_width, display_height
            )),
        )
        .unwrap();
        validate_arguments(&mut config).unwrap();
        assert_eq!(
            config.virtio_single_touch.unwrap().get_size(),
            (touch_width, touch_height)
        );
    }

    #[test]
    fn virtio_switches() {
        let mut config = Config::default();
        config
            .executable_path
            .replace(Executable::Kernel(PathBuf::from("kernel")));
        set_argument(&mut config, "switches", Some("/dev/switches-test")).unwrap();
        validate_arguments(&mut config).unwrap();
        assert_eq!(
            config.virtio_switches.unwrap(),
            PathBuf::from("/dev/switches-test")
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_default_vulkan_support() {
        assert!(
            !parse_gpu_options(Some("backend=virglrenderer"))
                .unwrap()
                .use_vulkan
        );

        #[cfg(feature = "gfxstream")]
        assert!(
            parse_gpu_options(Some("backend=gfxstream"))
                .unwrap()
                .use_vulkan
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_with_vulkan_specified() {
        assert!(parse_gpu_options(Some("vulkan=true")).unwrap().use_vulkan);
        assert!(
            parse_gpu_options(Some("backend=virglrenderer,vulkan=true"))
                .unwrap()
                .use_vulkan
        );
        assert!(
            parse_gpu_options(Some("vulkan=true,backend=virglrenderer"))
                .unwrap()
                .use_vulkan
        );
        assert!(!parse_gpu_options(Some("vulkan=false")).unwrap().use_vulkan);
        assert!(
            !parse_gpu_options(Some("backend=virglrenderer,vulkan=false"))
                .unwrap()
                .use_vulkan
        );
        assert!(
            !parse_gpu_options(Some("vulkan=false,backend=virglrenderer"))
                .unwrap()
                .use_vulkan
        );
        assert!(parse_gpu_options(Some("backend=virglrenderer,vulkan=invalid_value")).is_err());
        assert!(parse_gpu_options(Some("vulkan=invalid_value,backend=virglrenderer")).is_err());
    }

    #[cfg(all(feature = "gpu", feature = "gfxstream"))]
    #[test]
    fn parse_gpu_options_gfxstream_with_syncfd_specified() {
        assert!(
            parse_gpu_options(Some("backend=gfxstream,syncfd=true"))
                .unwrap()
                .gfxstream_use_syncfd
        );
        assert!(
            parse_gpu_options(Some("syncfd=true,backend=gfxstream"))
                .unwrap()
                .gfxstream_use_syncfd
        );
        assert!(
            !parse_gpu_options(Some("backend=gfxstream,syncfd=false"))
                .unwrap()
                .gfxstream_use_syncfd
        );
        assert!(
            !parse_gpu_options(Some("syncfd=false,backend=gfxstream"))
                .unwrap()
                .gfxstream_use_syncfd
        );
        assert!(parse_gpu_options(Some("backend=gfxstream,syncfd=invalid_value")).is_err());
        assert!(parse_gpu_options(Some("syncfd=invalid_value,backend=gfxstream")).is_err());
    }

    #[cfg(all(feature = "gpu", feature = "gfxstream"))]
    #[test]
    fn parse_gpu_options_not_gfxstream_with_syncfd_specified() {
        assert!(parse_gpu_options(Some("backend=virglrenderer,syncfd=true")).is_err());
        assert!(parse_gpu_options(Some("syncfd=true,backend=virglrenderer")).is_err());
    }

    #[test]
    fn parse_battery_vaild() {
        parse_battery_options(Some("type=goldfish")).expect("parse should have succeded");
    }

    #[test]
    fn parse_battery_vaild_no_type() {
        parse_battery_options(None).expect("parse should have succeded");
    }

    #[test]
    fn parse_battery_invaild_parameter() {
        parse_battery_options(Some("tyep=goldfish")).expect_err("parse should have failed");
    }

    #[test]
    fn parse_battery_invaild_type_value() {
        parse_battery_options(Some("type=xxx")).expect_err("parse should have failed");
    }
}
