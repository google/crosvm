// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Runs a virtual machine

pub mod panic_hook;

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::default::Default;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::ops::Deref;
#[cfg(feature = "direct")]
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::string::String;
use std::thread::sleep;
use std::time::Duration;

use arch::{set_default_serial_parameters, Pstore, VcpuAffinity};
use base::{debug, error, getpid, info, kill_process_group, pagesize, reap_child, syslog, warn};
#[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
use crosvm::platform::GpuRenderServerParameters;
#[cfg(feature = "direct")]
use crosvm::{argument::parse_hex_or_decimal, DirectIoOption, HostPcieRootPortParameters};
use crosvm::{
    argument::{self, print_help, set_arguments, Argument},
    platform, BindMount, Config, Executable, FileBackedMappingParameters, GidMap, SharedDir,
    TouchDeviceOption, VfioCommand, VhostUserFsOption, VhostUserOption, VhostUserWlOption,
    VvuOption,
};
use devices::serial_device::{SerialHardware, SerialParameters};
use devices::virtio::block::block::DiskOption;
#[cfg(feature = "audio_cras")]
use devices::virtio::snd::cras_backend::Error as CrasSndError;
#[cfg(feature = "audio_cras")]
use devices::virtio::vhost::user::device::run_cras_snd_device;
use devices::virtio::vhost::user::device::{
    run_block_device, run_console_device, run_fs_device, run_net_device, run_vsock_device,
    run_wl_device,
};
use devices::virtio::vhost::vsock::VhostVsockDeviceParameter;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
use devices::virtio::VideoBackendType;
#[cfg(feature = "gpu")]
use devices::virtio::{
    gpu::{
        GpuDisplayParameters, GpuMode, GpuParameters, DEFAULT_DISPLAY_HEIGHT, DEFAULT_DISPLAY_WIDTH,
    },
    vhost::user::device::run_gpu_device,
};
#[cfg(feature = "direct")]
use devices::BusRange;
#[cfg(feature = "audio")]
use devices::{Ac97Backend, Ac97Parameters};
use devices::{PciAddress, PciClassCode, StubPciParameters};
use disk::{self, QcowFile};
#[cfg(feature = "composite-disk")]
use disk::{
    create_composite_disk, create_disk_file, create_zero_filler, ImagePartitionType, PartitionInfo,
};
use hypervisor::ProtectionType;
use serde_keyvalue::from_key_values;
use uuid::Uuid;
use vm_control::{
    client::{
        do_modify_battery, do_usb_attach, do_usb_detach, do_usb_list, handle_request, vms_request,
        ModifyUsbError, ModifyUsbResult,
    },
    BalloonControlCommand, BatteryType, DiskControlCommand, UsbControlResult, VmRequest,
    VmResponse,
};

#[cfg(feature = "scudo")]
#[global_allocator]
static ALLOCATOR: scudo::GlobalScudoAllocator = scudo::GlobalScudoAllocator;

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

fn parse_cpu_capacity(s: &str, cpu_capacity: &mut BTreeMap<usize, u32>) -> argument::Result<()> {
    for cpu_pair in s.split(',') {
        let assignment: Vec<&str> = cpu_pair.split('=').collect();
        if assignment.len() != 2 {
            return Err(argument::Error::InvalidValue {
                value: cpu_pair.to_owned(),
                expected: String::from("invalid CPU capacity syntax"),
            });
        }
        let cpu = assignment[0]
            .parse()
            .map_err(|_| argument::Error::InvalidValue {
                value: assignment[0].to_owned(),
                expected: String::from("CPU index must be a non-negative integer"),
            })?;
        let capacity = assignment[1]
            .parse()
            .map_err(|_| argument::Error::InvalidValue {
                value: assignment[1].to_owned(),
                expected: String::from("CPU capacity must be a non-negative integer"),
            })?;
        if cpu_capacity.insert(cpu, capacity).is_some() {
            return Err(argument::Error::InvalidValue {
                value: cpu_pair.to_owned(),
                expected: String::from("CPU index must be unique"),
            });
        }
    }
    Ok(())
}

#[cfg(feature = "gpu")]
fn parse_gpu_options(s: Option<&str>, gpu_params: &mut GpuParameters) -> argument::Result<()> {
    #[cfg(feature = "gfxstream")]
    let mut vulkan_specified = false;
    #[cfg(feature = "gfxstream")]
    let mut syncfd_specified = false;
    #[cfg(feature = "gfxstream")]
    let mut angle_specified = false;

    let mut display_w: Option<u32> = None;
    let mut display_h: Option<u32> = None;

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

    if display_w.is_some() || display_h.is_some() {
        if display_w.is_none() || display_h.is_none() {
            return Err(argument::Error::InvalidValue {
                value: s.unwrap_or("").to_string(),
                expected: String::from(
                    "gpu must include both 'width' and 'height' if either is supplied",
                ),
            });
        }

        gpu_params.displays.push(GpuDisplayParameters {
            width: display_w.unwrap(),
            height: display_h.unwrap(),
        });
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

    Ok(())
}

#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
fn parse_video_options(s: Option<&str>) -> argument::Result<VideoBackendType> {
    const VALID_VIDEO_BACKENDS: &[&str] = &[
        #[cfg(feature = "libvda")]
        "libvda",
    ];

    match s {
        None => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "libvda")] {
                    Ok(VideoBackendType::Libvda)
                }
            }
        }
        #[cfg(feature = "libvda")]
        Some("libvda") => Ok(VideoBackendType::Libvda),
        #[cfg(feature = "libvda")]
        Some("libvda-vd") => Ok(VideoBackendType::LibvdaVd),
        Some(s) => Err(argument::Error::InvalidValue {
            value: s.to_owned(),
            expected: format!("should be one of ({})", VALID_VIDEO_BACKENDS.join("|")),
        }),
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
            #[cfg(feature = "audio_cras")]
            "client_type" => {
                ac97_params
                    .set_client_type(v)
                    .map_err(|e| argument::Error::InvalidValue {
                        value: v.to_string(),
                        expected: e.to_string(),
                    })?;
            }
            #[cfg(feature = "audio_cras")]
            "socket_type" => {
                ac97_params
                    .set_socket_type(v)
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

enum MsrAction {
    Invalid,
    /// Read MSR value from host CPU0 regardless of current vcpu.
    ReadFromCPU0,
}

fn parse_userspace_msr_options(value: &str) -> argument::Result<u32> {
    // TODO(b/215297064): Implement different type of operations, such
    // as write or reading from the correct CPU.
    let mut options = argument::parse_key_value_options("userspace-msr", value, ',');
    let index: u32 = options
        .next()
        .ok_or(argument::Error::ExpectedValue(String::from(
            "userspace-msr: expected index",
        )))?
        .key_numeric()?;
    let mut msr_config = MsrAction::Invalid;
    for opt in options {
        match opt.key() {
            "action" => match opt.value()? {
                "r0" => msr_config = MsrAction::ReadFromCPU0,
                _ => return Err(opt.invalid_value_err(String::from("bad action"))),
            },
            _ => return Err(opt.invalid_key_err()),
        }
    }

    match msr_config {
        MsrAction::ReadFromCPU0 => Ok(index),
        _ => Err(argument::Error::UnknownArgument(
            "userspace-msr action not specified".to_string(),
        )),
    }
}

fn parse_serial_options(s: &str) -> argument::Result<SerialParameters> {
    let serial_setting: SerialParameters =
        from_key_values(s).map_err(|e| argument::Error::ConfigParserError(e.to_string()))?;

    if serial_setting.stdin && serial_setting.input.is_some() {
        return Err(argument::Error::TooManyArguments(
            "Cannot specify both stdin and input options".to_string(),
        ));
    }
    if serial_setting.num < 1 {
        return Err(argument::Error::InvalidValue {
            value: serial_setting.num.to_string(),
            expected: String::from("Serial port num must be at least 1"),
        });
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
    let ranges: argument::Result<Vec<BusRange>> = parts[1]
        .split(',')
        .map(|frag| frag.split('-'))
        .map(|mut range| {
            let base = range
                .next()
                .map(|v| parse_hex_or_decimal(v))
                .map_or(Ok(None), |r| r.map(Some));
            let last = range
                .next()
                .map(|v| parse_hex_or_decimal(v))
                .map_or(Ok(None), |r| r.map(Some));
            (base, last)
        })
        .map(|range| match range {
            (Ok(Some(base)), Ok(None)) => Ok(BusRange { base, len: 1 }),
            (Ok(Some(base)), Ok(Some(last))) => Ok(BusRange {
                base,
                len: last.saturating_sub(base).saturating_add(1),
            }),
            (Err(_), _) => Err(argument::Error::InvalidValue {
                value: s.to_owned(),
                expected: String::from("invalid base range value"),
            }),
            (_, Err(_)) => Err(argument::Error::InvalidValue {
                value: s.to_owned(),
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

fn parse_stub_pci_parameters(s: Option<&str>) -> argument::Result<StubPciParameters> {
    let s = s.ok_or(argument::Error::ExpectedValue(String::from(
        "stub-pci-device configuration expected",
    )))?;

    let mut options = argument::parse_key_value_options("stub-pci-device", s, ',');
    let addr = options
        .next()
        .ok_or(argument::Error::ExpectedValue(String::from(
            "stub-pci-device: expected device address",
        )))?
        .key();
    let mut params = StubPciParameters {
        address: PciAddress::from_str(addr).map_err(|e| argument::Error::InvalidValue {
            value: addr.to_owned(),
            expected: format!("stub-pci-device: expected PCI address: {}", e),
        })?,
        vendor_id: 0,
        device_id: 0,
        class: PciClassCode::Other,
        subclass: 0,
        programming_interface: 0,
        subsystem_device_id: 0,
        subsystem_vendor_id: 0,
        revision_id: 0,
    };
    for opt in options {
        match opt.key() {
            "vendor" => params.vendor_id = opt.parse_numeric::<u16>()?,
            "device" => params.device_id = opt.parse_numeric::<u16>()?,
            "class" => {
                let class = opt.parse_numeric::<u32>()?;
                params.class = PciClassCode::try_from((class >> 16) as u8)
                    .map_err(|_| opt.invalid_value_err(String::from("Unknown class code")))?;
                params.subclass = (class >> 8) as u8;
                params.programming_interface = class as u8;
            }
            "multifunction" => {} // Ignore but allow the multifunction option for compatibility.
            "subsystem_vendor" => params.subsystem_vendor_id = opt.parse_numeric::<u16>()?,
            "subsystem_device" => params.subsystem_device_id = opt.parse_numeric::<u16>()?,
            "revision" => params.revision_id = opt.parse_numeric::<u8>()?,
            _ => return Err(opt.invalid_key_err()),
        }
    }

    Ok(params)
}

fn parse_file_backed_mapping(s: Option<&str>) -> argument::Result<FileBackedMappingParameters> {
    let s = s.ok_or(argument::Error::ExpectedValue(String::from(
        "file-backed-mapping: memory mapping option value required",
    )))?;

    let mut address = None;
    let mut size = None;
    let mut path = None;
    let mut offset = None;
    let mut writable = false;
    let mut sync = false;
    let mut align = false;
    for opt in argument::parse_key_value_options("file-backed-mapping", s, ',') {
        match opt.key() {
            "addr" => address = Some(opt.parse_numeric::<u64>()?),
            "size" => size = Some(opt.parse_numeric::<u64>()?),
            "path" => path = Some(PathBuf::from(opt.value()?)),
            "offset" => offset = Some(opt.parse_numeric::<u64>()?),
            "ro" => writable = !opt.parse_or::<bool>(true)?,
            "rw" => writable = opt.parse_or::<bool>(true)?,
            "sync" => sync = opt.parse_or::<bool>(true)?,
            "align" => align = opt.parse_or::<bool>(true)?,
            _ => return Err(opt.invalid_key_err()),
        }
    }

    let (address, path, size) = match (address, path, size) {
        (Some(a), Some(p), Some(s)) => (a, p, s),
        _ => {
            return Err(argument::Error::ExpectedValue(String::from(
                "file-backed-mapping: address, size, and path parameters are required",
            )))
        }
    };

    let pagesize_mask = pagesize() as u64 - 1;
    let aligned_address = address & !pagesize_mask;
    let aligned_size = ((address + size + pagesize_mask) & !pagesize_mask) - aligned_address;

    if !align && (aligned_address != address || aligned_size != size) {
        return Err(argument::Error::InvalidValue {
            value: s.to_owned(),
            expected: String::from("addr and size parameters must be page size aligned"),
        });
    }

    Ok(FileBackedMappingParameters {
        address: aligned_address,
        size: aligned_size,
        path,
        offset: offset.unwrap_or(0),
        writable,
        sync,
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
        "vhost-vsock-fd" => {
            if cfg.vhost_vsock_device.is_some() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("A vhost-vsock device was already specified"),
                });
            }
            cfg.vhost_vsock_device = Some(VhostVsockDeviceParameter::Fd(
                value
                    .unwrap()
                    .parse()
                    .map_err(|_| argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: String::from(
                            "this value for `vhost-vsock-fd` needs to be integer",
                        ),
                    })?,
            ));
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

            cfg.vhost_vsock_device = Some(VhostVsockDeviceParameter::Path(vhost_vsock_device_path));
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
        "cpu-cluster" => {
            cfg.cpu_clusters.push(parse_cpu_set(value.unwrap())?);
        }
        "cpu-capacity" => {
            parse_cpu_capacity(value.unwrap(), &mut cfg.cpu_capacity)?;
        }
        "per-vm-core-scheduling" => {
            cfg.per_vm_core_scheduling = true;
        }
        "vcpu-cgroup-path" => {
            let vcpu_cgroup_path = PathBuf::from(value.unwrap());
            if !vcpu_cgroup_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("This vcpu_cgroup_path path does not exist"),
                });
            }

            cfg.vcpu_cgroup_path = Some(vcpu_cgroup_path);
        }
        #[cfg(feature = "audio_cras")]
        "cras-snd" => {
            cfg.cras_snds.push(
                value
                    .unwrap()
                    .parse()
                    .map_err(|e: CrasSndError| argument::Error::Syntax(e.to_string()))?,
            );
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
        "delay-rt" => {
            cfg.delay_rt = true;
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
        #[cfg(target_arch = "aarch64")]
        "swiotlb" => {
            if cfg.swiotlb.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`swiotlb` already given".to_owned(),
                ));
            }
            cfg.swiotlb =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from("this value for `swiotlb` needs to be integer"),
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
        #[cfg(feature = "audio")]
        "sound" => {
            let client_path = PathBuf::from(value.unwrap());
            cfg.sound = Some(client_path);
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
            let value = value.ok_or(argument::Error::ExpectedArgument(
                "path to the disk image is missing".to_owned(),
            ))?;
            let mut params: DiskOption = from_key_values(value).map_err(|e| {
                argument::Error::Syntax(format!("while parsing \"{}\" parameter: {}", name, e))
            })?;

            if !name.starts_with("rw") {
                params.read_only = true;
            }

            let disk_path = &params.path;
            if !disk_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: disk_path.to_string_lossy().into_owned(),
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
                    if params.read_only { "ro" } else { "rw" }
                ));
            }

            cfg.disks.push(params);
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
                o_direct: false,
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
        "wayland-dmabuf" => {}
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
        "balloon-control" => {
            if cfg.balloon_control.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`balloon-control` already given".to_owned(),
                ));
            }
            let path = PathBuf::from(value.unwrap());
            if path.is_dir() || !path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: path.to_string_lossy().into_owned(),
                    expected: String::from("path is directory or missing"),
                });
            }
            cfg.balloon_control = Some(path);
        }
        "disable-sandbox" => {
            cfg.jail_config = None;
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
                let trimmed_line = line.split_once('#').map_or(&*line, |x| x.0).trim();
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
                let trimmed_line = line.split_once('#').map_or(&*line, |x| x.0).trim();
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
        "tap-name" => {
            cfg.tap_name.push(value.unwrap().to_owned());
        }
        #[cfg(feature = "gpu")]
        "gpu" => {
            let gpu_parameters = cfg.gpu_parameters.get_or_insert_with(Default::default);
            parse_gpu_options(value, gpu_parameters)?;
        }
        #[cfg(feature = "gpu")]
        "gpu-display" => {
            let gpu_parameters = cfg.gpu_parameters.get_or_insert_with(Default::default);
            parse_gpu_display_options(value, gpu_parameters)?;
        }
        #[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
        "gpu-render-server" => {
            cfg.gpu_render_server_parameters = Some(parse_gpu_render_server_options(value)?);
        }
        "software-tpm" => {
            cfg.software_tpm = true;
        }
        "single-touch" => {
            let mut it = value.unwrap().split(':');

            let mut single_touch_spec =
                TouchDeviceOption::new(PathBuf::from(it.next().unwrap().to_owned()));
            if let Some(width) = it.next() {
                single_touch_spec.set_width(width.trim().parse().unwrap());
            }
            if let Some(height) = it.next() {
                single_touch_spec.set_height(height.trim().parse().unwrap());
            }
            cfg.virtio_single_touch.push(single_touch_spec);
        }
        "multi-touch" => {
            let mut it = value.unwrap().split(':');

            let mut multi_touch_spec =
                TouchDeviceOption::new(PathBuf::from(it.next().unwrap().to_owned()));
            if let Some(width) = it.next() {
                multi_touch_spec.set_width(width.trim().parse().unwrap());
            }
            if let Some(height) = it.next() {
                multi_touch_spec.set_height(height.trim().parse().unwrap());
            }
            cfg.virtio_multi_touch.push(multi_touch_spec);
        }
        "trackpad" => {
            let mut it = value.unwrap().split(':');

            let mut trackpad_spec =
                TouchDeviceOption::new(PathBuf::from(it.next().unwrap().to_owned()));
            if let Some(width) = it.next() {
                trackpad_spec.set_width(width.trim().parse().unwrap());
            }
            if let Some(height) = it.next() {
                trackpad_spec.set_height(height.trim().parse().unwrap());
            }
            cfg.virtio_trackpad.push(trackpad_spec);
        }
        "mouse" => {
            cfg.virtio_mice
                .push(PathBuf::from(value.unwrap().to_owned()));
        }
        "keyboard" => {
            cfg.virtio_keyboard
                .push(PathBuf::from(value.unwrap().to_owned()));
        }
        "switches" => {
            cfg.virtio_switches
                .push(PathBuf::from(value.unwrap().to_owned()));
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
        "vfio" | "vfio-platform" => {
            let vfio_type = name.parse().unwrap();
            let vfio_dev = VfioCommand::new(vfio_type, value.unwrap())?;
            cfg.vfio.push(vfio_dev);
        }
        "virtio-iommu" => {
            cfg.virtio_iommu = true;
        }
        #[cfg(feature = "video-decoder")]
        "video-decoder" => {
            cfg.video_dec = Some(parse_video_options(value)?);
        }
        #[cfg(feature = "video-encoder")]
        "video-encoder" => {
            cfg.video_enc = Some(parse_video_options(value)?);
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
            // Balloon and USB devices only work for unprotected VMs.
            cfg.balloon = false;
            cfg.usb = false;
            // Protected VMs can't trust the RNG device, so don't provide it.
            cfg.rng = false;
        }
        "protected-vm-without-firmware" => {
            cfg.protected_vm = ProtectionType::ProtectedWithoutFirmware;
            // Balloon and USB devices only work for unprotected VMs.
            cfg.balloon = false;
            cfg.usb = false;
            // Protected VMs can't trust the RNG device, so don't provide it.
            cfg.rng = false;
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
        "no-balloon" => {
            cfg.balloon = false;
        }
        "no-rng" => {
            cfg.rng = false;
        }
        "no-usb" => {
            cfg.usb = false;
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
        "vhost-user-console" => cfg.vhost_user_console.push(VhostUserOption {
            socket: PathBuf::from(value.unwrap()),
        }),
        "vhost-user-gpu" => cfg.vhost_user_gpu.push(VhostUserOption {
            socket: PathBuf::from(value.unwrap()),
        }),
        "vhost-user-mac80211-hwsim" => {
            cfg.vhost_user_mac80211_hwsim = Some(VhostUserOption {
                socket: PathBuf::from(value.unwrap()),
            });
        }
        "vhost-user-net" => cfg.vhost_user_net.push(VhostUserOption {
            socket: PathBuf::from(value.unwrap()),
        }),
        #[cfg(feature = "audio")]
        "vhost-user-snd" => cfg.vhost_user_snd.push(VhostUserOption {
            socket: PathBuf::from(value.unwrap()),
        }),
        "vhost-user-vsock" => cfg.vhost_user_vsock.push(VhostUserOption {
            socket: PathBuf::from(value.unwrap()),
        }),
        "vhost-user-wl" => {
            let mut components = value.unwrap().splitn(2, ":");
            let socket = components.next().map(PathBuf::from).ok_or_else(|| {
                argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("missing socket path"),
                }
            })?;
            let vm_tube = components.next().map(PathBuf::from).ok_or_else(|| {
                argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from("missing vm tube path"),
                }
            })?;
            cfg.vhost_user_wl
                .push(VhostUserWlOption { socket, vm_tube });
        }
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
        "direct-mmio" => {
            if cfg.direct_mmio.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`direct_mmio` already given".to_owned(),
                ));
            }
            cfg.direct_mmio = Some(parse_direct_io_options(value)?);
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
        #[cfg(feature = "direct")]
        "direct-wake-irq" => {
            cfg.direct_wake_irq
                .push(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from(
                                "this value for `direct-wake-irq` must be an unsigned integer",
                            ),
                        })?,
                );
        }
        #[cfg(feature = "direct")]
        "direct-gpe" => {
            cfg.direct_gpe.push(value.unwrap().parse().map_err(|_| {
                argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: String::from(
                        "this value for `direct-gpe` must be an unsigned integer",
                    ),
                }
            })?);
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
        "no-legacy" => {
            cfg.no_legacy = true;
        }
        "userspace-msr" => {
            let index = parse_userspace_msr_options(value.unwrap())?;
            cfg.userspace_msr.insert(index);
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        "host-cpu-topology" => {
            cfg.host_cpu_topology = true;
        }
        "privileged-vm" => {
            cfg.privileged_vm = true;
        }
        "stub-pci-device" => {
            cfg.stub_pci_devices.push(parse_stub_pci_parameters(value)?);
        }
        "vvu-proxy" => {
            let opts: Vec<_> = value.unwrap().splitn(2, ',').collect();
            let socket = PathBuf::from(opts[0]);
            let mut vvu_opt = VvuOption {
                socket,
                addr: None,
                uuid: Default::default(),
            };

            if let Some(kvs) = opts.get(1) {
                for kv in argument::parse_key_value_options("vvu-proxy", kvs, ',') {
                    match kv.key() {
                        "addr" => {
                            let pci_address = kv.value()?;
                            if vvu_opt.addr.is_some() {
                                return Err(argument::Error::TooManyArguments(
                                    "`addr` already given".to_owned(),
                                ));
                            }

                            vvu_opt.addr =
                                Some(PciAddress::from_str(pci_address).map_err(|e| {
                                    argument::Error::InvalidValue {
                                        value: pci_address.to_string(),
                                        expected: format!("vvu-proxy PCI address: {}", e),
                                    }
                                })?);
                        }
                        "uuid" => {
                            let value = kv.value()?;
                            if vvu_opt.uuid.is_some() {
                                return Err(argument::Error::TooManyArguments(
                                    "`uuid` already given".to_owned(),
                                ));
                            }
                            let uuid = Uuid::parse_str(value).map_err(|e| {
                                argument::Error::InvalidValue {
                                    value: value.to_string(),
                                    expected: format!("invalid UUID is given for vvu-proxy: {}", e),
                                }
                            })?;
                            vvu_opt.uuid = Some(uuid);
                        }
                        _ => {
                            kv.invalid_key_err();
                        }
                    }
                }
            }

            cfg.vvu_proxy.push(vvu_opt);
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
        "file-backed-mapping" => {
            cfg.file_backed_mappings
                .push(parse_file_backed_mapping(value)?);
        }
        "init-mem" => {
            if cfg.init_memory.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`init-mem` already given".to_owned(),
                ));
            }
            cfg.init_memory =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: String::from("this value for `init-mem` needs to be integer"),
                        })?,
                )
        }
        #[cfg(feature = "direct")]
        "pcie-root-port" => {
            let opts: Vec<_> = value.unwrap().split(',').collect();
            if opts.len() > 2 {
                return Err(argument::Error::TooManyArguments(
                    "pcie-root-port has maxmimum two arguments".to_owned(),
                ));
            }
            let pcie_path = PathBuf::from(opts[0]);
            if !pcie_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: opts[0].to_owned(),
                    expected: String::from("the pcie root port path does not exist"),
                });
            }
            if !pcie_path.is_dir() {
                return Err(argument::Error::InvalidValue {
                    value: opts[0].to_owned(),
                    expected: String::from("the pcie root port path should be directory"),
                });
            }

            let hp_gpe = if opts.len() == 2 {
                let gpes: Vec<&str> = opts[1].split('=').collect();
                if gpes.len() != 2 || gpes[0] != "hp_gpe" {
                    return Err(argument::Error::InvalidValue {
                        value: opts[1].to_owned(),
                        expected: String::from("it should be hp_gpe=Num"),
                    });
                }
                match gpes[1].parse::<u32>() {
                    Ok(gpe) => Some(gpe),
                    Err(_) => {
                        return Err(argument::Error::InvalidValue {
                            value: gpes[1].to_owned(),
                            expected: String::from("host hp gpe must be a non-negative integer"),
                        });
                    }
                }
            } else {
                None
            };

            cfg.pcie_rp.push(HostPcieRootPortParameters {
                host_path: pcie_path,
                hp_gpe,
            });
        }
        "pivot-root" => {
            if let Some(jail_config) = &mut cfg.jail_config {
                jail_config.pivot_root = PathBuf::from(value.unwrap());
            }
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        "s2idle" => {
            cfg.force_s2idle = true;
        }
        "strict-balloon" => {
            cfg.strict_balloon = true;
        }
        #[cfg(feature = "direct")]
        "mmio-address-range" => {
            let ranges: argument::Result<Vec<RangeInclusive<u64>>> = value
                .unwrap()
                .split(",")
                .map(|s| {
                    let r: Vec<&str> = s.split("-").collect();
                    if r.len() != 2 {
                        return Err(argument::Error::InvalidValue {
                            value: s.to_string(),
                            expected: String::from("invalid range"),
                        });
                    }
                    let parse = |s: &str| -> argument::Result<u64> {
                        match parse_hex_or_decimal(s) {
                            Ok(v) => Ok(v),
                            Err(_) => {
                                return Err(argument::Error::InvalidValue {
                                    value: s.to_owned(),
                                    expected: String::from("expected u64 value"),
                                });
                            }
                        }
                    };
                    Ok(RangeInclusive::new(parse(r[0])?, parse(r[1])?))
                })
                .collect();
            cfg.mmio_address_ranges = ranges?;
        }
        #[cfg(target_os = "android")]
        "task-profiles" => {
            for name in value.unwrap().split(',') {
                cfg.task_profiles.push(name.to_owned());
            }
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
        if let Some(gpu_parameters) = cfg.gpu_parameters.as_mut() {
            if gpu_parameters.displays.is_empty() {
                gpu_parameters.displays.push(GpuDisplayParameters {
                    width: DEFAULT_DISPLAY_WIDTH,
                    height: DEFAULT_DISPLAY_HEIGHT,
                });
            }

            let width = gpu_parameters.displays[0].width;
            let height = gpu_parameters.displays[0].height;

            if let Some(virtio_multi_touch) = cfg.virtio_multi_touch.first_mut() {
                virtio_multi_touch.set_default_size(width, height);
            }
            if let Some(virtio_single_touch) = cfg.virtio_single_touch.first_mut() {
                virtio_single_touch.set_default_size(width, height);
            }
        }
    }
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    if cfg.gdb.is_some() && cfg.vcpu_count.unwrap_or(1) != 1 {
        return Err(argument::Error::ExpectedArgument(
            "`gdb` requires the number of vCPU to be 1".to_owned(),
        ));
    }
    if cfg.host_cpu_topology {
        if cfg.no_smt {
            return Err(argument::Error::ExpectedArgument(
                "`host-cpu-topology` cannot be set at the same time as `no_smt`, since \
                the smt of the Guest is the same as that of the Host when \
                `host-cpu-topology` is set."
                    .to_owned(),
            ));
        }

        // Safe because we pass a flag for this call and the host supports this system call
        let pcpu_count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) } as usize;
        if cfg.vcpu_count.is_some() {
            if pcpu_count != cfg.vcpu_count.unwrap() {
                return Err(argument::Error::ExpectedArgument(format!(
                    "`host-cpu-topology` requires the count of vCPUs({}) to equal the \
                            count of CPUs({}) on host.",
                    cfg.vcpu_count.unwrap(),
                    pcpu_count
                )));
            }
        } else {
            cfg.vcpu_count = Some(pcpu_count);
        }

        match &cfg.vcpu_affinity {
            None => {
                let mut affinity_map = BTreeMap::new();
                for cpu_id in 0..cfg.vcpu_count.unwrap() {
                    affinity_map.insert(cpu_id, vec![cpu_id]);
                }
                cfg.vcpu_affinity = Some(VcpuAffinity::PerVcpu(affinity_map));
            }
            _ => {
                return Err(argument::Error::ExpectedArgument(
                    "`host-cpu-topology` requires not to set `cpu-affinity` at the same time"
                        .to_owned(),
                ));
            }
        }
    }
    if !cfg.balloon && cfg.balloon_control.is_some() {
        return Err(argument::Error::ExpectedArgument(
            "'balloon-control' requires enabled balloon".to_owned(),
        ));
    }

    set_default_serial_parameters(
        &mut cfg.serial_parameters,
        !cfg.vhost_user_console.is_empty(),
    );

    // Remove jail configuration if it has not been enabled.
    if !cfg.jail_enabled {
        cfg.jail_config = None;
    }

    Ok(())
}

enum CommandStatus {
    Success,
    VmReset,
    VmStop,
    VmCrash,
    GuestPanic,
}

fn run_vm(args: std::env::Args) -> std::result::Result<CommandStatus, ()> {
    let arguments =
        &[Argument::positional("KERNEL", "bzImage of kernel to run"),
          Argument::value("kvm-device", "PATH", "Path to the KVM device. (default /dev/kvm)"),
          Argument::value("vhost-vsock-fd", "FD", "Open FD to the vhost-vsock device, mutually exclusive with vhost-vsock-device."),
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
          Argument::value("cpu-cluster", "CPUSET", "Group the given CPUs into a cluster (default: no clusters)"),
          Argument::value("cpu-capacity", "CPU=CAP[,CPU=CAP[,...]]", "Set the relative capacity of the given CPU (default: no capacity)"),
          Argument::flag("per-vm-core-scheduling", "Enable per-VM core scheduling intead of the default one (per-vCPU core scheduing) by
              making all vCPU threads share same cookie for core scheduling.
              This option is no-op on devices that have neither MDS nor L1TF vulnerability."),
          Argument::value("vcpu-cgroup-path", "PATH", "Move all vCPU threads to this CGroup (default: nothing moves)."),
#[cfg(feature = "audio_cras")]
          Argument::value("cras-snd",
          "[capture=true,client=crosvm,socket=unified,num_output_streams=1,num_input_streams=1]",
          "Comma separated key=value pairs for setting up cras snd devices.
              Possible key values:
              capture - Enable audio capture. Default to false.
              client_type - Set specific client type for cras backend.
              num_output_streams - Set number of output PCM streams
              num_input_streams - Set number of input PCM streams"),
          Argument::flag("no-smt", "Don't use SMT in the guest"),
          Argument::value("rt-cpus", "CPUSET", "Comma-separated list of CPUs or CPU ranges to run VCPUs on. (e.g. 0,1-3,5) (default: none)"),
          Argument::flag("delay-rt", "Don't set VCPUs real-time until make-rt command is run"),
          Argument::short_value('m',
                                "mem",
                                "N",
                                "Amount of guest memory in MiB. (default: 256)"),
          Argument::value("init-mem",
                          "N",
                          "Amount of guest memory outside the balloon at boot in MiB. (default: --mem)"),
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
                              id=STRING - Set the block device identifier to an ASCII string, up to 20 characters (default: no ID)
                              o_direct=BOOL - Use O_DIRECT mode to bypass page cache"),
          Argument::value("rwdisk", "PATH[,key=value[,key=value[,...]]", "Path to a writable disk image followed by optional comma-separated options.
                              See --disk for valid options."),
          Argument::value("rw-pmem-device", "PATH", "Path to a writable disk image."),
          Argument::value("pmem-device", "PATH", "Path to a disk image."),
          Argument::value("pstore", "path=PATH,size=SIZE", "Path to pstore buffer backend file followed by size."),
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
                              socket_type - Set specific socket type for cras backend.
                              server - The to the VIOS server (unix socket)."),
          #[cfg(feature = "audio")]
          Argument::value("sound", "[PATH]", "Path to the VioS server socket for setting up virtio-snd devices."),
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
          Argument::flag("wayland-dmabuf", "DEPRECATED: Enable support for DMABufs in Wayland device."),
          Argument::short_value('s',
                                "socket",
                                "PATH",
                                "Path to put the control socket. If PATH is a directory, a name will be generated."),
          Argument::value("balloon-control", "PATH", "Path for balloon controller socket."),
          Argument::flag("disable-sandbox", "Run all devices in one, non-sandboxed process."),
          Argument::value("cid", "CID", "Context ID for virtual sockets."),
          Argument::value("shared-dir", "PATH:TAG[:type=TYPE:writeback=BOOL:timeout=SECONDS:uidmap=UIDMAP:gidmap=GIDMAP:cache=CACHE:dax=BOOL,posix_acl=BOOL]",
                          "Colon-separated options for configuring a directory to be shared with the VM.
                              The first field is the directory to be shared and the second field is the tag that the VM can use to identify the device.
                              The remaining fields are key=value pairs that may appear in any order.  Valid keys are:
                              type=(p9, fs) - Indicates whether the directory should be shared via virtio-9p or virtio-fs (default: p9).
                              uidmap=UIDMAP - The uid map to use for the device's jail in the format \"inner outer count[,inner outer count]\" (default: 0 <current euid> 1).
                              gidmap=GIDMAP - The gid map to use for the device's jail in the format \"inner outer count[,inner outer count]\" (default: 0 <current egid> 1).
                              cache=(never, auto, always) - Indicates whether the VM can cache the contents of the shared directory (default: auto).  When set to \"auto\" and the type is \"fs\", the VM will use close-to-open consistency for file contents.
                              timeout=SECONDS - How long the VM should consider file attributes and directory entries to be valid (default: 5).  If the VM has exclusive access to the directory, then this should be a large value.  If the directory can be modified by other processes, then this should be 0.
                              writeback=BOOL - Enables writeback caching (default: false).  This is only safe to do when the VM has exclusive access to the files in a directory.  Additionally, the server should have read permission for all files as the VM may issue read requests even for files that are opened write-only.
                              dax=BOOL - Enables DAX support.  Enabling DAX can improve performance for frequently accessed files by mapping regions of the file directly into the VM's memory.  There is a cost of slightly increased latency the first time the file is accessed.  Since the mapping is shared directly from the host kernel's file cache, enabling DAX can improve performance even when the guest cache policy is \"Never\".  The default value for this option is \"false\".
                              posix_acl=BOOL - Indicates whether the shared directory supports POSIX ACLs.  This should only be enabled when the underlying file system supports POSIX ACLs.  The default value for this option is \"true\".
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
          Argument::value("tap-name",
                          "NAME",
                          "Name of a configured persistent TAP interface to use for networking. A different virtual network card will be added each time this argument is given."),
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
                              cache-path=PATH - The path to the virtio-gpu device shader cache.
                              cache-size=SIZE - The maximum size of the shader cache."),
          #[cfg(feature = "gpu")]
          Argument::flag_or_value("gpu-display",
                                  "[width=INT,height=INT]",
                                  "(EXPERIMENTAL) Comma separated key=value pairs for setting up a display on the virtio-gpu device
                              Possible key values:
                              width=INT - The width of the virtual display connected to the virtio-gpu.
                              height=INT - The height of the virtual display connected to the virtio-gpu."),
          #[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
          Argument::flag_or_value("gpu-render-server",
                                  "[path=PATH]",
                                  "(EXPERIMENTAL) Comma separated key=value pairs for setting up a render server for the virtio-gpu device
                              Possible key values:
                              path=PATH - The path to the render server executable.
                              cache-path=PATH - The path to the render server shader cache.
                              cache-size=SIZE - The maximum size of the shader cache."),
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
          Argument::value("vfio", "PATH[,guest-address=auto|<BUS:DEVICE.FUNCTION>][,iommu=on|off]", "Path to sysfs of PCI pass through or mdev device.
guest-address=auto|<BUS:DEVICE.FUNCTION> - PCI address that the device will be assigned in the guest (default: auto).  When set to \"auto\", the device will be assigned an address that mirrors its address in the host.
iommu=on|off - indicates whether to enable virtio IOMMU for this device"),
          Argument::value("vfio-platform", "PATH", "Path to sysfs of platform pass through"),
          Argument::flag("virtio-iommu", "Add a virtio-iommu device"),
          #[cfg(feature = "video-decoder")]
          Argument::flag_or_value("video-decoder", "[backend]", "(EXPERIMENTAL) enable virtio-video decoder device
                              Possible backend values: libvda"),
          #[cfg(feature = "video-encoder")]
          Argument::flag_or_value("video-encoder", "[backend]", "(EXPERIMENTAL) enable virtio-video encoder device
                              Possible backend values: libvda"),
          Argument::value("acpi-table", "PATH", "Path to user provided ACPI table"),
          Argument::flag("protected-vm", "(EXPERIMENTAL) prevent host access to guest memory"),
          Argument::flag("protected-vm-without-firmware", "(EXPERIMENTAL) prevent host access to guest memory, but don't use protected VM firmware"),
          #[cfg(target_arch = "aarch64")]
          Argument::value("swiotlb", "N", "(EXPERIMENTAL) Size of virtio swiotlb buffer in MiB (default: 64 if `--protected-vm` or `--protected-vm-without-firmware` is present)."),
          Argument::flag_or_value("battery",
                                  "[type=TYPE]",
                                  "Comma separated key=value pairs for setting up battery device
                              Possible key values:
                              type=goldfish - type of battery emulation, defaults to goldfish"),
          Argument::value("gdb", "PORT", "(EXPERIMENTAL) gdb on the given port"),
          Argument::flag("no-balloon", "Don't use virtio-balloon device in the guest"),
          #[cfg(feature = "usb")]
          Argument::flag("no-usb", "Don't use usb devices in the guest"),
          Argument::flag("no-rng", "Don't create RNG device in the guest"),
          Argument::value("balloon_bias_mib", "N", "Amount to bias balance of memory between host and guest as the balloon inflates, in MiB."),
          Argument::value("vhost-user-blk", "SOCKET_PATH", "Path to a socket for vhost-user block"),
          Argument::value("vhost-user-console", "SOCKET_PATH", "Path to a socket for vhost-user console"),
          Argument::value("vhost-user-gpu", "SOCKET_PATH", "Paths to a vhost-user socket for gpu"),
          Argument::value("vhost-user-mac80211-hwsim", "SOCKET_PATH", "Path to a socket for vhost-user mac80211_hwsim"),
          Argument::value("vhost-user-net", "SOCKET_PATH", "Path to a socket for vhost-user net"),
          #[cfg(feature = "audio")]
          Argument::value("vhost-user-snd", "SOCKET_PATH", "Path to a socket for vhost-user snd"),
          Argument::value("vhost-user-vsock", "SOCKET_PATH", "Path to a socket for vhost-user vsock"),
          Argument::value("vhost-user-wl", "SOCKET_PATH:TUBE_PATH", "Paths to a vhost-user socket for wayland and a Tube socket for additional wayland-specific messages"),
          Argument::value("vhost-user-fs", "SOCKET_PATH:TAG",
                          "Path to a socket path for vhost-user fs, and tag for the shared dir"),
          Argument::value("vvu-proxy", "SOCKET_PATH[,addr=DOMAIN:BUS:DEVICE.FUNCTION,uuid=UUID]", "Socket path for the Virtio Vhost User proxy device.
                              Parameters
                              addr=BUS:DEVICE.FUNCTION - PCI address that the proxy device will be allocated (default: automatically allocated)
                              uuid=UUID - UUID which will be stored in VVU PCI config space that is readable from guest userspace"),
          #[cfg(feature = "direct")]
          Argument::value("direct-pmio", "PATH@RANGE[,RANGE[,...]]", "Path and ranges for direct port mapped I/O access. RANGE may be decimal or hex (starting with 0x)."),
          #[cfg(feature = "direct")]
          Argument::value("direct-mmio", "PATH@RANGE[,RANGE[,...]]", "Path and ranges for direct memory mapped I/O access. RANGE may be decimal or hex (starting with 0x)."),
#[cfg(feature = "direct")]
          Argument::value("direct-level-irq", "irq", "Enable interrupt passthrough"),
#[cfg(feature = "direct")]
          Argument::value("direct-edge-irq", "irq", "Enable interrupt passthrough"),
#[cfg(feature = "direct")]
          Argument::value("direct-wake-irq", "irq", "Enable wakeup interrupt for host"),
#[cfg(feature = "direct")]
          Argument::value("direct-gpe", "gpe", "Enable GPE interrupt and register access passthrough"),
          Argument::value("dmi", "DIR", "Directory with smbios_entry_point/DMI files"),
          Argument::flag("no-legacy", "Don't use legacy KBD/RTC devices emulation"),
          Argument::value("userspace-msr", "INDEX,action=r0", "Userspace MSR handling. Takes INDEX of the MSR and how they are handled.
                              action=r0 - forward RDMSR to host kernel cpu0.
"),
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
          Argument::flag("host-cpu-topology", "Use mirror cpu topology of Host for Guest VM"),
          Argument::flag("privileged-vm", "Grant this Guest VM certian privileges to manage Host resources, such as power management."),
          Argument::value("stub-pci-device", "DOMAIN:BUS:DEVICE.FUNCTION[,vendor=NUM][,device=NUM][,class=NUM][,subsystem_vendor=NUM][,subsystem_device=NUM][,revision=NUM]", "Comma-separated key=value pairs for setting up a stub PCI device that just enumerates. The first option in the list must specify a PCI address to claim.
                              Optional further parameters
                              vendor=NUM - PCI vendor ID
                              device=NUM - PCI device ID
                              class=NUM - PCI class (including class code, subclass, and programming interface)
                              subsystem_vendor=NUM - PCI subsystem vendor ID
                              subsystem_device=NUM - PCI subsystem device ID
                              revision=NUM - revision"),
          Argument::flag_or_value("coiommu",
                          "unpin_policy=POLICY,unpin_interval=NUM,unpin_limit=NUM,unpin_gen_threshold=NUM ",
                          "Comma separated key=value pairs for setting up coiommu devices.
                              Possible key values:
                              unpin_policy=lru - LRU unpin policy.
                              unpin_interval=NUM - Unpin interval time in seconds.
                              unpin_limit=NUM - Unpin limit for each unpin cycle, in unit of page count. 0 is invalid.
                              unpin_gen_threshold=NUM -  Number of unpin intervals a pinned page must be busy for to be aged into the older which is less frequently checked generation."),
          Argument::value("file-backed-mapping", "addr=NUM,size=SIZE,path=PATH[,offset=NUM][,ro][,rw][,sync]", "Map the given file into guest memory at the specified address.
                              Parameters (addr, size, path are required):
                              addr=NUM - guest physical address to map at
                              size=NUM - amount of memory to map
                              path=PATH - path to backing file/device to map
                              offset=NUM - offset in backing file (default 0)
                              ro - make the mapping readonly (default)
                              rw - make the mapping writable
                              sync - open backing file with O_SYNC
                              align - whether to adjust addr and size to page boundaries implicitly"),
          #[cfg(feature = "direct")]
          Argument::value("pcie-root-port", "PATH[,hp_gpe=NUM]", "Path to sysfs of host pcie root port and host pcie root port hotplug gpe number"),
          Argument::value("pivot-root", "PATH", "Path to empty directory to use for sandbox pivot root."),
          #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
          Argument::flag("s2idle", "Set Low Power S0 Idle Capable Flag for guest Fixed ACPI Description Table"),
          Argument::flag("strict-balloon", "Don't allow guest to use pages from the balloon"),
          Argument::value("mmio-address-range", "STARTADDR-ENDADDR[,STARTADDR-ENDADDR]*",
                          "Ranges (inclusive) into which to limit guest mmio addresses. Note that
                           this this may cause mmio allocations to fail if the specified ranges are
                           incompatible with the default ranges calculated by crosvm."),
          #[cfg(target_os = "android")]
          Argument::value("task-profiles", "NAME[,...]", "Comma-separated names of the task profiles to apply to all threads in crosvm including the vCPU threads."),
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
                    Ok(CommandStatus::VmStop)
                }
                Err(e) => {
                    error!("{:#}", e);
                    Err(())
                }
            }
        }
        Ok(()) => match platform::run_config(cfg) {
            Ok(platform::ExitState::Stop) => {
                info!("crosvm has exited normally");
                Ok(CommandStatus::VmStop)
            }
            Ok(platform::ExitState::Reset) => {
                info!("crosvm has exited normally due to reset request");
                Ok(CommandStatus::VmReset)
            }
            Ok(platform::ExitState::Crash) => {
                info!("crosvm has exited due to a VM crash");
                Ok(CommandStatus::VmCrash)
            }
            Ok(platform::ExitState::GuestPanic) => {
                info!("crosvm has exited due to a kernel panic in guest");
                Ok(CommandStatus::GuestPanic)
            }
            Err(e) => {
                error!("crosvm has exited with error: {:#}", e);
                Err(())
            }
        },
        Err(argument::Error::PrintHelp) => {
            print_help("crosvm run", "KERNEL", &arguments[..]);
            Ok(CommandStatus::Success)
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

fn powerbtn_vms(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() == 0 {
        print_help("crosvm powerbtn", "VM_SOCKET...", &[]);
        println!("Triggers a power button event in the crosvm instance listening on each `VM_SOCKET` given.");
        return Err(());
    }
    let socket_path = &args.next().unwrap();
    let socket_path = Path::new(&socket_path);
    vms_request(&VmRequest::Powerbtn, socket_path)
}

fn inject_gpe(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() < 2 {
        print_help("crosvm gpe", "GPE# VM_SOCKET...", &[]);
        println!("Injects a general-purpose event (GPE#) into the crosvm instance listening on each `VM_SOCKET` given.");
        return Err(());
    }
    let gpe = match args.next().unwrap().parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            error!("Failed to parse GPE#");
            return Err(());
        }
    };

    let socket_path = &args.next().unwrap();
    let socket_path = Path::new(&socket_path);
    vms_request(&VmRequest::Gpe(gpe), socket_path)
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
    match serde_json::to_string_pretty(&response) {
        Ok(response_json) => println!("{}", response_json),
        Err(e) => {
            error!("Failed to serialize into JSON: {}", e);
            return Err(());
        }
    }
    match response {
        VmResponse::BalloonStats { .. } => Ok(()),
        _ => Err(()),
    }
}

fn modify_battery(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() < 4 {
        print_help(
            "crosvm battery BATTERY_TYPE ",
            "[status STATUS | \
             present PRESENT | \
             health HEALTH | \
             capacity CAPACITY | \
             aconline ACONLINE ] \
             VM_SOCKET...",
            &[],
        );
        return Err(());
    }

    // This unwrap will not panic because of the above length check.
    let battery_type = args.next().unwrap();
    let property = args.next().unwrap();
    let target = args.next().unwrap();

    let socket_path = args.next().unwrap();
    let socket_path = Path::new(&socket_path);

    do_modify_battery(socket_path, &*battery_type, &*property, &*target)
}

fn modify_vfio(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() < 3 {
        print_help(
            "crosvm vfio",
            "[add | remove host_vfio_sysfs] VM_SOCKET...",
            &[],
        );
        return Err(());
    }

    // This unwrap will not panic because of the above length check.
    let command = args.next().unwrap();
    let path_str = args.next().unwrap();
    let vfio_path = PathBuf::from(&path_str);
    if !vfio_path.exists() || !vfio_path.is_dir() {
        error!("Invalid host sysfs path: {}", path_str);
        return Err(());
    }

    let socket_path = args.next().unwrap();
    let socket_path = Path::new(&socket_path);

    let add = match command.as_ref() {
        "add" => true,
        "remove" => false,
        other => {
            error!("Invalid vfio command {}", other);
            return Err(());
        }
    };

    let request = VmRequest::VfioCommand { vfio_path, add };
    handle_request(&request, socket_path)?;
    Ok(())
}

#[cfg(feature = "composite-disk")]
fn create_composite(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() < 1 {
        print_help("crosvm create_composite", "PATH [LABEL:PARTITION]..", &[]);
        println!("Creates a new composite disk image containing the given partition images");
        return Err(());
    }

    let composite_image_path = args.next().unwrap();
    let zero_filler_path = format!("{}.filler", composite_image_path);
    let header_path = format!("{}.header", composite_image_path);
    let footer_path = format!("{}.footer", composite_image_path);

    let mut composite_image_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&composite_image_path)
        .map_err(|e| {
            error!(
                "Failed opening composite disk image file at '{}': {}",
                composite_image_path, e
            );
        })?;
    create_zero_filler(&zero_filler_path).map_err(|e| {
        error!(
            "Failed to create zero filler file at '{}': {}",
            &zero_filler_path, e
        );
    })?;
    let mut header_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&header_path)
        .map_err(|e| {
            error!(
                "Failed opening header image file at '{}': {}",
                header_path, e
            );
        })?;
    let mut footer_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&footer_path)
        .map_err(|e| {
            error!(
                "Failed opening footer image file at '{}': {}",
                footer_path, e
            );
        })?;

    let partitions = args
        .into_iter()
        .map(|partition_arg| {
            if let [label, path] = partition_arg.split(":").collect::<Vec<_>>()[..] {
                let partition_file = File::open(path)
                    .map_err(|e| error!("Failed to open partition image: {}", e))?;
                let size =
                    create_disk_file(partition_file, disk::MAX_NESTING_DEPTH, Path::new(path))
                        .map_err(|e| error!("Failed to create DiskFile instance: {}", e))?
                        .get_len()
                        .map_err(|e| error!("Failed to get length of partition image: {}", e))?;
                Ok(PartitionInfo {
                    label: label.to_owned(),
                    path: Path::new(path).to_owned(),
                    partition_type: ImagePartitionType::LinuxFilesystem,
                    writable: false,
                    size,
                })
            } else {
                error!(
                    "Must specify label and path for partition '{}', like LABEL:PATH",
                    partition_arg
                );
                Err(())
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    create_composite_disk(
        &partitions,
        &PathBuf::from(zero_filler_path),
        &PathBuf::from(header_path),
        &mut header_file,
        &PathBuf::from(footer_path),
        &mut footer_file,
        &mut composite_image_file,
    )
    .map_err(|e| {
        error!(
            "Failed to create composite disk image at '{}': {}",
            composite_image_path, e
        );
    })?;

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
            QcowFile::new_from_backing(file, &backing_file, disk::MAX_NESTING_DEPTH).map_err(
                |e| {
                    error!("Failed to create qcow file at '{}': {}", file_path, e);
                },
            )?
        }
        _ => unreachable!(),
    };
    Ok(())
}

fn start_device(mut args: std::env::Args) -> std::result::Result<(), ()> {
    let print_usage = || {
        print_help(
            "crosvm device",
            " (block|console|cras-snd|fs|gpu|net|wl) <device-specific arguments>",
            &[],
        );
    };

    if args.len() == 0 {
        print_usage();
        return Err(());
    }

    let device = args.next().unwrap();

    let program_name = format!("crosvm device {}", device);

    let args = args.collect::<Vec<_>>();
    let args = args.iter().map(Deref::deref).collect::<Vec<_>>();
    let args = args.as_slice();

    let result = match device.as_str() {
        "block" => run_block_device(&program_name, args),
        "console" => run_console_device(&program_name, args),
        #[cfg(feature = "audio_cras")]
        "cras-snd" => run_cras_snd_device(&program_name, args),
        "fs" => run_fs_device(&program_name, args),
        #[cfg(feature = "gpu")]
        "gpu" => run_gpu_device(&program_name, args),
        "net" => run_net_device(&program_name, args),
        "vsock" => run_vsock_device(&program_name, args),
        "wl" => run_wl_device(&program_name, args),
        _ => {
            println!("Unknown device name: {}", device);
            print_usage();
            return Err(());
        }
    };

    result.map_err(|e| {
        error!("Failed to run {} device: {:#}", device, e);
    })
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

fn make_rt(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() == 0 {
        print_help("crosvm make_rt", "VM_SOCKET...", &[]);
        println!("Makes the crosvm instance listening on each `VM_SOCKET` given RT.");
        return Err(());
    }
    let socket_path = &args.next().unwrap();
    let socket_path = Path::new(&socket_path);
    vms_request(&VmRequest::MakeRT, socket_path)
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
            let vid = u16::from_str_radix(vid, 16)
                .map_err(|e| ModifyUsbError::ArgParseInt("vid", vid.to_owned(), e))?;
            let pid = u16::from_str_radix(pid, 16)
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

    do_usb_attach(socket_path, bus, addr, vid, pid, &dev_path)
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
    do_usb_detach(socket_path, port)
}

fn usb_list(mut args: std::env::Args) -> ModifyUsbResult<UsbControlResult> {
    let socket_path = args
        .next()
        .ok_or(ModifyUsbError::ArgMissing("control socket path"))?;
    let socket_path = Path::new(&socket_path);
    do_usb_list(socket_path)
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

fn print_usage() {
    print_help("crosvm", "[--extended-status] [command]", &[]);
    println!("Commands:");
    println!("    balloon - Set balloon size of the crosvm instance.");
    println!("    balloon_stats - Prints virtio balloon statistics.");
    println!("    battery - Modify battery.");
    #[cfg(feature = "composite-disk")]
    println!("    create_composite  - Create a new composite disk image file.");
    println!("    create_qcow2  - Create a new qcow2 disk image file.");
    println!("    device - Start a device process.");
    println!("    disk - Manage attached virtual disk devices.");
    println!(
        "    make_rt - Enables real-time vcpu priority for crosvm instances started with \
         `--delay-rt`."
    );
    println!("    resume - Resumes the crosvm instance.");
    println!("    run - Start a new crosvm instance.");
    println!("    stop - Stops crosvm instances via their control sockets.");
    println!("    suspend - Suspends the crosvm instance.");
    println!("    powerbtn - Triggers a power button event in the crosvm instance.");
    println!("    gpe - Injects a general-purpose event into the crosvm instance.");
    println!("    usb - Manage attached virtual USB devices.");
    println!("    version - Show package version.");
    println!("    vfio - add/remove host vfio pci device into guest.");
}

fn crosvm_main() -> std::result::Result<CommandStatus, ()> {
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

    let mut cmd_arg = args.next();
    let extended_status = match cmd_arg.as_ref().map(|s| s.as_ref()) {
        Some("--extended-status") => {
            cmd_arg = args.next();
            true
        }
        _ => false,
    };

    let command = match cmd_arg {
        Some(c) => c,
        None => {
            print_usage();
            return Ok(CommandStatus::Success);
        }
    };

    // Past this point, usage of exit is in danger of leaking zombie processes.
    let ret = if command == "run" {
        // We handle run_vm separately because it does not simply signal success/error
        // but also indicates whether the guest requested reset or stop.
        run_vm(args)
    } else {
        match &command[..] {
            "balloon" => balloon_vms(args),
            "balloon_stats" => balloon_stats(args),
            "battery" => modify_battery(args),
            #[cfg(feature = "composite-disk")]
            "create_composite" => create_composite(args),
            "create_qcow2" => create_qcow2(args),
            "device" => start_device(args),
            "disk" => disk_cmd(args),
            "make_rt" => make_rt(args),
            "resume" => resume_vms(args),
            "stop" => stop_vms(args),
            "suspend" => suspend_vms(args),
            "powerbtn" => powerbtn_vms(args),
            "gpe" => inject_gpe(args),
            "usb" => modify_usb(args),
            "version" => pkg_version(),
            "vfio" => modify_vfio(args),
            c => {
                println!("invalid subcommand: {:?}", c);
                print_usage();
                Err(())
            }
        }
        .map(|_| CommandStatus::Success)
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
    ret.map(|s| {
        if extended_status {
            s
        } else {
            CommandStatus::Success
        }
    })
}

fn main() {
    let exit_code = match crosvm_main() {
        Ok(CommandStatus::Success | CommandStatus::VmStop) => 0,
        Ok(CommandStatus::VmReset) => 32,
        Ok(CommandStatus::VmCrash) => 33,
        Ok(CommandStatus::GuestPanic) => 34,
        Err(_) => 1,
    };
    std::process::exit(exit_code);
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

    #[cfg(feature = "audio_cras")]
    #[test]
    fn parse_ac97_vaild() {
        parse_ac97_options("backend=cras").expect("parse should have succeded");
    }

    #[cfg(feature = "audio")]
    #[test]
    fn parse_ac97_null_vaild() {
        parse_ac97_options("backend=null").expect("parse should have succeded");
    }

    #[cfg(feature = "audio_cras")]
    #[test]
    fn parse_ac97_capture_vaild() {
        parse_ac97_options("backend=cras,capture=true").expect("parse should have succeded");
    }

    #[cfg(feature = "audio_cras")]
    #[test]
    fn parse_ac97_client_type() {
        parse_ac97_options("backend=cras,capture=true,client_type=crosvm")
            .expect("parse should have succeded");
        parse_ac97_options("backend=cras,capture=true,client_type=arcvm")
            .expect("parse should have succeded");
        parse_ac97_options("backend=cras,capture=true,client_type=none")
            .expect_err("parse should have failed");
    }

    #[cfg(feature = "audio_cras")]
    #[test]
    fn parse_ac97_socket_type() {
        parse_ac97_options("socket_type=unified").expect("parse should have succeded");
        parse_ac97_options("socket_type=legacy").expect("parse should have succeded");
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
        assert!(config.plugin_mounts[0].writable);
    }

    #[test]
    fn parse_plugin_mount_valid_shorthand() {
        let mut config = Config::default();
        set_argument(&mut config, "plugin-mount", Some("/dev/null")).expect("parse should succeed");
        assert_eq!(config.plugin_mounts[0].dst, PathBuf::from("/dev/null"));
        assert!(!config.plugin_mounts[0].writable);
        set_argument(&mut config, "plugin-mount", Some("/dev/null:/dev/zero"))
            .expect("parse should succeed");
        assert_eq!(config.plugin_mounts[1].dst, PathBuf::from("/dev/zero"));
        assert!(!config.plugin_mounts[1].writable);
        set_argument(&mut config, "plugin-mount", Some("/dev/null::true"))
            .expect("parse should succeed");
        assert_eq!(config.plugin_mounts[2].dst, PathBuf::from("/dev/null"));
        assert!(config.plugin_mounts[2].writable);
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
            config.virtio_single_touch.first().unwrap().get_size(),
            (DEFAULT_TOUCH_DEVICE_WIDTH, DEFAULT_TOUCH_DEVICE_HEIGHT)
        );
        assert_eq!(
            config.virtio_trackpad.first().unwrap().get_size(),
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
            config.virtio_single_touch.first().unwrap().get_size(),
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
            config.virtio_single_touch.first().unwrap().get_size(),
            (width, height)
        );
        assert_eq!(
            config.virtio_trackpad.first().unwrap().get_size(),
            (width, height)
        );
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
            config.virtio_single_touch.first().unwrap().get_size(),
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
            config.virtio_switches.pop().unwrap(),
            PathBuf::from("/dev/switches-test")
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_default_vulkan_support() {
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_options(Some("backend=virglrenderer"), &mut gpu_params).is_ok());
            assert!(!gpu_params.use_vulkan);
        }

        #[cfg(feature = "gfxstream")]
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_options(Some("backend=gfxstream"), &mut gpu_params).is_ok());
            assert!(gpu_params.use_vulkan);
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_with_vulkan_specified() {
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_options(Some("vulkan=true"), &mut gpu_params).is_ok());
            assert!(gpu_params.use_vulkan);
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(
                parse_gpu_options(Some("backend=virglrenderer,vulkan=true"), &mut gpu_params)
                    .is_ok()
            );
            assert!(gpu_params.use_vulkan);
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(
                parse_gpu_options(Some("vulkan=true,backend=virglrenderer"), &mut gpu_params)
                    .is_ok()
            );
            assert!(gpu_params.use_vulkan);
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_options(Some("vulkan=false"), &mut gpu_params).is_ok());
            assert!(!gpu_params.use_vulkan);
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(
                parse_gpu_options(Some("backend=virglrenderer,vulkan=false"), &mut gpu_params)
                    .is_ok()
            );
            assert!(!gpu_params.use_vulkan);
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(
                parse_gpu_options(Some("vulkan=false,backend=virglrenderer"), &mut gpu_params)
                    .is_ok()
            );
            assert!(!gpu_params.use_vulkan);
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_options(
                Some("backend=virglrenderer,vulkan=invalid_value"),
                &mut gpu_params
            )
            .is_err());
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_options(
                Some("vulkan=invalid_value,backend=virglrenderer"),
                &mut gpu_params
            )
            .is_err());
        }
    }

    #[cfg(all(feature = "gpu", feature = "gfxstream"))]
    #[test]
    fn parse_gpu_options_gfxstream_with_syncfd_specified() {
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(
                parse_gpu_options(Some("backend=gfxstream,syncfd=true"), &mut gpu_params).is_ok()
            );
            assert!(gpu_params.gfxstream_use_syncfd);
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(
                parse_gpu_options(Some("syncfd=true,backend=gfxstream"), &mut gpu_params).is_ok()
            );
            assert!(gpu_params.gfxstream_use_syncfd);
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(
                parse_gpu_options(Some("backend=gfxstream,syncfd=false"), &mut gpu_params).is_ok()
            );
            assert!(!gpu_params.gfxstream_use_syncfd);
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(
                parse_gpu_options(Some("syncfd=false,backend=gfxstream"), &mut gpu_params).is_ok()
            );
            assert!(!gpu_params.gfxstream_use_syncfd);
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_options(
                Some("backend=gfxstream,syncfd=invalid_value"),
                &mut gpu_params
            )
            .is_err());
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(parse_gpu_options(
                Some("syncfd=invalid_value,backend=gfxstream"),
                &mut gpu_params
            )
            .is_err());
        }
    }

    #[cfg(all(feature = "gpu", feature = "gfxstream"))]
    #[test]
    fn parse_gpu_options_not_gfxstream_with_syncfd_specified() {
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(
                parse_gpu_options(Some("backend=virglrenderer,syncfd=true"), &mut gpu_params)
                    .is_err()
            );
        }
        {
            let mut gpu_params: GpuParameters = Default::default();
            assert!(
                parse_gpu_options(Some("syncfd=true,backend=virglrenderer"), &mut gpu_params)
                    .is_err()
            );
        }
    }

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

    #[test]
    fn parse_stub_pci() {
        let params = parse_stub_pci_parameters(Some("0000:01:02.3,vendor=0xfffe,device=0xfffd,class=0xffc1c2,subsystem_vendor=0xfffc,subsystem_device=0xfffb,revision=0xa")).unwrap();
        assert_eq!(params.address.bus, 1);
        assert_eq!(params.address.dev, 2);
        assert_eq!(params.address.func, 3);
        assert_eq!(params.vendor_id, 0xfffe);
        assert_eq!(params.device_id, 0xfffd);
        assert_eq!(params.class as u8, PciClassCode::Other as u8);
        assert_eq!(params.subclass, 0xc1);
        assert_eq!(params.programming_interface, 0xc2);
        assert_eq!(params.subsystem_vendor_id, 0xfffc);
        assert_eq!(params.subsystem_device_id, 0xfffb);
        assert_eq!(params.revision_id, 0xa);
    }

    #[cfg(feature = "direct")]
    #[test]
    fn parse_direct_io_options_valid() {
        let params = parse_direct_io_options(Some("/dev/mem@1,100-110")).unwrap();
        assert_eq!(params.path.to_str(), Some("/dev/mem"));
        assert_eq!(params.ranges[0], BusRange { base: 1, len: 1 });
        assert_eq!(params.ranges[1], BusRange { base: 100, len: 11 });
    }

    #[cfg(feature = "direct")]
    #[test]
    fn parse_direct_io_options_hex() {
        let params = parse_direct_io_options(Some("/dev/mem@1,0x10,100-110,0x10-0x20")).unwrap();
        assert_eq!(params.path.to_str(), Some("/dev/mem"));
        assert_eq!(params.ranges[0], BusRange { base: 1, len: 1 });
        assert_eq!(params.ranges[1], BusRange { base: 0x10, len: 1 });
        assert_eq!(params.ranges[2], BusRange { base: 100, len: 11 });
        assert_eq!(
            params.ranges[3],
            BusRange {
                base: 0x10,
                len: 0x11
            }
        );
    }

    #[cfg(feature = "direct")]
    #[test]
    fn parse_direct_io_options_invalid() {
        assert!(parse_direct_io_options(Some("/dev/mem@0y10"))
            .unwrap_err()
            .to_string()
            .contains("invalid base range value"));

        assert!(parse_direct_io_options(Some("/dev/mem@"))
            .unwrap_err()
            .to_string()
            .contains("invalid base range value"));
    }

    #[test]
    fn parse_file_backed_mapping_valid() {
        let params = parse_file_backed_mapping(Some(
            "addr=0x1000,size=0x2000,path=/dev/mem,offset=0x3000,ro,rw,sync",
        ))
        .unwrap();
        assert_eq!(params.address, 0x1000);
        assert_eq!(params.size, 0x2000);
        assert_eq!(params.path, PathBuf::from("/dev/mem"));
        assert_eq!(params.offset, 0x3000);
        assert!(params.writable);
        assert!(params.sync);
    }

    #[test]
    fn parse_file_backed_mapping_incomplete() {
        assert!(parse_file_backed_mapping(Some("addr=0x1000,size=0x2000"))
            .unwrap_err()
            .to_string()
            .contains("required"));
        assert!(parse_file_backed_mapping(Some("size=0x2000,path=/dev/mem"))
            .unwrap_err()
            .to_string()
            .contains("required"));
        assert!(parse_file_backed_mapping(Some("addr=0x1000,path=/dev/mem"))
            .unwrap_err()
            .to_string()
            .contains("required"));
    }

    #[test]
    fn parse_file_backed_mapping_unaligned() {
        assert!(
            parse_file_backed_mapping(Some("addr=0x1001,size=0x2000,path=/dev/mem"))
                .unwrap_err()
                .to_string()
                .contains("aligned")
        );
        assert!(
            parse_file_backed_mapping(Some("addr=0x1000,size=0x2001,path=/dev/mem"))
                .unwrap_err()
                .to_string()
                .contains("aligned")
        );
    }

    #[test]
    fn parse_file_backed_mapping_align() {
        let params =
            parse_file_backed_mapping(Some("addr=0x3042,size=0xff0,path=/dev/mem,align")).unwrap();
        assert_eq!(params.address, 0x3000);
        assert_eq!(params.size, 0x2000);
    }

    #[test]
    fn parse_userspace_msr_options_test() {
        let index = parse_userspace_msr_options("0x10,action=r0").unwrap();
        assert_eq!(index, 0x10);
        assert!(parse_userspace_msr_options("0x10,action=none").is_err());
        assert!(parse_userspace_msr_options("0x10").is_err());
        assert!(parse_userspace_msr_options("hoge").is_err());
    }
}
