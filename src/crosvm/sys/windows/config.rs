// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str::FromStr;

#[cfg(feature = "gpu")]
use base::info;
#[cfg(all(feature = "prod-build", feature = "kiwi"))]
use devices::serial_device::SerialType;
#[cfg(feature = "gpu")]
use devices::virtio::GpuDisplayMode;
#[cfg(feature = "gpu")]
use devices::virtio::GpuDisplayParameters;
#[cfg(feature = "gpu")]
use devices::virtio::GpuMode;
#[cfg(feature = "gpu")]
use devices::virtio::GpuParameters;
#[cfg(feature = "gpu")]
use devices::virtio::DEFAULT_REFRESH_RATE;
#[cfg(feature = "audio")]
use devices::Ac97Parameters;
use devices::SerialParameters;
#[cfg(feature = "gpu")]
use rutabaga_gfx::calculate_context_mask;
#[cfg(feature = "gpu")]
use rutabaga_gfx::RutabagaWsi;
use serde::Deserialize;
use serde::Serialize;

#[cfg(feature = "gpu")]
use crate::crosvm::argument;
use crate::crosvm::config::Config;

#[cfg(feature = "audio")]
pub fn parse_ac97_options(
    _ac97_params: &mut Ac97Parameters,
    key: &str,
    value: &str,
) -> Result<(), String> {
    Err(format!("unknown ac97 parameter {} {}", key, value))
}

#[cfg(feature = "gpu")]
pub fn is_gpu_backend_deprecated(backend: &str) -> bool {
    match backend {
        "2d" | "2D" | "3d" | "3D" | "virglrenderer" => {
            cfg!(feature = "gfxstream")
        }
        _ => false,
    }
}

#[cfg(feature = "gfxstream")]
pub fn use_vulkan() -> bool {
    false
}

pub fn check_serial_params(
    #[allow(unused_variables)] serial_params: &SerialParameters,
) -> Result<(), String> {
    #[cfg(all(feature = "prod-build", feature = "kiwi"))]
    {
        if matches!(serial_params.type_, SerialType::SystemSerialType) {
            return Err(format!(
                "device type not supported: {}",
                serial_params.type_.to_string()
            ));
        }
        if serial_params.stdin {
            return Err(format!("parameter not supported: stdin"));
        }
    }
    Ok(())
}

pub fn validate_config(_cfg: &mut Config) -> std::result::Result<(), String> {
    Ok(())
}

#[cfg(feature = "gpu")]
pub fn parse_gpu_options(s: &str) -> Result<GpuParameters, String> {
    parse_gpu_options_inner(s).map_err(|e| e.to_string())
}

#[cfg(feature = "gpu")]
fn parse_gpu_options_inner(s: &str) -> argument::Result<GpuParameters> {
    let mut gpu_params: GpuParameters = Default::default();
    #[cfg(feature = "gfxstream")]
    let mut vulkan_specified = false;
    #[cfg(feature = "gfxstream")]
    let mut gles31_specified = false;
    #[cfg(feature = "gfxstream")]
    let mut angle_specified = false;

    let mut width: Option<u32> = None;
    let mut height: Option<u32> = None;
    let mut dpi: Option<u32> = None;
    let mut display_mode: Option<String> = None;
    #[cfg(feature = "gfxstream")]
    let mut refresh_rate: Option<u32> = None;
    let opts = s
        .split(',')
        .map(|frag| frag.split('='))
        .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));
    let mut hidden: Option<bool> = None;

    for (k, v) in opts {
        match k {
            "backend" => match v {
                "2d" | "2D" => {
                    if crate::crosvm::sys::config::is_gpu_backend_deprecated(v) {
                        return Err(argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from(
                                "this backend type is deprecated, please use gfxstream.",
                            ),
                        });
                    } else {
                        gpu_params.mode = GpuMode::Mode2D;
                    }
                }
                "3d" | "3D" | "virglrenderer" => {
                    if crate::crosvm::sys::config::is_gpu_backend_deprecated(v) {
                        return Err(argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from(
                                "this backend type is deprecated, please use gfxstream.",
                            ),
                        });
                    } else {
                        gpu_params.mode = GpuMode::ModeVirglRenderer;
                    }
                }
                #[cfg(feature = "gfxstream")]
                "gfxstream" => {
                    gpu_params.mode = GpuMode::ModeGfxstream;
                }
                _ => {
                    return Err(argument::Error::InvalidValue {
                        value: v.to_string(),
                        expected: String::from(
                            #[cfg(feature = "gfxstream")]
                            "gpu parameter 'backend' should be one of (2d|virglrenderer|gfxstream)",
                            #[cfg(not(feature = "gfxstream"))]
                            "gpu parameter 'backend' should be one of (2d|3d)",
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
                        expected: String::from("gpu parameter 'surfaceless' should be a boolean"),
                    });
                }
            },
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
                            expected: String::from("gpu parameter 'vulkan' should be a boolean"),
                        });
                    }
                }
            }
            #[cfg(feature = "gfxstream")]
            "gles3.1" => {
                gles31_specified = true;
                match v {
                    "true" | "" => {
                        gpu_params.gfxstream_support_gles31 = true;
                    }
                    "false" => {
                        gpu_params.gfxstream_support_gles31 = false;
                    }
                    _ => {
                        return Err(argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from("gpu parameter 'gles3.1' should be a boolean"),
                        });
                    }
                }
            }
            "wsi" => match v {
                "vk" => {
                    gpu_params.wsi = Some(RutabagaWsi::Vulkan);
                }
                _ => {
                    return Err(argument::Error::InvalidValue {
                        value: v.to_string(),
                        expected: String::from("gpu parameter 'wsi' should be vk"),
                    });
                }
            },
            "width" => {
                if let Some(width) = width {
                    return Err(argument::Error::TooManyArguments(format!(
                        "width was already specified: {}",
                        width
                    )));
                }
                width = Some(
                    v.parse::<u32>()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from("gpu parameter 'width' must be a valid integer"),
                        })?,
                );
            }
            "height" => {
                if let Some(height) = height {
                    return Err(argument::Error::TooManyArguments(format!(
                        "height was already specified: {}",
                        height
                    )));
                }
                height = Some(
                    v.parse::<u32>()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from(
                                "gpu parameter 'height' must be a valid integer",
                            ),
                        })?,
                );
            }
            "dpi" => {
                if let Some(dpi) = dpi {
                    return Err(argument::Error::TooManyArguments(format!(
                        "dpi was already specified: {}",
                        dpi
                    )));
                }
                dpi = Some(
                    v.parse::<u32>()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: v.to_string(),
                            expected: String::from("gpu parameter 'dpi' must be a valid integer"),
                        })?,
                );
            }
            #[cfg(feature = "gfxstream")]
            "refresh_rate" => {
                if let Some(refresh_rate) = refresh_rate {
                    return Err(argument::Error::TooManyArguments(format!(
                        "refresh_rate was already specified: {}",
                        refresh_rate
                    )));
                }
                refresh_rate =
                    Some(
                        v.parse::<u32>()
                            .map_err(|_| argument::Error::InvalidValue {
                                value: v.to_string(),
                                expected: String::from(
                                    "gpu parameter 'refresh_rate' must be a valid integer",
                                ),
                            })?,
                    );
            }
            "display_mode" => {
                if let Some(display_mode) = display_mode {
                    return Err(argument::Error::TooManyArguments(format!(
                        "display_mode was already specified: {}",
                        display_mode
                    )));
                }
                display_mode = Some(String::from(v));
            }
            "hidden" => match v {
                "true" | "" => {
                    hidden = Some(true);
                }
                "false" => {
                    hidden = Some(false);
                }
                _ => {
                    return Err(argument::Error::InvalidValue {
                        value: v.to_string(),
                        expected: String::from("gpu parameter 'hidden' should be a boolean"),
                    });
                }
            },
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
            "context-types" => {
                let context_types: Vec<String> = v.split(':').map(|s| s.to_string()).collect();
                gpu_params.context_mask = calculate_context_mask(context_types);
            }
            "" => {}
            _ => {
                return Err(argument::Error::UnknownArgument(format!(
                    "gpu parameter {}",
                    k
                )));
            }
        }
    }

    let mut display_param = match display_mode.as_deref() {
        Some("windowed") => GpuDisplayParameters::default_windowed(),
        Some("borderless_full_screen") => GpuDisplayParameters::default_borderless_full_screen(),
        None => Default::default(),
        Some(display_mode) => {
            return Err(argument::Error::InvalidValue {
                value: display_mode.to_string(),
                expected: String::from(
                    "gpu parameter 'display_mode' must be either 'borderless_full_screen' \
                    or 'windowed'",
                ),
            })
        }
    };

    if let Some(hidden) = hidden {
        display_param.hidden = hidden;
    }

    #[cfg(feature = "gfxstream")]
    {
        if let Some(refresh_rate) = refresh_rate {
            gpu_params.refresh_rate = refresh_rate;
        }
    }

    match display_param.display_mode {
        GpuDisplayMode::Windowed {
            width: ref mut width_in_params,
            height: ref mut height_in_params,
            dpi: ref mut dpi_in_params,
        } => {
            if let Some(width) = width {
                *width_in_params = width;
            }
            if let Some(height) = height {
                *height_in_params = height;
            }
            if let Some(dpi) = dpi {
                *dpi_in_params = dpi;
            }
        }
        GpuDisplayMode::BorderlessFullScreen(_) => {
            if width.is_some() || height.is_some() || dpi.is_some() {
                return Err(argument::Error::UnknownArgument(
                    "width, height, or dpi is only supported for windowed display mode".to_string(),
                ));
            }
        }
    }

    #[cfg(feature = "gfxstream")]
    {
        if !vulkan_specified && gpu_params.mode == GpuMode::ModeGfxstream {
            gpu_params.use_vulkan = crate::crosvm::sys::config::use_vulkan();
        }
        if angle_specified || gles31_specified {
            match gpu_params.mode {
                GpuMode::ModeGfxstream => {}
                _ => {
                    return Err(argument::Error::UnknownArgument(
                        "gpu parameters angle and gles3.1 are only supported for gfxstream backend"
                            .to_string(),
                    ));
                }
            }
        }
    }

    gpu_params.display_params = vec![display_param];
    Ok(gpu_params)
}

#[cfg(feature = "gpu")]
pub(crate) fn validate_gpu_config(cfg: &mut Config) -> Result<(), String> {
    if let Some(gpu_parameters) = cfg.gpu_parameters.as_ref() {
        if gpu_parameters.display_params.is_empty() {
            gpu_parameters.display_params.push(Default::default());
        }

        let (width, height) = gpu_parameters.display_params[0].get_virtual_display_size();
        for virtio_multi_touch in cfg.virtio_multi_touch.iter_mut() {
            virtio_multi_touch.set_default_size(width, height);
        }
        for virtio_single_touch in cfg.virtio_single_touch.iter_mut() {
            virtio_single_touch.set_default_size(width, height);
        }

        let dpi = gpu_parameters.display_params[0].get_dpi();
        info!("using dpi {} on the Android guest", dpi);
        cfg.params.push(format!("androidboot.lcd_density={}", dpi));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum IrqChipKind {
    /// All interrupt controllers are emulated in the kernel.
    Kernel,
    /// APIC is emulated in the kernel.  All other interrupt controllers are in userspace.
    Split,
    /// All interrupt controllers are emulated in userspace.
    Userspace,
}

impl FromStr for IrqChipKind {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "kernel" => Ok(Self::Kernel),
            "split" => Ok(Self::Split),
            "userspace" => Ok(Self::Userspace),
            _ => Err("invalid irqchip kind: expected \"kernel\", \"split\", or \"userspace\""),
        }
    }
}

/// Hypervisor backend.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum HypervisorKind {
    #[cfg(feature = "gvm")]
    Gvm,
    #[cfg(feature = "haxm")]
    Haxm,
    #[cfg(feature = "haxm")]
    Ghaxm,
    #[cfg(feature = "whpx")]
    Whpx,
}

impl FromStr for HypervisorKind {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            #[cfg(feature = "gvm")]
            "gvm" => Ok(HypervisorKind::Gvm),
            #[cfg(feature = "haxm")]
            "haxm" => Ok(HypervisorKind::Haxm),
            #[cfg(feature = "haxm")]
            "ghaxm" => Ok(HypervisorKind::Ghaxm),
            #[cfg(feature = "whpx")]
            "whpx" => Ok(HypervisorKind::Whpx),
            _ => Err("invalid hypervisor backend"),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "gpu")]
    use devices::virtio::gpu::GpuDisplayMode;

    #[cfg(any(feature = "audio", feature = "gpu"))]
    use super::*;
    #[cfg(feature = "gpu")]
    use crate::crosvm::sys::config::parse_gpu_options;

    #[cfg(all(feature = "gpu", feature = "gfxstream"))]
    #[test]
    fn parse_gpu_options_gfxstream_with_wsi_specified() {
        {
            let gpu_params: GpuParameters = parse_gpu_options("backend=gfxstream,wsi=vk").unwrap();
            assert!(matches!(gpu_params.wsi, Some(RutabagaWsi::Vulkan)));
        }
        {
            let gpu_params: GpuParameters = parse_gpu_options("wsi=vk,backend=gfxstream").unwrap();
            assert!(matches!(gpu_params.wsi, Some(RutabagaWsi::Vulkan)));
        }
        {
            assert!(parse_gpu_options("backend=gfxstream,wsi=invalid_value").is_err());
        }
        {
            assert!(parse_gpu_options("wsi=invalid_value,backend=gfxstream").is_err());
        }
    }

    #[cfg(feature = "audio")]
    #[test]
    fn parse_ac97_vaild() {
        crate::crosvm::config::parse_ac97_options("backend=win_audio")
            .expect("parse should have succeded");
    }

    #[cfg(all(feature = "gpu"))]
    #[test]
    fn parse_gpu_options_default_vulkan_support() {
        #[cfg(unix)]
        assert!(
            !parse_gpu_options("backend=virglrenderer")
                .unwrap()
                .use_vulkan
        );
        #[cfg(feature = "gfxstream")]
        assert!(!parse_gpu_options("backend=gfxstream").unwrap().use_vulkan);
        #[cfg(all(feature = "gfxstream", unix))]
        assert!(parse_gpu_options("backend=gfxstream").unwrap().use_vulkan);
    }

    #[cfg(all(feature = "gpu"))]
    #[test]
    fn parse_gpu_options_with_vulkan_specified() {
        assert!(parse_gpu_options("vulkan=true").unwrap().use_vulkan);
        #[cfg(unix)]
        assert!(
            parse_gpu_options("backend=virglrenderer,vulkan=true")
                .unwrap()
                .use_vulkan
        );
        #[cfg(unix)]
        assert!(
            parse_gpu_options("vulkan=true,backend=virglrenderer")
                .unwrap()
                .use_vulkan
        );
        assert!(!parse_gpu_options("vulkan=false").unwrap().use_vulkan);
        #[cfg(unix)]
        assert!(
            !parse_gpu_options("backend=virglrenderer,vulkan=false")
                .unwrap()
                .use_vulkan
        );
        #[cfg(unix)]
        assert!(
            !parse_gpu_options("vulkan=false,backend=virglrenderer")
                .unwrap()
                .use_vulkan
        );
        #[cfg(unix)]
        assert!(parse_gpu_options("backend=virglrenderer,vulkan=invalid_value").is_err());
        assert!(parse_gpu_options("vulkan=invalid_value,backend=virglrenderer").is_err());
    }

    #[cfg(all(feature = "gpu", feature = "gfxstream"))]
    #[test]
    fn parse_gpu_options_gfxstream_with_gles31_specified() {
        assert!(
            parse_gpu_options("backend=gfxstream,gles3.1=true")
                .unwrap()
                .gfxstream_support_gles31
        );
        assert!(
            parse_gpu_options("gles3.1=true,backend=gfxstream")
                .unwrap()
                .gfxstream_support_gles31
        );
        assert!(
            !parse_gpu_options("backend=gfxstream,gles3.1=false")
                .unwrap()
                .gfxstream_support_gles31
        );
        assert!(
            !parse_gpu_options("gles3.1=false,backend=gfxstream")
                .unwrap()
                .gfxstream_support_gles31
        );
        assert!(parse_gpu_options("backend=gfxstream,gles3.1=invalid_value").is_err());
        assert!(parse_gpu_options("gles3.1=invalid_value,backend=gfxstream").is_err());
    }

    #[cfg(all(feature = "gpu", feature = "gfxstream"))]
    #[test]
    fn parse_gpu_options_not_gfxstream_with_gles31_specified() {
        assert!(parse_gpu_options("backend=virglrenderer,gles3.1=true").is_err());
        assert!(parse_gpu_options("gles3.1=true,backend=virglrenderer").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_gpu_display_mode() {
        let display_params = parse_gpu_options("display_mode=windowed")
            .unwrap()
            .display_params;
        assert!(matches!(
            display_params[0].display_mode,
            GpuDisplayMode::Windowed { .. }
        ));

        let display_params = parse_gpu_options("display_mode=borderless_full_screen")
            .unwrap()
            .display_params;
        assert!(matches!(
            display_params[0].display_mode,
            GpuDisplayMode::BorderlessFullScreen(_)
        ));

        assert!(parse_gpu_options("display_mode=invalid_mode").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_gpu_display_mode_duplicated() {
        assert!(parse_gpu_options("display_mode=windowed,display_mode=windowed").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_borderless_full_screen_shouldnt_be_specified_with_size() {
        assert!(parse_gpu_options("display_mode=borderless_full_screen,width=1280").is_err());
        assert!(parse_gpu_options("display_mode=borderless_full_screen,height=720").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_windowed_with_size() {
        const WIDTH: u32 = 1720;
        const HEIGHT: u32 = 1800;
        const DPI: u32 = 1808;

        let display_params =
            parse_gpu_options(format!("display_mode=windowed,width={}", WIDTH).as_str())
                .unwrap()
                .display_params;
        assert!(
            matches!(display_params[0].display_mode, GpuDisplayMode::Windowed { width, .. } if width == WIDTH)
        );

        let display_params =
            parse_gpu_options(format!("display_mode=windowed,height={}", HEIGHT).as_str())
                .unwrap()
                .display_params;
        assert!(
            matches!(display_params[0].display_mode, GpuDisplayMode::Windowed { height, .. } if height == HEIGHT)
        );

        let display_params =
            parse_gpu_options(format!("display_mode=windowed,dpi={}", DPI).as_str())
                .unwrap()
                .display_params;
        assert!(
            matches!(display_params[0].display_mode, GpuDisplayMode::Windowed { dpi, .. } if dpi == DPI)
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_hidden() {
        let display_params = parse_gpu_options("hidden=true").unwrap().display_params;
        assert!(display_params[0].hidden);

        let display_params = parse_gpu_options("hidden=false").unwrap().display_params;
        assert!(matches!(display_params[0].hidden, false));
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_refresh_rate() {
        const REFRESH_RATE: u32 = 120;
        let display_params = parse_gpu_options(format!("refresh_rate={}", REFRESH_RATE).as_str())
            .unwrap()
            .display_params;
        assert_eq!(display_params.refresh_rate, REFRESH_RATE);

        assert!(parse_gpu_options(format!("refresh_rate=invalid_value").as_str()).is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_size_duplicated() {
        assert!(parse_gpu_options("width=1280,width=1280").is_err());
        assert!(parse_gpu_options("height=1280,height=1280").is_err());
        assert!(parse_gpu_options("dpi=1280,dpi=1280").is_err());
    }
}
