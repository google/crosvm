// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str::FromStr;

#[cfg(all(feature = "prod-build", feature = "kiwi"))]
use devices::serial_device::SerialType;
#[cfg(feature = "gpu")]
use devices::virtio::GpuDisplayMode;
#[cfg(feature = "gpu")]
use devices::virtio::GpuDisplayParameters;
#[cfg(all(feature = "gpu", feature = "gfxstream"))]
use devices::virtio::GpuMode;
#[cfg(feature = "gpu")]
use devices::virtio::GpuParameters;
#[cfg(feature = "audio")]
use devices::Ac97Parameters;
use devices::SerialParameters;
use serde::Deserialize;
use serde::Serialize;

use crate::crosvm::config::Config;

#[cfg(feature = "audio")]
pub fn parse_ac97_options(
    _ac97_params: &mut Ac97Parameters,
    key: &str,
    value: &str,
) -> Result<(), String> {
    Err(format!("unknown ac97 parameter {} {}", key, value))
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
    use crate::crosvm::config::from_key_values;
    let mut gpu_params: GpuParameters = from_key_values(s)?;

    match (
        gpu_params.__width_compat.take(),
        gpu_params.__height_compat.take(),
    ) {
        (Some(width), Some(height)) => {
            let display_mode = GpuDisplayMode::Windowed(width, height);
            gpu_params
                .display_params
                .push(GpuDisplayParameters::default_with_mode(display_mode));
        }
        (None, None) => {}
        _ => {
            return Err("must include both 'width' and 'height' if either is supplied".to_string())
        }
    }

    #[cfg(feature = "gfxstream")]
    if matches!(gpu_params.mode, GpuMode::ModeGfxstream) {
        if gpu_params.use_vulkan.is_none() {
            gpu_params.use_vulkan = Some(use_vulkan());
        }
    } else {
        return Err(format!(
            "backend type {:?} is deprecated, please use gfxstream",
            gpu_params.mode
        ));
    }

    Ok(gpu_params)
}

#[cfg(feature = "gpu")]
pub(crate) fn validate_gpu_config(cfg: &mut Config) -> Result<(), String> {
    if let Some(gpu_parameters) = cfg.gpu_parameters.as_mut() {
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
    use argh::FromArgs;
    #[cfg(feature = "gpu")]
    use devices::virtio::gpu::GpuDisplayMode;
    #[cfg(all(feature = "gpu", feature = "gfxstream"))]
    use rutabaga_gfx::RutabagaWsi;

    #[cfg(any(feature = "audio", feature = "gpu"))]
    use super::*;
    #[cfg(feature = "gpu")]
    use crate::crosvm::config::from_key_values;
    #[cfg(feature = "gpu")]
    use crate::crosvm::sys::config::parse_gpu_options;

    #[cfg(feature = "gpu")]
    fn parse_gpu_display_options(s: &str) -> Result<GpuDisplayParameters, String> {
        from_key_values::<GpuDisplayParameters>(s)
    }

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
        #[cfg(feature = "gfxstream")]
        assert_eq!(
            parse_gpu_options("backend=gfxstream").unwrap().use_vulkan,
            Some(false)
        );
    }

    #[cfg(all(feature = "gpu"))]
    #[test]
    fn parse_gpu_options_with_vulkan_specified() {
        assert_eq!(
            parse_gpu_options("vulkan=true").unwrap().use_vulkan,
            Some(true)
        );
        assert_eq!(
            parse_gpu_options("vulkan=false").unwrap().use_vulkan,
            Some(false)
        );
        assert!(parse_gpu_options("vulkan=invalid_value,backend=virglrenderer").is_err());
    }

    #[cfg(all(feature = "gpu", feature = "gfxstream"))]
    #[test]
    fn parse_gpu_options_gfxstream_with_gles31_specified() {
        assert!(
            parse_gpu_options("backend=gfxstream,gles31=true")
                .unwrap()
                .gfxstream_support_gles31
        );
        assert!(
            parse_gpu_options("gles31=true,backend=gfxstream")
                .unwrap()
                .gfxstream_support_gles31
        );
        assert!(
            !parse_gpu_options("backend=gfxstream,gles31=false")
                .unwrap()
                .gfxstream_support_gles31
        );
        assert!(
            !parse_gpu_options("gles31=false,backend=gfxstream")
                .unwrap()
                .gfxstream_support_gles31
        );
        assert!(parse_gpu_options("backend=gfxstream,gles31=invalid_value").is_err());
        assert!(parse_gpu_options("gles31=invalid_value,backend=gfxstream").is_err());
    }

    #[cfg(all(feature = "gpu", feature = "gfxstream"))]
    #[test]
    fn parse_gpu_options_not_gfxstream_with_gles31_specified() {
        assert!(parse_gpu_options("backend=virglrenderer,gles31=true").is_err());
        assert!(parse_gpu_options("gles31=true,backend=virglrenderer").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_no_display_specified() {
        let display_params = parse_gpu_options("").unwrap().display_params;
        assert!(display_params.is_empty());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_display_size_valid() {
        const WIDTH: u32 = 1720;
        const HEIGHT: u32 = 1800;

        let display_params = parse_gpu_options(format!("width={},height=720", WIDTH).as_str())
            .unwrap()
            .display_params;
        assert_eq!(display_params.len(), 1);
        assert!(
            matches!(display_params[0].mode, GpuDisplayMode::Windowed(width, _) if width == WIDTH)
        );

        let display_params = parse_gpu_options(format!("width=1280,height={}", HEIGHT).as_str())
            .unwrap()
            .display_params;
        assert_eq!(display_params.len(), 1);
        assert!(
            matches!(display_params[0].mode, GpuDisplayMode::Windowed(_, height) if height == HEIGHT)
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_display_size_incomplete() {
        assert!(parse_gpu_options("width=1280").is_err());
        assert!(parse_gpu_options("height=720").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_display_size_duplicated() {
        assert!(parse_gpu_options("width=1280,width=1280,height=720").is_err());
        assert!(parse_gpu_options("width=1280,height=720,height=720").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_mode() {
        let display_params = parse_gpu_display_options("mode=windowed[1280,720]").unwrap();
        assert!(matches!(
            display_params.mode,
            GpuDisplayMode::Windowed(_, _)
        ));

        let display_params = parse_gpu_display_options("mode=borderless_full_screen").unwrap();
        assert!(matches!(
            display_params.mode,
            GpuDisplayMode::BorderlessFullScreen(_)
        ));

        assert!(parse_gpu_display_options("mode=invalid_mode").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_mode_duplicated() {
        assert!(
            parse_gpu_display_options("mode=windowed[1280,720],mode=windowed[1280,720]").is_err()
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_borderless_full_screen_should_not_be_specified_with_size() {
        assert!(parse_gpu_display_options("mode=borderless_full_screen[1280,720]").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_windowed_with_size() {
        const WIDTH: u32 = 1720;
        const HEIGHT: u32 = 1800;

        let display_params =
            parse_gpu_display_options(format!("mode=windowed[{},720]", WIDTH).as_str()).unwrap();
        assert!(matches!(
            display_params.mode,
            GpuDisplayMode::Windowed(width, _) if width == WIDTH
        ));

        let display_params =
            parse_gpu_display_options(format!("mode=windowed[1280,{}]", HEIGHT).as_str()).unwrap();
        assert!(matches!(
            display_params.mode,
            GpuDisplayMode::Windowed(_, height) if height == HEIGHT
        ));

        assert!(parse_gpu_display_options("mode=windowed[]").is_err());
        assert!(parse_gpu_display_options("mode=windowed[1280]").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_hidden() {
        let display_params = parse_gpu_display_options("hidden").unwrap();
        assert!(display_params.hidden);

        let display_params = parse_gpu_display_options("hidden=true").unwrap();
        assert!(display_params.hidden);

        let display_params = parse_gpu_display_options("hidden=false").unwrap();
        assert!(!display_params.hidden);
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_hidden_duplicated() {
        assert!(parse_gpu_display_options("hidden,hidden").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_refresh_rate() {
        const REFRESH_RATE: u32 = 30;

        let display_params =
            parse_gpu_display_options(format!("refresh-rate={}", REFRESH_RATE).as_str()).unwrap();
        assert_eq!(display_params.refresh_rate, REFRESH_RATE);
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_refresh_rate_duplicated() {
        assert!(parse_gpu_display_options("refresh-rate=30,refresh-rate=60").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_and_gpu_display_options_valid() {
        const WIDTH: u32 = 1720;
        const HEIGHT: u32 = 1800;
        const EXPECTED_DISPLAY_MODE: GpuDisplayMode = GpuDisplayMode::Windowed(WIDTH, HEIGHT);
        const BACKEND: &str = if cfg!(feature = "gfxstream") {
            "gfxstream"
        } else {
            "2d"
        };

        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--gpu",
                format!("backend={}", BACKEND).as_str(),
                "--gpu-display",
                format!("windowed[{},{}]", WIDTH, HEIGHT).as_str(),
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let gpu_params = config.gpu_parameters.unwrap();

        assert_eq!(gpu_params.display_params.len(), 1);
        assert_eq!(gpu_params.display_params[0].mode, EXPECTED_DISPLAY_MODE);

        // `width` and `height` in GPU options are supported for CLI backward compatibility.
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--gpu",
                format!("backend={},width={},height={}", BACKEND, WIDTH, HEIGHT).as_str(),
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let gpu_params = config.gpu_parameters.unwrap();

        assert_eq!(gpu_params.display_params.len(), 1);
        assert_eq!(gpu_params.display_params[0].mode, EXPECTED_DISPLAY_MODE);
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_and_gpu_display_options_multi_display_unsupported() {
        let command = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--gpu-display",
                "mode=borderless_full_screen",
                "--gpu-display",
                "mode=borderless_full_screen",
                "/dev/null",
            ],
        )
        .unwrap();
        assert!(Config::try_from(command).is_err());

        let command = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--gpu",
                "width=1280,height=720",
                "--gpu-display",
                "mode=borderless_full_screen",
                "/dev/null",
            ],
        )
        .unwrap();
        assert!(Config::try_from(command).is_err());
    }
}
