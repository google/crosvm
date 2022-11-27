// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use devices::virtio::GpuDisplayMode;
use devices::virtio::GpuDisplayParameters;
#[cfg(feature = "gfxstream")]
use devices::virtio::GpuMode;
use devices::virtio::GpuParameters;
use vm_control::gpu::DEFAULT_DPI;

use crate::crosvm::cmdline::FixedGpuDisplayParameters;
use crate::crosvm::cmdline::FixedGpuParameters;
use crate::crosvm::config::Config;

#[cfg(feature = "gfxstream")]
fn default_use_vulkan() -> bool {
    !cfg!(windows)
}

pub(crate) fn fixup_gpu_options(
    mut gpu_params: GpuParameters,
) -> Result<FixedGpuParameters, String> {
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
    if gpu_params.mode == GpuMode::ModeGfxstream {
        if gpu_params.use_vulkan.is_none() {
            gpu_params.use_vulkan = Some(default_use_vulkan());
        }
    } else {
        #[cfg(windows)]
        return Err(format!(
            "backend type {:?} is deprecated, please use gfxstream",
            gpu_params.mode
        ));

        #[cfg(unix)]
        {
            if gpu_params.gfxstream_use_guest_angle.is_some() {
                return Err("'angle' is only supported for gfxstream backend".to_string());
            }
            if gpu_params.gfxstream_support_gles31.is_some() {
                return Err("'gles31' is only supported for gfxstream backend".to_string());
            }
        }
    }

    Ok(FixedGpuParameters(gpu_params))
}

/// Fixes `GpuDisplayParameters` after parsing using serde.
///
/// The `dpi` field is guaranteed to be populated after this is called.
pub(crate) fn fixup_gpu_display_options(
    mut display_params: GpuDisplayParameters,
) -> Result<FixedGpuDisplayParameters, String> {
    let (horizontal_dpi_compat, vertical_dpi_compat) = (
        display_params.__horizontal_dpi_compat.take(),
        display_params.__vertical_dpi_compat.take(),
    );
    // Make sure `display_params.dpi` is always populated.
    display_params.dpi = Some(match display_params.dpi {
        Some(dpi) => {
            if horizontal_dpi_compat.is_some() || vertical_dpi_compat.is_some() {
                return Err(
                    "if 'dpi' is supplied, 'horizontal-dpi' and 'vertical-dpi' must not be supplied"
                        .to_string(),
                );
            }
            dpi
        }
        None => (
            horizontal_dpi_compat.unwrap_or(DEFAULT_DPI),
            vertical_dpi_compat.unwrap_or(DEFAULT_DPI),
        ),
    });

    Ok(FixedGpuDisplayParameters(display_params))
}

pub(crate) fn validate_gpu_config(cfg: &mut Config) -> Result<(), String> {
    if let Some(gpu_parameters) = cfg.gpu_parameters.as_mut() {
        if !gpu_parameters.pci_bar_size.is_power_of_two() {
            return Err(format!(
                "`pci-bar-size` must be a power of two but is {}",
                gpu_parameters.pci_bar_size
            ));
        }

        // Add a default display if no display is specified.
        if gpu_parameters.display_params.is_empty() {
            gpu_parameters.display_params.push(Default::default());
        }

        let (width, height) = gpu_parameters.display_params[0].get_virtual_display_size();
        if let Some(virtio_multi_touch) = cfg.virtio_multi_touch.first_mut() {
            virtio_multi_touch.set_default_size(width, height);
        }
        if let Some(virtio_single_touch) = cfg.virtio_single_touch.first_mut() {
            virtio_single_touch.set_default_size(width, height);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use argh::FromArgs;
    #[cfg(feature = "gfxstream")]
    use rutabaga_gfx::RutabagaWsi;

    use super::*;
    use crate::crosvm::config::from_key_values;

    const fn get_backend_name() -> &'static str {
        if cfg!(feature = "gfxstream") {
            "gfxstream"
        } else if cfg!(feature = "virgl_renderer") {
            "virglrenderer"
        } else {
            "2d"
        }
    }

    /// Parses and fix up a `GpuParameters` from a command-line option string.
    fn parse_gpu_options(s: &str) -> Result<GpuParameters, String> {
        from_key_values::<FixedGpuParameters>(s).map(|p| p.0)
    }

    fn parse_gpu_display_options(s: &str) -> Result<GpuDisplayParameters, String> {
        from_key_values::<GpuDisplayParameters>(s)
    }

    #[test]
    fn parse_gpu_options_mode() {
        use devices::virtio::gpu::GpuMode;

        let gpu_params = parse_gpu_options("backend=2d").unwrap();
        assert_eq!(gpu_params.mode, GpuMode::Mode2D);

        let gpu_params = parse_gpu_options("backend=2D").unwrap();
        assert_eq!(gpu_params.mode, GpuMode::Mode2D);

        #[cfg(feature = "virgl_renderer")]
        {
            let gpu_params = parse_gpu_options("backend=3d").unwrap();
            assert_eq!(gpu_params.mode, GpuMode::ModeVirglRenderer);

            let gpu_params = parse_gpu_options("backend=3D").unwrap();
            assert_eq!(gpu_params.mode, GpuMode::ModeVirglRenderer);

            let gpu_params = parse_gpu_options("backend=virglrenderer").unwrap();
            assert_eq!(gpu_params.mode, GpuMode::ModeVirglRenderer);
        }

        #[cfg(feature = "gfxstream")]
        {
            let gpu_params = parse_gpu_options("backend=gfxstream").unwrap();
            assert_eq!(gpu_params.mode, GpuMode::ModeGfxstream);
        }
    }

    #[test]
    fn parse_gpu_options_flags() {
        macro_rules! assert_default {
            ($p:ident.$a:ident) => {
                assert_eq!($p.$a, GpuParameters::default().$a)
            };
        }

        let gpu_params = parse_gpu_options("").unwrap();
        assert_default!(gpu_params.renderer_use_egl);
        assert_default!(gpu_params.renderer_use_gles);
        assert_default!(gpu_params.renderer_use_glx);
        assert_default!(gpu_params.renderer_use_surfaceless);
        assert_default!(gpu_params.use_vulkan);
        assert_default!(gpu_params.udmabuf);

        let gpu_params = parse_gpu_options("egl=false,gles=false").unwrap();
        assert_eq!(gpu_params.renderer_use_egl, false);
        assert_eq!(gpu_params.renderer_use_gles, false);
        assert_default!(gpu_params.renderer_use_glx);
        assert_default!(gpu_params.renderer_use_surfaceless);
        assert_default!(gpu_params.use_vulkan);
        assert_default!(gpu_params.udmabuf);

        let gpu_params = parse_gpu_options("surfaceless=false,glx").unwrap();
        assert_default!(gpu_params.renderer_use_egl);
        assert_default!(gpu_params.renderer_use_gles);
        assert_eq!(gpu_params.renderer_use_surfaceless, false);
        assert_eq!(gpu_params.renderer_use_glx, true);
        assert_default!(gpu_params.use_vulkan);
        assert_default!(gpu_params.udmabuf);

        let gpu_params = parse_gpu_options("vulkan,udmabuf").unwrap();
        assert_default!(gpu_params.renderer_use_egl);
        assert_default!(gpu_params.renderer_use_gles);
        assert_default!(gpu_params.renderer_use_glx);
        assert_default!(gpu_params.renderer_use_surfaceless);
        assert_eq!(gpu_params.use_vulkan, Some(true));
        assert_eq!(gpu_params.udmabuf, true);

        assert!(parse_gpu_options("egl=false,gles=true,foomatic").is_err());
    }

    #[cfg(feature = "gfxstream")]
    #[test]
    fn parse_gpu_options_gfxstream_with_wsi_specified() {
        {
            let gpu_params = parse_gpu_options("backend=gfxstream,wsi=vk").unwrap();
            assert!(matches!(gpu_params.wsi, Some(RutabagaWsi::Vulkan)));
        }
        {
            let gpu_params = parse_gpu_options("wsi=vk,backend=gfxstream").unwrap();
            assert!(matches!(gpu_params.wsi, Some(RutabagaWsi::Vulkan)));
        }
        {
            assert!(parse_gpu_options("backend=gfxstream,wsi=invalid_value").is_err());
        }
        {
            assert!(parse_gpu_options("wsi=invalid_value,backend=gfxstream").is_err());
        }
    }

    #[test]
    fn parse_gpu_options_default_vulkan_support() {
        let gpu_params = parse_gpu_options("backend=2d").unwrap();
        assert_eq!(gpu_params.use_vulkan, None);

        #[cfg(feature = "virgl_renderer")]
        {
            let gpu_params = parse_gpu_options("backend=virglrenderer").unwrap();
            assert_eq!(gpu_params.use_vulkan, None);
        }

        #[cfg(feature = "gfxstream")]
        {
            let gpu_params = parse_gpu_options("backend=gfxstream").unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(default_use_vulkan()));
        }
    }

    #[test]
    fn parse_gpu_options_with_vulkan_specified() {
        const BACKEND: &str = get_backend_name();
        {
            let gpu_params = parse_gpu_options("vulkan=true").unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(true));
        }
        {
            let gpu_params =
                parse_gpu_options(format!("backend={},vulkan=true", BACKEND).as_str()).unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(true));
        }
        {
            let gpu_params =
                parse_gpu_options(format!("vulkan=true,backend={}", BACKEND).as_str()).unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(true));
        }
        {
            let gpu_params = parse_gpu_options("vulkan=false").unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(false));
        }
        {
            let gpu_params =
                parse_gpu_options(format!("backend={},vulkan=false", BACKEND).as_str()).unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(false));
        }
        {
            let gpu_params =
                parse_gpu_options(format!("vulkan=false,backend={}", BACKEND).as_str()).unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(false));
        }
        {
            assert!(parse_gpu_options(
                format!("backend={},vulkan=invalid_value", BACKEND).as_str()
            )
            .is_err());
        }
        {
            assert!(parse_gpu_options(
                format!("vulkan=invalid_value,backend={}", BACKEND).as_str()
            )
            .is_err());
        }
    }

    #[cfg(feature = "gfxstream")]
    #[test]
    fn parse_gpu_options_gfxstream_with_guest_angle_specified() {
        assert_eq!(
            parse_gpu_options("backend=gfxstream")
                .unwrap()
                .gfxstream_use_guest_angle,
            None,
        );
        assert_eq!(
            parse_gpu_options("backend=gfxstream,angle=true")
                .unwrap()
                .gfxstream_use_guest_angle,
            Some(true),
        );
        assert_eq!(
            parse_gpu_options("angle=true,backend=gfxstream")
                .unwrap()
                .gfxstream_use_guest_angle,
            Some(true),
        );
        assert_eq!(
            parse_gpu_options("backend=gfxstream,angle=false")
                .unwrap()
                .gfxstream_use_guest_angle,
            Some(false),
        );
        assert_eq!(
            parse_gpu_options("angle=false,backend=gfxstream")
                .unwrap()
                .gfxstream_use_guest_angle,
            Some(false),
        );
        assert!(parse_gpu_options("backend=gfxstream,angle=invalid_value").is_err());
        assert!(parse_gpu_options("angle=invalid_value,backend=gfxstream").is_err());
    }

    #[test]
    fn parse_gpu_options_not_gfxstream_with_angle_specified() {
        assert!(parse_gpu_options("backend=2d,angle=true").is_err());
        assert!(parse_gpu_options("angle=true,backend=2d").is_err());

        #[cfg(feature = "virgl_renderer")]
        {
            assert!(parse_gpu_options("backend=virglrenderer,angle=true").is_err());
            assert!(parse_gpu_options("angle=true,backend=virglrenderer").is_err());
        }
    }

    #[cfg(feature = "gfxstream")]
    #[test]
    fn parse_gpu_options_gfxstream_with_gles31_specified() {
        assert_eq!(
            parse_gpu_options("backend=gfxstream")
                .unwrap()
                .gfxstream_support_gles31,
            None,
        );
        assert_eq!(
            parse_gpu_options("backend=gfxstream,gles31=true")
                .unwrap()
                .gfxstream_support_gles31,
            Some(true),
        );
        assert_eq!(
            parse_gpu_options("gles31=true,backend=gfxstream")
                .unwrap()
                .gfxstream_support_gles31,
            Some(true),
        );
        assert_eq!(
            parse_gpu_options("backend=gfxstream,gles31=false")
                .unwrap()
                .gfxstream_support_gles31,
            Some(false),
        );
        assert_eq!(
            parse_gpu_options("gles31=false,backend=gfxstream")
                .unwrap()
                .gfxstream_support_gles31,
            Some(false),
        );
        assert!(parse_gpu_options("backend=gfxstream,gles31=invalid_value").is_err());
        assert!(parse_gpu_options("gles31=invalid_value,backend=gfxstream").is_err());
    }

    #[test]
    fn parse_gpu_options_not_gfxstream_with_gles31_specified() {
        assert!(parse_gpu_options("backend=2d,gles31=true").is_err());
        assert!(parse_gpu_options("gles31=true,backend=2d").is_err());

        #[cfg(feature = "virgl_renderer")]
        {
            assert!(parse_gpu_options("backend=virglrenderer,gles31=true").is_err());
            assert!(parse_gpu_options("gles31=true,backend=virglrenderer").is_err());
        }
    }

    #[test]
    fn parse_gpu_options_context_types() {
        use rutabaga_gfx::RUTABAGA_CAPSET_CROSS_DOMAIN;
        use rutabaga_gfx::RUTABAGA_CAPSET_VIRGL;

        let gpu_params = parse_gpu_options("context-types=virgl:cross-domain").unwrap();
        assert_eq!(
            gpu_params.context_mask,
            (1 << RUTABAGA_CAPSET_VIRGL) | (1 << RUTABAGA_CAPSET_CROSS_DOMAIN)
        );
    }

    #[test]
    fn parse_gpu_options_cache() {
        let gpu_params = parse_gpu_options("cache-path=/path/to/cache,cache-size=16384").unwrap();
        assert_eq!(gpu_params.cache_path, Some("/path/to/cache".into()));
        assert_eq!(gpu_params.cache_size, Some("16384".into()));
    }

    #[test]
    fn parse_gpu_options_pci_bar() {
        let gpu_params = parse_gpu_options("pci-bar-size=0x100000").unwrap();
        assert_eq!(gpu_params.pci_bar_size, 0x100000);
    }

    #[test]
    fn parse_gpu_options_no_display_specified() {
        let display_params = parse_gpu_options("").unwrap().display_params;
        assert!(display_params.is_empty());
    }

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

    #[test]
    fn parse_gpu_options_display_size_incomplete() {
        assert!(parse_gpu_options("width=1280").is_err());
        assert!(parse_gpu_options("height=720").is_err());
    }

    #[test]
    fn parse_gpu_options_display_size_duplicated() {
        assert!(parse_gpu_options("width=1280,width=1280,height=720").is_err());
        assert!(parse_gpu_options("width=1280,height=720,height=720").is_err());
    }

    #[test]
    fn parse_gpu_display_options_mode() {
        let display_params = parse_gpu_display_options("mode=windowed[1280,720]").unwrap();
        assert!(matches!(
            display_params.mode,
            GpuDisplayMode::Windowed(_, _)
        ));

        #[cfg(windows)]
        {
            let display_params = parse_gpu_display_options("mode=borderless_full_screen").unwrap();
            assert!(matches!(
                display_params.mode,
                GpuDisplayMode::BorderlessFullScreen(_)
            ));
        }

        assert!(parse_gpu_display_options("mode=invalid_mode").is_err());
    }

    #[test]
    fn parse_gpu_display_options_mode_duplicated() {
        assert!(
            parse_gpu_display_options("mode=windowed[1280,720],mode=windowed[1280,720]").is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn parse_gpu_display_options_borderless_full_screen_should_not_be_specified_with_size() {
        assert!(parse_gpu_display_options("mode=borderless_full_screen[1280,720]").is_err());
    }

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

    #[test]
    fn parse_gpu_display_options_hidden() {
        let display_params = parse_gpu_display_options("hidden").unwrap();
        assert!(display_params.hidden);

        let display_params = parse_gpu_display_options("hidden=true").unwrap();
        assert!(display_params.hidden);

        let display_params = parse_gpu_display_options("hidden=false").unwrap();
        assert!(!display_params.hidden);
    }

    #[test]
    fn parse_gpu_display_options_hidden_duplicated() {
        assert!(parse_gpu_display_options("hidden,hidden").is_err());
    }

    #[test]
    fn parse_gpu_display_options_refresh_rate() {
        const REFRESH_RATE: u32 = 30;

        let display_params =
            parse_gpu_display_options(format!("refresh-rate={}", REFRESH_RATE).as_str()).unwrap();
        assert_eq!(display_params.refresh_rate, REFRESH_RATE);
    }

    #[test]
    fn parse_gpu_display_options_refresh_rate_duplicated() {
        assert!(parse_gpu_display_options("refresh-rate=30,refresh-rate=60").is_err());
    }

    #[test]
    fn parse_gpu_display_options_dpi() {
        const HORIZONTAL_DPI: u32 = 160;
        const VERTICAL_DPI: u32 = 25;

        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--gpu-display",
                format!("dpi=[{},{}]", HORIZONTAL_DPI, VERTICAL_DPI).as_str(),
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let gpu_params = config.gpu_parameters.unwrap();

        assert_eq!(gpu_params.display_params.len(), 1);
        assert_eq!(
            gpu_params.display_params[0].horizontal_dpi(),
            HORIZONTAL_DPI
        );
        assert_eq!(gpu_params.display_params[0].vertical_dpi(), VERTICAL_DPI);
    }

    #[test]
    fn parse_gpu_display_options_default_dpi() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--gpu-display", "mode=windowed[800,600]", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let gpu_params = config.gpu_parameters.unwrap();

        assert_eq!(gpu_params.display_params.len(), 1);
        assert_eq!(gpu_params.display_params[0].horizontal_dpi(), DEFAULT_DPI);
        assert_eq!(gpu_params.display_params[0].vertical_dpi(), DEFAULT_DPI);
    }

    #[test]
    fn parse_gpu_display_options_dpi_compat() {
        const HORIZONTAL_DPI: u32 = 160;
        const VERTICAL_DPI: u32 = 25;

        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--gpu-display",
                format!(
                    "horizontal-dpi={},vertical-dpi={}",
                    HORIZONTAL_DPI, VERTICAL_DPI
                )
                .as_str(),
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let gpu_params = config.gpu_parameters.unwrap();

        assert_eq!(gpu_params.display_params.len(), 1);
        assert_eq!(
            gpu_params.display_params[0].horizontal_dpi(),
            HORIZONTAL_DPI
        );
        assert_eq!(gpu_params.display_params[0].vertical_dpi(), VERTICAL_DPI);
    }

    #[test]
    fn parse_gpu_display_options_dpi_duplicated() {
        assert!(crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--gpu-display",
                "horizontal-dpi=160,horizontal-dpi=320",
                "/dev/null",
            ],
        )
        .is_err());

        assert!(crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--gpu-display",
                "vertical-dpi=25,vertical-dpi=50",
                "/dev/null",
            ],
        )
        .is_err());

        assert!(crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--gpu-display",
                "dpi=[160,320],horizontal-dpi=160,vertical-dpi=25",
                "/dev/null",
            ],
        )
        .is_err());
    }

    #[test]
    fn parse_gpu_options_single_display() {
        {
            let gpu_params = parse_gpu_options("displays=[[mode=windowed[800,600]]]").unwrap();
            assert_eq!(gpu_params.display_params.len(), 1);
            assert_eq!(
                gpu_params.display_params[0].mode,
                GpuDisplayMode::Windowed(800, 600)
            );
        }

        #[cfg(windows)]
        {
            let gpu_params = parse_gpu_options("displays=[[mode=borderless_full_screen]]").unwrap();
            assert_eq!(gpu_params.display_params.len(), 1);
            assert!(matches!(
                gpu_params.display_params[0].mode,
                GpuDisplayMode::BorderlessFullScreen(_)
            ));
        }
    }

    #[test]
    fn parse_gpu_options_multi_display() {
        {
            let gpu_params =
                parse_gpu_options("displays=[[mode=windowed[500,600]],[mode=windowed[700,800]]]")
                    .unwrap();
            assert_eq!(gpu_params.display_params.len(), 2);
            assert_eq!(
                gpu_params.display_params[0].mode,
                GpuDisplayMode::Windowed(500, 600)
            );
            assert_eq!(
                gpu_params.display_params[1].mode,
                GpuDisplayMode::Windowed(700, 800)
            );
        }

        #[cfg(windows)]
        {
            let gpu_params = parse_gpu_options(
                "displays=[[mode=windowed[800,600]],[mode=borderless_full_screen]]",
            )
            .unwrap();
            assert_eq!(gpu_params.display_params.len(), 2);
            assert_eq!(
                gpu_params.display_params[0].mode,
                GpuDisplayMode::Windowed(800, 600)
            );
            assert!(matches!(
                gpu_params.display_params[1].mode,
                GpuDisplayMode::BorderlessFullScreen(_)
            ));
        }
    }

    #[test]
    fn parse_gpu_options_single_display_compat() {
        const BACKEND: &str = get_backend_name();

        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--gpu",
                format!("backend={},width=500,height=600", BACKEND,).as_str(),
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let gpu_params = config.gpu_parameters.unwrap();

        assert_eq!(gpu_params.display_params.len(), 1);
        assert_eq!(
            gpu_params.display_params[0].mode,
            GpuDisplayMode::Windowed(500, 600)
        );

        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--gpu",
                format!("backend={}", BACKEND,).as_str(),
                "--gpu-display",
                "mode=windowed[700,800]",
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        let gpu_params = config.gpu_parameters.unwrap();

        assert_eq!(gpu_params.display_params.len(), 1);
        assert_eq!(
            gpu_params.display_params[0].mode,
            GpuDisplayMode::Windowed(700, 800)
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_gpu_options_and_gpu_display_options_multi_display_supported_on_unix() {
        {
            let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &[
                    "--gpu",
                    format!(
                        "backend={},width=500,height=600,displays=[[mode=windowed[700,800]]]",
                        get_backend_name()
                    )
                    .as_str(),
                    "--gpu-display",
                    "mode=windowed[900,1000]",
                    "/dev/null",
                ],
            )
            .unwrap()
            .try_into()
            .unwrap();

            let gpu_params = config.gpu_parameters.unwrap();

            assert_eq!(gpu_params.display_params.len(), 3);
            assert_eq!(
                gpu_params.display_params[0].mode,
                GpuDisplayMode::Windowed(700, 800)
            );
            assert_eq!(
                gpu_params.display_params[1].mode,
                GpuDisplayMode::Windowed(500, 600)
            );
            assert_eq!(
                gpu_params.display_params[2].mode,
                GpuDisplayMode::Windowed(900, 1000)
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn parse_gpu_options_and_gpu_display_options_multi_display_unsupported_on_windows() {
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

        let command = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--gpu",
                "displays=[[mode=windowed[1280,720]]]",
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
                "displays=[[mode=windowed[500,600]],[mode=windowed[700,800]]]",
                "/dev/null",
            ],
        )
        .unwrap();
        assert!(Config::try_from(command).is_err());
    }

    #[test]
    fn parse_gpu_options_cache_size() {
        {
            let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &[
                    "--gpu",
                    "vulkan=false,cache-path=/some/path,cache-size=50M",
                    "/dev/null",
                ],
            )
            .unwrap()
            .try_into()
            .unwrap();

            let gpu_params = config.gpu_parameters.unwrap();
            assert_eq!(gpu_params.cache_path, Some("/some/path".into()));
            assert_eq!(gpu_params.cache_size, Some("50M".into()));
        }
    }
}
