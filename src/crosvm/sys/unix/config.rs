// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

#[cfg(feature = "gpu")]
use devices::virtio::GpuDisplayMode;
#[cfg(feature = "gpu")]
use devices::virtio::GpuDisplayParameters;
#[cfg(feature = "gfxstream")]
use devices::virtio::GpuMode;
#[cfg(feature = "gpu")]
use devices::virtio::GpuParameters;
use devices::IommuDevType;
use devices::PciAddress;
use devices::SerialParameters;
use serde::Deserialize;
use serde::Serialize;

use crate::crosvm::config::invalid_value_err;
use crate::crosvm::config::Config;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum HypervisorKind {
    Kvm,
}

impl FromStr for HypervisorKind {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "kvm" => Ok(HypervisorKind::Kvm),
            _ => Err("invalid hypervisor backend"),
        }
    }
}

#[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
pub fn parse_gpu_render_server_options(
    s: &str,
) -> Result<crate::crosvm::sys::GpuRenderServerParameters, String> {
    use crate::crosvm::sys::GpuRenderServerParameters;

    let mut path: Option<PathBuf> = None;
    let mut cache_path = None;
    let mut cache_size = None;

    let opts = s
        .split(',')
        .map(|frag| frag.split('='))
        .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

    for (k, v) in opts {
        match k {
            "path" => path = Some(PathBuf::from_str(v).map_err(|e| invalid_value_err(v, e))?),
            "cache-path" => cache_path = Some(v.to_string()),
            "cache-size" => cache_size = Some(v.to_string()),
            "" => {}
            _ => {
                return Err(format!("invalid gpu-render-server parameter {}", k));
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
        Err(invalid_value_err(
            s,
            "gpu-render-server must include 'path'",
        ))
    }
}

#[cfg(feature = "audio")]
pub fn parse_ac97_options(
    #[allow(unused_variables)] ac97_params: &mut devices::Ac97Parameters,
    key: &str,
    #[allow(unused_variables)] value: &str,
) -> Result<(), String> {
    match key {
        #[cfg(feature = "audio_cras")]
        "client_type" => ac97_params
            .set_client_type(value)
            .map_err(|e| crate::crosvm::config::invalid_value_err(value, e)),
        #[cfg(feature = "audio_cras")]
        "socket_type" => ac97_params
            .set_socket_type(value)
            .map_err(|e| crate::crosvm::config::invalid_value_err(value, e)),
        _ => Err(format!("unknown ac97 parameter {}", key)),
    }
}

#[cfg(feature = "gfxstream")]
pub fn use_vulkan() -> bool {
    true
}

// Doesn't do anything on unix.
pub fn check_serial_params(_serial_params: &SerialParameters) -> Result<(), String> {
    Ok(())
}

pub fn validate_config(cfg: &mut Config) -> std::result::Result<(), String> {
    if cfg.host_ip.is_some() || cfg.netmask.is_some() || cfg.mac_address.is_some() {
        if cfg.host_ip.is_none() {
            return Err("`host-ip` missing from network config".to_string());
        }
        if cfg.netmask.is_none() {
            return Err("`netmask` missing from network config".to_string());
        }
        if cfg.mac_address.is_none() {
            return Err("`mac` missing from network config".to_string());
        }
    }

    Ok(())
}

#[cfg(feature = "gpu")]
pub fn parse_gpu_options(s: &str) -> Result<GpuParameters, String> {
    use crate::crosvm::config::from_key_values;
    let mut gpu_params: GpuParameters = from_key_values(s)?;

    if let (Some(width), Some(height)) = (
        gpu_params.__width_compat.take(),
        gpu_params.__height_compat.take(),
    ) {
        let display_param =
            GpuDisplayParameters::default_with_mode(GpuDisplayMode::Windowed(width, height));
        gpu_params.display_params.push(display_param);
    }

    #[cfg(feature = "gfxstream")]
    {
        if gpu_params.use_vulkan.is_none() && gpu_params.mode == GpuMode::ModeGfxstream {
            gpu_params.use_vulkan = Some(use_vulkan());
        }

        if gpu_params.gfxstream_use_guest_angle.is_some() {
            match gpu_params.mode {
                GpuMode::ModeGfxstream => {}
                _ => {
                    return Err(
                        "gpu parameter angle is only supported for gfxstream backend".to_string(),
                    );
                }
            }
        }
    }

    Ok(gpu_params)
}

#[cfg(feature = "gpu")]
pub(crate) fn validate_gpu_config(cfg: &mut Config) -> Result<(), String> {
    if let Some(gpu_parameters) = cfg.gpu_parameters.as_mut() {
        if !gpu_parameters.pci_bar_size.is_power_of_two() {
            return Err(format!(
                "gpu parameter `pci-bar-size` must be a power of two but is {}",
                gpu_parameters.pci_bar_size
            ));
        }
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

/// Vfio device type, recognized based on command line option.
#[derive(Eq, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum VfioType {
    Pci,
    Platform,
}

impl FromStr for VfioType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use VfioType::*;
        match s {
            "vfio" => Ok(Pci),
            "vfio-platform" => Ok(Platform),
            _ => Err("invalid vfio device type, must be 'vfio|vfio-platform'"),
        }
    }
}

#[derive(Serialize, Deserialize)]
/// VFIO device structure for creating a new instance based on command line options.
pub struct VfioCommand {
    pub vfio_path: PathBuf,
    pub dev_type: VfioType,
    pub params: BTreeMap<String, String>,
}

pub fn parse_vfio(s: &str) -> Result<VfioCommand, String> {
    VfioCommand::new(VfioType::Pci, s)
}

pub fn parse_vfio_platform(s: &str) -> Result<VfioCommand, String> {
    VfioCommand::new(VfioType::Platform, s)
}

impl VfioCommand {
    pub fn new(dev_type: VfioType, path: &str) -> Result<VfioCommand, String> {
        let mut param = path.split(',');
        let vfio_path = PathBuf::from(
            param
                .next()
                .ok_or_else(|| invalid_value_err(path, "missing vfio path"))?,
        );

        if !vfio_path.exists() {
            return Err(invalid_value_err(path, "the vfio path does not exist"));
        }
        if !vfio_path.is_dir() {
            return Err(invalid_value_err(path, "the vfio path should be directory"));
        }

        let mut params = BTreeMap::new();
        for p in param {
            let mut kv = p.splitn(2, '=');
            if let (Some(kind), Some(value)) = (kv.next(), kv.next()) {
                Self::validate_params(kind, value)?;
                params.insert(kind.to_owned(), value.to_owned());
            };
        }
        Ok(VfioCommand {
            vfio_path,
            params,
            dev_type,
        })
    }

    fn validate_params(kind: &str, value: &str) -> Result<(), String> {
        match kind {
            "guest-address" => {
                if value.eq_ignore_ascii_case("auto") || PciAddress::from_str(value).is_ok() {
                    Ok(())
                } else {
                    Err(invalid_value_err(
                        format!("{}={}", kind, value),
                        "option must be `guest-address=auto|<BUS:DEVICE.FUNCTION>`",
                    ))
                }
            }
            "iommu" => {
                if IommuDevType::from_str(value).is_ok() {
                    Ok(())
                } else {
                    Err(invalid_value_err(
                        format!("{}={}", kind, value),
                        "option must be `iommu=viommu|coiommu|off`",
                    ))
                }
            }
            #[cfg(feature = "direct")]
            "intel-lpss" => {
                if value.parse::<bool>().is_ok() {
                    Ok(())
                } else {
                    Err(invalid_value_err(
                        format!("{}={}", kind, value),
                        "option must be `intel-lpss=true|false`",
                    ))
                }
            }
            _ => Err(invalid_value_err(
                format!("{}={}", kind, value),
                "option must be `guest-address=<val>` and/or `iommu=<val>`",
            )),
        }
    }

    pub fn get_type(&self) -> VfioType {
        self.dev_type
    }

    pub fn guest_address(&self) -> Option<PciAddress> {
        self.params
            .get("guest-address")
            .and_then(|addr| PciAddress::from_str(addr).ok())
    }

    pub fn iommu_dev_type(&self) -> IommuDevType {
        if let Some(iommu) = self.params.get("iommu") {
            if let Ok(v) = IommuDevType::from_str(iommu) {
                return v;
            }
        }
        IommuDevType::NoIommu
    }

    #[cfg(feature = "direct")]
    pub fn is_intel_lpss(&self) -> bool {
        if let Some(lpss) = self.params.get("intel-lpss") {
            return lpss.parse::<bool>().unwrap_or(false);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use argh::FromArgs;

    use super::*;
    use crate::crosvm::config::from_key_values;
    #[cfg(feature = "audio_cras")]
    use crate::crosvm::config::parse_ac97_options;
    use crate::crosvm::config::BindMount;
    use crate::crosvm::config::DEFAULT_TOUCH_DEVICE_HEIGHT;
    use crate::crosvm::config::DEFAULT_TOUCH_DEVICE_WIDTH;

    #[cfg(feature = "audio_cras")]
    #[test]
    fn parse_ac97_socket_type() {
        parse_ac97_options("socket_type=unified").expect("parse should have succeded");
        parse_ac97_options("socket_type=legacy").expect("parse should have succeded");
    }

    #[test]
    fn parse_coiommu_options() {
        use std::time::Duration;

        use devices::CoIommuParameters;
        use devices::CoIommuUnpinPolicy;

        // unpin_policy
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_policy=off").unwrap();
        assert_eq!(
            coiommu_params,
            CoIommuParameters {
                unpin_policy: CoIommuUnpinPolicy::Off,
                ..Default::default()
            }
        );
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_policy=lru").unwrap();
        assert_eq!(
            coiommu_params,
            CoIommuParameters {
                unpin_policy: CoIommuUnpinPolicy::Lru,
                ..Default::default()
            }
        );
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_policy=foo");
        assert!(coiommu_params.is_err());

        // unpin_interval
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_interval=42").unwrap();
        assert_eq!(
            coiommu_params,
            CoIommuParameters {
                unpin_interval: Duration::from_secs(42),
                ..Default::default()
            }
        );
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_interval=foo");
        assert!(coiommu_params.is_err());

        // unpin_limit
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_limit=256").unwrap();
        assert_eq!(
            coiommu_params,
            CoIommuParameters {
                unpin_limit: Some(256),
                ..Default::default()
            }
        );
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_limit=0");
        assert!(coiommu_params.is_err());
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_limit=foo");
        assert!(coiommu_params.is_err());

        // unpin_gen_threshold
        let coiommu_params =
            from_key_values::<CoIommuParameters>("unpin_gen_threshold=32").unwrap();
        assert_eq!(
            coiommu_params,
            CoIommuParameters {
                unpin_gen_threshold: 32,
                ..Default::default()
            }
        );
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_gen_threshold=foo");
        assert!(coiommu_params.is_err());

        // All together
        let coiommu_params = from_key_values::<CoIommuParameters>(
            "unpin_policy=lru,unpin_interval=90,unpin_limit=8,unpin_gen_threshold=64",
        )
        .unwrap();
        assert_eq!(
            coiommu_params,
            CoIommuParameters {
                unpin_policy: CoIommuUnpinPolicy::Lru,
                unpin_interval: Duration::from_secs(90),
                unpin_limit: Some(8),
                unpin_gen_threshold: 64,
            }
        );

        // invalid parameter
        let coiommu_params = from_key_values::<CoIommuParameters>("unpin_invalid_param=0");
        assert!(coiommu_params.is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_mode() {
        use devices::virtio::gpu::GpuMode;

        let gpu_params: GpuParameters = from_key_values("backend=2d").unwrap();
        assert_eq!(gpu_params.mode, GpuMode::Mode2D);

        let gpu_params: GpuParameters = from_key_values("backend=2D").unwrap();
        assert_eq!(gpu_params.mode, GpuMode::Mode2D);

        let gpu_params: GpuParameters = from_key_values("backend=3d").unwrap();
        assert_eq!(gpu_params.mode, GpuMode::ModeVirglRenderer);

        let gpu_params: GpuParameters = from_key_values("backend=3D").unwrap();
        assert_eq!(gpu_params.mode, GpuMode::ModeVirglRenderer);

        let gpu_params: GpuParameters = from_key_values("backend=virglrenderer").unwrap();
        assert_eq!(gpu_params.mode, GpuMode::ModeVirglRenderer);

        let gpu_params: GpuParameters = from_key_values("backend=gfxstream").unwrap();
        assert_eq!(gpu_params.mode, GpuMode::ModeGfxstream);
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_flags() {
        macro_rules! assert_default {
            ($p:ident.$a:ident) => {
                assert_eq!($p.$a, GpuParameters::default().$a)
            };
        }

        let gpu_params: GpuParameters = from_key_values("").unwrap();
        assert_default!(gpu_params.renderer_use_egl);
        assert_default!(gpu_params.renderer_use_gles);
        assert_default!(gpu_params.renderer_use_glx);
        assert_default!(gpu_params.renderer_use_surfaceless);
        assert_default!(gpu_params.use_vulkan);
        assert_default!(gpu_params.udmabuf);

        let gpu_params: GpuParameters = from_key_values("egl=false,gles=false").unwrap();
        assert_eq!(gpu_params.renderer_use_egl, false);
        assert_eq!(gpu_params.renderer_use_gles, false);
        assert_default!(gpu_params.renderer_use_glx);
        assert_default!(gpu_params.renderer_use_surfaceless);
        assert_default!(gpu_params.use_vulkan);
        assert_default!(gpu_params.udmabuf);

        let gpu_params: GpuParameters = from_key_values("surfaceless=false,glx").unwrap();
        assert_default!(gpu_params.renderer_use_egl);
        assert_default!(gpu_params.renderer_use_gles);
        assert_eq!(gpu_params.renderer_use_surfaceless, false);
        assert_eq!(gpu_params.renderer_use_glx, true);
        assert_default!(gpu_params.use_vulkan);
        assert_default!(gpu_params.udmabuf);

        let gpu_params: GpuParameters = from_key_values("vulkan,udmabuf").unwrap();
        assert_default!(gpu_params.renderer_use_egl);
        assert_default!(gpu_params.renderer_use_gles);
        assert_default!(gpu_params.renderer_use_glx);
        assert_default!(gpu_params.renderer_use_surfaceless);
        assert_eq!(gpu_params.use_vulkan, Some(true));
        assert_eq!(gpu_params.udmabuf, true);

        assert!(from_key_values::<GpuParameters>("egl=false,gles=true,foomatic").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_default_vulkan_support() {
        {
            let gpu_params: GpuParameters = from_key_values("backend=virglrenderer").unwrap();
            assert_eq!(gpu_params.use_vulkan, None);
        }

        #[cfg(feature = "gfxstream")]
        {
            let gpu_params: GpuParameters = from_key_values("backend=gfxstream").unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(true));
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_with_vulkan_specified() {
        {
            let gpu_params: GpuParameters = from_key_values("vulkan=true").unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(true));
        }
        {
            let gpu_params: GpuParameters =
                parse_gpu_options("backend=virglrenderer,vulkan=true").unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(true));
        }
        {
            let gpu_params: GpuParameters =
                parse_gpu_options("vulkan=true,backend=virglrenderer").unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(true));
        }
        {
            let gpu_params: GpuParameters = parse_gpu_options("vulkan=false").unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(false));
        }
        {
            let gpu_params: GpuParameters =
                parse_gpu_options("backend=virglrenderer,vulkan=false").unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(false));
        }
        {
            let gpu_params: GpuParameters =
                parse_gpu_options("vulkan=false,backend=virglrenderer").unwrap();
            assert_eq!(gpu_params.use_vulkan, Some(false));
        }
        {
            assert!(parse_gpu_options("backend=virglrenderer,vulkan=invalid_value").is_err());
        }
        {
            assert!(parse_gpu_options("vulkan=invalid_value,backend=virglrenderer").is_err());
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_gfxstream_with_wsi_specified() {
        use rutabaga_gfx::RutabagaWsi;

        let gpu_params: GpuParameters = parse_gpu_options("backend=virglrenderer,wsi=vk").unwrap();
        assert!(matches!(gpu_params.wsi, Some(RutabagaWsi::Vulkan)));

        let gpu_params: GpuParameters =
            parse_gpu_options("backend=virglrenderer,wsi=vulkan").unwrap();
        assert!(matches!(gpu_params.wsi, Some(RutabagaWsi::Vulkan)));

        let gpu_params: GpuParameters = parse_gpu_options("wsi=vk,backend=virglrenderer").unwrap();
        assert!(matches!(gpu_params.wsi, Some(RutabagaWsi::Vulkan)));

        assert!(parse_gpu_options("backend=virglrenderer,wsi=invalid_value").is_err());

        assert!(parse_gpu_options("wsi=invalid_value,backend=virglrenderer").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_context_types() {
        use rutabaga_gfx::RUTABAGA_CAPSET_CROSS_DOMAIN;
        use rutabaga_gfx::RUTABAGA_CAPSET_VIRGL;

        let gpu_params: GpuParameters =
            from_key_values("context-types=virgl:cross-domain").unwrap();
        assert_eq!(
            gpu_params.context_mask,
            (1 << RUTABAGA_CAPSET_VIRGL) | (1 << RUTABAGA_CAPSET_CROSS_DOMAIN)
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_cache() {
        let gpu_params: GpuParameters =
            from_key_values("cache-path=/path/to/cache,cache-size=16384").unwrap();
        assert_eq!(gpu_params.cache_path, Some("/path/to/cache".into()));
        assert_eq!(gpu_params.cache_size, Some("16384".into()));
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_pci_bar() {
        let gpu_params: GpuParameters = from_key_values("pci-bar-size=0x100000").unwrap();
        assert_eq!(gpu_params.pci_bar_size, 0x100000);
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_valid() {
        // Default values.
        let gpu_params: GpuDisplayParameters = from_key_values("").unwrap();
        assert_eq!(gpu_params, GpuDisplayParameters::default());

        let gpu_params: GpuDisplayParameters = from_key_values("mode=windowed[800,600]").unwrap();
        assert_eq!(
            gpu_params,
            GpuDisplayParameters {
                mode: GpuDisplayMode::Windowed(800, 600),
                ..Default::default()
            }
        );

        assert!(from_key_values::<GpuDisplayParameters>("mode=invalid").is_err());

        let gpu_params: GpuDisplayParameters = from_key_values("hidden,refresh-rate=100").unwrap();
        assert_eq!(
            gpu_params,
            GpuDisplayParameters {
                hidden: true,
                refresh_rate: 100,
                ..Default::default()
            }
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_and_gpu_display_options_valid() {
        {
            let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &[
                    "--gpu",
                    "2D,width=500,height=600",
                    "--gpu-display",
                    "mode=windowed[700,800]",
                    "/dev/null",
                ],
            )
            .unwrap()
            .try_into()
            .unwrap();

            let gpu_params = config.gpu_parameters.unwrap();

            assert_eq!(gpu_params.display_params.len(), 2);
            assert_eq!(
                gpu_params.display_params[0].get_virtual_display_size(),
                (500, 600),
            );
            assert_eq!(
                gpu_params.display_params[1].get_virtual_display_size(),
                (700, 800),
            );
        }
        {
            let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &[
                    "--gpu",
                    "2D",
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
                gpu_params.display_params[0].get_virtual_display_size(),
                (700, 800),
            );
        }
    }

    #[cfg(feature = "gpu")]
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

    #[test]
    fn parse_plugin_mount_valid() {
        let opt: BindMount = "/dev/null:/dev/zero:true".parse().unwrap();

        assert_eq!(opt.src, PathBuf::from("/dev/null"));
        assert_eq!(opt.dst, PathBuf::from("/dev/zero"));
        assert!(opt.writable);
    }

    #[test]
    fn parse_plugin_mount_valid_shorthand() {
        let opt: BindMount = "/dev/null".parse().unwrap();
        assert_eq!(opt.dst, PathBuf::from("/dev/null"));
        assert!(!opt.writable);

        let opt: BindMount = "/dev/null:/dev/zero".parse().unwrap();
        assert_eq!(opt.dst, PathBuf::from("/dev/zero"));
        assert!(!opt.writable);

        let opt: BindMount = "/dev/null::true".parse().unwrap();
        assert_eq!(opt.dst, PathBuf::from("/dev/null"));
        assert!(opt.writable);
    }

    #[test]
    fn single_touch_spec_and_track_pad_spec_default_size() {
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--single-touch",
                "/dev/single-touch-test",
                "--trackpad",
                "/dev/single-touch-test",
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

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

        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--single-touch",
                "/dev/single-touch-test",
                "--gpu",
                &format!("width={},height={}", width, height),
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.virtio_single_touch.first().unwrap().get_size(),
            (width, height)
        );
    }

    #[test]
    fn single_touch_spec_and_track_pad_spec_with_size() {
        let width = 12345u32;
        let height = 54321u32;
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--single-touch",
                &format!("/dev/single-touch-test:{}:{}", width, height),
                "--trackpad",
                &format!("/dev/single-touch-test:{}:{}", width, height),
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

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
        let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &[
                "--single-touch",
                &format!("/dev/single-touch-test:{}:{}", touch_width, touch_height),
                "--gpu",
                &format!("width={},height={}", display_width, display_height),
                "/dev/null",
            ],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.virtio_single_touch.first().unwrap().get_size(),
            (touch_width, touch_height)
        );
    }

    #[test]
    fn virtio_switches() {
        let mut config: Config = crate::crosvm::cmdline::RunCommand::from_args(
            &[],
            &["--switches", "/dev/switches-test", "/dev/null"],
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(
            config.virtio_switches.pop().unwrap(),
            PathBuf::from("/dev/switches-test")
        );
    }
}
