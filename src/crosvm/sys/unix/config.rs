// Copyright 2022 The Chromium OS Authors. All rights reserved.,
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{collections::BTreeMap, path::PathBuf, str::FromStr, time::Duration};

use devices::{IommuDevType, PciAddress, SerialParameters};
use serde::{Deserialize, Serialize};

#[cfg(feature = "gpu")]
use devices::virtio::{
    GpuDisplayParameters, GpuParameters, DEFAULT_DISPLAY_HEIGHT, DEFAULT_DISPLAY_WIDTH,
};

use crate::crosvm::config::{invalid_value_err, Config};
#[cfg(feature = "gpu")]
use crate::crosvm::{argument, argument::parse_hex_or_decimal};

#[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
pub fn parse_gpu_render_server_options(
    s: &str,
) -> Result<crate::crosvm::sys::GpuRenderServerParameters, String> {
    use std::{path::PathBuf, str::FromStr};

    use crate::crosvm::{config::invalid_value_err, sys::GpuRenderServerParameters};

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
    ac97_params: &mut devices::Ac97Parameters,
    key: &str,
    #[allow(unused_variables)] value: &str,
) -> Result<(), String> {
    use std::{path::PathBuf, str::FromStr};

    match key {
        #[cfg(feature = "audio_cras")]
        "client_type" => {
            ac97_params
                .set_client_type(value)
                .map_err(|e| crate::crosvm::config::invalid_value_err(value, e))?;
        }
        #[cfg(feature = "audio_cras")]
        "socket_type" => {
            ac97_params
                .set_socket_type(value)
                .map_err(|e| crate::crosvm::config::invalid_value_err(value, e))?;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        "server" => {
            ac97_params.vios_server_path = Some(
                PathBuf::from_str(value)
                    .map_err(|e| crate::crosvm::config::invalid_value_err(value, e))?,
            );
        }
        _ => {
            return Err(format!("unknown ac97 parameter {}", key));
        }
    };
    Ok(())
}

#[cfg(feature = "audio")]
pub fn check_ac97_backend(
    #[allow(unused_variables)] ac97_params: &devices::Ac97Parameters,
) -> Result<(), String> {
    // server is required for and exclusive to vios backend
    #[cfg(target_os = "android")]
    match ac97_params.backend {
        devices::Ac97Backend::VIOS => {
            if ac97_params.vios_server_path.is_none() {
                return Err(String::from("server argument is required for VIOS backend"));
            }
        }
        _ => {
            if ac97_params.vios_server_path.is_some() {
                return Err(String::from(
                    "server argument is exclusive to the VIOS backend",
                ));
            }
        }
    }

    Ok(())
}

pub fn parse_coiommu_params(value: &str) -> Result<devices::CoIommuParameters, String> {
    let mut params: devices::CoIommuParameters = Default::default();

    let opts = value
        .split(',')
        .map(|frag| frag.splitn(2, '='))
        .map(|mut kv| (kv.next().unwrap_or(""), kv.next().unwrap_or("")));

    for (k, v) in opts {
        match k {
            "unpin_policy" => {
                params.unpin_policy = v
                    .parse::<devices::CoIommuUnpinPolicy>()
                    .map_err(|e| format!("{}", e))?
            }
            "unpin_interval" => {
                params.unpin_interval =
                    Duration::from_secs(v.parse::<u64>().map_err(|e| format!("{}", e))?)
            }
            "unpin_limit" => {
                let limit = v.parse::<u64>().map_err(|e| format!("{}", e))?;

                if limit == 0 {
                    return Err(String::from("Please use non-zero unpin_limit value"));
                }

                params.unpin_limit = Some(limit)
            }
            "unpin_gen_threshold" => {
                params.unpin_gen_threshold = v
                    .parse::<u64>()
                    .map_err(|e| format!("unknown argument: {}", e))?
            }
            _ => {
                return Err(format!("coiommu parameter {}", k));
            }
        }
    }
    Ok(params)
}

#[cfg(feature = "gpu")]
pub fn is_gpu_backend_deprecated(_backend: &str) -> bool {
    false
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
    crate::crosvm::check_opt_path!(cfg.vhost_vsock_device);
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
#[derive(Default)]
struct GpuDisplayParametersBuilder {
    width: Option<u32>,
    height: Option<u32>,
    args: Vec<String>,
}

#[cfg(feature = "gpu")]
impl GpuDisplayParametersBuilder {
    fn parse(&mut self, arg: &str) -> argument::Result<()> {
        let mut kv = arg.split('=');
        let k = kv.next().unwrap_or("");
        let v = kv.next().unwrap_or("");
        match k {
            "width" => {
                let width = v
                    .parse::<u32>()
                    .map_err(|_| argument::Error::InvalidValue {
                        value: v.to_string(),
                        expected: String::from("gpu parameter 'width' must be a valid integer"),
                    })?;
                self.width = Some(width);
            }
            "height" => {
                let height = v
                    .parse::<u32>()
                    .map_err(|_| argument::Error::InvalidValue {
                        value: v.to_string(),
                        expected: String::from("gpu parameter 'height' must be a valid integer"),
                    })?;
                self.height = Some(height);
            }
            _ => {
                return Err(argument::Error::UnknownArgument(format!(
                    "gpu-display parameter {}",
                    k
                )))
            }
        }
        self.args.push(arg.to_string());
        Ok(())
    }

    fn build(&self) -> Result<Option<GpuDisplayParameters>, String> {
        match (self.width, self.height) {
            (None, None) => Ok(None),
            (None, Some(_)) | (Some(_), None) => {
                let mut value = self
                    .args
                    .clone()
                    .into_iter()
                    .fold(String::new(), |args_so_far, arg| args_so_far + &arg + ",");
                value.pop();
                return Err(invalid_value_err(
                    value,
                    "gpu must include both 'width' and 'height' if either is supplied",
                ));
            }
            (Some(width), Some(height)) => Ok(Some(GpuDisplayParameters { width, height })),
        }
    }
}

#[cfg(feature = "gpu")]
pub fn parse_gpu_options(s: &str) -> Result<GpuParameters, String> {
    use devices::virtio::GpuMode;
    use rutabaga_gfx::RutabagaWsi;

    use crate::crosvm::sys::config::is_gpu_backend_deprecated;

    #[cfg(feature = "gfxstream")]
    let mut vulkan_specified = false;
    #[cfg(feature = "gfxstream")]
    let mut syncfd_specified = false;
    #[cfg(feature = "gfxstream")]
    let mut angle_specified = false;

    let mut display_param_builder: GpuDisplayParametersBuilder = Default::default();
    let mut gpu_params = GpuParameters::default();

    for frag in s.split(',') {
        let mut rest: Option<&str> = None;
        let mut kv = frag.split('=');
        let k = kv.next().unwrap_or("");
        let v = kv.next().unwrap_or("");
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
                    if is_gpu_backend_deprecated(v) {
                        return Err(invalid_value_err(
                            v,
                            "this backend type is deprecated, please use gfxstream.",
                        ));
                    } else {
                        gpu_params.mode = GpuMode::Mode2D;
                    }
                }
                "3d" | "3D" | "virglrenderer" => {
                    if is_gpu_backend_deprecated(v) {
                        return Err(invalid_value_err(
                            v,
                            "this backend type is deprecated, please use gfxstream.",
                        ));
                    } else {
                        gpu_params.mode = GpuMode::ModeVirglRenderer;
                    }
                }
                #[cfg(feature = "gfxstream")]
                "gfxstream" => {
                    gpu_params.mode = GpuMode::ModeGfxstream;
                }
                _ => {
                    return Err(invalid_value_err(
                        v,
                        #[cfg(feature = "gfxstream")]
                        "gpu parameter 'backend' should be one of (2d|virglrenderer|gfxstream)",
                        #[cfg(not(feature = "gfxstream"))]
                        "gpu parameter 'backend' should be one of (2d|3d)",
                    ));
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
                    return Err(invalid_value_err(
                        v,
                        "gpu parameter 'egl' should be a boolean",
                    ));
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
                    return Err(invalid_value_err(
                        v,
                        "gpu parameter 'gles' should be a boolean",
                    ));
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
                    return Err(invalid_value_err(
                        v,
                        "gpu parameter 'glx' should be a boolean",
                    ));
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
                    return Err(invalid_value_err(
                        v,
                        "gpu parameter 'surfaceless' should be a boolean",
                    ));
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
                        return Err(invalid_value_err(
                            v,
                            "gpu parameter 'syncfd' should be a boolean",
                        ));
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
                        return Err(invalid_value_err(
                            v,
                            "gpu parameter 'angle' should be a boolean",
                        ));
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
                        return Err(invalid_value_err(
                            v,
                            "gpu parameter 'vulkan' should be a boolean",
                        ));
                    }
                }
            }
            "wsi" => match v {
                "vk" => {
                    gpu_params.wsi = Some(RutabagaWsi::Vulkan);
                }
                _ => {
                    return Err(invalid_value_err(v, "gpu parameter 'wsi' should be vk"));
                }
            },
            "cache-path" => gpu_params.cache_path = Some(v.to_string()),
            "cache-size" => gpu_params.cache_size = Some(v.to_string()),
            "pci-bar-size" => {
                let size = parse_hex_or_decimal(v).map_err(|_| {
                    "gpu parameter `pci-bar-size` must be a valid hex or decimal value"
                })?;
                gpu_params.pci_bar_size = size;
            }
            "udmabuf" => match v {
                "true" | "" => {
                    gpu_params.udmabuf = true;
                }
                "false" => {
                    gpu_params.udmabuf = false;
                }
                _ => {
                    return Err(invalid_value_err(
                        v,
                        "gpu parameter 'udmabuf' should be a boolean",
                    ));
                }
            },
            "context-types" => {
                let context_types: Vec<String> = v.split(':').map(|s| s.to_string()).collect();
                gpu_params.context_mask = rutabaga_gfx::calculate_context_mask(context_types);
            }
            "" => {}
            _ => {
                rest = Some(frag);
            }
        }
        if let Some(arg) = rest.take() {
            match display_param_builder.parse(arg) {
                Ok(()) => {}
                Err(argument::Error::UnknownArgument(_)) => {
                    rest = Some(arg);
                }
                Err(err) => return Err(err.to_string()),
            }
        }
        if let Some(arg) = rest.take() {
            return Err(format!("unknown gpu parameter {}", arg));
        }
    }

    if let Some(display_param) = display_param_builder.build()?.take() {
        gpu_params.displays.push(display_param);
    }

    #[cfg(feature = "gfxstream")]
    {
        if !vulkan_specified && gpu_params.mode == GpuMode::ModeGfxstream {
            gpu_params.use_vulkan = use_vulkan();
        }

        if syncfd_specified || angle_specified {
            match gpu_params.mode {
                GpuMode::ModeGfxstream => {}
                _ => {
                    return Err(
                        "gpu parameter syncfd and angle are only supported for gfxstream backend"
                            .to_string(),
                    );
                }
            }
        }
    }

    Ok(gpu_params)
}

#[cfg(feature = "gpu")]
pub fn parse_gpu_display_options(s: &str) -> Result<GpuDisplayParameters, String> {
    let mut display_param_builder: GpuDisplayParametersBuilder = Default::default();

    for arg in s.split(',') {
        display_param_builder
            .parse(arg)
            .map_err(|e| e.to_string())?;
    }

    let display_param = display_param_builder.build()?;
    let display_param = display_param.ok_or_else(|| {
        invalid_value_err(s, "gpu-display must include both 'width' and 'height'")
    })?;

    Ok(display_param)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crosvm::config::{DEFAULT_TOUCH_DEVICE_HEIGHT, DEFAULT_TOUCH_DEVICE_WIDTH};

    use argh::FromArgs;
    use std::path::PathBuf;

    #[cfg(feature = "audio")]
    use crate::crosvm::config::parse_ac97_options;
    use crate::crosvm::config::BindMount;

    #[cfg(feature = "audio_cras")]
    #[test]
    fn parse_ac97_socket_type() {
        parse_ac97_options("socket_type=unified").expect("parse should have succeded");
        parse_ac97_options("socket_type=legacy").expect("parse should have succeded");
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_default_vulkan_support() {
        {
            let gpu_params: GpuParameters = parse_gpu_options("backend=virglrenderer").unwrap();
            assert!(!gpu_params.use_vulkan);
        }

        #[cfg(feature = "gfxstream")]
        {
            let gpu_params: GpuParameters = parse_gpu_options("backend=gfxstream").unwrap();
            assert!(gpu_params.use_vulkan);
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_with_vulkan_specified() {
        {
            let gpu_params: GpuParameters = parse_gpu_options("vulkan=true").unwrap();
            assert!(gpu_params.use_vulkan);
        }
        {
            let gpu_params: GpuParameters =
                parse_gpu_options("backend=virglrenderer,vulkan=true").unwrap();
            assert!(gpu_params.use_vulkan);
        }
        {
            let gpu_params: GpuParameters =
                parse_gpu_options("vulkan=true,backend=virglrenderer").unwrap();
            assert!(gpu_params.use_vulkan);
        }
        {
            let gpu_params: GpuParameters = parse_gpu_options("vulkan=false").unwrap();
            assert!(!gpu_params.use_vulkan);
        }
        {
            let gpu_params: GpuParameters =
                parse_gpu_options("backend=virglrenderer,vulkan=false").unwrap();
            assert!(!gpu_params.use_vulkan);
        }
        {
            let gpu_params: GpuParameters =
                parse_gpu_options("vulkan=false,backend=virglrenderer").unwrap();
            assert!(!gpu_params.use_vulkan);
        }
        {
            assert!(parse_gpu_options("backend=virglrenderer,vulkan=invalid_value").is_err());
        }
        {
            assert!(parse_gpu_options("vulkan=invalid_value,backend=virglrenderer").is_err());
        }
    }

    #[cfg(all(feature = "gpu", feature = "gfxstream"))]
    #[test]
    fn parse_gpu_options_gfxstream_with_syncfd_specified() {
        {
            let gpu_params: GpuParameters =
                parse_gpu_options("backend=gfxstream,syncfd=true").unwrap();

            assert!(gpu_params.gfxstream_use_syncfd);
        }
        {
            let gpu_params: GpuParameters =
                parse_gpu_options("syncfd=true,backend=gfxstream").unwrap();
            assert!(gpu_params.gfxstream_use_syncfd);
        }
        {
            let gpu_params: GpuParameters =
                parse_gpu_options("backend=gfxstream,syncfd=false").unwrap();

            assert!(!gpu_params.gfxstream_use_syncfd);
        }
        {
            let gpu_params: GpuParameters =
                parse_gpu_options("syncfd=false,backend=gfxstream").unwrap();
            assert!(!gpu_params.gfxstream_use_syncfd);
        }
        {
            assert!(parse_gpu_options("backend=gfxstream,syncfd=invalid_value").is_err());
        }
        {
            assert!(parse_gpu_options("syncfd=invalid_value,backend=gfxstream").is_err());
        }
    }

    #[cfg(all(feature = "gpu", feature = "gfxstream"))]
    #[test]
    fn parse_gpu_options_not_gfxstream_with_syncfd_specified() {
        {
            assert!(parse_gpu_options("backend=virglrenderer,syncfd=true").is_err());
        }
        {
            assert!(parse_gpu_options("syncfd=true,backend=virglrenderer").is_err());
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_options_gfxstream_with_wsi_specified() {
        use rutabaga_gfx::RutabagaWsi;

        let gpu_params: GpuParameters = parse_gpu_options("backend=virglrenderer,wsi=vk").unwrap();
        assert!(matches!(gpu_params.wsi, Some(RutabagaWsi::Vulkan)));

        let gpu_params: GpuParameters = parse_gpu_options("wsi=vk,backend=virglrenderer").unwrap();
        assert!(matches!(gpu_params.wsi, Some(RutabagaWsi::Vulkan)));

        assert!(parse_gpu_options("backend=virglrenderer,wsi=invalid_value").is_err());

        assert!(parse_gpu_options("wsi=invalid_value,backend=virglrenderer").is_err());
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_valid() {
        {
            let gpu_params: GpuDisplayParameters =
                parse_gpu_display_options("width=500,height=600").unwrap();
            assert_eq!(gpu_params.width, 500);
            assert_eq!(gpu_params.height, 600);
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn parse_gpu_display_options_invalid() {
        {
            assert!(parse_gpu_display_options("width=500").is_err());
        }
        {
            assert!(parse_gpu_display_options("height=500").is_err());
        }
        {
            assert!(parse_gpu_display_options("width").is_err());
        }
        {
            assert!(parse_gpu_display_options("blah").is_err());
        }
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
                    "width=700,height=800",
                    "/dev/null",
                ],
            )
            .unwrap()
            .try_into()
            .unwrap();

            let gpu_params = config.gpu_parameters.unwrap();

            assert_eq!(gpu_params.displays.len(), 2);
            assert_eq!(gpu_params.displays[0].width, 500);
            assert_eq!(gpu_params.displays[0].height, 600);
            assert_eq!(gpu_params.displays[1].width, 700);
            assert_eq!(gpu_params.displays[1].height, 800);
        }
        {
            let config: Config = crate::crosvm::cmdline::RunCommand::from_args(
                &[],
                &[
                    "--gpu",
                    "2D",
                    "--gpu-display",
                    "width=700,height=800",
                    "/dev/null",
                ],
            )
            .unwrap()
            .try_into()
            .unwrap();

            let gpu_params = config.gpu_parameters.unwrap();

            assert_eq!(gpu_params.displays.len(), 1);
            assert_eq!(gpu_params.displays[0].width, 700);
            assert_eq!(gpu_params.displays[0].height, 800);
        }
    }

    #[cfg(feature = "audio")]
    #[test]
    fn parse_ac97_vios_valid() {
        parse_ac97_options("backend=vios,server=/path/to/server")
            .expect("parse should have succeded");
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
