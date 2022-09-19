// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(target_os = "android")]
mod android;
pub mod cmdline;
pub mod config;
mod device_helpers;
#[cfg(feature = "gpu")]
pub(crate) mod gpu;
pub(crate) mod jail_helpers;
mod vcpu;

use std::cmp::max;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::convert::TryInto;
use std::ffi::CString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::stdin;
use std::iter;
use std::mem;
use std::ops::RangeInclusive;
use std::os::unix::prelude::OpenOptionsExt;
use std::path::Path;
use std::process;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Barrier;
#[cfg(any(target_arch = "x86_64", feature = "gdb"))]
use std::thread;
#[cfg(feature = "balloon")]
use std::time::Duration;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use aarch64::AArch64 as Arch;
use acpi_tables::sdt::SDT;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use arch::LinuxArch;
use arch::RunnableLinuxVm;
use arch::VcpuAffinity;
use arch::VirtioDeviceStub;
use arch::VmComponents;
use arch::VmImage;
use base::sys::WaitStatus;
#[cfg(feature = "balloon")]
use base::UnixSeqpacket;
use base::UnixSeqpacketListener;
use base::UnlinkUnixSeqpacketListener;
use base::*;
use cros_async::Executor;
use device_helpers::*;
use devices::serial_device::SerialHardware;
use devices::vfio::VfioCommonSetup;
use devices::vfio::VfioCommonTrait;
#[cfg(feature = "gpu")]
use devices::virtio;
use devices::virtio::device_constants::video::VideoDeviceType;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::virtio::memory_mapper::MemoryMapper;
use devices::virtio::memory_mapper::MemoryMapperTrait;
use devices::virtio::vhost::user::VhostUserListener;
use devices::virtio::vhost::user::VhostUserListenerTrait;
use devices::virtio::vhost::vsock::VhostVsockConfig;
#[cfg(feature = "balloon")]
use devices::virtio::BalloonFeatures;
#[cfg(feature = "balloon")]
use devices::virtio::BalloonMode;
#[cfg(feature = "gpu")]
use devices::virtio::EventDevice;
use devices::virtio::VirtioTransportType;
#[cfg(feature = "audio")]
use devices::Ac97Dev;
use devices::BusDeviceObj;
use devices::CoIommuDev;
#[cfg(feature = "usb")]
use devices::HostBackendDeviceProvider;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::HostHotPlugKey;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::HotPlugBus;
use devices::IommuDevType;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use devices::IrqChipAArch64 as IrqChipArch;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::IrqChipX86_64 as IrqChipArch;
use devices::IrqEventIndex;
use devices::IrqEventSource;
use devices::KvmKernelIrqChip;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::KvmSplitIrqChip;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::PciAddress;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::PciBridge;
use devices::PciDevice;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::PciRoot;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::PciRootCommand;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::PcieDownstreamPort;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::PcieHostPort;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::PcieRootPort;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use devices::PcieUpstreamPort;
use devices::PvPanicCode;
use devices::PvPanicPciDevice;
use devices::StubPciDevice;
use devices::VirtioMmioDevice;
use devices::VirtioPciDevice;
#[cfg(feature = "usb")]
use devices::XhciController;
#[cfg(feature = "gpu")]
pub use gpu::GpuRenderServerParameters;
#[cfg(feature = "gpu")]
use gpu::*;
use hypervisor::kvm::Kvm;
use hypervisor::kvm::KvmVcpu;
use hypervisor::kvm::KvmVm;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use hypervisor::CpuConfigX86_64;
use hypervisor::HypervisorCap;
use hypervisor::ProtectionType;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use hypervisor::VcpuAArch64 as VcpuArch;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use hypervisor::VcpuX86_64 as VcpuArch;
use hypervisor::Vm;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use hypervisor::VmAArch64 as VmArch;
use hypervisor::VmCap;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use hypervisor::VmX86_64 as VmArch;
use jail_helpers::*;
use libc;
use minijail::Minijail;
use resources::AddressRange;
use resources::Alloc;
#[cfg(feature = "direct")]
use resources::Error as ResourceError;
use resources::SystemAllocator;
use rutabaga_gfx::RutabagaGralloc;
use sync::Condvar;
use sync::Mutex;
use vm_control::*;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::MemoryPolicy;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::msr::get_override_msr_list;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::X8664arch as Arch;

use crate::crosvm::config::Config;
use crate::crosvm::config::Executable;
use crate::crosvm::config::FileBackedMappingParameters;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::crosvm::config::HostPcieRootPortParameters;
use crate::crosvm::config::HypervisorKind;
use crate::crosvm::config::JailConfig;
use crate::crosvm::config::SharedDir;
use crate::crosvm::config::SharedDirKind;
#[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
use crate::crosvm::gdb::gdb_thread;
#[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
use crate::crosvm::gdb::GdbStub;
use crate::crosvm::sys::cmdline::DevicesCommand;
use crate::crosvm::sys::config::VfioType;

fn create_virtio_devices(
    cfg: &Config,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    #[cfg_attr(not(feature = "gpu"), allow(unused_variables))] vm_evt_wrtube: &SendTube,
    #[cfg(feature = "balloon")] balloon_device_tube: Option<Tube>,
    #[cfg(feature = "balloon")] balloon_inflate_tube: Option<Tube>,
    #[cfg(feature = "balloon")] init_balloon_size: u64,
    disk_device_tubes: &mut Vec<Tube>,
    pmem_device_tubes: &mut Vec<Tube>,
    fs_device_tubes: &mut Vec<Tube>,
    #[cfg(feature = "gpu")] gpu_control_tube: Tube,
    #[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))] render_server_fd: Option<
        SafeDescriptor,
    >,
    vvu_proxy_device_tubes: &mut Vec<Tube>,
    vvu_proxy_max_sibling_mem_size: u64,
) -> DeviceResult<Vec<VirtioDeviceStub>> {
    let mut devs = Vec::new();

    for opt in &cfg.vhost_user_gpu {
        devs.push(create_vhost_user_gpu_device(cfg.protection_type, opt)?);
    }

    for opt in &cfg.vvu_proxy {
        devs.push(create_vvu_proxy_device(
            cfg.protection_type,
            &cfg.jail_config,
            opt,
            vvu_proxy_device_tubes.remove(0),
            vvu_proxy_max_sibling_mem_size,
        )?);
    }

    #[cfg(any(feature = "gpu", feature = "video-decoder", feature = "video-encoder"))]
    let mut resource_bridges = Vec::<Tube>::new();

    if !cfg.wayland_socket_paths.is_empty() {
        #[cfg_attr(not(feature = "gpu"), allow(unused_mut))]
        let mut wl_resource_bridge = None::<Tube>;

        #[cfg(feature = "gpu")]
        {
            if cfg.gpu_parameters.is_some() {
                let (wl_socket, gpu_socket) = Tube::pair().context("failed to create tube")?;
                resource_bridges.push(gpu_socket);
                wl_resource_bridge = Some(wl_socket);
            }
        }

        devs.push(create_wayland_device(
            cfg.protection_type,
            &cfg.jail_config,
            &cfg.wayland_socket_paths,
            wl_resource_bridge,
        )?);
    }

    #[cfg(feature = "video-decoder")]
    let video_dec_cfg = if let Some(config) = &cfg.video_dec {
        let (video_tube, gpu_tube) = Tube::pair().context("failed to create tube")?;
        resource_bridges.push(gpu_tube);
        Some((video_tube, config.backend_type))
    } else {
        None
    };

    #[cfg(feature = "video-encoder")]
    let video_enc_cfg = if let Some(config) = &cfg.video_enc {
        let (video_tube, gpu_tube) = Tube::pair().context("failed to create tube")?;
        resource_bridges.push(gpu_tube);
        Some((video_tube, config.backend_type))
    } else {
        None
    };

    #[cfg(feature = "gpu")]
    {
        if let Some(gpu_parameters) = &cfg.gpu_parameters {
            let display_param = if gpu_parameters.display_params.is_empty() {
                Default::default()
            } else {
                gpu_parameters.display_params[0].clone()
            };
            let (gpu_display_w, gpu_display_h) = display_param.get_virtual_display_size();

            let mut event_devices = Vec::new();
            if cfg.display_window_mouse {
                let (event_device_socket, virtio_dev_socket) =
                    StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte)
                        .context("failed to create socket")?;
                let (multi_touch_width, multi_touch_height) = cfg
                    .virtio_multi_touch
                    .first()
                    .as_ref()
                    .map(|multi_touch_spec| multi_touch_spec.get_size())
                    .unwrap_or((gpu_display_w, gpu_display_h));
                let dev = virtio::new_multi_touch(
                    // u32::MAX is the least likely to collide with the indices generated above for
                    // the multi_touch options, which begin at 0.
                    u32::MAX,
                    virtio_dev_socket,
                    multi_touch_width,
                    multi_touch_height,
                    virtio::base_features(cfg.protection_type),
                )
                .context("failed to set up mouse device")?;
                devs.push(VirtioDeviceStub {
                    dev: Box::new(dev),
                    jail: simple_jail(&cfg.jail_config, "input_device")?,
                });
                event_devices.push(EventDevice::touchscreen(event_device_socket));
            }
            if cfg.display_window_keyboard {
                let (event_device_socket, virtio_dev_socket) =
                    StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte)
                        .context("failed to create socket")?;
                let dev = virtio::new_keyboard(
                    // u32::MAX is the least likely to collide with the indices generated above for
                    // the multi_touch options, which begin at 0.
                    u32::MAX,
                    virtio_dev_socket,
                    virtio::base_features(cfg.protection_type),
                )
                .context("failed to set up keyboard device")?;
                devs.push(VirtioDeviceStub {
                    dev: Box::new(dev),
                    jail: simple_jail(&cfg.jail_config, "input_device")?,
                });
                event_devices.push(EventDevice::keyboard(event_device_socket));
            }

            devs.push(create_gpu_device(
                cfg,
                vm_evt_wrtube,
                gpu_control_tube,
                resource_bridges,
                // Use the unnamed socket for GPU display screens.
                cfg.wayland_socket_paths.get(""),
                cfg.x_display.clone(),
                #[cfg(feature = "virgl_renderer_next")]
                render_server_fd,
                event_devices,
            )?);
        }
    }

    for (_, param) in cfg
        .serial_parameters
        .iter()
        .filter(|(_k, v)| v.hardware == SerialHardware::VirtioConsole)
    {
        let dev = param.create_virtio_device_and_jail(cfg.protection_type, &cfg.jail_config)?;
        devs.push(dev);
    }

    for disk in &cfg.disks {
        let disk_config = DiskConfig::new(disk, Some(disk_device_tubes.remove(0)));
        devs.push(
            disk_config.create_virtio_device_and_jail(cfg.protection_type, &cfg.jail_config)?,
        );
    }

    for blk in &cfg.vhost_user_blk {
        devs.push(create_vhost_user_block_device(cfg.protection_type, blk)?);
    }

    for console in &cfg.vhost_user_console {
        devs.push(create_vhost_user_console_device(
            cfg.protection_type,
            console,
        )?);
    }

    for (index, pmem_disk) in cfg.pmem_devices.iter().enumerate() {
        let pmem_device_tube = pmem_device_tubes.remove(0);
        devs.push(create_pmem_device(
            cfg.protection_type,
            &cfg.jail_config,
            vm,
            resources,
            pmem_disk,
            index,
            pmem_device_tube,
        )?);
    }

    if cfg.rng {
        devs.push(create_rng_device(cfg.protection_type, &cfg.jail_config)?);
    }

    #[cfg(feature = "tpm")]
    {
        if cfg.software_tpm {
            devs.push(create_software_tpm_device(
                cfg.protection_type,
                &cfg.jail_config,
            )?);
        }
    }

    #[cfg(all(feature = "vtpm", target_arch = "x86_64"))]
    {
        if cfg.vtpm_proxy {
            devs.push(create_vtpm_proxy_device(
                cfg.protection_type,
                &cfg.jail_config,
            )?);
        }
    }

    for (idx, single_touch_spec) in cfg.virtio_single_touch.iter().enumerate() {
        devs.push(create_single_touch_device(
            cfg.protection_type,
            &cfg.jail_config,
            single_touch_spec,
            idx as u32,
        )?);
    }

    for (idx, multi_touch_spec) in cfg.virtio_multi_touch.iter().enumerate() {
        devs.push(create_multi_touch_device(
            cfg.protection_type,
            &cfg.jail_config,
            multi_touch_spec,
            idx as u32,
        )?);
    }

    for (idx, trackpad_spec) in cfg.virtio_trackpad.iter().enumerate() {
        devs.push(create_trackpad_device(
            cfg.protection_type,
            &cfg.jail_config,
            trackpad_spec,
            idx as u32,
        )?);
    }

    for (idx, mouse_socket) in cfg.virtio_mice.iter().enumerate() {
        devs.push(create_mouse_device(
            cfg.protection_type,
            &cfg.jail_config,
            mouse_socket,
            idx as u32,
        )?);
    }

    for (idx, keyboard_socket) in cfg.virtio_keyboard.iter().enumerate() {
        devs.push(create_keyboard_device(
            cfg.protection_type,
            &cfg.jail_config,
            keyboard_socket,
            idx as u32,
        )?);
    }

    for (idx, switches_socket) in cfg.virtio_switches.iter().enumerate() {
        devs.push(create_switches_device(
            cfg.protection_type,
            &cfg.jail_config,
            switches_socket,
            idx as u32,
        )?);
    }

    for dev_path in &cfg.virtio_input_evdevs {
        devs.push(create_vinput_device(
            cfg.protection_type,
            &cfg.jail_config,
            dev_path,
        )?);
    }

    #[cfg(feature = "balloon")]
    if let Some(balloon_device_tube) = balloon_device_tube {
        let balloon_features =
            (cfg.balloon_page_reporting as u64) << BalloonFeatures::PageReporting as u64;
        devs.push(create_balloon_device(
            cfg.protection_type,
            &cfg.jail_config,
            if cfg.strict_balloon {
                BalloonMode::Strict
            } else {
                BalloonMode::Relaxed
            },
            balloon_device_tube,
            balloon_inflate_tube,
            init_balloon_size,
            balloon_features,
        )?);
    }

    // We checked above that if the IP is defined, then the netmask is, too.
    for tap_fd in &cfg.tap_fd {
        devs.push(create_tap_net_device_from_fd(
            cfg.protection_type,
            &cfg.jail_config,
            cfg.net_vq_pairs.unwrap_or(1),
            cfg.vcpu_count.unwrap_or(1),
            *tap_fd,
        )?);
    }

    if let (Some(host_ip), Some(netmask), Some(mac_address)) =
        (cfg.host_ip, cfg.netmask, cfg.mac_address)
    {
        if !cfg.vhost_user_net.is_empty() {
            bail!("vhost-user-net cannot be used with any of --host-ip, --netmask or --mac");
        }
        devs.push(create_net_device_from_config(
            cfg.protection_type,
            &cfg.jail_config,
            cfg.net_vq_pairs.unwrap_or(1),
            cfg.vcpu_count.unwrap_or(1),
            if cfg.vhost_net {
                Some(cfg.vhost_net_device_path.clone())
            } else {
                None
            },
            host_ip,
            netmask,
            mac_address,
        )?);
    }

    for tap_name in &cfg.tap_name {
        devs.push(create_tap_net_device_from_name(
            cfg.protection_type,
            &cfg.jail_config,
            cfg.net_vq_pairs.unwrap_or(1),
            cfg.vcpu_count.unwrap_or(1),
            tap_name.as_bytes(),
        )?);
    }

    for net in &cfg.vhost_user_net {
        devs.push(create_vhost_user_net_device(cfg.protection_type, net)?);
    }

    for vsock in &cfg.vhost_user_vsock {
        devs.push(create_vhost_user_vsock_device(cfg.protection_type, vsock)?);
    }

    for opt in &cfg.vhost_user_wl {
        devs.push(create_vhost_user_wl_device(cfg.protection_type, opt)?);
    }

    #[cfg(feature = "audio")]
    {
        for virtio_snd in &cfg.virtio_snds {
            devs.push(create_virtio_snd_device(
                cfg.protection_type,
                &cfg.jail_config,
                virtio_snd.clone(),
            )?);
        }
    }

    #[cfg(feature = "video-decoder")]
    {
        if let Some((video_dec_tube, video_dec_backend)) = video_dec_cfg {
            register_video_device(
                video_dec_backend,
                &mut devs,
                video_dec_tube,
                cfg.protection_type,
                &cfg.jail_config,
                VideoDeviceType::Decoder,
            )?;
        }
    }
    if let Some(socket_path) = &cfg.vhost_user_video_dec {
        devs.push(create_vhost_user_video_device(
            cfg.protection_type,
            socket_path,
            VideoDeviceType::Decoder,
        )?);
    }

    #[cfg(feature = "video-encoder")]
    {
        if let Some((video_enc_tube, video_enc_backend)) = video_enc_cfg {
            register_video_device(
                video_enc_backend,
                &mut devs,
                video_enc_tube,
                cfg.protection_type,
                &cfg.jail_config,
                VideoDeviceType::Encoder,
            )?;
        }
    }

    if let Some(cid) = cfg.cid {
        let vhost_config = VhostVsockConfig {
            device: cfg.vhost_vsock_device.clone(),
            cid,
        };
        devs.push(create_vhost_vsock_device(
            cfg.protection_type,
            &cfg.jail_config,
            &vhost_config,
        )?);
    }

    for vhost_user_fs in &cfg.vhost_user_fs {
        devs.push(create_vhost_user_fs_device(
            cfg.protection_type,
            vhost_user_fs,
        )?);
    }

    for vhost_user_snd in &cfg.vhost_user_snd {
        devs.push(create_vhost_user_snd_device(
            cfg.protection_type,
            vhost_user_snd,
        )?);
    }

    for shared_dir in &cfg.shared_dirs {
        let SharedDir {
            src,
            tag,
            kind,
            uid_map,
            gid_map,
            fs_cfg,
            p9_cfg,
        } = shared_dir;

        let dev = match kind {
            SharedDirKind::FS => {
                let device_tube = fs_device_tubes.remove(0);
                create_fs_device(
                    cfg.protection_type,
                    &cfg.jail_config,
                    uid_map,
                    gid_map,
                    src,
                    tag,
                    fs_cfg.clone(),
                    device_tube,
                )?
            }
            SharedDirKind::P9 => create_9p_device(
                cfg.protection_type,
                &cfg.jail_config,
                uid_map,
                gid_map,
                src,
                tag,
                p9_cfg.clone(),
            )?,
        };
        devs.push(dev);
    }

    if let Some(vhost_user_mac80211_hwsim) = &cfg.vhost_user_mac80211_hwsim {
        devs.push(create_vhost_user_mac80211_hwsim_device(
            cfg.protection_type,
            vhost_user_mac80211_hwsim,
        )?);
    }

    #[cfg(feature = "audio")]
    if let Some(path) = &cfg.sound {
        devs.push(create_sound_device(
            path,
            cfg.protection_type,
            &cfg.jail_config,
        )?);
    }

    Ok(devs)
}

fn create_devices(
    cfg: &Config,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    vm_evt_wrtube: &SendTube,
    iommu_attached_endpoints: &mut BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
    control_tubes: &mut Vec<TaggedControlTube>,
    #[cfg(feature = "balloon")] balloon_device_tube: Option<Tube>,
    #[cfg(feature = "balloon")] init_balloon_size: u64,
    disk_device_tubes: &mut Vec<Tube>,
    pmem_device_tubes: &mut Vec<Tube>,
    fs_device_tubes: &mut Vec<Tube>,
    #[cfg(feature = "usb")] usb_provider: HostBackendDeviceProvider,
    #[cfg(feature = "gpu")] gpu_control_tube: Tube,
    #[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))] render_server_fd: Option<
        SafeDescriptor,
    >,
    vvu_proxy_device_tubes: &mut Vec<Tube>,
    vvu_proxy_max_sibling_mem_size: u64,
    iova_max_addr: &mut Option<u64>,
) -> DeviceResult<Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>> {
    let mut devices: Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)> = Vec::new();
    #[cfg(feature = "balloon")]
    let mut balloon_inflate_tube: Option<Tube> = None;
    if !cfg.vfio.is_empty() {
        let mut coiommu_attached_endpoints = Vec::new();

        for vfio_dev in cfg
            .vfio
            .iter()
            .filter(|dev| dev.get_type() == VfioType::Pci)
        {
            let vfio_path = &vfio_dev.vfio_path;
            let (vfio_pci_device, jail, viommu_mapper) = create_vfio_device(
                &cfg.jail_config,
                vm,
                resources,
                control_tubes,
                vfio_path.as_path(),
                false,
                None,
                vfio_dev.guest_address(),
                Some(&mut coiommu_attached_endpoints),
                vfio_dev.iommu_dev_type(),
                #[cfg(feature = "direct")]
                vfio_dev.is_intel_lpss(),
            )?;

            *iova_max_addr = Some(max(
                vfio_pci_device.get_max_iova(),
                iova_max_addr.unwrap_or(0),
            ));

            if let Some(viommu_mapper) = viommu_mapper {
                iommu_attached_endpoints.insert(
                    vfio_pci_device
                        .pci_address()
                        .context("not initialized")?
                        .to_u32(),
                    Arc::new(Mutex::new(Box::new(viommu_mapper))),
                );
            }

            devices.push((vfio_pci_device, jail));
        }

        for vfio_dev in cfg
            .vfio
            .iter()
            .filter(|dev| dev.get_type() == VfioType::Platform)
        {
            let vfio_path = &vfio_dev.vfio_path;
            let (vfio_plat_dev, jail) = create_vfio_platform_device(
                &cfg.jail_config,
                vm,
                resources,
                control_tubes,
                vfio_path.as_path(),
                iommu_attached_endpoints,
                IommuDevType::NoIommu, // Virtio IOMMU is not supported yet
            )?;

            devices.push((Box::new(vfio_plat_dev), jail));
        }

        if !coiommu_attached_endpoints.is_empty() || !iommu_attached_endpoints.is_empty() {
            let mut buf = mem::MaybeUninit::<libc::rlimit>::zeroed();
            let res = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, buf.as_mut_ptr()) };
            if res == 0 {
                let limit = unsafe { buf.assume_init() };
                let rlim_new = limit
                    .rlim_cur
                    .saturating_add(vm.get_memory().memory_size() as libc::rlim_t);
                let rlim_max = max(limit.rlim_max, rlim_new);
                if limit.rlim_cur < rlim_new {
                    let limit_arg = libc::rlimit {
                        rlim_cur: rlim_new as libc::rlim_t,
                        rlim_max: rlim_max as libc::rlim_t,
                    };
                    let res = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit_arg) };
                    if res != 0 {
                        bail!("Set rlimit failed");
                    }
                }
            } else {
                bail!("Get rlimit failed");
            }
        }
        #[cfg(feature = "balloon")]
        let coiommu_tube: Option<Tube>;
        #[cfg(not(feature = "balloon"))]
        let coiommu_tube: Option<Tube> = None;
        if !coiommu_attached_endpoints.is_empty() {
            let vfio_container =
                VfioCommonSetup::vfio_get_container(IommuDevType::CoIommu, None as Option<&Path>)
                    .context("failed to get vfio container")?;
            let (coiommu_host_tube, coiommu_device_tube) =
                Tube::pair().context("failed to create coiommu tube")?;
            control_tubes.push(TaggedControlTube::VmMemory {
                tube: coiommu_host_tube,
                expose_with_viommu: false,
            });
            let vcpu_count = cfg.vcpu_count.unwrap_or(1) as u64;
            #[cfg(feature = "balloon")]
            match Tube::pair() {
                Ok((x, y)) => {
                    coiommu_tube = Some(x);
                    balloon_inflate_tube = Some(y);
                }
                Err(x) => return Err(x).context("failed to create coiommu tube"),
            }
            let dev = CoIommuDev::new(
                vm.get_memory().clone(),
                vfio_container,
                coiommu_device_tube,
                coiommu_tube,
                coiommu_attached_endpoints,
                vcpu_count,
                cfg.coiommu_param.unwrap_or_default(),
            )
            .context("failed to create coiommu device")?;

            devices.push((
                Box::new(dev),
                simple_jail(&cfg.jail_config, "coiommu_device")?,
            ));
        }
    }

    let stubs = create_virtio_devices(
        cfg,
        vm,
        resources,
        vm_evt_wrtube,
        #[cfg(feature = "balloon")]
        balloon_device_tube,
        #[cfg(feature = "balloon")]
        balloon_inflate_tube,
        #[cfg(feature = "balloon")]
        init_balloon_size,
        disk_device_tubes,
        pmem_device_tubes,
        fs_device_tubes,
        #[cfg(feature = "gpu")]
        gpu_control_tube,
        #[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
        render_server_fd,
        vvu_proxy_device_tubes,
        vvu_proxy_max_sibling_mem_size,
    )?;

    for stub in stubs {
        match stub.dev.transport_type() {
            VirtioTransportType::Pci => {
                let (msi_host_tube, msi_device_tube) =
                    Tube::pair().context("failed to create tube")?;
                control_tubes.push(TaggedControlTube::VmIrq(msi_host_tube));

                let shared_memory_tube = if stub.dev.get_shared_memory_region().is_some() {
                    let (host_tube, device_tube) =
                        Tube::pair().context("failed to create VVU proxy tube")?;
                    control_tubes.push(TaggedControlTube::VmMemory {
                        tube: host_tube,
                        expose_with_viommu: stub.dev.expose_shmem_descriptors_with_viommu(),
                    });
                    Some(device_tube)
                } else {
                    None
                };

                let dev = VirtioPciDevice::new(
                    vm.get_memory().clone(),
                    stub.dev,
                    msi_device_tube,
                    cfg.disable_virtio_intx,
                    shared_memory_tube,
                )
                .context("failed to create virtio pci dev")?;

                devices.push((Box::new(dev) as Box<dyn BusDeviceObj>, stub.jail));
            }
            VirtioTransportType::Mmio => {
                let dev = VirtioMmioDevice::new(vm.get_memory().clone(), stub.dev)
                    .context("failed to create virtio mmio dev")?;
                devices.push((Box::new(dev) as Box<dyn BusDeviceObj>, stub.jail));
            }
        }
    }

    #[cfg(feature = "audio")]
    for ac97_param in &cfg.ac97_parameters {
        let dev = Ac97Dev::try_new(vm.get_memory().clone(), ac97_param.clone())
            .context("failed to create ac97 device")?;
        let jail = simple_jail(&cfg.jail_config, dev.minijail_policy())?;
        devices.push((Box::new(dev), jail));
    }

    #[cfg(feature = "usb")]
    if cfg.usb {
        // Create xhci controller.
        let usb_controller = Box::new(XhciController::new(vm.get_memory().clone(), usb_provider));
        devices.push((
            usb_controller,
            simple_jail(&cfg.jail_config, "xhci_device")?,
        ));
    }

    for params in &cfg.stub_pci_devices {
        // Stub devices don't need jailing since they don't do anything.
        devices.push((Box::new(StubPciDevice::new(params)), None));
    }

    devices.push((
        Box::new(PvPanicPciDevice::new(vm_evt_wrtube.try_clone()?)),
        None,
    ));

    Ok(devices)
}

fn create_file_backed_mappings(
    cfg: &Config,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
) -> Result<()> {
    for mapping in &cfg.file_backed_mappings {
        let file = OpenOptions::new()
            .read(true)
            .write(mapping.writable)
            .custom_flags(if mapping.sync { libc::O_SYNC } else { 0 })
            .open(&mapping.path)
            .context("failed to open file for file-backed mapping")?;
        let prot = if mapping.writable {
            Protection::read_write()
        } else {
            Protection::read()
        };
        let size = mapping
            .size
            .try_into()
            .context("Invalid size for file-backed mapping")?;
        let memory_mapping = MemoryMappingBuilder::new(size)
            .from_file(&file)
            .offset(mapping.offset)
            .protection(prot)
            .build()
            .context("failed to map backing file for file-backed mapping")?;

        let mapping_range = AddressRange::from_start_and_size(mapping.address, mapping.size)
            .context("failed to convert to AddressRange")?;
        match resources.mmio_allocator_any().allocate_at(
            mapping_range,
            Alloc::FileBacked(mapping.address),
            "file-backed mapping".to_owned(),
        ) {
            // OutOfSpace just means that this mapping is not in the MMIO regions at all, so don't
            // consider it an error.
            // TODO(b/222769529): Reserve this region in a global memory address space allocator once
            // we have that so nothing else can accidentally overlap with it.
            Ok(()) | Err(resources::Error::OutOfSpace) => {}
            e => e.context("failed to allocate guest address for file-backed mapping")?,
        }

        vm.add_memory_region(
            GuestAddress(mapping.address),
            Box::new(memory_mapping),
            !mapping.writable,
            /* log_dirty_pages = */ false,
        )
        .context("failed to configure file-backed mapping")?;
    }

    Ok(())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn create_pcie_root_port(
    host_pcie_rp: Vec<HostPcieRootPortParameters>,
    sys_allocator: &mut SystemAllocator,
    control_tubes: &mut Vec<TaggedControlTube>,
    devices: &mut Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>,
    hp_vec: &mut Vec<(u8, Arc<Mutex<dyn HotPlugBus>>)>,
    hp_endpoints_ranges: &mut Vec<RangeInclusive<u32>>,
    // TODO(b/228627457): clippy is incorrectly warning about this Vec, which needs to be a Vec so
    // we can push into it
    #[allow(clippy::ptr_arg)] gpe_notify_devs: &mut Vec<(u32, Arc<Mutex<dyn GpeNotify>>)>,
) -> Result<()> {
    if host_pcie_rp.is_empty() {
        // user doesn't specify host pcie root port which link to this virtual pcie rp,
        // find the empty bus and create a total virtual pcie rp
        let mut hp_sec_bus = 0u8;
        // Create Pcie Root Port for non-root buses, each non-root bus device will be
        // connected behind a virtual pcie root port.
        for i in 1..255 {
            if sys_allocator.pci_bus_empty(i) {
                if hp_sec_bus == 0 {
                    hp_sec_bus = i;
                }
                continue;
            }
            let pcie_root_port = Arc::new(Mutex::new(PcieRootPort::new(i, false)));
            let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
            control_tubes.push(TaggedControlTube::VmIrq(msi_host_tube));
            let pci_bridge = Box::new(PciBridge::new(pcie_root_port.clone(), msi_device_tube));
            // no ipc is used if the root port disables hotplug
            devices.push((pci_bridge, None));
        }

        // Create Pcie Root Port for hot-plug
        if hp_sec_bus == 0 {
            return Err(anyhow!("no more addresses are available"));
        }
        let pcie_root_port = Arc::new(Mutex::new(PcieRootPort::new(hp_sec_bus, true)));
        let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
        control_tubes.push(TaggedControlTube::VmIrq(msi_host_tube));
        let pci_bridge = Box::new(PciBridge::new(pcie_root_port.clone(), msi_device_tube));

        hp_endpoints_ranges.push(RangeInclusive::new(
            PciAddress {
                bus: pci_bridge.get_secondary_num(),
                dev: 0,
                func: 0,
            }
            .to_u32(),
            PciAddress {
                bus: pci_bridge.get_subordinate_num(),
                dev: 32,
                func: 8,
            }
            .to_u32(),
        ));

        devices.push((pci_bridge, None));
        hp_vec.push((hp_sec_bus, pcie_root_port as Arc<Mutex<dyn HotPlugBus>>));
    } else {
        // user specify host pcie root port which link to this virtual pcie rp,
        // reserve the host pci BDF and create a virtual pcie RP with some attrs same as host
        for host_pcie in host_pcie_rp.iter() {
            let (vm_host_tube, vm_device_tube) = Tube::pair().context("failed to create tube")?;
            let pcie_host = PcieHostPort::new(host_pcie.host_path.as_path(), vm_device_tube)?;
            let bus_range = pcie_host.get_bus_range();
            let mut slot_implemented = true;
            for i in bus_range.secondary..=bus_range.subordinate {
                // if this bus is occupied by one vfio-pci device, this vfio-pci device is
                // connected to a pci bridge on host statically, then it should be connected
                // to a virtual pci bridge in guest statically, this bridge won't have
                // hotplug capability and won't use slot.
                if !sys_allocator.pci_bus_empty(i) {
                    slot_implemented = false;
                    break;
                }
            }

            let pcie_root_port = Arc::new(Mutex::new(PcieRootPort::new_from_host(
                pcie_host,
                slot_implemented,
            )?));
            control_tubes.push(TaggedControlTube::Vm(vm_host_tube));

            let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
            control_tubes.push(TaggedControlTube::VmIrq(msi_host_tube));
            let mut pci_bridge = Box::new(PciBridge::new(pcie_root_port.clone(), msi_device_tube));
            // early reservation for host pcie root port devices.
            let rootport_addr = pci_bridge.allocate_address(sys_allocator);
            if rootport_addr.is_err() {
                warn!(
                    "address reservation failed for hot pcie root port {}",
                    pci_bridge.debug_label()
                );
            }

            // Only append the sub pci range of a hot-pluggable root port to virtio-iommu
            if slot_implemented {
                hp_endpoints_ranges.push(RangeInclusive::new(
                    PciAddress {
                        bus: pci_bridge.get_secondary_num(),
                        dev: 0,
                        func: 0,
                    }
                    .to_u32(),
                    PciAddress {
                        bus: pci_bridge.get_subordinate_num(),
                        dev: 32,
                        func: 8,
                    }
                    .to_u32(),
                ));
            }

            devices.push((pci_bridge, None));
            if slot_implemented {
                if let Some(gpe) = host_pcie.hp_gpe {
                    gpe_notify_devs
                        .push((gpe, pcie_root_port.clone() as Arc<Mutex<dyn GpeNotify>>));
                }
                hp_vec.push((
                    bus_range.secondary,
                    pcie_root_port as Arc<Mutex<dyn HotPlugBus>>,
                ));
            }
        }
    }

    Ok(())
}

fn setup_vm_components(cfg: &Config) -> Result<VmComponents> {
    let initrd_image = if let Some(initrd_path) = &cfg.initrd_path {
        Some(
            open_file(initrd_path, OpenOptions::new().read(true))
                .with_context(|| format!("failed to open initrd {}", initrd_path.display()))?,
        )
    } else {
        None
    };
    let pvm_fw_image = if let Some(pvm_fw_path) = &cfg.pvm_fw {
        Some(
            open_file(pvm_fw_path, OpenOptions::new().read(true))
                .with_context(|| format!("failed to open pvm_fw {}", pvm_fw_path.display()))?,
        )
    } else {
        None
    };

    let vm_image = match cfg.executable_path {
        Some(Executable::Kernel(ref kernel_path)) => VmImage::Kernel(
            open_file(kernel_path, OpenOptions::new().read(true)).with_context(|| {
                format!("failed to open kernel image {}", kernel_path.display())
            })?,
        ),
        Some(Executable::Bios(ref bios_path)) => VmImage::Bios(
            open_file(bios_path, OpenOptions::new().read(true))
                .with_context(|| format!("failed to open bios {}", bios_path.display()))?,
        ),
        _ => panic!("Did not receive a bios or kernel, should be impossible."),
    };

    let swiotlb = if let Some(size) = cfg.swiotlb {
        Some(
            size.checked_mul(1024 * 1024)
                .ok_or_else(|| anyhow!("requested swiotlb size too large"))?,
        )
    } else {
        match cfg.protection_type {
            ProtectionType::Protected | ProtectionType::ProtectedWithoutFirmware => {
                Some(64 * 1024 * 1024)
            }
            ProtectionType::Unprotected | ProtectionType::UnprotectedWithFirmware => None,
        }
    };

    let (pflash_image, pflash_block_size) = if let Some(pflash_parameters) = &cfg.pflash_parameters
    {
        (
            Some(
                open_file(
                    &pflash_parameters.path,
                    OpenOptions::new().read(true).write(true),
                )
                .with_context(|| {
                    format!("failed to open pflash {}", pflash_parameters.path.display())
                })?,
            ),
            pflash_parameters.block_size,
        )
    } else {
        (None, 0)
    };

    Ok(VmComponents {
        memory_size: cfg
            .memory
            .unwrap_or(256)
            .checked_mul(1024 * 1024)
            .ok_or_else(|| anyhow!("requested memory size too large"))?,
        swiotlb,
        vcpu_count: cfg.vcpu_count.unwrap_or(1),
        vcpu_affinity: cfg.vcpu_affinity.clone(),
        cpu_clusters: cfg.cpu_clusters.clone(),
        cpu_capacity: cfg.cpu_capacity.clone(),
        #[cfg(feature = "direct")]
        direct_gpe: cfg.direct_gpe.clone(),
        #[cfg(feature = "direct")]
        direct_fixed_evts: cfg.direct_fixed_evts.clone(),
        no_smt: cfg.no_smt,
        hugepages: cfg.hugepages,
        hv_cfg: hypervisor::Config {
            #[cfg(target_arch = "aarch64")]
            mte: cfg.mte,
            protection_type: cfg.protection_type,
        },
        vm_image,
        android_fstab: cfg
            .android_fstab
            .as_ref()
            .map(|x| {
                File::open(x)
                    .with_context(|| format!("failed to open android fstab file {}", x.display()))
            })
            .map_or(Ok(None), |v| v.map(Some))?,
        pstore: cfg.pstore.clone(),
        pflash_block_size,
        pflash_image,
        initrd_image,
        extra_kernel_params: cfg.params.clone(),
        acpi_sdts: cfg
            .acpi_tables
            .iter()
            .map(|path| {
                SDT::from_file(path)
                    .with_context(|| format!("failed to open ACPI file {}", path.display()))
            })
            .collect::<Result<Vec<SDT>>>()?,
        rt_cpus: cfg.rt_cpus.clone(),
        delay_rt: cfg.delay_rt,
        #[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
        gdb: None,
        dmi_path: cfg.dmi_path.clone(),
        no_i8042: cfg.no_i8042,
        no_rtc: cfg.no_rtc,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        oem_strings: cfg.oem_strings.clone(),
        host_cpu_topology: cfg.host_cpu_topology,
        itmt: cfg.itmt,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        force_s2idle: cfg.force_s2idle,
        pvm_fw: pvm_fw_image,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        pcie_ecam: cfg.pcie_ecam,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        pci_low_start: cfg.pci_low_start,
    })
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExitState {
    Reset,
    Stop,
    Crash,
    GuestPanic,
}
// Remove ranges in `guest_mem_layout` that overlap with ranges in `file_backed_mappings`.
// Returns the updated guest memory layout.
fn punch_holes_in_guest_mem_layout_for_mappings(
    guest_mem_layout: Vec<(GuestAddress, u64)>,
    file_backed_mappings: &[FileBackedMappingParameters],
) -> Vec<(GuestAddress, u64)> {
    // Create a set containing (start, end) pairs with exclusive end (end = start + size; the byte
    // at end is not included in the range).
    let mut layout_set = BTreeSet::new();
    for (addr, size) in &guest_mem_layout {
        layout_set.insert((addr.offset(), addr.offset() + size));
    }

    for mapping in file_backed_mappings {
        let mapping_start = mapping.address;
        let mapping_end = mapping_start + mapping.size;

        // Repeatedly split overlapping guest memory regions until no overlaps remain.
        while let Some((range_start, range_end)) = layout_set
            .iter()
            .find(|&&(range_start, range_end)| {
                mapping_start < range_end && mapping_end > range_start
            })
            .cloned()
        {
            layout_set.remove(&(range_start, range_end));

            if range_start < mapping_start {
                layout_set.insert((range_start, mapping_start));
            }
            if range_end > mapping_end {
                layout_set.insert((mapping_end, range_end));
            }
        }
    }

    // Build the final guest memory layout from the modified layout_set.
    layout_set
        .iter()
        .map(|(start, end)| (GuestAddress(*start), end - start))
        .collect()
}

fn run_kvm(cfg: Config, components: VmComponents, guest_mem: GuestMemory) -> Result<ExitState> {
    let kvm = Kvm::new_with_path(&cfg.kvm_device_path).with_context(|| {
        format!(
            "failed to open KVM device {}",
            cfg.kvm_device_path.display(),
        )
    })?;
    let vm = KvmVm::new(&kvm, guest_mem, components.hv_cfg).context("failed to create vm")?;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if cfg.itmt {
        vm.set_platform_info_read_access(false)
            .context("failed to disable MSR_PLATFORM_INFO read access")?;
    }

    if !cfg.userspace_msr.is_empty() {
        vm.enable_userspace_msr()
            .context("failed to enable userspace MSR handling, do you have kernel 5.10 or later")?;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            let msr_list = get_override_msr_list(&cfg.userspace_msr);
            vm.set_msr_filter(msr_list)
                .context("failed to set msr filter")?;
        }
    }

    // Check that the VM was actually created in protected mode as expected.
    if matches!(
        cfg.protection_type,
        ProtectionType::Protected | ProtectionType::ProtectedWithoutFirmware
    ) && !vm.check_capability(VmCap::Protected)
    {
        bail!("Failed to create protected VM");
    }
    let vm_clone = vm.try_clone().context("failed to clone vm")?;

    enum KvmIrqChip {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        Split(KvmSplitIrqChip),
        Kernel(KvmKernelIrqChip),
    }

    impl KvmIrqChip {
        fn as_mut(&mut self) -> &mut dyn IrqChipArch {
            match self {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                KvmIrqChip::Split(i) => i,
                KvmIrqChip::Kernel(i) => i,
            }
        }
    }

    let ioapic_host_tube;
    let mut irq_chip = if cfg.split_irqchip {
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        unimplemented!("KVM split irqchip mode only supported on x86 processors");
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            let (host_tube, ioapic_device_tube) = Tube::pair().context("failed to create tube")?;
            ioapic_host_tube = Some(host_tube);
            KvmIrqChip::Split(
                KvmSplitIrqChip::new(
                    vm_clone,
                    components.vcpu_count,
                    ioapic_device_tube,
                    Some(120),
                )
                .context("failed to create IRQ chip")?,
            )
        }
    } else {
        ioapic_host_tube = None;
        KvmIrqChip::Kernel(
            KvmKernelIrqChip::new(vm_clone, components.vcpu_count)
                .context("failed to create IRQ chip")?,
        )
    };

    run_vm::<KvmVcpu, KvmVm>(cfg, components, vm, irq_chip.as_mut(), ioapic_host_tube)
}

fn get_default_hypervisor() -> Result<HypervisorKind> {
    Ok(HypervisorKind::Kvm)
}

pub fn run_config(cfg: Config) -> Result<ExitState> {
    let components = setup_vm_components(&cfg)?;

    let guest_mem_layout =
        Arch::guest_memory_layout(&components).context("failed to create guest memory layout")?;

    let guest_mem_layout =
        punch_holes_in_guest_mem_layout_for_mappings(guest_mem_layout, &cfg.file_backed_mappings);

    let guest_mem = GuestMemory::new(&guest_mem_layout).context("failed to create guest memory")?;
    let mut mem_policy = MemoryPolicy::empty();
    if components.hugepages {
        mem_policy |= MemoryPolicy::USE_HUGEPAGES;
    }

    if cfg.lock_guest_memory {
        mem_policy |= MemoryPolicy::LOCK_GUEST_MEMORY;
    }
    guest_mem.set_memory_policy(mem_policy);

    let default_hypervisor = get_default_hypervisor().context("no enabled hypervisor")?;
    let hypervisor = cfg.hypervisor.unwrap_or(default_hypervisor);

    debug!("creating {:?} hypervisor", hypervisor);

    match hypervisor {
        HypervisorKind::Kvm => run_kvm(cfg, components, guest_mem),
    }
}

fn run_vm<Vcpu, V>(
    cfg: Config,
    #[allow(unused_mut)] mut components: VmComponents,
    mut vm: V,
    irq_chip: &mut dyn IrqChipArch,
    ioapic_host_tube: Option<Tube>,
) -> Result<ExitState>
where
    Vcpu: VcpuArch + 'static,
    V: VmArch + 'static,
{
    if cfg.jail_config.is_some() {
        // Printing something to the syslog before entering minijail so that libc's syslogger has a
        // chance to open files necessary for its operation, like `/etc/localtime`. After jailing,
        // access to those files will not be possible.
        info!("crosvm entering multiprocess mode");
    }

    #[cfg(feature = "gpu")]
    let (gpu_control_host_tube, gpu_control_device_tube) =
        Tube::pair().context("failed to create gpu tube")?;

    #[cfg(feature = "usb")]
    let (usb_control_tube, usb_provider) =
        HostBackendDeviceProvider::new().context("failed to create usb provider")?;

    // Masking signals is inherently dangerous, since this can persist across clones/execs. Do this
    // before any jailed devices have been spawned, so that we can catch any of them that fail very
    // quickly.
    let sigchld_fd = SignalFd::new(libc::SIGCHLD).context("failed to create signalfd")?;

    let control_server_socket = match &cfg.socket_path {
        Some(path) => Some(UnlinkUnixSeqpacketListener(
            UnixSeqpacketListener::bind(path).context("failed to create control server")?,
        )),
        None => None,
    };

    let mut control_tubes = Vec::new();

    #[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
    if let Some(port) = cfg.gdb {
        // GDB needs a control socket to interrupt vcpus.
        let (gdb_host_tube, gdb_control_tube) = Tube::pair().context("failed to create tube")?;
        control_tubes.push(TaggedControlTube::Vm(gdb_host_tube));
        components.gdb = Some((port, gdb_control_tube));
    }

    #[cfg(feature = "balloon")]
    let (balloon_host_tube, balloon_device_tube) = if cfg.balloon {
        if let Some(ref path) = cfg.balloon_control {
            (
                None,
                Some(Tube::new_from_unix_seqpacket(
                    UnixSeqpacket::connect(path).with_context(|| {
                        format!(
                            "failed to connect to balloon control socket {}",
                            path.display(),
                        )
                    })?,
                )),
            )
        } else {
            // Balloon gets a special socket so balloon requests can be forwarded
            // from the main process.
            let (host, device) = Tube::pair().context("failed to create tube")?;
            // Set recv timeout to avoid deadlock on sending BalloonControlCommand
            // before the guest is ready.
            host.set_recv_timeout(Some(Duration::from_millis(100)))
                .context("failed to set timeout")?;
            (Some(host), Some(device))
        }
    } else {
        (None, None)
    };

    // Create one control socket per disk.
    let mut disk_device_tubes = Vec::new();
    let mut disk_host_tubes = Vec::new();
    let disk_count = cfg.disks.len();
    for _ in 0..disk_count {
        let (disk_host_tub, disk_device_tube) = Tube::pair().context("failed to create tube")?;
        disk_host_tubes.push(disk_host_tub);
        disk_device_tubes.push(disk_device_tube);
    }

    let mut pmem_device_tubes = Vec::new();
    let pmem_count = cfg.pmem_devices.len();
    for _ in 0..pmem_count {
        let (pmem_host_tube, pmem_device_tube) = Tube::pair().context("failed to create tube")?;
        pmem_device_tubes.push(pmem_device_tube);
        control_tubes.push(TaggedControlTube::VmMsync(pmem_host_tube));
    }

    if let Some(ioapic_host_tube) = ioapic_host_tube {
        control_tubes.push(TaggedControlTube::VmIrq(ioapic_host_tube));
    }

    let battery = if cfg.battery_config.is_some() {
        #[cfg_attr(
            not(feature = "power-monitor-powerd"),
            allow(clippy::manual_map, clippy::needless_match)
        )]
        let jail = match simple_jail(&cfg.jail_config, "battery")? {
            #[cfg_attr(not(feature = "power-monitor-powerd"), allow(unused_mut))]
            Some(mut jail) => {
                // Setup a bind mount to the system D-Bus socket if the powerd monitor is used.
                #[cfg(feature = "power-monitor-powerd")]
                {
                    add_current_user_to_jail(&mut jail)?;

                    // Create a tmpfs in the device's root directory so that we can bind mount files.
                    jail.mount_with_data(
                        Path::new("none"),
                        Path::new("/"),
                        "tmpfs",
                        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as usize,
                        "size=67108864",
                    )?;

                    let system_bus_socket_path = Path::new("/run/dbus/system_bus_socket");
                    jail.mount_bind(system_bus_socket_path, system_bus_socket_path, true)?;
                }
                Some(jail)
            }
            None => None,
        };
        (cfg.battery_config.as_ref().map(|c| c.type_), jail)
    } else {
        (cfg.battery_config.as_ref().map(|c| c.type_), None)
    };

    let fs_count = cfg
        .shared_dirs
        .iter()
        .filter(|sd| sd.kind == SharedDirKind::FS)
        .count();
    let mut fs_device_tubes = Vec::with_capacity(fs_count);
    for _ in 0..fs_count {
        let (fs_host_tube, fs_device_tube) = Tube::pair().context("failed to create tube")?;
        control_tubes.push(TaggedControlTube::Fs(fs_host_tube));
        fs_device_tubes.push(fs_device_tube);
    }

    let mut vvu_proxy_device_tubes = Vec::new();
    for _ in 0..cfg.vvu_proxy.len() {
        let (vvu_proxy_host_tube, vvu_proxy_device_tube) =
            Tube::pair().context("failed to create VVU proxy tube")?;
        control_tubes.push(TaggedControlTube::VmMemory {
            tube: vvu_proxy_host_tube,
            expose_with_viommu: false,
        });
        vvu_proxy_device_tubes.push(vvu_proxy_device_tube);
    }

    let (vm_evt_wrtube, vm_evt_rdtube) =
        Tube::directional_pair().context("failed to create vm event tube")?;

    let pstore_size = components.pstore.as_ref().map(|pstore| pstore.size as u64);
    let mut sys_allocator = SystemAllocator::new(
        Arch::get_system_allocator_config(&vm),
        pstore_size,
        &cfg.mmio_address_ranges,
    )
    .context("failed to create system allocator")?;

    let ramoops_region = match &components.pstore {
        Some(pstore) => Some(
            arch::pstore::create_memory_region(
                &mut vm,
                sys_allocator.reserved_region().unwrap(),
                pstore,
            )
            .context("failed to allocate pstore region")?,
        ),
        None => None,
    };

    create_file_backed_mappings(&cfg, &mut vm, &mut sys_allocator)?;

    #[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
    // Hold on to the render server jail so it keeps running until we exit run_vm()
    let (_render_server_jail, render_server_fd) =
        if let Some(parameters) = &cfg.gpu_render_server_parameters {
            let (jail, fd) = start_gpu_render_server(&cfg, parameters)?;
            (Some(ScopedMinijail(jail)), Some(fd))
        } else {
            (None, None)
        };

    #[cfg(feature = "balloon")]
    let init_balloon_size = components
        .memory_size
        .checked_sub(cfg.init_memory.map_or(components.memory_size, |m| {
            m.checked_mul(1024 * 1024).unwrap_or(u64::MAX)
        }))
        .context("failed to calculate init balloon size")?;

    #[cfg(feature = "direct")]
    let mut irqs = Vec::new();

    #[cfg(feature = "direct")]
    for irq in &cfg.direct_level_irq {
        if !sys_allocator.reserve_irq(*irq) {
            warn!("irq {} already reserved.", irq);
        }
        use devices::CrosvmDeviceId;
        let irq_event_source = IrqEventSource {
            device_id: CrosvmDeviceId::DirectIo.into(),
            queue_id: 0,
            device_name: format!("direct edge irq {}", irq),
        };
        let irq_evt = devices::IrqLevelEvent::new().context("failed to create event")?;
        irq_chip
            .register_level_irq_event(*irq, &irq_evt, irq_event_source)
            .unwrap();
        let direct_irq = devices::DirectIrq::new_level(&irq_evt)
            .context("failed to enable interrupt forwarding")?;
        direct_irq
            .irq_enable(*irq)
            .context("failed to enable interrupt forwarding")?;
        irqs.push(direct_irq);
    }

    #[cfg(feature = "direct")]
    for irq in &cfg.direct_edge_irq {
        if !sys_allocator.reserve_irq(*irq) {
            warn!("irq {} already reserved.", irq);
        }
        use devices::CrosvmDeviceId;
        let irq_event_source = IrqEventSource {
            device_id: CrosvmDeviceId::DirectIo.into(),
            queue_id: 0,
            device_name: format!("direct level irq {}", irq),
        };
        let irq_evt = devices::IrqEdgeEvent::new().context("failed to create event")?;
        irq_chip
            .register_edge_irq_event(*irq, &irq_evt, irq_event_source)
            .unwrap();
        let direct_irq = devices::DirectIrq::new_edge(&irq_evt)
            .context("failed to enable interrupt forwarding")?;
        direct_irq
            .irq_enable(*irq)
            .context("failed to enable interrupt forwarding")?;
        irqs.push(direct_irq);
    }

    // Reserve direct mmio range in advance.
    #[cfg(feature = "direct")]
    if let Some(mmio) = &cfg.direct_mmio {
        for range in mmio.ranges.iter() {
            AddressRange::from_start_and_size(range.base, range.len)
                .ok_or(ResourceError::OutOfSpace)
                .and_then(|range| sys_allocator.reserve_mmio(range))
                .with_context(|| {
                    format!(
                        "failed to reserved direct mmio: {:x}-{:x}",
                        range.base,
                        range.base + range.len - 1,
                    )
                })?;
        }
    };

    let mut iommu_attached_endpoints: BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>> =
        BTreeMap::new();
    let mut iova_max_addr: Option<u64> = None;
    let mut devices = create_devices(
        &cfg,
        &mut vm,
        &mut sys_allocator,
        &vm_evt_wrtube,
        &mut iommu_attached_endpoints,
        &mut control_tubes,
        #[cfg(feature = "balloon")]
        balloon_device_tube,
        #[cfg(feature = "balloon")]
        init_balloon_size,
        &mut disk_device_tubes,
        &mut pmem_device_tubes,
        &mut fs_device_tubes,
        #[cfg(feature = "usb")]
        usb_provider,
        #[cfg(feature = "gpu")]
        gpu_control_device_tube,
        #[cfg(all(feature = "gpu", feature = "virgl_renderer_next"))]
        render_server_fd,
        &mut vvu_proxy_device_tubes,
        components.memory_size,
        &mut iova_max_addr,
    )?;

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    let hp_endpoints_ranges: Vec<RangeInclusive<u32>> = Vec::new();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let mut hp_endpoints_ranges: Vec<RangeInclusive<u32>> = Vec::new();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let mut hotplug_buses: Vec<(u8, Arc<Mutex<dyn HotPlugBus>>)> = Vec::new();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let mut gpe_notify_devs: Vec<(u32, Arc<Mutex<dyn GpeNotify>>)> = Vec::new();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "direct")]
        let rp_host = cfg.pcie_rp.clone();
        #[cfg(not(feature = "direct"))]
        let rp_host: Vec<HostPcieRootPortParameters> = Vec::new();

        // Create Pcie Root Port
        create_pcie_root_port(
            rp_host,
            &mut sys_allocator,
            &mut control_tubes,
            &mut devices,
            &mut hotplug_buses,
            &mut hp_endpoints_ranges,
            &mut gpe_notify_devs,
        )?;
    }

    arch::assign_pci_addresses(&mut devices, &mut sys_allocator)?;

    let (translate_response_senders, request_rx) = setup_virtio_access_platform(
        &mut sys_allocator,
        &mut iommu_attached_endpoints,
        &mut devices,
    )?;

    let iommu_host_tube = if !iommu_attached_endpoints.is_empty()
        || (cfg.vfio_isolate_hotplug && !hp_endpoints_ranges.is_empty())
    {
        let (iommu_host_tube, iommu_device_tube) = Tube::pair().context("failed to create tube")?;
        let iommu_dev = create_iommu_device(
            cfg.protection_type,
            &cfg.jail_config,
            iova_max_addr.unwrap_or(u64::MAX),
            iommu_attached_endpoints,
            hp_endpoints_ranges,
            translate_response_senders,
            request_rx,
            iommu_device_tube,
        )?;

        let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
        control_tubes.push(TaggedControlTube::VmIrq(msi_host_tube));
        let mut dev = VirtioPciDevice::new(
            vm.get_memory().clone(),
            iommu_dev.dev,
            msi_device_tube,
            cfg.disable_virtio_intx,
            None,
        )
        .context("failed to create virtio pci dev")?;
        // early reservation for viommu.
        dev.allocate_address(&mut sys_allocator)
            .context("failed to allocate resources early for virtio pci dev")?;
        let dev = Box::new(dev);
        devices.push((dev, iommu_dev.jail));
        Some(iommu_host_tube)
    } else {
        None
    };

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    for device in devices
        .iter_mut()
        .filter_map(|(dev, _)| dev.as_pci_device_mut())
    {
        let sdts = device
            .generate_acpi(components.acpi_sdts)
            .or_else(|| {
                error!("ACPI table generation error");
                None
            })
            .ok_or_else(|| anyhow!("failed to generate ACPI table"))?;
        components.acpi_sdts = sdts;
    }

    // KVM_CREATE_VCPU uses apic id for x86 and uses cpu id for others.
    let mut vcpu_ids = Vec::new();

    #[cfg_attr(not(feature = "direct"), allow(unused_mut))]
    let mut linux = Arch::build_vm::<V, Vcpu>(
        components,
        &vm_evt_wrtube,
        &mut sys_allocator,
        &cfg.serial_parameters,
        simple_jail(&cfg.jail_config, "serial_device")?,
        battery,
        vm,
        ramoops_region,
        devices,
        irq_chip,
        &mut vcpu_ids,
        simple_jail(&cfg.jail_config, "serial_device")?,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        simple_jail(&cfg.jail_config, "block_device")?,
    )
    .context("the architecture failed to build the vm")?;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let (hp_control_tube, hp_worker_tube) = mpsc::channel();

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        for (bus_num, hp_bus) in hotplug_buses {
            linux.hotplug_bus.insert(bus_num, hp_bus);
        }

        if let Some(pm) = &linux.pm {
            while let Some((gpe, notify_dev)) = gpe_notify_devs.pop() {
                pm.lock().register_gpe_notify_dev(gpe, notify_dev);
            }
        }

        let pci_root = linux.root_config.clone();
        thread::Builder::new()
            .name("pci_root".to_string())
            .spawn(move || start_pci_root_worker(pci_root, hp_worker_tube))?;
    }

    #[cfg(feature = "direct")]
    if let Some(pmio) = &cfg.direct_pmio {
        let direct_io = Arc::new(
            devices::DirectIo::new(&pmio.path, false).context("failed to open direct io device")?,
        );
        for range in pmio.ranges.iter() {
            linux
                .io_bus
                .insert_sync(direct_io.clone(), range.base, range.len)
                .context("Error with pmio")?;
        }
    };

    #[cfg(feature = "direct")]
    if let Some(mmio) = &cfg.direct_mmio {
        let direct_mmio = Arc::new(
            devices::DirectMmio::new(&mmio.path, false, &mmio.ranges)
                .context("failed to open direct mmio device")?,
        );

        for range in mmio.ranges.iter() {
            linux
                .mmio_bus
                .insert_sync(direct_mmio.clone(), range.base, range.len)
                .context("Error with mmio")?;
        }
    };

    let gralloc = RutabagaGralloc::new().context("failed to create gralloc")?;
    run_control(
        linux,
        sys_allocator,
        cfg,
        control_server_socket,
        control_tubes,
        #[cfg(feature = "balloon")]
        balloon_host_tube,
        &disk_host_tubes,
        #[cfg(feature = "gpu")]
        gpu_control_host_tube,
        #[cfg(feature = "usb")]
        usb_control_tube,
        vm_evt_rdtube,
        vm_evt_wrtube,
        sigchld_fd,
        gralloc,
        vcpu_ids,
        iommu_host_tube,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        hp_control_tube,
    )
}

// Hotplug command is facing dead lock issue when it tries to acquire the lock
// for pci root in the vm control thread. Dead lock could happen when the vm
// control thread(Thread A namely) is handling the hotplug command and it tries
// to get the lock for pci root. However, the lock is already hold by another
// device in thread B, which is actively sending an vm control to be handled by
// thread A and waiting for response. However, thread A is blocked on acquiring
// the lock, so dead lock happens. In order to resolve this issue, we add this
// worker thread and push all work that locks pci root to this thread.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn start_pci_root_worker(
    pci_root: Arc<Mutex<PciRoot>>,
    hp_device_tube: mpsc::Receiver<PciRootCommand>,
) {
    loop {
        match hp_device_tube.recv() {
            Ok(cmd) => match cmd {
                PciRootCommand::Add(addr, device) => {
                    pci_root.lock().add_device(addr, device);
                }
                PciRootCommand::AddBridge(pci_bus) => pci_root.lock().add_bridge(pci_bus),
                PciRootCommand::Remove(addr) => {
                    pci_root.lock().remove_device(addr);
                }
                PciRootCommand::Kill => break,
            },
            Err(e) => {
                error!("Error: pci root worker channel closed: {}", e);
                break;
            }
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn get_hp_bus<V: VmArch, Vcpu: VcpuArch>(
    linux: &RunnableLinuxVm<V, Vcpu>,
    host_addr: PciAddress,
) -> Result<Arc<Mutex<dyn HotPlugBus>>> {
    for (_, hp_bus) in linux.hotplug_bus.iter() {
        if hp_bus.lock().is_match(host_addr).is_some() {
            return Ok(hp_bus.clone());
        }
    }
    Err(anyhow!("Failed to find a suitable hotplug bus"))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn add_hotplug_device<V: VmArch, Vcpu: VcpuArch>(
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    cfg: &Config,
    control_tubes: &mut Vec<TaggedControlTube>,
    hp_control_tube: &mpsc::Sender<PciRootCommand>,
    iommu_host_tube: &Option<Tube>,
    device: &HotPlugDeviceInfo,
) -> Result<()> {
    let host_addr = PciAddress::from_path(&device.path)
        .context("failed to parse hotplug device's PCI address")?;
    let hp_bus = get_hp_bus(linux, host_addr)?;

    let (host_key, pci_address) = match device.device_type {
        HotPlugDeviceType::UpstreamPort | HotPlugDeviceType::DownstreamPort => {
            let (vm_host_tube, vm_device_tube) = Tube::pair().context("failed to create tube")?;
            control_tubes.push(TaggedControlTube::Vm(vm_host_tube));
            let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
            control_tubes.push(TaggedControlTube::VmIrq(msi_host_tube));
            let pcie_host = PcieHostPort::new(device.path.as_path(), vm_device_tube)?;
            let (host_key, pci_bridge) = match device.device_type {
                HotPlugDeviceType::UpstreamPort => {
                    let host_key = HostHotPlugKey::UpstreamPort { host_addr };
                    let pcie_upstream_port = Arc::new(Mutex::new(PcieUpstreamPort::new_from_host(
                        pcie_host, true,
                    )?));
                    let pci_bridge =
                        Box::new(PciBridge::new(pcie_upstream_port.clone(), msi_device_tube));
                    linux
                        .hotplug_bus
                        .insert(pci_bridge.get_secondary_num(), pcie_upstream_port);
                    (host_key, pci_bridge)
                }
                HotPlugDeviceType::DownstreamPort => {
                    let host_key = HostHotPlugKey::DownstreamPort { host_addr };
                    let pcie_downstream_port = Arc::new(Mutex::new(
                        PcieDownstreamPort::new_from_host(pcie_host, true)?,
                    ));
                    let pci_bridge = Box::new(PciBridge::new(
                        pcie_downstream_port.clone(),
                        msi_device_tube,
                    ));
                    linux
                        .hotplug_bus
                        .insert(pci_bridge.get_secondary_num(), pcie_downstream_port);
                    (host_key, pci_bridge)
                }
                _ => {
                    bail!("Impossible to reach here")
                }
            };
            let pci_address =
                Arch::register_pci_device(linux, pci_bridge, None, sys_allocator, hp_control_tube)?;

            (host_key, pci_address)
        }
        HotPlugDeviceType::EndPoint => {
            let host_key = HostHotPlugKey::Vfio { host_addr };
            let (vfio_pci_device, jail, viommu_mapper) = create_vfio_device(
                &cfg.jail_config,
                &linux.vm,
                sys_allocator,
                control_tubes,
                &device.path,
                true,
                None,
                None,
                None,
                if iommu_host_tube.is_some() {
                    IommuDevType::VirtioIommu
                } else {
                    IommuDevType::NoIommu
                },
                #[cfg(feature = "direct")]
                false,
            )?;
            let pci_address = Arch::register_pci_device(
                linux,
                vfio_pci_device,
                jail,
                sys_allocator,
                hp_control_tube,
            )?;
            if let Some(iommu_host_tube) = iommu_host_tube {
                let endpoint_addr = pci_address.to_u32();
                let vfio_wrapper = viommu_mapper.context("expected mapper")?;
                let descriptor = vfio_wrapper.clone_as_raw_descriptor()?;
                let request =
                    VirtioIOMMURequest::VfioCommand(VirtioIOMMUVfioCommand::VfioDeviceAdd {
                        endpoint_addr,
                        wrapper_id: vfio_wrapper.id(),
                        container: {
                            // Safe because the descriptor is uniquely owned by `descriptor`.
                            unsafe { File::from_raw_descriptor(descriptor) }
                        },
                    });
                match virtio_iommu_request(iommu_host_tube, &request)
                    .map_err(|_| VirtioIOMMUVfioError::SocketFailed)?
                {
                    VirtioIOMMUResponse::VfioResponse(VirtioIOMMUVfioResult::Ok) => (),
                    resp => bail!("Unexpected message response: {:?}", resp),
                }
            }

            (host_key, pci_address)
        }
    };
    hp_bus.lock().add_hotplug_device(host_key, pci_address);
    if device.hp_interrupt {
        hp_bus.lock().hot_plug(pci_address);
    }
    Ok(())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn remove_hotplug_bridge<V: VmArch, Vcpu: VcpuArch>(
    linux: &RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    hp_control_tube: &mpsc::Sender<PciRootCommand>,
    buses_to_remove: &mut Vec<u8>,
    host_key: HostHotPlugKey,
    child_bus: u8,
) -> Result<()> {
    for (bus_num, hp_bus) in linux.hotplug_bus.iter() {
        let mut hp_bus_lock = hp_bus.lock();
        if let Some(pci_addr) = hp_bus_lock.get_hotplug_device(host_key) {
            sys_allocator.release_pci(pci_addr.bus, pci_addr.dev, pci_addr.func);
            hp_bus_lock.hot_unplug(pci_addr);
            buses_to_remove.push(child_bus);
            if hp_bus_lock.is_empty() {
                if let Some(hotplug_key) = hp_bus_lock.get_hotplug_key() {
                    remove_hotplug_bridge(
                        linux,
                        sys_allocator,
                        hp_control_tube,
                        buses_to_remove,
                        hotplug_key,
                        *bus_num,
                    )?;
                }
            }
            return Ok(());
        }
    }

    Err(anyhow!(
        "Can not find device {:?} on hotplug buses",
        host_key
    ))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn remove_hotplug_device<V: VmArch, Vcpu: VcpuArch>(
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    hp_control_tube: &mpsc::Sender<PciRootCommand>,
    iommu_host_tube: &Option<Tube>,
    device: &HotPlugDeviceInfo,
) -> Result<()> {
    let host_addr = PciAddress::from_path(&device.path)?;
    let host_key = match device.device_type {
        HotPlugDeviceType::UpstreamPort => HostHotPlugKey::UpstreamPort { host_addr },
        HotPlugDeviceType::DownstreamPort => HostHotPlugKey::DownstreamPort { host_addr },
        HotPlugDeviceType::EndPoint => HostHotPlugKey::Vfio { host_addr },
    };

    let hp_bus = linux
        .hotplug_bus
        .iter()
        .find(|(_, hp_bus)| {
            let hp_bus = hp_bus.lock();
            hp_bus.get_hotplug_device(host_key).is_some()
        })
        .map(|(bus_num, hp_bus)| (*bus_num, hp_bus.clone()));

    if let Some((bus_num, hp_bus)) = hp_bus {
        let mut buses_to_remove = Vec::new();
        let mut removed_key = None;
        let mut hp_bus_lock = hp_bus.lock();
        if let Some(pci_addr) = hp_bus_lock.get_hotplug_device(host_key) {
            if let Some(iommu_host_tube) = iommu_host_tube {
                let request =
                    VirtioIOMMURequest::VfioCommand(VirtioIOMMUVfioCommand::VfioDeviceDel {
                        endpoint_addr: pci_addr.to_u32(),
                    });
                match virtio_iommu_request(iommu_host_tube, &request)
                    .map_err(|_| VirtioIOMMUVfioError::SocketFailed)?
                {
                    VirtioIOMMUResponse::VfioResponse(VirtioIOMMUVfioResult::Ok) => (),
                    resp => bail!("Unexpected message response: {:?}", resp),
                }
            }
            let mut empty_simbling = true;
            if let Some(HostHotPlugKey::DownstreamPort { host_addr }) =
                hp_bus_lock.get_hotplug_key()
            {
                let addr_alias = host_addr;
                for (simbling_bus_num, hp_bus) in linux.hotplug_bus.iter() {
                    if *simbling_bus_num != bus_num {
                        let hp_bus_lock = hp_bus.lock();
                        let hotplug_key = hp_bus_lock.get_hotplug_key();
                        if let Some(HostHotPlugKey::DownstreamPort { host_addr }) = hotplug_key {
                            if addr_alias.bus == host_addr.bus && !hp_bus_lock.is_empty() {
                                empty_simbling = false;
                                break;
                            }
                        }
                    }
                }
            }

            // If all simbling downstream ports are empty, do not send hot unplug event for this
            // downstream port. Root port will send one plug out interrupt and remove all
            // the remaining devices
            if !empty_simbling {
                hp_bus_lock.hot_unplug(pci_addr);
            }

            sys_allocator.release_pci(pci_addr.bus, pci_addr.dev, pci_addr.func);
            if empty_simbling || hp_bus_lock.is_empty() {
                if let Some(hotplug_key) = hp_bus_lock.get_hotplug_key() {
                    removed_key = Some(hotplug_key);
                    remove_hotplug_bridge(
                        linux,
                        sys_allocator,
                        hp_control_tube,
                        &mut buses_to_remove,
                        hotplug_key,
                        bus_num,
                    )?;
                }
            }
        }

        // Some types of TBT device has a few empty downstream ports. The emulated bridges
        // of these ports won't be removed since no vfio device is connected to our emulated
        // bridges. So we explicitly check all simbling bridges of the removed bridge here,
        // and remove them if bridge has no child device connected.
        if let Some(HostHotPlugKey::DownstreamPort { host_addr }) = removed_key {
            let addr_alias = host_addr;
            for (simbling_bus_num, hp_bus) in linux.hotplug_bus.iter() {
                if *simbling_bus_num != bus_num {
                    let hp_bus_lock = hp_bus.lock();
                    let hotplug_key = hp_bus_lock.get_hotplug_key();
                    if let Some(HostHotPlugKey::DownstreamPort { host_addr }) = hotplug_key {
                        if addr_alias.bus == host_addr.bus && hp_bus_lock.is_empty() {
                            remove_hotplug_bridge(
                                linux,
                                sys_allocator,
                                hp_control_tube,
                                &mut buses_to_remove,
                                hotplug_key.unwrap(),
                                *simbling_bus_num,
                            )?;
                        }
                    }
                }
            }
        }
        for bus in buses_to_remove.iter() {
            linux.hotplug_bus.remove(bus);
        }
        return Ok(());
    }

    Err(anyhow!(
        "Can not find device {:?} on hotplug buses",
        host_key
    ))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn handle_hotplug_command<V: VmArch, Vcpu: VcpuArch>(
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    cfg: &Config,
    add_tubes: &mut Vec<TaggedControlTube>,
    hp_control_tube: &mpsc::Sender<PciRootCommand>,
    iommu_host_tube: &Option<Tube>,
    device: &HotPlugDeviceInfo,
    add: bool,
) -> VmResponse {
    let iommu_host_tube = if cfg.vfio_isolate_hotplug {
        iommu_host_tube
    } else {
        &None
    };
    let ret = if add {
        add_hotplug_device(
            linux,
            sys_allocator,
            cfg,
            add_tubes,
            hp_control_tube,
            iommu_host_tube,
            device,
        )
    } else {
        remove_hotplug_device(
            linux,
            sys_allocator,
            hp_control_tube,
            iommu_host_tube,
            device,
        )
    };

    match ret {
        Ok(()) => VmResponse::Ok,
        Err(e) => {
            error!("hanlde_hotplug_command failure: {}", e);
            add_tubes.clear();
            VmResponse::Err(base::Error::new(libc::EINVAL))
        }
    }
}

fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
    mut linux: RunnableLinuxVm<V, Vcpu>,
    mut sys_allocator: SystemAllocator,
    cfg: Config,
    control_server_socket: Option<UnlinkUnixSeqpacketListener>,
    mut control_tubes: Vec<TaggedControlTube>,
    #[cfg(feature = "balloon")] balloon_host_tube: Option<Tube>,
    disk_host_tubes: &[Tube],
    #[cfg(feature = "gpu")] gpu_control_tube: Tube,
    #[cfg(feature = "usb")] usb_control_tube: Tube,
    vm_evt_rdtube: RecvTube,
    vm_evt_wrtube: SendTube,
    sigchld_fd: SignalFd,
    mut gralloc: RutabagaGralloc,
    vcpu_ids: Vec<usize>,
    iommu_host_tube: Option<Tube>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] hp_control_tube: mpsc::Sender<
        PciRootCommand,
    >,
) -> Result<ExitState> {
    #[derive(EventToken)]
    enum Token {
        VmEvent,
        Suspend,
        ChildSignal,
        IrqFd { index: IrqEventIndex },
        VmControlServer,
        VmControl { index: usize },
        DelayedIrqFd,
    }

    let mut iommu_client = iommu_host_tube
        .as_ref()
        .map(VmMemoryRequestIommuClient::new);

    stdin()
        .set_raw_mode()
        .expect("failed to set terminal raw mode");

    let wait_ctx = WaitContext::build_with(&[
        (&linux.suspend_evt, Token::Suspend),
        (&sigchld_fd, Token::ChildSignal),
        (&vm_evt_rdtube, Token::VmEvent),
    ])
    .context("failed to add descriptor to wait context")?;

    if let Some(socket_server) = &control_server_socket {
        wait_ctx
            .add(socket_server, Token::VmControlServer)
            .context("failed to add descriptor to wait context")?;
    }
    for (index, socket) in control_tubes.iter().enumerate() {
        wait_ctx
            .add(socket.as_ref(), Token::VmControl { index })
            .context("failed to add descriptor to wait context")?;
    }

    let events = linux
        .irq_chip
        .irq_event_tokens()
        .context("failed to add descriptor to wait context")?;

    for (index, _gsi, evt) in events {
        wait_ctx
            .add(&evt, Token::IrqFd { index })
            .context("failed to add descriptor to wait context")?;
    }

    if let Some(delayed_ioapic_irq_trigger) = linux.irq_chip.irq_delayed_event_token()? {
        wait_ctx
            .add(&delayed_ioapic_irq_trigger, Token::DelayedIrqFd)
            .context("failed to add descriptor to wait context")?;
    }

    if cfg.jail_config.is_some() {
        // Before starting VCPUs, in case we started with some capabilities, drop them all.
        drop_capabilities().context("failed to drop process capabilities")?;
    }

    #[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
    // Create a channel for GDB thread.
    let (to_gdb_channel, from_vcpu_channel) = if linux.gdb.is_some() {
        let (s, r) = mpsc::channel();
        (Some(s), Some(r))
    } else {
        (None, None)
    };

    let mut vcpu_handles = Vec::with_capacity(linux.vcpu_count);
    let vcpu_thread_barrier = Arc::new(Barrier::new(linux.vcpu_count + 1));
    let use_hypervisor_signals = !linux
        .vm
        .get_hypervisor()
        .check_capability(HypervisorCap::ImmediateExit);
    vcpu::setup_vcpu_signal_handler::<Vcpu>(use_hypervisor_signals)?;

    let vcpus: Vec<Option<_>> = match linux.vcpus.take() {
        Some(vec) => vec.into_iter().map(Some).collect(),
        None => iter::repeat_with(|| None).take(linux.vcpu_count).collect(),
    };
    // Enable core scheduling before creating vCPUs so that the cookie will be
    // shared by all vCPU threads.
    // TODO(b/199312402): Avoid enabling core scheduling for the crosvm process
    // itself for even better performance. Only vCPUs need the feature.
    if cfg.per_vm_core_scheduling {
        if let Err(e) = enable_core_scheduling() {
            error!("Failed to enable core scheduling: {}", e);
        }
    }
    let vcpu_cgroup_tasks_file = match &cfg.vcpu_cgroup_path {
        None => None,
        Some(cgroup_path) => {
            // Move main process to cgroup_path
            let mut f = File::create(&cgroup_path.join("tasks")).with_context(|| {
                format!(
                    "failed to create vcpu-cgroup-path {}",
                    cgroup_path.display(),
                )
            })?;
            f.write_all(process::id().to_string().as_bytes())?;
            Some(f)
        }
    };

    #[cfg(target_os = "android")]
    android::set_process_profiles(&cfg.task_profiles)?;

    let guest_suspended_cvar = Arc::new((Mutex::new(false), Condvar::new()));

    // Architecture-specific code must supply a vcpu_init element for each VCPU.
    assert_eq!(vcpus.len(), linux.vcpu_init.len());

    for ((cpu_id, vcpu), vcpu_init) in vcpus.into_iter().enumerate().zip(linux.vcpu_init.drain(..))
    {
        let (to_vcpu_channel, from_main_channel) = mpsc::channel();
        let vcpu_affinity = match linux.vcpu_affinity.clone() {
            Some(VcpuAffinity::Global(v)) => v,
            Some(VcpuAffinity::PerVcpu(mut m)) => m.remove(&cpu_id).unwrap_or_default(),
            None => Default::default(),
        };

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let cpu_config = Some(CpuConfigX86_64::new(
            cfg.force_calibrated_tsc_leaf,
            cfg.host_cpu_topology,
            cfg.enable_hwp,
            cfg.enable_pnp_data,
            cfg.no_smt,
            cfg.itmt,
        ));

        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        let cpu_config = None;

        let handle = vcpu::run_vcpu(
            cpu_id,
            vcpu_ids[cpu_id],
            vcpu,
            vcpu_init,
            linux.vm.try_clone().context("failed to clone vm")?,
            linux
                .irq_chip
                .try_box_clone()
                .context("failed to clone irqchip")?,
            linux.vcpu_count,
            linux.rt_cpus.contains(&cpu_id),
            vcpu_affinity,
            linux.delay_rt,
            vcpu_thread_barrier.clone(),
            linux.has_bios,
            (*linux.io_bus).clone(),
            (*linux.mmio_bus).clone(),
            vm_evt_wrtube
                .try_clone()
                .context("failed to clone vm event tube")?,
            linux.vm.check_capability(VmCap::PvClockSuspend),
            from_main_channel,
            use_hypervisor_signals,
            #[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
            to_gdb_channel.clone(),
            cfg.per_vm_core_scheduling,
            cpu_config,
            cfg.privileged_vm,
            match vcpu_cgroup_tasks_file {
                None => None,
                Some(ref f) => Some(
                    f.try_clone()
                        .context("failed to clone vcpu cgroup tasks file")?,
                ),
            },
            cfg.userspace_msr.clone(),
            guest_suspended_cvar.clone(),
        )?;
        vcpu_handles.push((handle, to_vcpu_channel));
    }

    #[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
    // Spawn GDB thread.
    if let Some((gdb_port_num, gdb_control_tube)) = linux.gdb.take() {
        let to_vcpu_channels = vcpu_handles
            .iter()
            .map(|(_handle, channel)| channel.clone())
            .collect();
        let target = GdbStub::new(
            gdb_control_tube,
            to_vcpu_channels,
            from_vcpu_channel.unwrap(), // Must succeed to unwrap()
        );
        thread::Builder::new()
            .name("gdb".to_owned())
            .spawn(move || gdb_thread(target, gdb_port_num))
            .context("failed to spawn GDB thread")?;
    };

    vcpu_thread_barrier.wait();

    let mut exit_state = ExitState::Stop;
    let mut pvpanic_code = PvPanicCode::Unknown;
    #[cfg(feature = "balloon")]
    let mut balloon_stats_id: u64 = 0;

    'wait: loop {
        let events = {
            match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to poll: {}", e);
                    break;
                }
            }
        };

        let mut vm_control_indices_to_remove = Vec::new();
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::VmEvent => {
                    let mut break_to_wait: bool = true;
                    match vm_evt_rdtube.recv::<VmEventType>() {
                        Ok(vm_event) => match vm_event {
                            VmEventType::Exit => {
                                info!("vcpu requested shutdown");
                                exit_state = ExitState::Stop;
                            }
                            VmEventType::Reset => {
                                info!("vcpu requested reset");
                                exit_state = ExitState::Reset;
                            }
                            VmEventType::Crash => {
                                info!("vcpu crashed");
                                exit_state = ExitState::Crash;
                            }
                            VmEventType::Panic(panic_code) => {
                                pvpanic_code = PvPanicCode::from_u8(panic_code);
                                info!("Guest reported panic [Code: {}]", pvpanic_code);
                                break_to_wait = false;
                            }
                        },
                        Err(e) => {
                            warn!("failed to recv VmEvent: {}", e);
                        }
                    }
                    if break_to_wait {
                        if pvpanic_code == PvPanicCode::Panicked {
                            exit_state = ExitState::GuestPanic;
                        }
                        break 'wait;
                    }
                }
                Token::Suspend => {
                    info!("VM requested suspend");
                    linux.suspend_evt.read().unwrap();
                    vcpu::kick_all_vcpus(
                        &vcpu_handles,
                        linux.irq_chip.as_irq_chip(),
                        VcpuControl::RunState(VmRunMode::Suspending),
                    );
                }
                Token::ChildSignal => {
                    // Print all available siginfo structs, then exit the loop.
                    while let Some(siginfo) =
                        sigchld_fd.read().context("failed to create signalfd")?
                    {
                        let pid = siginfo.ssi_pid;
                        let pid_label = match linux.pid_debug_label_map.get(&pid) {
                            Some(label) => format!("{} (pid {})", label, pid),
                            None => format!("pid {}", pid),
                        };
                        error!(
                            "child {} died: signo {}, status {}, code {}",
                            pid_label, siginfo.ssi_signo, siginfo.ssi_status, siginfo.ssi_code
                        );
                    }
                    break 'wait;
                }
                Token::IrqFd { index } => {
                    if let Err(e) = linux.irq_chip.service_irq_event(index) {
                        error!("failed to signal irq {}: {}", index, e);
                    }
                }
                Token::DelayedIrqFd => {
                    if let Err(e) = linux.irq_chip.process_delayed_irq_events() {
                        warn!("can't deliver delayed irqs: {}", e);
                    }
                }
                Token::VmControlServer => {
                    if let Some(socket_server) = &control_server_socket {
                        match socket_server.accept() {
                            Ok(socket) => {
                                wait_ctx
                                    .add(
                                        &socket,
                                        Token::VmControl {
                                            index: control_tubes.len(),
                                        },
                                    )
                                    .context("failed to add descriptor to wait context")?;
                                control_tubes.push(TaggedControlTube::Vm(
                                    Tube::new_from_unix_seqpacket(socket),
                                ));
                            }
                            Err(e) => error!("failed to accept socket: {}", e),
                        }
                    }
                }
                Token::VmControl { index } => {
                    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                    let mut add_tubes = Vec::new();
                    if let Some(socket) = control_tubes.get(index) {
                        match socket {
                            TaggedControlTube::Vm(tube) => match tube.recv::<VmRequest>() {
                                Ok(request) => {
                                    let mut run_mode_opt = None;
                                    let response = match request {
                                        VmRequest::HotPlugCommand { device, add } => {
                                            #[cfg(any(
                                                target_arch = "x86",
                                                target_arch = "x86_64"
                                            ))]
                                            {
                                                handle_hotplug_command(
                                                    &mut linux,
                                                    &mut sys_allocator,
                                                    &cfg,
                                                    &mut add_tubes,
                                                    &hp_control_tube,
                                                    &iommu_host_tube,
                                                    &device,
                                                    add,
                                                )
                                            }

                                            #[cfg(not(any(
                                                target_arch = "x86",
                                                target_arch = "x86_64"
                                            )))]
                                            VmResponse::Ok
                                        }
                                        _ => request.execute(
                                            &mut run_mode_opt,
                                            #[cfg(feature = "balloon")]
                                            balloon_host_tube.as_ref(),
                                            #[cfg(feature = "balloon")]
                                            &mut balloon_stats_id,
                                            disk_host_tubes,
                                            &mut linux.pm,
                                            #[cfg(feature = "gpu")]
                                            &gpu_control_tube,
                                            #[cfg(feature = "usb")]
                                            Some(&usb_control_tube),
                                            #[cfg(not(feature = "usb"))]
                                            None,
                                            &mut linux.bat_control,
                                            &vcpu_handles,
                                            cfg.force_s2idle,
                                            guest_suspended_cvar.clone(),
                                        ),
                                    };

                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmResponse: {}", e);
                                    }
                                    if let Some(run_mode) = run_mode_opt {
                                        info!("control socket changed run mode to {}", run_mode);
                                        match run_mode {
                                            VmRunMode::Exiting => {
                                                break 'wait;
                                            }
                                            other => {
                                                if other == VmRunMode::Running {
                                                    for dev in &linux.resume_notify_devices {
                                                        dev.lock().resume_imminent();
                                                    }
                                                }
                                                vcpu::kick_all_vcpus(
                                                    &vcpu_handles,
                                                    linux.irq_chip.as_irq_chip(),
                                                    VcpuControl::RunState(other),
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    if let TubeError::Disconnected = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmRequest: {}", e);
                                    }
                                }
                            },
                            TaggedControlTube::VmMemory {
                                tube,
                                expose_with_viommu,
                            } => match tube.recv::<VmMemoryRequest>() {
                                Ok(request) => {
                                    let response = request.execute(
                                        &mut linux.vm,
                                        &mut sys_allocator,
                                        &mut gralloc,
                                        if *expose_with_viommu {
                                            iommu_client.as_mut()
                                        } else {
                                            None
                                        },
                                    );
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmMemoryControlResponse: {}", e);
                                    }
                                }
                                Err(e) => {
                                    if let TubeError::Disconnected = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmMemoryControlRequest: {}", e);
                                    }
                                }
                            },
                            TaggedControlTube::VmIrq(tube) => match tube.recv::<VmIrqRequest>() {
                                Ok(request) => {
                                    let response = {
                                        let irq_chip = &mut linux.irq_chip;
                                        request.execute(
                                            |setup| match setup {
                                                IrqSetup::Event(irq, ev, device_id, queue_id, device_name) => {
                                                    let irq_evt = devices::IrqEdgeEvent::from_event(ev.try_clone()?);
                                                    let source = IrqEventSource{
                                                        device_id: device_id.try_into().expect("Invalid device_id"),
                                                        queue_id,
                                                        device_name,
                                                    };
                                                    if let Some(event_index) = irq_chip
                                                        .register_edge_irq_event(irq, &irq_evt, source)?
                                                    {
                                                        match wait_ctx.add(
                                                            ev,
                                                            Token::IrqFd {
                                                                index: event_index
                                                            },
                                                        ) {
                                                            Err(e) => {
                                                                warn!("failed to add IrqFd to poll context: {}", e);
                                                                Err(e)
                                                            },
                                                            Ok(_) => {
                                                                Ok(())
                                                            }
                                                        }
                                                    } else {
                                                        Ok(())
                                                    }
                                                }
                                                IrqSetup::Route(route) => irq_chip.route_irq(route),
                                                IrqSetup::UnRegister(irq, ev) => {
                                                    let irq_evt = devices::IrqEdgeEvent::from_event(ev.try_clone()?);
                                                    irq_chip.unregister_edge_irq_event(irq, &irq_evt)
                                                }
                                            },
                                            &mut sys_allocator,
                                        )
                                    };
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmIrqResponse: {}", e);
                                    }
                                }
                                Err(e) => {
                                    if let TubeError::Disconnected = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmIrqRequest: {}", e);
                                    }
                                }
                            },
                            TaggedControlTube::VmMsync(tube) => {
                                match tube.recv::<VmMsyncRequest>() {
                                    Ok(request) => {
                                        let response = request.execute(&mut linux.vm);
                                        if let Err(e) = tube.send(&response) {
                                            error!("failed to send VmMsyncResponse: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        if let TubeError::Disconnected = e {
                                            vm_control_indices_to_remove.push(index);
                                        } else {
                                            error!("failed to recv VmMsyncRequest: {}", e);
                                        }
                                    }
                                }
                            }
                            TaggedControlTube::Fs(tube) => match tube.recv::<FsMappingRequest>() {
                                Ok(request) => {
                                    let response =
                                        request.execute(&mut linux.vm, &mut sys_allocator);
                                    if let Err(e) = tube.send(&response) {
                                        error!("failed to send VmResponse: {}", e);
                                    }
                                }
                                Err(e) => {
                                    if let TubeError::Disconnected = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmResponse: {}", e);
                                    }
                                }
                            },
                        }
                    }
                    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                    if !add_tubes.is_empty() {
                        for (idx, socket) in add_tubes.iter().enumerate() {
                            wait_ctx
                                .add(
                                    socket.as_ref(),
                                    Token::VmControl {
                                        index: idx + control_tubes.len(),
                                    },
                                )
                                .context(
                                    "failed to add hotplug vfio-pci descriptor to wait context",
                                )?;
                        }
                        control_tubes.append(&mut add_tubes);
                    }
                }
            }
        }

        // It's possible more data is readable and buffered while the socket is hungup,
        // so don't delete the tube from the poll context until we're sure all the
        // data is read.
        // Below case covers a condition where we have received a hungup event and the tube is not
        // readable.
        // In case of readable tube, once all data is read, any attempt to read more data on hungup
        // tube should fail. On such failure, we get Disconnected error and index gets added to
        // vm_control_indices_to_remove by the time we reach here.
        for event in events.iter().filter(|e| e.is_hungup && !e.is_readable) {
            if let Token::VmControl { index } = event.token {
                vm_control_indices_to_remove.push(index);
            }
        }

        // Sort in reverse so the highest indexes are removed first. This removal algorithm
        // preserves correct indexes as each element is removed.
        vm_control_indices_to_remove.sort_unstable_by_key(|&k| Reverse(k));
        vm_control_indices_to_remove.dedup();
        for index in vm_control_indices_to_remove {
            // Delete the socket from the `wait_ctx` synchronously. Otherwise, the kernel will do
            // this automatically when the FD inserted into the `wait_ctx` is closed after this
            // if-block, but this removal can be deferred unpredictably. In some instances where the
            // system is under heavy load, we can even get events returned by `wait_ctx` for an FD
            // that has already been closed. Because the token associated with that spurious event
            // now belongs to a different socket, the control loop will start to interact with
            // sockets that might not be ready to use. This can cause incorrect hangup detection or
            // blocking on a socket that will never be ready. See also: crbug.com/1019986
            if let Some(socket) = control_tubes.get(index) {
                wait_ctx
                    .delete(socket)
                    .context("failed to remove descriptor from wait context")?;
            }

            // This line implicitly drops the socket at `index` when it gets returned by
            // `swap_remove`. After this line, the socket at `index` is not the one from
            // `vm_control_indices_to_remove`. Because of this socket's change in index, we need to
            // use `wait_ctx.modify` to change the associated index in its `Token::VmControl`.
            control_tubes.swap_remove(index);
            if let Some(tube) = control_tubes.get(index) {
                wait_ctx
                    .modify(tube, EventType::Read, Token::VmControl { index })
                    .context("failed to add descriptor to wait context")?;
            }
        }
    }

    vcpu::kick_all_vcpus(
        &vcpu_handles,
        linux.irq_chip.as_irq_chip(),
        VcpuControl::RunState(VmRunMode::Exiting),
    );
    for (handle, _) in vcpu_handles {
        if let Err(e) = handle.join() {
            error!("failed to join vcpu thread: {:?}", e);
        }
    }

    // Stop pci root worker thread
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let _ = hp_control_tube.send(PciRootCommand::Kill);

    // Explicitly drop the VM structure here to allow the devices to clean up before the
    // control sockets are closed when this function exits.
    mem::drop(linux);

    stdin()
        .set_canon_mode()
        .expect("failed to restore canonical mode for terminal");

    Ok(exit_state)
}

/// Start and jail a vhost-user device according to its configuration and a vhost listener string.
///
/// The jailing business is nasty and potentially unsafe if done from the wrong context - do not
/// call outside of `start_devices`!
///
/// Returns the pid of the jailed device process.
fn jail_and_start_vu_device<T: VirtioDeviceBuilder>(
    jail_config: &Option<JailConfig>,
    params: &T,
    vhost: &str,
    name: &str,
) -> anyhow::Result<(libc::pid_t, Option<Box<dyn std::any::Any>>)> {
    let mut keep_rds = Vec::new();

    base::syslog::push_descriptors(&mut keep_rds);

    // Create the device in the parent process, so the child does not need any privileges necessary
    // to do it (only runtime capabilities are required).
    let device = params
        .create_vhost_user_device(&mut keep_rds)
        .context("failed to create vhost-user backend")?;
    let mut listener = VhostUserListener::new(vhost, device.max_queue_num(), Some(&mut keep_rds))
        .context("failed to create the vhost listener")?;
    let parent_resources = listener.take_parent_process_resources();

    let jail_type = match &listener {
        VhostUserListener::Socket(_) => VirtioDeviceType::VhostUser,
        VhostUserListener::Vvu(_, _) => VirtioDeviceType::Vvu,
    };

    // Create a jail from the configuration. If the configuration is `None`, `create_jail` will also
    // return `None` so fall back to an empty (i.e. non-constrained) Minijail.
    let jail = params
        .create_jail(jail_config, jail_type)
        .with_context(|| format!("failed to create jail for {}", name))?
        .ok_or(())
        .or_else(|_| Minijail::new())
        .with_context(|| format!("failed to create empty jail for {}", name))?;

    // Safe because we are keeping all the descriptors needed for the child to function.
    match unsafe { jail.fork(Some(&keep_rds)).context("error while forking")? } {
        0 => {
            // In the child process.

            // Free memory for the resources managed by the parent, without running drop() on them.
            // The parent will do it as we exit.
            let _ = std::mem::ManuallyDrop::new(parent_resources);

            // Make sure the child process does not survive its parent.
            if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } < 0 {
                panic!("call to prctl(PR_SET_DEATHSIG, SIGKILL) failed. Aborting child process.");
            }

            // Set the name for the thread.
            const MAX_LEN: usize = 15; // pthread_setname_np() limit on Linux
            let debug_label_trimmed = &name.as_bytes()[..std::cmp::min(MAX_LEN, name.len())];
            let thread_name = CString::new(debug_label_trimmed).unwrap();
            // Safe because we trimmed the name to 15 characters (and pthread_setname_np will return
            // an error if we don't anyway).
            let _ = unsafe { libc::pthread_setname_np(libc::pthread_self(), thread_name.as_ptr()) };

            // Run the device loop and terminate the child process once it exits.
            let res = match listener.run_device(device) {
                Ok(()) => 0,
                Err(e) => {
                    error!("error while running device {}: {:#}", name, e);
                    1
                }
            };
            unsafe { libc::exit(res) };
        }
        pid => {
            // In the parent process. We will drop the device and listener when exiting this method.
            // This is fine as ownership for both has been transferred to the child process and they
            // will keep living there. We just retain `parent_resources` for things we are supposed
            // to clean up ourselves.

            info!("process for device {} (PID {}) started", &name, pid);
            Ok((pid, parent_resources))
        }
    }
}

fn process_vhost_user_control_request(tube: Tube, disk_host_tubes: &[Tube]) -> Result<()> {
    let command = tube
        .recv::<VmRequest>()
        .context("failed to receive VmRequest")?;
    let resp = match command {
        VmRequest::DiskCommand {
            disk_index,
            ref command,
        } => match &disk_host_tubes.get(disk_index) {
            Some(tube) => handle_disk_command(command, tube),
            None => VmResponse::Err(base::Error::new(libc::ENODEV)),
        },
        request => {
            error!(
                "Request {:?} currently not supported in vhost user backend",
                request
            );
            VmResponse::Err(base::Error::new(libc::EPERM))
        }
    };

    tube.send(&resp).context("failed to send VmResponse")?;
    Ok(())
}

fn start_vhost_user_control_server(
    control_server_socket: UnlinkUnixSeqpacketListener,
    disk_host_tubes: Vec<Tube>,
) {
    info!("Start vhost-user control server");
    loop {
        match control_server_socket.accept() {
            Ok(socket) => {
                let tube = Tube::new_from_unix_seqpacket(socket);
                if let Err(e) = process_vhost_user_control_request(tube, &disk_host_tubes) {
                    error!("failed to process control request: {:#}", e);
                }
            }
            Err(e) => {
                error!("failed to establish connection: {}", e);
            }
        }
    }
}

pub fn start_devices(opts: DevicesCommand) -> anyhow::Result<()> {
    struct DeviceJailInfo {
        // Unique name for the device, in the form `foomatic-0`.
        name: String,
        _drop_resources: Option<Box<dyn std::any::Any>>,
    }

    fn add_device<T: VirtioDeviceBuilder>(
        i: usize,
        device_params: &T,
        vhost: &str,
        jail_config: &Option<JailConfig>,
        devices_jails: &mut BTreeMap<libc::pid_t, DeviceJailInfo>,
    ) -> anyhow::Result<()> {
        let name = format!("{}-{}", T::NAME, i);

        let (pid, _drop_resources) =
            jail_and_start_vu_device::<T>(jail_config, device_params, vhost, &name)?;

        devices_jails.insert(
            pid,
            DeviceJailInfo {
                name,
                _drop_resources,
            },
        );

        Ok(())
    }

    let mut devices_jails: BTreeMap<libc::pid_t, DeviceJailInfo> = BTreeMap::new();

    let jail = if opts.disable_sandbox {
        None
    } else {
        Some(opts.jail)
    };

    // Create control server socket
    let control_server_socket = opts.control_socket.map(|path| {
        UnlinkUnixSeqpacketListener(
            UnixSeqpacketListener::bind(path).expect("Could not bind socket"),
        )
    });

    // Create serial devices.
    for (i, params) in opts.serial.iter().enumerate() {
        let serial_config = &params.device;
        add_device(i, serial_config, &params.vhost, &jail, &mut devices_jails)?;
    }

    let mut disk_host_tubes = Vec::new();
    let control_socket_exists = control_server_socket.is_some();
    // Create block devices.
    for (i, params) in opts.block.iter().enumerate() {
        let tube = if control_socket_exists {
            let (host_tube, device_tube) = Tube::pair().context("failed to create tube")?;
            disk_host_tubes.push(host_tube);
            Some(device_tube)
        } else {
            None
        };
        let disk_config = DiskConfig::new(&params.device, tube);
        add_device(i, &disk_config, &params.vhost, &jail, &mut devices_jails)?;
    }

    let ex = Executor::new()?;
    if let Some(control_server_socket) = control_server_socket {
        // Start the control server in the parent process.
        ex.spawn_blocking(move || {
            start_vhost_user_control_server(control_server_socket, disk_host_tubes)
        })
        .detach();
    }

    // Now wait for all device processes to return.
    while !devices_jails.is_empty() {
        match base::platform::wait_for_pid(-1, 0) {
            Err(e) => panic!("error waiting for child process to complete: {:#}", e),
            Ok((Some(pid), wait_status)) => match devices_jails.remove_entry(&pid) {
                Some((_, info)) => {
                    match wait_status {
                        WaitStatus::Exited(status) => info!(
                            "process for device {} (PID {}) exited with code {}",
                            &info.name, pid, status
                        ),
                        WaitStatus::Signaled(signal) => warn!(
                            "process for device {} (PID {}) has been killed by signal {:?}",
                            &info.name, pid, signal,
                        ),
                        // We are only interested in processes that actually terminate.
                        WaitStatus::Stopped(_) | WaitStatus::Continued | WaitStatus::Running => (),
                    };
                }
                None => error!("pid {} is not one of our device processes", pid),
            },
            // `wait_for_pid` will necessarily return a PID because we asked to it wait for one to
            // complete.
            Ok((None, _)) => unreachable!(),
        }
    }

    info!("all device processes have exited");

    Ok(())
}

/// Setup crash reporting for a process. Each process MUST provide a unique `product_type` to avoid
/// making crash reports incomprehensible.
#[cfg(feature = "crash-report")]
pub fn setup_emulator_crash_reporting(_cfg: &Config) -> anyhow::Result<String> {
    crash_report::setup_crash_reporting(crash_report::CrashReportAttributes {
        product_type: "emulator".to_owned(),
        pipe_name: None,
        report_uuid: None,
        product_name: None,
        product_version: None,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    // Create a file-backed mapping parameters struct with the given `address` and `size` and other
    // parameters set to default values.
    fn test_file_backed_mapping(address: u64, size: u64) -> FileBackedMappingParameters {
        FileBackedMappingParameters {
            address,
            size,
            path: PathBuf::new(),
            offset: 0,
            writable: false,
            sync: false,
            align: false,
        }
    }

    #[test]
    fn guest_mem_file_backed_mappings_overlap() {
        // Base case: no file mappings; output layout should be identical.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000),
                    (GuestAddress(0x1_0000_0000), 0x8_0000),
                ],
                &[]
            ),
            vec![
                (GuestAddress(0), 0xD000_0000),
                (GuestAddress(0x1_0000_0000), 0x8_0000),
            ]
        );

        // File mapping that does not overlap guest memory.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000),
                    (GuestAddress(0x1_0000_0000), 0x8_0000),
                ],
                &[test_file_backed_mapping(0xD000_0000, 0x1000)]
            ),
            vec![
                (GuestAddress(0), 0xD000_0000),
                (GuestAddress(0x1_0000_0000), 0x8_0000),
            ]
        );

        // File mapping at the start of the low address space region.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000),
                    (GuestAddress(0x1_0000_0000), 0x8_0000),
                ],
                &[test_file_backed_mapping(0, 0x2000)]
            ),
            vec![
                (GuestAddress(0x2000), 0xD000_0000 - 0x2000),
                (GuestAddress(0x1_0000_0000), 0x8_0000),
            ]
        );

        // File mapping at the end of the low address space region.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000),
                    (GuestAddress(0x1_0000_0000), 0x8_0000),
                ],
                &[test_file_backed_mapping(0xD000_0000 - 0x2000, 0x2000)]
            ),
            vec![
                (GuestAddress(0), 0xD000_0000 - 0x2000),
                (GuestAddress(0x1_0000_0000), 0x8_0000),
            ]
        );

        // File mapping fully contained within the middle of the low address space region.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000),
                    (GuestAddress(0x1_0000_0000), 0x8_0000),
                ],
                &[test_file_backed_mapping(0x1000, 0x2000)]
            ),
            vec![
                (GuestAddress(0), 0x1000),
                (GuestAddress(0x3000), 0xD000_0000 - 0x3000),
                (GuestAddress(0x1_0000_0000), 0x8_0000),
            ]
        );

        // File mapping at the start of the high address space region.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000),
                    (GuestAddress(0x1_0000_0000), 0x8_0000),
                ],
                &[test_file_backed_mapping(0x1_0000_0000, 0x2000)]
            ),
            vec![
                (GuestAddress(0), 0xD000_0000),
                (GuestAddress(0x1_0000_2000), 0x8_0000 - 0x2000),
            ]
        );

        // File mapping at the end of the high address space region.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000),
                    (GuestAddress(0x1_0000_0000), 0x8_0000),
                ],
                &[test_file_backed_mapping(0x1_0008_0000 - 0x2000, 0x2000)]
            ),
            vec![
                (GuestAddress(0), 0xD000_0000),
                (GuestAddress(0x1_0000_0000), 0x8_0000 - 0x2000),
            ]
        );

        // File mapping fully contained within the middle of the high address space region.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000),
                    (GuestAddress(0x1_0000_0000), 0x8_0000),
                ],
                &[test_file_backed_mapping(0x1_0000_1000, 0x2000)]
            ),
            vec![
                (GuestAddress(0), 0xD000_0000),
                (GuestAddress(0x1_0000_0000), 0x1000),
                (GuestAddress(0x1_0000_3000), 0x8_0000 - 0x3000),
            ]
        );

        // File mapping overlapping two guest memory regions.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000),
                    (GuestAddress(0x1_0000_0000), 0x8_0000),
                ],
                &[test_file_backed_mapping(0xA000_0000, 0x60002000)]
            ),
            vec![
                (GuestAddress(0), 0xA000_0000),
                (GuestAddress(0x1_0000_2000), 0x8_0000 - 0x2000),
            ]
        );
    }
}
