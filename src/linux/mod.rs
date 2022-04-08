// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::{max, Reverse};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::stdin;
use std::iter;
use std::mem;
use std::ops::RangeInclusive;
#[cfg(feature = "gpu")]
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::OpenOptionsExt;
use std::path::Path;
use std::str::FromStr;
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use std::process;
#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
use std::thread;

use devices::virtio::vhost::vsock::{VhostVsockConfig, VhostVsockDeviceParameter};
use libc;

use acpi_tables::sdt::SDT;

use anyhow::{anyhow, bail, Context, Result};
use base::*;
use base::{UnixSeqpacket, UnixSeqpacketListener, UnlinkUnixSeqpacketListener};
use devices::serial_device::SerialHardware;
use devices::vfio::{VfioCommonSetup, VfioCommonTrait};
use devices::virtio::memory_mapper::MemoryMapperTrait;
#[cfg(feature = "gpu")]
use devices::virtio::{self, EventDevice};
#[cfg(feature = "audio")]
use devices::Ac97Dev;
use devices::{
    self, BusDeviceObj, HostHotPlugKey, HotPlugBus, IrqEventIndex, KvmKernelIrqChip, PciAddress,
    PciDevice, PvPanicCode, PvPanicPciDevice, StubPciDevice, VirtioPciDevice,
};
use devices::{CoIommuDev, IommuDevType};
#[cfg(feature = "usb")]
use devices::{HostBackendDeviceProvider, XhciController};
use hypervisor::kvm::{Kvm, KvmVcpu, KvmVm};
use hypervisor::{HypervisorCap, ProtectionType, Vm, VmCap};
use minijail::{self, Minijail};
use resources::{Alloc, SystemAllocator};
use rutabaga_gfx::RutabagaGralloc;
use sync::Mutex;
use vm_control::*;
use vm_memory::{GuestAddress, GuestMemory, MemoryPolicy};

#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
use crate::gdb::{gdb_thread, GdbStub};
use crate::{Config, Executable, FileBackedMappingParameters, SharedDir, SharedDirKind, VfioType};
use arch::{
    self, LinuxArch, RunnableLinuxVm, VcpuAffinity, VirtioDeviceStub, VmComponents, VmImage,
};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use {
    crate::HostPcieRootPortParameters,
    devices::{
        IrqChipX86_64 as IrqChipArch, KvmSplitIrqChip, PciBridge, PcieHostRootPort, PcieRootPort,
    },
    hypervisor::{VcpuX86_64 as VcpuArch, VmX86_64 as VmArch},
    x86_64::X8664arch as Arch,
};
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use {
    aarch64::AArch64 as Arch,
    devices::IrqChipAArch64 as IrqChipArch,
    hypervisor::{VcpuAArch64 as VcpuArch, VmAArch64 as VmArch},
};

mod device_helpers;
use device_helpers::*;
pub(crate) mod jail_helpers;
use jail_helpers::*;
mod vcpu;

#[cfg(feature = "gpu")]
pub(crate) mod gpu;
#[cfg(feature = "gpu")]
pub use gpu::GpuRenderServerParameters;
#[cfg(feature = "gpu")]
use gpu::*;

#[cfg(target_os = "android")]
mod android;

// gpu_device_tube is not used when GPU support is disabled.
#[cfg_attr(not(feature = "gpu"), allow(unused_variables))]
fn create_virtio_devices(
    cfg: &Config,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    _exit_evt: &Event,
    wayland_device_tube: Tube,
    gpu_device_tube: Tube,
    vhost_user_gpu_tubes: Vec<(Tube, Tube, Tube)>,
    balloon_device_tube: Option<Tube>,
    balloon_inflate_tube: Option<Tube>,
    init_balloon_size: u64,
    disk_device_tubes: &mut Vec<Tube>,
    pmem_device_tubes: &mut Vec<Tube>,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
    fs_device_tubes: &mut Vec<Tube>,
    #[cfg(feature = "gpu")] render_server_fd: Option<SafeDescriptor>,
    vvu_proxy_device_tubes: &mut Vec<Tube>,
    vvu_proxy_max_sibling_mem_size: u64,
) -> DeviceResult<Vec<VirtioDeviceStub>> {
    let mut devs = Vec::new();

    #[cfg(feature = "gpu")]
    for (opt, (host_gpu_tube, device_gpu_tube, device_control_tube)) in
        cfg.vhost_user_gpu.iter().zip(vhost_user_gpu_tubes)
    {
        devs.push(create_vhost_user_gpu_device(
            cfg,
            opt,
            (host_gpu_tube, device_gpu_tube),
            device_control_tube,
        )?);
    }

    for opt in &cfg.vvu_proxy {
        devs.push(create_vvu_proxy_device(
            cfg,
            opt,
            vvu_proxy_device_tubes.remove(0),
            vvu_proxy_max_sibling_mem_size,
        )?);
    }

    #[cfg_attr(not(feature = "gpu"), allow(unused_mut))]
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
            cfg,
            wayland_device_tube,
            wl_resource_bridge,
        )?);
    }

    #[cfg(feature = "video-decoder")]
    let video_dec_cfg = if let Some(backend) = cfg.video_dec {
        let (video_tube, gpu_tube) = Tube::pair().context("failed to create tube")?;
        resource_bridges.push(gpu_tube);
        Some((video_tube, backend))
    } else {
        None
    };

    #[cfg(feature = "video-encoder")]
    let video_enc_cfg = if let Some(backend) = cfg.video_enc {
        let (video_tube, gpu_tube) = Tube::pair().context("failed to create tube")?;
        resource_bridges.push(gpu_tube);
        Some((video_tube, backend))
    } else {
        None
    };

    #[cfg(feature = "gpu")]
    {
        if let Some(gpu_parameters) = &cfg.gpu_parameters {
            let mut gpu_display_w = virtio::DEFAULT_DISPLAY_WIDTH;
            let mut gpu_display_h = virtio::DEFAULT_DISPLAY_HEIGHT;
            if !gpu_parameters.displays.is_empty() {
                gpu_display_w = gpu_parameters.displays[0].width;
                gpu_display_h = gpu_parameters.displays[0].height;
            }

            let mut event_devices = Vec::new();
            if cfg.display_window_mouse {
                let (event_device_socket, virtio_dev_socket) =
                    UnixStream::pair().context("failed to create socket")?;
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
                    virtio::base_features(cfg.protected_vm),
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
                    UnixStream::pair().context("failed to create socket")?;
                let dev = virtio::new_keyboard(
                    // u32::MAX is the least likely to collide with the indices generated above for
                    // the multi_touch options, which begin at 0.
                    u32::MAX,
                    virtio_dev_socket,
                    virtio::base_features(cfg.protected_vm),
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
                _exit_evt,
                gpu_device_tube,
                resource_bridges,
                // Use the unnamed socket for GPU display screens.
                cfg.wayland_socket_paths.get(""),
                cfg.x_display.clone(),
                render_server_fd,
                event_devices,
                map_request,
            )?);
        }
    }

    for (_, param) in cfg
        .serial_parameters
        .iter()
        .filter(|(_k, v)| v.hardware == SerialHardware::VirtioConsole)
    {
        let dev = create_console_device(cfg, param)?;
        devs.push(dev);
    }

    for disk in &cfg.disks {
        let disk_device_tube = disk_device_tubes.remove(0);
        devs.push(create_block_device(cfg, disk, disk_device_tube)?);
    }

    for blk in &cfg.vhost_user_blk {
        devs.push(create_vhost_user_block_device(cfg, blk)?);
    }

    for console in &cfg.vhost_user_console {
        devs.push(create_vhost_user_console_device(cfg, console)?);
    }

    for (index, pmem_disk) in cfg.pmem_devices.iter().enumerate() {
        let pmem_device_tube = pmem_device_tubes.remove(0);
        devs.push(create_pmem_device(
            cfg,
            vm,
            resources,
            pmem_disk,
            index,
            pmem_device_tube,
        )?);
    }

    if cfg.rng {
        devs.push(create_rng_device(cfg)?);
    }

    #[cfg(feature = "tpm")]
    {
        if cfg.software_tpm {
            devs.push(create_software_tpm_device(cfg)?);
        }
    }

    for (idx, single_touch_spec) in cfg.virtio_single_touch.iter().enumerate() {
        devs.push(create_single_touch_device(
            cfg,
            single_touch_spec,
            idx as u32,
        )?);
    }

    for (idx, multi_touch_spec) in cfg.virtio_multi_touch.iter().enumerate() {
        devs.push(create_multi_touch_device(
            cfg,
            multi_touch_spec,
            idx as u32,
        )?);
    }

    for (idx, trackpad_spec) in cfg.virtio_trackpad.iter().enumerate() {
        devs.push(create_trackpad_device(cfg, trackpad_spec, idx as u32)?);
    }

    for (idx, mouse_socket) in cfg.virtio_mice.iter().enumerate() {
        devs.push(create_mouse_device(cfg, mouse_socket, idx as u32)?);
    }

    for (idx, keyboard_socket) in cfg.virtio_keyboard.iter().enumerate() {
        devs.push(create_keyboard_device(cfg, keyboard_socket, idx as u32)?);
    }

    for (idx, switches_socket) in cfg.virtio_switches.iter().enumerate() {
        devs.push(create_switches_device(cfg, switches_socket, idx as u32)?);
    }

    for dev_path in &cfg.virtio_input_evdevs {
        devs.push(create_vinput_device(cfg, dev_path)?);
    }

    if let Some(balloon_device_tube) = balloon_device_tube {
        devs.push(create_balloon_device(
            cfg,
            balloon_device_tube,
            balloon_inflate_tube,
            init_balloon_size,
        )?);
    }

    // We checked above that if the IP is defined, then the netmask is, too.
    for tap_fd in &cfg.tap_fd {
        devs.push(create_tap_net_device_from_fd(cfg, *tap_fd)?);
    }

    if let (Some(host_ip), Some(netmask), Some(mac_address)) =
        (cfg.host_ip, cfg.netmask, cfg.mac_address)
    {
        if !cfg.vhost_user_net.is_empty() {
            bail!("vhost-user-net cannot be used with any of --host_ip, --netmask or --mac");
        }
        devs.push(create_net_device_from_config(
            cfg,
            host_ip,
            netmask,
            mac_address,
        )?);
    }

    for tap_name in &cfg.tap_name {
        devs.push(create_tap_net_device_from_name(cfg, tap_name.as_bytes())?);
    }

    for net in &cfg.vhost_user_net {
        devs.push(create_vhost_user_net_device(cfg, net)?);
    }

    for vsock in &cfg.vhost_user_vsock {
        devs.push(create_vhost_user_vsock_device(cfg, vsock)?);
    }

    for opt in &cfg.vhost_user_wl {
        devs.push(create_vhost_user_wl_device(cfg, opt)?);
    }

    #[cfg(feature = "audio_cras")]
    {
        for cras_snd in &cfg.cras_snds {
            devs.push(create_cras_snd_device(cfg, cras_snd.clone())?);
        }
    }

    #[cfg(feature = "video-decoder")]
    {
        if let Some((video_dec_tube, video_dec_backend)) = video_dec_cfg {
            register_video_device(
                video_dec_backend,
                &mut devs,
                video_dec_tube,
                cfg,
                devices::virtio::VideoDeviceType::Decoder,
            )?;
        }
    }

    #[cfg(feature = "video-encoder")]
    {
        if let Some((video_enc_tube, video_enc_backend)) = video_enc_cfg {
            register_video_device(
                video_enc_backend,
                &mut devs,
                video_enc_tube,
                cfg,
                devices::virtio::VideoDeviceType::Encoder,
            )?;
        }
    }

    if let Some(cid) = cfg.cid {
        let vhost_config = VhostVsockConfig {
            device: cfg
                .vhost_vsock_device
                .clone()
                .unwrap_or(VhostVsockDeviceParameter::default()),
            cid,
        };
        devs.push(create_vhost_vsock_device(cfg, &vhost_config)?);
    }

    for vhost_user_fs in &cfg.vhost_user_fs {
        devs.push(create_vhost_user_fs_device(cfg, vhost_user_fs)?);
    }

    #[cfg(feature = "audio")]
    for vhost_user_snd in &cfg.vhost_user_snd {
        devs.push(create_vhost_user_snd_device(cfg, vhost_user_snd)?);
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
                create_fs_device(cfg, uid_map, gid_map, src, tag, fs_cfg.clone(), device_tube)?
            }
            SharedDirKind::P9 => create_9p_device(cfg, uid_map, gid_map, src, tag, p9_cfg.clone())?,
        };
        devs.push(dev);
    }

    if let Some(vhost_user_mac80211_hwsim) = &cfg.vhost_user_mac80211_hwsim {
        devs.push(create_vhost_user_mac80211_hwsim_device(
            cfg,
            vhost_user_mac80211_hwsim,
        )?);
    }

    #[cfg(feature = "audio")]
    if let Some(path) = &cfg.sound {
        devs.push(create_sound_device(path, cfg)?);
    }

    Ok(devs)
}

fn create_devices(
    cfg: &Config,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    exit_evt: &Event,
    panic_wrtube: Tube,
    iommu_attached_endpoints: &mut BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
    control_tubes: &mut Vec<TaggedControlTube>,
    wayland_device_tube: Tube,
    gpu_device_tube: Tube,
    // Tuple content: (host-side GPU tube, device-side GPU tube, device-side control tube).
    vhost_user_gpu_tubes: Vec<(Tube, Tube, Tube)>,
    balloon_device_tube: Option<Tube>,
    init_balloon_size: u64,
    disk_device_tubes: &mut Vec<Tube>,
    pmem_device_tubes: &mut Vec<Tube>,
    fs_device_tubes: &mut Vec<Tube>,
    #[cfg(feature = "usb")] usb_provider: HostBackendDeviceProvider,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
    #[cfg(feature = "gpu")] render_server_fd: Option<SafeDescriptor>,
    vvu_proxy_device_tubes: &mut Vec<Tube>,
    vvu_proxy_max_sibling_mem_size: u64,
) -> DeviceResult<Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>> {
    let mut devices: Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)> = Vec::new();
    let mut balloon_inflate_tube: Option<Tube> = None;
    if !cfg.vfio.is_empty() {
        let mut coiommu_attached_endpoints = Vec::new();

        for vfio_dev in cfg
            .vfio
            .iter()
            .filter(|dev| dev.get_type() == VfioType::Pci)
        {
            let vfio_path = &vfio_dev.vfio_path;
            let (vfio_pci_device, jail) = create_vfio_device(
                cfg,
                vm,
                resources,
                control_tubes,
                vfio_path.as_path(),
                None,
                vfio_dev.guest_address(),
                iommu_attached_endpoints,
                Some(&mut coiommu_attached_endpoints),
                vfio_dev.iommu_dev_type(),
            )?;

            devices.push((vfio_pci_device, jail));
        }

        for vfio_dev in cfg
            .vfio
            .iter()
            .filter(|dev| dev.get_type() == VfioType::Platform)
        {
            let vfio_path = &vfio_dev.vfio_path;
            let (vfio_plat_dev, jail) = create_vfio_platform_device(
                cfg,
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

        if !coiommu_attached_endpoints.is_empty() {
            let vfio_container =
                VfioCommonSetup::vfio_get_container(IommuDevType::CoIommu, None as Option<&Path>)
                    .context("failed to get vfio container")?;
            let (coiommu_host_tube, coiommu_device_tube) =
                Tube::pair().context("failed to create coiommu tube")?;
            control_tubes.push(TaggedControlTube::VmMemory(coiommu_host_tube));
            let vcpu_count = cfg.vcpu_count.unwrap_or(1) as u64;
            let (coiommu_tube, balloon_tube) =
                Tube::pair().context("failed to create coiommu tube")?;
            balloon_inflate_tube = Some(balloon_tube);
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

            devices.push((Box::new(dev), simple_jail(&cfg.jail_config, "coiommu")?));
        }
    }

    let stubs = create_virtio_devices(
        cfg,
        vm,
        resources,
        exit_evt,
        wayland_device_tube,
        gpu_device_tube,
        vhost_user_gpu_tubes,
        balloon_device_tube,
        balloon_inflate_tube,
        init_balloon_size,
        disk_device_tubes,
        pmem_device_tubes,
        map_request,
        fs_device_tubes,
        #[cfg(feature = "gpu")]
        render_server_fd,
        vvu_proxy_device_tubes,
        vvu_proxy_max_sibling_mem_size,
    )?;

    for stub in stubs {
        let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
        control_tubes.push(TaggedControlTube::VmIrq(msi_host_tube));
        let dev = VirtioPciDevice::new(vm.get_memory().clone(), stub.dev, msi_device_tube)
            .context("failed to create virtio pci dev")?;
        let dev = Box::new(dev) as Box<dyn BusDeviceObj>;
        devices.push((dev, stub.jail));
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
        devices.push((usb_controller, simple_jail(&cfg.jail_config, "xhci")?));
    }

    for params in &cfg.stub_pci_devices {
        // Stub devices don't need jailing since they don't do anything.
        devices.push((Box::new(StubPciDevice::new(params)), None));
    }

    devices.push((Box::new(PvPanicPciDevice::new(panic_wrtube)), None));
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

        match resources.mmio_allocator_any().allocate_at(
            mapping.address,
            mapping.size,
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
    hp_vec: &mut Vec<Arc<Mutex<dyn HotPlugBus>>>,
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
        hp_vec.push(pcie_root_port as Arc<Mutex<dyn HotPlugBus>>);
    } else {
        // user specify host pcie root port which link to this virtual pcie rp,
        // reserve the host pci BDF and create a virtual pcie RP with some attrs same as host
        for host_pcie in host_pcie_rp.iter() {
            let (vm_host_tube, vm_device_tube) = Tube::pair().context("failed to create tube")?;
            let pcie_host = PcieHostRootPort::new(host_pcie.host_path.as_path(), vm_device_tube)?;
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
                hp_vec.push(pcie_root_port as Arc<Mutex<dyn HotPlugBus>>);
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
        match cfg.protected_vm {
            ProtectionType::Protected | ProtectionType::ProtectedWithoutFirmware => {
                Some(64 * 1024 * 1024)
            }
            ProtectionType::Unprotected => None,
        }
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
        no_smt: cfg.no_smt,
        hugepages: cfg.hugepages,
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
        protected_vm: cfg.protected_vm,
        #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
        gdb: None,
        dmi_path: cfg.dmi_path.clone(),
        no_legacy: cfg.no_legacy,
        host_cpu_topology: cfg.host_cpu_topology,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        force_s2idle: cfg.force_s2idle,
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
    guest_mem.set_memory_policy(mem_policy);
    let kvm = Kvm::new_with_path(&cfg.kvm_device_path).context("failed to create kvm")?;
    let vm = KvmVm::new(&kvm, guest_mem, components.protected_vm).context("failed to create vm")?;

    if !cfg.userspace_msr.is_empty() {
        vm.enable_userspace_msr()
            .context("failed to enable userspace MSR handling, do you have kernel 5.10 or later")?;
    }

    // Check that the VM was actually created in protected mode as expected.
    if cfg.protected_vm != ProtectionType::Unprotected && !vm.check_capability(VmCap::Protected) {
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

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    if let Some(port) = cfg.gdb {
        // GDB needs a control socket to interrupt vcpus.
        let (gdb_host_tube, gdb_control_tube) = Tube::pair().context("failed to create tube")?;
        control_tubes.push(TaggedControlTube::Vm(gdb_host_tube));
        components.gdb = Some((port, gdb_control_tube));
    }

    for wl_cfg in &cfg.vhost_user_wl {
        let wayland_host_tube = UnixSeqpacket::connect(&wl_cfg.vm_tube)
            .map(Tube::new)
            .context("failed to connect to wayland tube")?;
        control_tubes.push(TaggedControlTube::VmMemory(wayland_host_tube));
    }

    let mut vhost_user_gpu_tubes = Vec::with_capacity(cfg.vhost_user_gpu.len());
    for _ in 0..cfg.vhost_user_gpu.len() {
        let (host_control_tube, device_control_tube) =
            Tube::pair().context("failed to create tube")?;
        let (host_gpu_tube, device_gpu_tube) = Tube::pair().context("failed to create tube")?;
        vhost_user_gpu_tubes.push((host_gpu_tube, device_gpu_tube, device_control_tube));
        control_tubes.push(TaggedControlTube::VmMemory(host_control_tube));
    }

    let (wayland_host_tube, wayland_device_tube) = Tube::pair().context("failed to create tube")?;
    control_tubes.push(TaggedControlTube::VmMemory(wayland_host_tube));

    let (balloon_host_tube, balloon_device_tube) = if cfg.balloon {
        if let Some(ref path) = cfg.balloon_control {
            (
                None,
                Some(Tube::new(
                    UnixSeqpacket::connect(path).context("failed to create balloon control")?,
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

    let (gpu_host_tube, gpu_device_tube) = Tube::pair().context("failed to create tube")?;
    control_tubes.push(TaggedControlTube::VmMemory(gpu_host_tube));

    if let Some(ioapic_host_tube) = ioapic_host_tube {
        control_tubes.push(TaggedControlTube::VmIrq(ioapic_host_tube));
    }

    let battery = if cfg.battery_type.is_some() {
        #[cfg_attr(not(feature = "power-monitor-powerd"), allow(clippy::manual_map))]
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
        (&cfg.battery_type, jail)
    } else {
        (&cfg.battery_type, None)
    };

    let map_request: Arc<Mutex<Option<ExternalMapping>>> = Arc::new(Mutex::new(None));

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
        control_tubes.push(TaggedControlTube::VmMemory(vvu_proxy_host_tube));
        vvu_proxy_device_tubes.push(vvu_proxy_device_tube);
    }

    let exit_evt = Event::new().context("failed to create event")?;
    let reset_evt = Event::new().context("failed to create event")?;
    let crash_evt = Event::new().context("failed to create event")?;
    let (panic_rdtube, panic_wrtube) = Tube::pair().context("failed to create tube")?;

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

    #[cfg(feature = "gpu")]
    // Hold on to the render server jail so it keeps running until we exit run_vm()
    let (_render_server_jail, render_server_fd) =
        if let Some(parameters) = &cfg.gpu_render_server_parameters {
            let (jail, fd) = start_gpu_render_server(&cfg, parameters)?;
            (Some(ScopedMinijail(jail)), Some(fd))
        } else {
            (None, None)
        };

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
        let irq_evt = devices::IrqLevelEvent::new().context("failed to create event")?;
        irq_chip.register_level_irq_event(*irq, &irq_evt).unwrap();
        let direct_irq = devices::DirectIrq::new_level(&irq_evt)
            .context("failed to enable interrupt forwarding")?;
        direct_irq
            .irq_enable(*irq)
            .context("failed to enable interrupt forwarding")?;

        if cfg.direct_wake_irq.contains(&irq) {
            direct_irq
                .irq_wake_enable(*irq)
                .context("failed to enable interrupt wake")?;
        }

        irqs.push(direct_irq);
    }

    #[cfg(feature = "direct")]
    for irq in &cfg.direct_edge_irq {
        if !sys_allocator.reserve_irq(*irq) {
            warn!("irq {} already reserved.", irq);
        }
        let irq_evt = devices::IrqEdgeEvent::new().context("failed to create event")?;
        irq_chip.register_edge_irq_event(*irq, &irq_evt).unwrap();
        let direct_irq = devices::DirectIrq::new_edge(&irq_evt)
            .context("failed to enable interrupt forwarding")?;
        direct_irq
            .irq_enable(*irq)
            .context("failed to enable interrupt forwarding")?;

        if cfg.direct_wake_irq.contains(&irq) {
            direct_irq
                .irq_wake_enable(*irq)
                .context("failed to enable interrupt wake")?;
        }

        irqs.push(direct_irq);
    }

    let mut iommu_attached_endpoints: BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>> =
        BTreeMap::new();
    let mut devices = create_devices(
        &cfg,
        &mut vm,
        &mut sys_allocator,
        &exit_evt,
        panic_wrtube,
        &mut iommu_attached_endpoints,
        &mut control_tubes,
        wayland_device_tube,
        gpu_device_tube,
        vhost_user_gpu_tubes,
        balloon_device_tube,
        init_balloon_size,
        &mut disk_device_tubes,
        &mut pmem_device_tubes,
        &mut fs_device_tubes,
        #[cfg(feature = "usb")]
        usb_provider,
        Arc::clone(&map_request),
        #[cfg(feature = "gpu")]
        render_server_fd,
        &mut vvu_proxy_device_tubes,
        components.memory_size,
    )?;

    let mut hp_endpoints_ranges: Vec<RangeInclusive<u32>> = Vec::new();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let mut hotplug_buses: Vec<Arc<Mutex<dyn HotPlugBus>>> = Vec::new();
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

    let (translate_response_senders, request_rx) = setup_virtio_access_platform(
        &mut sys_allocator,
        &mut iommu_attached_endpoints,
        &mut devices,
    )?;

    let iommu_host_tube = if !iommu_attached_endpoints.is_empty() || cfg.virtio_iommu {
        let (iommu_host_tube, iommu_device_tube) = Tube::pair().context("failed to create tube")?;
        let iommu_dev = create_iommu_device(
            &cfg,
            (1u64 << vm.get_guest_phys_addr_bits()) - 1,
            iommu_attached_endpoints,
            hp_endpoints_ranges,
            translate_response_senders,
            request_rx,
            iommu_device_tube,
        )?;

        let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
        control_tubes.push(TaggedControlTube::VmIrq(msi_host_tube));
        let mut dev = VirtioPciDevice::new(vm.get_memory().clone(), iommu_dev.dev, msi_device_tube)
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
    let mut kvm_vcpu_ids = Vec::new();

    #[cfg_attr(not(feature = "direct"), allow(unused_mut))]
    let mut linux = Arch::build_vm::<V, Vcpu>(
        components,
        &exit_evt,
        &reset_evt,
        &mut sys_allocator,
        &cfg.serial_parameters,
        simple_jail(&cfg.jail_config, "serial")?,
        battery,
        vm,
        ramoops_region,
        devices,
        irq_chip,
        &mut kvm_vcpu_ids,
    )
    .context("the architecture failed to build the vm")?;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        for hotplug_bus in hotplug_buses.iter() {
            linux.hotplug_bus.push(hotplug_bus.clone());
        }

        if let Some(pm) = &linux.pm {
            while let Some((gpe, notify_dev)) = gpe_notify_devs.pop() {
                pm.lock().register_gpe_notify_dev(gpe, notify_dev);
            }
        }
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
                .unwrap();
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
                .unwrap();
        }
    };

    let gralloc = RutabagaGralloc::new().context("failed to create gralloc")?;
    run_control(
        linux,
        sys_allocator,
        cfg,
        control_server_socket,
        control_tubes,
        balloon_host_tube,
        &disk_host_tubes,
        #[cfg(feature = "usb")]
        usb_control_tube,
        exit_evt,
        reset_evt,
        crash_evt,
        panic_rdtube,
        sigchld_fd,
        Arc::clone(&map_request),
        gralloc,
        kvm_vcpu_ids,
        iommu_host_tube,
    )
}

fn get_hp_bus<V: VmArch, Vcpu: VcpuArch>(
    linux: &RunnableLinuxVm<V, Vcpu>,
    host_addr: PciAddress,
) -> Result<(Arc<Mutex<dyn HotPlugBus>>, u8)> {
    for hp_bus in linux.hotplug_bus.iter() {
        if let Some(number) = hp_bus.lock().is_match(host_addr) {
            return Ok((hp_bus.clone(), number));
        }
    }
    Err(anyhow!("Failed to find a suitable hotplug bus"))
}

fn add_vfio_device<V: VmArch, Vcpu: VcpuArch>(
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    cfg: &Config,
    control_tubes: &mut Vec<TaggedControlTube>,
    iommu_host_tube: &Option<Tube>,
    vfio_path: &Path,
) -> Result<()> {
    let host_os_str = vfio_path
        .file_name()
        .ok_or_else(|| anyhow!("failed to parse or find vfio path"))?;
    let host_str = host_os_str
        .to_str()
        .ok_or_else(|| anyhow!("failed to parse or find vfio path"))?;
    let host_addr = PciAddress::from_str(host_str).context("failed to parse vfio pci address")?;

    let (hp_bus, bus_num) = get_hp_bus(linux, host_addr)?;

    let mut endpoints: BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>> = BTreeMap::new();
    let (vfio_pci_device, jail) = create_vfio_device(
        cfg,
        &linux.vm,
        sys_allocator,
        control_tubes,
        vfio_path,
        Some(bus_num),
        None,
        &mut endpoints,
        None,
        if iommu_host_tube.is_some() {
            IommuDevType::VirtioIommu
        } else {
            IommuDevType::NoIommu
        },
    )?;

    let pci_address = Arch::register_pci_device(linux, vfio_pci_device, jail, sys_allocator)
        .context("Failed to configure pci hotplug device")?;

    if let Some(iommu_host_tube) = iommu_host_tube {
        let &endpoint_addr = endpoints.iter().next().unwrap().0;
        let mapper = endpoints.remove(&endpoint_addr).unwrap();
        if let Some(vfio_wrapper) = mapper.lock().as_vfio_wrapper() {
            let vfio_container = vfio_wrapper.as_vfio_container();
            let descriptor = vfio_container.lock().into_raw_descriptor()?;
            let request = VirtioIOMMURequest::VfioCommand(VirtioIOMMUVfioCommand::VfioDeviceAdd {
                endpoint_addr,
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
        };
    }

    let host_key = HostHotPlugKey::Vfio { host_addr };
    let mut hp_bus = hp_bus.lock();
    hp_bus.add_hotplug_device(host_key, pci_address);
    hp_bus.hot_plug(pci_address);
    Ok(())
}

fn remove_vfio_device<V: VmArch, Vcpu: VcpuArch>(
    linux: &RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    iommu_host_tube: &Option<Tube>,
    vfio_path: &Path,
) -> Result<()> {
    let host_os_str = vfio_path
        .file_name()
        .ok_or_else(|| anyhow!("failed to parse or find vfio path"))?;
    let host_str = host_os_str
        .to_str()
        .ok_or_else(|| anyhow!("failed to parse or find vfio path"))?;
    let host_addr = PciAddress::from_str(host_str).context("failed to parse vfio pci address")?;
    let host_key = HostHotPlugKey::Vfio { host_addr };
    for hp_bus in linux.hotplug_bus.iter() {
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

            hp_bus_lock.hot_unplug(pci_addr);
            sys_allocator.release_pci(pci_addr.bus, pci_addr.dev, pci_addr.func);
            return Ok(());
        }
    }

    Err(anyhow!("HotPlugBus hasn't been implemented"))
}

fn handle_vfio_command<V: VmArch, Vcpu: VcpuArch>(
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    cfg: &Config,
    add_tubes: &mut Vec<TaggedControlTube>,
    iommu_host_tube: &Option<Tube>,
    vfio_path: &Path,
    add: bool,
) -> VmResponse {
    let ret = if add {
        add_vfio_device(
            linux,
            sys_allocator,
            cfg,
            add_tubes,
            iommu_host_tube,
            vfio_path,
        )
    } else {
        remove_vfio_device(linux, sys_allocator, iommu_host_tube, vfio_path)
    };

    match ret {
        Ok(()) => VmResponse::Ok,
        Err(e) => {
            error!("hanlde_vfio_command failure: {}", e);
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
    balloon_host_tube: Option<Tube>,
    disk_host_tubes: &[Tube],
    #[cfg(feature = "usb")] usb_control_tube: Tube,
    exit_evt: Event,
    reset_evt: Event,
    crash_evt: Event,
    panic_rdtube: Tube,
    sigchld_fd: SignalFd,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
    mut gralloc: RutabagaGralloc,
    kvm_vcpu_ids: Vec<usize>,
    iommu_host_tube: Option<Tube>,
) -> Result<ExitState> {
    #[derive(PollToken)]
    enum Token {
        Exit,
        Reset,
        Crash,
        Panic,
        Suspend,
        ChildSignal,
        IrqFd { index: IrqEventIndex },
        VmControlServer,
        VmControl { index: usize },
        DelayedIrqFd,
    }

    stdin()
        .set_raw_mode()
        .expect("failed to set terminal raw mode");

    let wait_ctx = WaitContext::build_with(&[
        (&exit_evt, Token::Exit),
        (&reset_evt, Token::Reset),
        (&crash_evt, Token::Crash),
        (&panic_rdtube, Token::Panic),
        (&linux.suspend_evt, Token::Suspend),
        (&sigchld_fd, Token::ChildSignal),
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

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
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
            let mut f = File::create(&cgroup_path.join("tasks"))?;
            f.write_all(process::id().to_string().as_bytes())?;
            Some(f)
        }
    };

    #[cfg(target_os = "android")]
    android::set_process_profiles(&cfg.task_profiles)?;

    for (cpu_id, vcpu) in vcpus.into_iter().enumerate() {
        let (to_vcpu_channel, from_main_channel) = mpsc::channel();
        let vcpu_affinity = match linux.vcpu_affinity.clone() {
            Some(VcpuAffinity::Global(v)) => v,
            Some(VcpuAffinity::PerVcpu(mut m)) => m.remove(&cpu_id).unwrap_or_default(),
            None => Default::default(),
        };
        let handle = vcpu::run_vcpu(
            cpu_id,
            kvm_vcpu_ids[cpu_id],
            vcpu,
            linux.vm.try_clone().context("failed to clone vm")?,
            linux
                .irq_chip
                .try_box_clone()
                .context("failed to clone irqchip")?,
            linux.vcpu_count,
            linux.rt_cpus.contains(&cpu_id),
            vcpu_affinity,
            linux.delay_rt,
            linux.no_smt,
            vcpu_thread_barrier.clone(),
            linux.has_bios,
            (*linux.io_bus).clone(),
            (*linux.mmio_bus).clone(),
            exit_evt.try_clone().context("failed to clone event")?,
            reset_evt.try_clone().context("failed to clone event")?,
            crash_evt.try_clone().context("failed to clone event")?,
            linux.vm.check_capability(VmCap::PvClockSuspend),
            from_main_channel,
            use_hypervisor_signals,
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            to_gdb_channel.clone(),
            cfg.per_vm_core_scheduling,
            cfg.host_cpu_topology,
            cfg.privileged_vm,
            match vcpu_cgroup_tasks_file {
                None => None,
                Some(ref f) => Some(
                    f.try_clone()
                        .context("failed to clone vcpu cgroup tasks file")?,
                ),
            },
            cfg.userspace_msr.clone(),
        )?;
        vcpu_handles.push((handle, to_vcpu_channel));
    }

    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
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
                Token::Exit => {
                    info!("vcpu requested shutdown");
                    break 'wait;
                }
                Token::Reset => {
                    info!("vcpu requested reset");
                    exit_state = ExitState::Reset;
                    break 'wait;
                }
                Token::Crash => {
                    info!("vcpu crashed");
                    exit_state = ExitState::Crash;
                    break 'wait;
                }
                Token::Panic => {
                    let mut break_to_wait: bool = true;
                    match panic_rdtube.recv::<u8>() {
                        Ok(panic_code) => {
                            let panic_code = PvPanicCode::from_u8(panic_code);
                            info!("Guest reported panic [Code: {}]", panic_code);
                            if panic_code == PvPanicCode::CrashLoaded {
                                // VM is booting to crash kernel.
                                break_to_wait = false;
                            }
                        }
                        Err(e) => {
                            warn!("failed to recv panic event: {} ", e);
                        }
                    }
                    if break_to_wait {
                        exit_state = ExitState::GuestPanic;
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
                                control_tubes.push(TaggedControlTube::Vm(Tube::new(socket)));
                            }
                            Err(e) => error!("failed to accept socket: {}", e),
                        }
                    }
                }
                Token::VmControl { index } => {
                    let mut add_tubes = Vec::new();
                    if let Some(socket) = control_tubes.get(index) {
                        match socket {
                            TaggedControlTube::Vm(tube) => match tube.recv::<VmRequest>() {
                                Ok(request) => {
                                    let mut run_mode_opt = None;
                                    let response = match request {
                                        VmRequest::VfioCommand { vfio_path, add } => {
                                            handle_vfio_command(
                                                &mut linux,
                                                &mut sys_allocator,
                                                &cfg,
                                                &mut add_tubes,
                                                &iommu_host_tube,
                                                &vfio_path,
                                                add,
                                            )
                                        }
                                        _ => request.execute(
                                            &mut run_mode_opt,
                                            balloon_host_tube.as_ref(),
                                            &mut balloon_stats_id,
                                            disk_host_tubes,
                                            &mut linux.pm,
                                            #[cfg(feature = "usb")]
                                            Some(&usb_control_tube),
                                            #[cfg(not(feature = "usb"))]
                                            None,
                                            &mut linux.bat_control,
                                            &vcpu_handles,
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
                            TaggedControlTube::VmMemory(tube) => {
                                match tube.recv::<VmMemoryRequest>() {
                                    Ok(request) => {
                                        let response = request.execute(
                                            &mut linux.vm,
                                            &mut sys_allocator,
                                            Arc::clone(&map_request),
                                            &mut gralloc,
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
                                }
                            }
                            TaggedControlTube::VmIrq(tube) => match tube.recv::<VmIrqRequest>() {
                                Ok(request) => {
                                    let response = {
                                        let irq_chip = &mut linux.irq_chip;
                                        request.execute(
                                            |setup| match setup {
                                                IrqSetup::Event(irq, ev, _, _, _) => {
                                                    let irq_evt = devices::IrqEdgeEvent::from_event(ev.try_clone()?);
                                                    if let Some(event_index) = irq_chip
                                                        .register_edge_irq_event(irq, &irq_evt)?
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
                                    "failed to add hotplug vfio-pci descriptor ot wait context",
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

    // Explicitly drop the VM structure here to allow the devices to clean up before the
    // control sockets are closed when this function exits.
    mem::drop(linux);

    stdin()
        .set_canon_mode()
        .expect("failed to restore canonical mode for terminal");

    Ok(exit_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
