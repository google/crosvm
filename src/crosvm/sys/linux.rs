// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(target_os = "android")]
mod android;
pub mod cmdline;
pub mod config;
mod device_helpers;
pub(crate) mod ext2;
#[cfg(feature = "gpu")]
pub(crate) mod gpu;
#[cfg(feature = "pci-hotplug")]
pub(crate) mod jail_warden;
#[cfg(feature = "pci-hotplug")]
pub(crate) mod pci_hotplug_helpers;
#[cfg(feature = "pci-hotplug")]
pub(crate) mod pci_hotplug_manager;
mod vcpu;

#[cfg(all(feature = "pvclock", target_arch = "aarch64"))]
use std::arch::asm;
use std::cmp::max;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
#[cfg(feature = "registered_events")]
use std::collections::HashMap;
#[cfg(feature = "registered_events")]
use std::collections::HashSet;
use std::convert::TryInto;
use std::ffi::CString;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use std::fs::create_dir_all;
use std::fs::File;
use std::fs::OpenOptions;
#[cfg(feature = "registered_events")]
use std::hash::Hash;
use std::io::stdin;
use std::iter;
use std::mem;
#[cfg(target_arch = "x86_64")]
use std::ops::RangeInclusive;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use std::path::PathBuf;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use std::process;
#[cfg(feature = "registered_events")]
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread::JoinHandle;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use aarch64::AArch64 as Arch;
use acpi_tables::sdt::SDT;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use arch::DtbOverlay;
use arch::IrqChipArch;
use arch::LinuxArch;
use arch::RunnableLinuxVm;
use arch::VcpuAffinity;
use arch::VcpuArch;
use arch::VirtioDeviceStub;
use arch::VmArch;
use arch::VmComponents;
use arch::VmImage;
use argh::FromArgs;
use base::ReadNotifier;
#[cfg(feature = "balloon")]
use base::UnixSeqpacket;
use base::UnixSeqpacketListener;
use base::UnlinkUnixSeqpacketListener;
use base::*;
use cros_async::Executor;
use device_helpers::*;
use devices::create_devices_worker_thread;
use devices::serial_device::SerialHardware;
#[cfg(all(feature = "pvclock", target_arch = "x86_64"))]
use devices::tsc::get_tsc_sync_mitigations;
use devices::vfio::VfioContainerManager;
#[cfg(feature = "gpu")]
use devices::virtio;
#[cfg(any(feature = "video-decoder", feature = "video-encoder"))]
use devices::virtio::device_constants::video::VideoDeviceType;
#[cfg(feature = "gpu")]
use devices::virtio::gpu::EventDevice;
#[cfg(target_arch = "x86_64")]
use devices::virtio::memory_mapper::MemoryMapper;
use devices::virtio::memory_mapper::MemoryMapperTrait;
use devices::virtio::vhost::user::VhostUserConnectionTrait;
use devices::virtio::vhost::user::VhostUserListener;
#[cfg(feature = "balloon")]
use devices::virtio::BalloonFeatures;
#[cfg(feature = "pci-hotplug")]
use devices::virtio::NetParameters;
#[cfg(feature = "pci-hotplug")]
use devices::virtio::NetParametersMode;
use devices::virtio::VirtioDevice;
use devices::virtio::VirtioDeviceType;
use devices::Bus;
use devices::BusDeviceObj;
use devices::BusType;
use devices::CoIommuDev;
#[cfg(feature = "usb")]
use devices::DeviceProvider;
#[cfg(target_arch = "x86_64")]
use devices::HotPlugBus;
#[cfg(target_arch = "x86_64")]
use devices::HotPlugKey;
use devices::IommuDevType;
use devices::IrqEventIndex;
use devices::IrqEventSource;
#[cfg(feature = "pci-hotplug")]
use devices::NetResourceCarrier;
#[cfg(target_arch = "x86_64")]
use devices::PciAddress;
#[cfg(target_arch = "x86_64")]
use devices::PciBridge;
use devices::PciDevice;
#[cfg(target_arch = "x86_64")]
use devices::PciMmioMapper;
#[cfg(target_arch = "x86_64")]
use devices::PciRoot;
#[cfg(target_arch = "x86_64")]
use devices::PciRootCommand;
#[cfg(target_arch = "x86_64")]
use devices::PcieDownstreamPort;
#[cfg(target_arch = "x86_64")]
use devices::PcieHostPort;
#[cfg(target_arch = "x86_64")]
use devices::PcieRootPort;
#[cfg(target_arch = "x86_64")]
use devices::PcieUpstreamPort;
use devices::PvPanicCode;
use devices::PvPanicPciDevice;
#[cfg(feature = "pci-hotplug")]
use devices::ResourceCarrier;
use devices::StubPciDevice;
use devices::VirtioPciDevice;
#[cfg(feature = "usb")]
use devices::XhciController;
#[cfg(feature = "gpu")]
use gpu::*;
#[cfg(target_arch = "riscv64")]
use hypervisor::CpuConfigRiscv64;
#[cfg(target_arch = "x86_64")]
use hypervisor::CpuConfigX86_64;
use hypervisor::Hypervisor;
use hypervisor::HypervisorCap;
use hypervisor::MemCacheType;
use hypervisor::ProtectionType;
use hypervisor::Vm;
use hypervisor::VmCap;
use jail::*;
#[cfg(feature = "pci-hotplug")]
use jail_warden::JailWarden;
#[cfg(feature = "pci-hotplug")]
use jail_warden::JailWardenImpl;
#[cfg(feature = "pci-hotplug")]
use jail_warden::PermissiveJailWarden;
use libc;
use metrics::MetricsController;
use minijail::Minijail;
#[cfg(feature = "pci-hotplug")]
use pci_hotplug_manager::PciHotPlugManager;
use resources::AddressRange;
use resources::Alloc;
use resources::SystemAllocator;
#[cfg(target_arch = "riscv64")]
use riscv64::Riscv64 as Arch;
use rutabaga_gfx::RutabagaGralloc;
use rutabaga_gfx::RutabagaGrallocBackendFlags;
use smallvec::SmallVec;
#[cfg(feature = "swap")]
use swap::SwapController;
use sync::Condvar;
use sync::Mutex;
use vm_control::api::VmMemoryClient;
use vm_control::*;
use vm_memory::FileBackedMappingParameters;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::MemoryPolicy;
use vm_memory::MemoryRegionOptions;
#[cfg(target_arch = "x86_64")]
use x86_64::X8664arch as Arch;

use crate::crosvm::config::Config;
use crate::crosvm::config::Executable;
use crate::crosvm::config::HypervisorKind;
use crate::crosvm::config::InputDeviceOption;
use crate::crosvm::config::IrqChipKind;
use crate::crosvm::config::DEFAULT_TOUCH_DEVICE_HEIGHT;
use crate::crosvm::config::DEFAULT_TOUCH_DEVICE_WIDTH;
#[cfg(feature = "gdb")]
use crate::crosvm::gdb::gdb_thread;
#[cfg(feature = "gdb")]
use crate::crosvm::gdb::GdbStub;
#[cfg(target_arch = "x86_64")]
use crate::crosvm::ratelimit::Ratelimit;
use crate::crosvm::sys::cmdline::DevicesCommand;
use crate::crosvm::sys::config::SharedDir;
use crate::crosvm::sys::config::SharedDirKind;
use crate::crosvm::sys::platform::vcpu::VcpuPidTid;

const KVM_PATH: &str = "/dev/kvm";
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
#[cfg(feature = "geniezone")]
const GENIEZONE_PATH: &str = "/dev/gzvm";
#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), feature = "gunyah"))]
static GUNYAH_PATH: &str = "/dev/gunyah";
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
#[cfg(feature = "halla")]
const HALLA_PATH: &str = "/dev/hvm";

fn create_virtio_devices(
    cfg: &Config,
    vm: &mut impl VmArch,
    resources: &mut SystemAllocator,
    add_control_tube: &mut impl FnMut(AnyControlTube),
    #[cfg_attr(not(feature = "gpu"), allow(unused_variables))] vm_evt_wrtube: &SendTube,
    #[cfg(feature = "balloon")] balloon_inflate_tube: Option<Tube>,
    worker_process_pids: &mut BTreeSet<Pid>,
    #[cfg(feature = "gpu")] render_server_fd: Option<SafeDescriptor>,
    #[cfg(feature = "gpu")] has_vfio_gfx_device: bool,
    #[cfg(feature = "registered_events")] registered_evt_q: &SendTube,
) -> DeviceResult<Vec<VirtioDeviceStub>> {
    let mut devs = Vec::new();

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
            cfg.jail_config.as_ref(),
            &cfg.wayland_socket_paths,
            wl_resource_bridge,
        )?);
    }

    #[cfg(all(feature = "media", feature = "video-decoder"))]
    let media_adapter_cfg = cfg
        .media_decoder
        .iter()
        .map(|config| {
            let (video_tube, gpu_tube) =
                Tube::pair().expect("failed to create tube for media adapter");
            resource_bridges.push(gpu_tube);
            (video_tube, config.backend)
        })
        .collect::<Vec<_>>();

    #[cfg(feature = "video-decoder")]
    let video_dec_cfg = cfg
        .video_dec
        .iter()
        .map(|config| {
            let (video_tube, gpu_tube) =
                Tube::pair().expect("failed to create tube for video decoder");
            resource_bridges.push(gpu_tube);
            (video_tube, config.backend)
        })
        .collect::<Vec<_>>();

    #[cfg(feature = "video-encoder")]
    let video_enc_cfg = cfg
        .video_enc
        .iter()
        .map(|config| {
            let (video_tube, gpu_tube) =
                Tube::pair().expect("failed to create tube for video encoder");
            resource_bridges.push(gpu_tube);
            (video_tube, config.backend)
        })
        .collect::<Vec<_>>();

    #[cfg(feature = "gpu")]
    {
        if let Some(gpu_parameters) = &cfg.gpu_parameters {
            let mut event_devices = Vec::new();
            if cfg.display_window_mouse {
                let display_param = if gpu_parameters.display_params.is_empty() {
                    Default::default()
                } else {
                    gpu_parameters.display_params[0].clone()
                };
                let (gpu_display_w, gpu_display_h) = display_param.get_virtual_display_size();

                let (event_device_socket, virtio_dev_socket) =
                    StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte)
                        .context("failed to create socket")?;
                let mut multi_touch_width = gpu_display_w;
                let mut multi_touch_height = gpu_display_h;
                let mut multi_touch_name = None;
                for input in &cfg.virtio_input {
                    if let InputDeviceOption::MultiTouch {
                        width,
                        height,
                        name,
                        ..
                    } = input
                    {
                        if let Some(width) = width {
                            multi_touch_width = *width;
                        }
                        if let Some(height) = height {
                            multi_touch_height = *height;
                        }
                        if let Some(name) = name {
                            multi_touch_name = Some(name.as_str());
                        }
                        break;
                    }
                }
                let dev = virtio::input::new_multi_touch(
                    // u32::MAX is the least likely to collide with the indices generated above for
                    // the multi_touch options, which begin at 0.
                    u32::MAX,
                    virtio_dev_socket,
                    multi_touch_width,
                    multi_touch_height,
                    multi_touch_name,
                    virtio::base_features(cfg.protection_type),
                )
                .context("failed to set up mouse device")?;
                devs.push(VirtioDeviceStub {
                    dev: Box::new(dev),
                    jail: simple_jail(cfg.jail_config.as_ref(), "input_device")?,
                });
                event_devices.push(EventDevice::touchscreen(event_device_socket));
            }
            if cfg.display_window_keyboard {
                let (event_device_socket, virtio_dev_socket) =
                    StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte)
                        .context("failed to create socket")?;
                let dev = virtio::input::new_keyboard(
                    // u32::MAX is the least likely to collide with the indices generated above for
                    // the multi_touch options, which begin at 0.
                    u32::MAX,
                    virtio_dev_socket,
                    virtio::base_features(cfg.protection_type),
                )
                .context("failed to set up keyboard device")?;
                devs.push(VirtioDeviceStub {
                    dev: Box::new(dev),
                    jail: simple_jail(cfg.jail_config.as_ref(), "input_device")?,
                });
                event_devices.push(EventDevice::keyboard(event_device_socket));
            }

            let (gpu_control_host_tube, gpu_control_device_tube) =
                Tube::pair().context("failed to create gpu tube")?;
            add_control_tube(DeviceControlTube::Gpu(gpu_control_host_tube).into());
            devs.push(create_gpu_device(
                cfg,
                vm_evt_wrtube,
                gpu_control_device_tube,
                resource_bridges,
                render_server_fd,
                has_vfio_gfx_device,
                event_devices,
            )?);
        }
    }

    for (_, param) in cfg
        .serial_parameters
        .iter()
        .filter(|(_k, v)| v.hardware == SerialHardware::VirtioConsole)
    {
        let dev =
            param.create_virtio_device_and_jail(cfg.protection_type, cfg.jail_config.as_ref())?;
        devs.push(dev);
    }

    for disk in &cfg.disks {
        let (disk_host_tube, disk_device_tube) = Tube::pair().context("failed to create tube")?;
        add_control_tube(DeviceControlTube::Disk(disk_host_tube).into());
        let disk_config = DiskConfig::new(disk, Some(disk_device_tube));
        devs.push(
            disk_config
                .create_virtio_device_and_jail(cfg.protection_type, cfg.jail_config.as_ref())?,
        );
    }

    if !cfg.scsis.is_empty() {
        let scsi_config = ScsiConfig(&cfg.scsis);
        devs.push(
            scsi_config
                .create_virtio_device_and_jail(cfg.protection_type, cfg.jail_config.as_ref())?,
        );
    }

    for (index, pmem_disk) in cfg.pmems.iter().enumerate() {
        let (pmem_host_tube, pmem_device_tube) = Tube::pair().context("failed to create tube")?;
        add_control_tube(TaggedControlTube::VmMsync(pmem_host_tube).into());
        devs.push(create_pmem_device(
            cfg.protection_type,
            cfg.jail_config.as_ref(),
            vm,
            resources,
            pmem_disk,
            index,
            pmem_device_tube,
        )?);
    }

    for (index, pmem_ext2) in cfg.pmem_ext2.iter().enumerate() {
        // Prepare a `VmMemoryClient` for pmem-ext2 device to send a request for mmap() and memory
        // registeration.
        let (pmem_ext2_host_tube, pmem_ext2_device_tube) =
            Tube::pair().context("failed to create tube")?;
        let vm_memory_client = VmMemoryClient::new(pmem_ext2_device_tube);
        add_control_tube(
            VmMemoryTube {
                tube: pmem_ext2_host_tube,
                expose_with_viommu: false,
            }
            .into(),
        );
        let (pmem_host_tube, pmem_device_tube) = Tube::pair().context("failed to create tube")?;
        add_control_tube(TaggedControlTube::VmMsync(pmem_host_tube).into());
        devs.push(create_pmem_ext2_device(
            cfg.protection_type,
            cfg.jail_config.as_ref(),
            resources,
            pmem_ext2,
            index,
            vm_memory_client,
            pmem_device_tube,
            worker_process_pids,
        )?);
    }

    if cfg.rng {
        devs.push(create_rng_device(
            cfg.protection_type,
            cfg.jail_config.as_ref(),
        )?);
    }

    #[cfg(feature = "pvclock")]
    if cfg.pvclock {
        // pvclock gets a tube for handling suspend/resume requests from the main thread.
        let (host_suspend_tube, suspend_tube) = Tube::pair().context("failed to create tube")?;
        add_control_tube(DeviceControlTube::PvClock(host_suspend_tube).into());

        let frequency: u64;
        #[cfg(target_arch = "x86_64")]
        {
            let tsc_state = devices::tsc::tsc_state()?;
            let tsc_sync_mitigations =
                get_tsc_sync_mitigations(&tsc_state, cfg.vcpu_count.unwrap_or(1));
            if tsc_state.core_grouping.size() > 1 {
                // Host TSCs are not in sync. Log what mitigations are applied.
                warn!(
                    "Host TSCs are not in sync, applying the following mitigations: {:?}",
                    tsc_sync_mitigations
                );
            }
            frequency = tsc_state.frequency;
        }
        #[cfg(target_arch = "aarch64")]
        {
            let mut x: u64;
            // SAFETY: This instruction have no side effect apart from storing the current timestamp
            //         frequency into the specified register.
            unsafe {
                asm!("mrs {x}, cntfrq_el0",
                    x = out(reg) x,
                );
            }
            frequency = x;

            // If unset, KVM defaults to an offset that is calculated from VM boot time. Explicitly
            // set it to zero on boot. When updating the offset, we always set it to the total
            // amount of time the VM has been suspended.
            vm.set_counter_offset(0)
                .context("failed to set up pvclock")?;
        }
        let dev = create_pvclock_device(
            cfg.protection_type,
            cfg.jail_config.as_ref(),
            frequency,
            suspend_tube,
        )?;
        devs.push(dev);
        info!("virtio-pvclock is enabled for this vm");
    }

    #[cfg(feature = "vtpm")]
    {
        if cfg.vtpm_proxy {
            devs.push(create_vtpm_proxy_device(
                cfg.protection_type,
                cfg.jail_config.as_ref(),
            )?);
        }
    }

    let mut keyboard_idx = 0;
    let mut mouse_idx = 0;
    let mut rotary_idx = 0;
    let mut switches_idx = 0;
    let mut multi_touch_idx = 0;
    let mut single_touch_idx = 0;
    let mut trackpad_idx = 0;
    let mut multi_touch_trackpad_idx = 0;
    let mut custom_idx = 0;
    for input in &cfg.virtio_input {
        let input_dev = match input {
            InputDeviceOption::Evdev { path } => create_vinput_device(
                cfg.protection_type,
                cfg.jail_config.as_ref(),
                path.as_path(),
            )?,
            InputDeviceOption::Keyboard { path } => {
                let dev = create_keyboard_device(
                    cfg.protection_type,
                    cfg.jail_config.as_ref(),
                    path.as_path(),
                    keyboard_idx,
                )?;
                keyboard_idx += 1;
                dev
            }
            InputDeviceOption::Mouse { path } => {
                let dev = create_mouse_device(
                    cfg.protection_type,
                    cfg.jail_config.as_ref(),
                    path.as_path(),
                    mouse_idx,
                )?;
                mouse_idx += 1;
                dev
            }
            InputDeviceOption::MultiTouch {
                path,
                width,
                height,
                name,
            } => {
                let mut width = *width;
                let mut height = *height;
                if multi_touch_idx == 0 {
                    if width.is_none() {
                        width = cfg.display_input_width;
                    }
                    if height.is_none() {
                        height = cfg.display_input_height;
                    }
                }
                let dev = create_multi_touch_device(
                    cfg.protection_type,
                    cfg.jail_config.as_ref(),
                    path.as_path(),
                    width.unwrap_or(DEFAULT_TOUCH_DEVICE_WIDTH),
                    height.unwrap_or(DEFAULT_TOUCH_DEVICE_HEIGHT),
                    name.as_deref(),
                    multi_touch_idx,
                )?;
                multi_touch_idx += 1;
                dev
            }
            InputDeviceOption::Rotary { path } => {
                let dev = create_rotary_device(
                    cfg.protection_type,
                    cfg.jail_config.as_ref(),
                    path.as_path(),
                    rotary_idx,
                )?;
                rotary_idx += 1;
                dev
            }
            InputDeviceOption::SingleTouch {
                path,
                width,
                height,
                name,
            } => {
                let mut width = *width;
                let mut height = *height;
                if single_touch_idx == 0 {
                    if width.is_none() {
                        width = cfg.display_input_width;
                    }
                    if height.is_none() {
                        height = cfg.display_input_height;
                    }
                }
                let dev = create_single_touch_device(
                    cfg.protection_type,
                    cfg.jail_config.as_ref(),
                    path.as_path(),
                    width.unwrap_or(DEFAULT_TOUCH_DEVICE_WIDTH),
                    height.unwrap_or(DEFAULT_TOUCH_DEVICE_HEIGHT),
                    name.as_deref(),
                    single_touch_idx,
                )?;
                single_touch_idx += 1;
                dev
            }
            InputDeviceOption::Switches { path } => {
                let dev = create_switches_device(
                    cfg.protection_type,
                    cfg.jail_config.as_ref(),
                    path.as_path(),
                    switches_idx,
                )?;
                switches_idx += 1;
                dev
            }
            InputDeviceOption::Trackpad {
                path,
                width,
                height,
                name,
            } => {
                let dev = create_trackpad_device(
                    cfg.protection_type,
                    cfg.jail_config.as_ref(),
                    path.as_path(),
                    width.unwrap_or(DEFAULT_TOUCH_DEVICE_WIDTH),
                    height.unwrap_or(DEFAULT_TOUCH_DEVICE_HEIGHT),
                    name.as_deref(),
                    trackpad_idx,
                )?;
                trackpad_idx += 1;
                dev
            }
            InputDeviceOption::MultiTouchTrackpad {
                path,
                width,
                height,
                name,
            } => {
                let dev = create_multitouch_trackpad_device(
                    cfg.protection_type,
                    cfg.jail_config.as_ref(),
                    path.as_path(),
                    width.unwrap_or(DEFAULT_TOUCH_DEVICE_WIDTH),
                    height.unwrap_or(DEFAULT_TOUCH_DEVICE_HEIGHT),
                    name.as_deref(),
                    multi_touch_trackpad_idx,
                )?;
                multi_touch_trackpad_idx += 1;
                dev
            }
            InputDeviceOption::Custom { path, config_path } => {
                let dev = create_custom_device(
                    cfg.protection_type,
                    cfg.jail_config.as_ref(),
                    path.as_path(),
                    custom_idx,
                    config_path.clone(),
                )?;
                custom_idx += 1;
                dev
            }
        };
        devs.push(input_dev);
    }

    #[cfg(feature = "balloon")]
    if cfg.balloon {
        let balloon_device_tube = if let Some(ref path) = cfg.balloon_control {
            Tube::try_from(UnixSeqpacket::connect(path).with_context(|| {
                format!(
                    "failed to connect to balloon control socket {}",
                    path.display(),
                )
            })?)?
        } else {
            // Balloon gets a special socket so balloon requests can be forwarded
            // from the main process.
            let (host, device) = Tube::pair().context("failed to create tube")?;
            add_control_tube(DeviceControlTube::Balloon(host).into());
            device
        };

        let balloon_features = (cfg.balloon_page_reporting as u64)
            << BalloonFeatures::PageReporting as u64
            | (cfg.balloon_ws_reporting as u64) << BalloonFeatures::WSReporting as u64;

        let init_balloon_size = if let Some(init_memory) = cfg.init_memory {
            let init_memory_bytes = init_memory.saturating_mul(1024 * 1024);
            let total_memory_bytes = vm.get_memory().memory_size();

            if init_memory_bytes > total_memory_bytes {
                bail!(
                    "initial memory {} cannot be greater than total memory {}",
                    init_memory,
                    total_memory_bytes / (1024 * 1024),
                );
            }

            // The initial balloon size is the total memory size minus the initial memory size.
            total_memory_bytes - init_memory_bytes
        } else {
            // No --init-mem specified; start with balloon completely deflated.
            0
        };

        // The balloon device also needs a tube to communicate back to the main process to
        // handle remapping memory dynamically.
        let (dynamic_mapping_host_tube, dynamic_mapping_device_tube) =
            Tube::pair().context("failed to create tube")?;
        add_control_tube(
            VmMemoryTube {
                tube: dynamic_mapping_host_tube,
                expose_with_viommu: false,
            }
            .into(),
        );

        devs.push(create_balloon_device(
            cfg.protection_type,
            cfg.jail_config.as_ref(),
            balloon_device_tube,
            balloon_inflate_tube,
            init_balloon_size,
            VmMemoryClient::new(dynamic_mapping_device_tube),
            balloon_features,
            #[cfg(feature = "registered_events")]
            Some(
                registered_evt_q
                    .try_clone()
                    .context("failed to clone registered_evt_q tube")?,
            ),
            cfg.balloon_ws_num_bins,
        )?);
    }

    #[cfg(feature = "net")]
    for opt in &cfg.net {
        let dev =
            opt.create_virtio_device_and_jail(cfg.protection_type, cfg.jail_config.as_ref())?;
        devs.push(dev);
    }

    #[cfg(feature = "audio")]
    {
        for (card_index, virtio_snd) in cfg.virtio_snds.iter().enumerate() {
            let (snd_host_tube, snd_device_tube) =
                Tube::pair().context("failed to create tube for snd")?;
            add_control_tube(DeviceControlTube::Snd(snd_host_tube).into());
            let mut snd_params = virtio_snd.clone();
            snd_params.card_index = card_index;
            devs.push(create_virtio_snd_device(
                cfg.protection_type,
                cfg.jail_config.as_ref(),
                snd_params,
                snd_device_tube,
            )?);
        }
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(feature = "media")]
    {
        for v4l2_device in &cfg.v4l2_proxy {
            devs.push(create_v4l2_device(cfg.protection_type, v4l2_device)?);
        }
    }

    #[cfg(feature = "media")]
    if cfg.simple_media_device {
        devs.push(create_simple_media_device(cfg.protection_type)?);
    }

    #[cfg(all(feature = "media", feature = "video-decoder"))]
    {
        for (tube, backend) in media_adapter_cfg {
            devs.push(create_virtio_media_adapter(
                cfg.protection_type,
                cfg.jail_config.as_ref(),
                tube,
                backend,
            )?);
        }
    }

    #[cfg(feature = "video-decoder")]
    {
        for (tube, backend) in video_dec_cfg {
            register_video_device(
                backend,
                &mut devs,
                tube,
                cfg.protection_type,
                cfg.jail_config.as_ref(),
                VideoDeviceType::Decoder,
            )?;
        }
    }

    #[cfg(feature = "video-encoder")]
    {
        for (tube, backend) in video_enc_cfg {
            register_video_device(
                backend,
                &mut devs,
                tube,
                cfg.protection_type,
                cfg.jail_config.as_ref(),
                VideoDeviceType::Encoder,
            )?;
        }
    }

    if let Some(vsock_config) = &cfg.vsock {
        devs.push(
            vsock_config
                .create_virtio_device_and_jail(cfg.protection_type, cfg.jail_config.as_ref())?,
        );
    }

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        if cfg.vhost_scmi {
            devs.push(create_vhost_scmi_device(
                cfg.protection_type,
                cfg.jail_config.as_ref(),
                cfg.vhost_scmi_device.clone(),
            )?);
        }
    }

    for shared_dir in &cfg.shared_dirs {
        let SharedDir {
            src,
            tag,
            kind,
            ugid,
            uid_map,
            gid_map,
            fs_cfg,
            p9_cfg,
        } = shared_dir;

        let dev = match kind {
            SharedDirKind::FS => {
                let (host_tube, device_tube) = Tube::pair().context("failed to create tube")?;
                add_control_tube(TaggedControlTube::Fs(host_tube).into());

                create_fs_device(
                    cfg.protection_type,
                    cfg.jail_config.as_ref(),
                    *ugid,
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
                cfg.jail_config.as_ref(),
                *ugid,
                uid_map,
                gid_map,
                src,
                tag,
                p9_cfg.clone(),
            )?,
        };
        devs.push(dev);
    }

    #[cfg(feature = "audio")]
    if let Some(path) = &cfg.sound {
        devs.push(create_sound_device(
            path,
            cfg.protection_type,
            cfg.jail_config.as_ref(),
        )?);
    }

    for opt in &cfg.vhost_user {
        devs.push(create_vhost_user_frontend(
            cfg.protection_type,
            opt,
            cfg.vhost_user_connect_timeout_ms,
            vm_evt_wrtube.try_clone()?,
        )?);
    }

    Ok(devs)
}

fn create_devices(
    cfg: &Config,
    vm: &mut impl VmArch,
    resources: &mut SystemAllocator,
    add_control_tube: &mut impl FnMut(AnyControlTube),
    vm_evt_wrtube: &SendTube,
    iommu_attached_endpoints: &mut BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>>,
    #[cfg(feature = "usb")] usb_provider: DeviceProvider,
    #[cfg(feature = "gpu")] render_server_fd: Option<SafeDescriptor>,
    iova_max_addr: &mut Option<u64>,
    #[cfg(feature = "registered_events")] registered_evt_q: &SendTube,
    vfio_container_manager: &mut VfioContainerManager,
    // Stores a set of PID of child processes that are suppose to exit cleanly.
    worker_process_pids: &mut BTreeSet<Pid>,
) -> DeviceResult<Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>> {
    let mut devices: Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)> = Vec::new();
    #[cfg(feature = "balloon")]
    let mut balloon_inflate_tube: Option<Tube> = None;
    #[cfg(feature = "gpu")]
    let mut has_vfio_gfx_device = false;
    if !cfg.vfio.is_empty() {
        let mut coiommu_attached_endpoints = Vec::new();

        for vfio_dev in &cfg.vfio {
            let (dev, jail, viommu_mapper) = create_vfio_device(
                cfg.jail_config.as_ref(),
                vm,
                resources,
                add_control_tube,
                &vfio_dev.path,
                false,
                None,
                vfio_dev.guest_address,
                Some(&mut coiommu_attached_endpoints),
                vfio_dev.iommu,
                vfio_dev.dt_symbol.clone(),
                vfio_container_manager,
            )?;
            match dev {
                VfioDeviceVariant::Pci(vfio_pci_device) => {
                    *iova_max_addr = Some(max(
                        vfio_pci_device.get_max_iova(),
                        iova_max_addr.unwrap_or(0),
                    ));

                    #[cfg(feature = "gpu")]
                    if vfio_pci_device.is_gfx() {
                        has_vfio_gfx_device = true;
                    }

                    if let Some(viommu_mapper) = viommu_mapper {
                        iommu_attached_endpoints.insert(
                            vfio_pci_device
                                .pci_address()
                                .context("not initialized")?
                                .to_u32(),
                            Arc::new(Mutex::new(Box::new(viommu_mapper))),
                        );
                    }

                    devices.push((Box::new(vfio_pci_device), jail));
                }
                VfioDeviceVariant::Platform(vfio_plat_dev) => {
                    devices.push((Box::new(vfio_plat_dev), jail));
                }
            }
        }

        if !coiommu_attached_endpoints.is_empty() || !iommu_attached_endpoints.is_empty() {
            let mut buf = mem::MaybeUninit::<libc::rlimit64>::zeroed();
            // SAFETY: trivially safe
            let res = unsafe { libc::getrlimit64(libc::RLIMIT_MEMLOCK, buf.as_mut_ptr()) };
            if res == 0 {
                // SAFETY: safe because getrlimit64 has returned success.
                let limit = unsafe { buf.assume_init() };
                let rlim_new = limit.rlim_cur.saturating_add(vm.get_memory().memory_size());
                let rlim_max = max(limit.rlim_max, rlim_new);
                if limit.rlim_cur < rlim_new {
                    let limit_arg = libc::rlimit64 {
                        rlim_cur: rlim_new,
                        rlim_max,
                    };
                    // SAFETY: trivially safe
                    let res = unsafe { libc::setrlimit64(libc::RLIMIT_MEMLOCK, &limit_arg) };
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
            let vfio_container = vfio_container_manager
                .get_container(IommuDevType::CoIommu, None as Option<&Path>)
                .context("failed to get vfio container")?;
            let (coiommu_host_tube, coiommu_device_tube) =
                Tube::pair().context("failed to create coiommu tube")?;
            add_control_tube(
                VmMemoryTube {
                    tube: coiommu_host_tube,
                    expose_with_viommu: false,
                }
                .into(),
            );
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
                VmMemoryClient::new(coiommu_device_tube),
                coiommu_tube,
                coiommu_attached_endpoints,
                vcpu_count,
                cfg.coiommu_param.unwrap_or_default(),
            )
            .context("failed to create coiommu device")?;

            devices.push((
                Box::new(dev),
                simple_jail(cfg.jail_config.as_ref(), "coiommu_device")?,
            ));
        }
    }

    let stubs = create_virtio_devices(
        cfg,
        vm,
        resources,
        add_control_tube,
        vm_evt_wrtube,
        #[cfg(feature = "balloon")]
        balloon_inflate_tube,
        worker_process_pids,
        #[cfg(feature = "gpu")]
        render_server_fd,
        #[cfg(feature = "gpu")]
        has_vfio_gfx_device,
        #[cfg(feature = "registered_events")]
        registered_evt_q,
    )?;

    for stub in stubs {
        let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
        add_control_tube(AnyControlTube::IrqTube(msi_host_tube));

        let shared_memory_tube = if stub.dev.get_shared_memory_region().is_some() {
            let (host_tube, device_tube) =
                Tube::pair().context("failed to create shared memory tube")?;
            add_control_tube(
                VmMemoryTube {
                    tube: host_tube,
                    expose_with_viommu: stub.dev.expose_shmem_descriptors_with_viommu(),
                }
                .into(),
            );
            Some(device_tube)
        } else {
            None
        };

        let (ioevent_host_tube, ioevent_device_tube) =
            Tube::pair().context("failed to create ioevent tube")?;
        add_control_tube(
            VmMemoryTube {
                tube: ioevent_host_tube,
                expose_with_viommu: false,
            }
            .into(),
        );

        let (host_tube, device_tube) =
            Tube::pair().context("failed to create device control tube")?;
        add_control_tube(TaggedControlTube::Vm(host_tube).into());

        let dev = VirtioPciDevice::new(
            vm.get_memory().clone(),
            stub.dev,
            msi_device_tube,
            cfg.disable_virtio_intx,
            shared_memory_tube.map(VmMemoryClient::new),
            VmMemoryClient::new(ioevent_device_tube),
            device_tube,
        )
        .context("failed to create virtio pci dev")?;

        devices.push((Box::new(dev) as Box<dyn BusDeviceObj>, stub.jail));
    }

    #[cfg(feature = "usb")]
    if cfg.usb {
        // Create xhci controller.
        let usb_controller = Box::new(XhciController::new(
            vm.get_memory().clone(),
            Box::new(usb_provider),
        ));
        devices.push((
            usb_controller,
            simple_jail(cfg.jail_config.as_ref(), "xhci_device")?,
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

fn create_mmio_file_backed_mappings(
    cfg: &Config,
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
) -> Result<()> {
    for mapping in &cfg.file_backed_mappings_mmio {
        let file = mapping
            .open()
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
            // TODO(b/222769529): Reserve this region in a global memory address space allocator
            // once we have that so nothing else can accidentally overlap with it.
            Ok(()) | Err(resources::Error::OutOfSpace) => {}
            e => e.context("failed to allocate guest address for file-backed mapping")?,
        }

        vm.add_memory_region(
            GuestAddress(mapping.address),
            Box::new(memory_mapping),
            !mapping.writable,
            /* log_dirty_pages = */ false,
            MemCacheType::CacheCoherent,
        )
        .context("failed to configure file-backed mapping")?;
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
/// Collection of devices related to PCI hotplug.
struct HotPlugStub {
    /// Map from bus index to hotplug bus.
    hotplug_buses: BTreeMap<u8, Arc<Mutex<dyn HotPlugBus>>>,
    /// Bus ranges of devices for virtio-iommu.
    iommu_bus_ranges: Vec<RangeInclusive<u32>>,
    /// Map from gpe index to GpeNotify devices.
    gpe_notify_devs: BTreeMap<u32, Arc<Mutex<dyn GpeNotify>>>,
    /// Map from bus index to GpeNotify devices.
    pme_notify_devs: BTreeMap<u8, Arc<Mutex<dyn PmeNotify>>>,
}

#[cfg(target_arch = "x86_64")]
impl HotPlugStub {
    /// Constructs empty HotPlugStub.
    fn new() -> Self {
        Self {
            hotplug_buses: BTreeMap::new(),
            iommu_bus_ranges: Vec::new(),
            gpe_notify_devs: BTreeMap::new(),
            pme_notify_devs: BTreeMap::new(),
        }
    }
}

#[cfg(target_arch = "x86_64")]
/// Creates PCIE root port with only virtual devices.
///
/// user doesn't specify host pcie root port which link to this virtual pcie rp,
/// find the empty bus and create a total virtual pcie rp
fn create_pure_virtual_pcie_root_port(
    sys_allocator: &mut SystemAllocator,
    add_control_tube: &mut impl FnMut(AnyControlTube),
    devices: &mut Vec<(Box<dyn BusDeviceObj>, Option<Minijail>)>,
    hp_bus_count: u8,
) -> Result<HotPlugStub> {
    let mut hp_sec_buses = Vec::new();
    let mut hp_stub = HotPlugStub::new();
    // Create Pcie Root Port for non-root buses, each non-root bus device will be
    // connected behind a virtual pcie root port.
    for i in 1..255 {
        if sys_allocator.pci_bus_empty(i) {
            if hp_sec_buses.len() < hp_bus_count.into() {
                hp_sec_buses.push(i);
            }
            continue;
        }
        let pcie_root_port = Arc::new(Mutex::new(PcieRootPort::new(i, false)));
        hp_stub
            .pme_notify_devs
            .insert(i, pcie_root_port.clone() as Arc<Mutex<dyn PmeNotify>>);
        let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
        add_control_tube(AnyControlTube::IrqTube(msi_host_tube));
        let pci_bridge = Box::new(PciBridge::new(pcie_root_port.clone(), msi_device_tube));
        // no ipc is used if the root port disables hotplug
        devices.push((pci_bridge, None));
    }

    // Create Pcie Root Port for hot-plug
    if hp_sec_buses.len() < hp_bus_count.into() {
        return Err(anyhow!("no more addresses are available"));
    }

    for hp_sec_bus in hp_sec_buses {
        let pcie_root_port = Arc::new(Mutex::new(PcieRootPort::new(hp_sec_bus, true)));
        hp_stub.pme_notify_devs.insert(
            hp_sec_bus,
            pcie_root_port.clone() as Arc<Mutex<dyn PmeNotify>>,
        );
        let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
        add_control_tube(AnyControlTube::IrqTube(msi_host_tube));
        let pci_bridge = Box::new(PciBridge::new(pcie_root_port.clone(), msi_device_tube));

        hp_stub.iommu_bus_ranges.push(RangeInclusive::new(
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
        hp_stub
            .hotplug_buses
            .insert(hp_sec_bus, pcie_root_port as Arc<Mutex<dyn HotPlugBus>>);
    }
    Ok(hp_stub)
}

fn setup_vm_components(cfg: &Config) -> Result<VmComponents> {
    let initrd_image = if let Some(initrd_path) = &cfg.initrd_path {
        Some(
            open_file_or_duplicate(initrd_path, OpenOptions::new().read(true))
                .with_context(|| format!("failed to open initrd {}", initrd_path.display()))?,
        )
    } else {
        None
    };
    let pvm_fw_image = if let Some(pvm_fw_path) = &cfg.pvm_fw {
        Some(
            open_file_or_duplicate(pvm_fw_path, OpenOptions::new().read(true))
                .with_context(|| format!("failed to open pvm_fw {}", pvm_fw_path.display()))?,
        )
    } else {
        None
    };

    let vm_image = match cfg.executable_path {
        Some(Executable::Kernel(ref kernel_path)) => VmImage::Kernel(
            open_file_or_duplicate(kernel_path, OpenOptions::new().read(true)).with_context(
                || format!("failed to open kernel image {}", kernel_path.display()),
            )?,
        ),
        Some(Executable::Bios(ref bios_path)) => VmImage::Bios(
            open_file_or_duplicate(bios_path, OpenOptions::new().read(true))
                .with_context(|| format!("failed to open bios {}", bios_path.display()))?,
        ),
        _ => panic!("Did not receive a bios or kernel, should be impossible."),
    };

    let swiotlb = if let Some(size) = cfg.swiotlb {
        Some(
            size.checked_mul(1024 * 1024)
                .ok_or_else(|| anyhow!("requested swiotlb size too large"))?,
        )
    } else if matches!(cfg.protection_type, ProtectionType::Unprotected) {
        None
    } else {
        Some(64 * 1024 * 1024)
    };

    let (pflash_image, pflash_block_size) = if let Some(pflash_parameters) = &cfg.pflash_parameters
    {
        (
            Some(
                open_file_or_duplicate(
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

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let mut cpu_frequencies = BTreeMap::new();
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let mut normalized_cpu_ipc_ratios = BTreeMap::new();

    // if --enable-fw-cfg or --fw-cfg was given, we want to enable fw_cfg
    let fw_cfg_enable = cfg.enable_fw_cfg || !cfg.fw_cfg_parameters.is_empty();
    let (cpu_clusters, cpu_capacity) = if cfg.host_cpu_topology {
        (
            Arch::get_host_cpu_clusters()?,
            Arch::get_host_cpu_capacity()?,
        )
    } else {
        (cfg.cpu_clusters.clone(), cfg.cpu_capacity.clone())
    };

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let cpu_ipc_ratio = if cfg.host_cpu_topology {
        &cpu_capacity
    } else {
        &cfg.cpu_ipc_ratio
    };

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let mut vcpu_domain_paths = BTreeMap::new();
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let mut vcpu_domains = BTreeMap::new();

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    if cfg.virt_cpufreq || cfg.virt_cpufreq_v2 {
        if !cfg.cpu_frequencies_khz.is_empty() {
            cpu_frequencies = cfg.cpu_frequencies_khz.clone();
        } else {
            match Arch::get_host_cpu_frequencies_khz() {
                Ok(host_cpu_frequencies) => {
                    for cpu_id in 0..cfg.vcpu_count.unwrap_or(1) {
                        let vcpu_affinity = match cfg.vcpu_affinity.clone() {
                            Some(VcpuAffinity::Global(v)) => v,
                            Some(VcpuAffinity::PerVcpu(mut m)) => {
                                m.remove(&cpu_id).unwrap_or_default()
                            }
                            None => {
                                panic!("There must be some vcpu_affinity setting with VirtCpufreq enabled!")
                            }
                        };

                        // Check that the physical CPUs that the vCPU is affined to all share the
                        // same frequency domain.
                        if let Some(freq_domain) = host_cpu_frequencies.get(&vcpu_affinity[0]) {
                            for cpu in vcpu_affinity.iter() {
                                if let Some(frequencies) = host_cpu_frequencies.get(cpu) {
                                    if frequencies != freq_domain {
                                        panic!("Affined CPUs do not share a frequency domain!");
                                    }
                                }
                            }
                            cpu_frequencies.insert(cpu_id, freq_domain.clone());
                        } else {
                            panic!("No frequency domain for cpu:{}", cpu_id);
                        }
                    }
                }
                Err(e) => {
                    warn!("Unable to get host cpu frequencies {:#}", e);
                }
            }
        }

        if !cpu_frequencies.is_empty() {
            let host_max_freqs = Arch::get_host_cpu_max_freq_khz()?;
            // Find the highest maximum frequency over all host CPUs. The guest CPU IPC ratios will
            // be normalized by dividing by this value.
            let host_max_freq = host_max_freqs.values().copied().max().unwrap_or_default();

            normalized_cpu_ipc_ratios = normalize_cpu_ipc_ratios(
                cpu_frequencies.iter().map(|(cpu_id, frequencies)| {
                    (
                        *cpu_id,
                        frequencies.iter().copied().max().unwrap_or_default(),
                    )
                }),
                host_max_freq,
                |cpu_id| cpu_ipc_ratio.get(&cpu_id).copied().unwrap_or(1024),
            )?;

            if !cfg.cpu_freq_domains.is_empty() {
                let cgroup_path = cfg
                    .vcpu_cgroup_path
                    .clone()
                    .context("cpu_freq_domains requires vcpu_cgroup_path")?;

                if !cgroup_path.join("cgroup.controllers").exists() {
                    panic!("CGroupsV2 must be enabled for cpu freq domain support!");
                }

                // Assign parent crosvm process to top level cgroup
                let cgroup_procs_path = cgroup_path.join("cgroup.procs");
                std::fs::write(
                    cgroup_procs_path.clone(),
                    process::id().to_string().as_bytes(),
                )
                .with_context(|| {
                    format!(
                        "failed to create vcpu-cgroup-path {}",
                        cgroup_procs_path.display(),
                    )
                })?;

                for (freq_domain_idx, cpus) in cfg.cpu_freq_domains.iter().enumerate() {
                    let vcpu_domain_path =
                        cgroup_path.join(format!("vcpu-domain{}", freq_domain_idx));
                    // Create subtree for domain
                    create_dir_all(&vcpu_domain_path)?;

                    // Set vcpu_domain cgroup type as 'threaded' to get thread level granularity
                    // controls
                    let cgroup_type_path = cgroup_path.join(vcpu_domain_path.join("cgroup.type"));
                    std::fs::write(cgroup_type_path.clone(), b"threaded").with_context(|| {
                        format!(
                            "failed to create vcpu-cgroup-path {}",
                            cgroup_type_path.display(),
                        )
                    })?;
                    for core_idx in cpus.iter() {
                        vcpu_domain_paths.insert(*core_idx, vcpu_domain_path.clone());
                        vcpu_domains.insert(*core_idx, freq_domain_idx as u32);
                    }
                }
            }
        }
    }

    Ok(VmComponents {
        #[cfg(target_arch = "x86_64")]
        ac_adapter: cfg.ac_adapter,
        #[cfg(target_arch = "x86_64")]
        break_linux_pci_config_io: cfg.break_linux_pci_config_io,
        memory_size: cfg
            .memory
            .unwrap_or(256)
            .checked_mul(1024 * 1024)
            .ok_or_else(|| anyhow!("requested memory size too large"))?,
        swiotlb,
        fw_cfg_enable,
        bootorder_fw_cfg_blob: Vec::new(),
        vcpu_count: cfg.vcpu_count.unwrap_or(1),
        vcpu_affinity: cfg.vcpu_affinity.clone(),
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        vcpu_domains,
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        vcpu_domain_paths,
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        cpu_frequencies,
        fw_cfg_parameters: cfg.fw_cfg_parameters.clone(),
        cpu_clusters,
        cpu_capacity,
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        normalized_cpu_ipc_ratios,
        no_smt: cfg.no_smt,
        hugepages: cfg.hugepages,
        hv_cfg: hypervisor::Config {
            #[cfg(target_arch = "aarch64")]
            mte: cfg.mte,
            protection_type: cfg.protection_type,
            #[cfg(all(target_os = "android", target_arch = "aarch64"))]
            ffa: cfg.ffa.map(|g| g.auto).unwrap_or(false),
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
        no_i8042: cfg.no_i8042,
        no_rtc: cfg.no_rtc,
        #[cfg(target_arch = "x86_64")]
        smbios: cfg.smbios.clone(),
        host_cpu_topology: cfg.host_cpu_topology,
        itmt: cfg.itmt,
        #[cfg(target_arch = "x86_64")]
        force_s2idle: cfg.force_s2idle,
        pvm_fw: pvm_fw_image,
        pci_config: cfg.pci_config,
        dynamic_power_coefficient: cfg.dynamic_power_coefficient.clone(),
        boot_cpu: cfg.boot_cpu,
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        virt_cpufreq_v2: cfg.virt_cpufreq_v2,
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        sve_config: cfg.sve.unwrap_or_default(),
    })
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
fn normalize_cpu_ipc_ratios(
    max_frequency_per_cpu: impl Iterator<Item = (usize, u32)>,
    host_max_freq: u32,
    cpu_ipc_ratio: impl Fn(usize) -> u32,
) -> Result<BTreeMap<usize, u32>> {
    if host_max_freq == 0 {
        return Err(anyhow!("invalid host_max_freq 0"));
    }

    let host_max_freq = u64::from(host_max_freq);
    let mut normalized_cpu_ipc_ratios = BTreeMap::new();
    for (cpu_id, max_freq) in max_frequency_per_cpu {
        let ipc_ratio = u64::from(cpu_ipc_ratio(cpu_id));
        let max_freq = u64::from(max_freq);

        let normalized_cpu_ipc_ratio = (ipc_ratio * max_freq) / host_max_freq;

        normalized_cpu_ipc_ratios.insert(
            cpu_id,
            u32::try_from(normalized_cpu_ipc_ratio)
                .context("normalized CPU IPC ratio out of u32 range")?,
        );
    }

    Ok(normalized_cpu_ipc_ratios)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExitState {
    Reset,
    Stop,
    Crash,
    GuestPanic,
    WatchdogReset,
}

// Replaces ranges in `guest_mem_layout` that overlap with ranges in `file_backed_mappings`.
// Returns the updated guest memory layout.
fn punch_holes_in_guest_mem_layout_for_mappings(
    guest_mem_layout: Vec<(GuestAddress, u64, MemoryRegionOptions)>,
    file_backed_mappings_ram: &[FileBackedMappingParameters],
) -> Result<Vec<(GuestAddress, u64, MemoryRegionOptions)>> {
    // Create a set containing (start, end) pairs with exclusive end (end = start + size; the byte
    // at end is not included in the range).
    let mut layout_set = BTreeSet::new();
    for (addr, size, options) in &guest_mem_layout {
        layout_set.insert((addr.offset(), addr.offset() + size, options.clone()));
    }

    // Make sure the RAM mappings are a subset of the RAM memory layout.
    // For simplicity, we currently require each mapping to be fully contained within a single
    // region of the input layout.
    for mapping in file_backed_mappings_ram {
        anyhow::ensure!(
            layout_set
                .iter()
                .any(|(addr, size, _)| *addr <= mapping.address
                    && mapping.address + mapping.size <= *addr + *size),
            "RAM file-backed-mapping must be a subset of a RAM region"
        );
    }

    for mapping in file_backed_mappings_ram.iter().cloned() {
        let mapping_start = mapping.address;
        let mapping_end = mapping_start + mapping.size;
        let mut purpose = None;
        // Repeatedly split overlapping guest memory regions until no overlaps remain.
        while let Some((range_start, range_end, options)) = layout_set
            .iter()
            .find(|&&(range_start, range_end, _)| {
                mapping_start < range_end && mapping_end > range_start
            })
            .cloned()
        {
            let purpose = *purpose.get_or_insert(options.purpose);
            anyhow::ensure!(
                options.purpose == purpose,
                "RAM file-backed-mapping cannot span regions with different purposes: {:?} vs {:?}",
                options.purpose,
                purpose
            );

            layout_set.remove(&(range_start, range_end, options.clone()));

            if range_start < mapping_start {
                layout_set.insert((range_start, mapping_start, options.clone()));
            }
            if range_end > mapping_end {
                layout_set.insert((mapping_end, range_end, options));
            }
        }
        layout_set.insert((
            mapping_start,
            mapping_end,
            MemoryRegionOptions::new()
                .purpose(purpose.unwrap())
                .file_backed(mapping),
        ));
    }

    // Build the final guest memory layout from the modified layout_set.
    Ok(layout_set
        .into_iter()
        .map(|(start, end, options)| (GuestAddress(start), end - start, options))
        .collect())
}

fn create_guest_memory(
    cfg: &Config,
    components: &VmComponents,
    arch_memory_layout: &<Arch as LinuxArch>::ArchMemoryLayout,
    hypervisor: &impl Hypervisor,
) -> Result<GuestMemory> {
    let guest_mem_layout = Arch::guest_memory_layout(components, arch_memory_layout, hypervisor)
        .context("failed to create guest memory layout")?;

    let guest_mem_layout = punch_holes_in_guest_mem_layout_for_mappings(
        guest_mem_layout,
        &cfg.file_backed_mappings_ram,
    )?;

    let mut guest_mem = GuestMemory::new_with_options(&guest_mem_layout)
        .context("failed to create guest memory")?;
    let mut mem_policy = MemoryPolicy::empty();
    if components.hugepages {
        mem_policy |= MemoryPolicy::USE_HUGEPAGES;
    }

    if cfg.lock_guest_memory || cfg.lock_guest_memory_dontneed {
        mem_policy |= MemoryPolicy::LOCK_GUEST_MEMORY;
    }
    if cfg.lock_guest_memory_dontneed {
        mem_policy |= MemoryPolicy::USE_DONTNEED_LOCKED;
    }
    guest_mem.set_memory_policy(mem_policy);

    if cfg.unmap_guest_memory_on_fork {
        // Note that this isn't compatible with sandboxing. We could potentially fix that by
        // delaying the call until after the sandboxed devices are forked. However, the main use
        // for this is in conjunction with protected VMs, where most of the guest memory has been
        // unshared with the host. We'd need to be confident that the guest memory is unshared with
        // the host only after the `use_dontfork` call and those details will vary by hypervisor.
        // So, for now we keep things simple to be safe.
        guest_mem.use_dontfork().context("use_dontfork failed")?;
    }

    Ok(guest_mem)
}

#[cfg(all(target_arch = "aarch64", feature = "geniezone"))]
fn run_gz(device_path: Option<&Path>, cfg: Config, components: VmComponents) -> Result<ExitState> {
    use devices::GeniezoneKernelIrqChip;
    use hypervisor::geniezone::Geniezone;
    use hypervisor::geniezone::GeniezoneVcpu;
    use hypervisor::geniezone::GeniezoneVm;

    let device_path = device_path.unwrap_or(Path::new(GENIEZONE_PATH));
    let gzvm = Geniezone::new_with_path(device_path)
        .with_context(|| format!("failed to open GenieZone device {}", device_path.display()))?;

    let arch_memory_layout =
        Arch::arch_memory_layout(&components).context("failed to create arch memory layout")?;
    let guest_mem = create_guest_memory(&cfg, &components, &arch_memory_layout, &gzvm)?;

    #[cfg(feature = "swap")]
    let swap_controller = if let Some(swap_dir) = cfg.swap_dir.as_ref() {
        Some(
            SwapController::launch(guest_mem.clone(), swap_dir, cfg.jail_config.as_ref())
                .context("launch vmm-swap monitor process")?,
        )
    } else {
        None
    };

    let vm =
        GeniezoneVm::new(&gzvm, guest_mem, components.hv_cfg).context("failed to create vm")?;

    // Check that the VM was actually created in protected mode as expected.
    if cfg.protection_type.isolates_memory() && !vm.check_capability(VmCap::Protected) {
        bail!("Failed to create protected VM");
    }
    let vm_clone = vm.try_clone().context("failed to clone vm")?;

    let ioapic_host_tube;
    let mut irq_chip = match cfg.irq_chip.unwrap_or(IrqChipKind::Kernel) {
        IrqChipKind::Split => bail!("Geniezone does not support split irqchip mode"),
        IrqChipKind::Userspace => bail!("Geniezone does not support userspace irqchip mode"),
        IrqChipKind::Kernel => {
            ioapic_host_tube = None;
            GeniezoneKernelIrqChip::new(vm_clone, components.vcpu_count)
                .context("failed to create IRQ chip")?
        }
    };

    run_vm::<GeniezoneVcpu, GeniezoneVm>(
        cfg,
        components,
        &arch_memory_layout,
        vm,
        &mut irq_chip,
        ioapic_host_tube,
        #[cfg(feature = "swap")]
        swap_controller,
    )
}

#[cfg(all(target_arch = "aarch64", feature = "halla"))]
fn run_halla(
    device_path: Option<&Path>,
    cfg: Config,
    components: VmComponents,
) -> Result<ExitState> {
    use devices::HallaKernelIrqChip;
    use hypervisor::halla::Halla;
    use hypervisor::halla::HallaVcpu;
    use hypervisor::halla::HallaVm;

    let device_path = device_path.unwrap_or(Path::new(HALLA_PATH));
    let hvm = Halla::new_with_path(device_path)
        .with_context(|| format!("failed to open Halla device {}", device_path.display()))?;

    let arch_memory_layout =
        Arch::arch_memory_layout(&components).context("failed to create arch memory layout")?;
    let guest_mem = create_guest_memory(&cfg, &components, &arch_memory_layout, &hvm)?;

    #[cfg(feature = "swap")]
    let swap_controller = if let Some(swap_dir) = cfg.swap_dir.as_ref() {
        Some(
            SwapController::launch(guest_mem.clone(), swap_dir, cfg.jail_config.as_ref())
                .context("launch vmm-swap monitor process")?,
        )
    } else {
        None
    };

    let vm = HallaVm::new(&hvm, guest_mem, components.hv_cfg).context("failed to create vm")?;

    // Check that the VM was actually created in protected mode as expected.
    if cfg.protection_type.isolates_memory() && !vm.check_capability(VmCap::Protected) {
        bail!("Failed to create protected VM");
    }
    let vm_clone = vm.try_clone().context("failed to clone vm")?;

    let ioapic_host_tube;
    let mut irq_chip = match cfg.irq_chip.unwrap_or(IrqChipKind::Kernel) {
        IrqChipKind::Split => bail!("Halla does not support split irqchip mode"),
        IrqChipKind::Userspace => bail!("Halla does not support userspace irqchip mode"),
        IrqChipKind::Kernel => {
            ioapic_host_tube = None;
            HallaKernelIrqChip::new(vm_clone, components.vcpu_count)
                .context("failed to create IRQ chip")?
        }
    };

    run_vm::<HallaVcpu, HallaVm>(
        cfg,
        components,
        &arch_memory_layout,
        vm,
        &mut irq_chip,
        ioapic_host_tube,
        #[cfg(feature = "swap")]
        swap_controller,
    )
}

fn run_kvm(device_path: Option<&Path>, cfg: Config, components: VmComponents) -> Result<ExitState> {
    use devices::KvmKernelIrqChip;
    #[cfg(target_arch = "x86_64")]
    use devices::KvmSplitIrqChip;
    use hypervisor::kvm::Kvm;
    use hypervisor::kvm::KvmVcpu;
    use hypervisor::kvm::KvmVm;

    let device_path = device_path.unwrap_or(Path::new(KVM_PATH));
    let kvm = Kvm::new_with_path(device_path)
        .with_context(|| format!("failed to open KVM device {}", device_path.display()))?;

    let arch_memory_layout =
        Arch::arch_memory_layout(&components).context("failed to create arch memory layout")?;
    let guest_mem = create_guest_memory(&cfg, &components, &arch_memory_layout, &kvm)?;

    #[cfg(feature = "swap")]
    let swap_controller = if let Some(swap_dir) = cfg.swap_dir.as_ref() {
        Some(
            SwapController::launch(guest_mem.clone(), swap_dir, cfg.jail_config.as_ref())
                .context("launch vmm-swap monitor process")?,
        )
    } else {
        None
    };

    let vm = KvmVm::new(&kvm, guest_mem, components.hv_cfg).context("failed to create vm")?;

    #[cfg(target_arch = "x86_64")]
    if cfg.itmt {
        vm.set_platform_info_read_access(false)
            .context("failed to disable MSR_PLATFORM_INFO read access")?;
    }

    // Check that the VM was actually created in protected mode as expected.
    // This check is only needed on aarch64. On x86_64, protected VM creation will fail
    // if protected mode is not supported.
    #[cfg(not(target_arch = "x86_64"))]
    if cfg.protection_type.isolates_memory() && !vm.check_capability(VmCap::Protected) {
        bail!("Failed to create protected VM");
    }
    let vm_clone = vm.try_clone().context("failed to clone vm")?;

    enum KvmIrqChip {
        #[cfg(target_arch = "x86_64")]
        Split(KvmSplitIrqChip),
        Kernel(KvmKernelIrqChip),
    }

    impl KvmIrqChip {
        fn as_mut(&mut self) -> &mut dyn IrqChipArch {
            match self {
                #[cfg(target_arch = "x86_64")]
                KvmIrqChip::Split(i) => i,
                KvmIrqChip::Kernel(i) => i,
            }
        }
    }

    let ioapic_host_tube;
    let mut irq_chip = match cfg.irq_chip.unwrap_or(IrqChipKind::Kernel) {
        IrqChipKind::Userspace => {
            bail!("KVM userspace irqchip mode not implemented");
        }
        IrqChipKind::Split => {
            #[cfg(not(target_arch = "x86_64"))]
            bail!("KVM split irqchip mode only supported on x86 processors");
            #[cfg(target_arch = "x86_64")]
            {
                let (host_tube, ioapic_device_tube) =
                    Tube::pair().context("failed to create tube")?;
                ioapic_host_tube = Some(host_tube);
                KvmIrqChip::Split(
                    KvmSplitIrqChip::new(
                        vm_clone,
                        components.vcpu_count,
                        ioapic_device_tube,
                        Some(24),
                    )
                    .context("failed to create IRQ chip")?,
                )
            }
        }
        IrqChipKind::Kernel => {
            ioapic_host_tube = None;
            KvmIrqChip::Kernel(
                KvmKernelIrqChip::new(vm_clone, components.vcpu_count)
                    .context("failed to create IRQ chip")?,
            )
        }
    };

    run_vm::<KvmVcpu, KvmVm>(
        cfg,
        components,
        &arch_memory_layout,
        vm,
        irq_chip.as_mut(),
        ioapic_host_tube,
        #[cfg(feature = "swap")]
        swap_controller,
    )
}

#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), feature = "gunyah"))]
fn run_gunyah(
    device_path: Option<&Path>,
    qcom_trusted_vm_id: Option<u16>,
    qcom_trusted_vm_pas_id: Option<u32>,
    cfg: Config,
    components: VmComponents,
) -> Result<ExitState> {
    use devices::GunyahIrqChip;
    use hypervisor::gunyah::Gunyah;
    use hypervisor::gunyah::GunyahVcpu;
    use hypervisor::gunyah::GunyahVm;

    let device_path = device_path.unwrap_or(Path::new(GUNYAH_PATH));
    let gunyah = Gunyah::new_with_path(device_path)
        .with_context(|| format!("failed to open Gunyah device {}", device_path.display()))?;

    let arch_memory_layout =
        Arch::arch_memory_layout(&components).context("failed to create arch memory layout")?;
    let guest_mem = create_guest_memory(&cfg, &components, &arch_memory_layout, &gunyah)?;

    #[cfg(feature = "swap")]
    let swap_controller = if let Some(swap_dir) = cfg.swap_dir.as_ref() {
        Some(
            SwapController::launch(guest_mem.clone(), swap_dir, cfg.jail_config.as_ref())
                .context("launch vmm-swap monitor process")?,
        )
    } else {
        None
    };

    let vm = GunyahVm::new(
        &gunyah,
        qcom_trusted_vm_id,
        qcom_trusted_vm_pas_id,
        guest_mem,
        components.hv_cfg,
    )
    .context("failed to create vm")?;

    // Check that the VM was actually created in protected mode as expected.
    if cfg.protection_type.isolates_memory() && !vm.check_capability(VmCap::Protected) {
        bail!("Failed to create protected VM");
    }

    let vm_clone = vm.try_clone()?;

    run_vm::<GunyahVcpu, GunyahVm>(
        cfg,
        components,
        &arch_memory_layout,
        vm,
        &mut GunyahIrqChip::new(vm_clone)?,
        None,
        #[cfg(feature = "swap")]
        swap_controller,
    )
}

/// Choose a default hypervisor if no `--hypervisor` option was specified.
fn get_default_hypervisor() -> Option<HypervisorKind> {
    let kvm_path = Path::new(KVM_PATH);
    if kvm_path.exists() {
        return Some(HypervisorKind::Kvm {
            device: Some(kvm_path.to_path_buf()),
        });
    }

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    #[cfg(feature = "geniezone")]
    {
        let gz_path = Path::new(GENIEZONE_PATH);
        if gz_path.exists() {
            return Some(HypervisorKind::Geniezone {
                device: Some(gz_path.to_path_buf()),
            });
        }
    }

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    #[cfg(feature = "halla")]
    {
        let halla_path = Path::new(HALLA_PATH);
        if halla_path.exists() {
            return Some(HypervisorKind::Halla {
                device: Some(halla_path.to_path_buf()),
            });
        }
    }

    #[cfg(all(
        unix,
        any(target_arch = "arm", target_arch = "aarch64"),
        feature = "gunyah"
    ))]
    {
        let gunyah_path = Path::new(GUNYAH_PATH);
        if gunyah_path.exists() {
            return Some(HypervisorKind::Gunyah {
                device: Some(gunyah_path.to_path_buf()),
                qcom_trusted_vm_id: None,
                qcom_trusted_vm_pas_id: None,
            });
        }
    }

    None
}

pub fn run_config(cfg: Config) -> Result<ExitState> {
    let components = setup_vm_components(&cfg)?;

    let hypervisor = cfg
        .hypervisor
        .clone()
        .or_else(get_default_hypervisor)
        .context("no enabled hypervisor")?;

    debug!("creating hypervisor: {:?}", hypervisor);

    match hypervisor {
        HypervisorKind::Kvm { device } => run_kvm(device.as_deref(), cfg, components),
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        #[cfg(feature = "geniezone")]
        HypervisorKind::Geniezone { device } => run_gz(device.as_deref(), cfg, components),
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        #[cfg(feature = "halla")]
        HypervisorKind::Halla { device } => run_halla(device.as_deref(), cfg, components),
        #[cfg(all(
            unix,
            any(target_arch = "arm", target_arch = "aarch64"),
            feature = "gunyah"
        ))]
        HypervisorKind::Gunyah {
            device,
            qcom_trusted_vm_id,
            qcom_trusted_vm_pas_id,
        } => run_gunyah(
            device.as_deref(),
            qcom_trusted_vm_id,
            qcom_trusted_vm_pas_id,
            cfg,
            components,
        ),
    }
}

fn run_vm<Vcpu, V>(
    cfg: Config,
    #[allow(unused_mut)] mut components: VmComponents,
    arch_memory_layout: &<Arch as LinuxArch>::ArchMemoryLayout,
    mut vm: V,
    irq_chip: &mut dyn IrqChipArch,
    ioapic_host_tube: Option<Tube>,
    #[cfg(feature = "swap")] mut swap_controller: Option<SwapController>,
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

    let (metrics_send, metrics_recv) = Tube::directional_pair().context("metrics tube")?;
    metrics::initialize(metrics_send);

    #[cfg(all(feature = "pci-hotplug", feature = "swap"))]
    let swap_device_helper = match &swap_controller {
        Some(swap_controller) => Some(swap_controller.create_device_helper()?),
        None => None,
    };
    // pci-hotplug is only implemented for x86_64 for now, attempting to use it on other platform
    // would crash.
    #[cfg(all(feature = "pci-hotplug", not(target_arch = "x86_64")))]
    if cfg.pci_hotplug_slots.is_some() {
        bail!("pci-hotplug is not implemented for non x86_64 architecture");
    }
    // hotplug_manager must be created before vm is started since it forks jail warden process.
    #[cfg(feature = "pci-hotplug")]
    // TODO(293801301): Remove unused_mut after aarch64 support
    #[allow(unused_mut)]
    let mut hotplug_manager = if cfg.pci_hotplug_slots.is_some() {
        Some(PciHotPlugManager::new(
            vm.get_memory().clone(),
            &cfg,
            #[cfg(feature = "swap")]
            swap_device_helper,
        )?)
    } else {
        None
    };

    #[cfg(feature = "usb")]
    let (usb_control_tube, usb_provider) =
        DeviceProvider::new().context("failed to create usb provider")?;

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

    let mut all_control_tubes = Vec::new();
    let mut add_control_tube = |t| all_control_tubes.push(t);

    if let Some(ioapic_host_tube) = ioapic_host_tube {
        add_control_tube(AnyControlTube::IrqTube(ioapic_host_tube));
    }

    let battery = if cfg.battery_config.is_some() {
        #[cfg_attr(
            not(feature = "power-monitor-powerd"),
            allow(clippy::manual_map, clippy::needless_match, unused_mut)
        )]
        let jail = if let Some(jail_config) = cfg.jail_config.as_ref() {
            let mut config = SandboxConfig::new(jail_config, "battery");
            #[cfg(feature = "power-monitor-powerd")]
            {
                config.bind_mounts = true;
            }
            let mut jail =
                create_sandbox_minijail(&jail_config.pivot_root, MAX_OPEN_FILES_DEFAULT, &config)?;

            // Setup a bind mount to the system D-Bus socket if the powerd monitor is used.
            #[cfg(feature = "power-monitor-powerd")]
            {
                let system_bus_socket_path = Path::new("/run/dbus/system_bus_socket");
                jail.mount_bind(system_bus_socket_path, system_bus_socket_path, true)?;
            }
            Some(jail)
        } else {
            None
        };
        (cfg.battery_config.as_ref().map(|c| c.type_), jail)
    } else {
        (cfg.battery_config.as_ref().map(|c| c.type_), None)
    };

    let (vm_evt_wrtube, vm_evt_rdtube) =
        Tube::directional_pair().context("failed to create vm event tube")?;

    let pstore_size = components.pstore.as_ref().map(|pstore| pstore.size as u64);
    let mut sys_allocator = SystemAllocator::new(
        Arch::get_system_allocator_config(&vm, arch_memory_layout),
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

    create_mmio_file_backed_mappings(&cfg, &mut vm, &mut sys_allocator)?;

    #[cfg(feature = "gpu")]
    // Hold on to the render server jail so it keeps running until we exit run_vm()
    let (_render_server_jail, render_server_fd) =
        if let Some(parameters) = &cfg.gpu_render_server_parameters {
            let (jail, fd) = start_gpu_render_server(&cfg, parameters)?;
            (Some(ScopedMinijail(jail)), Some(fd))
        } else {
            (None, None)
        };

    let mut iommu_attached_endpoints: BTreeMap<u32, Arc<Mutex<Box<dyn MemoryMapperTrait>>>> =
        BTreeMap::new();
    let mut iova_max_addr: Option<u64> = None;

    let mut vfio_container_manager = VfioContainerManager::new();

    #[cfg(feature = "registered_events")]
    let (reg_evt_wrtube, reg_evt_rdtube) =
        Tube::directional_pair().context("failed to create registered event tube")?;

    let mut worker_process_pids = BTreeSet::new();

    let mut devices = create_devices(
        &cfg,
        &mut vm,
        &mut sys_allocator,
        &mut add_control_tube,
        &vm_evt_wrtube,
        &mut iommu_attached_endpoints,
        #[cfg(feature = "usb")]
        usb_provider,
        #[cfg(feature = "gpu")]
        render_server_fd,
        &mut iova_max_addr,
        #[cfg(feature = "registered_events")]
        &reg_evt_wrtube,
        &mut vfio_container_manager,
        &mut worker_process_pids,
    )?;

    #[cfg(feature = "pci-hotplug")]
    // TODO(293801301): Remove unused_variables after aarch64 support
    #[allow(unused_variables)]
    let pci_hotplug_slots = cfg.pci_hotplug_slots;
    #[cfg(not(feature = "pci-hotplug"))]
    #[allow(unused_variables)]
    let pci_hotplug_slots: Option<u8> = None;
    #[cfg(target_arch = "x86_64")]
    let hp_stub = create_pure_virtual_pcie_root_port(
        &mut sys_allocator,
        &mut add_control_tube,
        &mut devices,
        pci_hotplug_slots.unwrap_or(1),
    )?;

    arch::assign_pci_addresses(&mut devices, &mut sys_allocator)?;

    let pci_devices: Vec<&dyn PciDevice> = devices
        .iter()
        .filter_map(|d| (d.0).as_pci_device())
        .collect();

    let virtio_devices: Vec<(&dyn VirtioDevice, devices::PciAddress)> = pci_devices
        .into_iter()
        .flat_map(|s| {
            if let Some(virtio_pci_device) = s.as_virtio_pci_device() {
                std::iter::zip(
                    Some(virtio_pci_device.virtio_device()),
                    virtio_pci_device.pci_address(),
                )
                .next()
            } else {
                None
            }
        })
        .collect();

    let mut open_firmware_device_paths: Vec<(Vec<u8>, usize)> = virtio_devices
        .iter()
        .flat_map(|s| (s.0).bootorder_fw_cfg(s.1.dev))
        .collect();

    // order the OpenFirmware device paths, in ascending order, by their boot_index
    open_firmware_device_paths.sort_by(|a, b| (a.1).cmp(&(b.1)));

    // "/pci@iocf8/" is x86 specific and represents the root at the system bus port
    let mut bootorder_fw_cfg_blob =
        open_firmware_device_paths
            .into_iter()
            .fold(Vec::new(), |a, b| {
                a.into_iter()
                    .chain("/pci@i0cf8/".as_bytes().iter().copied())
                    .chain(b.0)
                    .chain("\n".as_bytes().iter().copied())
                    .collect()
            });

    // the "bootorder" file is expected to end with a null terminator
    bootorder_fw_cfg_blob.push(0);

    components.bootorder_fw_cfg_blob = bootorder_fw_cfg_blob;

    // if the bootindex argument was given, we want to make sure that fw_cfg is enabled so the
    // "bootorder" file can be accessed by the guest.
    components.fw_cfg_enable |= components.bootorder_fw_cfg_blob.len() > 1;

    let (translate_response_senders, request_rx) = setup_virtio_access_platform(
        &mut sys_allocator,
        &mut iommu_attached_endpoints,
        &mut devices,
    )?;

    #[cfg(target_arch = "x86_64")]
    let iommu_bus_ranges = hp_stub.iommu_bus_ranges;
    #[cfg(not(target_arch = "x86_64"))]
    let iommu_bus_ranges = Vec::new();

    let iommu_host_tube = if !iommu_attached_endpoints.is_empty()
        || (cfg.vfio_isolate_hotplug && !iommu_bus_ranges.is_empty())
    {
        let (iommu_host_tube, iommu_device_tube) = Tube::pair().context("failed to create tube")?;
        let iommu_dev = create_iommu_device(
            cfg.protection_type,
            cfg.jail_config.as_ref(),
            iova_max_addr.unwrap_or(u64::MAX),
            iommu_attached_endpoints,
            iommu_bus_ranges,
            translate_response_senders,
            request_rx,
            iommu_device_tube,
        )?;

        let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
        add_control_tube(AnyControlTube::IrqTube(msi_host_tube));
        let (ioevent_host_tube, ioevent_device_tube) =
            Tube::pair().context("failed to create ioevent tube")?;
        add_control_tube(
            VmMemoryTube {
                tube: ioevent_host_tube,
                expose_with_viommu: false,
            }
            .into(),
        );
        let (host_tube, device_tube) =
            Tube::pair().context("failed to create device control tube")?;
        add_control_tube(TaggedControlTube::Vm(host_tube).into());
        let mut dev = VirtioPciDevice::new(
            vm.get_memory().clone(),
            iommu_dev.dev,
            msi_device_tube,
            cfg.disable_virtio_intx,
            None,
            VmMemoryClient::new(ioevent_device_tube),
            device_tube,
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

    #[cfg(target_arch = "x86_64")]
    for device in devices
        .iter_mut()
        .filter_map(|(dev, _)| dev.as_pci_device_mut())
    {
        device
            .generate_acpi(&mut components.acpi_sdts)
            .with_context(|| format!("generate_acpi failed for {}", device.debug_label()))?;
    }

    // KVM_CREATE_VCPU uses apic id for x86 and uses cpu id for others.
    let mut vcpu_ids = Vec::new();

    let guest_suspended_cvar = if cfg.force_s2idle {
        Some(Arc::new((Mutex::new(false), Condvar::new())))
    } else {
        None
    };

    let dt_overlays = cfg
        .device_tree_overlay
        .iter()
        .map(|o| {
            Ok(DtbOverlay {
                file: open_file_or_duplicate(o.path.as_path(), OpenOptions::new().read(true))
                    .with_context(|| {
                        format!("failed to open device tree overlay {}", o.path.display())
                    })?,
                do_filter: o.filter_devs,
            })
        })
        .collect::<Result<Vec<DtbOverlay>>>()?;

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let vcpu_domain_paths = components.vcpu_domain_paths.clone();

    let mut linux = Arch::build_vm::<V, Vcpu>(
        components,
        arch_memory_layout,
        &vm_evt_wrtube,
        &mut sys_allocator,
        &cfg.serial_parameters,
        simple_jail(cfg.jail_config.as_ref(), "serial_device")?,
        battery,
        vm,
        ramoops_region,
        devices,
        irq_chip,
        &mut vcpu_ids,
        cfg.dump_device_tree_blob.clone(),
        simple_jail(cfg.jail_config.as_ref(), "serial_device")?,
        #[cfg(target_arch = "x86_64")]
        simple_jail(cfg.jail_config.as_ref(), "block_device")?,
        #[cfg(target_arch = "x86_64")]
        simple_jail(cfg.jail_config.as_ref(), "fw_cfg_device")?,
        #[cfg(feature = "swap")]
        &mut swap_controller,
        guest_suspended_cvar.clone(),
        dt_overlays,
        cfg.fdt_position,
        cfg.no_pmu,
    )
    .context("the architecture failed to build the vm")?;

    for tube in linux.vm_request_tubes.drain(..) {
        add_control_tube(TaggedControlTube::Vm(tube).into());
    }

    #[cfg(target_arch = "x86_64")]
    let (hp_control_tube, hp_worker_tube) = mpsc::channel();
    #[cfg(all(feature = "pci-hotplug", target_arch = "x86_64"))]
    if let Some(hotplug_manager) = &mut hotplug_manager {
        hotplug_manager.set_rootbus_controller(hp_control_tube.clone())?;
    }
    #[cfg(target_arch = "x86_64")]
    let hp_thread = {
        for (bus_num, hp_bus) in hp_stub.hotplug_buses.into_iter() {
            #[cfg(feature = "pci-hotplug")]
            if let Some(hotplug_manager) = &mut hotplug_manager {
                hotplug_manager.add_port(hp_bus)?;
            } else {
                linux.hotplug_bus.insert(bus_num, hp_bus);
            }
            #[cfg(not(feature = "pci-hotplug"))]
            linux.hotplug_bus.insert(bus_num, hp_bus);
        }

        if let Some(pm) = &linux.pm {
            for (gpe, notify_dev) in hp_stub.gpe_notify_devs.into_iter() {
                pm.lock().register_gpe_notify_dev(gpe, notify_dev);
            }
            for (bus, notify_dev) in hp_stub.pme_notify_devs.into_iter() {
                pm.lock().register_pme_notify_dev(bus, notify_dev);
            }
        }

        let (hp_vm_mem_host_tube, hp_vm_mem_worker_tube) =
            Tube::pair().context("failed to create tube")?;
        add_control_tube(
            VmMemoryTube {
                tube: hp_vm_mem_host_tube,
                expose_with_viommu: false,
            }
            .into(),
        );

        let supports_readonly_mapping = linux.vm.supports_readonly_mapping();
        let pci_root = linux.root_config.clone();
        std::thread::Builder::new()
            .name("pci_root".to_string())
            .spawn(move || {
                start_pci_root_worker(
                    supports_readonly_mapping,
                    pci_root,
                    hp_worker_tube,
                    hp_vm_mem_worker_tube,
                )
            })?
    };

    let flags = RutabagaGrallocBackendFlags::new().disable_vulkano();
    let gralloc = RutabagaGralloc::new(flags).context("failed to create gralloc")?;

    run_control(
        linux,
        sys_allocator,
        cfg,
        control_server_socket,
        all_control_tubes,
        #[cfg(feature = "usb")]
        usb_control_tube,
        vm_evt_rdtube,
        vm_evt_wrtube,
        sigchld_fd,
        gralloc,
        vcpu_ids,
        iommu_host_tube,
        #[cfg(target_arch = "x86_64")]
        hp_control_tube,
        #[cfg(target_arch = "x86_64")]
        hp_thread,
        #[cfg(feature = "pci-hotplug")]
        hotplug_manager,
        #[cfg(feature = "swap")]
        swap_controller,
        #[cfg(feature = "registered_events")]
        reg_evt_rdtube,
        guest_suspended_cvar,
        metrics_recv,
        vfio_container_manager,
        worker_process_pids,
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        vcpu_domain_paths,
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
#[cfg(target_arch = "x86_64")]
fn start_pci_root_worker(
    supports_readonly_mapping: bool,
    pci_root: Arc<Mutex<PciRoot>>,
    hp_device_tube: mpsc::Receiver<PciRootCommand>,
    vm_control_tube: Tube,
) {
    struct PciMmioMapperTube {
        supports_readonly_mapping: bool,
        vm_control_tube: Tube,
        registered_regions: BTreeMap<u32, VmMemoryRegionId>,
        next_id: u32,
    }

    impl PciMmioMapper for PciMmioMapperTube {
        fn supports_readonly_mapping(&self) -> bool {
            self.supports_readonly_mapping
        }

        fn add_mapping(&mut self, addr: GuestAddress, shmem: &SharedMemory) -> anyhow::Result<u32> {
            let shmem = shmem
                .try_clone()
                .context("failed to create new SharedMemory")?;
            self.vm_control_tube
                .send(&VmMemoryRequest::RegisterMemory {
                    source: VmMemorySource::SharedMemory(shmem),
                    dest: VmMemoryDestination::GuestPhysicalAddress(addr.0),
                    prot: Protection::read(),
                    cache: MemCacheType::CacheCoherent,
                })
                .context("failed to send request")?;
            match self.vm_control_tube.recv::<VmMemoryResponse>() {
                Ok(VmMemoryResponse::RegisterMemory { region_id, .. }) => {
                    let cur_id = self.next_id;
                    self.registered_regions.insert(cur_id, region_id);
                    self.next_id += 1;
                    Ok(cur_id)
                }
                res => bail!("Bad response: {:?}", res),
            }
        }
    }

    let mut mapper = PciMmioMapperTube {
        supports_readonly_mapping,
        vm_control_tube,
        registered_regions: BTreeMap::new(),
        next_id: 0,
    };

    loop {
        match hp_device_tube.recv() {
            Ok(cmd) => match cmd {
                PciRootCommand::Add(addr, device) => {
                    if let Err(e) = pci_root.lock().add_device(addr, device, &mut mapper) {
                        error!("failed to add hotplugged device to PCI root port: {}", e);
                    }
                }
                PciRootCommand::AddBridge(pci_bus) => {
                    if let Err(e) = pci_root.lock().add_bridge(pci_bus) {
                        error!("failed to add hotplugged bridge to PCI root port: {}", e);
                    }
                }
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

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
fn add_hotplug_device<V: VmArch, Vcpu: VcpuArch>(
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    cfg: &Config,
    add_control_tube: &mut impl FnMut(AnyControlTube),
    hp_control_tube: &mpsc::Sender<PciRootCommand>,
    iommu_host_tube: Option<&Tube>,
    device: &HotPlugDeviceInfo,
    #[cfg(feature = "swap")] swap_controller: &mut Option<SwapController>,
    vfio_container_manager: &mut VfioContainerManager,
) -> Result<()> {
    let host_addr = PciAddress::from_path(&device.path)
        .context("failed to parse hotplug device's PCI address")?;
    let hp_bus = get_hp_bus(linux, host_addr)?;

    let (hotplug_key, pci_address) = match device.device_type {
        HotPlugDeviceType::UpstreamPort | HotPlugDeviceType::DownstreamPort => {
            let (vm_host_tube, vm_device_tube) = Tube::pair().context("failed to create tube")?;
            add_control_tube(TaggedControlTube::Vm(vm_host_tube).into());
            let (msi_host_tube, msi_device_tube) = Tube::pair().context("failed to create tube")?;
            add_control_tube(AnyControlTube::IrqTube(msi_host_tube));
            let pcie_host = PcieHostPort::new(device.path.as_path(), vm_device_tube)?;
            let (hotplug_key, pci_bridge) = match device.device_type {
                HotPlugDeviceType::UpstreamPort => {
                    let hotplug_key = HotPlugKey::HostUpstreamPort { host_addr };
                    let pcie_upstream_port = Arc::new(Mutex::new(PcieUpstreamPort::new_from_host(
                        pcie_host, true,
                    )?));
                    let pci_bridge =
                        Box::new(PciBridge::new(pcie_upstream_port.clone(), msi_device_tube));
                    linux
                        .hotplug_bus
                        .insert(pci_bridge.get_secondary_num(), pcie_upstream_port);
                    (hotplug_key, pci_bridge)
                }
                HotPlugDeviceType::DownstreamPort => {
                    let hotplug_key = HotPlugKey::HostDownstreamPort { host_addr };
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
                    (hotplug_key, pci_bridge)
                }
                _ => {
                    bail!("Impossible to reach here")
                }
            };
            let pci_address = Arch::register_pci_device(
                linux,
                pci_bridge,
                None,
                sys_allocator,
                hp_control_tube,
                #[cfg(feature = "swap")]
                swap_controller,
            )?;

            (hotplug_key, pci_address)
        }
        HotPlugDeviceType::EndPoint => {
            let hotplug_key = HotPlugKey::HostVfio { host_addr };
            let (vfio_device, jail, viommu_mapper) = create_vfio_device(
                cfg.jail_config.as_ref(),
                &linux.vm,
                sys_allocator,
                add_control_tube,
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
                None,
                vfio_container_manager,
            )?;
            let vfio_pci_device = match vfio_device {
                VfioDeviceVariant::Pci(pci) => Box::new(pci),
                VfioDeviceVariant::Platform(_) => bail!("vfio platform hotplug not supported"),
            };
            let pci_address = Arch::register_pci_device(
                linux,
                vfio_pci_device,
                jail,
                sys_allocator,
                hp_control_tube,
                #[cfg(feature = "swap")]
                swap_controller,
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
                            // SAFETY:
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

            (hotplug_key, pci_address)
        }
    };
    hp_bus.lock().add_hotplug_device(hotplug_key, pci_address);
    if device.hp_interrupt {
        hp_bus.lock().hot_plug(pci_address)?;
    }
    Ok(())
}

#[cfg(feature = "pci-hotplug")]
fn add_hotplug_net<V: VmArch, Vcpu: VcpuArch>(
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    add_control_tube: &mut impl FnMut(AnyControlTube),
    hotplug_manager: &mut PciHotPlugManager,
    net_param: NetParameters,
) -> Result<u8> {
    let (msi_host_tube, msi_device_tube) = Tube::pair().context("create tube")?;
    add_control_tube(AnyControlTube::IrqTube(msi_host_tube));
    let (ioevent_host_tube, ioevent_device_tube) = Tube::pair().context("create tube")?;
    let ioevent_vm_memory_client = VmMemoryClient::new(ioevent_device_tube);
    add_control_tube(
        VmMemoryTube {
            tube: ioevent_host_tube,
            expose_with_viommu: false,
        }
        .into(),
    );
    let (vm_control_host_tube, vm_control_device_tube) = Tube::pair().context("create tube")?;
    add_control_tube(TaggedControlTube::Vm(vm_control_host_tube).into());
    let net_carrier_device = NetResourceCarrier::new(
        net_param,
        msi_device_tube,
        ioevent_vm_memory_client,
        vm_control_device_tube,
    );
    hotplug_manager.hotplug_device(
        vec![ResourceCarrier::VirtioNet(net_carrier_device)],
        linux,
        sys_allocator,
    )
}

#[cfg(feature = "pci-hotplug")]
fn handle_hotplug_net_command<V: VmArch, Vcpu: VcpuArch>(
    net_cmd: NetControlCommand,
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    add_control_tube: &mut impl FnMut(AnyControlTube),
    hotplug_manager: &mut PciHotPlugManager,
) -> VmResponse {
    match net_cmd {
        NetControlCommand::AddTap(tap_name) => handle_hotplug_net_add(
            linux,
            sys_allocator,
            add_control_tube,
            hotplug_manager,
            &tap_name,
        ),
        NetControlCommand::RemoveTap(bus) => {
            handle_hotplug_net_remove(linux, sys_allocator, hotplug_manager, bus)
        }
    }
}

#[cfg(feature = "pci-hotplug")]
fn handle_hotplug_net_add<V: VmArch, Vcpu: VcpuArch>(
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    add_control_tube: &mut impl FnMut(AnyControlTube),
    hotplug_manager: &mut PciHotPlugManager,
    tap_name: &str,
) -> VmResponse {
    let net_param_mode = NetParametersMode::TapName {
        tap_name: tap_name.to_owned(),
        mac: None,
    };
    let net_param = NetParameters {
        mode: net_param_mode,
        vhost_net: None,
        vq_pairs: None,
        packed_queue: false,
        pci_address: None,
        mrg_rxbuf: false,
    };
    let ret = add_hotplug_net(
        linux,
        sys_allocator,
        add_control_tube,
        hotplug_manager,
        net_param,
    );

    match ret {
        Ok(pci_bus) => VmResponse::PciHotPlugResponse { bus: pci_bus },
        Err(e) => VmResponse::ErrString(format!("{:?}", e)),
    }
}

#[cfg(feature = "pci-hotplug")]
fn handle_hotplug_net_remove<V: VmArch, Vcpu: VcpuArch>(
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    hotplug_manager: &mut PciHotPlugManager,
    bus: u8,
) -> VmResponse {
    match hotplug_manager.remove_hotplug_device(bus, linux, sys_allocator) {
        Ok(_) => VmResponse::Ok,
        Err(e) => VmResponse::ErrString(format!("{:?}", e)),
    }
}

#[cfg(target_arch = "x86_64")]
fn remove_hotplug_bridge<V: VmArch, Vcpu: VcpuArch>(
    linux: &RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    buses_to_remove: &mut Vec<u8>,
    hotplug_key: HotPlugKey,
    child_bus: u8,
) -> Result<()> {
    for (bus_num, hp_bus) in linux.hotplug_bus.iter() {
        let mut hp_bus_lock = hp_bus.lock();
        if let Some(pci_addr) = hp_bus_lock.get_hotplug_device(hotplug_key) {
            sys_allocator.release_pci(pci_addr);
            hp_bus_lock.hot_unplug(pci_addr)?;
            buses_to_remove.push(child_bus);
            if hp_bus_lock.is_empty() {
                if let Some(hotplug_key) = hp_bus_lock.get_hotplug_key() {
                    remove_hotplug_bridge(
                        linux,
                        sys_allocator,
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
        hotplug_key
    ))
}

#[cfg(target_arch = "x86_64")]
fn remove_hotplug_device<V: VmArch, Vcpu: VcpuArch>(
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    iommu_host_tube: Option<&Tube>,
    device: &HotPlugDeviceInfo,
) -> Result<()> {
    let host_addr = PciAddress::from_path(&device.path)?;
    let hotplug_key = match device.device_type {
        HotPlugDeviceType::UpstreamPort => HotPlugKey::HostUpstreamPort { host_addr },
        HotPlugDeviceType::DownstreamPort => HotPlugKey::HostDownstreamPort { host_addr },
        HotPlugDeviceType::EndPoint => HotPlugKey::HostVfio { host_addr },
    };

    let hp_bus = linux
        .hotplug_bus
        .iter()
        .find(|(_, hp_bus)| {
            let hp_bus = hp_bus.lock();
            hp_bus.get_hotplug_device(hotplug_key).is_some()
        })
        .map(|(bus_num, hp_bus)| (*bus_num, hp_bus.clone()));

    if let Some((bus_num, hp_bus)) = hp_bus {
        let mut buses_to_remove = Vec::new();
        let mut removed_key = None;
        let mut hp_bus_lock = hp_bus.lock();
        if let Some(pci_addr) = hp_bus_lock.get_hotplug_device(hotplug_key) {
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
            if let Some(HotPlugKey::HostDownstreamPort { host_addr }) =
                hp_bus_lock.get_hotplug_key()
            {
                let addr_alias = host_addr;
                for (simbling_bus_num, hp_bus) in linux.hotplug_bus.iter() {
                    if *simbling_bus_num != bus_num {
                        let hp_bus_lock = hp_bus.lock();
                        let hotplug_key = hp_bus_lock.get_hotplug_key();
                        if let Some(HotPlugKey::HostDownstreamPort { host_addr }) = hotplug_key {
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
                hp_bus_lock.hot_unplug(pci_addr)?;
            }

            sys_allocator.release_pci(pci_addr);
            if empty_simbling || hp_bus_lock.is_empty() {
                if let Some(hotplug_key) = hp_bus_lock.get_hotplug_key() {
                    removed_key = Some(hotplug_key);
                    remove_hotplug_bridge(
                        linux,
                        sys_allocator,
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
        if let Some(HotPlugKey::HostDownstreamPort { host_addr }) = removed_key {
            let addr_alias = host_addr;
            for (simbling_bus_num, hp_bus) in linux.hotplug_bus.iter() {
                if *simbling_bus_num != bus_num {
                    let hp_bus_lock = hp_bus.lock();
                    let hotplug_key = hp_bus_lock.get_hotplug_key();
                    if let Some(HotPlugKey::HostDownstreamPort { host_addr }) = hotplug_key {
                        if addr_alias.bus == host_addr.bus && hp_bus_lock.is_empty() {
                            remove_hotplug_bridge(
                                linux,
                                sys_allocator,
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
        hotplug_key
    ))
}

pub fn trigger_vm_suspend_and_wait_for_entry(
    guest_suspended_cvar: Arc<(Mutex<bool>, Condvar)>,
    tube: &SendTube,
    response: vm_control::VmResponse,
    suspend_tube: Arc<Mutex<SendTube>>,
    pm: Option<Arc<Mutex<dyn PmResource + Send>>>,
) {
    let (lock, cvar) = &*guest_suspended_cvar;
    let mut guest_suspended = lock.lock();

    *guest_suspended = false;

    // During suspend also emulate sleepbtn, which allows to suspend VM (if running e.g. acpid and
    // reacts on sleep button events)
    if let Some(pm) = pm {
        pm.lock().slpbtn_evt();
    } else {
        error!("generating sleepbtn during suspend not supported");
    }

    // Wait for notification about guest suspension, if not received after 15sec,
    // proceed anyway.
    let result = cvar.wait_timeout(guest_suspended, std::time::Duration::from_secs(15));
    guest_suspended = result.0;

    if result.1.timed_out() {
        warn!("Guest suspension timeout - proceeding anyway");
    } else if *guest_suspended {
        info!("Guest suspended");
    }

    if let Err(e) = suspend_tube.lock().send(&true) {
        error!("failed to trigger suspend event: {}", e);
    }
    // Now we ready to send response over the tube and communicate that VM suspend has finished
    if let Err(e) = tube.send(&response) {
        error!("failed to send VmResponse: {}", e);
    }
}

#[cfg(feature = "pvclock")]
#[derive(Debug)]
/// The action requested by the pvclock device to perform on the main thread.
enum PvClockAction {
    #[cfg(target_arch = "aarch64")]
    /// Update the counter offset with VmAarch64::set_counter_offset.
    SetCounterOffset(u64),
}

#[cfg(feature = "pvclock")]
fn send_pvclock_cmd(tube: &Tube, command: PvClockCommand) -> Result<Option<PvClockAction>> {
    tube.send(&command)
        .with_context(|| format!("failed to send pvclock command {:?}", command))?;
    let resp = tube
        .recv::<PvClockCommandResponse>()
        .context("failed to receive pvclock command response")?;
    match resp {
        PvClockCommandResponse::Err(e) => {
            bail!("pvclock encountered error on {:?}: {}", command, e);
        }
        PvClockCommandResponse::DeviceInactive => {
            warn!("Tried to send {command:?} but pvclock device was inactive");
            Ok(None)
        }
        PvClockCommandResponse::Resumed {
            total_suspended_ticks,
        } => {
            info!("{command:?} completed with {total_suspended_ticks} total_suspended_ticks");
            cfg_if::cfg_if! {
                if #[cfg(target_arch = "aarch64")] {
                    Ok(Some(PvClockAction::SetCounterOffset(total_suspended_ticks)))
                } else {
                    // For non-AArch64 platforms this is handled by directly updating the offset in
                    // shared memory in the pvclock device worker.
                    Ok(None)
                }
            }
        }
        PvClockCommandResponse::Ok => {
            info!("{command:?} completed with {resp:?}");
            Ok(None)
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn handle_hotplug_command<V: VmArch, Vcpu: VcpuArch>(
    linux: &mut RunnableLinuxVm<V, Vcpu>,
    sys_allocator: &mut SystemAllocator,
    cfg: &Config,
    add_control_tube: &mut impl FnMut(AnyControlTube),
    hp_control_tube: &mpsc::Sender<PciRootCommand>,
    iommu_host_tube: Option<&Tube>,
    device: &HotPlugDeviceInfo,
    add: bool,
    #[cfg(feature = "swap")] swap_controller: &mut Option<SwapController>,
    vfio_container_manager: &mut VfioContainerManager,
) -> VmResponse {
    let iommu_host_tube = if cfg.vfio_isolate_hotplug {
        iommu_host_tube
    } else {
        None
    };

    let ret = if add {
        add_hotplug_device(
            linux,
            sys_allocator,
            cfg,
            add_control_tube,
            hp_control_tube,
            iommu_host_tube,
            device,
            #[cfg(feature = "swap")]
            swap_controller,
            vfio_container_manager,
        )
    } else {
        remove_hotplug_device(linux, sys_allocator, iommu_host_tube, device)
    };

    match ret {
        Ok(()) => VmResponse::Ok,
        Err(e) => {
            error!("handle_hotplug_command failure: {}", e);
            VmResponse::Err(base::Error::new(libc::EINVAL))
        }
    }
}

struct ControlLoopState<'a, V: VmArch, Vcpu: VcpuArch> {
    linux: &'a mut RunnableLinuxVm<V, Vcpu>,
    cfg: &'a Config,
    sys_allocator: &'a Arc<Mutex<SystemAllocator>>,
    control_tubes: &'a BTreeMap<usize, TaggedControlTube>,
    disk_host_tubes: &'a [Tube],
    #[cfg(feature = "audio")]
    snd_host_tubes: &'a [Tube],
    #[cfg(feature = "gpu")]
    gpu_control_tube: Option<&'a Tube>,
    #[cfg(feature = "usb")]
    usb_control_tube: &'a Tube,
    #[cfg(target_arch = "x86_64")]
    iommu_host_tube: &'a Option<Arc<Mutex<Tube>>>,
    #[cfg(target_arch = "x86_64")]
    hp_control_tube: &'a mpsc::Sender<PciRootCommand>,
    guest_suspended_cvar: &'a Option<Arc<(Mutex<bool>, Condvar)>>,
    #[cfg(feature = "pci-hotplug")]
    hotplug_manager: &'a mut Option<PciHotPlugManager>,
    #[cfg(feature = "swap")]
    swap_controller: &'a mut Option<SwapController>,
    vcpu_handles: &'a [(JoinHandle<()>, mpsc::Sender<vm_control::VcpuControl>)],
    #[cfg(feature = "balloon")]
    balloon_tube: Option<&'a mut BalloonTube>,
    device_ctrl_tube: &'a Tube,
    irq_handler_control: &'a Tube,
    #[cfg(any(target_arch = "x86_64", feature = "pci-hotplug"))]
    vm_memory_handler_control: &'a Tube,
    #[cfg(feature = "registered_events")]
    registered_evt_tubes: &'a mut HashMap<RegisteredEvent, HashSet<AddressedProtoTube>>,
    #[cfg(feature = "pvclock")]
    pvclock_host_tube: Option<Arc<Tube>>,
    vfio_container_manager: &'a mut VfioContainerManager,
    suspended_pvclock_state: &'a mut Option<hypervisor::ClockState>,
    vcpus_pid_tid: &'a BTreeMap<usize, (u32, u32)>,
}

struct VmRequestResult {
    response: Option<VmResponse>,
    exit: bool,
}

impl VmRequestResult {
    fn new(response: Option<VmResponse>, exit: bool) -> Self {
        VmRequestResult { response, exit }
    }
}

fn process_vm_request<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
    state: &mut ControlLoopState<V, Vcpu>,
    id: usize,
    tube: &Tube,
    request: VmRequest,
    #[cfg_attr(
        not(any(target_arch = "x86_64", feature = "pci-hotplug")),
        allow(unused_variables, clippy::ptr_arg)
    )]
    add_tubes: &mut Vec<TaggedControlTube>,
) -> Result<VmRequestResult> {
    #[cfg(any(target_arch = "x86_64", feature = "pci-hotplug"))]
    let mut add_irq_control_tubes = Vec::new();
    #[cfg(any(target_arch = "x86_64", feature = "pci-hotplug"))]
    let mut add_vm_memory_control_tubes = Vec::new();

    #[cfg(any(target_arch = "x86_64", feature = "pci-hotplug"))]
    let mut add_control_tube = |t| match t {
        AnyControlTube::DeviceControlTube(_) => {
            panic!("hotplugging DeviceControlTube not supported yet")
        }
        AnyControlTube::IrqTube(t) => add_irq_control_tubes.push(t),
        AnyControlTube::TaggedControlTube(t) => add_tubes.push(t),
        AnyControlTube::VmMemoryTube(t) => add_vm_memory_control_tubes.push(t),
    };

    let response = match request {
        VmRequest::Exit => {
            return Ok(VmRequestResult::new(Some(VmResponse::Ok), true));
        }
        VmRequest::HotPlugVfioCommand { device, add } => {
            #[cfg(target_arch = "x86_64")]
            {
                handle_hotplug_command(
                    state.linux,
                    &mut state.sys_allocator.lock(),
                    state.cfg,
                    &mut add_control_tube,
                    state.hp_control_tube,
                    state.iommu_host_tube.as_ref().map(|t| t.lock()).as_deref(),
                    &device,
                    add,
                    #[cfg(feature = "swap")]
                    state.swap_controller,
                    state.vfio_container_manager,
                )
            }

            #[cfg(not(target_arch = "x86_64"))]
            {
                // Suppress warnings.
                let _ = (device, add);
                let _ = &state.vfio_container_manager;
                VmResponse::Ok
            }
        }
        #[cfg(feature = "pci-hotplug")]
        VmRequest::HotPlugNetCommand(net_cmd) => {
            if let Some(hotplug_manager) = state.hotplug_manager.as_mut() {
                handle_hotplug_net_command(
                    net_cmd,
                    state.linux,
                    &mut state.sys_allocator.lock(),
                    &mut add_control_tube,
                    hotplug_manager,
                )
            } else {
                VmResponse::ErrString("PCI hotplug is not enabled.".to_owned())
            }
        }
        #[cfg(feature = "registered_events")]
        VmRequest::RegisterListener { socket_addr, event } => {
            let (registered_tube, already_registered) =
                find_registered_tube(state.registered_evt_tubes, &socket_addr, event);

            if !already_registered {
                let addr_tube = make_addr_tube_from_maybe_existing(registered_tube, socket_addr)?;

                if let Some(tubes) = state.registered_evt_tubes.get_mut(&event) {
                    tubes.insert(addr_tube);
                } else {
                    state
                        .registered_evt_tubes
                        .insert(event, vec![addr_tube].into_iter().collect());
                }
            }
            VmResponse::Ok
        }
        #[cfg(feature = "registered_events")]
        VmRequest::UnregisterListener { socket_addr, event } => {
            if let Some(tubes) = state.registered_evt_tubes.get_mut(&event) {
                tubes.retain(|t| t.socket_addr != socket_addr);
            }
            state
                .registered_evt_tubes
                .retain(|_, tubes| !tubes.is_empty());
            VmResponse::Ok
        }
        #[cfg(feature = "registered_events")]
        VmRequest::Unregister { socket_addr } => {
            for (_, tubes) in state.registered_evt_tubes.iter_mut() {
                tubes.retain(|t| t.socket_addr != socket_addr);
            }
            state
                .registered_evt_tubes
                .retain(|_, tubes| !tubes.is_empty());
            VmResponse::Ok
        }
        #[cfg(feature = "balloon")]
        VmRequest::BalloonCommand(cmd) => {
            if let Some(tube) = state.balloon_tube.as_mut() {
                let Some((r, key)) = tube.send_cmd(cmd, Some(id)) else {
                    return Ok(VmRequestResult::new(None, false));
                };
                if key != id {
                    let Some(TaggedControlTube::Vm(tube)) = state.control_tubes.get(&key) else {
                        return Ok(VmRequestResult::new(None, false));
                    };
                    if let Err(e) = tube.send(&r) {
                        error!("failed to send VmResponse: {}", e);
                    }
                    return Ok(VmRequestResult::new(None, false));
                }
                r
            } else {
                VmResponse::Err(base::Error::new(libc::ENOTSUP))
            }
        }
        VmRequest::VcpuPidTid => VmResponse::VcpuPidTidResponse {
            pid_tid_map: state.vcpus_pid_tid.clone(),
        },
        VmRequest::Throttle(vcpu, cycles) => {
            vcpu::kick_vcpu(
                &state.vcpu_handles.get(vcpu),
                state.linux.irq_chip.as_irq_chip(),
                VcpuControl::Throttle(cycles),
            );
            return Ok(VmRequestResult::new(None, false));
        }
        _ => {
            if !state.cfg.force_s2idle {
                #[cfg(feature = "pvclock")]
                if let Some(ref pvclock_host_tube) = state.pvclock_host_tube {
                    // Update clock offset when pvclock is used.
                    if let VmRequest::ResumeVcpus = request {
                        let cmd = PvClockCommand::Resume;
                        match send_pvclock_cmd(pvclock_host_tube, cmd.clone()) {
                            Ok(action) => {
                                info!("{:?} command successfully processed", cmd);
                                if let Some(action) = action {
                                    match action {
                                        #[cfg(target_arch = "aarch64")]
                                        PvClockAction::SetCounterOffset(offset) => {
                                            state.linux.vm.set_counter_offset(offset)?;
                                        }
                                    }
                                }
                            }
                            Err(e) => error!("{:?} command failed: {:#}", cmd, e),
                        };
                    }
                }
            }
            let kick_all_vcpus = |msg| {
                if let VcpuControl::RunState(VmRunMode::Running) = msg {
                    for dev in &state.linux.resume_notify_devices {
                        dev.lock().resume_imminent();
                    }
                }
                vcpu::kick_all_vcpus(state.vcpu_handles, state.linux.irq_chip.as_irq_chip(), msg);
            };
            let response = request.execute(
                &state.linux.vm,
                state.disk_host_tubes,
                #[cfg(feature = "audio")]
                state.snd_host_tubes,
                #[cfg(not(feature = "audio"))]
                &[],
                &mut state.linux.pm,
                #[cfg(feature = "gpu")]
                state.gpu_control_tube,
                #[cfg(not(feature = "gpu"))]
                None,
                #[cfg(feature = "usb")]
                Some(state.usb_control_tube),
                #[cfg(not(feature = "usb"))]
                None,
                &mut state.linux.bat_control,
                kick_all_vcpus,
                |index, msg| {
                    vcpu::kick_vcpu(
                        &state.vcpu_handles.get(index),
                        state.linux.irq_chip.as_irq_chip(),
                        msg,
                    )
                },
                state.cfg.force_s2idle,
                #[cfg(feature = "swap")]
                state.swap_controller.as_ref(),
                state.device_ctrl_tube,
                state.vcpu_handles.len(),
                state.irq_handler_control,
                || state.linux.irq_chip.snapshot(state.linux.vcpu_count),
                state.suspended_pvclock_state,
            );
            if state.cfg.force_s2idle {
                if let VmRequest::SuspendVcpus = request {
                    // Spawn s2idle wait thread.
                    let send_tube = tube.try_clone_send_tube().unwrap();
                    let suspend_tube = state.linux.suspend_tube.0.clone();
                    let guest_suspended_cvar = state.guest_suspended_cvar.clone();
                    let pm = state.linux.pm.clone();

                    std::thread::Builder::new()
                        .name("s2idle_wait".to_owned())
                        .spawn(move || {
                            trigger_vm_suspend_and_wait_for_entry(
                                guest_suspended_cvar.unwrap(),
                                &send_tube,
                                response,
                                suspend_tube,
                                pm,
                            )
                        })
                        .context("failed to spawn s2idle_wait thread")?;

                    // For s2idle, omit the response since it will be sent by
                    // s2idle_wait thread when suspension actually happens.
                    return Ok(VmRequestResult::new(None, false));
                }
            } else {
                #[cfg(feature = "pvclock")]
                if let Some(ref pvclock_host_tube) = state.pvclock_host_tube {
                    // Record the time after VCPUs are suspended to track suspension duration.
                    if let VmRequest::SuspendVcpus = request {
                        let cmd = PvClockCommand::Suspend;
                        match send_pvclock_cmd(pvclock_host_tube, cmd.clone()) {
                            Ok(action) => {
                                info!("{:?} command successfully processed", cmd);
                                if let Some(action) = action {
                                    error!("Unexpected action {:?} requested for suspend", action);
                                }
                            }
                            Err(e) => error!("{:?} command failed: {:#}", cmd, e),
                        };
                    }
                }
            }
            response
        }
    };

    cfg_if::cfg_if! {
        if #[cfg(any(target_arch = "x86_64", feature = "pci-hotplug"))] {
            if !add_irq_control_tubes.is_empty() {
                state
                    .irq_handler_control
                    .send(&IrqHandlerRequest::AddIrqControlTubes(
                        add_irq_control_tubes,
                    ))?;
            }
            if !add_vm_memory_control_tubes.is_empty() {
                state
                    .vm_memory_handler_control
                    .send(&VmMemoryHandlerRequest::AddControlTubes(
                        add_vm_memory_control_tubes,
                    ))?;
            }
        }
    }

    Ok(VmRequestResult::new(Some(response), false))
}

fn process_vm_control_event<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
    state: &mut ControlLoopState<V, Vcpu>,
    id: usize,
    socket: &TaggedControlTube,
) -> Result<(bool, Vec<usize>, Vec<TaggedControlTube>)> {
    let mut vm_control_ids_to_remove = Vec::new();
    let mut add_tubes = Vec::new();
    match socket {
        TaggedControlTube::Vm(tube) => match tube.recv::<VmRequest>() {
            Ok(request) => {
                let res = process_vm_request(state, id, tube, request, &mut add_tubes)?;

                if let Some(response) = res.response {
                    if let Err(e) = tube.send(&response) {
                        error!("failed to send VmResponse: {}", e);
                    }
                }

                if res.exit {
                    return Ok((true, Vec::new(), Vec::new()));
                }
            }
            Err(e) => {
                if let TubeError::Disconnected = e {
                    vm_control_ids_to_remove.push(id);
                } else {
                    error!("failed to recv VmRequest: {}", e);
                }
            }
        },
        TaggedControlTube::VmMsync(tube) => match tube.recv::<VmMemoryMappingRequest>() {
            Ok(request) => {
                let response = request.execute(&mut state.linux.vm);
                if let Err(e) = tube.send(&response) {
                    error!("failed to send VmMsyncResponse: {}", e);
                }
            }
            Err(e) => {
                if let TubeError::Disconnected = e {
                    vm_control_ids_to_remove.push(id);
                } else {
                    error!("failed to recv VmMsyncRequest: {}", e);
                }
            }
        },
        TaggedControlTube::Fs(tube) => match tube.recv::<FsMappingRequest>() {
            Ok(request) => {
                let response =
                    request.execute(&mut state.linux.vm, &mut state.sys_allocator.lock());
                if let Err(e) = tube.send(&response) {
                    error!("failed to send VmResponse: {}", e);
                }
            }
            Err(e) => {
                if let TubeError::Disconnected = e {
                    vm_control_ids_to_remove.push(id);
                } else {
                    error!("failed to recv VmResponse: {}", e);
                }
            }
        },
    }

    Ok((false, vm_control_ids_to_remove, add_tubes))
}

#[cfg(feature = "registered_events")]
struct AddressedProtoTube {
    tube: Rc<ProtoTube>,
    socket_addr: String,
}

#[cfg(feature = "registered_events")]
impl PartialEq for AddressedProtoTube {
    fn eq(&self, other: &Self) -> bool {
        self.socket_addr == other.socket_addr
    }
}

#[cfg(feature = "registered_events")]
impl Eq for AddressedProtoTube {}

#[cfg(feature = "registered_events")]
impl Hash for AddressedProtoTube {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.socket_addr.hash(state);
    }
}

#[cfg(feature = "registered_events")]
impl AddressedProtoTube {
    pub fn send<M: protobuf::Message>(&self, msg: &M) -> Result<(), base::TubeError> {
        self.tube.send_proto(msg)
    }
}

#[cfg(feature = "registered_events")]
fn find_registered_tube<'a>(
    registered_tubes: &'a HashMap<RegisteredEvent, HashSet<AddressedProtoTube>>,
    socket_addr: &str,
    event: RegisteredEvent,
) -> (Option<&'a Rc<ProtoTube>>, bool) {
    let mut registered_tube: Option<&Rc<ProtoTube>> = None;
    let mut already_registered = false;
    'outer: for (evt, addr_tubes) in registered_tubes {
        for addr_tube in addr_tubes {
            if addr_tube.socket_addr == socket_addr {
                if *evt == event {
                    already_registered = true;
                    break 'outer;
                }
                // Since all tubes of the same addr should
                // be an RC to the same tube, it doesn't
                // matter which one we get. But we do need
                // to check for a registration for the
                // current event, so can't break here.
                registered_tube = Some(&addr_tube.tube);
            }
        }
    }
    (registered_tube, already_registered)
}

#[cfg(feature = "registered_events")]
fn make_addr_tube_from_maybe_existing(
    tube: Option<&Rc<ProtoTube>>,
    addr: String,
) -> Result<AddressedProtoTube> {
    if let Some(registered_tube) = tube {
        Ok(AddressedProtoTube {
            tube: registered_tube.clone(),
            socket_addr: addr,
        })
    } else {
        let sock = UnixSeqpacket::connect(addr.clone()).with_context(|| {
            format!("failed to connect to registered listening socket {}", addr)
        })?;
        let tube = ProtoTube::from(Tube::try_from(sock)?);
        Ok(AddressedProtoTube {
            tube: Rc::new(tube),
            socket_addr: addr,
        })
    }
}

fn run_control<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
    mut linux: RunnableLinuxVm<V, Vcpu>,
    sys_allocator: SystemAllocator,
    cfg: Config,
    control_server_socket: Option<UnlinkUnixSeqpacketListener>,
    all_control_tubes: Vec<AnyControlTube>,
    #[cfg(feature = "usb")] usb_control_tube: Tube,
    vm_evt_rdtube: RecvTube,
    vm_evt_wrtube: SendTube,
    sigchld_fd: SignalFd,
    gralloc: RutabagaGralloc,
    vcpu_ids: Vec<usize>,
    iommu_host_tube: Option<Tube>,
    #[cfg(target_arch = "x86_64")] hp_control_tube: mpsc::Sender<PciRootCommand>,
    #[cfg(target_arch = "x86_64")] hp_thread: std::thread::JoinHandle<()>,
    #[cfg(feature = "pci-hotplug")] mut hotplug_manager: Option<PciHotPlugManager>,
    #[allow(unused_mut)] // mut is required x86 only
    #[cfg(feature = "swap")]
    mut swap_controller: Option<SwapController>,
    #[cfg(feature = "registered_events")] reg_evt_rdtube: RecvTube,
    guest_suspended_cvar: Option<Arc<(Mutex<bool>, Condvar)>>,
    metrics_tube: RecvTube,
    mut vfio_container_manager: VfioContainerManager,
    // A set of PID of child processes whose clean exit is expected and can be ignored.
    mut worker_process_pids: BTreeSet<Pid>,
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))] vcpu_domain_paths: BTreeMap<
        usize,
        PathBuf,
    >,
) -> Result<ExitState> {
    // Split up `all_control_tubes`.
    #[cfg(feature = "balloon")]
    let mut balloon_host_tube = None;
    let mut disk_host_tubes = Vec::new();
    #[cfg(feature = "gpu")]
    let mut gpu_control_tube = None;
    #[cfg(feature = "pvclock")]
    let mut pvclock_host_tube = None;
    #[cfg(feature = "audio")]
    let mut snd_host_tubes = Vec::new();
    let mut irq_control_tubes = Vec::new();
    let mut vm_memory_control_tubes = Vec::new();
    let mut control_tubes = Vec::new();
    for t in all_control_tubes {
        match t {
            #[cfg(feature = "balloon")]
            AnyControlTube::DeviceControlTube(DeviceControlTube::Balloon(t)) => {
                assert!(balloon_host_tube.is_none());
                balloon_host_tube = Some(t)
            }
            AnyControlTube::DeviceControlTube(DeviceControlTube::Disk(t)) => {
                disk_host_tubes.push(t)
            }
            #[cfg(feature = "gpu")]
            AnyControlTube::DeviceControlTube(DeviceControlTube::Gpu(t)) => {
                assert!(gpu_control_tube.is_none());
                gpu_control_tube = Some(t)
            }
            #[cfg(feature = "pvclock")]
            AnyControlTube::DeviceControlTube(DeviceControlTube::PvClock(t)) => {
                assert!(pvclock_host_tube.is_none());
                pvclock_host_tube = Some(Arc::new(t))
            }
            #[cfg(feature = "audio")]
            AnyControlTube::DeviceControlTube(DeviceControlTube::Snd(t)) => {
                snd_host_tubes.push(t);
            }
            AnyControlTube::IrqTube(t) => irq_control_tubes.push(t),
            AnyControlTube::TaggedControlTube(t) => control_tubes.push(t),
            AnyControlTube::VmMemoryTube(t) => vm_memory_control_tubes.push(t),
        }
    }

    #[cfg(feature = "gdb")]
    let (to_gdb_channel, gdb) = if let Some(port) = cfg.gdb {
        // GDB needs a control socket to interrupt vcpus.
        let (gdb_host_tube, gdb_control_tube) = Tube::pair().context("failed to create tube")?;
        control_tubes.push(TaggedControlTube::Vm(gdb_host_tube));
        // Create a channel for GDB thread.
        let (to_gdb_channel, from_vcpu_channel) = mpsc::channel();
        (
            Some(to_gdb_channel),
            Some((port, gdb_control_tube, from_vcpu_channel)),
        )
    } else {
        (None, None)
    };

    #[derive(EventToken)]
    enum Token {
        VmEvent,
        Suspend,
        ChildSignal,
        VmControlServer,
        VmControl {
            id: usize,
        },
        #[cfg(feature = "registered_events")]
        RegisteredEvent,
        #[cfg(feature = "balloon")]
        BalloonTube,
    }
    stdin()
        .set_raw_mode()
        .expect("failed to set terminal raw mode");

    let sys_allocator_mutex = Arc::new(Mutex::new(sys_allocator));
    let iommu_host_tube = iommu_host_tube.map(|t| Arc::new(Mutex::new(t)));

    let wait_ctx = WaitContext::build_with(&[
        (&linux.suspend_tube.1, Token::Suspend),
        (&sigchld_fd, Token::ChildSignal),
        (&vm_evt_rdtube, Token::VmEvent),
        #[cfg(feature = "registered_events")]
        (&reg_evt_rdtube, Token::RegisteredEvent),
    ])
    .context("failed to build wait context")?;

    if let Some(socket_server) = &control_server_socket {
        wait_ctx
            .add(socket_server, Token::VmControlServer)
            .context("failed to add descriptor to wait context")?;
    }
    let mut control_tubes = BTreeMap::from_iter(control_tubes.into_iter().enumerate());
    let mut next_control_id = control_tubes.len();
    for (id, socket) in control_tubes.iter() {
        wait_ctx
            .add(socket.as_ref(), Token::VmControl { id: *id })
            .context("failed to add descriptor to wait context")?;
    }

    #[cfg(feature = "balloon")]
    let mut balloon_tube = balloon_host_tube
        .map(|tube| -> Result<BalloonTube> {
            wait_ctx
                .add(&tube, Token::BalloonTube)
                .context("failed to add descriptor to wait context")?;
            Ok(BalloonTube::new(tube))
        })
        .transpose()
        .context("failed to create balloon tube")?;

    if cfg.jail_config.is_some() {
        // Before starting VCPUs, in case we started with some capabilities, drop them all.
        drop_capabilities().context("failed to drop process capabilities")?;
    }

    let (device_ctrl_tube, device_ctrl_resp) = Tube::pair().context("failed to create tube")?;
    // Create devices thread, and restore if a restore file exists.
    linux.devices_thread = match create_devices_worker_thread(
        linux.io_bus.clone(),
        linux.mmio_bus.clone(),
        device_ctrl_resp,
    ) {
        Ok(join_handle) => Some(join_handle),
        Err(e) => {
            return Err(anyhow!("Failed to start devices thread: {}", e));
        }
    };

    let mut vcpu_handles = Vec::with_capacity(linux.vcpu_count);
    let vcpu_thread_barrier = Arc::new(Barrier::new(linux.vcpu_count + 1));

    if !linux
        .vm
        .get_hypervisor()
        .check_capability(HypervisorCap::ImmediateExit)
    {
        return Err(anyhow!(
            "missing required hypervisor capability ImmediateExit"
        ));
    }

    vcpu::setup_vcpu_signal_handler()?;

    let vcpus: Vec<Option<_>> = match linux.vcpus.take() {
        Some(vec) => vec.into_iter().map(Some).collect(),
        None => iter::repeat_with(|| None).take(linux.vcpu_count).collect(),
    };
    // Enable core scheduling before creating vCPUs so that the cookie will be
    // shared by all vCPU threads.
    // TODO(b/199312402): Avoid enabling core scheduling for the crosvm process
    // itself for even better performance. Only vCPUs need the feature.
    if cfg.core_scheduling && cfg.per_vm_core_scheduling {
        if let Err(e) = enable_core_scheduling() {
            error!("Failed to enable core scheduling: {}", e);
        }
    }

    // The tasks file only exist on sysfs if CgroupV1 hierachies are enabled
    let vcpu_cgroup_tasks_file = match &cfg.vcpu_cgroup_path {
        None => None,
        Some(cgroup_path) => {
            // Move main process to cgroup_path
            match File::create(cgroup_path.join("tasks")) {
                Ok(file) => Some(file),
                Err(_) => {
                    info!(
                        "Unable to open tasks file in cgroup: {}, trying CgroupV2",
                        cgroup_path.display()
                    );
                    None
                }
            }
        }
    };

    // vCPU freq domains are currently only supported with CgroupsV2.
    let mut vcpu_cgroup_v2_files: std::collections::BTreeMap<usize, File> = BTreeMap::new();
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    for (vcpu_id, vcpu_domain_path) in vcpu_domain_paths.iter() {
        let vcpu_cgroup_v2_file = File::create(vcpu_domain_path.join("cgroup.threads"))
            .with_context(|| {
                format!(
                    "failed to create vcpu-cgroup-path {}",
                    vcpu_domain_path.join("cgroup.threads").display(),
                )
            })?;
        vcpu_cgroup_v2_files.insert(*vcpu_id, vcpu_cgroup_v2_file);
    }

    #[cfg(target_arch = "x86_64")]
    let bus_lock_ratelimit_ctrl: Arc<Mutex<Ratelimit>> = Arc::new(Mutex::new(Ratelimit::new()));
    #[cfg(target_arch = "x86_64")]
    if cfg.bus_lock_ratelimit > 0 {
        let bus_lock_ratelimit = cfg.bus_lock_ratelimit;
        if linux.vm.check_capability(VmCap::BusLockDetect) {
            info!("Hypervisor support bus lock detect");
            linux
                .vm
                .enable_capability(VmCap::BusLockDetect, 0)
                .expect("kvm: Failed to enable bus lock detection cap");
            info!("Hypervisor enabled bus lock detect");
            bus_lock_ratelimit_ctrl
                .lock()
                .ratelimit_set_speed(bus_lock_ratelimit);
        } else {
            bail!("Kvm: bus lock detection unsuported");
        }
    }

    #[cfg(target_os = "android")]
    android::set_process_profiles(&cfg.task_profiles)?;

    #[allow(unused_mut)]
    let mut run_mode = if cfg.suspended {
        // Sleep devices before creating vcpus.
        device_ctrl_tube
            .send(&DeviceControlCommand::SleepDevices)
            .context("send command to devices control socket")?;
        match device_ctrl_tube
            .recv()
            .context("receive from devices control socket")?
        {
            VmResponse::Ok => (),
            resp => bail!("device sleep failed: {}", resp),
        }
        VmRunMode::Suspending
    } else {
        VmRunMode::Running
    };
    #[cfg(feature = "gdb")]
    if to_gdb_channel.is_some() {
        // Wait until a GDB client attaches
        run_mode = VmRunMode::Breakpoint;
    }
    // If we are restoring from a snapshot, then start suspended.
    let (run_mode, post_restore_run_mode) = if cfg.restore_path.is_some() {
        (VmRunMode::Suspending, run_mode)
    } else {
        (run_mode, run_mode)
    };

    // Architecture-specific code must supply a vcpu_init element for each VCPU.
    assert_eq!(vcpus.len(), linux.vcpu_init.len());

    let (vcpu_pid_tid_sender, vcpu_pid_tid_receiver) = mpsc::channel();
    for ((cpu_id, vcpu), vcpu_init) in vcpus.into_iter().enumerate().zip(linux.vcpu_init.drain(..))
    {
        let vcpu_cgroup_file: Option<File>;
        if let Some(cgroup_file) = &vcpu_cgroup_tasks_file {
            vcpu_cgroup_file = Some(cgroup_file.try_clone().unwrap())
        } else if !cfg.cpu_freq_domains.is_empty() {
            vcpu_cgroup_file = Some(
                (vcpu_cgroup_v2_files.remove(&cpu_id).unwrap())
                    .try_clone()
                    .unwrap(),
            )
        } else {
            vcpu_cgroup_file = None
        };

        let (to_vcpu_channel, from_main_channel) = mpsc::channel();
        let vcpu_affinity = match linux.vcpu_affinity.clone() {
            Some(VcpuAffinity::Global(v)) => v,
            Some(VcpuAffinity::PerVcpu(mut m)) => m.remove(&cpu_id).unwrap_or_default(),
            None => Default::default(),
        };

        #[cfg(target_arch = "x86_64")]
        let vcpu_hybrid_type = if !cfg.vcpu_hybrid_type.is_empty() {
            Some(*cfg.vcpu_hybrid_type.get(&cpu_id).unwrap())
        } else {
            None
        };

        #[cfg(target_arch = "x86_64")]
        let cpu_config = Some(CpuConfigX86_64::new(
            cfg.force_calibrated_tsc_leaf,
            cfg.host_cpu_topology,
            cfg.enable_hwp,
            cfg.no_smt,
            cfg.itmt,
            vcpu_hybrid_type,
        ));
        #[cfg(target_arch = "x86_64")]
        let bus_lock_ratelimit_ctrl = Arc::clone(&bus_lock_ratelimit_ctrl);

        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        let cpu_config = None;

        #[cfg(target_arch = "riscv64")]
        let cpu_config = Some(CpuConfigRiscv64::new(vcpu_init.fdt_address));

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
            (*linux.io_bus).clone(),
            (*linux.mmio_bus).clone(),
            vm_evt_wrtube
                .try_clone()
                .context("failed to clone vm event tube")?,
            from_main_channel,
            #[cfg(feature = "gdb")]
            to_gdb_channel.clone(),
            cfg.core_scheduling,
            cfg.per_vm_core_scheduling,
            cpu_config,
            match vcpu_cgroup_file {
                None => None,
                Some(ref f) => Some(
                    f.try_clone()
                        .context("failed to clone vcpu cgroup tasks file")?,
                ),
            },
            #[cfg(target_arch = "x86_64")]
            bus_lock_ratelimit_ctrl,
            run_mode,
            cfg.boost_uclamp,
            vcpu_pid_tid_sender.clone(),
        )?;
        vcpu_handles.push((handle, to_vcpu_channel));
    }

    let mut vcpus_pid_tid = BTreeMap::new();
    for _ in 0..vcpu_handles.len() {
        let vcpu_pid_tid: VcpuPidTid = vcpu_pid_tid_receiver
            .recv()
            .context("failed receiving vcpu pid/tid")?;
        if vcpus_pid_tid
            .insert(
                vcpu_pid_tid.vcpu_id,
                (vcpu_pid_tid.process_id, vcpu_pid_tid.thread_id),
            )
            .is_some()
        {
            return Err(anyhow!(
                "Vcpu {} returned more than 1 PID and TID",
                vcpu_pid_tid.vcpu_id
            ));
        }
    }

    #[cfg(feature = "gdb")]
    // Spawn GDB thread.
    if let Some((gdb_port_num, gdb_control_tube, from_vcpu_channel)) = gdb {
        let to_vcpu_channels = vcpu_handles
            .iter()
            .map(|(_handle, channel)| channel.clone())
            .collect();
        let target = GdbStub::new(gdb_control_tube, to_vcpu_channels, from_vcpu_channel);
        std::thread::Builder::new()
            .name("gdb".to_owned())
            .spawn(move || gdb_thread(target, gdb_port_num))
            .context("failed to spawn GDB thread")?;
    };

    let (irq_handler_control, irq_handler_control_for_thread) = Tube::pair()?;
    let sys_allocator_for_thread = sys_allocator_mutex.clone();
    let irq_chip_for_thread = linux.irq_chip.try_box_clone()?;
    let irq_handler_thread = std::thread::Builder::new()
        .name("irq_handler_thread".into())
        .spawn(move || {
            irq_handler_thread(
                irq_control_tubes,
                irq_chip_for_thread,
                sys_allocator_for_thread,
                irq_handler_control_for_thread,
            )
        })
        .unwrap();

    let (vm_memory_handler_control, vm_memory_handler_control_for_thread) = Tube::pair()?;
    let vm_memory_handler_thread = std::thread::Builder::new()
        .name("vm_memory_handler_thread".into())
        .spawn({
            let vm = linux.vm.try_clone().context("failed to clone Vm")?;
            let sys_allocator_mutex = sys_allocator_mutex.clone();
            let iommu_client = iommu_host_tube
                .as_ref()
                .map(|t| VmMemoryRequestIommuClient::new(t.clone()));
            move || {
                vm_memory_handler_thread(
                    vm_memory_control_tubes,
                    vm,
                    sys_allocator_mutex,
                    gralloc,
                    iommu_client,
                    vm_memory_handler_control_for_thread,
                )
            }
        })
        .unwrap();

    vcpu_thread_barrier.wait();

    // See comment on `VmRequest::execute`.
    let mut suspended_pvclock_state: Option<hypervisor::ClockState> = None;

    // Restore VM (if applicable).
    // Must happen after the vCPU barrier to avoid deadlock.
    if let Some(path) = &cfg.restore_path {
        vm_control::do_restore(
            path,
            |msg| vcpu::kick_all_vcpus(&vcpu_handles, linux.irq_chip.as_irq_chip(), msg),
            |msg, index| {
                vcpu::kick_vcpu(&vcpu_handles.get(index), linux.irq_chip.as_irq_chip(), msg)
            },
            &irq_handler_control,
            &device_ctrl_tube,
            linux.vcpu_count,
            |image| {
                linux
                    .irq_chip
                    .try_box_clone()?
                    .restore(image, linux.vcpu_count)
            },
            /* require_encrypted= */ false,
            &mut suspended_pvclock_state,
            &linux.vm,
        )?;
        // Allow the vCPUs to start for real.
        vcpu::kick_all_vcpus(
            &vcpu_handles,
            linux.irq_chip.as_irq_chip(),
            VcpuControl::RunState(post_restore_run_mode),
        )
    }

    #[cfg(feature = "swap")]
    if let Some(swap_controller) = &swap_controller {
        swap_controller
            .on_static_devices_setup_complete()
            .context("static device setup complete")?;
    }

    let metrics_thread = if metrics::is_initialized() {
        Some(
            std::thread::Builder::new()
                .name("metrics_thread".into())
                .spawn(move || {
                    if let Err(e) = MetricsController::new(vec![metrics_tube]).run() {
                        error!("Metrics controller error: {:?}", e);
                    }
                })
                .context("metrics thread failed")?,
        )
    } else {
        None
    };

    let mut exit_state = ExitState::Stop;
    let mut pvpanic_code = PvPanicCode::Unknown;
    #[cfg(feature = "registered_events")]
    let mut registered_evt_tubes: HashMap<RegisteredEvent, HashSet<AddressedProtoTube>> =
        HashMap::new();

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

        let mut vm_control_ids_to_remove = Vec::new();
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                #[cfg(feature = "registered_events")]
                Token::RegisteredEvent => match reg_evt_rdtube.recv::<RegisteredEventWithData>() {
                    Ok(reg_evt) => {
                        let evt = reg_evt.into_event();
                        let mut tubes_to_remove: Vec<String> = Vec::new();
                        if let Some(tubes) = registered_evt_tubes.get_mut(&evt) {
                            for tube in tubes.iter() {
                                if let Err(e) = tube.send(&reg_evt.into_proto()) {
                                    warn!(
                                        "failed to send registered event {:?} to {}, removing from \
                                         registrations: {}",
                                        reg_evt, tube.socket_addr, e
                                    );
                                    tubes_to_remove.push(tube.socket_addr.clone());
                                }
                            }
                        }
                        for tube_addr in tubes_to_remove {
                            for tubes in registered_evt_tubes.values_mut() {
                                tubes.retain(|t| t.socket_addr != tube_addr);
                            }
                        }
                        registered_evt_tubes.retain(|_, tubes| !tubes.is_empty());
                    }
                    Err(e) => {
                        warn!("failed to recv RegisteredEvent: {}", e);
                    }
                },
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
                            VmEventType::DeviceCrashed => {
                                info!("device crashed");
                                exit_state = ExitState::Crash;
                            }
                            VmEventType::Panic(panic_code) => {
                                pvpanic_code = PvPanicCode::from_u8(panic_code);
                                info!("Guest reported panic [Code: {}]", pvpanic_code);
                                break_to_wait = false;
                            }
                            VmEventType::WatchdogReset => {
                                info!("vcpu stall detected");
                                exit_state = ExitState::WatchdogReset;
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
                Token::Suspend => match linux.suspend_tube.1.recv::<bool>() {
                    Ok(is_suspend_request) => {
                        let mode = if is_suspend_request {
                            VmRunMode::Suspending
                        } else {
                            for dev in &linux.resume_notify_devices {
                                dev.lock().resume_imminent();
                            }
                            VmRunMode::Running
                        };
                        info!("VM requested {}", mode);
                        vcpu::kick_all_vcpus(
                            &vcpu_handles,
                            linux.irq_chip.as_irq_chip(),
                            VcpuControl::RunState(mode),
                        );
                    }
                    Err(err) => {
                        warn!("Failed to read suspend tube {:?}", err);
                    }
                },
                Token::ChildSignal => {
                    // Print all available siginfo structs, then exit the loop if child process has
                    // been exited except CLD_STOPPED and CLD_CONTINUED. the two should be ignored
                    // here since they are used by the vmm-swap feature.
                    let mut do_exit = false;
                    while let Some(siginfo) =
                        sigchld_fd.read().context("failed to read signalfd")?
                    {
                        let pid = siginfo.ssi_pid;
                        let pid_label = match linux.pid_debug_label_map.get(&pid) {
                            Some(label) => format!("{} (pid {})", label, pid),
                            None => format!("pid {}", pid),
                        };

                        // TODO(kawasin): this is a temporary exception until device suspension.
                        #[cfg(feature = "swap")]
                        if siginfo.ssi_code == libc::CLD_STOPPED
                            || siginfo.ssi_code == libc::CLD_CONTINUED
                        {
                            continue;
                        }

                        // Ignore clean exits of non-tracked child processes when running without
                        // sandboxing. The virtio gpu process launches a render server for
                        // pass-through graphics. Host GPU drivers have been observed to fork
                        // child processes that exit cleanly which should not be considered a
                        // crash. When running with sandboxing, this should be handled by the
                        // device's process handler.
                        if cfg.jail_config.is_none()
                            && !linux.pid_debug_label_map.contains_key(&pid)
                            && siginfo.ssi_signo == libc::SIGCHLD as u32
                            && siginfo.ssi_code == libc::CLD_EXITED
                            && siginfo.ssi_status == 0
                        {
                            continue;
                        }

                        // Allow clean exits of a child process in `worker_process_pids`.
                        if siginfo.ssi_signo == libc::SIGCHLD as u32
                            && siginfo.ssi_code == libc::CLD_EXITED
                            && siginfo.ssi_status == 0
                            && worker_process_pids.remove(&(pid as Pid))
                        {
                            info!("child {pid} exited successfully");
                            continue;
                        }

                        if siginfo.ssi_signo == libc::SIGCHLD as u32
                            && (siginfo.ssi_code == libc::CLD_KILLED
                                || siginfo.ssi_code == libc::CLD_DUMPED)
                        {
                            error!(
                                "child {} killed by signal {} ({})",
                                pid_label,
                                siginfo.ssi_status,
                                base::signal::Signal::try_from(siginfo.ssi_status)
                                    .map(|s| s.to_string())
                                    .unwrap_or("unknown".to_string()),
                            );
                        } else {
                            error!(
                                "child {} exited: signo {}, status {}, code {}",
                                pid_label, siginfo.ssi_signo, siginfo.ssi_status, siginfo.ssi_code
                            );
                        }
                        do_exit = true;
                    }
                    if do_exit {
                        exit_state = ExitState::Crash;
                        break 'wait;
                    }
                }
                Token::VmControlServer => {
                    if let Some(socket_server) = &control_server_socket {
                        match socket_server.accept() {
                            Ok(socket) => {
                                let id = next_control_id;
                                next_control_id += 1;
                                wait_ctx
                                    .add(&socket, Token::VmControl { id })
                                    .context("failed to add descriptor to wait context")?;
                                control_tubes
                                    .insert(id, TaggedControlTube::Vm(Tube::try_from(socket)?));
                            }
                            Err(e) => error!("failed to accept socket: {}", e),
                        }
                    }
                }
                Token::VmControl { id } => {
                    if let Some(socket) = control_tubes.get(&id) {
                        let mut state = ControlLoopState {
                            linux: &mut linux,
                            cfg: &cfg,
                            sys_allocator: &sys_allocator_mutex,
                            control_tubes: &control_tubes,
                            disk_host_tubes: &disk_host_tubes[..],
                            #[cfg(feature = "audio")]
                            snd_host_tubes: &snd_host_tubes[..],
                            #[cfg(feature = "gpu")]
                            gpu_control_tube: gpu_control_tube.as_ref(),
                            #[cfg(feature = "usb")]
                            usb_control_tube: &usb_control_tube,
                            #[cfg(target_arch = "x86_64")]
                            iommu_host_tube: &iommu_host_tube,
                            #[cfg(target_arch = "x86_64")]
                            hp_control_tube: &hp_control_tube,
                            guest_suspended_cvar: &guest_suspended_cvar,
                            #[cfg(feature = "pci-hotplug")]
                            hotplug_manager: &mut hotplug_manager,
                            #[cfg(feature = "swap")]
                            swap_controller: &mut swap_controller,
                            vcpu_handles: &vcpu_handles,
                            #[cfg(feature = "balloon")]
                            balloon_tube: balloon_tube.as_mut(),
                            device_ctrl_tube: &device_ctrl_tube,
                            irq_handler_control: &irq_handler_control,
                            #[cfg(any(target_arch = "x86_64", feature = "pci-hotplug"))]
                            vm_memory_handler_control: &vm_memory_handler_control,
                            #[cfg(feature = "registered_events")]
                            registered_evt_tubes: &mut registered_evt_tubes,
                            #[cfg(feature = "pvclock")]
                            pvclock_host_tube: pvclock_host_tube.clone(),
                            vfio_container_manager: &mut vfio_container_manager,
                            suspended_pvclock_state: &mut suspended_pvclock_state,
                            vcpus_pid_tid: &vcpus_pid_tid,
                        };
                        let (exit_requested, mut ids_to_remove, add_tubes) =
                            process_vm_control_event(&mut state, id, socket)?;
                        if exit_requested {
                            break 'wait;
                        }
                        vm_control_ids_to_remove.append(&mut ids_to_remove);
                        for socket in add_tubes {
                            let id = next_control_id;
                            next_control_id += 1;
                            wait_ctx
                                .add(socket.as_ref(), Token::VmControl { id })
                                .context(
                                    "failed to add hotplug vfio-pci descriptor to wait context",
                                )?;
                            control_tubes.insert(id, socket);
                        }
                    }
                }
                #[cfg(feature = "balloon")]
                Token::BalloonTube => {
                    match balloon_tube.as_mut().expect("missing balloon tube").recv() {
                        Ok(resp) => {
                            for (resp, idx) in resp {
                                if let Some(TaggedControlTube::Vm(tube)) = control_tubes.get(&idx) {
                                    if let Err(e) = tube.send(&resp) {
                                        error!("failed to send VmResponse: {}", e);
                                    }
                                } else {
                                    error!("Bad tube index {}", idx);
                                }
                            }
                        }
                        Err(err) => {
                            error!("Error processing balloon tube {:?}", err)
                        }
                    }
                }
            }
        }

        remove_hungup_and_drained_tubes(
            &events,
            &wait_ctx,
            &mut control_tubes,
            vm_control_ids_to_remove,
            |token: &Token| {
                if let Token::VmControl { id } = token {
                    return Some(*id);
                }
                None
            },
        )?;
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

    // After joining all vcpu threads, unregister the process-wide signal handler.
    if let Err(e) = vcpu::remove_vcpu_signal_handler() {
        error!("failed to remove vcpu thread signal handler: {:#}", e);
    }

    // Stop the vmm-swap monitor process.
    #[cfg(feature = "swap")]
    drop(swap_controller);

    // Stop pci root worker thread
    #[cfg(target_arch = "x86_64")]
    {
        let _ = hp_control_tube.send(PciRootCommand::Kill);
        if let Err(e) = hp_thread.join() {
            error!("failed to join hotplug thread: {:?}", e);
        }
    }

    if linux.devices_thread.is_some() {
        if let Err(e) = device_ctrl_tube.send(&DeviceControlCommand::Exit) {
            error!("failed to stop device control loop: {}", e);
        };
        if let Some(thread) = linux.devices_thread.take() {
            if let Err(e) = thread.join() {
                error!("failed to exit devices thread: {:?}", e);
            }
        }
    }

    // At this point, the only remaining `Arc` references to the `Bus` objects should be the ones
    // inside `linux`. If the checks below fail, then some other thread is probably still running
    // and needs to be explicitly stopped before dropping `linux` to ensure devices actually get
    // cleaned up.
    match Arc::try_unwrap(std::mem::replace(
        &mut linux.mmio_bus,
        Arc::new(Bus::new(BusType::Mmio)),
    )) {
        Ok(_) => {}
        Err(_) => panic!("internal error: mmio_bus had more than one reference at shutdown"),
    }
    match Arc::try_unwrap(std::mem::replace(
        &mut linux.io_bus,
        Arc::new(Bus::new(BusType::Io)),
    )) {
        Ok(_) => {}
        Err(_) => panic!("internal error: io_bus had more than one reference at shutdown"),
    }

    // Explicitly drop the VM structure here to allow the devices to clean up before the
    // control sockets are closed when this function exits.
    mem::drop(linux);

    // Shut down the VM memory handler thread. This must happen after the potential device worker
    // threads(including the vhost device request handler threads) exit, because device worker
    // threads can issue VM memory requests. Those device worker threads are supposed to stop after
    // the RunnableLinuxVm is dropped.
    if let Err(e) = vm_memory_handler_control.send(&VmMemoryHandlerRequest::Exit) {
        error!(
            "failed to request exit from VM Memory handler thread: {}",
            e
        );
    }
    if let Err(e) = vm_memory_handler_thread.join() {
        error!("failed to exit VM Memory handler thread: {:?}", e);
    }

    // Shut down the IRQ handler thread after the devices are dropped.
    if let Err(e) = irq_handler_control.send(&IrqHandlerRequest::Exit) {
        error!("failed to request exit from IRQ handler thread: {}", e);
    }
    if let Err(e) = irq_handler_thread.join() {
        error!("failed to exit irq handler thread: {:?}", e);
    }

    // Drop the hotplug manager to tell the warden process to exit before we try to join
    // the metrics thread.
    #[cfg(feature = "pci-hotplug")]
    mem::drop(hotplug_manager);

    // All our children should have exited by now, so closing our fd should
    // terminate metrics. Then join so that everything gets flushed.
    metrics::get_destructor().cleanup();
    if let Some(metrics_thread) = metrics_thread {
        if let Err(e) = metrics_thread.join() {
            error!("failed to exit irq handler thread: {:?}", e);
        }
    }

    stdin()
        .set_canon_mode()
        .expect("failed to restore canonical mode for terminal");

    Ok(exit_state)
}

#[derive(EventToken)]
enum IrqHandlerToken {
    IrqFd { index: IrqEventIndex },
    VmIrq { id: usize },
    DelayedIrqFd,
    HandlerControl,
}

/// Handles IRQs and requests from devices to add additional IRQ lines.
fn irq_handler_thread(
    irq_control_tubes: Vec<Tube>,
    mut irq_chip: Box<dyn IrqChipArch + 'static>,
    sys_allocator_mutex: Arc<Mutex<SystemAllocator>>,
    handler_control: Tube,
) -> anyhow::Result<()> {
    let wait_ctx = WaitContext::build_with(&[(
        handler_control.get_read_notifier(),
        IrqHandlerToken::HandlerControl,
    )])
    .context("failed to build wait context")?;

    if let Some(delayed_ioapic_irq_trigger) = irq_chip.irq_delayed_event_token()? {
        wait_ctx
            .add(&delayed_ioapic_irq_trigger, IrqHandlerToken::DelayedIrqFd)
            .context("failed to add descriptor to wait context")?;
    }

    let mut irq_event_tokens = irq_chip
        .irq_event_tokens()
        .context("failed get event tokens from irqchip")?;

    for (index, _gsi, evt) in irq_event_tokens.iter() {
        wait_ctx
            .add(evt, IrqHandlerToken::IrqFd { index: *index })
            .context("failed to add irq chip event tokens to wait context")?;
    }

    let mut irq_control_tubes = BTreeMap::from_iter(irq_control_tubes.into_iter().enumerate());
    let mut next_control_id = irq_control_tubes.len();
    for (id, socket) in irq_control_tubes.iter() {
        wait_ctx
            .add(
                socket.get_read_notifier(),
                IrqHandlerToken::VmIrq { id: *id },
            )
            .context("irq control tubes to wait context")?;
    }

    'wait: loop {
        let events = {
            match wait_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to poll: {}", e);
                    break 'wait;
                }
            }
        };
        let token_count = events.len();
        let mut vm_irq_tubes_to_remove = Vec::new();
        let mut notify_control_on_iteration_end = false;

        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                IrqHandlerToken::HandlerControl => {
                    match handler_control.recv::<IrqHandlerRequest>() {
                        Ok(request) => {
                            match request {
                                IrqHandlerRequest::Exit => break 'wait,
                                IrqHandlerRequest::AddIrqControlTubes(tubes) => {
                                    for socket in tubes {
                                        let id = next_control_id;
                                        next_control_id += 1;
                                        wait_ctx
                                        .add(
                                            socket.get_read_notifier(),
                                            IrqHandlerToken::VmIrq { id },
                                        )
                                        .context("failed to add new IRQ control Tube to wait context")?;
                                        irq_control_tubes.insert(id, socket);
                                    }
                                }
                                IrqHandlerRequest::RefreshIrqEventTokens => {
                                    for (_index, _gsi, evt) in irq_event_tokens.iter() {
                                        wait_ctx.delete(evt).context(
                                            "failed to remove irq chip event \
                                                token from wait context",
                                        )?;
                                    }

                                    irq_event_tokens = irq_chip
                                        .irq_event_tokens()
                                        .context("failed get event tokens from irqchip")?;
                                    for (index, _gsi, evt) in irq_event_tokens.iter() {
                                        wait_ctx
                                            .add(evt, IrqHandlerToken::IrqFd { index: *index })
                                            .context(
                                                "failed to add irq chip event \
                                                tokens to wait context",
                                            )?;
                                    }

                                    if let Err(e) = handler_control
                                        .send(&IrqHandlerResponse::IrqEventTokenRefreshComplete)
                                    {
                                        error!(
                                            "failed to notify IRQ event token refresh \
                                            was completed: {}",
                                            e
                                        );
                                    }
                                }
                                IrqHandlerRequest::WakeAndNotifyIteration => {
                                    notify_control_on_iteration_end = true;
                                }
                            }
                        }
                        Err(e) => {
                            if let TubeError::Disconnected = e {
                                panic!("irq handler control tube disconnected.");
                            } else {
                                error!("failed to recv IrqHandlerRequest: {}", e);
                            }
                        }
                    }
                }
                IrqHandlerToken::VmIrq { id } => {
                    if let Some(tube) = irq_control_tubes.get(&id) {
                        handle_irq_tube_request(
                            &sys_allocator_mutex,
                            &mut irq_chip,
                            &mut vm_irq_tubes_to_remove,
                            &wait_ctx,
                            tube,
                            id,
                        );
                    }
                }
                IrqHandlerToken::IrqFd { index } => {
                    if let Err(e) = irq_chip.service_irq_event(index) {
                        error!("failed to signal irq {}: {}", index, e);
                    }
                }
                IrqHandlerToken::DelayedIrqFd => {
                    if let Err(e) = irq_chip.process_delayed_irq_events() {
                        warn!("can't deliver delayed irqs: {}", e);
                    }
                }
            }
        }

        if notify_control_on_iteration_end {
            if let Err(e) = handler_control.send(&IrqHandlerResponse::HandlerIterationComplete(
                token_count - 1,
            )) {
                error!(
                    "failed to notify on iteration completion (snapshotting may fail): {}",
                    e
                );
            }
        }

        remove_hungup_and_drained_tubes(
            &events,
            &wait_ctx,
            &mut irq_control_tubes,
            vm_irq_tubes_to_remove,
            |token: &IrqHandlerToken| {
                if let IrqHandlerToken::VmIrq { id } = token {
                    return Some(*id);
                }
                None
            },
        )?;
        if events.iter().any(|e| {
            e.is_hungup && !e.is_readable && matches!(e.token, IrqHandlerToken::HandlerControl)
        }) {
            error!("IRQ handler control hung up but did not request an exit.");
            break 'wait;
        }
    }
    Ok(())
}

fn handle_irq_tube_request(
    sys_allocator_mutex: &Arc<Mutex<SystemAllocator>>,
    irq_chip: &mut Box<dyn IrqChipArch + 'static>,
    vm_irq_tubes_to_remove: &mut Vec<usize>,
    wait_ctx: &WaitContext<IrqHandlerToken>,
    tube: &Tube,
    tube_index: usize,
) {
    match tube.recv::<VmIrqRequest>() {
        Ok(request) => {
            let response = {
                request.execute(
                    |setup| match setup {
                        IrqSetup::Event(irq, ev, device_id, queue_id, device_name) => {
                            let irq_evt = devices::IrqEdgeEvent::from_event(ev.try_clone()?);
                            let source = IrqEventSource {
                                device_id: device_id.try_into().expect("Invalid device_id"),
                                queue_id,
                                device_name,
                            };
                            if let Some(event_index) =
                                irq_chip.register_edge_irq_event(irq, &irq_evt, source)?
                            {
                                if let Err(e) =
                                    wait_ctx.add(ev, IrqHandlerToken::IrqFd { index: event_index })
                                {
                                    warn!("failed to add IrqFd to poll context: {}", e);
                                    return Err(e);
                                }
                            }
                            Ok(())
                        }
                        IrqSetup::Route(route) => irq_chip.route_irq(route),
                        IrqSetup::UnRegister(irq, ev) => {
                            let irq_evt = devices::IrqEdgeEvent::from_event(ev.try_clone()?);
                            irq_chip.unregister_edge_irq_event(irq, &irq_evt)
                        }
                    },
                    &mut sys_allocator_mutex.lock(),
                )
            };
            if let Err(e) = tube.send(&response) {
                error!("failed to send VmIrqResponse: {}", e);
            }
        }
        Err(e) => {
            if let TubeError::Disconnected = e {
                vm_irq_tubes_to_remove.push(tube_index);
            } else {
                error!("failed to recv VmIrqRequest: {}", e);
            }
        }
    }
}

/// Commands to control the VM Memory handler thread.
#[derive(serde::Serialize, serde::Deserialize)]
pub enum VmMemoryHandlerRequest {
    /// No response is sent for this command.
    AddControlTubes(Vec<VmMemoryTube>),
    /// No response is sent for this command.
    Exit,
}

fn vm_memory_handler_thread(
    control_tubes: Vec<VmMemoryTube>,
    mut vm: impl Vm,
    sys_allocator_mutex: Arc<Mutex<SystemAllocator>>,
    mut gralloc: RutabagaGralloc,
    mut iommu_client: Option<VmMemoryRequestIommuClient>,
    handler_control: Tube,
) -> anyhow::Result<()> {
    #[derive(EventToken)]
    enum Token {
        VmControl { id: usize },
        HandlerControl,
    }

    let wait_ctx =
        WaitContext::build_with(&[(handler_control.get_read_notifier(), Token::HandlerControl)])
            .context("failed to build wait context")?;
    let mut control_tubes = BTreeMap::from_iter(control_tubes.into_iter().enumerate());
    let mut next_control_id = control_tubes.len();
    for (id, socket) in control_tubes.iter() {
        wait_ctx
            .add(socket.as_ref(), Token::VmControl { id: *id })
            .context("failed to add descriptor to wait context")?;
    }

    let mut region_state: VmMemoryRegionState = Default::default();

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

        let mut vm_control_ids_to_remove = Vec::new();
        for event in events.iter().filter(|e| e.is_readable) {
            match event.token {
                Token::HandlerControl => match handler_control.recv::<VmMemoryHandlerRequest>() {
                    Ok(request) => match request {
                        VmMemoryHandlerRequest::Exit => break 'wait,
                        VmMemoryHandlerRequest::AddControlTubes(tubes) => {
                            for socket in tubes {
                                let id = next_control_id;
                                next_control_id += 1;
                                wait_ctx
                                    .add(socket.get_read_notifier(), Token::VmControl { id })
                                    .context(
                                        "failed to add new vm memory control Tube to wait context",
                                    )?;
                                control_tubes.insert(id, socket);
                            }
                        }
                    },
                    Err(e) => {
                        if let TubeError::Disconnected = e {
                            panic!("vm memory control tube disconnected.");
                        } else {
                            error!("failed to recv VmMemoryHandlerRequest: {}", e);
                        }
                    }
                },
                Token::VmControl { id } => {
                    if let Some(VmMemoryTube {
                        tube,
                        expose_with_viommu,
                    }) = control_tubes.get(&id)
                    {
                        match tube.recv::<VmMemoryRequest>() {
                            Ok(request) => {
                                let response = request.execute(
                                    tube,
                                    &mut vm,
                                    &mut sys_allocator_mutex.lock(),
                                    &mut gralloc,
                                    if *expose_with_viommu {
                                        iommu_client.as_mut()
                                    } else {
                                        None
                                    },
                                    &mut region_state,
                                );
                                if let Err(e) = tube.send(&response) {
                                    error!("failed to send VmMemoryControlResponse: {}", e);
                                }
                            }
                            Err(e) => {
                                if let TubeError::Disconnected = e {
                                    vm_control_ids_to_remove.push(id);
                                } else {
                                    error!("failed to recv VmMemoryControlRequest: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }

        remove_hungup_and_drained_tubes(
            &events,
            &wait_ctx,
            &mut control_tubes,
            vm_control_ids_to_remove,
            |token: &Token| {
                if let Token::VmControl { id } = token {
                    return Some(*id);
                }
                None
            },
        )?;
        if events
            .iter()
            .any(|e| e.is_hungup && !e.is_readable && matches!(e.token, Token::HandlerControl))
        {
            error!("vm memory handler control hung up but did not request an exit.");
            break 'wait;
        }
    }
    Ok(())
}

/// When control tubes hang up, we want to make sure that we've fully drained
/// the underlying socket before removing it. This function also handles
/// removing closed sockets in such a way that avoids phantom events.
///
/// `tube_ids_to_remove` is the set of ids that we already know should
/// be removed (e.g. from getting a disconnect error on read).
fn remove_hungup_and_drained_tubes<T, U>(
    events: &SmallVec<[TriggeredEvent<T>; 16]>,
    wait_ctx: &WaitContext<T>,
    tubes: &mut BTreeMap<usize, U>,
    mut tube_ids_to_remove: Vec<usize>,
    get_tube_id: fn(token: &T) -> Option<usize>,
) -> anyhow::Result<()>
where
    T: EventToken,
    U: ReadNotifier,
{
    // It's possible more data is readable and buffered while the socket is hungup,
    // so don't delete the tube from the poll context until we're sure all the
    // data is read.
    // Below case covers a condition where we have received a hungup event and the tube is not
    // readable.
    // In case of readable tube, once all data is read, any attempt to read more data on hungup
    // tube should fail. On such failure, we get Disconnected error and ids gets added to
    // tube_ids_to_remove by the time we reach here.
    for event in events.iter().filter(|e| e.is_hungup && !e.is_readable) {
        if let Some(id) = get_tube_id(&event.token) {
            tube_ids_to_remove.push(id);
        }
    }

    tube_ids_to_remove.dedup();
    for id in tube_ids_to_remove {
        // Delete the socket from the `wait_ctx` synchronously. Otherwise, the kernel will do
        // this automatically when the FD inserted into the `wait_ctx` is closed after this
        // if-block, but this removal can be deferred unpredictably. In some instances where the
        // system is under heavy load, we can even get events returned by `wait_ctx` for an FD
        // that has already been closed. Because the token associated with that spurious event
        // now belongs to a different socket, the control loop will start to interact with
        // sockets that might not be ready to use. This can cause incorrect hangup detection or
        // blocking on a socket that will never be ready. See also: crbug.com/1019986
        if let Some(socket) = tubes.remove(&id) {
            wait_ctx
                .delete(socket.get_read_notifier())
                .context("failed to remove descriptor from wait context")?;
        }
    }
    Ok(())
}

/// Start and jail a vhost-user device according to its configuration and a vhost listener string.
///
/// The jailing business is nasty and potentially unsafe if done from the wrong context - do not
/// call outside of `start_devices`!
///
/// Returns the pid of the jailed device process.
fn jail_and_start_vu_device<T: VirtioDeviceBuilder>(
    jail_config: Option<&JailConfig>,
    params: T,
    vhost: &str,
    name: &str,
) -> anyhow::Result<(libc::pid_t, Option<Box<dyn std::any::Any>>)> {
    let mut keep_rds = Vec::new();

    base::syslog::push_descriptors(&mut keep_rds);
    cros_tracing::push_descriptors!(&mut keep_rds);
    metrics::push_descriptors(&mut keep_rds);

    let jail_type = VirtioDeviceType::VhostUser;

    // Create a jail from the configuration. If the configuration is `None`, `create_jail` will also
    // return `None` so fall back to an empty (i.e. non-constrained) Minijail.
    let jail = params
        .create_jail(jail_config, jail_type)
        .with_context(|| format!("failed to create jail for {}", name))?
        .ok_or(())
        .or_else(|_| Minijail::new())
        .with_context(|| format!("failed to create empty jail for {}", name))?;

    // Create the device in the parent process, so the child does not need any privileges necessary
    // to do it (only runtime capabilities are required).
    let device = params
        .create_vhost_user_device(&mut keep_rds)
        .context("failed to create vhost-user device")?;
    let mut listener =
        VhostUserListener::new(vhost).context("failed to create the vhost listener")?;
    keep_rds.push(listener.as_raw_descriptor());
    let parent_resources = listener.take_parent_process_resources();

    // Executor must be created before jail in order to prevent the jailed process from creating
    // unrestricted io_urings.
    let ex = Executor::new().context("Failed to create an Executor")?;
    keep_rds.extend(ex.as_raw_descriptors());

    // Deduplicate the FDs since minijail expects them to be unique.
    keep_rds.sort_unstable();
    keep_rds.dedup();

    // SAFETY:
    // Safe because we are keeping all the descriptors needed for the child to function.
    match unsafe { jail.fork(Some(&keep_rds)).context("error while forking")? } {
        0 => {
            // In the child process.

            // Free memory for the resources managed by the parent, without running drop() on them.
            // The parent will do it as we exit.
            let _ = std::mem::ManuallyDrop::new(parent_resources);

            // Make sure the child process does not survive its parent.
            // SAFETY: trivially safe
            if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } < 0 {
                panic!("call to prctl(PR_SET_DEATHSIG, SIGKILL) failed. Aborting child process.");
            }

            // Set the name for the thread.
            const MAX_LEN: usize = 15; // pthread_setname_np() limit on Linux
            let debug_label_trimmed = &name.as_bytes()[..std::cmp::min(MAX_LEN, name.len())];
            let thread_name = CString::new(debug_label_trimmed).unwrap();
            // SAFETY:
            // Safe because we trimmed the name to 15 characters (and pthread_setname_np will return
            // an error if we don't anyway).
            let _ = unsafe { libc::pthread_setname_np(libc::pthread_self(), thread_name.as_ptr()) };

            // Run the device loop and terminate the child process once it exits.
            let res = match listener.run_device(ex, device) {
                Ok(()) => 0,
                Err(e) => {
                    error!("error while running device {}: {:#}", name, e);
                    1
                }
            };
            // SAFETY: trivially safe
            unsafe { libc::exit(res) };
        }
        pid => {
            // In the parent process. We will drop the device and listener when exiting this method.
            // This is fine as ownership for both has been transferred to the child process and they
            // will keep living there. We just retain `parent_resources` for things we are supposed
            // to clean up ourselves.

            info!("process for device {} (PID {}) started", &name, pid);
            #[cfg(feature = "seccomp_trace")]
            debug!(
                    "seccomp_trace {{\"event\": \"minijail_fork\", \"pid\": {}, \"name\": \"{}\", \"jail_addr\": \"0x{:x}\"}}",
                    pid,
                    &name,
                    read_jail_addr(&jail)
                );
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
                let tube = match Tube::try_from(socket) {
                    Ok(tube) => tube,
                    Err(e) => {
                        error!("failed to open tube: {:#}", e);
                        return;
                    }
                };
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
    if let Some(async_executor) = opts.async_executor {
        Executor::set_default_executor_kind(async_executor)
            .context("Failed to set the default async executor")?;
    }

    struct DeviceJailInfo {
        // Unique name for the device, in the form `foomatic-0`.
        name: String,
        _drop_resources: Option<Box<dyn std::any::Any>>,
    }

    fn add_device<T: VirtioDeviceBuilder>(
        i: usize,
        device_params: T,
        vhost: &str,
        jail_config: Option<&JailConfig>,
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
        Some(&opts.jail)
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
        add_device(i, serial_config, &params.vhost, jail, &mut devices_jails)?;
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
        add_device(i, disk_config, &params.vhost, jail, &mut devices_jails)?;
    }

    // Create vsock devices.
    for (i, params) in opts.vsock.iter().enumerate() {
        add_device(i, &params.device, &params.vhost, jail, &mut devices_jails)?;
    }

    // Create network devices.
    #[cfg(feature = "net")]
    for (i, params) in opts.net.iter().enumerate() {
        add_device(i, &params.device, &params.vhost, jail, &mut devices_jails)?;
    }

    // No device created, that's probably not intended - print the help in that case.
    if devices_jails.is_empty() {
        let err = DevicesCommand::from_args(
            &[&std::env::args().next().unwrap_or(String::from("crosvm"))],
            &["--help"],
        )
        .unwrap_err();
        println!("{}", err.output);
        return Ok(());
    }

    if let Some(control_server_socket) = control_server_socket {
        // Start the control server in the parent process.
        std::thread::spawn(move || {
            start_vhost_user_control_server(control_server_socket, disk_host_tubes)
        });
    }

    // Now wait for all device processes to return.
    while !devices_jails.is_empty() {
        match base::linux::wait_for_pid(-1, 0) {
            Err(e) => panic!("error waiting for child process to complete: {:#}", e),
            Ok((Some(pid), wait_status)) => match devices_jails.remove_entry(&pid) {
                Some((_, info)) => {
                    if let Some(status) = wait_status.code() {
                        info!(
                            "process for device {} (PID {}) exited with code {}",
                            &info.name, pid, status
                        );
                    } else if let Some(signal) = wait_status.signal() {
                        warn!(
                            "process for device {} (PID {}) has been killed by signal {:?}",
                            &info.name, pid, signal,
                        );
                    }
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

    use vm_memory::MemoryRegionPurpose;

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
            ram: true,
        }
    }

    #[test]
    fn guest_mem_file_backed_mappings_overlap() {
        // Base case: no file mappings; output layout should be identical.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000, Default::default()),
                    (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
                ],
                &[]
            )
            .unwrap(),
            vec![
                (GuestAddress(0), 0xD000_0000, Default::default()),
                (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
            ],
        );

        // File mapping that does not overlap guest memory.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000, Default::default()),
                    (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
                ],
                &[test_file_backed_mapping(0xD000_0000, 0x1000)]
            )
            .unwrap_err()
            .to_string(),
            "RAM file-backed-mapping must be a subset of a RAM region",
        );

        // File mapping at the start of the low address space region.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000, Default::default()),
                    (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
                ],
                &[test_file_backed_mapping(0, 0x2000)]
            )
            .unwrap(),
            vec![
                (
                    GuestAddress(0),
                    0x2000,
                    MemoryRegionOptions::new()
                        .purpose(MemoryRegionPurpose::GuestMemoryRegion)
                        .file_backed(test_file_backed_mapping(0, 0x2000)),
                ),
                (
                    GuestAddress(0x2000),
                    0xD000_0000 - 0x2000,
                    Default::default()
                ),
                (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
            ],
        );

        // File mapping at the end of the low address space region.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000, Default::default()),
                    (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
                ],
                &[test_file_backed_mapping(0xD000_0000 - 0x2000, 0x2000)]
            )
            .unwrap(),
            vec![
                (GuestAddress(0), 0xD000_0000 - 0x2000, Default::default()),
                (
                    GuestAddress(0xD000_0000 - 0x2000),
                    0x2000,
                    MemoryRegionOptions::new()
                        .purpose(MemoryRegionPurpose::GuestMemoryRegion)
                        .file_backed(test_file_backed_mapping(0xD000_0000 - 0x2000, 0x2000)),
                ),
                (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
            ],
        );

        // File mapping fully contained within the middle of the low address space region.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000, Default::default()),
                    (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
                ],
                &[test_file_backed_mapping(0x1000, 0x2000)]
            )
            .unwrap(),
            vec![
                (GuestAddress(0), 0x1000, Default::default()),
                (
                    GuestAddress(0x1000),
                    0x2000,
                    MemoryRegionOptions::new()
                        .purpose(MemoryRegionPurpose::GuestMemoryRegion)
                        .file_backed(test_file_backed_mapping(0x1000, 0x2000)),
                ),
                (
                    GuestAddress(0x3000),
                    0xD000_0000 - 0x3000,
                    Default::default()
                ),
                (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
            ],
        );

        // File mapping at the start of the high address space region.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000, Default::default()),
                    (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
                ],
                &[test_file_backed_mapping(0x1_0000_0000, 0x2000)]
            )
            .unwrap(),
            vec![
                (GuestAddress(0), 0xD000_0000, Default::default()),
                (
                    GuestAddress(0x1_0000_0000),
                    0x2000,
                    MemoryRegionOptions::new()
                        .purpose(MemoryRegionPurpose::GuestMemoryRegion)
                        .file_backed(test_file_backed_mapping(0x1_0000_0000, 0x2000)),
                ),
                (
                    GuestAddress(0x1_0000_2000),
                    0x8_0000 - 0x2000,
                    Default::default()
                ),
            ],
        );

        // File mapping at the end of the high address space region.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000, Default::default()),
                    (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
                ],
                &[test_file_backed_mapping(0x1_0008_0000 - 0x2000, 0x2000)]
            )
            .unwrap(),
            vec![
                (GuestAddress(0), 0xD000_0000, Default::default()),
                (
                    GuestAddress(0x1_0000_0000),
                    0x8_0000 - 0x2000,
                    Default::default()
                ),
                (
                    GuestAddress(0x1_0008_0000 - 0x2000),
                    0x2000,
                    MemoryRegionOptions::new()
                        .purpose(MemoryRegionPurpose::GuestMemoryRegion)
                        .file_backed(test_file_backed_mapping(0x1_0008_0000 - 0x2000, 0x2000)),
                ),
            ],
        );

        // File mapping fully contained within the middle of the high address space region.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000, Default::default()),
                    (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
                ],
                &[test_file_backed_mapping(0x1_0000_1000, 0x2000)]
            )
            .unwrap(),
            vec![
                (GuestAddress(0), 0xD000_0000, Default::default()),
                (GuestAddress(0x1_0000_0000), 0x1000, Default::default()),
                (
                    GuestAddress(0x1_0000_1000),
                    0x2000,
                    MemoryRegionOptions::new()
                        .purpose(MemoryRegionPurpose::GuestMemoryRegion)
                        .file_backed(test_file_backed_mapping(0x1_0000_1000, 0x2000)),
                ),
                (
                    GuestAddress(0x1_0000_3000),
                    0x8_0000 - 0x3000,
                    Default::default()
                ),
            ],
        );

        // File mapping overlapping two guest memory regions.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0), 0xD000_0000, Default::default()),
                    (GuestAddress(0x1_0000_0000), 0x8_0000, Default::default()),
                ],
                &[test_file_backed_mapping(0xA000_0000, 0x60002000)]
            )
            .unwrap_err()
            .to_string(),
            "RAM file-backed-mapping must be a subset of a RAM region",
        );

        // File mapping with different region purpose.
        assert_eq!(
            punch_holes_in_guest_mem_layout_for_mappings(
                vec![
                    (GuestAddress(0x0000), 0x2000, Default::default()),
                    (
                        GuestAddress(0x2000),
                        0x2000,
                        MemoryRegionOptions::new().purpose(MemoryRegionPurpose::Bios)
                    ),
                ],
                &[test_file_backed_mapping(0x2000, 0x2000)]
            )
            .unwrap(),
            vec![
                (GuestAddress(0x0000), 0x2000, Default::default()),
                (
                    GuestAddress(0x2000),
                    0x2000,
                    MemoryRegionOptions::new()
                        .purpose(MemoryRegionPurpose::Bios)
                        .file_backed(test_file_backed_mapping(0x2000, 0x2000)),
                ),
            ],
        );
    }

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    #[test]
    fn normalized_cpu_ipc_ratios_simple() {
        let host_max_freq = 5000000;
        let mut cpu_frequencies = BTreeMap::new();
        cpu_frequencies.insert(0, vec![100000, 200000, 500000]);
        cpu_frequencies.insert(1, vec![50000, 75000, 200000]);

        let mut cpu_ipc_ratio = BTreeMap::new();
        cpu_ipc_ratio.insert(0, 1024);
        cpu_ipc_ratio.insert(1, 512);

        let normalized_cpu_ipc_ratios = normalize_cpu_ipc_ratios(
            cpu_frequencies.iter().map(|(cpu_id, frequencies)| {
                (
                    *cpu_id,
                    frequencies.iter().copied().max().unwrap_or_default(),
                )
            }),
            host_max_freq,
            |cpu_id| cpu_ipc_ratio.get(&cpu_id).copied().unwrap_or(1024),
        )
        .expect("normalize_cpu_ipc_ratios failed");

        let ratios: Vec<(usize, u32)> = normalized_cpu_ipc_ratios.into_iter().collect();
        assert_eq!(ratios, vec![(0, 102), (1, 20)]);
    }
}
